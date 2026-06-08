# ===== JavaScript Core UI (Lookup, Render, Events) =====
$htmlPage += @'
// ---- Live check-progress popover helpers ----
//
// While a domain lookup runs, the SPA fans out 8 parallel API calls. Some
// finish in milliseconds (cached DNS), others (WHOIS/RDAP, DNSBL fan-out)
// can take several seconds. The popover gives the user real-time visibility
// into which checks are still in flight, which completed, and which failed.
//
// UX model: the popover is shown automatically whenever a lookup is in
// flight (replacing the legacy "Checking {domain} ..." status text) and
// hidden as soon as every backend call has resolved. It is rendered as a
// centered card in normal document flow between the search box and the
// results, so it cannot be hidden behind any other element.
//
// State is kept on a single `checkProgress` object so the popover can be
// re-rendered cheaply (e.g. when the language changes mid-lookup) without
// touching the lookup workflow itself. runId guards against late updates
// from a previous lookup leaking into the popover for a newer one.
const checkProgress = {
  runId: 0,
  tasks: [],
  // Whether a lookup is currently in flight; controls popover visibility.
  active: false
};

// Map from API task key -> translation key. We deliberately reuse existing
// translation keys so this feature ships in all 10 supported languages
// without needing new translation strings. 'dkim' has no plain key in the
// translations file (only dkim1Title/dkim2Title), but "DKIM" is the
// universally recognized name for the standard, so a literal is fine.
const CHECK_PROGRESS_LABELS = {
  base:       'domain',
  mx:         'mxRecords',
  records:    'dnsRecords',
  whois:      'domainRegistration',
  dmarc:      'dmarc',
  dkim:       null,
  cname:      'cname',
  reputation: 'reputationDnsbl'
};

function getCheckProgressLabel(key) {
  if (key === 'dkim') return 'DKIM';
  const tKey = CHECK_PROGRESS_LABELS[key];
  return tKey ? t(tKey) : key;
}

function renderCheckProgressPopover() {
  const el = document.getElementById('checkProgressPopover');
  if (!el || !checkProgress.tasks || !checkProgress.tasks.length) return;
  // Static "Gathering Data" header. The per-row spinners already convey
  // progress, so a duplicated header spinner would be visual noise.
  const titleHtml = '<div class="check-progress-title">'
    + escapeHtml(t('gatheringData'))
    + '</div>';
  const itemsHtml = checkProgress.tasks.map(function (task) {
    // Status -> icon glyph: spinner is rendered via CSS ::after for
    // 'pending', so we only need glyphs for terminal states.
    let glyph = '';
    if (task.status === 'done') glyph = '\u2713';   // check mark
    else if (task.status === 'error') glyph = '\u2717'; // ballot X
    return '<li class="check-progress-item ' + escapeHtml(task.status) + '">'
      + '<span class="check-progress-icon ' + escapeHtml(task.status) + '">' + glyph + '</span>'
      + '<span class="check-progress-label">' + escapeHtml(getCheckProgressLabel(task.key)) + '</span>'
      + '</li>';
  }).join('');
  el.innerHTML = titleHtml + '<ul class="check-progress-list">' + itemsHtml + '</ul>';
}

function markCheckProgress(runId, key, status) {
  // Drop late updates from a superseded lookup so the popover for the
  // current run is never corrupted by stragglers.
  if (runId !== checkProgress.runId) return;
  if (!checkProgress.tasks) return;
  for (let i = 0; i < checkProgress.tasks.length; i++) {
    if (checkProgress.tasks[i].key === key) {
      checkProgress.tasks[i].status = status;
      break;
    }
  }
  renderCheckProgressPopover();
}

function setCheckProgressActive(active) {
  checkProgress.active = !!active;
  const el = document.getElementById('checkProgressPopover');
  if (!el) return;
  if (checkProgress.active) {
    renderCheckProgressPopover();
    el.hidden = false;
  } else {
    el.hidden = true;
  }
}

function lookup(options = {}) {
  const input = document.getElementById("domainInput");
  const btn   = document.getElementById("lookupBtn");
  const screenshotBtn = document.getElementById("screenshotBtn");
  const dlBtn = document.getElementById("downloadBtn");
  const resultsEl = document.getElementById("results");
  const animateTopIntro = !!options.animateTopIntro;
  const domainSource = Object.prototype.hasOwnProperty.call(options, 'domainOverride') ? options.domainOverride : input.value;
  const domain = normalizeDomain(domainSource);
  input.value = domain;
  toggleClearBtn();
  // Reflect the queried domain in the document/tab title so browser
  // shortcuts/bookmarks created from this page show what was checked.
  updatePageTitle(domain);

  if (!domain) {
    setStatus(t('promptEnterDomain'));
    return;
  }

  if (!isValidDomain(domain)) {
    setStatus(t('promptEnterValidDomain'));
    return;
  }

  // Cancel any previous lookup's requests and start a new run
  const runId = ++activeLookup.runId;
  cancelInflightLookup();
  dnsRecordsFilterState.query = '';
  dnsRecordsFilterState.column = 'all';
  selectedDnsRecordKeys.clear();

  beginSectionAnimationCycle({ includeTopIntro: animateTopIntro });

  // Clear previous results while preserving the current top-bar actions
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches && resultsEl) {
    resultsEl.innerHTML = "";
  }
  setStatus("");
  if (dlBtn) {
    dlBtn.style.display = "";
    dlBtn.disabled = true;
  }
  lookupInProgress = true;

  const url = new URL(window.location.href);
  url.searchParams.set("domain", domain);
  url.searchParams.set(LANG_PARAM, currentLanguage);
  window.history.replaceState({}, "", url);

  // Keep Lookup clickable so another click can cancel/restart
  btn.disabled = false;
  if (screenshotBtn) screenshotBtn.disabled = true;
  btn.innerHTML = `${escapeHtml(t('gatheringData'))} <span class="spinner"></span>`;
  // setStatus("Checking " + escapeHtml(domain) + " &#x23F3;");

  function parseHttpError(r, bodyText) {
    const details = (bodyText || "").trim();
    return `HTTP ${r.status}${r.statusText ? " " + r.statusText : ""}${details ? ": " + details : ""}`;
  }

  async function fetchJson(path) {
    const controller = new AbortController();
    activeLookup.controllers.push(controller);
    try {
      let headers = {};
      const apiKey = (acsApiKey || '').trim();
      if (apiKey && !apiKey.startsWith('__')) {
        headers['X-Api-Key'] = apiKey;
      }
      headers = buildConsentRequestHeaders(headers);
      // Add cache-busting query param and explicit no-store cache mode so the browser
      // never serves stale DNS/WHOIS data from its HTTP cache or BFCache.
      headers['Cache-Control'] = 'no-cache';
      headers['Pragma'] = 'no-cache';
      const cacheBuster = "_=" + Date.now();
      const url = path + "?domain=" + encodeURIComponent(domain) + "&" + cacheBuster;
      const r = await fetch(url, { signal: controller.signal, headers: headers, cache: 'no-store' });
      if (!r.ok) {
        let body = "";
        try { body = await r.text(); } catch {}
        throw new Error(parseHttpError(r, body));
      }
      const raw = await r.arrayBuffer();
      const text = new TextDecoder('utf-8', { fatal: false }).decode(raw);
      return repairObjectStrings(JSON.parse(text));
    } finally {
      // Remove controller to avoid leaks
      activeLookup.controllers = (activeLookup.controllers || []).filter(c => c !== controller);
    }
  }

function showTopBarItem(element) {
  if (!element) return;
  element.style.display = '';
  if (document.body && document.body.classList.contains('section-fade-enabled') && element.classList && element.classList.contains('engage-top-item')) {
    element.classList.add('engage-top-in');
  }
}

function hideTopBarItem(element) {
  if (!element) return;
  element.style.display = 'none';
}

  function ensureResultObject() {
    if (!lastResult || typeof lastResult !== "object") {
      lastResult = {};
    }
    if (!lastResult._loaded) {
      lastResult._loaded = { base: false, mx: false, records: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false };
    }
    if (!lastResult._errors) {
      lastResult._errors = {};
    }
  }

  ensureResultObject();
  lastResult = {
    domain,
    _loaded: { base: false, mx: false, records: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false },
    _errors: {},
    guidance: [],
    acsReady: false
  };
  recomputeDerived(lastResult);
  render(lastResult);

  const requests = [
    { key: "base",  path: "/api/base"  },
    { key: "mx",    path: "/api/mx"    },
    { key: "records", path: "/api/records" },
    { key: "whois", path: "/api/whois" },
    { key: "dmarc", path: "/api/dmarc" },
    { key: "dkim",  path: "/api/dkim"  },
    { key: "cname", path: "/api/cname" },
    { key: "reputation", path: "/api/reputation" }
  ];

  // ---- Live check-progress popover state ----
  // Tracks the per-task status displayed in #checkProgressPopover so the
  // user can see exactly which of the eight parallel backend calls is
  // still in flight. We initialize the state here (per-lookup, not global)
  // so a fresh run always starts with a clean slate. The popover is
  // shown automatically while the lookup is active and hidden as soon
  // as setCheckProgressActive(false) is called from the .finally() below.
  //
  // When this lookup runs as part of the page intro (bootstrap ?domain=),
  // we defer revealing the popover until the staggered top-section
  // animation finishes so the popover slides in *after* the search box
  // settles instead of beating it to the screen. For ad-hoc lookups
  // (user clicks Lookup) the page is already settled, so reveal
  // immediately.
  checkProgress.runId = runId;
  checkProgress.tasks = requests.map(function (r) { return { key: r.key, status: 'pending' }; });
  if (animateTopIntro && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const introDelayMs = getTopSectionAnimationDurationMs();
    window.setTimeout(function () {
      // Drop the deferred reveal if a newer lookup has already started
      // (or this one was cancelled) so we never flash a stale popover.
      if (runId !== activeLookup.runId) return;
      setCheckProgressActive(true);
    }, introDelayMs);
  } else {
    setCheckProgressActive(true);
  }

  let savedHistory = false;
  let downloadShown = false;

  const tasks = requests.map(async ({ key, path }) => {
    try {
      const data = await fetchJson(path);

      // Ignore late results from older runs
      if (runId !== activeLookup.runId) return;

      ensureResultObject();
      if (key === 'whois') {
        // Namespace WHOIS fields to avoid collisions with DNS fields.
        lastResult.whoisLookupDomain = data.lookupDomain;
        lastResult.whoisSource = data.source;
        lastResult.whoisCreationDateUtc = data.creationDateUtc;
        lastResult.whoisExpiryDateUtc = data.expiryDateUtc;
        lastResult.whoisRegistrar = data.registrar;
        lastResult.whoisRegistrant = data.registrant;
        lastResult.whoisAgeDays = data.ageDays;
        lastResult.whoisAgeHuman = data.ageHuman;
        lastResult.whoisIsYoungDomain = data.isYoungDomain;
        lastResult.whoisIsVeryYoungDomain = data.isVeryYoungDomain;
        lastResult.whoisExpiryDays = data.expiryDays;
        lastResult.whoisIsExpired = data.isExpired;
        lastResult.whoisExpiryHuman = data.expiryHuman;
        lastResult.whoisExpiryUnavailableReason = data.expiryUnavailableReason || null;
        lastResult.whoisNewDomainThresholdDays = data.newDomainThresholdDays;
        lastResult.whoisNewDomainWarnThresholdDays = data.newDomainWarnThresholdDays;
        lastResult.whoisNewDomainErrorThresholdDays = data.newDomainErrorThresholdDays;
        lastResult.whoisError = data.error;
        lastResult.whoisRawText = data.rawWhoisText;
        lastResult.whoisRawRdapText = data.rawRdapText;
        lastResult.whoisRegistryWebForm = data.registryWebForm || null;
      } else if (key === 'reputation') {
        lastResult.reputation = data;
      } else if (key === 'records') {
        lastResult.dnsRecords = Array.isArray(data.records) ? data.records : [];
        lastResult.dnsRecordsError = data.error || null;
      } else {
        Object.assign(lastResult, data);
      }
      lastResult._loaded[key] = true;
      delete lastResult._errors[key];
      // Mark this task as completed in the live progress popover so the
      // user gets immediate feedback that this specific check is done.
      markCheckProgress(runId, key, 'done');

      if (!downloadShown) {
        const dlBtn2 = document.getElementById("downloadBtn");
        if (dlBtn2) {
          dlBtn2.style.display = "";
          dlBtn2.disabled = false;
        }
        downloadShown = true;
      }

      if (!savedHistory && key === "base") {
        saveHistory(domain);
        savedHistory = true;
      }

      recomputeDerived(lastResult);
      render(lastResult);
    } catch (err) {
      if (err && err.name === "AbortError") return;
      if (runId !== activeLookup.runId) return;

      const reason = (err && err.message) ? err.message : String(err);
      ensureResultObject();
      lastResult._loaded[key] = true;
      lastResult._errors[key] = reason;
      // Surface the per-task failure in the popover too so the user knows
      // which check failed without having to scroll through cards.
      markCheckProgress(runId, key, 'error');
      recomputeDerived(lastResult);
      render(lastResult);
    }
  });

  Promise.allSettled(tasks)
    .catch(() => {})
    .finally(() => {
      if (runId !== activeLookup.runId) return;
      lookupInProgress = false;
      btn.disabled = false;
      if (screenshotBtn) screenshotBtn.disabled = false;
      if (dlBtn) dlBtn.disabled = false;
      btn.innerHTML = t('lookup');
      // Lookup finished: hide the progress popover.
      setCheckProgressActive(false);
    });
}

// Parse the assembled results markup into an ordered list of section entries.
// Each card opens with `<div class="card" id="card-KEY">` followed by a header
// that contains an optional status badge `<span class="tag TAGCLASS">BADGE</span>`
// and a `<strong>TITLE</strong>`. We capture all three so navigation UI can show
// a colored status dot (matching the card's badge) plus the badge text. Parsing
// the final markup (instead of a hand-curated list) keeps every navigation aid
// perfectly in sync with the cards that actually rendered, in on-page order.
// The section-nav card itself is skipped so it never lists itself.
function parseSectionNavEntries(markup) {
  const entries = [];
  if (!markup) return entries;
  const seen = {};
  // Capture: (1) card key, (2) the header HTML up to and including the title's
  // </strong>. We then sub-parse the header chunk for the badge + title so the
  // optional tag span doesn't have to be modeled inline in one brittle regex.
  const re = /<div class="card"[^>]*\bid="card-([^"]+)"[^>]*>([\s\S]*?<strong[^>]*>[\s\S]*?<\/strong>)/g;
  let m;
  while ((m = re.exec(markup)) !== null) {
    const key = m[1];
    if (key === 'section-nav' || seen[key]) continue;
    const headerChunk = m[2];

    // Title: strip nested markup (icons, emphasis spans) so the label is clean.
    const titleMatch = /<strong[^>]*>([\s\S]*?)<\/strong>/.exec(headerChunk);
    const title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim() : '';
    if (!title) continue;

    // Status badge: the first `tag` span in the header (e.g. tag-pass / tag-fail
    // / tag-warn / tag-info). Used to color the nav dot and show the short
    // status word. Some cards (e.g. Domain) may not carry a badge.
    let tagClass = '';
    let badgeText = '';
    const tagMatch = /<span class="tag ([^"]*)"[^>]*>([\s\S]*?)<\/span>/.exec(headerChunk);
    if (tagMatch) {
      tagClass = tagMatch[1].replace(/\s+/g, ' ').trim();
      badgeText = tagMatch[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    }

    seen[key] = true;
    entries.push({ key, title, tagClass, badgeText });
  }
  return entries;
}

// Build the inline "Jump to section" navigation card (rendered at the top of
// the results). Uses the shared section entries so it matches the cards that
// actually rendered, each button showing a colored status dot plus, for real
// pass/warn/fail statuses, the short status word.
function buildSectionNavHtml(markup) {
  const entries = parseSectionNavEntries(markup);
  if (entries.length === 0) return '';

  const buttons = entries
    .map(e => {
      const dot = `<span class="section-nav-dot ${escapeHtml(e.tagClass)}" aria-hidden="true"></span>`;
      // Only surface the badge word for real pass/warn/fail statuses. Info-style
      // tags (READINESS TIPS, DOCS, TOOLS, NAVIGATE, LOOKED UP, ...) are section
      // labels rather than statuses, so showing them as badges just adds noise —
      // the colored dot is enough for those.
      const isStatusBadge = /\btag-(pass|warn|fail)\b/.test(e.tagClass);
      const badge = (isStatusBadge && e.badgeText)
        ? `<span class="section-nav-badge ${escapeHtml(e.tagClass)}">${escapeHtml(e.badgeText)}</span>`
        : '';
      return `<button type="button" class="section-nav-btn" onclick="scrollToSection('${e.key}')" title="${escapeHtml(e.title)}">` +
        `${dot}<span class="section-nav-label">${escapeHtml(e.title)}</span>${badge}</button>`;
    })
    .join('');

  return `
  <div class="card section-nav-card hide-on-screenshot" id="card-section-nav">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('jumpToTag'))}</span>
      <strong>${escapeHtml(t('jumpToSection'))}</strong>
    </div>
    <div class="card-content">
      <div class="section-nav-grid">${buttons}</div>
    </div>
  </div>`;
}

// Tracks the IntersectionObserver powering the floating rail scrollspy so it can
// be disconnected and rebuilt on each new render.
let sectionRailObserver = null;
let sectionRailVisibility = {};
// Ordered list of section keys (top-to-bottom) for page-extreme highlighting,
// and a guard so the scroll/resize scrollspy listener is only bound once.
let sectionRailKeys = [];
let sectionRailScrollHandlerBound = false;
// Persisted (functional preference) collapsed state for the floating rail. When
// collapsed the rail tucks flush to the left edge as a slim vertical tab that
// only shows the "Jump to Section" label + an expand arrow.
const SECTION_RAIL_COLLAPSED_KEY = 'acsSectionRailCollapsed';

// Populate the floating left-hand section rail from the shared section entries
// and wire up an IntersectionObserver scrollspy that highlights whichever
// section is currently in view. The rail lives outside #results (see
// 20a-HtmlScriptSetup.ps1) so it can be position:fixed and persist while the
// results scroll beneath it. Hidden automatically when there are no sections.
function buildSectionRail(markup) {
  const rail = document.getElementById('sectionRail');
  if (!rail) return;

  // Tear down any previous observer before rebuilding for the new results.
  if (sectionRailObserver) {
    sectionRailObserver.disconnect();
    sectionRailObserver = null;
  }
  sectionRailVisibility = {};

  const entries = parseSectionNavEntries(markup);
  if (entries.length === 0) {
    rail.innerHTML = '';
    rail.classList.remove('section-rail-visible');
    return;
  }

  const items = entries
    .map(e => {
      const dot = `<span class="section-rail-dot ${escapeHtml(e.tagClass)}" aria-hidden="true"></span>`;
      return `<li><a href="#card-${escapeHtml(e.key)}" class="section-rail-link" data-key="${escapeHtml(e.key)}" ` +
        `onclick="event.preventDefault(); scrollToSection('${e.key}');" title="${escapeHtml(e.title)}">` +
        `${dot}<span class="section-rail-label">${escapeHtml(e.title)}</span></a></li>`;
    })
    .join('');

  rail.innerHTML = `
    <div class="section-rail-header">
      <span class="section-rail-title">${escapeHtml(t('jumpToSection'))}</span>
      <button type="button" class="section-rail-toggle" onclick="toggleSectionRailCollapsed()"
        aria-label="${escapeHtml(t('jumpToSectionCollapse'))}" title="${escapeHtml(t('jumpToSectionCollapse'))}">
        <span class="section-rail-toggle-icon" aria-hidden="true">&#x276E;</span>
      </button>
    </div>
    <ul class="section-rail-list">${items}</ul>
    <button type="button" class="section-rail-expand" onclick="toggleSectionRailCollapsed()"
      aria-label="${escapeHtml(t('jumpToSectionExpand'))}" title="${escapeHtml(t('jumpToSectionExpand'))}">
      <span class="section-rail-expand-label">${escapeHtml(t('jumpToSection'))}</span>
      <span class="section-rail-expand-icon" aria-hidden="true">&#x276F;</span>
    </button>`;
  rail.classList.add('section-rail-visible');

  // Restore the persisted collapsed/expanded state so it survives re-renders and
  // page reloads (functional preference; gated behind cookie consent).
  applySectionRailCollapsedState(rail);

  // Remember the on-page order of keys so the scrollspy can force the first/last
  // section active at the very top/bottom of the page (where the biased active
  // band below can't otherwise reach the edge cards).
  sectionRailKeys = entries.map(e => e.key);

  // Scrollspy: observe each card and mark the rail link for whichever card is
  // most prominently in view as active. We track per-card intersection ratios
  // and pick the highest so the highlight follows the dominant on-screen card.
  const observer = new IntersectionObserver((observed) => {
    observed.forEach(entry => {
      const id = entry.target.id; // e.g. "card-spf"
      const key = id.replace(/^card-/, '');
      sectionRailVisibility[key] = entry.isIntersecting ? entry.intersectionRatio : 0;
    });
    updateActiveSectionRailLink();
  }, {
    // Bias the active band toward the upper-middle of the viewport so the
    // highlight lands on the section the user is actually reading.
    rootMargin: '-20% 0px -55% 0px',
    threshold: [0, 0.25, 0.5, 0.75, 1]
  });

  entries.forEach(e => {
    const card = document.getElementById(`card-${e.key}`);
    if (card) observer.observe(card);
  });
  sectionRailObserver = observer;

  // The IntersectionObserver alone can't highlight the last section when the
  // page is scrolled fully to the bottom (no content below to push the final
  // cards into the biased active band) or the first section at the very top.
  // A lightweight scroll/resize listener fills those gaps. Registered once.
  if (!sectionRailScrollHandlerBound) {
    window.addEventListener('scroll', updateActiveSectionRailLink, { passive: true });
    window.addEventListener('resize', updateActiveSectionRailLink, { passive: true });
    sectionRailScrollHandlerBound = true;
  }

  // Establish an initial highlight without waiting for a scroll event.
  updateActiveSectionRailLink();
}

// Apply the persisted collapsed/expanded state to the rail element. When
// collapsed the rail gains .section-rail-collapsed, which CSS uses to tuck it
// flush against the left edge as a slim "Jump to Section" tab. Reads are gated
// behind functional cookie consent; without consent the rail defaults to
// expanded.
function applySectionRailCollapsedState(rail) {
  const target = rail || document.getElementById('sectionRail');
  if (!target) return;
  const collapsed = consentAwareGetItem(SECTION_RAIL_COLLAPSED_KEY, 'functional') === '1';
  target.classList.toggle('section-rail-collapsed', collapsed);
  syncSectionRailToggleLabels(target, collapsed);
}

// Flip the rail between expanded and collapsed, persisting the new state so it
// is remembered across renders and reloads (functional preference).
function toggleSectionRailCollapsed() {
  const rail = document.getElementById('sectionRail');
  if (!rail) return;
  const collapsed = !rail.classList.contains('section-rail-collapsed');
  rail.classList.toggle('section-rail-collapsed', collapsed);
  consentAwareSetItem(SECTION_RAIL_COLLAPSED_KEY, collapsed ? '1' : '0', 'functional');
  syncSectionRailToggleLabels(rail, collapsed);
}

// Keep the collapse/expand control accessible labels in sync with the current
// state so screen-reader users get the correct "collapse"/"expand" action text.
function syncSectionRailToggleLabels(rail, collapsed) {
  const collapseBtn = rail.querySelector('.section-rail-toggle');
  if (collapseBtn) {
    const label = collapsed ? t('jumpToSectionExpand') : t('jumpToSectionCollapse');
    collapseBtn.setAttribute('aria-label', label);
    collapseBtn.setAttribute('title', label);
  }
}

// Highlight the rail link for the section currently at the TOP of the viewport.
// We deliberately use a top-anchored algorithm instead of "largest visible
// area": the active section is the last card whose top edge has scrolled to (or
// above) a thin activation line near the top of the viewport. This matches what
// scrollToSection() does (it aligns a card's top just below the viewport top),
// so clicking e.g. "TXT" highlights TXT rather than a taller neighbour like
// DKIM1 that happens to occupy more pixels below it.
function updateActiveSectionRailLink() {
  const rail = document.getElementById('sectionRail');
  if (!rail) return;

  // Activation line: a small distance below the very top of the viewport. It is
  // kept just below scrollToSection()'s 16px top offset so that immediately
  // after a click the targeted card's top (which lands at ~16px) is already at
  // or above the line and therefore selected.
  const ACTIVATION_LINE = 24;

  let bestKey = null;
  // Walk sections in on-page order and keep the last one whose top is at or
  // above the activation line. That is the section occupying the top of the
  // screen right now.
  for (let i = 0; i < sectionRailKeys.length; i++) {
    const key = sectionRailKeys[i];
    const card = document.getElementById(`card-${key}`);
    if (!card) continue;
    const top = card.getBoundingClientRect().top;
    if (top <= ACTIVATION_LINE) {
      bestKey = key;
    } else {
      // Cards are rendered top-to-bottom, so once a card starts below the line
      // every later card is also below it.
      break;
    }
  }

  // Page-extreme overrides. Use a small tolerance so "close enough" to the edge
  // still counts (smooth-scroll easing and sub-pixel rounding rarely land exact).
  const doc = document.documentElement;
  const scrollTop = window.pageYOffset || doc.scrollTop || 0;
  const maxScroll = (doc.scrollHeight || 0) - window.innerHeight;
  const atBottom = maxScroll > 0 && scrollTop >= maxScroll - 4;
  const atTop = scrollTop <= 4;

  if (atBottom && sectionRailKeys.length) {
    // At the very bottom the last card's top may never reach the activation
    // line (not enough content below to scroll it up), so force the last one.
    bestKey = sectionRailKeys[sectionRailKeys.length - 1];
  } else if (atTop && sectionRailKeys.length) {
    bestKey = sectionRailKeys[0];
  } else if (!bestKey && sectionRailKeys.length) {
    // Above the first card's activation point: default to the first section.
    bestKey = sectionRailKeys[0];
  }

  const links = rail.querySelectorAll('.section-rail-link');
  links.forEach(link => {
    const isActive = !!bestKey && link.getAttribute('data-key') === bestKey;
    link.classList.toggle('section-rail-link-active', isActive);
    if (isActive) {
      // Keep the active link visible if the rail itself overflows/scrolls.
      if (typeof link.scrollIntoView === 'function') {
        link.scrollIntoView({ block: 'nearest' });
      }
    }
  });
}

function scrollToSection(key) {
  if (!key) return;
  const el = document.getElementById(`card-${key}`);
  if (el) {
    // If the card was collapsed, open it
    const header = el.querySelector('.card-header');
    if (header && header.classList.contains('collapsed-header')) {
        toggleCard(header);
    }

    // Align to the TOP of the card (not center): tall cards such as the DNS
    // records table are taller than the viewport, so centering them would push
    // the card header and first rows off-screen. We scroll the card's top edge
    // to just below the top of the viewport, with a small offset for breathing
    // room. Computed manually (rather than scrollIntoView block:'start') so the
    // offset is consistent across browsers.
    const offset = 16;
    const top = el.getBoundingClientRect().top + (window.pageYOffset || document.documentElement.scrollTop || 0) - offset;
    window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });

    // Reset animation if already playing
    el.classList.remove('flash-active');
    void el.offsetWidth; // Trigger reflow
    el.classList.add('flash-active');

    setTimeout(() => {
      el.classList.remove('flash-active');
    }, 2400);
  }
}

function showTopBarItem(element) {
  if (!element) return;
  element.style.display = '';
  if (document.body && document.body.classList.contains('section-fade-enabled') && element.classList && element.classList.contains('engage-top-item')) {
    element.classList.add('engage-top-in');
  }
}

function hideTopBarItem(element) {
  if (!element) return;
  element.style.display = 'none';
}

let topSectionAnimationTimers = [];
let resultSectionAnimationTimers = [];
let resultSectionRevealTimer = null;
let pendingResultsMarkup = null;
let resultSectionsRevealAtMs = 0;
let resultSectionsAnimationPending = false;
const TOP_BUTTON_ANIMATION_START_MS = 80;
const TOP_BUTTON_STAGGER_MS = 110;
const TOP_BUTTON_FADE_DURATION_MS = 620;
const TOP_SECTION_ANIMATION_START_MS = 120;
const TOP_SECTION_ANIMATION_STAGGER_MS = 180;
const TOP_SECTION_FADE_DURATION_MS = 880;
const RESULT_SECTION_REVEAL_DELAY_MS = 180;
const RESULT_SECTION_STAGGER_MS = 140;

function getVisibleTopAnimationItems() {
  return Array.from(document.querySelectorAll('.engage-top-item')).filter(el => {
    if (!el) return false;
    const computed = window.getComputedStyle(el);
    return computed.display !== 'none';
  });
}

function getVisibleEngageSections() {
  return Array.from(document.querySelectorAll('.engage-section')).filter(el => {
    if (!el) return false;
    const computed = window.getComputedStyle(el);
    return computed.display !== 'none';
  });
}

function getTopSectionAnimationDurationMs() {
  const topItemCount = getVisibleTopAnimationItems().length;
  const sectionCount = getVisibleEngageSections().length;
  const topItemsDuration = topItemCount > 0
    ? TOP_BUTTON_ANIMATION_START_MS + ((topItemCount - 1) * TOP_BUTTON_STAGGER_MS) + TOP_BUTTON_FADE_DURATION_MS
    : 0;
  const sectionsDuration = sectionCount > 0
    ? topItemsDuration + TOP_SECTION_ANIMATION_START_MS + ((sectionCount - 1) * TOP_SECTION_ANIMATION_STAGGER_MS) + TOP_SECTION_FADE_DURATION_MS
    : topItemsDuration;
  return Math.max(topItemsDuration, sectionsDuration);
}

function clearResultSectionAnimationTimers() {
  resultSectionAnimationTimers.forEach(timer => clearTimeout(timer));
  resultSectionAnimationTimers = [];
  if (resultSectionRevealTimer) {
    clearTimeout(resultSectionRevealTimer);
    resultSectionRevealTimer = null;
  }
}

function beginSectionAnimationCycle(options = {}) {
  const includeTopIntro = !!options.includeTopIntro;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const results = document.getElementById('results');
  if (!results) return;

  if (includeTopIntro) {
    animateTopSections();
  }

  clearResultSectionAnimationTimers();
  pendingResultsMarkup = null;
  resultSectionsRevealAtMs = performance.now() + (includeTopIntro ? getTopSectionAnimationDurationMs() : 0) + RESULT_SECTION_REVEAL_DELAY_MS;
  resultSectionsAnimationPending = true;
  results.classList.add('results-fade-out');
}

function animateResultSectionsIn() {
  const results = document.getElementById('results');
  if (!results) return;

  clearResultSectionAnimationTimers();
  results.classList.remove('results-fade-out');

  const cards = Array.from(results.children).filter(el => el && el.classList && el.classList.contains('card'));
  if (cards.length === 0) return;

  cards.forEach(card => {
    card.classList.remove('result-card-in');
    card.classList.add('result-card-prep');
  });

  void results.offsetWidth;

  cards.forEach((card, index) => {
    const timer = window.setTimeout(() => {
      card.classList.add('result-card-in');
    }, index * RESULT_SECTION_STAGGER_MS);
    resultSectionAnimationTimers.push(timer);
  });
}

function renderResultsMarkup(markup) {
  const results = document.getElementById('results');
  if (!results) return;

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  pendingResultsMarkup = markup;

  const applyMarkup = (animateCards) => {
    if (pendingResultsMarkup === null) return;

    clearResultSectionAnimationTimers();
    results.innerHTML = pendingResultsMarkup;
    pendingResultsMarkup = null;

    if (animateCards) {
      animateResultSectionsIn();
    } else {
      results.classList.remove('results-fade-out');
    }

    filterDnsRecordsTable();

    startLoadingDotAnimations();
  };

  if (reducedMotion) {
    resultSectionsAnimationPending = false;
    applyMarkup(false);
    return;
  }

  if (resultSectionsAnimationPending) {
    if (resultSectionRevealTimer) {
      clearTimeout(resultSectionRevealTimer);
    }

    const delay = Math.max(0, resultSectionsRevealAtMs - performance.now());
    resultSectionRevealTimer = window.setTimeout(() => {
      resultSectionRevealTimer = null;
      resultSectionsAnimationPending = false;
      applyMarkup(true);
    }, delay);
    return;
  }

  applyMarkup(false);
}

function animateTopSections() {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const body = document.body;
  if (!body) return;

  const topItems = getVisibleTopAnimationItems();
  const sections = getVisibleEngageSections();

  if (topItems.length === 0 && sections.length === 0) return;

  topSectionAnimationTimers.forEach(timer => clearTimeout(timer));
  topSectionAnimationTimers = [];

  body.classList.add('section-fade-enabled');
  topItems.forEach(el => {
    el.classList.remove('engage-top-in');
  });
  sections.forEach(el => {
    el.classList.remove('engage-in');
  });

  void body.offsetWidth;

  topItems.forEach((el, index) => {
    const timer = window.setTimeout(() => {
      el.classList.add('engage-top-in');
    }, TOP_BUTTON_ANIMATION_START_MS + (index * TOP_BUTTON_STAGGER_MS));
    topSectionAnimationTimers.push(timer);
  });

  const topItemsDuration = topItems.length > 0
    ? TOP_BUTTON_ANIMATION_START_MS + ((topItems.length - 1) * TOP_BUTTON_STAGGER_MS) + TOP_BUTTON_FADE_DURATION_MS
    : 0;

  sections.forEach((el, index) => {
    const timer = window.setTimeout(() => {
      el.classList.add('engage-in');
    }, topItemsDuration + TOP_SECTION_ANIMATION_START_MS + (index * TOP_SECTION_ANIMATION_STAGGER_MS));
    topSectionAnimationTimers.push(timer);
  });
}

function card(title, value, label, cls, key, showCopy = true, titleSuffixHtml = '', appendHtml = '', bodyHtml = '') {
  const cardId = key ? `card-${key}` : '';
  const checkedDomain = (lastResult && lastResult.domain) ? String(lastResult.domain) : '';
  // Always escape the title text to prevent XSS via crafted DNS responses.
  // Use titleSuffixHtml for trusted HTML additions (e.g., info-dot buttons, links).
  // appendHtml is rendered after the value div and is trusted (caller is
  // responsible for escaping any user-derived content it embeds). It is
  // intentionally OUTSIDE the field-${key} div so that the Copy button --
  // which reads `innerText` of that div -- skips the appended content (used
  // for warning/notice bubbles that should not pollute the clipboard).
  // bodyHtml, when provided, REPLACES the auto-escaped plain-text body so a
  // caller can render a rich layout (table, grid, etc.). The caller is then
  // responsible for embedding properly escaped user-derived content. The
  // resulting `innerText` of that rich layout is what the Copy button copies,
  // so the rendered text should still read sensibly when stripped of markup.
  const safeTitle = applyCheckedDomainEmphasis(escapeHtml(title), checkedDomain);
  const safeValue = applyCheckedDomainEmphasis(escapeHtml(value || t('noRecordsAvailable')), checkedDomain);
  const bodyContent = bodyHtml ? bodyHtml : safeValue;
  const translatedLabel = label ? escapeHtml(translateBadge(label)) : "";
  return `
  <div class="card"${cardId ? ` id="${cardId}"` : ''}>
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      ${label ? `<span class="tag ${cls}">${translatedLabel}</span>` : ""}
      <strong>${safeTitle}</strong>${titleSuffixHtml ? ' ' + titleSuffixHtml : ''}
      ${showCopy ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, '${key}')">${escapeHtml(t('copy'))}</button>` : ""}
    </div>
    <div id="field-${key}" class="code card-content">${bodyContent}</div>${appendHtml ? appendHtml : ''}
  </div>`;
}

// Walk the recursive spfAnalysis tree (server-built by Get-SpfNestedAnalysis) and
// produce a flat array of rows describing every include / redirect target that was
// resolved during expansion, including the resolved TXT record text and the parent
// node that referenced it. Used to render the SPF Expansion Records table inside
// its own sibling card so the main DNS records table can stay scoped to the
// queried domain.
function flattenSpfExpansion(analysis, parentDomain, depth, out) {
  if (!analysis || !out) return;
  // Helper: read a numeric field off a nested analysis node safely. The server
  // emits lookupTerms (direct at that node) and totalLookupTerms (subtree sum).
  const readInt = (obj, key) => {
    if (!obj) return null;
    const v = obj[key];
    if (v === null || typeof v === 'undefined') return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  const includes = Array.isArray(analysis.includes) ? analysis.includes : [];
  for (const inc of includes) {
    if (!inc) continue;
    // Each include mechanism costs 1 DNS lookup itself plus any lookup-style
    // terms found inside the resolved record. We surface the subtree total so
    // the UI can show the contribution of this branch against the 10-lookup
    // limit.
    const ownLookups = readInt(inc.analysis, 'lookupTerms');
    const subtreeLookups = readInt(inc.analysis, 'totalLookupTerms');
    out.push({
      depth: depth,
      parent: parentDomain || '',
      mechanism: 'include',
      target: String(inc.domain || ''),
      record: inc.record ? String(inc.record) : '',
      error: inc.error ? String(inc.error) : '',
      ownLookups: ownLookups,
      subtreeLookups: subtreeLookups
    });
    if (inc.analysis) {
      flattenSpfExpansion(inc.analysis, String(inc.domain || ''), depth + 1, out);
    }
  }
  const redirect = analysis.redirect;
  if (redirect) {
    const rOwnLookups = readInt(redirect.analysis, 'lookupTerms');
    const rSubtreeLookups = readInt(redirect.analysis, 'totalLookupTerms');
    out.push({
      depth: depth,
      parent: parentDomain || '',
      mechanism: 'redirect',
      target: String(redirect.domain || ''),
      record: redirect.record ? String(redirect.record) : '',
      error: redirect.error ? String(redirect.error) : '',
      ownLookups: rOwnLookups,
      subtreeLookups: rSubtreeLookups
    });
    if (redirect.analysis) {
      flattenSpfExpansion(redirect.analysis, String(redirect.domain || ''), depth + 1, out);
    }
  }
}

// Build the inner HTML for the SPF Expansion Records card body. Returns either an
// HTML <table> with one row per resolved include/redirect target, or a short
// localized note explaining that the SPF record has no expansion to show.
function buildSpfExpansionCardHtml(analysis, queriedDomain) {
  const rows = [];
  if (analysis) {
    flattenSpfExpansion(analysis, String(queriedDomain || ''), 1, rows);
  }

  if (rows.length === 0) {
    return `<div class="code">${escapeHtml(t('spfExpansionEmpty'))}</div>`;
  }

  // Pull the root SPF chain's total DNS-lookup count so we can tell the user
  // at a glance whether the record stays within the SPF 10-lookup limit.
  const rootTotalLookups = (analysis && analysis.totalLookupTerms !== null && typeof analysis.totalLookupTerms !== 'undefined' && Number.isFinite(Number(analysis.totalLookupTerms)))
    ? Number(analysis.totalLookupTerms)
    : null;
  const exceededLimit = rootTotalLookups !== null && rootTotalLookups > 10;

  // The table uses auto layout so Parent/Target columns expand to fit the
  // longest domain on a single line. The Resolved TXT record column is
  // constrained via CSS (.spf-col-record) so it wraps instead of dragging
  // the table to ridiculous widths. A scroll wrapper around the table lets
  // very wide SPF chains scroll horizontally on narrow viewports.
  //
  // Adds an "Explain" column at the end with a small button per row. Clicking
  // it expands a hidden sibling <tr> containing the SPF Explained breakdown
  // (Prefix / Type / Value / PrefixDesc / Description) for THAT row's
  // resolved SPF record. This gives users a per-record decomposition without
  // having to copy the record out and run the queried-domain SPF Explained
  // toggle separately. The expanded row is purely client-side and reuses
  // buildSpfExplainedHtml so the formatting stays in sync with the SPF card.
  const header = `
    <thead>
      <tr>
        <th style="text-align:center;">${escapeHtml(t('spfExpansionDepth'))}</th>
        <th>${escapeHtml(t('spfExpansionMechanism'))}</th>
        <th>${escapeHtml(t('spfExpansionParent'))}</th>
        <th>${escapeHtml(t('spfExpansionTarget'))}</th>
        <th style="text-align:right;" title="${escapeHtml(t('spfExpansionLookupsHint'))}">${escapeHtml(t('spfExpansionLookups'))}</th>
        <th>${escapeHtml(t('spfExpansionRecord'))}</th>
        <th class="spf-col-explain" aria-label="${escapeHtml(t('spfExpansionExplainTooltip'))}">${escapeHtml(t('spfExpansionExplainColumn'))}</th>
      </tr>
    </thead>`;

  // Track the previous row's target so nested rows can dim a repeated parent
  // value (chain continuation) to reduce visual noise.
  let previousTarget = '';
  const body = rows.map((row, idx) => {
    const recordCellHtml = row.error
      ? `<span style="color: var(--fail-fg, #d33);">${escapeHtml(row.error)}</span>`
      : (row.record ? escapeHtml(row.record) : `<span style="opacity:0.6;">${escapeHtml(t('noRecordsAvailable'))}</span>`);

    // Resolve the per-row lookup count for display. Prefer the OWN-node
    // count (lookup-style terms found directly inside this node's resolved
    // record) so the column reflects this row's real contribution to the
    // 10-lookup budget. The subtree total is intentionally NOT used here
    // because it double-counts as you walk up the chain (root subtree =
    // sum of every descendant subtree). The card-level summary line still
    // reports the chain-wide total, which is what users compare to 10.
    let lookupsValue = null;
    if (row.ownLookups !== null && typeof row.ownLookups !== 'undefined') {
      lookupsValue = Number(row.ownLookups);
    } else if (row.subtreeLookups !== null && typeof row.subtreeLookups !== 'undefined') {
      lookupsValue = Number(row.subtreeLookups);
    }
    let lookupsCellHtml = '\u2014';
    if (lookupsValue !== null && Number.isFinite(lookupsValue)) {
      // Heavy-contributor flag: any single record introducing >=3 lookup
      // terms by itself is worth highlighting since the SPF budget is only
      // 10 across the whole chain.
      const heavy = lookupsValue >= 3;
      lookupsCellHtml = heavy
        ? `<span class="spf-lookups-heavy">${escapeHtml(String(lookupsValue))}</span>`
        : escapeHtml(String(lookupsValue));
    }

    // Depth indent: render an em-dash arrow per depth level so the hierarchy
    // is visible in the Target column without requiring readers to reconcile
    // Parent/Target manually.
    const indentDepth = Math.max(0, Number(row.depth) - 1);
    const indentHtml = indentDepth > 0
      ? `<span class="spf-chain-arrow" aria-hidden="true">${'&nbsp;&nbsp;'.repeat(indentDepth - 1)}&#x21B3;</span>`
      : '';

    // Dim the Parent cell when it equals the target of the previous row, i.e.
    // when this row is a direct child of the row immediately above it.
    const parentText = escapeHtml(row.parent || '');
    const parentRepeats = row.parent && previousTarget && row.parent === previousTarget;
    const parentCellHtml = parentRepeats
      ? `<span class="spf-parent-repeat" title="${escapeHtml(t('spfExpansionParentRepeatHint'))}">${parentText}</span>`
      : parentText;

    previousTarget = row.target || '';

    // Per-row Explain button. Only render an interactive control when the
    // row carries a usable SPF record (no error, non-empty record string).
    // The detail row directly below shares the same id suffix so
    // toggleSpfExpansionExplain() can find it by id.
    const detailId = `spfExpansionExplain-${idx}`;
    const hasRecord = !row.error && row.record && /^v=spf1\b/i.test(String(row.record).trim());
    const explainBtnHtml = hasRecord
      ? `<button type="button" class="spf-expansion-explain-btn hide-on-screenshot" onclick="toggleSpfExpansionExplain(this, '${detailId}')" title="${escapeHtml(t('spfExpansionExplainTooltip'))}">${escapeHtml(t('spfExpansionExplain'))}</button>`
      : '';

    // Hidden details row. The colspan covers every column so the explained
    // table renders edge-to-edge under the row it explains. buildSpfExplainedHtml
    // already produces the full record box, breakdown table, and legend.
    const detailRowHtml = hasRecord
      ? `<tr id="${detailId}" class="spf-expansion-explain-row" style="display:none;"><td colspan="7" class="spf-expansion-explain-cell">${buildSpfExplainedHtml(row.record)}</td></tr>`
      : '';

    // data-spf-mech / data-spf-target let setSpfExpansionHighlight find every
    // matching `.spf-record-token[data-spf-type=...][data-spf-value=...]`
    // anywhere on the page so hovering this row lights up the corresponding
    // include/redirect token inside any open SPF Explained panel (the
    // queried-domain panel and the per-row Explain panels).
    const safeMech = escapeHtml(String(row.mechanism || ''));
    const safeTarget = escapeHtml(String(row.target || ''));
    return `
      <tr data-spf-mech="${safeMech}" data-spf-target="${safeTarget}" onmouseenter="setSpfExpansionHighlight(this, true)" onmouseleave="setSpfExpansionHighlight(this, false)">
        <td class="spf-col-depth">${escapeHtml(String(row.depth))}</td>
        <td class="spf-col-mechanism">${escapeHtml(row.mechanism)}</td>
        <td class="spf-col-parent">${parentCellHtml}</td>
        <td class="spf-col-target">${indentHtml}${escapeHtml(row.target)}</td>
        <td class="spf-col-lookups">${lookupsCellHtml}</td>
        <td class="spf-col-record">${recordCellHtml}</td>
        <td class="spf-col-explain">${explainBtnHtml}</td>
      </tr>${detailRowHtml}`;
  }).join('');

  const rowsCountHtml = `<div style="font-size:12px; opacity:0.75;">${escapeHtml(t('spfExpansionRowsCount', { count: String(rows.length) }))}</div>`;
  let limitSummaryHtml = '';
  if (rootTotalLookups !== null) {
    const statusText = exceededLimit ? t('spfExpansionExceededLimit') : t('spfExpansionWithinLimit');
    const statusColor = exceededLimit ? 'var(--fail-fg, #d33)' : 'var(--pass-fg, #2a8f2a)';
    limitSummaryHtml = `<div style="font-size:12px; margin-top:2px; color:${statusColor};">${escapeHtml(t('spfExpansionLookupSummary', { total: String(rootTotalLookups), status: statusText }))}</div>`;
  }
  const summary = `<div style="margin-bottom:6px;">${rowsCountHtml}${limitSummaryHtml}</div>`;
  return `${summary}<div class="spf-expansion-scroll"><table class="mx-table spf-expansion-table">${header}<tbody>${body}</tbody></table></div>`;
}

// Parse a single SPF record string into a flat array of mechanism descriptors.
// Each descriptor is shaped { qualifier, type, value, raw } where:
//   - qualifier: '+', '-', '~', '?' or '' (empty when no qualifier prefix was set).
//     Note: the SPF spec defaults to '+' (Pass) when no qualifier is present.
//   - type     : the canonical mechanism/modifier keyword, lowercased.
//                Mechanisms (RFC 7208 \u00A75): all, include, a, mx, ptr, ip4, ip6, exists.
//                Modifiers  (RFC 7208 \u00A76): redirect, exp.
//                The synthetic type 'v'   is emitted for the leading 'v=spf1' tag so the
//                Explained table can describe the record version on the very first row.
//                The synthetic type 'unknown' is emitted for tokens that match no known
//                SPF keyword so the table can still surface them rather than silently
//                dropping malformed input.
//   - value    : the right-hand side of the mechanism (after ':' or '='), or '' when
//                the mechanism has no value (e.g., 'all', bare 'a', bare 'mx').
//   - raw      : the original token as it appeared in the record, for diagnostics.
//
// This parser is purely textual; it does NOT perform DNS lookups. The expanded
// SPF chain (with live DNS results) is rendered by the sibling
// "SPF Expansion Records" card via buildSpfExpansionCardHtml. The Explained
// view is intentionally a per-record decomposition mirroring the MXToolbox
// "SPF Record Lookup" Prefix / Type / Value / PrefixDesc / Description layout.

// Module-level counter used to mint unique ids for the per-row CIDR detail
// rows generated by buildSpfExplainedHtml. Multiple SPF Explained panels can
// coexist on the page (the queried-domain panel plus every per-row Expansion
// Explain panel) and each ip4/ip6 row gets its own toggleable detail row, so
// the ids must be globally unique to keep toggleSpfCidrDetail's
// document.getElementById lookup deterministic.
let __spfCidrDetailCounter = 0;

function parseSpfMechanisms(spfRecord) {
  const out = [];
  if (!spfRecord) return out;

  // The card body sometimes embeds a localized "ACS Outlook requirement satisfied"
  // verdict joined to the raw record with a blank line. Take only the first line
  // so the parser sees pure SPF tokens and not localized prose.
  const firstLine = String(spfRecord).split(/\r?\n/)[0] || '';
  const tokens = firstLine.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return out;

  for (const tok of tokens) {
    // The 'v=spf1' tag is technically a key=value pair, not a mechanism. Emit
    // it as a synthetic 'v' row so the Explained table can describe the SPF
    // version on the first line (matches MXToolbox's presentation).
    if (/^v=/i.test(tok)) {
      out.push({ qualifier: '', type: 'v', value: tok.replace(/^v=/i, ''), raw: tok });
      continue;
    }

    // 'redirect=' and 'exp=' are modifiers, not mechanisms, and never carry a
    // qualifier prefix. Treat them separately so we don't strip a leading '-'
    // from a domain name that happens to start with a hyphen.
    if (/^redirect=/i.test(tok)) {
      out.push({ qualifier: '', type: 'redirect', value: tok.replace(/^redirect=/i, ''), raw: tok });
      continue;
    }
    if (/^exp=/i.test(tok)) {
      out.push({ qualifier: '', type: 'exp', value: tok.replace(/^exp=/i, ''), raw: tok });
      continue;
    }

    // Mechanism: optional qualifier (+, -, ~, ?), then a keyword, then an
    // optional ':value' (or no value at all for 'all', bare 'a', bare 'mx').
    const m = tok.match(/^([+\-~?])?(all|include|a|mx|ptr|ip4|ip6|exists)(?::(.*))?$/i);
    if (m) {
      out.push({
        qualifier: m[1] || '',
        type: m[2].toLowerCase(),
        value: typeof m[3] === 'undefined' ? '' : m[3],
        raw: tok
      });
      continue;
    }

    // Unknown token. Surface it so users notice typos / malformed records.
    out.push({ qualifier: '', type: 'unknown', value: '', raw: tok });
  }

  return out;
}

// Translate an SPF qualifier character (+/-/~/?) into a short label suitable
// for the "PrefixDesc" column of the Explained table. Returns '' when the
// mechanism does not carry a qualifier (modifiers like redirect=, and the
// synthetic 'v' row).
//
// Note on `-` => 'HardFail': the SPF spec only defines four qualifiers
// (Pass/Fail/SoftFail/Neutral), but MXToolbox and most receiver
// documentation refer to `-` as "HardFail" to clearly distinguish it from
// `~all` (SoftFail). We surface the "HardFail" wording in the UI so users
// can immediately tell a strict `-all` apart from a lenient `~all`.
function getSpfQualifierDescription(qualifier) {
  switch (qualifier) {
    case '+': return t('spfPrefixPass');
    case '-': return t('spfPrefixFail');
    case '~': return t('spfPrefixSoftFail');
    case '?': return t('spfPrefixNeutral');
    default:  return '';
  }
}

// Translate an SPF mechanism/modifier keyword into a one-line human-readable
// description for the rightmost "Description" column. Falls back to the
// 'unknown' description for tokens parseSpfMechanisms could not classify.
function getSpfMechanismDescription(type) {
  switch (type) {
    case 'v':        return t('spfDescVersion');
    case 'all':      return t('spfDescAll');
    case 'include':  return t('spfDescInclude');
    case 'a':        return t('spfDescA');
    case 'mx':       return t('spfDescMx');
    case 'ptr':      return t('spfDescPtr');
    case 'ip4':      return t('spfDescIp4');
    case 'ip6':      return t('spfDescIp6');
    case 'exists':   return t('spfDescExists');
    case 'redirect': return t('spfDescRedirect');
    case 'exp':      return t('spfDescExp');
    default:         return t('spfDescUnknown');
  }
}

// Parse an IPv4 CIDR (e.g., "40.107.0.0/16") or bare address into structured
// pieces used by formatSpfCidrInfo. Returns null when the input is not a
// well-formed IPv4 value, so the caller can decide to skip the info button
// for tokens like include:domain or unparseable malformed addresses.
function parseSpfIpv4(value) {
  if (!value) return null;
  const m = String(value).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some(n => n < 0 || n > 255)) return null;
  // Default to /32 when no prefix is supplied so a bare address still shows
  // a single-host range and a 255.255.255.255 mask.
  let prefix = (typeof m[5] === 'undefined') ? 32 : parseInt(m[5], 10);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  // Convert to a 32-bit unsigned integer using BigInt to sidestep JS signed
  // right-shift surprises around /0 and /1.
  const addrInt = (BigInt(octets[0]) << 24n) | (BigInt(octets[1]) << 16n) | (BigInt(octets[2]) << 8n) | BigInt(octets[3]);
  const hostBits = 32 - prefix;
  const maskInt = (hostBits === 32) ? 0n : (((1n << BigInt(prefix)) - 1n) << BigInt(hostBits));
  const networkInt = addrInt & maskInt;
  const broadcastInt = networkInt | ((1n << BigInt(hostBits)) - 1n);
  const size = 1n << BigInt(hostBits);
  const toDotted = (n) => `${Number((n >> 24n) & 0xFFn)}.${Number((n >> 16n) & 0xFFn)}.${Number((n >> 8n) & 0xFFn)}.${Number(n & 0xFFn)}`;
  return {
    family: 'ip4',
    prefix,
    network: toDotted(networkInt),
    mask: toDotted(maskInt),
    firstAddress: toDotted(networkInt),
    lastAddress: toDotted(broadcastInt),
    size
  };
}

// Parse an IPv6 CIDR (e.g., "2a01:111:f400::/48") or bare address. Handles
// the "::" compressed form and falls back to a /128 host route when no
// prefix is supplied. Returns null for malformed input so the caller can
// skip rendering the info button.
function parseSpfIpv6(value) {
  if (!value) return null;
  const raw = String(value).trim();
  const slash = raw.indexOf('/');
  const addrPart = slash >= 0 ? raw.substring(0, slash) : raw;
  let prefix = slash >= 0 ? parseInt(raw.substring(slash + 1), 10) : 128;
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 128) return null;
  // Expand the "::" shorthand by counting the explicit groups on either side.
  if (addrPart.indexOf(':::') >= 0) return null;
  const doubleColonIdx = addrPart.indexOf('::');
  let groups;
  if (doubleColonIdx >= 0) {
    const left = addrPart.substring(0, doubleColonIdx).split(':').filter(s => s !== '');
    const right = addrPart.substring(doubleColonIdx + 2).split(':').filter(s => s !== '');
    const missing = 8 - (left.length + right.length);
    if (missing < 0) return null;
    groups = left.concat(new Array(missing).fill('0'), right);
  } else {
    groups = addrPart.split(':');
  }
  if (groups.length !== 8) return null;
  // Validate each group is a 1-4 char hex string.
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
  }
  // Pack into a 128-bit BigInt for prefix-mask math.
  let addrInt = 0n;
  for (const g of groups) {
    addrInt = (addrInt << 16n) | BigInt(parseInt(g, 16));
  }
  const hostBits = 128 - prefix;
  const maskInt = (hostBits === 128) ? 0n : (((1n << BigInt(prefix)) - 1n) << BigInt(hostBits));
  const networkInt = addrInt & maskInt;
  const broadcastInt = networkInt | ((1n << BigInt(hostBits)) - 1n);
  const size = 1n << BigInt(hostBits);
  // Format back to compressed canonical IPv6. We render the lowercased
  // 4-hex-digit form first and then collapse the longest run of "0" groups
  // into "::" so addresses match what users typically see in tooling.
  const toIpv6 = (n) => {
    const parts = [];
    for (let i = 7; i >= 0; i--) {
      parts.push(((n >> BigInt(i * 16)) & 0xFFFFn).toString(16));
    }
    // Find the longest run of consecutive "0" groups (length >= 2) to
    // compress with "::". RFC 5952 picks the leftmost when ties occur.
    let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (let i = 0; i < parts.length; i++) {
      if (parts[i] === '0') {
        if (curStart < 0) { curStart = i; curLen = 1; } else { curLen++; }
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else {
        curStart = -1; curLen = 0;
      }
    }
    if (bestLen >= 2) {
      const head = parts.slice(0, bestStart).join(':');
      const tail = parts.slice(bestStart + bestLen).join(':');
      return `${head}::${tail}`.replace(/^:/, '::').replace(/:$/, '::');
    }
    return parts.join(':');
  };
  return {
    family: 'ip6',
    prefix,
    network: toIpv6(networkInt),
    mask: null, // IPv6 traditionally uses prefix length; subnet masks are rare.
    firstAddress: toIpv6(networkInt),
    lastAddress: toIpv6(broadcastInt),
    size
  };
}

// Format an ip4/ip6 mechanism value into the multi-line HTML block shown
// inside the click-to-expand CIDR detail row beneath an SPF Explained
// table row. Returns '' when the value is not a parseable IP/CIDR so the
// caller can suppress the button entirely.
//
// The output is HTML (NOT plain text) so the labels can be wrapped in
// <strong>. The detail row uses a monospace font with `white-space: pre`
// in CSS, so we pad each line with regular spaces AFTER the (visible)
// label to keep the value columns column-aligned. All user/value-derived
// strings are HTML-escaped inline; label translations are passed through
// escapeHtml as well so a hostile/edge-case translation string can't
// inject markup.
function formatSpfCidrInfo(type, value) {
  const info = (type === 'ip4') ? parseSpfIpv4(value) : (type === 'ip6') ? parseSpfIpv6(value) : null;
  if (!info) return '';
  // Localized labels fall back to English via t() so untranslated locales
  // still render readable text instead of the raw key name.
  const lblNetwork = t('spfCidrLabelNetwork');
  const lblPrefix  = t('spfCidrLabelPrefix');
  const lblMask    = t('spfCidrLabelMask');
  const lblRange   = t('spfCidrLabelRange');
  const lblSize    = t('spfCidrLabelSize');
  const lblAddrs   = t('spfCidrLabelAddresses');
  const lblThrough = t('spfCidrRangeThrough');
  // Use locale-aware grouping for the address count. BigInt -> Number is
  // safe up to 2^53; /0 (2^32 / 2^128) is unrealistic in SPF records, but
  // we fall back to toString() if the value exceeds Number.MAX_SAFE_INTEGER.
  let sizeStr;
  if (info.size <= BigInt(Number.MAX_SAFE_INTEGER)) {
    try {
      sizeStr = Number(info.size).toLocaleString();
    } catch (_) {
      sizeStr = info.size.toString();
    }
  } else {
    sizeStr = info.size.toString();
  }
  // Compute the longest label so the value columns line up regardless of
  // which locale is active. We pad with plain spaces between the closing
  // </strong> and the value text; the surrounding <pre> preserves them.
  const labels = [lblNetwork, lblPrefix, lblMask, lblRange, lblSize];
  const labelWidth = labels.reduce((max, s) => Math.max(max, s.length), 0) + 1;
  const lineHtml = (label, valueHtml) => {
    const pad = ' '.repeat(Math.max(1, labelWidth - label.length));
    return `<strong>${escapeHtml(label)}</strong>${pad}${valueHtml}`;
  };
  const lines = [];
  lines.push(lineHtml(lblNetwork, escapeHtml(info.network)));
  lines.push(lineHtml(lblPrefix,  escapeHtml('/' + info.prefix)));
  if (info.mask) {
    lines.push(lineHtml(lblMask, escapeHtml(info.mask)));
  }
  lines.push(lineHtml(lblRange, `${escapeHtml(info.firstAddress)} ${escapeHtml(lblThrough)} ${escapeHtml(info.lastAddress)}`));
  lines.push(lineHtml(lblSize,  `${escapeHtml(sizeStr)} ${escapeHtml(lblAddrs)}`));
  return lines.join('\n');
}

// Build the inner HTML for the SPF Explained collapsible section. Returns
// either a Prefix / Type / Value / PrefixDesc / Description table or a short
// localized note explaining that no SPF record was found. The raw record is
// rendered above the table inside a highlighted box so users can see the
// exact string the table is decomposing.
//
// Hover behavior: each <tr> in the table carries `data-token-idx="N"` and
// fires onmouseenter/onmouseleave to call setSpfTokenHighlight(). Each
// token inside the green record box is wrapped in a
// `<span class="spf-record-token" data-token-idx="N">` whose index matches
// the corresponding mechanism row. The whole block is wrapped in
// `.spf-explained-block` so the hover handler can scope its querySelector
// to the nearest ancestor (lets the queried-domain SPF Explained panel and
// every per-row Explain panel coexist without cross-talk).
function buildSpfExplainedHtml(spfRecord) {
  const trimmed = spfRecord ? String(spfRecord).split(/\r?\n/)[0].trim() : '';
  if (!trimmed) {
    return `<div class="code">${escapeHtml(t('spfExplainedEmpty'))}</div>`;
  }

  const mechs = parseSpfMechanisms(trimmed);
  if (mechs.length === 0) {
    return `<div class="code">${escapeHtml(t('spfExplainedEmpty'))}</div>`;
  }

  const header = `
    <thead>
      <tr>
        <th>${escapeHtml(t('spfExplainedPrefix'))}</th>
        <th>${escapeHtml(t('spfExplainedType'))}</th>
        <th>${escapeHtml(t('spfExplainedValue'))}</th>
        <th>${escapeHtml(t('spfExplainedPrefixDesc'))}</th>
        <th>${escapeHtml(t('spfExplainedDescription'))}</th>
      </tr>
    </thead>`;

  const body = mechs.map((m, idx) => {
    // For ip4/ip6 mechanisms whose value is a parseable address or CIDR,
    // attach a small "i" button beside the value that toggles a hidden
    // sibling row right beneath this one. The sibling row spans all five
    // columns and renders the Network/CIDR prefix/Subnet mask/Range/Size
    // breakdown inside a <pre> so the padded labels stay column-aligned.
    // This is the same pattern used by per-row Explain inside the SPF
    // Expansion Records table (see toggleSpfExpansionExplain).
    //
    // Each detail row gets a unique id derived from a module-level counter
    // so that multiple SPF Explained panels on the same page (the
    // queried-domain panel plus every per-row Expansion Explain panel) do
    // not collide.
    const cidrInfo = (m.type === 'ip4' || m.type === 'ip6') ? formatSpfCidrInfo(m.type, m.value) : '';
    let valueExtraHtml = '';
    let cidrDetailRowHtml = '';
    if (cidrInfo) {
      const detailId = `spfCidrDetail-${++__spfCidrDetailCounter}`;
      valueExtraHtml = ` <button type="button" class="spf-cidr-info-btn" aria-expanded="false" aria-controls="${detailId}" title="${escapeHtml(t('spfExplainedCidrInfoLabel'))}" onclick="toggleSpfCidrDetail(this, '${detailId}')">i</button>`;
      // formatSpfCidrInfo returns already-escaped HTML (it wraps the labels
      // in <strong> so they render bold inside the <pre>). Insert as-is.
      cidrDetailRowHtml = `<tr id="${detailId}" class="spf-cidr-detail-row" style="display:none;"><td colspan="5" class="spf-cidr-detail-cell"><pre class="spf-cidr-detail-pre">${cidrInfo}</pre></td></tr>`;
    }
    return `
      <tr data-token-idx="${idx}" onmouseenter="setSpfTokenHighlight(this, true)" onmouseleave="setSpfTokenHighlight(this, false)">
        <td class="spf-col-prefix">${escapeHtml(m.qualifier)}</td>
        <td class="spf-col-type">${escapeHtml(m.type)}</td>
        <td class="spf-col-value">${escapeHtml(m.value)}${valueExtraHtml}</td>
        <td class="spf-col-prefixdesc">${escapeHtml(getSpfQualifierDescription(m.qualifier))}</td>
        <td class="spf-col-description">${escapeHtml(getSpfMechanismDescription(m.type))}</td>
      </tr>${cidrDetailRowHtml}`;
  }).join('');

  // Tokenize the raw record into spans whose index matches the table row
  // index. parseSpfMechanisms emits one entry per whitespace-separated token
  // in document order, so joining `m.raw` with single spaces reproduces the
  // canonical record while letting us wrap each token in an addressable span.
  // `data-spf-type` / `data-spf-value` are mirrored onto the span so the
  // outer SPF Expansion Records table can also highlight tokens by
  // type+value (e.g., include:spf.crsend.com).
  const tokenSpans = mechs.map((m, idx) =>
    `<span class="spf-record-token" data-token-idx="${idx}" data-spf-type="${escapeHtml(m.type)}" data-spf-value="${escapeHtml(m.value)}">${escapeHtml(m.raw)}</span>`
  ).join(' ');

  // Box the raw record above the table so the breakdown reads naturally as
  // "here is the record, here is what each piece means". The legend below the
  // table summarizes qualifier semantics for users new to SPF.
  const recordBox = `<div class="spf-explained-record">${tokenSpans}</div>`;
  const legend = `<div class="spf-explained-legend">${escapeHtml(t('spfExplainedLegend'))}</div>`;
  const table = `<div class="spf-expansion-scroll"><table class="mx-table spf-explained-table">${header}<tbody>${body}</tbody></table></div>`;
  return `<div class="spf-explained-block">${recordBox}${table}${legend}</div>`;
}

// Show/hide the SPF Explained section attached to the SPF card. Mirrors the
// toggleMxDetails / toggleWhoisRaw pattern, and additionally toggles the
// visibility of the card body (#field-spf). The Explained panel already
// renders the raw record inside its green token box at the top, so leaving
// #field-spf visible would show the same record twice. Hiding the body
// while the panel is open removes the redundancy; the body is restored
// when the user clicks "Show SPF Explained" again (label flips back) or
// collapses the card. The requirement summary and any parent-domain
// inheritance note are already mirrored INSIDE the panel by the wiring
// site, so no context is lost while the body is hidden.
function toggleSpfExplained(element) {
  const el = document.getElementById('spfExplained');
  if (!el || !element) return;

  const body = document.getElementById('field-spf');

  const header = element.closest ? element.closest('.card-header') : null;
  const content = header ? header.nextElementSibling : null;
  const isCollapsed = !!(header && header.classList && header.classList.contains('collapsed-header')) ||
                      !!(content && content.classList && content.classList.contains('collapsed'));
  if (isCollapsed && header) {
    toggleCard(header);
    el.style.display = 'block';
    if (body) body.style.display = 'none';
    element.textContent = t('spfExplainedHide');
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === 'none');
  element.textContent = isOpen ? t('spfExplainedHide') : t('spfExplainedShow');
  el.style.display = isOpen ? 'block' : 'none';
  if (body) body.style.display = isOpen ? 'none' : '';
}

// Per-row Explain toggle inside the SPF Expansion Records table. Each row
// has a hidden sibling <tr> (id passed via detailId) containing the full
// SPF Explained breakdown for THAT row's resolved record. Clicking the
// button reveals or hides that row in place, mirroring the show/hide
// pattern used by toggleSpfExplained but scoped to a single table row so
// users can drill into any include / redirect target inline without
// re-running the queried-domain breakdown.
function toggleSpfExpansionExplain(element, detailId) {
  if (!element || !detailId) return;
  const row = document.getElementById(detailId);
  if (!row) return;
  const current = row.style.display;
  const isOpen = (!current || current === 'none');
  row.style.display = isOpen ? 'table-row' : 'none';
  element.textContent = isOpen ? t('spfExpansionExplainHide') : t('spfExpansionExplain');
  if (element.setAttribute) {
    element.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }
}

// Click handler for the "i" button beside an ip4/ip6 value inside an SPF
// Explained table. Toggles the visibility of the sibling detail row that
// holds the Network/CIDR prefix/Subnet mask/Range/Size breakdown. Mirrors
// the toggleSpfExpansionExplain pattern: flip aria-expanded and the
// `.spf-cidr-info-btn--open` class so the button can visually indicate the
// open state via CSS. We only swap display + state; we never re-render the
// table because buildSpfExplainedHtml already emitted the detail row in the
// closed state at render time.
function toggleSpfCidrDetail(element, detailId) {
  if (!element || !detailId) return;
  const row = document.getElementById(detailId);
  if (!row) return;
  const current = row.style.display;
  const isOpen = (!current || current === 'none');
  row.style.display = isOpen ? 'table-row' : 'none';
  if (element.setAttribute) {
    element.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }
  if (element.classList) {
    element.classList.toggle('spf-cidr-info-btn--open', isOpen);
  }
}

// ===== DMARC Explained =====
// Parser + descriptive helpers + builder + toggle. Mirrors the SPF Explained
// pattern: take a single DMARC record string and decompose it into a table of
// Tag / Value / TagDesc / ValueDesc rows. No DNS is involved -- the parser
// operates purely on the text of `r.dmarc`. Tag order is preserved from the
// record so users can read the breakdown left-to-right against the green
// record box above the table. Unknown tags are surfaced as their own row so
// typos / non-standard tags are visible rather than silently dropped.
function parseDmarcTags(dmarcRecord) {
  const out = [];
  if (!dmarcRecord) return out;

  // The card body sometimes embeds a localized "inherited policy" note joined
  // to the raw record with a blank line. Take only the first line so the
  // parser sees pure DMARC tokens and not localized prose.
  const firstLine = String(dmarcRecord).split(/\r?\n/)[0] || '';

  // DMARC tags are semicolon-separated key=value pairs. Whitespace around
  // tokens, the '=', and around values is all ignored per RFC 7489 sec 6.4.
  const segments = firstLine.split(';');
  for (const seg of segments) {
    const part = seg.trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq < 0) {
      // Token without '='. Surface as unknown so users see it instead of
      // silently dropping it.
      out.push({ name: part.toLowerCase(), value: '', raw: part });
      continue;
    }
    const name = part.substring(0, eq).trim().toLowerCase();
    const value = part.substring(eq + 1).trim();
    out.push({ name: name, value: value, raw: part });
  }

  return out;
}

// Translate a DMARC tag name into a short human-readable description for the
// "TagDesc" column. Unknown tags fall back to the 'unknown' description so the
// table still renders consistently.
function getDmarcTagDescription(name) {
  switch (String(name || '').toLowerCase()) {
    case 'v':     return t('dmarcTagDescVersion');
    case 'p':     return t('dmarcTagDescPolicy');
    case 'sp':    return t('dmarcTagDescSubdomainPolicy');
    case 'pct':   return t('dmarcTagDescPercent');
    case 'rua':   return t('dmarcTagDescRua');
    case 'ruf':   return t('dmarcTagDescRuf');
    case 'fo':    return t('dmarcTagDescFo');
    case 'adkim': return t('dmarcTagDescAdkim');
    case 'aspf':  return t('dmarcTagDescAspf');
    case 'ri':    return t('dmarcTagDescRi');
    case 'rf':    return t('dmarcTagDescRf');
    default:      return t('dmarcTagDescUnknown');
  }
}

// Translate a DMARC tag VALUE into a more specific description for the
// "ValueDesc" column. Several tags have well-defined enum values (p, sp,
// adkim, aspf, rf, pct, fo) -- for those we surface the exact semantic
// meaning. For free-form tags (rua, ruf, ri) the value is just a URI list /
// integer so we return an empty string and let the row read naturally with
// only the TagDesc column populated.
function getDmarcValueDescription(name, value) {
  const n = String(name || '').toLowerCase();
  const v = String(value || '').trim().toLowerCase();
  if (!v) return '';

  switch (n) {
    case 'p':
    case 'sp':
      if (v === 'none')       return t('dmarcValueDescPolicyNone');
      if (v === 'quarantine') return t('dmarcValueDescPolicyQuarantine');
      if (v === 'reject')     return t('dmarcValueDescPolicyReject');
      return '';
    case 'adkim':
    case 'aspf':
      if (v === 'r') return t('dmarcValueDescAlignRelaxed');
      if (v === 's') return t('dmarcValueDescAlignStrict');
      return '';
    case 'fo': {
      // fo= is a colon-separated list (e.g., "0:1:d:s"). Describe each piece
      // on its own line so multi-value fo= reads as a structured list.
      const parts = v.split(':').map(s => s.trim()).filter(Boolean);
      const descs = parts.map(p => {
        if (p === '0') return t('dmarcValueDescFoZero');
        if (p === '1') return t('dmarcValueDescFoOne');
        if (p === 'd') return t('dmarcValueDescFoD');
        if (p === 's') return t('dmarcValueDescFoS');
        return '';
      }).filter(Boolean);
      return descs.join('\n');
    }
    case 'rf':
      if (v === 'afrf') return t('dmarcValueDescRfAfrf');
      return '';
    case 'pct': {
      const n2 = parseInt(v, 10);
      if (!Number.isFinite(n2)) return '';
      if (n2 === 100) return t('dmarcValueDescPercentFull');
      return t('dmarcValueDescPercentPartial', { percent: String(n2) });
    }
    default:
      return '';
  }
}

// Build the inner HTML for the DMARC Explained panel. Returns either a small
// "no DMARC record" note or a record box + tag table + legend block. Mirrors
// the buildSpfExplainedHtml structure so the two panels look like siblings.
function buildDmarcExplainedHtml(dmarcRecord) {
  const trimmed = dmarcRecord ? String(dmarcRecord).split(/\r?\n/)[0].trim() : '';
  if (!trimmed) {
    return `<div class="code">${escapeHtml(t('dmarcExplainedEmpty'))}</div>`;
  }

  const tags = parseDmarcTags(trimmed);
  if (tags.length === 0) {
    return `<div class="code">${escapeHtml(t('dmarcExplainedEmpty'))}</div>`;
  }

  const header = `
    <thead>
      <tr>
        <th>${escapeHtml(t('dmarcExplainedTag'))}</th>
        <th>${escapeHtml(t('dmarcExplainedValue'))}</th>
        <th>${escapeHtml(t('dmarcExplainedTagDesc'))}</th>
        <th>${escapeHtml(t('dmarcExplainedValueDesc'))}</th>
      </tr>
    </thead>`;

  // Build the table body. Each <tr> carries `data-token-idx="N"` and
  // onmouseenter/onmouseleave handlers so hovering a row highlights the
  // matching tag=value token in the record box above (and vice-versa).
  // This mirrors the SPF Explained hover wiring exactly.
  const body = tags.map((tag, idx) => {
    // ValueDesc can contain newline-separated descriptions for multi-value
    // tags like fo=. Convert \n to <br> after escaping so the per-piece
    // descriptions render as a small inline list inside the same cell.
    const valueDesc = getDmarcValueDescription(tag.name, tag.value);
    const valueDescHtml = valueDesc ? escapeHtml(valueDesc).replace(/\n/g, '<br>') : '';
    return `
      <tr data-token-idx="${idx}" onmouseenter="setDmarcTokenHighlight(this, true)" onmouseleave="setDmarcTokenHighlight(this, false)">
        <td class="dmarc-col-tag">${escapeHtml(tag.name)}</td>
        <td class="dmarc-col-value">${escapeHtml(tag.value)}</td>
        <td class="dmarc-col-tagdesc">${escapeHtml(getDmarcTagDescription(tag.name))}</td>
        <td class="dmarc-col-valuedesc">${valueDescHtml}</td>
      </tr>`;
  }).join('');

  // Tokenize the raw record into spans whose index matches the table row
  // index. parseDmarcTags preserves each tag's original `raw` substring in
  // document order, so rejoining with "; " reproduces a canonical DMARC
  // record while letting us wrap each tag=value pair in an addressable
  // span. If the original record ended with a trailing ";", preserve it so
  // the rendered record box matches what users typically publish.
  const hadTrailingSemicolon = /;\s*$/.test(trimmed);
  const tokenSpans = tags
    .map((tag, idx) => `<span class="dmarc-record-token" data-token-idx="${idx}">${escapeHtml(tag.raw)}</span>`)
    .join('; ') + (hadTrailingSemicolon ? ';' : '');

  // Box the raw record above the table so the breakdown reads naturally as
  // "here is the record, here is what each piece means". The legend below the
  // table summarizes DMARC tag rules for users new to DMARC.
  const recordBox = `<div class="dmarc-explained-record">${tokenSpans}</div>`;
  const legend = `<div class="dmarc-explained-legend">${escapeHtml(t('dmarcExplainedLegend'))}</div>`;
  const table = `<div class="spf-expansion-scroll"><table class="mx-table dmarc-explained-table">${header}<tbody>${body}</tbody></table></div>`;
  return `<div class="dmarc-explained-block">${recordBox}${table}${legend}</div>`;
}

// Hover handler for rows inside a buildDmarcExplainedHtml() table. The
// matching `.dmarc-record-token` span in the same `.dmarc-explained-block`
// is highlighted (or un-highlighted) so users can visually correlate a
// table row with the exact tag=value substring inside the record box above.
// Scoped to the nearest `.dmarc-explained-block` so future panels do not
// cross-talk -- mirrors setSpfTokenHighlight's scoping pattern.
function setDmarcTokenHighlight(rowEl, isOn) {
  if (!rowEl || !rowEl.getAttribute) return;
  const idx = rowEl.getAttribute('data-token-idx');
  if (idx === null || typeof idx === 'undefined') return;
  const block = rowEl.closest ? rowEl.closest('.dmarc-explained-block') : null;
  if (!block) return;
  const tok = block.querySelector(`.dmarc-record-token[data-token-idx="${idx}"]`);
  if (!tok || !tok.classList) return;
  if (isOn) {
    tok.classList.add('dmarc-record-token-active');
    rowEl.classList.add('dmarc-explained-row-active');
  } else {
    tok.classList.remove('dmarc-record-token-active');
    rowEl.classList.remove('dmarc-explained-row-active');
  }
}

// Show/hide the DMARC Explained section attached to the DMARC card. Mirrors
// toggleSpfExplained but also toggles the visibility of the card body
// (#field-dmarc). The Explained panel already renders the raw record inside
// its green box at the top, so leaving #field-dmarc visible would show the
// same text twice. Hiding the body while the panel is open removes the
// redundancy; the body is restored when the user clicks "Show DMARC
// Explained" again (label flips back) or collapses it.
function toggleDmarcExplained(element) {
  const el = document.getElementById('dmarcExplained');
  if (!el || !element) return;

  const body = document.getElementById('field-dmarc');

  const header = element.closest ? element.closest('.card-header') : null;
  const content = header ? header.nextElementSibling : null;
  const isCollapsed = !!(header && header.classList && header.classList.contains('collapsed-header')) ||
                      !!(content && content.classList && content.classList.contains('collapsed'));
  if (isCollapsed && header) {
    toggleCard(header);
    el.style.display = 'block';
    if (body) body.style.display = 'none';
    element.textContent = t('dmarcExplainedHide');
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === 'none');
  element.textContent = isOpen ? t('dmarcExplainedHide') : t('dmarcExplainedShow');
  el.style.display = isOpen ? 'block' : 'none';
  if (body) body.style.display = isOpen ? 'none' : '';
}

// Hover handler for rows inside a buildSpfExplainedHtml() table. The matching
// `.spf-record-token` span in the same `.spf-explained-block` is highlighted
// (or un-highlighted) so users can visually correlate a table row with the
// exact substring inside the green record box above. Scoped to the nearest
// `.spf-explained-block` so multiple Explained panels on the page (the
// queried-domain SPF Explained panel plus every per-row Explain panel
// inside the SPF Expansion Records card) do not cross-talk.
function setSpfTokenHighlight(rowEl, isOn) {
  if (!rowEl || !rowEl.getAttribute) return;
  const idx = rowEl.getAttribute('data-token-idx');
  if (idx === null || typeof idx === 'undefined') return;
  const block = rowEl.closest ? rowEl.closest('.spf-explained-block') : null;
  if (!block) return;
  const tok = block.querySelector(`.spf-record-token[data-token-idx="${idx}"]`);
  if (!tok || !tok.classList) return;
  if (isOn) {
    tok.classList.add('spf-record-token-active');
    rowEl.classList.add('spf-explained-row-active');
  } else {
    tok.classList.remove('spf-record-token-active');
    rowEl.classList.remove('spf-explained-row-active');
  }
}

// Hover handler for rows inside the SPF Expansion Records table. Highlights
// every `.spf-record-token` (across any open Explained panel on the page)
// whose data-spf-type+value matches this expansion row's mechanism/target
// (e.g., include:spf.crsend.com). This lets users hover an entry in the
// expansion table and immediately see where it appears inside the queried-
// domain SPF Explained record box. Tokens are matched globally rather than
// scoped to a single block because the expansion row references targets
// from ANY ancestor SPF record, not just the queried one.
function setSpfExpansionHighlight(rowEl, isOn) {
  if (!rowEl || !rowEl.getAttribute) return;
  const mech = (rowEl.getAttribute('data-spf-mech') || '').toLowerCase();
  const target = rowEl.getAttribute('data-spf-target') || '';
  if (!mech || !target) return;
  // Build a CSS-attribute-selector-safe value. We escape backslashes and
  // double quotes; SPF targets are DNS names and won't contain either in
  // practice, but guard against weird inputs anyway.
  const safeTarget = target.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const selector = `.spf-record-token[data-spf-type="${mech}"][data-spf-value="${safeTarget}"]`;
  let matches = [];
  try {
    matches = Array.from(document.querySelectorAll(selector));
  } catch (_) { /* invalid selector; bail silently */ }
  for (const tok of matches) {
    if (!tok || !tok.classList) continue;
    if (isOn) tok.classList.add('spf-record-token-active');
    else tok.classList.remove('spf-record-token-active');
  }
  // Also mirror the row highlight so users can tell at a glance which
  // expansion row drove the highlight.
  if (rowEl.classList) {
    if (isOn) rowEl.classList.add('spf-expansion-row-active');
    else rowEl.classList.remove('spf-expansion-row-active');
  }
}

// Toggle for MX additional details
function toggleMxDetails(element) {
  const el = document.getElementById("mxDetails");
  if (!el) return;

  // If the MX card is collapsed, expand it first and force details open.
  const header = element && element.closest ? element.closest(".card-header") : null;
  const content = header ? header.nextElementSibling : null;
  const isCollapsed = !!(header && header.classList && header.classList.contains("collapsed-header")) ||
                      !!(content && content.classList && content.classList.contains("collapsed"));
  if (isCollapsed && header) {
    toggleCard(header);
    el.style.display = "block";
    element.textContent = t('additionalDetailsMinus');
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === "none");
  if (isOpen) {
    element.textContent = t('additionalDetailsMinus');
  } else {
    element.textContent = t('additionalDetailsPlus');
  }
  el.style.display = isOpen ? "block" : "none";
}

function toggleWhoisRaw(element) {
  const el = document.getElementById("whoisRawData");
  if (!el || !element) return;

  const current = el.style.display;
  const isOpen = (!current || current === "none");
  element.textContent = isOpen ? (element.dataset.closeLabel || `${t('rawWhoisRdapDataButton')} -`) : (element.dataset.openLabel || `${t('rawWhoisRdapDataButton')} +`);
  el.style.display = isOpen ? "block" : "none";
}

// Convert RDAP JSON into small grouped sections first so the registration card
// is readable before the user decides to expand the full raw payload.
function getRdapVcardText(vcardArray, propertyName) {
  const cardEntries = Array.isArray(vcardArray) && vcardArray.length >= 2 && Array.isArray(vcardArray[1]) ? vcardArray[1] : [];
  for (const entry of cardEntries) {
    if (!Array.isArray(entry) || entry.length < 4 || String(entry[0] || '').toLowerCase() !== String(propertyName || '').toLowerCase()) {
      continue;
    }

    const value = entry[3];
    if (Array.isArray(value)) {
      const flattened = value.flat(Infinity).filter(Boolean).map(item => String(item).trim()).filter(Boolean);
      if (flattened.length > 0) {
        return flattened.join(', ');
      }
    }

    const text = String(value || '').trim();
    if (text) {
      return text;
    }
  }

  return '';
}

function formatRdapDateValue(value) {
  const rawValue = String(value || '').trim();
  if (!rawValue) {
    return '';
  }

  return formatLocalDateTime(rawValue) || rawValue;
}

function formatRdapLabel(label) {
  return String(label || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, letter => letter.toUpperCase());
}

// Map well-known RDAP event actions, entity roles, EPP status codes, and
// common notice titles to translation keys so they can be localized.  Values
// that don't match fall back to formatRdapLabel.
const RDAP_LABEL_KEYS = {
  // Event actions
  'registration':                   'rdapActionRegistration',
  'expiration':                     'rdapActionExpiration',
  'last changed':                   'rdapActionLastChanged',
  'last update of rdap database':   'rdapActionLastUpdateRdap',
  'transfer':                       'rdapActionTransfer',
  'locked':                         'rdapActionLocked',
  'unlocked':                       'rdapActionUnlocked',
  // Entity roles
  'registrar':                      'rdapRoleRegistrar',
  'registrant':                     'rdapRoleRegistrant',
  'administrative':                 'rdapRoleAdministrative',
  'technical':                      'rdapRoleTechnical',
  'abuse':                          'rdapRoleAbuse',
  'billing':                        'rdapRoleBilling',
  'noc':                            'rdapRoleNoc',
  // Link attributes
  'self':                           'rdapLinkRelSelf',
  'related':                        'rdapLinkRelRelated',
  'alternate':                      'rdapLinkRelAlternate',
  'application/rdap+json':          'rdapLinkTypeRdapJson',
  // Common EPP / RDAP domain status codes (ICANN-defined)
  'active':                         'eppActive',
  'inactive':                       'eppInactive',
  'ok':                             'eppOk',
  'client delete prohibited':       'eppClientDeleteProhibited',
  'client hold':                    'eppClientHold',
  'client renew prohibited':        'eppClientRenewProhibited',
  'client transfer prohibited':     'eppClientTransferProhibited',
  'client update prohibited':       'eppClientUpdateProhibited',
  'server delete prohibited':       'eppServerDeleteProhibited',
  'server hold':                    'eppServerHold',
  'server renew prohibited':        'eppServerRenewProhibited',
  'server transfer prohibited':     'eppServerTransferProhibited',
  'server update prohibited':       'eppServerUpdateProhibited',
  'pending create':                 'eppPendingCreate',
  'pending delete':                 'eppPendingDelete',
  'pending renew':                  'eppPendingRenew',
  'pending transfer':               'eppPendingTransfer',
  'pending update':                 'eppPendingUpdate',
  'redemption period':              'eppRedemptionPeriod',
  'auto renew period':              'eppAutoRenewPeriod',
  'add period':                     'eppAddPeriod',
  'renew period':                   'eppRenewPeriod',
  'transfer period':                'eppTransferPeriod',
  // Common RDAP notice titles returned by most registries
  'terms of service':               'rdapNoticeTermsOfService',
  'status codes':                   'rdapNoticeStatusCodes',
  'rdds inaccuracy complaint form': 'rdapNoticeRddsComplaint'
};

function translateRdapLabel(rawLabel) {
  const key = RDAP_LABEL_KEYS[String(rawLabel || '').trim().toLowerCase()];
  if (key) {
    const translated = t(key);
    // t() falls back to the key name if untranslated; in that case use the
    // formatted label so we never expose a raw translation key.
    if (translated && translated !== key) {
      return translated;
    }
  }
  return formatRdapLabel(rawLabel);
}

function renderRdapDigestSection(title, bodyHtml) {
  if (!bodyHtml) {
    return '';
  }

  return `<div class="rdap-digest-section"><div class="rdap-digest-title">${escapeHtml(title)}</div>${bodyHtml}</div>`;
}

function renderRdapDigestList(items, formatter) {
  const values = (Array.isArray(items) ? items : []).map(item => formatter(item)).filter(Boolean);
  if (!values.length) {
    return '';
  }

  return `<ul class="rdap-digest-list">${values.map(value => `<li>${value}</li>`).join('')}</ul>`;
}

function renderRdapDigestPills(items, formatter) {
  const values = (Array.isArray(items) ? items : []).map(item => formatter(item)).filter(Boolean);
  if (!values.length) {
    return '';
  }

  return `<div class="rdap-pill-list">${values.map(value => `<span class="rdap-pill">${value}</span>`).join('')}</div>`;
}

function renderRdapDigestTimeline(items, formatter) {
  const values = (Array.isArray(items) ? items : []).map(item => formatter(item)).filter(Boolean);
  if (!values.length) {
    return '';
  }

  return `<div class="rdap-timeline">${values.join('')}</div>`;
}

// RDAP providers do not always return events in a reader-friendly order, so
// normalize them chronologically before building the timeline.
function sortRdapEventsChronologically(events) {
  return [...(Array.isArray(events) ? events : [])]
    .map((event, index) => ({ event, index }))
    .sort((left, right) => {
      const leftDate = Date.parse(left && left.event && left.event.eventDate ? left.event.eventDate : '');
      const rightDate = Date.parse(right && right.event && right.event.eventDate ? right.event.eventDate : '');
      const leftValid = Number.isFinite(leftDate);
      const rightValid = Number.isFinite(rightDate);

      if (leftValid && rightValid) {
        return leftDate - rightDate;
      }

      if (leftValid) {
        return -1;
      }

      if (rightValid) {
        return 1;
      }

      return left.index - right.index;
    })
    .map(item => item.event);
}

function renderRdapDigestCards(items, formatter, className = 'rdap-detail-card-list') {
  const values = (Array.isArray(items) ? items : []).map(item => formatter(item)).filter(Boolean);
  if (!values.length) {
    return '';
  }

  return `<div class="${className}">${values.join('')}</div>`;
}

function renderRdapDigest(rawRdapText) {
  const sourceText = String(rawRdapText || '').trim();
  if (!sourceText) {
    return '';
  }

  let rdap;
  try {
    rdap = repairObjectStrings(JSON.parse(sourceText));
  } catch {
    return `<div class="rdap-digest-section"><div class="rdap-digest-title">${escapeHtml(t('rdapRawLabel'))}</div><pre class="code rdap-raw-pre">${escapeHtml(sourceText)}</pre></div>`;
  }

  const sortedEvents = sortRdapEventsChronologically(rdap.events);
  const statusCount = Array.isArray(rdap.status) ? rdap.status.filter(Boolean).length : 0;
  const eventCount = sortedEvents.filter(Boolean).length;
  const nameserverCount = Array.isArray(rdap.nameservers) ? rdap.nameservers.filter(Boolean).length : 0;
  const entityCount = Array.isArray(rdap.entities) ? rdap.entities.filter(Boolean).length : 0;
  const linkCount = Array.isArray(rdap.links) ? rdap.links.filter(Boolean).length : 0;
  const noticeCount = ([...(Array.isArray(rdap.notices) ? rdap.notices : []), ...(Array.isArray(rdap.remarks) ? rdap.remarks : [])]).filter(Boolean).length;

  // Use translateRdapLabel so EPP status codes (e.g. "client delete prohibited")
  // are localized when a translation key exists; otherwise falls back to
  // formatRdapLabel for readable title-casing.
  const statusHtml = renderRdapDigestPills(rdap.status, status => escapeHtml(translateRdapLabel(status)));
  const eventHtml = renderRdapDigestTimeline(sortedEvents, event => {
    if (!event || typeof event !== 'object') {
      return '';
    }

    const action = translateRdapLabel(event.eventAction || 'Event');
    const value = formatRdapDateValue(event.eventDate);
    return `
      <div class="rdap-timeline-item">
        <div class="rdap-timeline-marker"></div>
        <div class="rdap-timeline-content">
          <div class="rdap-timeline-title">${escapeHtml(action)}</div>
          ${value ? `<div class="rdap-timeline-meta">${escapeHtml(value)}</div>` : ''}
        </div>
      </div>`;
  });
  const nameserverHtml = renderRdapDigestPills(rdap.nameservers, nameserver => {
    const ldhName = nameserver && typeof nameserver === 'object' ? (nameserver.ldhName || nameserver.unicodeName || nameserver.handle) : nameserver;
    return escapeHtml(String(ldhName || '').toLowerCase());
  });
  const entityHtml = renderRdapDigestCards(rdap.entities, entity => {
    if (!entity || typeof entity !== 'object') {
      return '';
    }

    const roleText = Array.isArray(entity.roles) && entity.roles.length > 0
      ? entity.roles.map(role => translateRdapLabel(role)).join(', ')
      : translateRdapLabel(entity.objectClassName || 'Entity');
    const displayName = getRdapVcardText(entity.vcardArray, 'fn') || getRdapVcardText(entity.vcardArray, 'org') || entity.handle || '';
    const email = getRdapVcardText(entity.vcardArray, 'email');
    const phone = getRdapVcardText(entity.vcardArray, 'tel');
    const details = [
      displayName ? `<div class="rdap-detail-primary">${escapeHtml(displayName)}</div>` : '',
      email ? `<div class="rdap-detail-meta">${escapeHtml(email)}</div>` : '',
      phone ? `<div class="rdap-detail-meta">${escapeHtml(phone)}</div>` : ''
    ].filter(Boolean).join('');
    return `
      <div class="rdap-detail-card">
        <div class="rdap-detail-card-title">${escapeHtml(roleText)}</div>
        ${details || `<div class="rdap-detail-meta">${escapeHtml(entity.handle || '')}</div>`}
      </div>`;
  });
  const linkHtml = renderRdapDigestCards(rdap.links, link => {
    if (!link || typeof link !== 'object') {
      return '';
    }

    const href = String(link.href || link.value || '').trim();
    if (!href) {
      return '';
    }

    const label = [link.rel, link.type].filter(Boolean).map(item => translateRdapLabel(item)).join(' · ');
    return `
      <div class="rdap-detail-card rdap-link-card">
        <a class="rdap-link" href="${escapeHtml(href)}" target="_blank" rel="noopener">${escapeHtml(href)}</a>
        ${label ? `<div class="rdap-detail-meta">${escapeHtml(label)}</div>` : ''}
      </div>`;
  }, 'rdap-link-card-list');
  const noticeHtml = renderRdapDigestCards([...(Array.isArray(rdap.notices) ? rdap.notices : []), ...(Array.isArray(rdap.remarks) ? rdap.remarks : [])], notice => {
    if (!notice || typeof notice !== 'object') {
      return '';
    }

    const rawTitle = String(notice.title || '').trim();
    // Translate well-known RDAP notice titles (e.g. "Terms of Service",
    // "Status Codes") when a translation key exists.
    const title = rawTitle ? translateRdapLabel(rawTitle) : '';
    const description = Array.isArray(notice.description) ? notice.description.filter(Boolean).join(' ') : '';
    return `
      <div class="rdap-notice-card">
        ${title ? `<div class="rdap-detail-card-title">${escapeHtml(title)}</div>` : ''}
        ${description ? `<div class="rdap-detail-meta">${escapeHtml(description)}</div>` : ''}
      </div>`;
  }, 'rdap-notice-card-list');

  const summaryHeaderHtml = `
    <div class="rdap-summary-grid">
      ${statusCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${statusCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapStatusesLabel'))}</span></div>` : ''}
      ${eventCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${eventCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapEventsLabel'))}</span></div>` : ''}
      ${nameserverCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${nameserverCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapNameserversLabel'))}</span></div>` : ''}
      ${entityCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${entityCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapContactsLabel'))}</span></div>` : ''}
      ${linkCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${linkCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapLinksLabel'))}</span></div>` : ''}
      ${noticeCount > 0 ? `<div class="rdap-summary-tile"><span class="rdap-summary-count">${noticeCount}</span><span class="rdap-summary-label">${escapeHtml(t('rdapNoticesLabel'))}</span></div>` : ''}
    </div>`;

  const summarySections = [
    renderRdapDigestSection(`${t('rdapStatusLabel')}${statusCount > 0 ? ` \u00B7 ${statusCount}` : ''}`, statusHtml),
    renderRdapDigestSection(`${t('rdapEventsLabel')}${eventCount > 0 ? ` \u00B7 ${eventCount}` : ''}`, eventHtml),
    renderRdapDigestSection(`${t('rdapNameserversLabel')}${nameserverCount > 0 ? ` \u00B7 ${nameserverCount}` : ''}`, nameserverHtml),
    renderRdapDigestSection(`${t('rdapContactsLabel')}${entityCount > 0 ? ` \u00B7 ${entityCount}` : ''}`, entityHtml),
    renderRdapDigestSection(`${t('rdapLinksLabel')}${linkCount > 0 ? ` \u00B7 ${linkCount}` : ''}`, linkHtml),
    renderRdapDigestSection(`${t('rdapNoticesLabel')}${noticeCount > 0 ? ` \u00B7 ${noticeCount}` : ''}`, noticeHtml)
  ].filter(Boolean).join('');

  const prettyJson = (() => {
    try {
      return JSON.stringify(rdap, null, 2);
    } catch {
      return sourceText;
    }
  })();

  return `
    <div class="rdap-digest-wrapper">
      ${summaryHeaderHtml}
      ${summarySections}
      <details class="rdap-raw-details">
        <summary>${escapeHtml(t('rdapRawJsonLabel'))}</summary>
        <pre class="code rdap-raw-pre">${escapeHtml(prettyJson)}</pre>
      </details>
    </div>`;
}

function formatTtlClock(totalSeconds) {
  const total = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const secondsPerMinute = 60;
  const secondsPerHour = 60 * secondsPerMinute;
  const secondsPerDay = 24 * secondsPerHour;
  const secondsPerMonth = 30 * secondsPerDay;

  const months = Math.floor(total / secondsPerMonth);
  let remaining = total % secondsPerMonth;
  const days = Math.floor(remaining / secondsPerDay);
  remaining = remaining % secondsPerDay;
  const hours = Math.floor(remaining / secondsPerHour);
  const minutes = Math.floor((remaining % secondsPerHour) / secondsPerMinute);
  const seconds = remaining % secondsPerMinute;

  const segments = [];
  if (months > 0) {
    segments.push(`${months}mo`);
  }
  if (days > 0) {
    segments.push(`${days}d`);
  }
  if (hours > 0) {
    segments.push(`${hours}h`);
  }
  if (minutes > 0) {
    segments.push(`${minutes}m`);
  }
  if (seconds > 0 || segments.length === 0) {
    segments.push(`${seconds}s`);
  }
  return segments.join(' ');
}

function formatDnsRecordTtl(ttlSeconds) {
  if (ttlSeconds === null || ttlSeconds === undefined || ttlSeconds === '') {
    return escapeHtml(t('unknown'));
  }

  const total = Math.max(0, Math.floor(Number(ttlSeconds) || 0));
  return `${escapeHtml(String(total))}s (${escapeHtml(formatTtlClock(total))})`;
}

const dnsRecordsFilterState = { query: '', column: 'all', filters: [] };
const selectedDnsRecordKeys = new Set();
const dnsRecordFilterSuggestionState = { activeIndex: -1, items: [] };

// Keep the DNS records table stable and predictable by applying an explicit
// client-side default sort before the rows are rendered.
function compareDnsRecordSortValues(leftValue, rightValue) {
  return String(leftValue || '').localeCompare(String(rightValue || ''), undefined, { numeric: true, sensitivity: 'base' });
}

function sortDnsRecordsRows(records) {
  const sorted = [...(Array.isArray(records) ? records : [])].sort((left, right) => {
    const valueComparisons = [
      compareDnsRecordSortValues(left && left.type, right && right.type),
      compareDnsRecordSortValues(left && left.name, right && right.name),
      compareDnsRecordSortValues(left && left.data, right && right.data),
      compareDnsRecordSortValues(left && left.class, right && right.class)
    ];

    for (const comparison of valueComparisons) {
      if (comparison !== 0) {
        return comparison;
      }
    }

    return (Number(left && left.ttlSeconds) || 0) - (Number(right && right.ttlSeconds) || 0);
  });

  // Post-sort chain reorder: when a CNAME row's `data` (target hostname)
  // matches the `name` of one or more TXT rows in the table, splice those
  // TXT rows in directly after the CNAME row. This makes resolved DKIM keys
  // (and any other CNAME->TXT chain) appear visually grouped under the
  // selector that points to them, instead of being scattered at the bottom
  // of the alphabetical TXT block. The base Type/Name/Data sort is still
  // applied; only "child" TXT rows are repositioned.
  return reorderDnsCnameTxtChains(sorted);
}

// Normalize a DNS name for comparison: strip trailing dots and lowercase.
function normalizeDnsNameForChain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.+$/, '');
}

// Walk a pre-sorted records array. Whenever we emit a CNAME row, look up any
// TXT rows whose name matches the CNAME's target hostname and emit them
// immediately afterward. Each record is emitted exactly once -- the `added`
// set guards against duplication when the TXT happens to sort before its
// CNAME parent in the base ordering.
function reorderDnsCnameTxtChains(sorted) {
  if (!Array.isArray(sorted) || sorted.length === 0) return sorted;

  // Index TXT rows by normalized name for O(1) lookup during the walk.
  const txtByName = new Map();
  sorted.forEach((record, index) => {
    if (!record || String(record.type || '').toUpperCase() !== 'TXT') return;
    const key = normalizeDnsNameForChain(record.name);
    if (!key) return;
    if (!txtByName.has(key)) txtByName.set(key, []);
    txtByName.get(key).push(index);
  });

  if (txtByName.size === 0) return sorted;

  const added = new Set();
  const result = [];
  for (let i = 0; i < sorted.length; i++) {
    if (added.has(i)) continue;
    const record = sorted[i];
    result.push(record);
    added.add(i);

    if (!record || String(record.type || '').toUpperCase() !== 'CNAME') continue;

    const target = normalizeDnsNameForChain(record.data);
    if (!target) continue;

    const matchIndices = txtByName.get(target);
    if (!matchIndices) continue;

    for (const txtIndex of matchIndices) {
      if (added.has(txtIndex)) continue;
      // Shallow-clone the TXT record and tag it as a chained child so the
      // renderer can prefix the Name column with a `↳` glyph. We avoid
      // mutating the original record because the same object may be cached
      // upstream (e.g., reused across re-renders or re-sorts).
      const childRecord = Object.assign({}, sorted[txtIndex], { _chainedFromCname: true });
      result.push(childRecord);
      added.add(txtIndex);
    }
  }

  return result;
}

function getDnsRecordSelectionKey(record) {
  if (!record || typeof record !== 'object') return '';
  return [record.name || '', record.class || 'IN', record.type || '', record.data || '', String(record.ttlSeconds ?? '')].join('\u001F');
}

function getDnsRecordSearchText(record) {
  if (!record || typeof record !== 'object') return '';

  const details = Array.isArray(record.details) ? record.details.filter(Boolean) : [];
  const detailText = details.map(item => `${t(item.labelKey || '')} ${item.value || ''}`.trim()).join(' ');
  const raw = [
    record.name || '',
    record.class || 'IN',
    record.type || '',
    record.data || '',
    formatDnsRecordTtl(record.ttlSeconds),
    detailText
  ].join(' ');

  return String(raw).toLowerCase();
}

function syncDnsRecordsFilterState() {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const columnSelect = document.getElementById('dnsRecordsFilterColumn');
  dnsRecordsFilterState.query = searchInput ? String(searchInput.value || '').trim().toLowerCase() : '';
  dnsRecordsFilterState.column = columnSelect ? String(columnSelect.value || 'all') : 'all';
}

function getDnsRecordFilterColumnLabel(column) {
  switch (String(column || 'all')) {
    case 'name': return t('dnsRecordName');
    case 'class': return t('dnsRecordClass');
    case 'type': return t('type');
    case 'data': return t('dnsRecordData');
    case 'ttl': return t('dnsRecordTtl');
    case 'all':
    default: return t('dnsRecordsFilterAllColumns');
  }
}

function getDnsRecordFilterChipKey(filter) {
  if (!filter || typeof filter !== 'object') return '';
  return `${String(filter.column || 'all')}\u001F${String(filter.query || '')}`;
}

// Store DNS record filters as removable chips so users can see exactly which
// constraints are active instead of having to infer them from a single textbox.
function updateDnsRecordsFilterChips() {
  const container = document.getElementById('dnsRecordsFilterChips');
  if (!container) {
    return;
  }

  const filters = Array.isArray(dnsRecordsFilterState.filters) ? dnsRecordsFilterState.filters : [];
  if (!filters.length) {
    container.innerHTML = '';
    container.style.display = 'none';
    return;
  }

  container.innerHTML = filters.map((filter, index) => {
    return `<span class="history-chip dns-records-filter-chip" data-filter-index="${index}"><span class="dns-records-filter-chip-column">${escapeHtml(getDnsRecordFilterColumnLabel(filter.column))}:</span><span class="dns-records-filter-chip-value">${escapeHtml(filter.displayValue || filter.query || '')}</span><button type="button" class="history-remove dns-records-filter-remove" aria-label="${escapeHtml(t('removeLabel'))}" title="${escapeHtml(t('removeLabel'))}" onclick="event.stopPropagation(); removeDnsRecordsFilterByIndex(${index})">&#x2715;</button></span>`;
  }).join('');
  container.style.display = 'flex';
}

function addDnsRecordsFilter(rawValue = null, rawColumn = null) {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const columnSelect = document.getElementById('dnsRecordsFilterColumn');
  const column = String(rawColumn || (columnSelect ? columnSelect.value : dnsRecordsFilterState.column) || 'all');
  const inputValue = rawValue === null || rawValue === undefined
    ? String(searchInput ? searchInput.value || '' : '')
    : String(rawValue || '');
  const trimmedValue = inputValue.trim();
  if (!trimmedValue) {
    return false;
  }

  const pendingFilters = [];
  if ((column === 'class' || column === 'type') && /\s/.test(trimmedValue)) {
    const parts = trimmedValue.split(/\s+/).filter(Boolean);
    const primaryValue = parts.shift() || '';
    if (primaryValue) {
      pendingFilters.push({ column, query: primaryValue.toLowerCase(), displayValue: primaryValue });
    }
    if (parts.length > 0) {
      const remainingText = parts.join(' ');
      pendingFilters.push({ column: 'all', query: remainingText.toLowerCase(), displayValue: remainingText });
    }
  } else {
    pendingFilters.push({ column, query: trimmedValue.toLowerCase(), displayValue: trimmedValue });
  }

  let changed = false;
  pendingFilters.forEach(filter => {
    const key = getDnsRecordFilterChipKey(filter);
    if (!key) {
      return;
    }

    const exists = dnsRecordsFilterState.filters.some(existing => getDnsRecordFilterChipKey(existing) === key);
    if (!exists) {
      dnsRecordsFilterState.filters.push(filter);
      changed = true;
    }
  });

  if (searchInput) {
    searchInput.value = '';
    searchInput.focus();
  }
  dnsRecordsFilterState.query = '';
  hideDnsRecordFilterSuggestions();
  updateDnsRecordsFilterChips();
  filterDnsRecordsTable();
  return changed;
}

function removeDnsRecordsFilterByIndex(index) {
  const filters = Array.isArray(dnsRecordsFilterState.filters) ? dnsRecordsFilterState.filters : [];
  if (index < 0 || index >= filters.length) {
    return;
  }

  filters.splice(index, 1);
  updateDnsRecordsFilterChips();
  filterDnsRecordsTable();
}

function hideDnsRecordFilterSuggestions() {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const suggestionsList = document.getElementById('dnsRecordsSearchSuggestions');
  if (!suggestionsList) {
    return;
  }

  dnsRecordFilterSuggestionState.items = [];
  dnsRecordFilterSuggestionState.activeIndex = -1;
  suggestionsList.innerHTML = '';
  suggestionsList.classList.remove('dns-records-search-suggestions-visible');
  if (searchInput) {
    searchInput.setAttribute('aria-expanded', 'false');
    searchInput.removeAttribute('aria-activedescendant');
  }
}

function getDnsRecordFilterSuggestionButtons() {
  const suggestionsList = document.getElementById('dnsRecordsSearchSuggestions');
  return suggestionsList ? Array.from(suggestionsList.querySelectorAll('.dns-records-search-suggestion-item')) : [];
}

function setActiveDnsRecordFilterSuggestion(index) {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const buttons = getDnsRecordFilterSuggestionButtons();
  if (!buttons.length) {
    dnsRecordFilterSuggestionState.activeIndex = -1;
    if (searchInput) {
      searchInput.removeAttribute('aria-activedescendant');
    }
    return;
  }

  const boundedIndex = Math.max(0, Math.min(index, buttons.length - 1));
  dnsRecordFilterSuggestionState.activeIndex = boundedIndex;
  buttons.forEach((button, buttonIndex) => {
    const isActive = buttonIndex === boundedIndex;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', isActive ? 'true' : 'false');
    if (isActive) {
      button.scrollIntoView({ block: 'nearest' });
      if (searchInput) {
        searchInput.setAttribute('aria-activedescendant', button.id);
      }
    }
  });
}

function moveDnsRecordFilterSuggestion(offset) {
  const buttons = getDnsRecordFilterSuggestionButtons();
  if (!buttons.length) {
    return;
  }

  const currentIndex = dnsRecordFilterSuggestionState.activeIndex;
  const nextIndex = currentIndex < 0
    ? (offset >= 0 ? 0 : buttons.length - 1)
    : (currentIndex + offset + buttons.length) % buttons.length;
  setActiveDnsRecordFilterSuggestion(nextIndex);
}

// For narrow enum-style columns such as Class and Type, surface distinct
// values in a compact custom picker so filtering can stay exact-match only.
function getDnsRecordFilterSuggestions(column, query = '') {
  if (column !== 'class' && column !== 'type') {
    return [];
  }

  const tbody = document.getElementById('dnsRecordsTableBody');
  if (!tbody) {
    return [];
  }

  const suggestions = new Map();
  Array.from(tbody.querySelectorAll('tr')).forEach(row => {
    const normalizedValue = String(row.getAttribute(`data-col-${column}`) || '').trim();
    const displayValue = String(row.getAttribute(`data-col-display-${column}`) || '').trim();
    if (!normalizedValue || !displayValue || suggestions.has(normalizedValue)) {
      return;
    }

    suggestions.set(normalizedValue, displayValue);
  });

  const allSuggestions = Array.from(suggestions.entries())
    .map(([normalizedValue, displayValue]) => ({ normalizedValue, displayValue }))
    .sort((left, right) => compareDnsRecordSortValues(left.displayValue, right.displayValue));

  const normalizedQuery = String(query || '').trim().toLowerCase();
  if (!normalizedQuery) {
    return allSuggestions;
  }

  const exactMatches = allSuggestions.filter(item => item.normalizedValue === normalizedQuery);
  if (exactMatches.length > 0) {
    return exactMatches;
  }

  const prefixMatches = allSuggestions.filter(item => item.normalizedValue.startsWith(normalizedQuery));
  if (prefixMatches.length > 0) {
    return prefixMatches;
  }

  return allSuggestions.filter(item => item.normalizedValue.includes(normalizedQuery));
}

function updateDnsRecordFilterSuggestions() {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const suggestionsList = document.getElementById('dnsRecordsSearchSuggestions');
  if (!searchInput || !suggestionsList) {
    return;
  }

  const primary = String(dnsRecordsFilterState.query || '').trim().toLowerCase();
  const suggestionValues = getDnsRecordFilterSuggestions(dnsRecordsFilterState.column, dnsRecordsFilterState.query);
  const shouldShowSuggestions = (dnsRecordsFilterState.column === 'class' || dnsRecordsFilterState.column === 'type')
    && document.activeElement === searchInput
    && !!primary
    && suggestionValues.length > 0
    && !suggestionValues.some(item => item.normalizedValue === primary);

  if (!shouldShowSuggestions) {
    hideDnsRecordFilterSuggestions();
    return;
  }

  dnsRecordFilterSuggestionState.items = suggestionValues;
  suggestionsList.innerHTML = suggestionValues
    .map((item, index) => `<button type="button" id="dnsRecordsSearchSuggestion-${index}" class="dns-records-search-suggestion-item" role="option" aria-selected="false" data-value="${escapeHtml(item.displayValue)}" onmousedown="event.preventDefault()" onmouseenter="setActiveDnsRecordFilterSuggestion(${index})" onclick="selectDnsRecordFilterSuggestion(this.getAttribute('data-value') || '')">${escapeHtml(item.displayValue)}</button>`)
    .join('');
  suggestionsList.classList.add('dns-records-search-suggestions-visible');

  const preferredIndex = suggestionValues.findIndex(item => item.normalizedValue === primary);
  searchInput.setAttribute('aria-expanded', 'true');
  setActiveDnsRecordFilterSuggestion(preferredIndex >= 0 ? preferredIndex : 0);
}

function selectDnsRecordFilterSuggestion(value) {
  addDnsRecordsFilter(String(value || '').trim(), dnsRecordsFilterState.column);
}

function handleDnsRecordFilterKeydown(event) {
  if (!event) {
    return;
  }

  // Keep keyboard behavior aligned with a standard combobox so Arrow keys move
  // through suggestions, Enter selects, and Escape dismisses the popup.
  const isSuggestionListVisible = !!document.querySelector('.dns-records-search-suggestions.dns-records-search-suggestions-visible');
  if (event.key === 'ArrowDown') {
    event.preventDefault();
    if (!isSuggestionListVisible) {
      updateDnsRecordFilterSuggestions();
    }
    moveDnsRecordFilterSuggestion(1);
    return;
  }

  if (event.key === 'ArrowUp') {
    event.preventDefault();
    if (!isSuggestionListVisible) {
      updateDnsRecordFilterSuggestions();
    }
    moveDnsRecordFilterSuggestion(-1);
    return;
  }

  if (event.key === 'Home' && isSuggestionListVisible) {
    event.preventDefault();
    setActiveDnsRecordFilterSuggestion(0);
    return;
  }

  if (event.key === 'End' && isSuggestionListVisible) {
    event.preventDefault();
    setActiveDnsRecordFilterSuggestion(getDnsRecordFilterSuggestionButtons().length - 1);
    return;
  }

  if (event.key === 'Enter' && isSuggestionListVisible && dnsRecordFilterSuggestionState.activeIndex >= 0) {
    event.preventDefault();
    const activeButton = getDnsRecordFilterSuggestionButtons()[dnsRecordFilterSuggestionState.activeIndex];
    if (activeButton) {
      selectDnsRecordFilterSuggestion(activeButton.getAttribute('data-value') || '');
    }
    return;
  }

  if (event.key === 'Enter') {
    event.preventDefault();
    addDnsRecordsFilter();
    return;
  }

  if (event.key === 'Backspace' && !String((event.target && event.target.value) || '').trim() && Array.isArray(dnsRecordsFilterState.filters) && dnsRecordsFilterState.filters.length > 0) {
    dnsRecordsFilterState.filters.pop();
    updateDnsRecordsFilterChips();
    filterDnsRecordsTable();
    return;
  }

  if (event.key === 'Escape') {
    hideDnsRecordFilterSuggestions();
  }
}

function matchesDnsRecordFilter(haystack, query, column) {
  const normalizedQuery = String(query || '').trim().toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  // Class and Type remain exact-match filters, while broader columns keep
  // substring matching so multiple chips can be combined intuitively.
  if (column === 'class' || column === 'type') {
    return haystack === normalizedQuery;
  }

  return haystack.includes(normalizedQuery);
}

function updateDnsRecordsFilterSummary(visibleCount, totalCount) {
  const summary = document.getElementById('dnsRecordsFilterSummary');
  if (!summary) return;
  summary.textContent = t('dnsRecordsFilterSummary', { visible: String(visibleCount), total: String(totalCount) });
}

function filterDnsRecordsTable() {
  syncDnsRecordsFilterState();
  updateDnsRecordFilterSuggestions();
  updateDnsRecordsFilterChips();

  const tbody = document.getElementById('dnsRecordsTableBody');
  const noMatches = document.getElementById('dnsRecordsNoMatches');
  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll('tr'));
  const filters = Array.isArray(dnsRecordsFilterState.filters) ? dnsRecordsFilterState.filters : [];
  let visibleCount = 0;

  rows.forEach(row => {
    const isMatch = filters.every(filter => {
      const column = String(filter && filter.column || 'all');
      const haystack = column === 'all'
        ? String(row.getAttribute('data-search') || '')
        : String(row.getAttribute(`data-col-${column}`) || '');
      return matchesDnsRecordFilter(haystack, filter && filter.query, column);
    });
    row.style.display = isMatch ? '' : 'none';
    if (isMatch) visibleCount++;
  });

  if (noMatches) {
    noMatches.style.display = visibleCount === 0 ? 'block' : 'none';
  }

  updateDnsRecordsFilterSummary(visibleCount, rows.length);
}

function clearDnsRecordsFilters() {
  const searchInput = document.getElementById('dnsRecordsSearchInput');
  const columnSelect = document.getElementById('dnsRecordsFilterColumn');
  if (searchInput) searchInput.value = '';
  if (columnSelect) columnSelect.value = 'all';
  dnsRecordsFilterState.query = '';
  dnsRecordsFilterState.column = 'all';
  dnsRecordsFilterState.filters = [];
  hideDnsRecordFilterSuggestions();
  updateDnsRecordsFilterChips();
  filterDnsRecordsTable();
}

function toggleDnsRecordRowSelection(row) {
  if (!row) return;
  const key = String(row.getAttribute('data-row-key') || '');
  if (!key) return;

  if (selectedDnsRecordKeys.has(key)) {
    selectedDnsRecordKeys.delete(key);
    row.classList.remove('dns-record-row-selected');
    row.setAttribute('aria-pressed', 'false');
  } else {
    selectedDnsRecordKeys.add(key);
    row.classList.add('dns-record-row-selected');
    row.setAttribute('aria-pressed', 'true');
  }
}

function handleDnsRecordRowKeydown(event, row) {
  if (!event || !row) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  toggleDnsRecordRowSelection(row);
}

function renderDnsRecordsTable(records) {
  const rows = sortDnsRecordsRows(Array.isArray(records) ? records.filter(Boolean) : []);
  if (!rows.length) {
    return `<div class="code">${escapeHtml(t('noRecordsAvailable'))}</div>`;
  }

  const body = rows.map(record => {
    const isChainedChild = !!(record && record._chainedFromCname);
    const escapedName = escapeHtml(record.name || '');
    // Prefix chained-child rows (e.g., a DKIM TXT key resolved via a CNAME)
    // with a muted "down-and-right arrow" glyph so the parent/child
    // relationship reads visually in the Name column. The glyph is rendered
    // via a span so it can be styled separately and is hidden from the
    // search/filter haystack (which uses the original `record.name`).
    const name = isChainedChild
      ? `<span class="dns-record-chain-marker" aria-hidden="true">&#x21B3;&nbsp;</span>${escapedName}`
      : escapedName;
    const dnsClass = escapeHtml(record.class || 'IN');
    const type = escapeHtml(record.type || '');
    const details = Array.isArray(record.details) ? record.details.filter(Boolean) : [];
    const ttl = formatDnsRecordTtl(record.ttlSeconds);
    const data = details.length
      ? `<div class="dns-record-detail-list">${details.map(item => `<div class="dns-record-detail-row"><span class="dns-record-detail-label">${escapeHtml(t(item.labelKey || ''))}:</span><span class="dns-record-detail-value">${escapeHtml(item.value || '')}</span></div>`).join('')}</div>`
      : escapeHtml(record.data || '');
    const rowKey = getDnsRecordSelectionKey(record);
    const isSelected = selectedDnsRecordKeys.has(rowKey);
    const searchText = getDnsRecordSearchText(record);
    const rowClasses = ['dns-record-row'];
    if (isSelected) rowClasses.push('dns-record-row-selected');
    if (isChainedChild) rowClasses.push('dns-record-row-chained');
    return `<tr class="${rowClasses.join(' ')}" data-row-key="${escapeHtml(rowKey)}" data-search="${escapeHtml(searchText)}" data-col-name="${escapeHtml(String(record.name || '').toLowerCase())}" data-col-class="${escapeHtml(String(record.class || 'IN').toLowerCase())}" data-col-display-class="${dnsClass}" data-col-type="${escapeHtml(String(record.type || '').toLowerCase())}" data-col-display-type="${type}" data-col-data="${escapeHtml(String((record.data || '') + ' ' + details.map(item => `${t(item.labelKey || '')} ${item.value || ''}`.trim()).join(' ')).toLowerCase())}" data-col-ttl="${escapeHtml(String(ttl).toLowerCase())}" aria-pressed="${isSelected ? 'true' : 'false'}" tabindex="0" onclick="toggleDnsRecordRowSelection(this)" onkeydown="handleDnsRecordRowKeydown(event, this)"><td>${name}</td><td>${dnsClass}</td><td>${type}</td><td class="dns-record-data">${data}</td><td class="dns-record-ttl">${ttl}</td></tr>`;
  }).join('');

  return `
    <div class="code code-lite" style="margin-top:6px;">
      <div class="dns-records-toolbar hide-on-screenshot">
        <label class="dns-records-toolbar-label" for="dnsRecordsSearchInput">${escapeHtml(t('dnsRecordsSearchLabel'))}</label>
        <label class="dns-records-toolbar-label" for="dnsRecordsFilterColumn">${escapeHtml(t('dnsRecordsFilterColumn'))}</label>
        <span></span><span></span>
        <div class="dns-records-search-dropdown">
          <input id="dnsRecordsSearchInput" type="text" class="dns-records-search-input" placeholder="${escapeHtml(t('dnsRecordsSearchPlaceholder'))}" value="${escapeHtml(dnsRecordsFilterState.query)}" autocomplete="off" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="dnsRecordsSearchSuggestions" onfocus="updateDnsRecordFilterSuggestions()" oninput="filterDnsRecordsTable()" onkeydown="handleDnsRecordFilterKeydown(event)" onblur="window.setTimeout(hideDnsRecordFilterSuggestions, 120)" />
          <div id="dnsRecordsSearchSuggestions" class="dns-records-search-suggestions" role="listbox" aria-label="${escapeHtml(t('dnsRecordsSearchLabel'))}"></div>
        </div>
        <select id="dnsRecordsFilterColumn" class="dns-records-filter-select" onchange="filterDnsRecordsTable()">
          <option value="all"${dnsRecordsFilterState.column === 'all' ? ' selected' : ''}>${escapeHtml(t('dnsRecordsFilterAllColumns'))}</option>
          <option value="name"${dnsRecordsFilterState.column === 'name' ? ' selected' : ''}>${escapeHtml(t('dnsRecordName'))}</option>
          <option value="class"${dnsRecordsFilterState.column === 'class' ? ' selected' : ''}>${escapeHtml(t('dnsRecordClass'))}</option>
          <option value="type"${dnsRecordsFilterState.column === 'type' ? ' selected' : ''}>${escapeHtml(t('type'))}</option>
          <option value="data"${dnsRecordsFilterState.column === 'data' ? ' selected' : ''}>${escapeHtml(t('dnsRecordData'))}</option>
          <option value="ttl"${dnsRecordsFilterState.column === 'ttl' ? ' selected' : ''}>${escapeHtml(t('dnsRecordTtl'))}</option>
        </select>
        <button type="button" class="copy-btn dns-records-clear-btn" onclick="clearDnsRecordsFilters()">${escapeHtml(t('dnsRecordsClearFilters'))}</button>
        <span id="dnsRecordsFilterSummary" class="dns-records-filter-summary">${escapeHtml(t('dnsRecordsFilterSummary', { visible: String(rows.length), total: String(rows.length) }))}</span>
        <div id="dnsRecordsFilterChips" class="dns-records-filter-chip-row" style="display:${dnsRecordsFilterState.filters.length ? 'flex' : 'none'};">${(dnsRecordsFilterState.filters || []).map((filter, index) => `<span class="history-chip dns-records-filter-chip" data-filter-index="${index}"><span class="dns-records-filter-chip-column">${escapeHtml(getDnsRecordFilterColumnLabel(filter.column))}:</span><span class="dns-records-filter-chip-value">${escapeHtml(filter.displayValue || filter.query || '')}</span><button type="button" class="history-remove dns-records-filter-remove" aria-label="${escapeHtml(t('removeLabel'))}" title="${escapeHtml(t('removeLabel'))}" onclick="event.stopPropagation(); removeDnsRecordsFilterByIndex(${index})">&#x2715;</button></span>`).join('')}</div>
      </div>
      <table id="dnsRecordsTable" class="mx-table dns-records-table">
        <thead>
          <tr>
            <th>${escapeHtml(t('dnsRecordName'))}</th>
            <th>${escapeHtml(t('dnsRecordClass'))}</th>
            <th>${escapeHtml(t('type'))}</th>
            <th>${escapeHtml(t('dnsRecordData'))}</th>
            <th>${escapeHtml(t('dnsRecordTtl'))}</th>
          </tr>
        </thead>
        <tbody id="dnsRecordsTableBody">${body}</tbody>
      </table>
      <div id="dnsRecordsNoMatches" class="dns-records-no-matches" style="display:none;">${escapeHtml(t('dnsRecordsNoMatches'))}</div>
    </div>`;
}

function render(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};
  // The TXT recovery helper normalizes the effective TXT/SPF/ACS view so the
  // cards can keep rendering even when the dedicated base TXT lookup timed out
  // but the detailed DNS records payload still contains the queried-domain TXT rows.
  const txtRecovery = (r && r._txtRecovery) ? r._txtRecovery : getDnsTxtRecoveryState(r);
  const txtLookupResolved = !!txtRecovery.txtLookupResolved;
  const effectiveTxtRecords = Array.isArray(txtRecovery.txtRecords) ? txtRecovery.txtRecords : [];
  const effectiveSpfPresent = !!txtRecovery.spfPresent;
  const effectiveSpfValue = txtRecovery.spfValue || null;
  const effectiveSpfHasRequiredInclude = txtRecovery.spfHasRequiredInclude;
  // Macro-delegated / hosted SPF (Valimail, OnDMARC, Sendmarc, ...) resolves the
  // Outlook include dynamically per message, so it can be neither confirmed nor
  // denied statically. The server signals this via matchType 'macro-delegated'
  // (with spfHasRequiredInclude === null). Treat it as an indeterminate WARN
  // rather than a hard FAIL so the SPF card does not look misleadingly broken.
  const effectiveSpfRequiredIncludeMatchType = txtRecovery.spfRequiredIncludeMatchType || (r && r.spfRequiredIncludeMatchType) || null;
  const effectiveSpfIsMacroDelegated = (String(effectiveSpfRequiredIncludeMatchType || '').trim().toLowerCase() === 'macro-delegated')
    || (effectiveSpfPresent && effectiveSpfHasRequiredInclude === null);
  const effectiveAcsPresent = !!txtRecovery.acsPresent;
  const effectiveAcsValue = txtRecovery.acsValue || null;
  const mxLookupDomain = r && r.mxLookupDomain ? r.mxLookupDomain : (r ? r.domain : null);
  const mxFallbackUsed = !!(r && r.mxFallbackUsed);
  const mxFallbackChecked = r && r.mxFallbackDomainChecked ? r.mxFallbackDomainChecked : null;
  const allLoaded = !!(loaded.base && loaded.mx && loaded.records && loaded.whois && loaded.dmarc && loaded.dkim && loaded.cname && loaded.reputation);
  const anyError = !!(errors && Object.keys(errors).length > 0);
  let gatheredAtLocal = r.collectedAt ? formatLocalDateTime(r.collectedAt) : null;

  // Ensure collectedAt is stamped once all checks complete (for display + copy text)
  if (!r.collectedAt && allLoaded) {
    r.collectedAt = new Date().toISOString();
    gatheredAtLocal = formatLocalDateTime(r.collectedAt);
  }

  let statusText = "";

  if (!allLoaded) {
    // While the lookup is still in flight, the #checkProgressPopover ("Gathering Data")
    // already shows per-task progress, so we deliberately leave the inline #status
    // text empty to avoid duplicating the same information twice on screen.
    statusText = "";
  } else if (anyError) {
    statusText = escapeHtml(t('statusSomeChecksFailed'));
  } else if (loaded.base && !txtLookupResolved) {
    statusText = escapeHtml(t('statusTxtFailed'));
  } else {
    // Determine overall status for Email Quota and Domain Verification

    // Domain Verification: strictly based on ACS readiness (ms-domain-verification TXT)
    let domainVerStatus = `${escapeHtml(t('failed'))} &#x274C;`;
    if (r.acsReady) {
      domainVerStatus = `${escapeHtml(t('passing'))} &#x2705;`;
    }

    // Email Quota: aggregation of MX, SPF, DMARC, DKIM, Reputation, Registration
    // Logic:
    // - If any required check fails (MX, SPF, DMARC, DKIM) -> Failed (or Warning if it's just reputation/registration warning)
    // - If partial issues -> Warning
    // - If all good -> Passing

    // Let's refine Quota status based on the "Email Quota" card logic:
    // MX: Pass if records exist. Warn otherwise.
    // Reputation: Pass if >=75% or no listings. Warn if listed or poor.
    // Registration: Pass if valid. Fail if expired/new.
    // SPF: Pass if present. Warn if missing.
    // Note: DMARC/DKIM are not strictly in the "Email Quota" card in the current UI (they are separate cards),
    // but often considered part of email readiness. The user said "Email Quota checks".
    // Looking at the 'Email Quota' card implementation in render(): it lists MX, Reputation, Registration, SPF.

    let quotaFail = false;
    let quotaWarn = false;

    // 1. MX
    if (!r.mxRecords || r.mxRecords.length === 0) { quotaFail = true; }

    // 2. Reputation
    // Logic from card: state is 'warn' if listed or poor reputation.
    if (r.reputation) {
        const repSum = r.reputation.summary || {};
        const repValid = (repSum.totalQueries || 0) - (repSum.errorCount || 0);
        const repPercent = (repValid > 0) ? ((repSum.notListedCount || 0) / repValid * 100) : null;
        if ((repSum.listedCount > 0) || (repPercent !== null && repPercent < 75)) {
            quotaWarn = true;
        }
    }

    // 3. Registration
    const whoisErrorText = errors.whois || r.whoisError || '';
    const whoisHasData = !!(r.whoisSource || r.whoisCreationDateUtc || r.whoisExpiryDateUtc || r.whoisRegistrar || r.whoisRegistrant || r.whoisAgeHuman || r.whoisExpiryHuman);
    // Treat web-form-only TLDs (e.g. .gr) as a neutral INFO, not a warning:
    // the registry intentionally does not publish WHOIS/RDAP, so the absence
    // of structured data is expected and shouldn't tarnish the overall state.
    const whoisRegistryWebFormOnly = !!(typeof r.whoisRegistryWebForm === 'string' && r.whoisRegistryWebForm.trim() && !whoisHasData);
    if (!whoisRegistryWebFormOnly && (whoisErrorText || !whoisHasData)) {
        quotaWarn = true; // missing/failed WHOIS should not show PASS
    }
    if (r.whoisIsExpired === true || r.whoisIsVeryYoungDomain === true || r.whoisIsYoungDomain === true) {
        // Expired is bad. Very young is an error. Young is warning.
        if (r.whoisIsExpired === true || r.whoisIsVeryYoungDomain === true) quotaFail = true;
        else quotaWarn = true;
    }

    // 4. SPF
    if (!effectiveSpfPresent || effectiveSpfHasRequiredInclude !== true) { quotaFail = true; }

    let emailQuotaStatus = `${escapeHtml(t('passing'))} &#x2705;`;
    if (quotaFail) {
        emailQuotaStatus = `${escapeHtml(t('failed'))} &#x274C;`;
    } else if (quotaWarn) {
        emailQuotaStatus = `${escapeHtml(t('warningState'))} &#x26A0;&#xFE0F;`;
    }

    statusText = `${escapeHtml(t('emailQuota'))}: ${emailQuotaStatus} | ${escapeHtml(t('domainVerification'))}: ${domainVerStatus}`;
  }

  const statusWithTime = gatheredAtLocal
    ? `${statusText}<div style="font-size:12px;color:var(--status);margin-top:2px;">${escapeHtml(t('statusCollectedOn', { value: gatheredAtLocal }))}</div>`
    : statusText;

  setStatus(statusWithTime);

  const cards = [];

  // Email Quota box (ordered requirements)
  const quotaItems = [];
  let quotaCopyText = '';
  const quotaLines = [];
  const quotaLinesHtml = [];
  const quotaCopyPlainLines = [];
  const quotaCopyHtmlLines = [];
  const quotaStateClass = (state) => {
    switch (state) {
      case 'pass': return 'tag-pass';
      case 'fail':
      case 'error': return 'tag-fail';
      case 'warn': return 'tag-warn';
      case 'pending':
      default: return 'tag-info';
    }
  };
  const quotaRow = (name, state, detail, infoTitle = null, targetId = null, extraHtml = '') => {
    const stateKeyMap = { pass: 'pass', fail: 'fail', error: 'error', warn: 'warn', pending: 'pending' };
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(t(stateKeyMap[state] || String(state || '').toLowerCase()))}</span>`;
    const nameHtml = escapeHtml(name)
      + (infoTitle ? ` <button type="button" class="info-dot" aria-label="${escapeHtml(infoTitle)}" data-info="${escapeHtml(infoTitle)}">i</button>` : "")
      + (extraHtml ? ` ${extraHtml}` : '');
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">${escapeHtml(t('view'))}</button>` : '';
    return `<div class="status-row"><span class="status-name">${nameHtml}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  let mxCopyDetail = '';
  let repCopyDetail = '';
  let repStats = null;
  const localizedWhoisAgeHuman = localizeDurationText(r.whoisAgeHuman);
  const localizedWhoisExpiryHuman = r.whoisIsExpired === true ? t('wordExpired') : localizeDurationText(r.whoisExpiryHuman);

  const domainForCopy = r.domain || '';
  quotaLines.push(`**${t('emailQuota')} (${t('domainNameLabel')}):** ${domainForCopy}`.trim());
  quotaLinesHtml.push(`<strong>${escapeHtml(t('emailQuota'))} (${escapeHtml(t('domainNameLabel'))}):</strong> ${escapeHtml(domainForCopy)}`.trim());
  quotaCopyPlainLines.push(`${t('domainNameLabel')}: ${domainForCopy}`);
  quotaCopyPlainLines.push('----------------------------------');
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainNameLabel'))}:</strong> ${escapeHtml(domainForCopy)}</div>`);
  quotaCopyHtmlLines.push('<div>----------------------------------</div>');


  // 1) MX Records
  let mxStatusText = '';
    if (!loaded.mx && !errors.mx) {
    mxCopyDetail = t('checkingMxRecords');
    quotaItems.push(quotaRow(t('mxRecords'), 'pending', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** PENDING${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> PENDING${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = t('checkingValue');
  } else if (errors.mx) {
    mxCopyDetail = errors.mx;
    quotaItems.push(quotaRow(t('mxRecords'), 'error', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ERROR${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ERROR${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = t('error');
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    const mxRecordsText = (r.mxRecords || []).join(', ');
    if (hasMx) {
      let note = '';
      if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
        note = ` ${t('mxUsingParentNote', { lookupDomain: mxLookupDomain })}`;
      }
      mxCopyDetail = localizeMxRecordText(mxRecordsText || t('mxRecords')) + note;
    } else {
      mxCopyDetail = t('noMxRecordsDetected');
      if (mxFallbackChecked && mxFallbackChecked !== r.domain) {
        mxCopyDetail += ` ${t('parentCheckedNoMx', { parentDomain: mxFallbackChecked })}`;
      }
    }
    const mxState = hasMx ? 'PASS' : 'FAIL';
    quotaItems.push(quotaRow(t('mxRecords'), hasMx ? 'pass' : 'fail', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ${mxState}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ${escapeHtml(mxState)}${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = hasMx ? t('yes') : t('no');
  }

  quotaCopyPlainLines.push(`${t('mxRecordsLabel')}:   ${mxStatusText || t('unknown')}`);
  if (mxCopyDetail) { quotaCopyPlainLines.push(`  ${mxCopyDetail}`); }
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('mxRecordsLabel'))}:</strong> ${escapeHtml(mxStatusText || t('unknown'))}</div>` + (mxCopyDetail ? `<div style="margin-left:12px;">${escapeHtml(mxCopyDetail)}</div>` : ''));

  const multiRblLink = `https://multirbl.valli.org/dnsbl-lookup/${encodeURIComponent(r.domain || "")}.html`;
  const multiRblHtml = `<a href="${multiRblLink}" target="_blank" rel="noopener" style="font-size:11px; color:#2f80ed; text-decoration:none;">(MultiRBL &#x2197;)</a>`;

  // 2) Reputation
  const reputationInfo = "Default DNSBL checks use a safer free/no-budget set: Spamcop, Barracuda, PSBL, DroneBL, and 0spam. Optional user-supplied zones may also be queried. Reputation = percent of not-listed over successful DNSBL queries. Ratings: Excellent \u226599%, Great \u226590%, Good \u226575%, Fair \u226550%, Poor otherwise. Risk summary: 0 hits = Clean, 1 hit = Warning, 2+ hits = ElevatedRisk. Listed entries are shown when present; errors reduce confidence.";
  let repStateForCopy = '';
  if (!loaded.reputation && !errors.reputation) {
    repCopyDetail = t('checkingDnsblReputation');
    // Only pass plain name to quotaRow if we modify quotaRow or pass raw HTML differently.
    // However, quotaRow escapes name. Let's look at quotaRow definition in the user code above.
    // quotaRow calculates: const nameHtml = escapeHtml(name) + ...
    // So we cannot just append HTML to 'name'.

    // Changing strategy: We modify quotaRow call to include the link if it allows HTML or we modify quotaRow.
    // But modifying quotaRow is harder with replace_string.
    // Let's look at how quotaRow is defined:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => { ... const nameHtml = escapeHtml(name) ... }

    // I will modify `quotaRow` to accept an optional `extraHtml` argument or similar, OR just handle the link insertion inside the Reputation items.
    // But `quotaRow` is used for MX, Domain Reg, SPF too.

    // Actually, looking at `quotaRow` definition again:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => {

    // If I change the definition of quotaRow to:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null, nameSuffixHtml = '') => {

    // This seems valuable.

    // However, I also need to update the "Copy Email Quota" text.
    // That is constructed via `quotaCopyPlainLines` and `quotaCopyHtmlLines`.

    // Let's start by modifying the quotaRow definition to support a suffix.

    quotaItems.push(quotaRow(t('reputationDnsbl'), 'pending', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** PENDING${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> PENDING${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}`);
    repStateForCopy = 'PENDING';
  } else if (errors.reputation) {
    repCopyDetail = errors.reputation;
    quotaItems.push(quotaRow(t('reputationDnsbl'), 'error', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** ERROR${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> ERROR${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}`);
    repStateForCopy = 'ERROR';
  } else {
    const rep = r.reputation || {};
    const summary = rep.summary || {};
    const listed = summary.listedCount || 0;
    const notListed = summary.notListedCount || 0;
    const errorCount = summary.errorCount || 0;
    const total = summary.totalQueries || 0;
    const repUsedParent = rep.lookupUsedParent === true && rep.lookupDomain && rep.lookupDomain !== (r.domain || '');
    const valid = Math.max(0, total - errorCount);
    const percent = (valid > 0) ? Math.max(0, Math.min(100, Math.round((notListed / valid) * 100))) : null;
    const rating = percent === null ? 'unknown' : (percent >= 99 ? 'excellent' : percent >= 90 ? 'great' : percent >= 75 ? 'good' : percent >= 50 ? 'fair' : 'poor');
      const ratingMap = { excellent: t('excellent'), great: t('great'), good: t('good'), fair: t('fair'), poor: t('poor'), unknown: t('unknown') };
      const ratingLabel = ratingMap[rating] || rating;
    const state = listed > 0 ? 'warn' : (percent === null ? 'warn' : (percent >= 75 ? 'pass' : 'warn'));
      const riskSummary = (summary.riskSummary || 'Clean') === 'Clean' ? t('clean') : (summary.riskSummary || 'Clean');
    const baseDetail = percent === null
      ? `${t('riskLabel')}: ${riskSummary} | ${t('totalQueries')}: ${total}, ${t('notListed')}: ${notListed}`
      : `${t('riskLabel')}: ${riskSummary} | ${t('reputationWord')}: ${ratingLabel} (${percent}%) | ${t('listed')}: ${listed}, ${t('notListed')}: ${notListed}`;
      const parentNote = repUsedParent ? t('usingIpParent', { domain: rep.lookupDomain, queryDomain: r.domain || '' }) : '';
    const detail = parentNote ? `${baseDetail} | ${parentNote}` : baseDetail;
    repCopyDetail = detail;
    repStats = {
      zones: Array.isArray(rep.rblZones) ? rep.rblZones.length : 0,
      total,
      errors: errorCount,
      percent,
      rating: ratingLabel,
      listed,
      notListed: summary.notListedCount || 0
    };
    quotaItems.push(quotaRow(t('reputationDnsbl'), state, detail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** ${state.toUpperCase()}${detail ? ' - ' + detail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> ${escapeHtml(state.toUpperCase())}${detail ? ' - ' + escapeHtml(detail) : ''}`);
    repStateForCopy = state.toUpperCase();
  }

  // 3) Domain Registration
  let regState = 'PENDING';
  const whoisErrorText = errors.whois || r.whoisError || '';
  // Structured WHOIS/RDAP signal must come from real registration fields, NOT
  // just `whoisSource` (provider name) or `whoisRawText` (raw banner). A
  // provider that returns partial data — e.g., DENIC for .de returns only
  // "Last Changed" + nameservers with no creation/expiry/registrar — was
  // previously slipping into the PASS branch below and rendering a green
  // "Resolved successfully." badge despite having no real registration age or
  // expiry to show. Mirror the SPA card's `hasStructuredWhoisDetails` check so
  // the Email Quota row agrees with the card header.
  const whoisHasData = !!(
    r.whoisCreationDateUtc ||
    r.whoisExpiryDateUtc ||
    r.whoisRegistrar ||
    r.whoisRegistrant ||
    r.whoisAgeHuman ||
    r.whoisExpiryHuman ||
    (r.whoisAgeDays !== null && r.whoisAgeDays !== undefined) ||
    (r.whoisExpiryDays !== null && r.whoisExpiryDays !== undefined) ||
    r.whoisIsExpired === true ||
    r.whoisIsVeryYoungDomain === true ||
    r.whoisIsYoungDomain === true
  );
  // When the registry doesn't operate WHOIS/RDAP at all (e.g. .gr / .ελ via
  // FORTH) we render a friendly link panel in the card. The Email Quota row
  // for the same check should not display a misleading red ERROR; instead use
  // a neutral INFO state with a localized "registry-only web form" message.
  const whoisRegistryWebFormUrl = (typeof r.whoisRegistryWebForm === 'string' && r.whoisRegistryWebForm.trim()) ? r.whoisRegistryWebForm.trim() : '';

  if (!loaded.whois && !errors.whois) {
    quotaItems.push(quotaRow(t('domainRegistration'), 'pending', t('loadingValue'), null, 'whois'));
    regState = 'PENDING';
  } else if (whoisRegistryWebFormUrl && !whoisHasData) {
    const msg = t('registryNoWhoisShort');
    quotaItems.push(quotaRow(t('domainRegistration'), 'info', msg, null, 'whois'));
    regState = 'INFO';
    quotaLines.push(`**Domain Registration:** ${regState} - ${msg}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)} - ${escapeHtml(msg)}`);
  } else if (whoisErrorText) {
    quotaItems.push(quotaRow(t('domainRegistration'), 'error', whoisErrorText, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState}${whoisErrorText ? ' - ' + whoisErrorText : ''}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${whoisErrorText ? ' - ' + escapeHtml(whoisErrorText) : ''}`);
  } else if (!whoisHasData) {
    const msg = t('registrationDetailsUnavailable');
    quotaItems.push(quotaRow(t('domainRegistration'), 'error', msg, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState} - ${msg}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)} - ${escapeHtml(msg)}`);
  } else {
    if (r.whoisIsExpired === true) {
      const expText = r.whoisExpiryDateUtc ? t('expiredOn', { date: r.whoisExpiryDateUtc }) : t('registrationAppearsExpired');
      quotaItems.push(quotaRow(t('domainRegistration'), 'fail', expText, null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${expText ? ' - ' + expText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${expText ? ' - ' + escapeHtml(expText) : ''}`);
    } else if (r.whoisIsVeryYoungDomain === true) {
      const suffix = localizedWhoisAgeHuman ? ': ' + localizedWhoisAgeHuman : '';
      const text = t('newDomainUnderDays', { days: String(r.whoisNewDomainErrorThresholdDays || 90), suffix }).trim();
      quotaItems.push(quotaRow(t('domainRegistration'), 'fail', text || t('newDomainUnder90Days'), null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else if (r.whoisIsYoungDomain === true) {
      const suffix = localizedWhoisAgeHuman ? ': ' + localizedWhoisAgeHuman : '';
      const text = t('newDomainUnderDays', { days: String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180), suffix }).trim();
      quotaItems.push(quotaRow(t('domainRegistration'), 'warn', text || t('newDomainUnder180Days'), null, 'whois'));
      regState = 'WARN';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else {
      const parts = [];
      if (localizedWhoisAgeHuman) { parts.push(`${t('ageLabel')}: ${localizedWhoisAgeHuman}`); }
      if (localizedWhoisExpiryHuman) { parts.push(`${t('expiresInLabel')}: ${localizedWhoisExpiryHuman}`); }
      // Only emit PASS when we actually have a registration age or expiry to
      // show. If neither is known (e.g., a thin RDAP/WHOIS response that
      // returned no creation/expiry dates), downgrade to INFO so we don't
      // claim "Resolved successfully." with no underlying evidence.
      if (parts.length === 0) {
        const msg = t('registrationDetailsUnavailable');
        quotaItems.push(quotaRow(t('domainRegistration'), 'info', msg, null, 'whois'));
        regState = 'INFO';
        quotaLines.push(`**Domain Registration:** ${regState} - ${msg}`);
        quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)} - ${escapeHtml(msg)}`);
      } else {
        const ageText = parts.join(' | ');
        quotaItems.push(quotaRow(t('domainRegistration'), 'pass', ageText, null, 'whois'));
        regState = 'PASS';
        quotaLines.push(`**Domain Registration:** ${regState}${ageText ? ' - ' + ageText : ''}`);
        quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${ageText ? ' - ' + escapeHtml(ageText) : ''}`);
      }
    }
  }

  // 4) SPF
  if (!loaded.base && !errors.base) {
    quotaItems.push(quotaRow(t('spfQueried'), 'pending', t('waitingForTxtLookup'), null, 'spf'));
    quotaLines.push('**SPF (queried domain TXT):** PENDING - Waiting for TXT lookup...');
    quotaLinesHtml.push('<strong>SPF (queried domain TXT):</strong> PENDING - Waiting for TXT lookup...');
  } else if (errors.base) {
    quotaItems.push(quotaRow(t('spfQueried'), 'error', errors.base, null, 'spf'));
    quotaLines.push(`**SPF (queried domain TXT):** ERROR${errors.base ? ' - ' + errors.base : ''}`);
    quotaLinesHtml.push(`<strong>SPF (queried domain TXT):</strong> ERROR${errors.base ? ' - ' + escapeHtml(errors.base) : ''}`);
  } else if (!txtLookupResolved) {
    quotaItems.push(quotaRow(t('spfQueried'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), null, 'spf'));
    quotaLines.push(`**${t('spfQueried')}:** FAIL${r.dnsError ? ' - ' + r.dnsError : ' - ' + t('txtLookupFailedOrTimedOut')}`);
    quotaLinesHtml.push(`<strong>${escapeHtml(t('spfQueried'))}:</strong> FAIL${r.dnsError ? ' - ' + escapeHtml(r.dnsError) : ' - ' + escapeHtml(t('txtLookupFailedOrTimedOut'))}`);
  } else {
    const spfPassesRequirement = !!(effectiveSpfPresent && effectiveSpfHasRequiredInclude === true);
    const spfIsIndeterminate = !spfPassesRequirement && effectiveSpfPresent && effectiveSpfIsMacroDelegated;
    const spfDetail = effectiveSpfPresent
      ? ([effectiveSpfValue, getLocalizedSpfRequirementSummary({ spfPresent: effectiveSpfPresent, spfHasRequiredInclude: effectiveSpfHasRequiredInclude, spfRequiredIncludeMatchType: effectiveSpfRequiredIncludeMatchType, spfRequiredIncludeProvider: r && r.spfRequiredIncludeProvider })].filter(Boolean).join("\n\n"))
      : t('noSpfRecordDetected');
    quotaItems.push(quotaRow(t('spfQueried'), spfPassesRequirement ? 'pass' : (spfIsIndeterminate ? 'warn' : 'fail'), spfDetail, null, 'spf'));
    const spfState = spfPassesRequirement ? 'PASS' : (spfIsIndeterminate ? 'WARN' : 'FAIL');
    quotaLines.push(`**${t('spfQueried')}:** ${spfState}${spfDetail ? ' - ' + spfDetail.replace(/\r?\n/g, ' | ') : ''}`);
    quotaLinesHtml.push(`<strong>${escapeHtml(t('spfQueried'))}:</strong> ${escapeHtml(spfState)}${spfDetail ? ' - ' + escapeHtml(spfDetail).replace(/\r?\n/g, '<br>') : ''}`);
  }

  // Domain age / expiry for copy block
  const ageText = localizedWhoisAgeHuman || t('unknown');
  const expiryText = localizedWhoisExpiryHuman || t('unknown');
  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`${t('domainAgeLabel')}:  ${ageText}`);
  quotaCopyPlainLines.push(`${t('domainExpiringIn')}: ${expiryText}`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainAgeLabel'))}:</strong> ${escapeHtml(ageText)}</div>`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainExpiringIn'))}:</strong> ${escapeHtml(expiryText)}</div>`);

  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`${t('reputationDnsbl')} [MultiRBL: ${multiRblLink}] - ${repStateForCopy || t('unknown')}${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('reputationDnsbl'))} - ${escapeHtml(repStateForCopy || t('unknown'))}</strong>&nbsp;${multiRblHtml}${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}</div>`);

  if (repStats) {
    const repLines = [
      `${t('zonesQueried')}: ${repStats.zones}`,
      `${t('totalQueries')}: ${repStats.total}`,
      `${t('errorsCount')}: ${repStats.errors}`,
      `${t('reputationWord')}: ${repStats.rating}${repStats.percent !== null ? ` (${repStats.percent}%)` : ''}`,
      `${t('listed')}: ${repStats.listed}`,
      `${t('notListed')}: ${repStats.notListed}`
    ];
    quotaCopyPlainLines.push(...repLines);
    quotaCopyHtmlLines.push('<div>' + repLines.map(l => escapeHtml(l)).join('<br>') + '</div>');
  }

  const repSummaryText = `${(repStateForCopy || t('unknown'))}${repCopyDetail ? ' - ' + repCopyDetail : ''}` + (repStats
    ? ` | ${t('zonesQueried')}: ${repStats.zones} | ${t('totalQueries')}: ${repStats.total} | ${t('listed')}: ${repStats.listed} | ${t('notListed')}: ${repStats.notListed}`
    : '');

  const domainStatusText = (!loaded.base && !errors.base)
    ? t('pending')
    : (errors.base
      ? t('error')
      : (effectiveAcsPresent ? t('verified') : t('notVerified')));

  const spfStatusText = (!loaded.base && !errors.base)
    ? t('pending')
    : (errors.base
      ? t('error')
      : ((effectiveSpfPresent && effectiveSpfHasRequiredInclude !== false) ? t('verified') : t('notStarted')));

  const dkim1StatusText = (!loaded.dkim && !errors.dkim)
    ? t('pending')
    : (errors.dkim
      ? t('error')
      : (r.dkim1 ? t('verified') : t('notStarted')));

  const dkim2StatusText = (!loaded.dkim && !errors.dkim)
    ? t('pending')
    : (errors.dkim
      ? t('error')
      : (r.dkim2 ? t('verified') : t('notStarted')));

  const dmarcStatusText = (!loaded.dmarc && !errors.dmarc)
    ? t('pending')
    : (errors.dmarc
      ? t('error')
      : (r.dmarc ? t('verified') : t('notStarted')));

  const plainTable = [];
  const htmlTableRows = [];
  const addRow = (name, value) => { htmlTableRows.push(`<tr><th>${escapeHtml(name)}</th><td>${escapeHtml(value)}</td></tr>`); };
  plainTable.push('| Field | Value |');
  plainTable.push('| --- | --- |');
  plainTable.push(`| ${t('domainNameLabel')} | ${domainForCopy || t('unknown')} |`);
  plainTable.push(`| ${t('domainStatusLabel')} | ${domainStatusText} |`);
  plainTable.push(`| ${t('mxRecordsLabel')} | ${mxStatusText || t('unknown')}${mxCopyDetail ? ` - ${mxCopyDetail}` : ''} |`);
  plainTable.push(`| ${t('domainAgeLabel')} | ${ageText} |`);
  plainTable.push(`| ${t('domainExpiringIn')} | ${expiryText} |`);
  plainTable.push(`| ${t('spfStatusLabel')} | ${spfStatusText} |`);
  plainTable.push(`| ${t('dkim1StatusLabel')} | ${dkim1StatusText} |`);
  plainTable.push(`| ${t('dkim2StatusLabel')} | ${dkim2StatusText} |`);
  plainTable.push(`| ${t('dmarcStatusLabel')} | ${dmarcStatusText} |`);
  plainTable.push(`| ${t('reputationDnsbl')} | ${repSummaryText} [MultiRBL: ${multiRblLink}] |`);
  // Build the page/report link the same way the top-of-page "Copy link" button
  // does (copyShareLink in 20c): start from the current location, set the
  // queried domain (when valid) and the active language so the recipient lands
  // on the exact same view this report was generated for.
  const reportLinkUrl = (() => {
    try {
      const url = new URL(window.location.href);
      const domainForLink = normalizeDomain(domainForCopy || '');
      if (domainForLink && isValidDomain(domainForLink)) {
        url.searchParams.set('domain', domainForLink);
      } else {
        url.searchParams.delete('domain');
      }
      url.searchParams.set(LANG_PARAM, currentLanguage);
      return url.toString();
    } catch (e) {
      return window.location.href;
    }
  })();
  plainTable.push(`| ${t('pageLinkLabel')} | ${reportLinkUrl} |`);
  addRow(t('domainNameLabel'), domainForCopy || t('unknown'));
  addRow(t('domainStatusLabel'), domainStatusText);
  addRow(t('mxRecordsLabel'), `${mxStatusText || t('unknown')}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
  addRow(t('domainAgeLabel'), ageText);
  addRow(t('domainExpiringIn'), expiryText);
  addRow(t('spfStatusLabel'), spfStatusText);
  addRow(t('dkim1StatusLabel'), dkim1StatusText);
  addRow(t('dkim2StatusLabel'), dkim2StatusText);
  addRow(t('dmarcStatusLabel'), dmarcStatusText);
  // Manual push for Reputation to include parsed HTML link (multiRblHtml)
  htmlTableRows.push(`<tr><th>${escapeHtml(t('reputationDnsbl'))}</th><td>${escapeHtml(repSummaryText)}<br>${multiRblHtml}</td></tr>`);
  // Page/report link row below Reputation: render a clickable anchor in the
  // rich-text variant so pasting into Outlook/Teams/Word produces a usable link.
  htmlTableRows.push(`<tr><th>${escapeHtml(t('pageLinkLabel'))}</th><td><a href="${escapeHtml(reportLinkUrl)}">${escapeHtml(reportLinkUrl)}</a></td></tr>`);

  const quotaCopyTextPlain = plainTable.join('\n');
  const quotaCopyTextHtml = `<table style="border-collapse:collapse;min-width:260px;">${htmlTableRows.map(r => r.replace('<th>', '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">').replace('<td>', '<td style="padding:4px 8px;border:1px solid #ddd;">')).join('')}</table>`;
  // Store the base DNS/quota table so the copy handler can recombine it with
  // the latest intake content at click time. The intake block is intentionally
  // NOT baked in here: render() runs during the domain lookup (before the user
  // clicks "Process Data"), so building the intake portion now would freeze an
  // empty/stale snapshot. buildQuotaCopyPayload() rebuilds it on demand.
  window.quotaCopyBase = { plain: quotaCopyTextPlain, html: quotaCopyTextHtml };
  quotaCopyText = quotaCopyTextPlain;
  // Expose for inline copy handler with rich + plain variants
  window.quotaCopyText = { plain: quotaCopyTextPlain, html: quotaCopyTextHtml };

  cards.push(`
  <div class="card" id="card-email-quota">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('checklist'))}</span>
      <strong>${escapeHtml(t('emailQuota'))}</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left:auto;" onclick="event.stopPropagation(); copyText(buildQuotaCopyPayload(), this)">${escapeHtml(t('copyEmailQuota'))}</button>
    </div>
    <div class="card-content">
      <div class="status-summary">${quotaItems.join('')}</div>
    </div>
  </div>
  `);

  // Domain Verification box (ACS requirements)
  const verificationItems = [];
  const verifyRow = (name, state, detail, targetId = null) => {
    const stateKeyMap = { pass: 'pass', fail: 'fail', error: 'error', warn: 'warn', pending: 'pending' };
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(t(stateKeyMap[state] || String(state || '').toLowerCase()))}</span>`;
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">${escapeHtml(t('view'))}</button>` : '';
    return `<div class="status-row"><span class="status-name">${escapeHtml(name)}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  if (!loaded.base && !errors.base) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'pending', t('waitingForBaseTxtLookup'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'pending', t('waitingForBaseTxtLookup'), 'acsTxt'));
  } else if (errors.base) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'error', errors.base, 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'error', t('unableDetermineAcsTxtValue'), 'acsTxt'));
  } else if (!txtLookupResolved) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'fail', t('missingRequiredAcsTxt'), 'acsTxt'));
  } else {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'pass', t('resolvedSuccessfully'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), effectiveAcsPresent ? 'pass' : 'fail', effectiveAcsPresent ? t('msDomainVerificationFound') : t('addAcsTxtFromPortal'), 'acsTxt'));
  }

  // Overall ACS readiness
  verificationItems.push(verifyRow(t('acsReadiness'), (loaded.base && !errors.base && txtLookupResolved && effectiveAcsPresent) ? 'pass' : (loaded.base && !errors.base ? 'fail' : 'pending'), r.acsReady ? t('acsReadyMessage') : t('missingRequiredAcsTxt'), 'verification'));

  cards.push(`
  <div class="card" id="card-verification">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('verificationTag'))}</span>
      <strong>${escapeHtml(t('domainVerification'))}</strong>
    </div>
    <div class="card-content">
      <div class="status-summary">${verificationItems.join('')}</div>
    </div>
  </div>
  `);

  const basePending = !loaded.base && !errors.base;
  const baseError = !!errors.base;

  // Domain Registration card now appears second
  if (!loaded.whois && !errors.whois) {
    cards.push(card(
      t('domainRegistration'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "whois",
      true
    ));
  } else if (errors.whois) {
    cards.push(card(
      t('domainRegistration'),
      errors.whois,
      "ERROR",
      "tag-fail",
      "whois",
      true
    ));
  } else {
    const isExpired = r.whoisIsExpired === true;
    const isYoung = r.whoisIsYoungDomain === true;
    const isVeryYoung = r.whoisIsVeryYoungDomain === true;
    const whoisRows = [];
    const addWhoisRow = (label, value, options = {}) => {
      if (value === null || value === undefined || value === '') return;
      const valueHtml = options.html
        ? options.html
        : options.italic
        ? `<em>${escapeHtml(value)}</em>`
        : escapeHtml(value);
      whoisRows.push(`<div class="kv-label">${escapeHtml(label)}:</div><div class="kv-value">${valueHtml}</div>`);
    };

    const formatWhoisDateValueHtml = (dateValue) => {
      const rawValue = String(dateValue || '').trim();
      if (!rawValue) {
        return '';
      }

      const localized = formatLocalDateTime(rawValue);
      if (!localized || localized === rawValue) {
        return escapeHtml(rawValue);
      }

      // Show the human-readable local time first, then the raw UTC value
      // prefixed with "UTC:" so users can distinguish the two formats.
      return `<div>${escapeHtml(localized)}</div><div class="kv-value-secondary">UTC: ${escapeHtml(rawValue)}</div>`;
    };

    addWhoisRow(t('lookupDomainLabel'), r.whoisLookupDomain);
    if (r.whoisLookupDomain && r.whoisSource) {
      whoisRows.push('<div class="kv-spacer"></div>');
    }
    addWhoisRow(t('source'), r.whoisSource, { italic: true });
    addWhoisRow(t('creationDate'), r.whoisCreationDateUtc, { html: formatWhoisDateValueHtml(r.whoisCreationDateUtc) });
    addWhoisRow(t('registryExpiryDate'), r.whoisExpiryDateUtc, { html: formatWhoisDateValueHtml(r.whoisExpiryDateUtc) });
    // When the registry deliberately does not publish expiry (e.g. SWITCH for
    // .ch/.li, DENIC for .de, EURid for .eu), surface a short explanatory note
    // so users do not interpret the missing date as a lookup failure.
    if (!r.whoisExpiryDateUtc && r.whoisExpiryUnavailableReason && r.whoisExpiryUnavailableReason.message) {
      const reason = r.whoisExpiryUnavailableReason;
      const reasonHtml = `<div class="kv-value-secondary">${escapeHtml(reason.message)}</div>`;
      // `addWhoisRow()` renders `html` values directly, so text-only style flags
      // like `italic` would be ignored here and would only make the call misleading.
      addWhoisRow(t('registryExpiryDate'), reason.message, { html: reasonHtml });
    }
    addWhoisRow(t('registrarLabel'), r.whoisRegistrar);
    addWhoisRow(t('registrantLabel'), r.whoisRegistrant);
    if (r.whoisAgeHuman) {
      addWhoisRow(t('domainAgeLabel'), localizeDurationText(r.whoisAgeHuman));
    } else if (r.whoisAgeDays !== null && r.whoisAgeDays !== undefined) {
      addWhoisRow(t('domainAgeLabel') + ' (days)', String(r.whoisAgeDays));
    }
    if (r.whoisExpiryHuman) {
      addWhoisRow(t('domainExpiringIn'), r.whoisIsExpired === true ? t('wordExpired') : localizeDurationText(r.whoisExpiryHuman));
    }
    if (isExpired) {
      addWhoisRow(t('statusLabel'), localizeWhoisStatus(t('expired')));
    } else if (isVeryYoung) {
      addWhoisRow(t('statusLabel'), t('noteDomainLessThanDays', { days: String(r.whoisNewDomainErrorThresholdDays || 90) }));
    } else if (isYoung) {
      addWhoisRow(t('statusLabel'), t('noteDomainLessThanDays', { days: String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180) }));
    }

    const hasStructuredWhoisDetails = !!(
      r.whoisCreationDateUtc ||
      r.whoisExpiryDateUtc ||
      r.whoisRegistrar ||
      r.whoisRegistrant ||
      r.whoisAgeHuman ||
      r.whoisExpiryHuman ||
      (r.whoisAgeDays !== null && r.whoisAgeDays !== undefined) ||
      (r.whoisExpiryDays !== null && r.whoisExpiryDays !== undefined) ||
      (r.whoisExpiryUnavailableReason && r.whoisExpiryUnavailableReason.message) ||
      isExpired ||
      isYoung ||
      isVeryYoung
    );

    // Some ccTLD registries (e.g. FORTH for .gr / .ελ) do not run a port-43
    // WHOIS server, and the IANA upstream replies with a referral pointing at
    // the registry's web form. The PowerShell side captures that URL into
    // `whoisRegistryWebForm`. Render it as a friendly INFO panel with a
    // clickable link instead of dumping the raw "This TLD has no whois server"
    // banner, so users have a clear next step. Localized strings fall back to
    // English via t() when a language doesn't override them yet.
    const registryWebFormUrl = (typeof r.whoisRegistryWebForm === 'string' && r.whoisRegistryWebForm.trim()) ? r.whoisRegistryWebForm.trim() : '';
    const showRegistryWebFormPanel = !!registryWebFormUrl && !hasStructuredWhoisDetails;
    let registryWebFormHtml = '';
    if (showRegistryWebFormPanel) {
      let displayUrl = registryWebFormUrl;
      try { displayUrl = new URL(registryWebFormUrl).host || registryWebFormUrl; } catch (_) { /* keep raw */ }
      registryWebFormHtml = `
        <div class="rdap-digest-section" style="margin-top:10px;">
          <div class="rdap-digest-title">${escapeHtml(t('registryNoWhoisHeading'))}</div>
          <div style="margin-top:6px;">${escapeHtml(t('registryNoWhoisExplanation', { domain: r.whoisLookupDomain || r.domain || '' }))}</div>
          <div style="margin-top:8px;">
            <a href="${escapeHtml(registryWebFormUrl)}" target="_blank" rel="noopener noreferrer" class="external-link">${escapeHtml(t('registryWebFormCta', { host: displayUrl }))}</a>
          </div>
        </div>`;
    }

    const rawSectionHtml = [];
    if (r.whoisRawRdapText) {
      rawSectionHtml.push(renderRdapDigest(r.whoisRawRdapText));
    }
    if (r.whoisRawText) {
      rawSectionHtml.push(`<div class="rdap-digest-section"><div class="rdap-digest-title">${escapeHtml(`${t('rawLabel')} (${r.whoisSource || t('rawWhoisLabel')})`)}</div><pre class="code rdap-raw-pre">${escapeHtml(r.whoisRawText)}</pre></div>`);
    }
    const hasRawRegistrationData = rawSectionHtml.length > 0;
    const showRawInline = hasRawRegistrationData && !hasStructuredWhoisDetails;
    const rawWhoisButtonOpenLabel = `${t('rawWhoisRdapDataButton')} +`;
    const rawWhoisButtonCloseLabel = `${t('rawWhoisRdapDataButton')} -`;
    const rawWhoisButtonHtml = (hasRawRegistrationData && !showRawInline)
      ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-top:10px;" data-open-label="${escapeHtml(rawWhoisButtonOpenLabel)}" data-close-label="${escapeHtml(rawWhoisButtonCloseLabel)}" onclick="event.stopPropagation(); toggleWhoisRaw(this)">${escapeHtml(rawWhoisButtonOpenLabel)}</button>`
      : '';
    const rawWhoisHtml = hasRawRegistrationData
      ? `<div id="whoisRawData" class="whois-raw-panel" style="margin-top:10px;${showRawInline ? '' : ' display:none;'}">${rawSectionHtml.join('')}</div>`
      : '';
    // Suppress the bare "Domain registration lookup failed." error string when
    // we already have a friendly registry web-form panel to show; the panel
    // explains the situation more clearly than a generic error line.
    const whoisErrorHtml = (r.whoisError && !showRegistryWebFormPanel)
      ? `<div class="code" style="margin-top:10px;">${escapeHtml(t('error'))}: ${escapeHtml(r.whoisError)}</div>`
      : '';

    let whoisLabel = "INFO";
    let whoisTagClass = "tag-info";
    if (isExpired) {
      whoisLabel = "EXPIRED";
      whoisTagClass = "tag-fail";
    } else if (isVeryYoung) {
      whoisLabel = "NEW DOMAIN";
      whoisTagClass = "tag-fail";
    } else if (isYoung) {
      whoisLabel = "NEW DOMAIN";
      whoisTagClass = "tag-warn";
    }

    cards.push(`
  <div class="card" id="card-whois">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag ${whoisTagClass}">${escapeHtml(translateBadge(whoisLabel))}</span>
      <strong>${escapeHtml(t('domainRegistration'))}</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, 'whois')">${escapeHtml(t('copy'))}</button>
    </div>
    <div id="field-whois" class="card-content">
      ${whoisRows.length > 0 ? `<div class="kv-grid">${whoisRows.join('')}</div>` : `<div class="code">${escapeHtml(t('noRegistrationInformation'))}</div>`}
      ${registryWebFormHtml}
      ${rawWhoisButtonHtml}
      ${rawWhoisHtml}
      ${whoisErrorHtml}
    </div>
  </div>
    `);
  }

  {
  const baseLoaded = loaded.base && !errors.base && txtLookupResolved;
    const ipv4List = Array.isArray(txtRecovery.ipv4Addresses) ? txtRecovery.ipv4Addresses : [];
    const ipv6List = Array.isArray(txtRecovery.ipv6Addresses) ? txtRecovery.ipv6Addresses : [];
    const ipLookupDomain = txtRecovery.ipLookupDomain || r.ipLookupDomain || r.domain;
    const ipUsedParent = txtRecovery.ipUsedParent === true && ipLookupDomain && ipLookupDomain !== r.domain;
  const domainLabel = basePending ? "PENDING" : (baseError ? "ERROR" : (txtLookupResolved ? "LOOKED UP" : "DNS ERROR"));
    const domainClass = basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info");

    const ipNote = baseLoaded && ipUsedParent
      ? `<div class="code code-lite" style="margin-top:6px;">${escapeHtml(t('usingIpParent', { domain: ipLookupDomain, queryDomain: r.domain || '' }))}</div>`
      : '';

    const ipvTable = baseLoaded ? `
      <div class="code code-lite" style="margin-top:6px;">
        <table class="mx-table">
          <thead>
            <tr>
              <th style="width: 120px;">${escapeHtml(t('type'))}</th>
              <th>${escapeHtml(t('addresses'))}</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>${escapeHtml(t('ipv4'))}</td><td>${ipv4List.length ? ipv4List.map(escapeHtml).join(', ') : escapeHtml(t('none'))}</td></tr>
            <tr><td>${escapeHtml(t('ipv6'))}</td><td>${ipv6List.length ? ipv6List.map(escapeHtml).join(', ') : escapeHtml(t('none'))}</td></tr>
          </tbody>
        </table>
      </div>
    ` : '';

    cards.push(`
      <div class="card" id="card-domain">
        <div class="card-header" onclick="toggleCard(this)">
          <span class="chevron">&#x25BC;</span>
          <span class="tag ${domainClass}">${escapeHtml(translateBadge(domainLabel))}</span>
          <strong>${escapeHtml(t('domain'))}</strong>
        </div>
        <div class="card-content">
      <div id="field-domain" class="code code-lite">${escapeHtml(r.domain || t('noRecordsAvailable'))}</div>
          ${ipNote}${ipvTable}
        </div>
      </div>
    `);
  }

  if (!loaded.records && !errors.records) {
    cards.push(card(
      t('dnsRecords'),
      t('loadingValue'),
      'LOADING',
      'tag-info',
      'records',
      true
    ));
  } else if (errors.records) {
    cards.push(card(
      t('dnsRecords'),
      errors.records,
      'ERROR',
      'tag-fail',
      'records',
      true
    ));
  } else {
    const recordsBody = renderDnsRecordsTable(r.dnsRecords);
    const recordsErrorHtml = r.dnsRecordsError
      ? `<div class="code" style="margin-top:10px;">${escapeHtml(t('error'))}: ${escapeHtml(r.dnsRecordsError)}</div>`
      : '';

    cards.push(`
      <div class="card" id="card-records">
        <div class="card-header" onclick="toggleCard(this)">
          <span class="chevron">&#x25BC;</span>
          <span class="tag tag-info">${escapeHtml(t('info'))}</span>
          <strong>${escapeHtml(t('dnsRecords'))}</strong>
          <button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, 'records')">${escapeHtml(t('copy'))}</button>
        </div>
        <div id="field-records" class="card-content">
          ${recordsBody}
          ${recordsErrorHtml}
        </div>
      </div>
    `);
  }

  // MX (placed directly below Domain per UI request)
  if (!loaded.mx && !errors.mx) {
    cards.push(card(
      t('mxRecords'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "mx",
      false
    ));
  } else if (errors.mx) {
    cards.push(card(
      t('mxRecords'),
      errors.mx,
      "ERROR",
      "tag-fail",
      "mx",
      false
    ));
  } else {
    let mxFallbackNote = '';
    if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('noMxParentShowing', { domain: r.domain || '', lookupDomain: mxLookupDomain }))}</div>`;
    } else if ((!r.mxRecords || r.mxRecords.length === 0) && mxFallbackChecked && mxFallbackChecked !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('noMxParentChecked', { domain: r.domain || '', parentDomain: mxFallbackChecked }))}</div>`;
    }

    const ipv4Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv4");
    const ipv6Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv6");
    const noIpRecords = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "N/A");

    let mxDetailsContent = "";

    if (ipv4Records.length > 0) {
      const ipv4Rows = ipv4Records.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('ipv4Addresses'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('ipAddress'))}</th>
            </tr>
          </thead>
          <tbody>${ipv4Rows}</tbody>
        </table>
      </div>`;
    }

    if (ipv6Records.length > 0) {
      const ipv6Rows = ipv6Records.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('ipv6Addresses'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('ipAddress'))}</th>
            </tr>
          </thead>
          <tbody>${ipv6Rows}</tbody>
        </table>
      </div>`;
    }

    if (noIpRecords.length > 0) {
      const noIpRows = noIpRecords.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div>
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('noIpAddressesFound'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('status'))}</th>
            </tr>
          </thead>
          <tbody>${noIpRows}</tbody>
        </table>
      </div>`;
    }

    if (!mxDetailsContent) {
      mxDetailsContent = `<div class="code">${escapeHtml(t('noAdditionalMxDetails'))}</div>`;
    }

    cards.push(`
  <div class="card" id="card-mx">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('info'))}</span>
      <strong>${escapeHtml(t('mxRecords'))}</strong>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              style="margin-left: auto;"
              onclick="event.stopPropagation(); toggleMxDetails(this)">
        ${escapeHtml(t('additionalDetailsPlus'))}
      </button>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              onclick="event.stopPropagation(); copyField(this, 'mx')">
        ${escapeHtml(t('copy'))}
      </button>
    </div>
    <div class="card-content">
      ${mxFallbackNote}
      ${r.mxProvider ? `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('detectedProvider'))}: ${escapeHtml(r.mxProvider)}${getLocalizedMxProviderHint(r.mxProvider, r.mxProviderHint) ? " \u2014 " + escapeHtml(getLocalizedMxProviderHint(r.mxProvider, r.mxProviderHint)) : ""}</div>` : ""}
      <div id="field-mx" class="code">${escapeHtml((r.mxRecords || []).join("\n") || t('noRecordsAvailable'))}</div>
      <div id="mxDetails" style="margin-top:6px; display:none;">${mxDetailsContent}</div>
    </div>
  </div>
    `);
  }

  // Match card order to the Check Summary.
  const spfCardBaseValue = loaded.base
    ? (effectiveSpfValue || ((r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('none')}: ${r.domain}\n\n${t('resolvedUsingGuidance', { lookupDomain: r.txtLookupDomain })}\n${r.parentSpfValue || ''}`) : null))
    : (baseError ? (errors.base || t('error')) : t('loadingValue'));
  const spfCardValue = [spfCardBaseValue, getLocalizedSpfRequirementSummary({ spfPresent: effectiveSpfPresent, spfHasRequiredInclude: effectiveSpfHasRequiredInclude, spfRequiredIncludeMatchType: effectiveSpfRequiredIncludeMatchType, spfRequiredIncludeProvider: r && r.spfRequiredIncludeProvider })].filter(Boolean).join("\n\n");
  // The SPF card body intentionally stops at the record value + ACS Outlook
  // requirement verdict. The full expanded SPF chain (per-node domain,
  // resolved TXT, and lookup-count contributions) is rendered as a
  // structured table in the sibling SPF Expansion Records card below, so
  // duplicating the same data here as an indented text dump just adds
  // visual noise. (The server still emits r.spfExpandedText for raw API
  // consumers.)
  //
  // The "Explained" toggle below decomposes the queried-domain SPF record
  // into a Prefix / Type / Value / PrefixDesc / Description table inspired
  // by MXToolbox's SPF Record Lookup. It only operates on the local record
  // string, so no DNS is involved. We hand the toggle button to card() via
  // titleSuffixHtml (placed next to the title) and the hidden details panel
  // via appendHtml (placed after the card body but outside field-spf, so
  // the Copy button does not include the explained markup in the clipboard).
  //
  // When the panel is open, toggleSpfExplained() also hides #field-spf to
  // avoid showing the raw record twice (once in the card body, once at the
  // top of the panel). Any contextual notes that lived in the card body --
  // the ACS Outlook requirement summary, and the "resolved using parent
  // domain" line when SPF was inherited -- are mirrored INSIDE the panel
  // above the record box so hiding the body does not drop that context.
  //
  // The CLOSED card body is also upgraded to render the raw record in the
  // same green token-style box and the requirement verdict in the same
  // green note box used by the Explained panel, so the two views stay
  // visually consistent. Built only when a real v=spf1 record is present;
  // missing/error/loading states still fall back to the plain text body so
  // their messaging stays unchanged.
  let spfExplainedTitleSuffix = '';
  let spfExplainedAppend = '';
  let spfBodyHtml = '';
  if (loaded.base && spfCardBaseValue) {
    const spfRawForParse = (effectiveSpfValue || (r.parentSpfPresent && r.txtUsedParent ? r.parentSpfValue : '') || '').split(/\r?\n/)[0].trim();
    if (spfRawForParse && /^v=spf1/i.test(spfRawForParse)) {
      // Mirror the "resolved using parent domain" note inside the panel so
      // operators still see why an inherited SPF record is being explained.
      const isInheritedFromParent = !!(r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain);
      const spfInheritedNote = isInheritedFromParent
        ? `<div class="spf-explained-inherited">${escapeHtml(t('resolvedUsingGuidance', { lookupDomain: r.txtLookupDomain }))}</div>`
        : '';
      // Mirror the ACS Outlook requirement verdict inside the panel. This
      // is the same string the card body would normally show under the raw
      // record. Empty when no verdict is available (e.g., no SPF at all).
      const spfRequirementText = getLocalizedSpfRequirementSummary({ spfPresent: effectiveSpfPresent, spfHasRequiredInclude: effectiveSpfHasRequiredInclude, spfRequiredIncludeMatchType: effectiveSpfRequiredIncludeMatchType, spfRequiredIncludeProvider: r && r.spfRequiredIncludeProvider });
      const spfRequirementNote = spfRequirementText
        ? `<div class="spf-explained-requirement">${escapeHtml(spfRequirementText)}</div>`
        : '';
      const explainedHtml = spfInheritedNote + spfRequirementNote + buildSpfExplainedHtml(spfRawForParse);
      spfExplainedTitleSuffix = `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); toggleSpfExplained(this)" title="${escapeHtml(t('spfExplainedTooltip'))}">${escapeHtml(t('spfExplainedShow'))}</button>`;
      spfExplainedAppend = `<div id="spfExplained" class="card-content" style="display:none;">${explainedHtml}</div>`;

      // Closed-card body: same boxed presentation as the Explained panel
      // minus the breakdown table and legend. We intentionally do NOT
      // tokenize the record here (no hover-highlight targets exist when
      // the table isn't rendered), so a plain pre-formatted green box is
      // sufficient. innerText of #field-spf still reads as clean plain
      // text for the Copy button.
      const spfRecordBoxHtml = `<div class="spf-explained-record">${escapeHtml(spfRawForParse)}</div>`;
      spfBodyHtml = spfInheritedNote + spfRecordBoxHtml + spfRequirementNote;
    }
  }
  cards.push(card(
    t('spfQueried'),
    (spfCardValue || t('noRecordsAvailable')),
    basePending ? "LOADING" : (baseError ? "ERROR" : ((effectiveSpfPresent && effectiveSpfHasRequiredInclude === true) ? "PASS" : ((effectiveSpfPresent && effectiveSpfIsMacroDelegated) ? "WARN" : "FAIL"))),
    basePending ? "tag-info" : (baseError ? "tag-fail" : ((effectiveSpfPresent && effectiveSpfHasRequiredInclude === true) ? "tag-pass" : ((effectiveSpfPresent && effectiveSpfIsMacroDelegated) ? "tag-warn" : "tag-fail"))),
    "spf",
    true,
    spfExplainedTitleSuffix,
    spfExplainedAppend,
    spfBodyHtml
  ));

  // Sibling card listing every include/redirect target the SPF expansion resolved,
  // along with the actual TXT record returned for each. This keeps the main DNS
  // records table scoped to the queried domain while still surfacing the resolved
  // third-party SPF chain for troubleshooting.
  if (loaded.base && r.spfAnalysis && (effectiveSpfPresent || r.spfPresent)) {
    const spfExpansionBodyHtml = buildSpfExpansionCardHtml(r.spfAnalysis, r.domain);
    cards.push(`
  <div class="card" id="card-spfExpansion">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(translateBadge('INFO'))}</span>
      <strong>${escapeHtml(t('spfExpansionRecordsTitle'))}</strong>
    </div>
    <div class="card-content">${spfExpansionBodyHtml}</div>
  </div>`);
  }

  cards.push(card(
    t('acsDomainVerificationTxt'),
    loaded.base ? (effectiveAcsValue || ((r.parentAcsPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noRecordOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainAcsTxtInfo', { lookupDomain: r.txtLookupDomain })}\n${r.parentAcsValue || ''}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
    basePending ? "LOADING" : (baseError ? "ERROR" : (effectiveAcsPresent ? "PASS" : "MISSING")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (effectiveAcsPresent ? "tag-pass" : "tag-fail")),
    "acsTxt"
  ));

  cards.push(card(
    t('txtRecordsQueried'),
    loaded.base ? ((effectiveTxtRecords.join("\n")) || ((r.parentTxtRecords && r.parentTxtRecords.length > 0 && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noTxtRecordsOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainTxtRecordsInfo', { lookupDomain: r.txtLookupDomain })}\n${(r.parentTxtRecords || []).join("\n")}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
    basePending ? "LOADING" : (baseError ? "ERROR" : "INFO"),
    basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info"),
    "txtRecords",
    false
  ));

  // DMARC Explained toggle. Mirrors the SPF Explained pattern: when the
  // DMARC record is present, decompose it into a Tag / Value / TagDesc /
  // ValueDesc table inspired by MXToolbox's DMARC Record Lookup. The button
  // is rendered via titleSuffixHtml so it sits next to the title; the hidden
  // panel is appended OUTSIDE the field-dmarc div via appendHtml so the
  // Copy button (which reads innerText of field-dmarc) does not include the
  // explained markup in the clipboard.
  //
  // When the panel is open, toggleDmarcExplained() also hides #field-dmarc
  // to avoid showing the raw record twice (once in the card body, once at
  // the top of the panel). If the DMARC policy was inherited from a parent
  // domain, we surface that note inside the panel as well so hiding the
  // body does not drop that context.
  let dmarcExplainedTitleSuffix = '';
  let dmarcExplainedAppend = '';
  if (loaded.dmarc && r.dmarc) {
    const dmarcRawForParse = String(r.dmarc).split(/\r?\n/)[0].trim();
    if (dmarcRawForParse && /^v=DMARC1/i.test(dmarcRawForParse)) {
      const inheritedNote = (r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain)
        ? `<div class="dmarc-explained-inherited">${escapeHtml(t('effectivePolicyInherited', { lookupDomain: r.dmarcLookupDomain }))}</div>`
        : '';
      const dmarcExplainedHtml = inheritedNote + buildDmarcExplainedHtml(dmarcRawForParse);
      dmarcExplainedTitleSuffix = `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); toggleDmarcExplained(this)" title="${escapeHtml(t('dmarcExplainedTooltip'))}">${escapeHtml(t('dmarcExplainedShow'))}</button>`;
      dmarcExplainedAppend = `<div id="dmarcExplained" class="card-content" style="display:none;">${dmarcExplainedHtml}</div>`;
    }
  }
  cards.push(card(
    t('dmarc'),
    loaded.dmarc ? (r.dmarc ? (r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain ? (`${r.dmarc}\n\n${t('effectivePolicyInherited', { lookupDomain: r.dmarcLookupDomain })}`) : r.dmarc) : null) : (errors.dmarc ? errors.dmarc : t('loadingValue')),
    (!loaded.dmarc && !errors.dmarc) ? "LOADING" : (errors.dmarc ? "ERROR" : (r.dmarc ? "PASS" : "OPTIONAL")),
    (!loaded.dmarc && !errors.dmarc) ? "tag-info" : (errors.dmarc ? "tag-fail" : (r.dmarc ? "tag-pass" : "tag-info")),
    "dmarc",
    true,
    dmarcExplainedTitleSuffix,
    dmarcExplainedAppend
  ));

  // include full selector host with domain in title.
  // ONE tag only, driven by the strict ACS-specific check (`dkim*AcsConfigured`):
  //   - PASS     => CNAME at the ACS selector matches the ACS-managed target
  //   - FAIL     => something is published at the ACS selector hostname but
  //                 does not point at ACS (will not satisfy ACS verification)
  //   - OPTIONAL => nothing is published at the ACS selector hostname
  //
  // Card body shows ONLY the published record value(s) -- either the ACS
  // selector chain (CNAME + TXT) or, when the ACS selector is missing, the
  // fallback selector chain that the server-side probe discovered. When the
  // displayed records are NOT the ACS selector itself, we render a separate
  // yellow warning bubble below the body so the operator can immediately see
  // the records on screen are alternate DKIM, not the ACS-required selector.
  // The warning HTML is intentionally inline-styled (no new CSS class) to keep
  // this UI tweak self-contained.
  function buildDkimAcsMissingNotice() {
    // English string is intentionally hardcoded here to stay consistent with
    // the existing DKIM client-side fallback guidance (no translation key has
    // been added across the i18n tables yet). The notice is purely
    // informational; the canonical PASS/FAIL/OPTIONAL contract lives in the
    // card tag. Rendered OUTSIDE the field-${key} div so the Copy button
    // (which reads `innerText` of that div) does not include this prose.
    return '<div class="card-content" style="margin:0 12px 12px 12px; padding:8px 10px; '
      + 'background:#fff8e1; border:1px solid #f9d976; border-radius:6px; color:#5c3c00; '
      + 'font-size:0.9em; display:flex; gap:8px; align-items:flex-start;">'
      + '<span aria-hidden="true" style="font-size:1.1em; line-height:1;">&#x26A0;&#xFE0F;</span>'
      + '<span>ACS selector not published. The records shown above are alternate DKIM selectors detected on this domain.</span>'
      + '</div>';
  }

  // Render one selector "block": a header line with the selector hostname and a
  // small Type | Value grid for whichever record types are present. All
  // user-derived strings are escaped. Returns '' when the selector has no
  // record content so the caller can filter empty blocks out.
  function buildDkimSelectorBlockHtml(name, cnameTarget, txtValue) {
    const safeName = escapeHtml(String(name || ''));
    const rows = [];
    if (cnameTarget) {
      rows.push(
        '<div class="dkim-record-type">CNAME</div>'
        + '<div class="dkim-record-value">' + escapeHtml(String(cnameTarget)) + '</div>'
      );
    }
    if (txtValue) {
      rows.push(
        '<div class="dkim-record-type">TXT</div>'
        + '<div class="dkim-record-value">' + escapeHtml(String(txtValue)) + '</div>'
      );
    }
    if (rows.length === 0) return '';
    return '<div class="dkim-selector-block">'
      + '<div class="dkim-selector-name">' + safeName + '</div>'
      + '<div class="dkim-record-grid">' + rows.join('') + '</div>'
      + '</div>';
  }

  // Build the full rich body for a DKIM card. Three cases:
  //   1. ACS selector itself has CNAME/TXT  -> render single block for the ACS
  //      selector hostname (the strict ACS PASS/FAIL applies)
  //   2. Only fallback selectors detected   -> render one block per fallback
  //      selector row returned by the server
  //   3. Nothing                            -> '' (caller falls back to the
  //      default escaped "No Records Available" text body)
  function buildDkimBodyHtml(domain, slot, acsCnameTarget, acsTxtValue, fallbackSelectors) {
    if (acsCnameTarget || acsTxtValue) {
      const acsName = 'selector' + slot + '-azurecomm-prod-net._domainkey.' + (domain || '');
      const block = buildDkimSelectorBlockHtml(acsName, acsCnameTarget, acsTxtValue);
      return block ? '<div class="dkim-record-list">' + block + '</div>' : '';
    }

    const rows = Array.isArray(fallbackSelectors) ? fallbackSelectors : [];
    const blocks = rows
      .map(row => row ? buildDkimSelectorBlockHtml(row.Name, row.CnameTarget, row.TxtValue) : '')
      .filter(Boolean);
    if (blocks.length === 0) return '';
    return '<div class="dkim-record-list">' + blocks.join('') + '</div>';
  }

  const dkim1HasAcsSelectorRecord = !!(r.dkim1CnameTarget || r.dkim1TxtValue);
  // Plain-text fallback body used when the rich HTML body is empty (loading,
  // error, or truly nothing-found cases). r.dkim1 already contains the
  // server-built display string for a non-empty record set, but we prefer the
  // rich HTML when the data is structured enough to render it.
  const dkim1PlainBody = loaded.dkim
    ? (r.dkim1 || null)
    : (errors.dkim ? errors.dkim : t('loadingValue'));
  const dkim1RichBody = loaded.dkim && !errors.dkim
    ? buildDkimBodyHtml(r.domain, 1, r.dkim1CnameTarget, r.dkim1TxtValue, r.dkim1FallbackSelectors)
    : '';
  const dkim1Tag = (!loaded.dkim && !errors.dkim)
    ? "LOADING"
    : (errors.dkim ? "ERROR" : (r.dkim1AcsConfigured ? "PASS" : (dkim1HasAcsSelectorRecord ? "FAIL" : "OPTIONAL")));
  const dkim1TagClass = (!loaded.dkim && !errors.dkim)
    ? "tag-info"
    : (errors.dkim ? "tag-fail" : (r.dkim1AcsConfigured ? "tag-pass" : (dkim1HasAcsSelectorRecord ? "tag-fail" : "tag-info")));
  const dkim1ShowAcsMissingNotice = loaded.dkim && !errors.dkim
    && !dkim1HasAcsSelectorRecord && !!dkim1RichBody;
  cards.push(card(
    `${t('dkim1Title')} (selector1-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    dkim1PlainBody,
    dkim1Tag,
    dkim1TagClass,
    "dkim1",
    true,
    '',
    dkim1ShowAcsMissingNotice ? buildDkimAcsMissingNotice() : '',
    dkim1RichBody
  ));

  const dkim2HasAcsSelectorRecord = !!(r.dkim2CnameTarget || r.dkim2TxtValue);
  const dkim2PlainBody = loaded.dkim
    ? (r.dkim2 || null)
    : (errors.dkim ? errors.dkim : t('loadingValue'));
  const dkim2RichBody = loaded.dkim && !errors.dkim
    ? buildDkimBodyHtml(r.domain, 2, r.dkim2CnameTarget, r.dkim2TxtValue, r.dkim2FallbackSelectors)
    : '';
  const dkim2Tag = (!loaded.dkim && !errors.dkim)
    ? "LOADING"
    : (errors.dkim ? "ERROR" : (r.dkim2AcsConfigured ? "PASS" : (dkim2HasAcsSelectorRecord ? "FAIL" : "OPTIONAL")));
  const dkim2TagClass = (!loaded.dkim && !errors.dkim)
    ? "tag-info"
    : (errors.dkim ? "tag-fail" : (r.dkim2AcsConfigured ? "tag-pass" : (dkim2HasAcsSelectorRecord ? "tag-fail" : "tag-info")));
  const dkim2ShowAcsMissingNotice = loaded.dkim && !errors.dkim
    && !dkim2HasAcsSelectorRecord && !!dkim2RichBody;
  cards.push(card(
    `${t('dkim2Title')} (selector2-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    dkim2PlainBody,
    dkim2Tag,
    dkim2TagClass,
    "dkim2",
    true,
    '',
    dkim2ShowAcsMissingNotice ? buildDkimAcsMissingNotice() : '',
    dkim2RichBody
  ));

  // Reputation / DNSBL
  if (!loaded.reputation && !errors.reputation) {
    cards.push(card(
      t('reputationDnsbl'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "reputation",
      false,
      multiRblHtml
    ));
  } else if (errors.reputation) {
    cards.push(card(
      t('reputationDnsbl'),
      errors.reputation,
      "ERROR",
      "tag-fail",
      "reputation",
      false,
      `<button type="button" class="info-dot" aria-label="${escapeHtml(reputationInfo)}" data-info="${escapeHtml(reputationInfo)}">i</button> ${multiRblHtml}`
    ));
  } else {
    const rep = r.reputation || {};
    const summary = rep.summary || {};
    const listed = summary.listedCount || 0;
    const errorCount = summary.errorCount || 0;
    const notListed = summary.notListedCount || 0;
    const total = summary.totalQueries || 0;
    const repUsedParent = rep.lookupUsedParent === true && rep.lookupDomain && rep.lookupDomain !== (r.domain || '');
    const validQueries = Math.max(0, total - errorCount);

    let percent = null;
    if (validQueries > 0) {
      percent = Math.max(0, Math.min(100, Math.round((notListed / validQueries) * 100)));
    }

    let rating = t('unknown');
    if (percent !== null) {
      if (percent >= 99) rating = t('excellent');
      else if (percent >= 90) rating = t('great');
      else if (percent >= 75) rating = t('good');
      else if (percent >= 50) rating = t('fair');
      else rating = t('poor');
    }

    const statusLabel = percent === null ? t('unknown') : `${rating.toUpperCase()} (${percent}%)`;
    const statusClass = percent === null ? "tag-info"
      : (percent >= 90 ? "tag-pass"
      : (percent >= 75 ? "tag-info" : "tag-fail"));

    // Show only listed entries to avoid noise
    const listedItems = (rep.results || []).filter(x => x && x.listed === true);
    let body = `${t('zonesQueried')}: ${rep.rblZones ? rep.rblZones.length : 0}\n` +
               `${t('totalQueries')}: ${total}\n` +
               `${t('errorsCount')}: ${errorCount}`;
    if (percent !== null) {
    const riskSummary = localizeRiskSummary(summary.riskSummary || 'Clean');
      body += `\n${t('riskLabel')}: ${riskSummary} | ${t('reputationWord')}: ${rating} (${percent}%)`;
      body += `\n${t('listed')}: ${listed}\n${t('notListed')}: ${notListed}`;
    } else {
      const riskSummary = localizeRiskSummary(summary.riskSummary || 'Clean');
      body += `\n${t('riskLabel')}: ${riskSummary}`;
      body += `\n${t('reputationWord')}: ${t('noSuccessfulQueries')}`;
    }
    if (listedItems.length > 0) {
      const lines = listedItems.map(x => t('listedOnZone', {
        ip: x.ip,
        zone: x.queriedZone,
        suffix: x.listedAddress ? ` (${x.listedAddress})` : ''
      }));
      body += `\n\n${t('listingsLabel')}:\n` + lines.join("\n");
    }

    cards.push(card(
      t('reputationDnsbl'),
      body,
      statusLabel,
      statusClass,
      "reputation",
      false,
      `<button type="button" class="info-dot" aria-label="${escapeHtml(reputationInfo)}" data-info="${escapeHtml(reputationInfo)}">i</button> ${multiRblHtml}`
    ));
  }

  cards.push(card(
    t('cname'),
    loaded.cname ? (r.cname ? (r.cnameUsedWwwFallback && r.cnameLookupDomain && r.cnameLookupDomain !== r.domain ? (`${r.cname}\n\n${t('resolvedUsingGuidance', { lookupDomain: r.cnameLookupDomain })}`) : r.cname) : null) : (errors.cname ? errors.cname : t('loadingValue')),
    (!loaded.cname && !errors.cname) ? "LOADING" : (errors.cname ? "ERROR" : (r.cname ? "PASS" : "FAIL")),
    (!loaded.cname && !errors.cname) ? "tag-info" : (errors.cname ? "tag-fail" : (r.cname ? "tag-pass" : "tag-fail")),
    "cname"
  ));

  const guidanceWorkflowComplete = Object.values(loaded).length > 0 && Object.values(loaded).every(Boolean);
  const guidanceItems = (r.guidance || []).map(g => {
    let iconHtml = '';
    let text = g;
    let type = 'info';

    if (typeof g === 'object' && g !== null) {
      text = g.text;
      type = g.type || 'info';
    }

    let iconClass = 'icon-info';
    let iconSrc = getLucideIconUrl('info');
    let iconTitle = t('guidanceIconInformational');

    if (type === 'error') {
      iconClass = 'icon-error';
      iconSrc = getLucideIconUrl('alert-circle');
      iconTitle = t('guidanceIconError');
    } else if (type === 'attention') {
      iconClass = 'icon-warning';
      iconSrc = getLucideIconUrl('triangle-alert');
      iconTitle = t('guidanceIconAttention');
    } else if (type === 'success') {
      iconClass = 'icon-success';
      iconSrc = getLucideIconUrl('check-circle');
      iconTitle = t('guidanceIconSuccess');
    }

    iconHtml = `<img src="${iconSrc}" class="status-icon ${iconClass}" alt="${iconTitle}" title="${iconTitle}" />`;

    return '<li style="display:flex; align-items:flex-start; gap:8px; margin-bottom:8px;">' + iconHtml + '<span style="padding-top:2px;">' + formatGuidanceText(text, r.domain || '') + '</span></li>';
  }).join("");
  cards.push(`
    <div class="card" id="card-guidance">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('readinessTips'))}</span>
        <strong>${renderLabelWithIcon('guidance')}</strong>
        <div class="card-icons" style="margin-left: auto; font-size: 0.8em; display: flex; align-items: center; gap: 6px;">
           <img src="${getLucideIconUrl('triangle-alert')}" class="status-icon icon-warning" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendAttention'))}"/> <span style="margin-right: 8px;">${escapeHtml(t('guidanceLegendAttention'))}</span>
           <img src="${getLucideIconUrl('info')}" class="status-icon icon-info" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendInformational'))}"/> <span>${escapeHtml(t('guidanceLegendInformational'))}</span>
        </div>
      </div>
      <div id="field-guidance" class="card-content">
        <ul class="guidance">
          ${guidanceItems || `<li>${escapeHtml(guidanceWorkflowComplete ? t('noAdditionalGuidance') : t('loadingValue'))}</li>`}
        </ul>
      </div>
    </div>
  `);

  cards.push(`
    <div class="card" id="card-helpfulLinks">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('docs'))}</span>
        <strong>${escapeHtml(t('helpfulLinks'))}</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="https://learn.microsoft.com/azure/communication-services/quickstarts/email/add-custom-verified-domains" target="_blank" rel="noopener">${escapeHtml(t('acsEmailDomainVerification'))}</a></li>
          <li><a href="https://learn.microsoft.com/azure/communication-services/concepts/email/email-quota-increase" target="_blank" rel="noopener">${escapeHtml(t('acsEmailQuotaLimitIncrease'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure" target="_blank" rel="noopener">${escapeHtml(t('spfRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records" target="_blank" rel="noopener">${escapeHtml(t('dmarcRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure" target="_blank" rel="noopener">${escapeHtml(t('dkimRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider?view=o365-worldwide" target="_blank" rel="noopener">${escapeHtml(t('mxRecordBasics'))}</a></li>
        </ul>
      </div>
    </div>
  `);

  const domainForLinks = encodeURIComponent(r.domain || "");
  const centralOps = `https://centralops.net/co/DomainDossier.aspx?addr=${domainForLinks}&dom_whois=true&dom_dns=true&traceroute=true&net_whois=true&svc_scan=true`;
  const multiRbl = `https://multirbl.valli.org/dnsbl-lookup/${domainForLinks}.html`;
  // MXToolbox SuperTool deep-link: the SuperTool action string is a single
  // colon-prefixed parameter ("domain:<name>") that the form URL-encodes as
  // "domain%3A<name>". `domainForLinks` is already URI-component-encoded, so
  // appending it after the literal "domain%3A" produces a valid SuperTool URL
  // that lands directly on a domain-scoped lookup view.
  const mxToolbox = `https://mxtoolbox.com/SuperTool.aspx?action=domain%3A${domainForLinks}&run=toolpage`;
  cards.push(`
    <div class="card" id="card-tools">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('tools'))}</span>
        <strong>${escapeHtml(t('externalTools'))}</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="${centralOps}" target="_blank" rel="noopener">${escapeHtml(t('domainDossier'))}</a></li>
          <li><a href="${multiRbl}" target="_blank" rel="noopener">${escapeHtml(t('multiRblLookup'))}</a></li>
          <li><a href="${mxToolbox}" target="_blank" rel="noopener">${escapeHtml(t('mxToolboxSuperTool'))}</a></li>
        </ul>
      </div>
    </div>
  `);

  // Prepend a "Jump to section" navigation card so users can quickly scroll to
  // any returned result card. It is derived from the assembled card markup so it
  // always matches the cards that actually rendered, in their on-page order.
  const cardsMarkup = cards.join("");
  const sectionNavHtml = buildSectionNavHtml(cardsMarkup);
  renderResultsMarkup(sectionNavHtml + cardsMarkup);

  // Build the floating left-hand section rail + scrollspy. Deferred so it runs
  // after renderResultsMarkup has committed the cards to the DOM (which may be
  // delayed by the section-reveal animation), otherwise the IntersectionObserver
  // would have no card elements to watch.
  scheduleSectionRailBuild(cardsMarkup);
}

// Rebuild the floating section rail once the results DOM is in place. We poll a
// couple of animation frames for the first card to exist so the rail works
// whether renderResultsMarkup committed synchronously or after a reveal delay.
let _sectionRailBuildTimer = null;
function scheduleSectionRailBuild(markup) {
  if (_sectionRailBuildTimer) {
    clearTimeout(_sectionRailBuildTimer);
    _sectionRailBuildTimer = null;
  }
  let attempts = 0;
  const tryBuild = () => {
    attempts++;
    const ready = document.querySelector('#results .card[id^="card-"]');
    if (ready || attempts > 60) {
      buildSectionRail(markup);
      return;
    }
    _sectionRailBuildTimer = window.setTimeout(tryBuild, 50);
  };
  tryBuild();
}

let _loadingDotsTimer = null;
function startLoadingDotAnimations() {
  if (_loadingDotsTimer) { clearInterval(_loadingDotsTimer); _loadingDotsTimer = null; }
  const codeEls = document.querySelectorAll('#results .code');
  const targets = [];
  codeEls.forEach(el => {
    const txt = el.textContent || '';
    if (txt.length > 3 && txt.endsWith('...') && !el.querySelector('.loading-dot')) {
      const base = txt.slice(0, -3);
      el.innerHTML = escapeHtml(base)
        + '<span class="loading-dot">.</span>'
        + '<span class="loading-dot">.</span>'
        + '<span class="loading-dot">.</span>';
      el.classList.add('loading-dots');
      targets.push(el);
    }
  });
  document.querySelectorAll('#status .loading-dots').forEach(el => targets.push(el));
  if (targets.length === 0) return;
  let step = 0;
  _loadingDotsTimer = setInterval(() => {
    const active = document.querySelectorAll('#results .loading-dots, #status .loading-dots');
    if (active.length === 0) { clearInterval(_loadingDotsTimer); _loadingDotsTimer = null; return; }
    active.forEach(el => {
      const dots = el.querySelectorAll('.loading-dot');
      dots.forEach((d, i) => {
        d.classList.toggle('active', i === step % 3);
      });
    });
    step++;
  }, 400);
}

document.getElementById("domainInput").addEventListener("keyup", function (e) {
  if (e.key === "Enter") {
    lookup();
  }
});

// ===== Customer Intake Form (rich-text editor) =====
// The intake section is a single contenteditable region. We persist both
// the HTML (for the rich Copy Email Quota output) and a plain-text
// projection (used when the clipboard target only accepts text). Storage
// is gated through the same consent-aware wrapper as the rest of the app.
const INTAKE_STORAGE_KEY = 'acsIntakeRich';
const INTAKE_TEMPLATE_HTML = [
  '<p><strong>Customer Information</strong></p>',
  '<ul>',
  '<li>Company name: </li>',
  '<li>Company website: </li>',
  '<li>Provide a brief description of your business: </li>',
  '</ul>',
  '<p><strong>Email Service Information</strong></p>',
  '<ul>',
  '<li>Subscription ID: </li>',
  '<li>Azure Communication Services Resource Name: </li>',
  '<li>Is your custom domain already set up and currently used for sending messages: </li>',
  '<li>Indicate the domain from which you are currently sending emails: </li>',
  '</ul>',
  '<p><strong>Usage Information</strong></p>',
  '<ol>',
  '<li>What type of emails do you send? (such as Transactional, Marketing, Promotional) </li>',
  '<li>Specify the expected volume of emails you plan to send:',
  '<ul>',
  '<li>What is the maximum rate of messages per minute that you require? </li>',
  '<li>What is the maximum rate of messages per hour that you require? </li>',
  '<li>What is the maximum rate of messages per day that you require? </li>',
  '</ul></li>',
  '<li>What is the maximum attachment size (in MB) that you require? </li>',
  '</ol>',
  '<p><strong>Additional Information</strong></p>',
  '<p>What is the source of the email addresses that you use for sending your messages?</p>',
  '<p><em>Note: The source of the email addresses that you send your messages to plays a crucial role in the effectiveness and compliance of your email marketing campaigns. Providing details about the source of your email addresses helps us understand how you acquire and maintain your subscriber list.</em></p>',
  '<p><br></p>',
  '<p>How do you currently manage and remove email addresses that have unsubscribed or resulted in bounce backs from your mailing list?</p>',
  '<p><em>Explain if you have an automated process in place that handles unsubscribes when recipients click on the \'unsubscribe\' link in your emails. Additionally, if you receive bounce/undeliverable notifications, can you include how you handle those and whether you have any mechanism to automatically remove email addresses that result in consistent bounces.</em></p>',
  '<p><br></p>'
].join('');

function getIntakeEditor() { return document.getElementById('intakeRichEditor'); }

function loadIntakeForm() {
  const editor = getIntakeEditor();
  if (!editor) return;
  let html = '';
  try { html = consentAwareGetItem(INTAKE_STORAGE_KEY, 'functional') || ''; } catch (_) {}
  if (html) editor.innerHTML = html;

  if (!editor.__intakeBound) {
    editor.addEventListener('input', saveIntakeForm);
    editor.addEventListener('blur', saveIntakeForm);
    // Strip styles from pasted content but keep structural markup so the
    // copied payload doesn't inherit weird fonts/colors from the source.
    editor.addEventListener('paste', handleIntakePaste);
    bindIntakeToolbar();
    editor.__intakeBound = true;
  }
}

function saveIntakeForm() {
  const editor = getIntakeEditor();
  if (!editor) return;
  try { consentAwareSetItem(INTAKE_STORAGE_KEY, editor.innerHTML, 'functional'); } catch (_) {}
}

function clearIntakeForm() {
  const editor = getIntakeEditor();
  if (editor) editor.innerHTML = '';
  try { consentAwareSetItem(INTAKE_STORAGE_KEY, '', 'functional'); } catch (_) {}
  intakeExtractedOverrides = {};
  const wrap = document.getElementById('intakeExtractedWrap');
  if (wrap) wrap.style.display = 'none';
  const status = document.getElementById('intakeProcessStatus');
  if (status) status.textContent = '';
}

function prefillIntakeForm() {
  const editor = getIntakeEditor();
  if (!editor) return;
  const existing = (editor.innerHTML || '').trim();
  if (existing && !window.confirm('Replace the current intake notes with the standard template?')) return;
  editor.innerHTML = INTAKE_TEMPLATE_HTML;
  saveIntakeForm();
}

function handleIntakePaste(e) {
  // Prefer HTML so formatting/tables survive; fall back to plain text.
  const cd = e.clipboardData || window.clipboardData;
  if (!cd) return;
  const html = cd.getData('text/html');
  const text = cd.getData('text/plain');
  if (html) {
    e.preventDefault();
    // Sanitize: drop <script>/<style> and inline event handlers / style
    // attributes so the editor cannot inherit malicious or visually
    // disruptive markup from the clipboard source.
    const cleaned = sanitizeIntakeHtml(html);
    document.execCommand('insertHTML', false, cleaned);
    saveIntakeForm();
  } else if (text) {
    e.preventDefault();
    document.execCommand('insertText', false, text);
    saveIntakeForm();
  }
}

function sanitizeIntakeHtml(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String(html || '');
  const walker = document.createTreeWalker(tpl.content, NodeFilter.SHOW_ELEMENT);
  const toRemove = [];
  let n;
  while ((n = walker.nextNode())) {
    const tag = n.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'META' || tag === 'LINK') {
      toRemove.push(n);
      continue;
    }
    // Drop style attribute and any on* event handlers.
    if (n.hasAttribute('style')) n.removeAttribute('style');
    for (const attr of Array.from(n.attributes)) {
      if (/^on/i.test(attr.name)) n.removeAttribute(attr.name);
    }
  }
  toRemove.forEach(el => el.parentNode && el.parentNode.removeChild(el));
  return tpl.innerHTML;
}

function bindIntakeToolbar() {
  const bar = document.getElementById('intakeFormToolbar');
  if (!bar || bar.__intakeBound) return;
  bar.__intakeBound = true;
  bar.addEventListener('mousedown', (e) => {
    // Keep editor selection while clicking toolbar buttons.
    const btn = e.target.closest('button[data-cmd]');
    if (btn) e.preventDefault();
  });
  bar.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-cmd]');
    if (!btn) return;
    const cmd = btn.getAttribute('data-cmd');
    let arg = btn.getAttribute('data-arg') || null;
    if (cmd === 'createLink') {
      const url = window.prompt('Link URL:', 'https://');
      if (!url) return;
      arg = url;
    }
    document.execCommand(cmd, false, arg);
    const editor = getIntakeEditor();
    if (editor) editor.focus();
    saveIntakeForm();
  });
}

function getIntakeContent() {
  // Returns { plain, html } for whatever the user has currently typed,
  // or null when the editor is empty.
  const editor = getIntakeEditor();
  if (!editor) return null;
  const html = (editor.innerHTML || '').trim();
  const text = (editor.innerText || '').trim();
  if (!text && !html) return null;
  if (!text) return null;
  return { plain: text, html: html };
}

// ----- Extraction -----------------------------------------------------
// Standard ACS intake fields. Each entry lists the canonical label plus
// alternate phrasings/keywords we'll look for in the rich-text editor.
// Matching is case-insensitive and tolerant of trailing punctuation.
const INTAKE_EXTRACT_FIELDS = [
  { id: 'companyName',          label: 'Company name',                                 patterns: ['company name', 'customer name', 'organization name', 'organisation name'] },
  { id: 'companyWebsite',       label: 'Company website',                              patterns: ['company website', 'website', 'company url', 'web site'] },
  { id: 'businessDescription',  label: 'Brief description of your business',           rich: true, patterns: ['provide a brief description of your business', 'brief description of your business', 'business description', 'description of your business', 'description of business', 'brief description', 'about the business', 'about your business'] },
  { id: 'subscriptionId',       label: 'Subscription ID',                              patterns: ['subscription id', 'azure subscription id', 'subscription'] },
  { id: 'acsResourceName',      label: 'Azure Communication Services Resource Name',   patterns: ['azure communication services resource name', 'acs resource name', 'communication services resource name', 'resource name'] },
  { id: 'customDomainInUse',    label: 'Custom domain already set up and in use',      patterns: ['is your custom domain already set up and currently used for sending messages', 'custom domain already set up', 'custom domain set up', 'custom domain in use', 'domain already in use', 'custom domain'] },
  { id: 'currentSendingDomain', label: 'Current sending domain',                       patterns: ['indicate the domain from which you are currently sending emails', 'current sending domain', 'currently sending from', 'sending domain'] },
  { id: 'emailType',            label: 'Type of emails sent',                          patterns: ['what type of emails do you send', 'type of emails do you send', 'type of emails', 'email type', 'types of emails'] },
  { id: 'currentTier',          label: 'Current tier level',                           patterns: ['current tier level', 'current tier', 'existing tier', 'throttling tier for current subscription', 'throttling tier'] },
  { id: 'expectedVolume',       label: 'Expected tier level',                          patterns: ['specify the expected volume of emails you plan to send', 'expected volume of emails you plan to send', 'expected volume of emails', 'expected volume', 'expected tier level', 'expected tier', 'requested tier', 'estimated monthly volume', 'monthly volume', 'email volume', 'volume of emails'] },
  { id: 'ratePerMinute',        label: 'Max rate per minute',                          patterns: ['maximum rate of messages per minute', 'maximum messages per minute', 'max messages per minute', 'messages per minute', 'maximum per minute', 'max per minute', 'rate per minute', 'msgs per minute', 'msg/min', 'messages/minute'] },
  { id: 'ratePerHour',          label: 'Max rate per hour',                            patterns: ['maximum rate of messages per hour', 'maximum messages per hour', 'max messages per hour', 'messages per hour', 'maximum per hour', 'max per hour', 'rate per hour', 'msgs per hour', 'msg/hour', 'messages/hour'] },
  { id: 'ratePerDay',           label: 'Max rate per day',                             patterns: ['maximum rate of messages per day', 'maximum messages per day', 'max messages per day', 'messages per day', 'maximum per day', 'max per day', 'rate per day', 'msgs per day', 'msg/day', 'messages/day'] },
  { id: 'attachmentSizeMb',      label: 'Max attachment size (MB)',                     patterns: ['what is the maximum attachment size in mb', 'maximum attachment size in mb', 'max attachment size in mb', 'attachment size in mb', 'maximum attachment size', 'max attachment size', 'attachment size'] },
  { id: 'addressSource',        label: 'Source of email addresses',                    patterns: ['what is the source of the email addresses that you use for sending your messages', 'source of the email addresses', 'source of email addresses', 'how do you acquire', 'how are addresses acquired', 'source of addresses'] },
  { id: 'bounceHandling',       label: 'Unsubscribe / bounce handling',                rich: true, patterns: ['how do you currently manage and remove email addresses that have unsubscribed or resulted in bounce backs from your mailing list', 'how do you currently manage and remove email addresses that have unsubscribed', 'manage and remove email addresses that have unsubscribed', 'manage and remove email addresses', 'unsubscribe handling', 'bounce handling', 'handle bounces', 'remove bounced'] }
];

// Track manual edits made in the extracted-fields table so re-running
// "Process Data" doesn't blow them away unless the user explicitly clears
// the field first.
let intakeExtractedOverrides = {};

// ACS Email throttling tiers. Each entry: { name, perMinute, perHour }.
// "Expected tier level" is computed as the smallest tier whose per-minute
// AND per-hour caps both meet or exceed the customer's requested rates.
//
// Tier names are stored base64-encoded (and decoded once at runtime) so
// they are not trivially greppable in the bundled source. This is light
// obfuscation, NOT a security control -- anyone who runs the page can
// still read the decoded list in the browser. True one-way hashing would
// prevent us from ever displaying the name, which defeats the feature.
const INTAKE_TIERS = (function () {
  const raw = [
    { n: 'TWVyY3VyeQ==',                  perMinute:     30, perHour:      100 },
    { n: 'VmVudXM=',                      perMinute:    100, perHour:     1000 },
    { n: 'VmVudXNTdGFuZGFyZA==',          perMinute:    500, perHour:     2000 },
    { n: 'VmVudXNQcm9mZXNzaW9uYWw=',      perMinute:   1000, perHour:     3000 },
    { n: 'VmVudXNQcmVtaXVt',              perMinute:   2000, perHour:     4000 },
    { n: 'RWFydGg=',                      perMinute:   5000, perHour:    20000 },
    { n: 'RWFydGhTdGFuZGFyZA==',          perMinute:  10000, perHour:    40000 },
    { n: 'RWFydGhQcm9mZXNzaW9uYWw=',      perMinute:  15000, perHour:    80000 },
    { n: 'RWFydGhQcmVtaXVt',              perMinute:  20000, perHour:   100000 },
    { n: 'RWFydGhTaWx2ZXI=',              perMinute: 100000, perHour:   500000 },
    { n: 'RWFydGhHb2xk',                  perMinute: 200000, perHour:  1000000 },
    { n: 'RWFydGhQbGF0aW51bQ==',          perMinute: 400000, perHour:  2000000 }
  ];
  const decode = (s) => {
    try { return decodeURIComponent(escape(atob(s))); }
    catch (_) { try { return atob(s); } catch (__) { return s; } }
  };
  return raw.map(t => ({ name: decode(t.n), perMinute: t.perMinute, perHour: t.perHour }));
})();

function parseIntakeNumeric(text) {
  if (text === null || text === undefined) return null;
  // Pull the first integer-like token out of the cell. Handles "1,000",
  // "1000 msgs", "~100", etc. Returns null when no number is present.
  const m = String(text).replace(/[\u00A0\s]/g, '').match(/(\d{1,3}(?:,\d{3})+|\d+)/);
  if (!m) return null;
  const n = parseInt(m[1].replace(/,/g, ''), 10);
  return isNaN(n) ? null : n;
}

function inferExpectedTierIndex(perMinute, perHour) {
  // Returns the index of the smallest tier that meets both rates, or -1
  // when the customer's request exceeds every published tier.
  const wantMin = parseIntakeNumeric(perMinute);
  const wantHour = parseIntakeNumeric(perHour);
  if (wantMin === null && wantHour === null) return -1;
  for (let i = 0; i < INTAKE_TIERS.length; i++) {
    const t = INTAKE_TIERS[i];
    const okMin  = (wantMin  === null) || (t.perMinute >= wantMin);
    const okHour = (wantHour === null) || (t.perHour   >= wantHour);
    if (okMin && okHour) return i;
  }
  return -1;
}

function inferExpectedTier(perMinute, perHour) {
  const idx = inferExpectedTierIndex(perMinute, perHour);
  return idx >= 0 ? INTAKE_TIERS[idx].name : null;
}

function formatExpectedTierValue(existingValue, perMinute, perHour) {
  // Prefix the inferred tier label onto whatever the user wrote in the
  // expected-volume question. We never replace user-supplied text; we only
  // enrich it so support reviewers see the target level next to the raw ask.
  let tierIndex = inferExpectedTierIndex(perMinute, perHour);
  // Tier index 0 is the default/base level, so quota-increase requests start
  // at the next level up.
  if (tierIndex === 0) tierIndex = 1;
  const tier = tierIndex >= 0 && INTAKE_TIERS[tierIndex] ? INTAKE_TIERS[tierIndex].name : null;
  const existing = (existingValue || '').trim();
  if (!tier) return existing;
  if (!existing) return tier;
  // Avoid double-prefixing if the tier name is already in the text.
  if (existing.toLowerCase().indexOf(tier.toLowerCase()) !== -1) return existing;
  return tier + ' \u2014 ' + existing;
}

function normalizeIntakePlainText(plain) {
  // Collapse non-breaking spaces and trim each line. Keep blank lines so
  // we can detect multi-line answers under a question heading. Before
  // splitting, insert soft line breaks before well-known form labels and
  // section headers; this lets the extractor handle both nicely formatted
  // multi-line forms and single-paragraph paste artifacts where fields run
  // together ("Company name: X Company website: Y ...").
  let text = String(plain || '').replace(/\u00A0/g, ' ');
  // Split markers fall into two families:
  //   1. Canonical ACS intake questions (long, unambiguous).
  //   2. Short "label:" variants people use when they retype the form by hand
  //      (often copied straight from this app's own "Extracted fields" table).
  // Every short label that mirrors a displayed field label is included so the
  // app can round-trip its own output, and so hand-typed forms still split.
  const markers = [
    'Customer Information',
    'Company name:',
    'Company website:',
    'Please provide a brief description of your business:',
    'Provide a brief description of your business:',
    'Brief description of your business:',
    'Brief description:',
    'Email Service Information',
    'Subscription ID:',
    'Azure Communication Services Resource Name:',
    'Is your custom domain already set up and currently used for sending messages:',
    'Custom domain already set up and in use:',
    'Custom domain already set up:',
    'Custom domain set up:',
    'Indicate the domain from which you are currently sending emails:',
    'Current sending domain:',
    'Sending domain:',
    'Usage Information',
    'What type of emails do you send?',
    'Type of emails sent:',
    'Type of emails:',
    'Please specify the expected volume of emails you plan to send:',
    'Specify the expected volume of emails you plan to send:',
    'Expected tier level:',
    'Expected volume:',
    'Current tier level:',
    'What is the maximum rate of messages per minute that you require?',
    'What is the maximum rate of messages per hour that you require?',
    'What is the maximum rate of messages per day that you require?',
    'Max rate per minute:',
    'Max rate per hour:',
    'Max rate per day:',
    'Maximum per minute:',
    'Maximum per hour:',
    'Maximum per day:',
    'Estimated monthly volume:',
    'What is the maximum attachment size in MB?',
    'Max attachment size (MB):',
    'Max attachment size:',
    'Additional Information',
    'What is the source of the email addresses that you use for sending your messages?',
    'Source of email addresses:',
    'How do you currently manage and remove email addresses that have unsubscribed or resulted in bounce backs from your mailing list?',
    'Unsubscribe / bounce handling:',
    'Unsubscribe and bounce handling:'
  ];
  // Process the LONGEST, most specific markers first and replace each match
  // with an opaque sentinel token. This prevents a SHORTER marker from
  // re-splitting a region a longer marker already claimed -- e.g. the short
  // "Sending domain:" label must never carve "Current" off the longer
  // "Current sending domain:" label, and "Expected volume:" must never split
  // the middle of "Specify the expected volume of emails you plan to send:".
  // Sentinels are made of NUL bytes + an index, which can never appear in
  // pasted form text and can never match another marker.
  const ordered = markers
    .map((m, i) => ({ marker: m, i: i }))
    .sort(function (a, b) {
      // Longest first; stable on original order for equal lengths.
      if (b.marker.length !== a.marker.length) return b.marker.length - a.marker.length;
      return a.i - b.i;
    });
  const sentinels = [];
  for (const entry of ordered) {
    const escaped = entry.marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Insert a soft line break before the marker. Absorb an optional leading
    // list number ("1. " / "2) ") into the same line so "2. Specify ..." is
    // not split into a bare "2." line followed by the question text (which
    // previously got glued onto the prior answer as e.g. "Transactional 2.").
    text = text.replace(
      new RegExp('\\s+(\\d+[\\.)]\\s+)?(' + escaped + ')', 'gi'),
      function (m, num, mk) {
        const token = '\u0000' + sentinels.length + '\u0000';
        sentinels.push(mk);
        return '\n' + (num || '') + token;
      }
    );
  }
  // Restore each sentinel back to the exact marker text (original casing) that
  // produced it now that all splitting is finished.
  text = text.replace(/\u0000(\d+)\u0000/g, function (m, idx) {
    const original = sentinels[parseInt(idx, 10)];
    return (original === undefined || original === null) ? '' : original;
  });
  return text
    .replace(/\u00A0/g, ' ')
    .split(/\r?\n/)
    .map(s => s.replace(/\s+$/, ''));
}

function isIntakeSectionHeader(line) {
  // These section dividers are part of the customer form, not answers. Treat
  // them as hard boundaries so a previous answer never absorbs the next
  // section title (for example, "appmail.example.com Usage Information").
  const s = String(line || '').trim().toLowerCase().replace(/[\u00A0\s]+/g, ' ');
  return s === 'customer information'
    || s === 'email service information'
    || s === 'usage information'
    || s === 'additional information';
}

// Sub-questions / clarifying prompts that aren't extracted as their own field
// but DO mark the end of the previous answer. Without these, a narrative answer
// would keep absorbing the follow-up prompt and its response.
const INTAKE_QUESTION_BOUNDARIES = [
  'explain if you have an automated process',
  'additionally, if you receive bounce'
];
function isIntakeQuestionBoundary(line) {
  const s = String(line || '').trim().toLowerCase().replace(/[\u00A0\s]+/g, ' ');
  for (const b of INTAKE_QUESTION_BOUNDARIES) {
    if (s.indexOf(b) !== -1) return true;
  }
  return false;
}

function isLikelyNonAnswerTail(text) {
  // Some patterns intentionally match only the stable part of a question.
  // For example, matching "maximum rate of messages per minute" leaves
  // "that you require?" as the tail. That is not an answer; force the parser
  // to collect the next line instead.
  const s = String(text || '').trim().toLowerCase();
  return !s
    || s === '?'
    || s === ':'
    || s === 'or'
    || s === 'and'
    || s === 'that you require?'
    || s === 'that you require'
    || s === 'you require?'
    || s === 'you require'
    || /^or resulted\b/.test(s)
    || /^resulted in bounce backs\b/.test(s)
    || /^from your mailing list\??$/.test(s);
}

function cleanIntakeAnswerText(text) {
  return String(text || '')
    // Remove bullets or numbered-list prefixes, but never remove a real
    // numeric answer like "10 messages per minute" or "30 MB".
    .replace(/^[\s\-\*\u2022\u2023\u25E6]+/, '')
    .replace(/^\d+[\.)]\s+/, '')
    .replace(/^(re|answer|ans|a)\s*[:\-\u2013\u2014]\s*/i, '')
    .trim();
}

function matchIntakePattern(line, patterns) {
  // Returns { rest } when `line` contains one of the patterns near its
  // start, otherwise null. We accept patterns located in the first ~30
  // chars (to allow short prefixes like "Provide a " or "1. ") or any
  // long pattern (>= 20 chars) anywhere in the line, since long phrase
  // matches are unambiguous. The returned `rest` is the line's tail with
  // the matched phrase, any leading parenthetical clarifier, trailing
  // "?"/":"/"-" punctuation, and a leading "Re:"/"Answer:" prefix stripped.
  const norm = String(line || '')
    // Strip bullets, but preserve numeric-leading answers such as
    // "10 messages per minute". Only remove numbered-list prefixes when
    // they include punctuation ("1. " / "2) ").
    .replace(/^[\s\-\*\u2022\u2023\u25E6]+/, '')
    .replace(/^\d+[\.)]\s+/, '')
    .trim();
  const lower = norm.toLowerCase();
  for (const p of patterns) {
    const pl = p.toLowerCase();
    const idx = lower.indexOf(pl);
    if (idx < 0) continue;
    // Lines such as "10 messages per minute" are answers, not questions.
    // Do not let generic patterns ("messages per minute") classify them
    // as question lines and steal only the trailing punctuation.
    if (idx > 0 && /^\d[\d,\.]*\s+/.test(norm)) continue;
    if (idx === 0 || idx <= 30 || pl.length >= 20) {
      let rest = norm.slice(idx + pl.length).trim();
      // Strip a leading "(...)" clarifier such as "(such as Transactional...)".
      rest = rest.replace(/^\([^)]*\)\s*/, '');
      // Strip leading separator punctuation: : - ? \u2013 \u2014.
      rest = rest.replace(/^[:?\-\u2013\u2014]+\s*/, '');
      // Strip another parenthetical that may sit after the colon.
      rest = rest.replace(/^\([^)]*\)\s*/, '');
      // Strip a leading "Re:" / "Answer:" prefix on inline answers.
      rest = rest.replace(/^(re|answer|ans|a)\s*[:\-\u2013\u2014]\s*/i, '');
      // Strip a trailing question clause that precedes the inline answer, e.g.
      // "...per minute that you require? 3 aprox" -> "3 aprox".
      rest = rest.replace(/^that\s+you\s+require\s*\??\s*/i, '');
      rest = rest.replace(/^you\s+require\s*\??\s*/i, '');
      if (isLikelyNonAnswerTail(rest)) rest = '';
      return { rest: rest };
    }
  }
  return null;
}

function extractIntakeFields(plain) {
  const lines = normalizeIntakePlainText(plain).map(l => l || '');
  const found = {};
  const reAnswer = /^\s*(re|answer|ans|a)\s*[:\-\u2013\u2014]\s*(.+)$/i;
  const isQuestionLine = (line) => {
    if (isIntakeSectionHeader(line)) return true;
    if (isIntakeQuestionBoundary(line)) return true;
    for (const f of INTAKE_EXTRACT_FIELDS) {
      if (matchIntakePattern(line, f.patterns)) return true;
    }
    return false;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    // Build candidates: the current line on its own, and the current line
    // joined with the next non-blank line (handles word-wrapped questions
    // such as "How do you currently manage and remove email addresses
    // that have unsubscribed or\nresulted in bounce backs...").
    const candidates = [{ text: line, span: 1 }];
    if (i + 1 < lines.length && lines[i + 1].trim()) {
      candidates.push({ text: line + ' ' + lines[i + 1].trim(), span: 2 });
    }

    for (const field of INTAKE_EXTRACT_FIELDS) {
      if (found[field.id]) continue;
      let match = null;
      let span = 1;
      for (const c of candidates) {
        const m = matchIntakePattern(c.text, field.patterns);
        if (m) { match = m; span = c.span; break; }
      }
      if (!match) continue;

      let value = (match.rest || '').trim();

      // Look ahead for an explicit "Re:" / "Answer:" line within the next
      // ~12 non-blank lines (stopping at the next known question). When
      // present that overrides any inline rest, because intake docs often
      // repeat the question text on multiple lines before the response.
      let reValue = '';
      for (let j = i + span; j < Math.min(lines.length, i + span + 14); j++) {
        const nl = lines[j];
        if (!nl.trim()) continue;
        if (isQuestionLine(nl)) break;
        const am = nl.match(reAnswer);
        if (am) {
          reValue = am[2].trim();
          for (let k = j + 1; k < lines.length; k++) {
            const nl2 = lines[k];
            if (!nl2.trim()) break;
            if (isQuestionLine(nl2)) break;
            if (reAnswer.test(nl2)) break;
            reValue += ' ' + nl2.trim();
          }
          break;
        }
      }
      if (reValue) value = reValue;

      // If still empty, gather following non-blank lines until a blank
      // line or another known question.
      if (!value) {
        const collected = [];
        let started = false;
        for (let j = i + span; j < lines.length; j++) {
          const next = lines[j];
          if (!next.trim()) {
            // Allow blank lines between a question and its answer, and also
            // within longer narrative answers. Stop only after we've already
            // collected something and the next non-blank line is a question or
            // section header; otherwise keep scanning.
            let k = j + 1;
            while (k < lines.length && !lines[k].trim()) k++;
            if (started && (k >= lines.length || isQuestionLine(lines[k]))) break;
            continue;
          }
          // A clarifying sub-prompt (e.g. "Explain if you have an automated
          // process..." / "Additionally, if you receive bounce...") is still
          // part of the PRINTED question, not the answer. The real answer is
          // the paragraph that follows the clarifier block. Skip over the
          // entire clarifier paragraph and resume collecting from the first
          // non-blank line after it -- unless that line is itself another known
          // question/section header, in which case there is no answer to grab.
          if (isIntakeQuestionBoundary(next)) {
            let p = j;
            while (p + 1 < lines.length && lines[p + 1].trim()) p++;
            let q = p + 1;
            while (q < lines.length && !lines[q].trim()) q++;
            if (q < lines.length && !isQuestionLine(lines[q])) {
              // Discard any wrapped question-continuation text collected so far
              // and restart the scan at the answer paragraph.
              collected.length = 0;
              started = false;
              j = q - 1;
              continue;
            }
            break;
          }
          if (isQuestionLine(next)) break;
          // Before we've collected anything, skip wrapped question-continuation
          // lines (the tail of a multi-line question, which typically ends with
          // "?"). This prevents an answer from being set to leftover question
          // text such as "resulted in bounce backs from your mailing list?".
          if (!started && /\?\s*$/.test(next)) continue;
          let t = cleanIntakeAnswerText(next);
          if (!t || /^note\s*:/i.test(t)) break;
          collected.push(t);
          started = true;
        }
        value = collected.join(' ').trim();
      }

      if (value) found[field.id] = value;
    }
  }
  return found;
}

function processIntakeForm() {
  const status = document.getElementById('intakeProcessStatus');
  const wrap = document.getElementById('intakeExtractedWrap');
  const body = document.getElementById('intakeExtractedBody');
  if (!body || !wrap) return;

  const intake = getIntakeContent();
  if (!intake || !intake.plain) {
    wrap.style.display = 'none';
    if (status) status.textContent = 'Editor is empty &mdash; nothing to process.';
    return;
  }

  const detected = extractIntakeFields(intake.plain);
  // Enrich "Expected tier level" with the inferred ACS throttling tier
  // name when we have per-minute / per-hour rate values. The user's
  // original text (e.g. "100 / min, 1000 / hr") is preserved as a suffix.
  const inferredVolumeBase = detected.expectedVolume || '';
  const enrichedVolume = formatExpectedTierValue(inferredVolumeBase, detected.ratePerMinute, detected.ratePerHour);
  if (enrichedVolume) detected.expectedVolume = enrichedVolume;

  // Merge with prior manual overrides so the user's edits survive a re-run.
  const merged = {};
  let detectedCount = 0;
  for (const f of INTAKE_EXTRACT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(intakeExtractedOverrides, f.id)) {
      merged[f.id] = intakeExtractedOverrides[f.id];
    } else if (Object.prototype.hasOwnProperty.call(detected, f.id)) {
      merged[f.id] = detected[f.id];
      detectedCount++;
    } else {
      merged[f.id] = '';
    }
  }

  renderExtractedIntakeTable(merged);
  wrap.style.display = '';
  if (status) {
    status.textContent = detectedCount > 0
      ? 'Detected ' + detectedCount + ' of ' + INTAKE_EXTRACT_FIELDS.length + ' fields. Edit any cell to correct.'
      : 'No fields detected. You can fill them in manually below.';
  }

  // If the intake form names a "Current sending domain" that differs from the
  // domain the checker is currently set to, automatically re-run the domain
  // checker against the sending domain so the results reflect the customer's
  // actual mail domain rather than whatever was previously typed/loaded.
  maybeRunCheckerForIntakeDomain(merged.currentSendingDomain, status);
}

// Some intake forms list MORE THAN ONE "Current sending domain" in a single
// answer (for example "mail1.example.com, mail2.example.com" or
// "example.com and example.net"). The checker can only run against one domain,
// so we deliberately pick the FIRST valid domain we can find and ignore the
// rest. Returns '' when no token in the value normalizes to a valid domain.
function getFirstIntakeSendingDomain(rawSendingDomain) {
  const raw = (rawSendingDomain === null || rawSendingDomain === undefined)
    ? '' : String(rawSendingDomain);
  if (!raw.trim()) return '';

  // First, fast-path the common single-value case: if the whole answer
  // already normalizes to one valid domain, use it as-is.
  const whole = normalizeDomain(raw);
  if (whole && isValidDomain(whole)) return whole;

  // Otherwise split the answer into candidate tokens on the separators people
  // actually use between multiple domains: commas, semicolons, pipes, slashes,
  // whitespace/newlines, and the words "and"/"or". Each token is then run
  // through the same normalizer (which also strips http(s):// and mailto/@)
  // and validator the single-domain path uses. We return the first hit.
  const tokens = raw.split(/(?:\s+|[,;|]+|\/+|\b(?:and|or)\b)+/i);
  for (const token of tokens) {
    if (!token) continue;
    const candidate = normalizeDomain(token);
    if (candidate && isValidDomain(candidate)) return candidate;
  }
  return '';
}

// Compare the intake "Current sending domain" against the domain currently
// loaded in the checker. When they differ (and the sending domain is valid),
// load it into the search box and trigger a fresh lookup. When the intake
// answer lists multiple domains we only ever run the checker on the FIRST
// valid one (see getFirstIntakeSendingDomain).
function maybeRunCheckerForIntakeDomain(rawSendingDomain, status) {
  const sendingDomain = getFirstIntakeSendingDomain(rawSendingDomain);
  if (!sendingDomain) return;

  const input = document.getElementById('domainInput');
  const currentDomain = normalizeDomain(input ? input.value : '');
  if (sendingDomain === currentDomain) return;

  if (input) input.value = sendingDomain;
  if (typeof toggleClearBtn === 'function') toggleClearBtn();
  if (status) {
    // Replace the status text (don't append) so repeated edits to the sending
    // domain don't pile up multiple "Running checker against ..." fragments.
    status.textContent = 'Running checker against ' + sendingDomain + '\u2026';
  }
  // Pass the sending domain explicitly so the lookup is not affected by any
  // race with the input value update above.
  lookup({ domainOverride: sendingDomain, animateTopIntro: true });
}

function renderExtractedIntakeTable(values) {
  const body = document.getElementById('intakeExtractedBody');
  if (!body) return;
  // Quick lookup of each field's definition so the blur handler can tell
  // whether a cell is a rich-text field (keeps multi-line formatting) or a
  // plain field (single line, formatting stripped, ends trimmed).
  const fieldById = {};
  for (const f of INTAKE_EXTRACT_FIELDS) fieldById[f.id] = f;
  const rows = [];
  for (const f of INTAKE_EXTRACT_FIELDS) {
    const val = values[f.id] || '';
    const emptyCls = val ? '' : ' class="intake-extracted-empty"';
    // Only the two narrative fields (business description, unsubscribe/bounce
    // handling) keep rich-text behavior. Every other cell is marked as a plain
    // single-line field so the blur handler can flatten and trim it.
    const plainAttr = f.rich ? '' : ' data-plain-field="true"';
    rows.push(
      '<tr' + emptyCls + ' data-field-id="' + escapeHtml(f.id) + '">' +
      '<th>' + escapeHtml(f.label) + '</th>' +
      '<td contenteditable="true" data-empty-text="(not detected)"' + plainAttr + '>' +
      (val ? escapeHtml(val) : '(not detected)') +
      '</td></tr>'
    );
  }
  body.innerHTML = rows.join('');
  // Wire up edit tracking.
  Array.from(body.querySelectorAll('td[contenteditable="true"]')).forEach(td => {
    const isPlainField = td.getAttribute('data-plain-field') === 'true';
    // Clear placeholder text on focus when the cell has the empty marker.
    td.addEventListener('focus', () => {
      const tr = td.parentElement;
      if (tr && tr.classList.contains('intake-extracted-empty')) {
        td.textContent = '';
        tr.classList.remove('intake-extracted-empty');
      }
    });
    // For plain (non-rich) fields, intercept paste so rich clipboard content
    // is inserted as plain text only. Rich fields keep the default behavior.
    if (isPlainField) {
      td.addEventListener('paste', (e) => {
        e.preventDefault();
        const clip = (e.clipboardData || window.clipboardData);
        const pasted = clip ? clip.getData('text/plain') : '';
        // Collapse any newlines so a multi-line paste stays single-line.
        const flat = String(pasted || '').replace(/[\r\n]+/g, ' ');
        if (typeof document.execCommand === 'function') {
          document.execCommand('insertText', false, flat);
        } else {
          td.textContent = (td.innerText || '') + flat;
        }
      });
    }
    td.addEventListener('blur', () => {
      const tr = td.parentElement;
      const fieldId = tr ? tr.getAttribute('data-field-id') : null;
      // Plain fields are flattened to a single line and have leading/trailing
      // whitespace removed. Rich fields keep their internal formatting but are
      // still trimmed of surrounding whitespace.
      let text;
      if (isPlainField) {
        text = (td.innerText || '').replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
        // Re-render the cell as flat text so any pasted markup/line breaks are
        // visually removed too, not just stripped from the stored value.
        if (text) td.textContent = text;
      } else {
        text = (td.innerText || '').replace(/^\s+|\s+$/g, '');
      }
      if (fieldId) {
        if (text) {
          intakeExtractedOverrides[fieldId] = text;
        } else {
          delete intakeExtractedOverrides[fieldId];
          td.textContent = '(not detected)';
          tr.classList.add('intake-extracted-empty');
        }
        // When the user edits the "Current sending domain" cell, re-run the
        // checker against it immediately (using the first valid domain when
        // several are listed) rather than waiting for the next "Process Data".
        if (fieldId === 'currentSendingDomain' && text) {
          maybeRunCheckerForIntakeDomain(text, document.getElementById('intakeProcessStatus'));
        }
      }
    });
  });
}

function getExtractedIntakeValues() {
  // Returns the currently displayed extracted fields, in canonical order,
  // skipping rows the user/extractor left empty.
  const body = document.getElementById('intakeExtractedBody');
  if (!body) return [];
  const out = [];
  for (const f of INTAKE_EXTRACT_FIELDS) {
    const tr = body.querySelector('tr[data-field-id="' + f.id + '"]');
    if (!tr || tr.classList.contains('intake-extracted-empty')) continue;
    const td = tr.querySelector('td[contenteditable="true"]');
    const val = td ? (td.innerText || '').trim() : '';
    if (val) out.push({ id: f.id, label: f.label, value: val });
  }
  return out;
}

// Returns a plain { fieldId: value } lookup of the currently displayed
// extracted fields, used by the structured request-template builder below.
function getExtractedIntakeMap() {
  const map = {};
  for (const f of getExtractedIntakeValues()) {
    map[f.id] = f.value;
  }
  return map;
}

// Canonical ACS "Email quota increase" intake template. Each row mirrors the
// numbered questionnaire reviewers expect, mapping the long "Required
// Information" prompt to the extractor field whose value fills the "Details to
// Provide" column. Rows with `id: null` are pure section/sub-headers; rows
// with a `sub: true` flag are indented sub-questions under a parent number.
const INTAKE_REQUEST_TEMPLATE = [
  { id: 'subscriptionId',       label: 'Subscription ID' },
  { id: 'companyName',          label: 'Company Name' },
  { id: 'companyWebsite',       label: 'Company Website' },
  { id: 'businessDescription',  label: 'Brief Description of Your Business' },
  { id: 'customDomainInUse',    label: 'Is your custom domain already set up and currently used for sending emails? This is a pre-requisite before the quota increase and AMD domain is only for testing purpose, not allowed for quota increase and the failure rate should be less than 1%.' },
  { id: 'currentSendingDomain', label: 'What is the domain you are currently sending emails from? Please make sure it has successfully sent emails.' },
  { id: 'acsResourceName',      label: 'ACS Resource Name' },
  { id: 'emailType',            label: 'What type of emails do you send? (e.g., Transactional, Marketing, Promotional)' },
  { id: null,                   label: 'Please specify the expected volume of emails you plan to send (exact in number).' },
  { id: 'currentTier',          label: 'Current tier level', sub: true },
  { id: 'expectedVolume',       label: 'Expected tier level', sub: true },
  { id: 'ratePerMinute',        label: 'What is the maximum rate of messages per minute that you require?', sub: true },
  { id: 'ratePerHour',          label: 'What is the maximum rate of messages per hour that you require?', sub: true },
  { id: 'ratePerDay',           label: 'What is the maximum rate of messages per day that you require?', sub: true },
  { id: 'attachmentSizeMb',     label: 'What is the maximum attachment size (in MB) that you require?' },
  { id: 'addressSource',        label: 'What is the source of the email addresses that you use for sending your messages? (e.g., The source of the email addresses that you use for sending your messages plays a crucial role in the effectiveness and compliance of your email marketing campaigns. Providing details about the source of your email addresses will help us understand how you acquire and maintain your subscriber list).' },
  { id: 'bounceHandling',       label: 'How do you currently manage and remove email addresses that have unsubscribed or resulted in bounces from your mailing list? (e.g., Explain whether you have an automated process in place that handles unsubscribes when recipients click on the \'unsubscribe\' link in your emails. Additionally, if you receive bounce notifications, can you mention how you handle those and whether you have any mechanism to automatically remove email addresses that result in consistent bounces).' }
];

// Builds the numbered "Required Information / Details to Provide" request
// template as both plain text and HTML, filling the Details column from the
// extracted intake fields. Returns null when no intake fields are available.
function buildIntakeRequestTemplate() {
  const values = getExtractedIntakeMap();
  if (!values || Object.keys(values).length === 0) return null;

  const plainRows = [];
  const htmlRows = [];
  let sno = 0;
  for (const row of INTAKE_REQUEST_TEMPLATE) {
    const detail = (row.id && values[row.id]) ? values[row.id] : '';
    // Sub-questions (rate per minute/hour/day) sit under the prior number and
    // get a blank S.No cell; everything else advances the running number.
    const numberLabel = row.sub ? '' : String(++sno);
    plainRows.push((numberLabel ? numberLabel + '. ' : '   ') + row.label + (detail ? ' => ' + detail : ' =>'));
    const indentStyle = row.sub ? 'padding-left:24px;' : '';
    htmlRows.push(
      '<tr>' +
      '<td style="padding:4px 8px;border:1px solid #ddd;text-align:center;vertical-align:top;">' + escapeHtml(numberLabel) + '</td>' +
      '<td style="padding:4px 8px;border:1px solid #ddd;vertical-align:top;' + indentStyle + '">' + escapeHtml(row.label) + '</td>' +
      '<td style="padding:4px 8px;border:1px solid #ddd;vertical-align:top;white-space:pre-wrap;">' + escapeHtml(detail) + '</td>' +
      '</tr>'
    );
  }

  const plain = ['S.No | Required Information | Details to Provide', '---'].concat(plainRows).join('\n');
  const html =
    '<table style="border-collapse:collapse;min-width:480px;margin-top:4px;">' +
    '<thead><tr>' +
    '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">S.No</th>' +
    '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">Required Information</th>' +
    '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">Details to Provide</th>' +
    '</tr></thead><tbody>' + htmlRows.join('') + '</tbody></table>';

  return { plain: plain, html: html };
}

// Builds the full Copy Email Quota payload at click time: the base DNS/quota
// table (captured during render) plus the latest Customer Intake Information
// block. This is computed on demand so clicking "Process Data" after a lookup
// is reflected in the copied output without re-running the domain check.
function buildQuotaCopyPayload() {
  const base = window.quotaCopyBase || { plain: '', html: '' };
  let intakePlain = '';
  let intakeHtml = '';
  try {
    const extracted = (typeof getExtractedIntakeValues === 'function') ? getExtractedIntakeValues() : [];
    const requestTemplate = (typeof buildIntakeRequestTemplate === 'function') ? buildIntakeRequestTemplate() : null;
    const hasExtracted = extracted && extracted.length > 0;
    if (hasExtracted) {
      const plainParts = ['', '---', 'Customer Intake Information', '---'];
      const htmlParts = ['<br><strong>Customer Intake Information</strong>'];
      if (requestTemplate) {
        // Structured "Required Information / Details to Provide" request table,
        // matching the ACS email quota increase intake questionnaire.
        plainParts.push(requestTemplate.plain);
        htmlParts.push(requestTemplate.html);
      } else {
        plainParts.push('Extracted fields:');
        for (const f of extracted) {
          plainParts.push('- ' + f.label + ': ' + f.value);
        }
        const rows = extracted.map(f =>
          '<tr>' +
          '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">' + escapeHtml(f.label) + '</th>' +
          '<td style="padding:4px 8px;border:1px solid #ddd;white-space:pre-wrap;">' + escapeHtml(f.value) + '</td>' +
          '</tr>'
        ).join('');
        htmlParts.push('<table style="border-collapse:collapse;min-width:260px;margin-top:4px;">' + rows + '</table>');
      }
      // Intentionally NOT including the raw editor notes (intake.plain /
      // intake.html) here: the copied output should contain only the
      // structured extracted-fields table, not the free-form intake text.
      intakePlain = '\n' + plainParts.join('\n');
      intakeHtml = htmlParts.join('');
    }
  } catch (_) {}
  const payload = {
    plain: (base.plain || '') + intakePlain,
    html: (base.html || '') + intakeHtml
  };
  // Keep the legacy global in sync for any other consumers.
  window.quotaCopyText = payload;
  return payload;
}

// Returns true when the app is being served from a local development host
// (localhost / loopback). Used to unconditionally reveal developer-only UI
// (such as the Customer Intake form) so features can be tested on a dev
// machine without signing in with a Microsoft account.
function isLocalDevHost() {
  try {
    const host = (window.location.hostname || '').toLowerCase();
    return host === 'localhost'
      || host === '127.0.0.1'
      || host === '::1'
      || host === '[::1]'
      || host.endsWith('.localhost');
  } catch (e) {
    return false;
  }
}

// Show the intake form only when the signed-in user has been identified
// as a Microsoft employee. Called from updateAuthUI in
// 20e-HtmlAzureIntegration.ps1.
function updateIntakeFormVisibility(isSignedIn) {
  const card = document.getElementById('intakeFormCard');
  if (!card) return;
  // Only show the Customer Intake form to users signed in with a Microsoft
  // account. Hide it (and don't load saved content) otherwise. On a local
  // development host we always show it so features can be tested without
  // signing in; the production sign-in gating is unchanged.
  if (isSignedIn || isLocalDevHost()) {
    card.style.display = '';
    loadIntakeForm();
  } else {
    card.style.display = 'none';
  }
}

// Theme + query-domain initialization
function initializePage() {
  const params = new URLSearchParams(window.location.search);
  const bootstrapDomain = normalizeDomain(params.get("domain") || '');
  const openCookieSettingsRequested = typeof consumeOpenCookieSettingsRequest === 'function'
    ? consumeOpenCookieSettingsRequest()
    : false;
  currentLanguage = detectLanguage();

  // 1. Check for saved theme
  // 2. If none, check system preference (Dark vs Light)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = systemPrefersDark ? "dark" : "light";

  // Read saved theme only if functional cookies are consented
  const savedTheme = consentAwareGetItem("acsTheme", 'functional') || defaultTheme;

  applyTheme(savedTheme);
  applyLanguage(currentLanguage, false);
  loadHistory();
  document.getElementById("domainInput").value = bootstrapDomain;
  toggleClearBtn();
  // Set the title up front so a shareable ?domain= URL produces a domain-suffixed
  // tab title even before the asynchronous lookup begins rendering.
  updatePageTitle(bootstrapDomain);

  const reportBtn = document.getElementById("reportIssueBtn");
  const issueUrl = (acsIssueUrl || '').trim();
  if (reportBtn) {
    if (!issueUrl || issueUrl.startsWith('__')) {
      hideTopBarItem(reportBtn);
    } else {
      showTopBarItem(reportBtn);
    }
  }

  // Initialize Microsoft Entra ID authentication
  if (typeof initMsAuth === 'function') {
    initMsAuth();
  }

  // Show cookie consent banner if no consent has been given yet (EU GDPR / ePrivacy)
  if (shouldShowCookieConsent() || openCookieSettingsRequested) {
    applyCookieConsentLanguage();
    showCookieConsentBanner();
  }

  // Customer intake form starts hidden; it is revealed by updateAuthUI
  // only when the signed-in user is a Microsoft employee. On a local
  // development host, reveal it immediately so features can be tested
  // without signing in.
  if (typeof updateIntakeFormVisibility === 'function') {
    updateIntakeFormVisibility(false);
  }

  scheduleInitialLookup(bootstrapDomain);
}

let initialLookupHasStarted = false;
let initialLookupIsScheduled = false;
let pageInitializationHasStarted = false;
let initialLookupRetryCount = 0;
const INITIAL_LOOKUP_MAX_RETRIES = 20;
const INITIAL_LOOKUP_RETRY_DELAY_MS = 50;

function startPageInitialization() {
  if (pageInitializationHasStarted) return;
  pageInitializationHasStarted = true;
  // When the page is loaded inside an iframe it is almost always MSAL's hidden
  // token-renewal frame (ssoSilent / acquireTokenSilent redirect the iframe
  // back to our own origin). That frame only needs MSAL's redirect handler to
  // run so the parent window can read the result; booting the entire SPA there
  // wastes work and triggers a benign but noisy "Autofocus processing was
  // blocked" console message because the hidden frame never has focus. Detect
  // the framed case and run a minimal MSAL-only init instead of the full UI.
  let inIframe = false;
  try { inIframe = (window.self !== window.top); } catch (e) { inIframe = true; }
  if (inIframe) {
    if (typeof initMsAuth === 'function') {
      initMsAuth();
    }
    return;
  }
  initializePage();
}

function scheduleInitialLookup(domain) {
  const bootstrapDomain = normalizeDomain(domain || '');
  if (initialLookupHasStarted || initialLookupIsScheduled) return;

  if (!bootstrapDomain) {
    initialLookupHasStarted = true;
    animateTopSections();
    return;
  }

  const input = document.getElementById("domainInput");
  const lookupBtn = document.getElementById("lookupBtn");
  if (!input || !lookupBtn || typeof lookup !== 'function') {
    if (initialLookupRetryCount < INITIAL_LOOKUP_MAX_RETRIES) {
      initialLookupRetryCount++;
      window.setTimeout(() => scheduleInitialLookup(bootstrapDomain), INITIAL_LOOKUP_RETRY_DELAY_MS);
    }
    return;
  }

  input.value = bootstrapDomain;
  toggleClearBtn();
  initialLookupIsScheduled = true;

  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      initialLookupIsScheduled = false;
      initialLookupHasStarted = true;
      lookup({ animateTopIntro: true, domainOverride: bootstrapDomain });
    });
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startPageInitialization, { once: true });
} else {
  window.setTimeout(startPageInitialization, 0);
}

window.addEventListener('load', () => {
  const params = new URLSearchParams(window.location.search);
  scheduleInitialLookup(params.get('domain') || '');
}, { once: true });

window.addEventListener('pageshow', () => {
  const params = new URLSearchParams(window.location.search);
  scheduleInitialLookup(params.get('domain') || '');
}, { once: true });

// ------------------- Microsoft Entra ID Authentication -------------------
// Uses MSAL.js v2 with Authorization Code + PKCE (most secure SPA flow).
// The client ID must match an Azure AD app registration configured as a
// Single-Page Application with redirect URI matching this app's origin.
// Set the ACS_ENTRA_CLIENT_ID env var or update the placeholder below.

let msalInstance = null;
let msAuthAccount = null;
let isMsEmployee = false;
let msalInitError = null;
const GRAPH_SCOPES = ['User.Read'];

'@
