# ===== JavaScript Core UI (Lookup, Render, Events) =====
$htmlPage += @'
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
  btn.innerHTML = `${escapeHtml(t('checkingShort'))} <span class="spinner"></span>`;
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
      const r = await fetch(path + "?domain=" + encodeURIComponent(domain), { signal: controller.signal, headers: headers });
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

    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

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

function card(title, value, label, cls, key, showCopy = true, titleSuffixHtml = '') {
  const cardId = key ? `card-${key}` : '';
  const checkedDomain = (lastResult && lastResult.domain) ? String(lastResult.domain) : '';
  // Always escape the title text to prevent XSS via crafted DNS responses.
  // Use titleSuffixHtml for trusted HTML additions (e.g., info-dot buttons, links).
  const safeTitle = applyCheckedDomainEmphasis(escapeHtml(title), checkedDomain);
  const safeValue = applyCheckedDomainEmphasis(escapeHtml(value || t('noRecordsAvailable')), checkedDomain);
  const translatedLabel = label ? escapeHtml(translateBadge(label)) : "";
  return `
  <div class="card"${cardId ? ` id="${cardId}"` : ''}>
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      ${label ? `<span class="tag ${cls}">${translatedLabel}</span>` : ""}
      <strong>${safeTitle}</strong>${titleSuffixHtml ? ' ' + titleSuffixHtml : ''}
      ${showCopy ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, '${key}')">${escapeHtml(t('copy'))}</button>` : ""}
    </div>
    <div id="field-${key}" class="code card-content">${safeValue}</div>
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
  const header = `
    <thead>
      <tr>
        <th style="text-align:center;">${escapeHtml(t('spfExpansionDepth'))}</th>
        <th>${escapeHtml(t('spfExpansionMechanism'))}</th>
        <th>${escapeHtml(t('spfExpansionParent'))}</th>
        <th>${escapeHtml(t('spfExpansionTarget'))}</th>
        <th style="text-align:right;" title="${escapeHtml(t('spfExpansionLookupsHint'))}">${escapeHtml(t('spfExpansionLookups'))}</th>
        <th>${escapeHtml(t('spfExpansionRecord'))}</th>
      </tr>
    </thead>`;

  // Track the previous row's target so nested rows can dim a repeated parent
  // value (chain continuation) to reduce visual noise.
  let previousTarget = '';
  const body = rows.map((row) => {
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

    return `
      <tr>
        <td class="spf-col-depth">${escapeHtml(String(row.depth))}</td>
        <td class="spf-col-mechanism">${escapeHtml(row.mechanism)}</td>
        <td class="spf-col-parent">${parentCellHtml}</td>
        <td class="spf-col-target">${indentHtml}${escapeHtml(row.target)}</td>
        <td class="spf-col-lookups">${lookupsCellHtml}</td>
        <td class="spf-col-record">${recordCellHtml}</td>
      </tr>`;
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
  return [...(Array.isArray(records) ? records : [])].sort((left, right) => {
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
    const name = escapeHtml(record.name || '');
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
    return `<tr class="dns-record-row${isSelected ? ' dns-record-row-selected' : ''}" data-row-key="${escapeHtml(rowKey)}" data-search="${escapeHtml(searchText)}" data-col-name="${escapeHtml(String(record.name || '').toLowerCase())}" data-col-class="${escapeHtml(String(record.class || 'IN').toLowerCase())}" data-col-display-class="${dnsClass}" data-col-type="${escapeHtml(String(record.type || '').toLowerCase())}" data-col-display-type="${type}" data-col-data="${escapeHtml(String((record.data || '') + ' ' + details.map(item => `${t(item.labelKey || '')} ${item.value || ''}`.trim()).join(' ')).toLowerCase())}" data-col-ttl="${escapeHtml(String(ttl).toLowerCase())}" aria-pressed="${isSelected ? 'true' : 'false'}" tabindex="0" onclick="toggleDnsRecordRowSelection(this)" onkeydown="handleDnsRecordRowKeydown(event, this)"><td>${name}</td><td>${dnsClass}</td><td>${type}</td><td class="dns-record-data">${data}</td><td class="dns-record-ttl">${ttl}</td></tr>`;
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
    statusText = `${escapeHtml(t('statusChecking', { domain: r.domain || '' }))} <span class="loading-dots status-loading-dots"><span class="loading-dot active">.</span><span class="loading-dot">.</span><span class="loading-dot">.</span></span>`;
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
    if (whoisErrorText || !whoisHasData) {
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
  const whoisHasData = !!(r.whoisSource || r.whoisCreationDateUtc || r.whoisExpiryDateUtc || r.whoisRegistrar || r.whoisRegistrant || r.whoisAgeHuman || r.whoisExpiryHuman);

  if (!loaded.whois && !errors.whois) {
    quotaItems.push(quotaRow(t('domainRegistration'), 'pending', t('loadingValue'), null, 'whois'));
    regState = 'PENDING';
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
      const ageText = parts.join(' | ') || t('resolvedSuccessfully');
      quotaItems.push(quotaRow(t('domainRegistration'), 'pass', ageText, null, 'whois'));
      regState = 'PASS';
      quotaLines.push(`**Domain Registration:** ${regState}${ageText ? ' - ' + ageText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${ageText ? ' - ' + escapeHtml(ageText) : ''}`);
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
    const spfDetail = effectiveSpfPresent
      ? ([effectiveSpfValue, getLocalizedSpfRequirementSummary({ spfPresent: effectiveSpfPresent, spfHasRequiredInclude: effectiveSpfHasRequiredInclude })].filter(Boolean).join("\n\n"))
      : t('noSpfRecordDetected');
    quotaItems.push(quotaRow(t('spfQueried'), spfPassesRequirement ? 'pass' : 'fail', spfDetail, null, 'spf'));
    const spfState = spfPassesRequirement ? 'PASS' : 'FAIL';
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

  const quotaCopyTextPlain = plainTable.join('\n');
  const quotaCopyTextHtml = `<table style="border-collapse:collapse;min-width:260px;">${htmlTableRows.map(r => r.replace('<th>', '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">').replace('<td>', '<td style="padding:4px 8px;border:1px solid #ddd;">')).join('')}</table>`;
  quotaCopyText = quotaCopyTextPlain;
  // Expose for inline copy handler with rich + plain variants
  window.quotaCopyText = { plain: quotaCopyTextPlain, html: quotaCopyTextHtml };

  cards.push(`
  <div class="card" id="card-email-quota">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('checklist'))}</span>
      <strong>${escapeHtml(t('emailQuota'))}</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left:auto;" onclick="event.stopPropagation(); copyText(window.quotaCopyText, this)">${escapeHtml(t('copyEmailQuota'))}</button>
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
    if (r.whoisExpiryDays !== null && r.whoisExpiryDays !== undefined) {
      addWhoisRow(t('daysUntilExpiry'), String(r.whoisExpiryDays));
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
    const whoisErrorHtml = r.whoisError
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
  const spfCardValue = [spfCardBaseValue, getLocalizedSpfRequirementSummary({ spfPresent: effectiveSpfPresent, spfHasRequiredInclude: effectiveSpfHasRequiredInclude })].filter(Boolean).join("\n\n");
  // The SPF card body intentionally stops at the record value + ACS Outlook
  // requirement verdict. The full expanded SPF chain (per-node domain,
  // resolved TXT, and lookup-count contributions) is rendered as a
  // structured table in the sibling SPF Expansion Records card below, so
  // duplicating the same data here as an indented text dump just adds
  // visual noise. (The server still emits r.spfExpandedText for raw API
  // consumers.)
  cards.push(card(
    t('spfQueried'),
    (spfCardValue || t('noRecordsAvailable')),
    basePending ? "LOADING" : (baseError ? "ERROR" : ((effectiveSpfPresent && effectiveSpfHasRequiredInclude === true) ? "PASS" : "FAIL")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : ((effectiveSpfPresent && effectiveSpfHasRequiredInclude === true) ? "tag-pass" : "tag-fail")),
    "spf"
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

  cards.push(card(
    t('dmarc'),
    loaded.dmarc ? (r.dmarc ? (r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain ? (`${r.dmarc}\n\n${t('effectivePolicyInherited', { lookupDomain: r.dmarcLookupDomain })}`) : r.dmarc) : null) : (errors.dmarc ? errors.dmarc : t('loadingValue')),
    (!loaded.dmarc && !errors.dmarc) ? "LOADING" : (errors.dmarc ? "ERROR" : (r.dmarc ? "PASS" : "OPTIONAL")),
    (!loaded.dmarc && !errors.dmarc) ? "tag-info" : (errors.dmarc ? "tag-fail" : (r.dmarc ? "tag-pass" : "tag-info")),
    "dmarc"
  ));

  // include full selector host with domain in title
  cards.push(card(
    `${t('dkim1Title')} (selector1-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim1 : (errors.dkim ? errors.dkim : t('loadingValue')),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim1 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim1 ? "tag-pass" : "tag-info")),
    "dkim1"
  ));

  cards.push(card(
    `${t('dkim2Title')} (selector2-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim2 : (errors.dkim ? errors.dkim : t('loadingValue')),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim2 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim2 ? "tag-pass" : "tag-info")),
    "dkim2"
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
    <div class="card">
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
    <div class="card">
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
  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('tools'))}</span>
        <strong>${escapeHtml(t('externalTools'))}</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="${centralOps}" target="_blank" rel="noopener">${escapeHtml(t('domainDossier'))}</a></li>
          <li><a href="${multiRbl}" target="_blank" rel="noopener">${escapeHtml(t('multiRblLookup'))}</a></li>
        </ul>
      </div>
    </div>
  `);

  renderResultsMarkup(cards.join(""));
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

document.getElementById('azureSubscriptionSelect').addEventListener('change', function () {
  azureDiagnosticsState.resources = [];
  azureDiagnosticsState.workspaces = [];
  renderAzureDiagnosticsUi();
  discoverAzureResources();
});

document.getElementById('azureResourceSelect').addEventListener('change', function () {
  azureDiagnosticsState.workspaces = [];
  renderAzureDiagnosticsUi();
  discoverAzureWorkspaces();
});

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
const ARM_SCOPES = ['https://management.azure.com/user_impersonation'];
const LOG_ANALYTICS_SCOPES = ['https://api.loganalytics.io/Data.Read'];
const GRAPH_SCOPES = ['User.Read'];
let azureDiagnosticsState = {
  subscriptions: [],
  resources: [],
  workspaces: [],
  lastQueryText: '',
  lastQueryName: '',
  lastResult: null,
  isBusy: false
};

'@
