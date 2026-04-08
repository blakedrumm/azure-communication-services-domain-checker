# ===== JavaScript Core UI (Lookup, Render, Events) =====
$htmlPage += @'
function lookup() {
  const input = document.getElementById("domainInput");
  const btn   = document.getElementById("lookupBtn");
  const screenshotBtn = document.getElementById("screenshotBtn");
  const dlBtn = document.getElementById("downloadBtn");
  const domain = normalizeDomain(input.value);
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

  // Clear previous results and hide download button
  document.getElementById("results").innerHTML = "";
  setStatus("");
  if (dlBtn) dlBtn.style.display = "none";
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
      const headers = {};
      const apiKey = (acsApiKey || '').trim();
      if (apiKey && !apiKey.startsWith('__')) {
        headers['X-Api-Key'] = apiKey;
      }
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

  function ensureResultObject() {
    if (!lastResult || typeof lastResult !== "object") {
      lastResult = {};
    }
    if (!lastResult._loaded) {
      lastResult._loaded = { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false };
    }
    if (!lastResult._errors) {
      lastResult._errors = {};
    }
  }

  ensureResultObject();
  lastResult = {
    domain,
    _loaded: { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false },
    _errors: {},
    guidance: [],
    acsReady: false
  };
  recomputeDerived(lastResult);
  render(lastResult);

  const requests = [
    { key: "base",  path: "/api/base"  },
    { key: "mx",    path: "/api/mx"    },
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
        lastResult.whoisNewDomainThresholdDays = data.newDomainThresholdDays;
        lastResult.whoisNewDomainWarnThresholdDays = data.newDomainWarnThresholdDays;
        lastResult.whoisNewDomainErrorThresholdDays = data.newDomainErrorThresholdDays;
        lastResult.whoisError = data.error;
        lastResult.whoisRawText = data.rawWhoisText;
      } else if (key === 'reputation') {
        lastResult.reputation = data;
      } else {
        Object.assign(lastResult, data);
      }
      lastResult._loaded[key] = true;
      delete lastResult._errors[key];

      if (!downloadShown) {
        const dlBtn2 = document.getElementById("downloadBtn");
        if (dlBtn2) dlBtn2.style.display = "inline-block";
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

function render(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};
  const mxLookupDomain = r && r.mxLookupDomain ? r.mxLookupDomain : (r ? r.domain : null);
  const mxFallbackUsed = !!(r && r.mxFallbackUsed);
  const mxFallbackChecked = r && r.mxFallbackDomainChecked ? r.mxFallbackDomainChecked : null;
  const allLoaded = !!(loaded.base && loaded.mx && loaded.whois && loaded.dmarc && loaded.dkim && loaded.cname && loaded.reputation);
  const anyError = !!(errors && Object.keys(errors).length > 0);
  let gatheredAtLocal = r.collectedAt ? formatLocalDateTime(r.collectedAt) : null;

  // Ensure collectedAt is stamped once all checks complete (for display + copy text)
  if (!r.collectedAt && allLoaded) {
    r.collectedAt = new Date().toISOString();
    gatheredAtLocal = formatLocalDateTime(r.collectedAt);
  }

  let statusText = "";

  if (!allLoaded) {
    statusText = escapeHtml(t('statusChecking', { domain: r.domain || '' }));
  } else if (anyError) {
    statusText = escapeHtml(t('statusSomeChecksFailed'));
  } else if (loaded.base && r.dnsFailed) {
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
    if (!r.spfPresent || r.spfHasRequiredInclude !== true) { quotaFail = true; }

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

    // Wait, I can redefine quotaRow or pass a special marker. Or simpler:
    // The user wants the link "beside the text (Reputation (DNSBL))".

    // Let's modify the usage of quotaRow for Reputation to hack it? No, escapeHtml prevents that.

    // I need to modify the quotaRow definition or the specific calls.
    // Since I can only replace strings, and the quotaRow definition is local to render(), I can modify quotaRow safely if I find it.

    // Let's see where quotaRow is defined.
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => {
    //   const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(state.toUpperCase())}</span>`;
    //   const nameHtml = escapeHtml(name) + (infoTitle ? ` <span class="info-dot" title="${escapeHtml(infoTitle)}">i</span>` : "");
    //   ...

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
  } else if (r.dnsFailed) {
    quotaItems.push(quotaRow(t('spfQueried'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), null, 'spf'));
    quotaLines.push(`**${t('spfQueried')}:** FAIL${r.dnsError ? ' - ' + r.dnsError : ' - ' + t('txtLookupFailedOrTimedOut')}`);
    quotaLinesHtml.push(`<strong>${escapeHtml(t('spfQueried'))}:</strong> FAIL${r.dnsError ? ' - ' + escapeHtml(r.dnsError) : ' - ' + escapeHtml(t('txtLookupFailedOrTimedOut'))}`);
  } else {
    const spfPassesRequirement = !!(r.spfPresent && r.spfHasRequiredInclude === true);
    const spfDetail = r.spfPresent
      ? ([r.spfValue, getLocalizedSpfRequirementSummary(r)].filter(Boolean).join("\n\n"))
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
      : (r.acsPresent ? t('verified') : t('notVerified')));

  const spfStatusText = (!loaded.base && !errors.base)
    ? t('pending')
    : (errors.base
      ? t('error')
      : ((r.spfPresent && r.spfHasRequiredInclude !== false) ? t('verified') : t('notStarted')));

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

  const htmlTableRows = [];
  const addRow = (name, value) => { htmlTableRows.push(`<tr><th>${escapeHtml(name)}</th><td>${escapeHtml(value)}</td></tr>`); };
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
  } else if (r.dnsFailed) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'fail', t('missingRequiredAcsTxt'), 'acsTxt'));
  } else {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'pass', t('resolvedSuccessfully'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), r.acsPresent ? 'pass' : 'fail', r.acsPresent ? t('msDomainVerificationFound') : t('addAcsTxtFromPortal'), 'acsTxt'));
  }

  // Overall ACS readiness
  verificationItems.push(verifyRow(t('acsReadiness'), (loaded.base && !errors.base && !r.dnsFailed && r.acsPresent) ? 'pass' : (loaded.base && !errors.base ? 'fail' : 'pending'), r.acsReady ? t('acsReadyMessage') : t('missingRequiredAcsTxt'), 'verification'));

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
      const valueHtml = options.italic
        ? `<em>${escapeHtml(value)}</em>`
        : escapeHtml(value);
      whoisRows.push(`<div class="kv-label">${escapeHtml(label)}:</div><div class="kv-value">${valueHtml}</div>`);
    };

    addWhoisRow(t('lookupDomainLabel'), r.whoisLookupDomain);
    if (r.whoisLookupDomain && r.whoisSource) {
      whoisRows.push('<div class="kv-spacer"></div>');
    }
    addWhoisRow(t('source'), r.whoisSource, { italic: true });
    addWhoisRow(t('creationDate'), r.whoisCreationDateUtc);
    addWhoisRow(t('registryExpiryDate'), r.whoisExpiryDateUtc);
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

    const rawWhoisHtml = (r.whoisRawText && !r.whoisCreationDateUtc && !r.whoisExpiryDateUtc && !r.whoisRegistrar && !r.whoisRegistrant)
      ? `<div class="code" style="margin-top:10px;">${escapeHtml(t('rawLabel'))} (${escapeHtml(r.whoisSource || t('rawWhoisLabel'))}):\n${escapeHtml(r.whoisRawText)}</div>`
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
      ${rawWhoisHtml}
      ${whoisErrorHtml}
    </div>
  </div>
    `);
  }

  {
    const baseLoaded = loaded.base && !errors.base && !r.dnsFailed;
    const ipv4List = Array.isArray(r.ipv4Addresses) ? r.ipv4Addresses.filter(x => x) : [];
    const ipv6List = Array.isArray(r.ipv6Addresses) ? r.ipv6Addresses.filter(x => x) : [];
    const ipLookupDomain = r.ipLookupDomain || r.domain;
    const ipUsedParent = r.ipUsedParent === true && ipLookupDomain && ipLookupDomain !== r.domain;
    const domainLabel = basePending ? "PENDING" : (baseError ? "ERROR" : (r.dnsFailed ? "DNS ERROR" : "LOOKED UP"));
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
    ? (r.spfValue || ((r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('none')}: ${r.domain}\n\n${t('resolvedUsingGuidance', { lookupDomain: r.txtLookupDomain })}\n${r.parentSpfValue || ''}`) : null))
    : (baseError ? (errors.base || t('error')) : t('loadingValue'));
  const spfCardValue = [spfCardBaseValue, getLocalizedSpfRequirementSummary(r)].filter(Boolean).join("\n\n");
  // The expanded SPF analysis is server-generated in English, and it is only meaningful once the
  // base TXT payload has loaded, so only render it for English after the base check completes.
  const spfExpandedSection = currentLanguage === 'en' && loaded.base && r.spfExpandedText
    ? `\n\n--- ${t('spfRecordBasics')} ---\n${stripSpfRequirementSection(r.spfExpandedText)}`
    : '';
  cards.push(card(
    t('spfQueried'),
    (spfCardValue || t('noRecordsAvailable')) + spfExpandedSection,
    basePending ? "LOADING" : (baseError ? "ERROR" : ((r.spfPresent && r.spfHasRequiredInclude === true) ? "PASS" : "FAIL")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : ((r.spfPresent && r.spfHasRequiredInclude === true) ? "tag-pass" : "tag-fail")),
    "spf"
  ));

  cards.push(card(
    t('acsDomainVerificationTxt'),
    loaded.base ? (r.acsValue || ((r.parentAcsPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noRecordOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainAcsTxtInfo', { lookupDomain: r.txtLookupDomain })}\n${r.parentAcsValue || ''}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.acsPresent ? "PASS" : "MISSING")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.acsPresent ? "tag-pass" : "tag-fail")),
    "acsTxt"
  ));

  cards.push(card(
    t('txtRecordsQueried'),
    loaded.base ? (((r.txtRecords || []).join("\n")) || ((r.parentTxtRecords && r.parentTxtRecords.length > 0 && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noTxtRecordsOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainTxtRecordsInfo', { lookupDomain: r.txtLookupDomain })}\n${(r.parentTxtRecords || []).join("\n")}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
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
      body += `\n${t('riskLabel')}: ${riskSummary}`;
      body += `\n${t('reputationWord')}: ${rating} (${percent}%)`;
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

  const guidanceItems = (r.guidance || []).map(g => {
    let iconHtml = '';
    let text = g;
    let type = 'info';

    if (typeof g === 'object' && g !== null) {
      text = g.text;
      type = g.type || 'info';
    }

    let iconClass = 'icon-info';
    let iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/info.svg';
    let iconTitle = t('guidanceIconInformational');

    if (type === 'error') {
      iconClass = 'icon-error';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/alert-circle.svg';
      iconTitle = t('guidanceIconError');
    } else if (type === 'attention') {
      iconClass = 'icon-warning';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/triangle-alert.svg';
      iconTitle = t('guidanceIconAttention');
    } else if (type === 'success') {
      iconClass = 'icon-success';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/check-circle.svg';
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
           <img src="https://cdn.jsdelivr.net/npm/lucide-static/icons/triangle-alert.svg" class="status-icon icon-warning" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendAttention'))}"/> <span style="margin-right: 8px;">${escapeHtml(t('guidanceLegendAttention'))}</span>
           <img src="https://cdn.jsdelivr.net/npm/lucide-static/icons/info.svg" class="status-icon icon-info" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendInformational'))}"/> <span>${escapeHtml(t('guidanceLegendInformational'))}</span>
        </div>
      </div>
      <div id="field-guidance" class="card-content">
        <ul class="guidance">
          ${guidanceItems || `<li>${escapeHtml(t('noAdditionalGuidance'))}</li>`}
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

  document.getElementById("results").innerHTML = cards.join("");
  startLoadingDotAnimations();
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
  if (targets.length === 0) return;
  let step = 0;
  _loadingDotsTimer = setInterval(() => {
    const active = document.querySelectorAll('#results .loading-dots');
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
window.addEventListener("load", function () {
  currentLanguage = detectLanguage();

  // 1. Check for saved theme
  // 2. If none, check system preference (Dark vs Light)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = systemPrefersDark ? "dark" : "light";

  const savedTheme = localStorage.getItem("acsTheme") || defaultTheme;

  applyTheme(savedTheme);
  applyLanguage(currentLanguage, false);
  loadHistory();
  toggleClearBtn();

  const params = new URLSearchParams(window.location.search);
  const d = params.get("domain");
  if (d) {
    document.getElementById("domainInput").value = d;
    toggleClearBtn();
    lookup();
  }

  const reportBtn = document.getElementById("reportIssueBtn");
  const issueUrl = (acsIssueUrl || '').trim();
  if (reportBtn) {
    reportBtn.style.display = (!issueUrl || issueUrl.startsWith('__')) ? 'none' : '';
  }

  // Initialize Microsoft Entra ID authentication
  initMsAuth();
});

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
