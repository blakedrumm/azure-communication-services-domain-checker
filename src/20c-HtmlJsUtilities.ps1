# ===== JavaScript Utility Functions =====
$htmlPage += @'

// ---- Cookie Consent Manager (EU GDPR / ePrivacy compliance) ----
// Consent state is stored in localStorage under 'acsCookieConsent'.
// Three categories: essential (always on), functional (theme/lang/history), analytics (metrics).
// All localStorage/cookie writes for non-essential purposes are gated behind these checks.
const COOKIE_CONSENT_KEY = 'acsCookieConsent';

// Returns the current consent state, or null if consent has not been given yet.
function getCookieConsent() {
  try {
    const raw = localStorage.getItem(COOKIE_CONSENT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && typeof parsed.functional === 'boolean') {
      return parsed;
    }
  } catch {}
  return null;
}

// Check whether a specific cookie category has been consented to.
// 'essential' always returns true. 'functional' and 'analytics' depend on user choice.
function hasConsentFor(category) {
  if (category === 'essential') return true;
  const consent = getCookieConsent();
  if (!consent) return false;
  return !!consent[category];
}

// Persist the consent choices to localStorage with a timestamp.
function persistCookieConsent(functional, analytics) {
  const consent = {
    essential: true,
    functional: !!functional,
    analytics: !!analytics,
    timestamp: new Date().toISOString()
  };
  try {
    localStorage.setItem(COOKIE_CONSENT_KEY, JSON.stringify(consent));
  } catch {}
  return consent;
}

// Build the compact consent header value sent to same-origin API routes.
// This lets the PowerShell server distinguish essential-only requests from
// requests where the user explicitly granted analytics consent.
function buildCookieConsentHeaderValue(consent) {
  const state = consent || getCookieConsent() || { essential: true, functional: false, analytics: false };
  return `essential=${state.essential ? '1' : '0'};functional=${state.functional ? '1' : '0'};analytics=${state.analytics ? '1' : '0'}`;
}

function buildConsentRequestHeaders(headers = {}, consent) {
  const next = Object.assign({}, headers || {});
  next['X-ACS-Cookie-Consent'] = buildCookieConsentHeaderValue(consent);
  return next;
}

// Notify the server whenever consent changes so it can clear previously issued
// analytics cookies immediately when the user rejects analytics storage.
async function syncCookieConsentWithServer(consent) {
  try {
    await fetch('/api/consent', {
      method: 'POST',
      headers: buildConsentRequestHeaders({ 'Content-Type': 'application/json' }, consent),
      body: JSON.stringify({
        essential: true,
        functional: !!(consent && consent.functional),
        analytics: !!(consent && consent.analytics)
      })
    });
  } catch {}
}

// Show the cookie consent banner.
function showCookieConsentBanner() {
  const overlay = document.getElementById('cookieConsentOverlay');
  if (overlay) {
    // Restore toggle states from any previously saved consent
    const existing = getCookieConsent();
    const funcToggle = document.getElementById('cookieToggleFunctional');
    const analyticsToggle = document.getElementById('cookieToggleAnalytics');
    if (existing) {
      if (funcToggle) funcToggle.checked = !!existing.functional;
      if (analyticsToggle) analyticsToggle.checked = !!existing.analytics;
    } else {
      // Default to checked for first-time visitors (opt-in UI)
      if (funcToggle) funcToggle.checked = true;
      if (analyticsToggle) analyticsToggle.checked = true;
    }
    overlay.style.display = '';
    // Trap focus inside the banner for accessibility
    const firstBtn = overlay.querySelector('button');
    if (firstBtn) firstBtn.focus();
  }
}

// Hide the cookie consent banner.
function hideCookieConsentBanner() {
  const overlay = document.getElementById('cookieConsentOverlay');
  if (overlay) overlay.style.display = 'none';
}

// Handle cookie consent save action.
// mode: 'acceptAll' | 'reject' | 'custom'
async function saveCookieConsent(mode) {
  let functional = false;
  let analytics = false;

  if (mode === 'acceptAll') {
    functional = true;
    analytics = true;
  } else if (mode === 'reject') {
    functional = false;
    analytics = false;
  } else {
    // Custom: read toggle states
    const funcToggle = document.getElementById('cookieToggleFunctional');
    const analyticsToggle = document.getElementById('cookieToggleAnalytics');
    functional = funcToggle ? funcToggle.checked : false;
    analytics = analyticsToggle ? analyticsToggle.checked : false;
  }

  const consent = persistCookieConsent(functional, analytics);

  // Apply the consent: if functional was just granted, persist any pending
  // preferences that were held back (theme, language, history).
  if (consent.functional) {
    const theme = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
    consentAwareSetItem('acsTheme', theme, 'functional');
    if (typeof currentLanguage !== 'undefined' && currentLanguage) {
      consentAwareSetItem(LANG_KEY, currentLanguage, 'functional');
    }
  } else {
    // Functional cookies rejected: remove stored preferences
    clearNonEssentialStorage('functional');
  }

  if (!consent.analytics) {
    // Analytics rejected: clear any analytics-related storage
    clearNonEssentialStorage('analytics');
  }

  await syncCookieConsentWithServer(consent);
  hideCookieConsentBanner();
}

// Remove stored data for a rejected cookie category.
function clearNonEssentialStorage(category) {
  try {
    if (category === 'functional') {
      localStorage.removeItem('acsTheme');
      localStorage.removeItem(LANG_KEY);
      localStorage.removeItem(HISTORY_KEY);
    }
    // Analytics data is server-side; no client-side cleanup needed.
  } catch {}
}

// Re-open the cookie preferences banner (called from footer link).
function openCookieSettings() {
  showCookieConsentBanner();
}

// Check if the consent banner should be shown (first visit or no consent stored).
function shouldShowCookieConsent() {
  return getCookieConsent() === null;
}

// Gate-aware wrapper for localStorage.setItem — only writes if the category is consented.
// category: 'functional' | 'analytics' | 'essential'
function consentAwareSetItem(key, value, category) {
  if (!hasConsentFor(category || 'functional')) return false;
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {}
  return false;
}

// Gate-aware wrapper for localStorage.getItem — reads are allowed for essential,
// but functional/analytics reads return null if consent was not given.
function consentAwareGetItem(key, category) {
  if (!hasConsentFor(category || 'functional')) return null;
  try {
    return localStorage.getItem(key);
  } catch {}
  return null;
}

// Update cookie consent banner text to match the current language.
function applyCookieConsentLanguage() {
  const title = document.getElementById('cookieConsentTitle');
  if (title) title.textContent = t('cookieConsentTitle');

  const desc = document.getElementById('cookieConsentDesc');
  if (desc) desc.textContent = t('cookieConsentDescription');

  const essName = document.getElementById('cookieCatEssentialName');
  if (essName) essName.textContent = t('cookieCatEssential');

  const essDesc = document.getElementById('cookieCatEssentialDesc');
  if (essDesc) essDesc.textContent = t('cookieCatEssentialDesc');

  const funcName = document.getElementById('cookieCatFunctionalName');
  if (funcName) funcName.textContent = t('cookieCatFunctional');

  const funcDesc = document.getElementById('cookieCatFunctionalDesc');
  if (funcDesc) funcDesc.textContent = t('cookieCatFunctionalDesc');

  const analName = document.getElementById('cookieCatAnalyticsName');
  if (analName) analName.textContent = t('cookieCatAnalytics');

  const analDesc = document.getElementById('cookieCatAnalyticsDesc');
  if (analDesc) analDesc.textContent = t('cookieCatAnalyticsDesc');

  const rejectBtn = document.getElementById('cookieBtnReject');
  if (rejectBtn) rejectBtn.textContent = t('cookieBtnReject');

  const saveBtn = document.getElementById('cookieBtnSave');
  if (saveBtn) saveBtn.textContent = t('cookieBtnSave');

  const acceptBtn = document.getElementById('cookieBtnAcceptAll');
  if (acceptBtn) acceptBtn.textContent = t('cookieBtnAcceptAll');
}

function normalizeLanguageCode(lang) {
  const value = String(lang || '').trim().toLowerCase();
  if (!value) return 'en';
  if (value === 'ptbr' || value.startsWith('pt-br') || value.startsWith('pt_br') || value.startsWith('pt')) return 'pt-BR';
  if (value.startsWith('es')) return 'es';
  if (value.startsWith('fr')) return 'fr';
  if (value.startsWith('de')) return 'de';
  if (value.startsWith('ar')) return 'ar';
  if (value === 'zh' || value.startsWith('zh-cn') || value.startsWith('zh_cn') || value.startsWith('zh-hans')) return 'zh-CN';
  if (value === 'hi' || value.startsWith('hi-in') || value.startsWith('hi_in')) return 'hi-IN';
  if (value === 'ja' || value.startsWith('ja-jp') || value.startsWith('ja_jp')) return 'ja-JP';
  if (value === 'ru' || value.startsWith('ru-ru') || value.startsWith('ru_ru')) return 'ru-RU';
  return 'en';
}

function isRtlLanguage(language) {
  return RTL_LANGUAGES.has(normalizeLanguageCode(language));
}

function getLanguageFromUrl() {
  try {
    const params = new URLSearchParams(window.location.search);
    const lang = params.get(LANG_PARAM) || params.get('language');
    return lang ? normalizeLanguageCode(lang) : null;
  } catch {
    return null;
  }
}

function updateLanguageUrlParameter() {
  try {
    const url = new URL(window.location.href);
    url.searchParams.set(LANG_PARAM, currentLanguage);
    window.history.replaceState({}, '', url);
  } catch {}
}

// Allow static pages such as /privacy and /terms to deep-link back into the SPA
// and immediately reopen the cookie preferences dialog.
function consumeOpenCookieSettingsRequest() {
  try {
    const url = new URL(window.location.href);
    const raw = String(url.searchParams.get('openCookieSettings') || '').trim().toLowerCase();
    const shouldOpen = raw === '1' || raw === 'true' || raw === 'yes';
    if (!shouldOpen) return false;
    url.searchParams.delete('openCookieSettings');
    window.history.replaceState({}, '', url);
    return true;
  } catch {
    return false;
  }
}

function getSavedLanguage() {
  try {
    // Language preference requires functional cookie consent
    return consentAwareGetItem(LANG_KEY, 'functional');
  } catch {
    return null;
  }
}

function detectLanguage() {
  const urlLanguage = getLanguageFromUrl();
  if (urlLanguage) return urlLanguage;
  const saved = getSavedLanguage();
  if (saved) return normalizeLanguageCode(saved);
  return normalizeLanguageCode(navigator.language || navigator.userLanguage || 'en');
}

function t(key, params = {}) {
  const langTable = TRANSLATIONS[currentLanguage] || TRANSLATIONS.en;
  let text = langTable[key] || TRANSLATIONS.en[key] || key;
  const resolved = String(text).replace(/\{(\w+)\}/g, (_, token) => {
    const value = Object.prototype.hasOwnProperty.call(params, token) ? params[token] : `{${token}}`;
    return value === null || value === undefined ? '' : String(value);
  });

  return stripUiEmoji(repairMojibake(resolved));
}

function looksLikeMojibake(text) {
  // Detect double-encoded UTF-8 misinterpreted as Latin-1/Windows-1252.
  // Lead-byte chars must be followed by continuation-byte chars (\u0080-\u00BF),
  // NOT arbitrary characters, to avoid false-positives on valid Portuguese/French
  // text like \u00E3o (\u00E3 + o) or \u00C3O (\u00C3 + O).
  return /(?:[\u00C2-\u00DF][\u0080-\u00BF]|[\u00E0-\u00EF][\u0080-\u00BF]{2}|[\u00F0-\u00F4][\u0080-\u00BF]{3})/.test(String(text || ''));
}

function repairMojibake(text) {
  const value = String(text || '');
  if (!looksLikeMojibake(value)) return value;

  try {
    const bytes = new Uint8Array(Array.from(value, ch => ch.charCodeAt(0) & 0xFF));
    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    if (decoded && !looksLikeMojibake(decoded)) return decoded;
  } catch {}

  try {
    const decoded = decodeURIComponent(escape(value));
    if (decoded && !looksLikeMojibake(decoded)) return decoded;
  } catch {}

  return value;
}

function repairObjectStrings(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return repairMojibake(value);
  if (Array.isArray(value)) return value.map(repairObjectStrings);
  if (typeof value === 'object') {
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = repairObjectStrings(entry);
    }
    return result;
  }
  return value;
}

function stripUiEmoji(text) {
  return String(text || '')
    .replace(/\uD83C\uDF19|\u2600\uFE0F?|\uD83D\uDD17|\uD83D\uDCF8|\uD83D\uDCE5|\uD83D\uDC1B|\uD83D\uDD12|\u23F3|\u274C|\uD83D\uDCA1/g, '')
    .replace(/\uFE0F/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

const UI_LABEL_ICONS = {
  themeDark: { icon: 'moon-star', className: 'icon-info' },
  themeLight: { icon: 'sun', className: 'icon-warning' },
  copyLink: { icon: 'link', className: 'icon-info' },
  copyScreenshot: { icon: 'camera', className: 'icon-info' },
  downloadJson: { icon: 'download', className: 'icon-success' },
  reportIssue: { icon: 'bug', className: 'icon-warning' },
  signInMicrosoft: { icon: 'lock-keyhole', className: 'icon-info' },
  guidance: { icon: 'lightbulb', className: 'icon-warning guidance-title-icon' }
};

function getLucideIconUrl(iconName) {
  return `/assets/vendor/lucide-static/icons/${iconName}.svg`;
}

function renderLabelWithIcon(key) {
  const config = UI_LABEL_ICONS[key];
  const text = escapeHtml(t(key));
  if (!config) return text;

  const iconHtml = `<img src="${getLucideIconUrl(config.icon)}" class="toolbar-icon ${config.className}" alt="" aria-hidden="true" />`;
  return `<span class="inline-label">${text}${iconHtml}</span>`;
}

function getLanguageDisplayName(code) {
  return repairMojibake(LANGUAGE_DISPLAY_NAMES[code] || ((TRANSLATIONS[code] && TRANSLATIONS[code].languageName) ? TRANSLATIONS[code].languageName : code));
}

function translateBadge(label) {
  const normalized = String(label || '').trim().toUpperCase();
  const map = {
    'CHECKLIST': 'checklist',
    'VERIFICATION': 'verificationTag',
    'DOCS': 'docs',
    'TOOLS': 'tools',
    'READINESS TIPS': 'readinessTips',
    'LOOKED UP': 'lookedUp',
    'LOADING': 'loading',
    'MISSING': 'missing',
    'OPTIONAL': 'optional',
    'INFO': 'info',
    'ERROR': 'error',
    'PASS': 'pass',
    'FAIL': 'fail',
    'WARN': 'warn',
    'PENDING': 'pending',
    'DNS ERROR': 'dnsError',
    'NEW DOMAIN': 'newDomain',
    'EXPIRED': 'expired'
  };
  return map[normalized] ? t(map[normalized]) : label;
}

function getLanguageButtonHtml(code) {
  const flagUrl = LANGUAGE_FLAG_URLS[code] || '';
  const name = getLanguageDisplayName(code);
  const safeName = escapeHtml(name);
  const flagHtml = flagUrl ? `<img class="language-flag" src="${escapeHtml(flagUrl)}" alt="" loading="lazy" />` : '';
  return `${flagHtml}<span>${safeName}</span><span class="caret">&#x25BE;</span>`;
}

function closeLanguageMenu() {
  const menu = document.getElementById('languageSelectMenu');
  const button = document.getElementById('languageSelectBtn');
  if (menu) menu.classList.remove('open');
  if (button) button.setAttribute('aria-expanded', 'false');
}

function toggleLanguageMenu() {
  const menu = document.getElementById('languageSelectMenu');
  const button = document.getElementById('languageSelectBtn');
  if (!menu || !button) return;
  const willOpen = !menu.classList.contains('open');
  menu.classList.toggle('open', willOpen);
  button.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
}

function populateLanguageSelect() {
  const button = document.getElementById('languageSelectBtn');
  const menu = document.getElementById('languageSelectMenu');
  if (!button || !menu) return;

  button.innerHTML = getLanguageButtonHtml(currentLanguage);
  button.setAttribute('aria-label', `${t('languageLabel')}: ${getLanguageDisplayName(currentLanguage)}`);

  menu.innerHTML = LANGUAGE_OPTIONS.map(code => {
    const selected = code === currentLanguage ? ' active' : '';
    return `<button type="button" class="language-option${selected}" role="option" aria-selected="${code === currentLanguage ? 'true' : 'false'}" onclick="changeLanguage('${code}')">${getLanguageButtonHtml(code).replace('<span class="caret">&#x25BE;</span>', '')}</button>`;
  }).join('');
}

function applyLanguageToStaticUi() {
  document.documentElement.lang = currentLanguage;
  document.documentElement.dir = isRtlLanguage(currentLanguage) ? 'rtl' : 'ltr';
  document.title = t('pageTitle');

  const heading = document.getElementById('appHeading');
  if (heading) heading.innerHTML = t('appHeading');

  const input = document.getElementById('domainInput');
  if (input) input.placeholder = t('placeholderDomain');

  const lookupBtn = document.getElementById('lookupBtn');
  if (lookupBtn) {
    lookupBtn.innerHTML = lookupInProgress
      ? `${escapeHtml(t('checkingShort'))} <span class="spinner"></span>`
      : t('lookup');
  }

  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn) {
    themeBtn.innerHTML = document.documentElement.classList.contains('dark') ? renderLabelWithIcon('themeLight') : renderLabelWithIcon('themeDark');
  }

  const copyLinkBtn = document.getElementById('copyLinkBtn');
  if (copyLinkBtn) copyLinkBtn.innerHTML = renderLabelWithIcon('copyLink');

  const screenshotBtn = document.getElementById('screenshotBtn');
  if (screenshotBtn) screenshotBtn.innerHTML = renderLabelWithIcon('copyScreenshot');

  const downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) downloadBtn.innerHTML = renderLabelWithIcon('downloadJson');

  const reportBtn = document.getElementById('reportIssueBtn');
  if (reportBtn) reportBtn.innerHTML = renderLabelWithIcon('reportIssue');
  if (reportBtn) reportBtn.title = t('reportIssueTitle');

  const signInBtn = document.getElementById('msSignInBtn');
  if (signInBtn && signInBtn.style.display !== 'none') signInBtn.innerHTML = renderLabelWithIcon('signInMicrosoft');

  const signOutBtn = document.getElementById('msSignOutBtn');
  if (signOutBtn) signOutBtn.innerHTML = t('signOut');

  const azureTag = document.getElementById('azureDiagnosticsTag');
  if (azureTag) azureTag.textContent = t('azureTag');

  const azureTitle = document.getElementById('azureDiagnosticsTitle');
  if (azureTitle) azureTitle.textContent = t('azureDiagnosticsTitle');

  const azureHint = document.getElementById('azureDiagnosticsHint');
  if (azureHint) azureHint.textContent = t('azureDiagnosticsHint');

  const azureSubscriptionLabel = document.getElementById('azureSubscriptionLabel');
  if (azureSubscriptionLabel) azureSubscriptionLabel.textContent = t('azureSubscription');

  const azureSwitchDirectoryLabel = document.getElementById('azureSwitchDirectoryLabel');
  if (azureSwitchDirectoryLabel) azureSwitchDirectoryLabel.textContent = t('azureSwitchDirectory');
  const azureSwitchDirectoryBtn = document.getElementById('azureSwitchDirectoryBtn');
  if (azureSwitchDirectoryBtn) azureSwitchDirectoryBtn.textContent = t('azureSwitchBtn');

  const azureResourceLabel = document.getElementById('azureResourceLabel');
  if (azureResourceLabel) azureResourceLabel.textContent = t('azureAcsResource');

  const azureWorkspaceLabel = document.getElementById('azureWorkspaceLabel');
  if (azureWorkspaceLabel) azureWorkspaceLabel.textContent = t('azureWorkspace');

  const azureRunInventoryBtn = document.getElementById('azureRunInventoryBtn');
  if (azureRunInventoryBtn) azureRunInventoryBtn.textContent = t('azureRunInventory');

  const azureRunDomainSearchBtn = document.getElementById('azureRunDomainSearchBtn');
  if (azureRunDomainSearchBtn) azureRunDomainSearchBtn.textContent = t('azureRunDomainSearch');

  const azureRunAcsSearchBtn = document.getElementById('azureRunAcsSearchBtn');
  if (azureRunAcsSearchBtn) azureRunAcsSearchBtn.textContent = t('azureRunAcsSearch');

  const footer = document.getElementById('footerText');
  if (footer) {
    let footerHtml = t('footer', { version: appVersion });
    const langSuffix = currentLanguage ? '?lang=' + encodeURIComponent(currentLanguage) : '';
    footerHtml += ' &bull; <a href="/terms' + langSuffix + '" target="_blank" rel="noopener" style="color:inherit;">' + escapeHtml(t('termsOfService')) + '</a>';
    footerHtml += ' &bull; <a href="/privacy' + langSuffix + '" target="_blank" rel="noopener" style="color:inherit;">' + escapeHtml(t('privacyStatement')) + '</a>';
    footerHtml += ' &bull; <a href="#" class="cookie-settings-link" onclick="openCookieSettings(); return false;" style="color:inherit;">' + escapeHtml(t('cookieSettings')) + '</a>';
    footer.innerHTML = footerHtml;
  }

  populateLanguageSelect();
  loadHistory();
  renderAzureDiagnosticsUi();

  if (typeof updateAuthUI === 'function') {
    updateAuthUI(lastAuthData);
  }
}

function applyLanguage(language, persist = true) {
  currentLanguage = normalizeLanguageCode(language);
  if (persist) {
    // Only persist language preference if functional cookies are consented
    consentAwareSetItem(LANG_KEY, currentLanguage, 'functional');
  }
  updateLanguageUrlParameter();
  applyLanguageToStaticUi();
  // Update cookie consent banner text when language changes
  applyCookieConsentLanguage();
  closeLanguageMenu();
  if (lastResult) {
    // Rebuild derived, language-sensitive strings before rendering cached results again.
    recomputeDerived(lastResult);
    render(lastResult);
  }
}

function changeLanguage(language) {
  applyLanguage(language, true);
}

function cancelInflightLookup() {
  for (const c of (activeLookup.controllers || [])) {
    try { c.abort(); } catch {}
  }
  activeLookup.controllers = [];
}

function normalizeDomain(raw) {
  raw = (raw === null || raw === undefined) ? "" : String(raw);
  raw = raw.trim();

  // If user pasted an email, use the part after @
  const at = raw.lastIndexOf("@");
  if (at > -1 && at < raw.length - 1) {
    raw = raw.slice(at + 1);
  }

  // If user pasted a URL, extract hostname
  try {
    if (/^https?:\/\//i.test(raw)) {
      raw = new URL(raw).hostname;
    }
  } catch {
    // ignore
  }

  // Remove wildcard prefix and surrounding dots/spaces
  raw = raw.replace(/^\*\./, "");
  raw = raw.replace(/^\.+/, "").replace(/\.+$/, "");

  return raw.toLowerCase();
}

function isValidDomain(domain) {
  domain = (domain === null || domain === undefined) ? "" : String(domain);
  domain = domain.trim();
  if (!domain) return false;

  // Basic charset + structure checks (lenient, supports punycode)
  if (domain.length > 253) return false;
  if (!/^[a-z0-9.-]+$/.test(domain)) return false;
  if (domain.includes("..")) return false;
  if (domain.startsWith("-") || domain.endsWith("-")) return false;

  const labels = domain.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!label) return false;
    if (label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return true;
}

function toggleClearBtn() {
  const input = document.getElementById("domainInput");
  const btn = document.getElementById("clearBtn");
  if (btn) btn.style.display = input.value ? "block" : "none";
}

function clearInput() {
  const input = document.getElementById("domainInput");
  input.value = "";
  input.focus();
  toggleClearBtn();
}

function readHistoryItems() {
  try {
    // History requires functional cookie consent
    const raw = consentAwareGetItem(HISTORY_KEY, 'functional');
    const items = raw ? JSON.parse(raw) : [];
    return Array.isArray(items) ? items.map(String) : [];
  } catch {
    return [];
  }
}

function writeHistoryItems(items) {
  // Only persist history if functional cookies are consented
  consentAwareSetItem(HISTORY_KEY, JSON.stringify(items), 'functional');
}

function captureHistoryChipRects(container) {
  const rects = new Map();
  if (!container) return rects;
  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;
    rects.set(key, chip.getBoundingClientRect());
  }
  return rects;
}

function playHistoryFlip(container, beforeRects) {
  if (!container || !beforeRects || beforeRects.size === 0) return;

  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;

    const first = beforeRects.get(key);
    if (!first) continue;

    const last = chip.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (dx === 0 && dy === 0) continue;

    chip.style.transition = 'transform 0s';
    chip.style.transform = `translate(${dx}px, ${dy}px)`;
    chip.getBoundingClientRect();

    chip.style.transition = 'transform 180ms ease';
    chip.style.transform = '';

    const cleanup = () => {
      chip.style.transition = '';
      chip.style.transform = '';
      chip.removeEventListener('transitionend', cleanup);
    };
    chip.addEventListener('transitionend', cleanup);
    setTimeout(cleanup, 250);
  }
}

function promoteHistory(domain, animate) {
  const d = (domain === null || domain === undefined) ? "" : String(domain).trim();
  if (!d) return;

  const current = readHistoryItems();
  const lower = d.toLowerCase();
  let next = current.filter(i => String(i).toLowerCase() !== lower);
  next.unshift(d);
  if (next.length > 5) next = next.slice(0, 5);

  const changed =
    current.length !== next.length ||
    current.some((v, idx) => String(v).toLowerCase() !== String(next[idx]).toLowerCase());
  if (!changed) return;

  const container = document.getElementById('history');
  const before = animate ? captureHistoryChipRects(container) : null;

  writeHistoryItems(next);
  renderHistory(next);

  if (animate) {
    requestAnimationFrame(() => playHistoryFlip(container, before));
  }
}

function loadHistory() {
  try {
    renderHistory(readHistoryItems());
  } catch (e) { console.error(e); }
}

function saveHistory(domain) {
  try {
    promoteHistory(domain, false);
  } catch (e) { console.error(e); }
}

function renderHistory(items) {
  const container = document.getElementById("history");
  if (!items || items.length === 0) {
    container.innerHTML = "";
    return;
  }
  const chips = items.map(d => {
    const text = (d === null || d === undefined) ? "" : String(d);
    const safe = escapeHtml(text);
    const key = escapeHtml(text.toLowerCase());
    const arg = JSON.stringify(text);
    const removeLabel = escapeHtml(t('removeLabel'));
    return `<span class="history-chip" data-domain="${key}">
      <span class="history-item" onclick='runHistory(${arg})'>${safe}</span>
      <button type="button" class="history-remove" title="${removeLabel}" aria-label="${removeLabel}" onclick='event.stopPropagation(); removeHistory(${arg})'>&#x2715;</button>
    </span>`;
  }).join(" ");
  container.innerHTML = escapeHtml(t('recent')) + ": " + chips;
}

function removeHistory(domain) {
  const d = (domain === null || domain === undefined) ? "" : String(domain);
  try {
    const raw = consentAwareGetItem(HISTORY_KEY, 'functional');
    if (!raw) return;
    let items = JSON.parse(raw);
    items = (items || []).filter(i => String(i).toLowerCase() !== d.toLowerCase());
    consentAwareSetItem(HISTORY_KEY, JSON.stringify(items), 'functional');
    renderHistory(items);
  } catch (e) { console.error(e); }
}

function runHistory(domain) {
  promoteHistory(domain, true);
  document.getElementById("domainInput").value = domain;
  toggleClearBtn();
  lookup();
}
function downloadReport() {
  if (!lastResult) return;
  const json = JSON.stringify(lastResult, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "acs-check-" + lastResult.domain + ".json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toggleCard(header) {
  header.classList.toggle("collapsed-header");
  const content = header.nextElementSibling;
  if (content) {
    content.classList.toggle("collapsed");
  }

  // If the MX card is being collapsed, also hide the additional details and reset the button label.
  const isNowCollapsed = header.classList.contains("collapsed-header") || (content && content.classList.contains("collapsed"));
  if (isNowCollapsed) {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails && header.parentElement && header.parentElement.contains(mxDetails)) {
      mxDetails.style.display = "none";
      const btns = header.querySelectorAll("button");
      for (const b of btns) {
        const buttonText = (b.textContent || "").trim();
        if (buttonText === t('additionalDetailsPlus') || buttonText === t('additionalDetailsMinus') || buttonText.startsWith('Additional Details')) {
          b.textContent = t('additionalDetailsPlus');
          break;
        }
      }
    }
  }
}

function setStatus(html) {
  document.getElementById("status").innerHTML = html;
}

function escapeHtml(text) {
  text = (text === null || text === undefined) ? "" : String(text);
  return text.replace(/[&<>\"]/g, function(ch) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[ch];
  });
}

function linkifyText(text) {
  const escaped = escapeHtml(text);
  return escaped.replace(/(https?:\/\/[^\s<]+)/gi, function(url) {
    return `<a href="${url}" target="_blank" rel="noopener">${url}</a>`;
  });
}

function escapeRegex(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function applyCheckedDomainEmphasis(html, checkedDomain) {
  const domain = String(checkedDomain || '').trim();
  if (!domain) return String(html || '');

  const escapedDomain = escapeHtml(domain);
  if (!escapedDomain) return String(html || '');

  return String(html || '').replace(new RegExp(escapeRegex(escapedDomain), 'gi'), '<em class="checked-domain">$&</em>');
}

function formatGuidanceText(text, checkedDomain) {
  let value = String(text || '');
  const protectedTokens = [];

  const protect = (pattern) => {
    value = value.replace(pattern, (match) => {
      const token = `__GUIDANCE_CODE_${protectedTokens.length}__`;
      protectedTokens.push(match);
      return token;
    });
  };

  protect(/v=spf1\s+include:spf\.protection\.outlook\.com\s+-all/gi);
  protect(/\b(?:p|sp)=(?:none|quarantine|reject)\b/gi);
  protect(/\bpct=\d+\b/gi);
  protect(/\b(?:adkim|aspf)=[rs]\b/gi);
  protect(/\b(?:rua|ruf)=\b/gi);
  protect(/_dmarc\.[a-z0-9.-]+/gi);
  protect(/\binclude:spf\.protection\.outlook\.com\b/gi);
  protect(/\bspf\.protection\.outlook\.com\b/gi);
  protect(/\b_spf\.google\.com\b/gi);
  protect(/\binclude:zoho\.com\b/gi);
  protect(/\bms-domain-verification\b/gi);
  protect(/\bselector[12]-azurecomm-prod-net\b/gi);

  let formatted = linkifyText(value);
  formatted = formatted.replace(/`([^`]+)`/g, '<code class="guidance-code">$1</code>');
  formatted = applyCheckedDomainEmphasis(formatted, checkedDomain);
  formatted = formatted.replace(/__GUIDANCE_CODE_(\d+)__/g, (_, index) => {
    const token = protectedTokens[Number(index)] || '';
    return `<code class="guidance-code">${escapeHtml(token)}</code>`;
  });

  return formatted;
}

function formatLocalDateTime(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return null;

  try {
    return new Intl.DateTimeFormat(currentLanguage, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short'
    }).format(d);
  } catch {
    return d.toLocaleString();
  }
}

function formatLocalizedCount(count, singularKey, pluralKey) {
  const value = Number.parseInt(count, 10);
  if (!Number.isFinite(value)) return String(count || '');
  return `${value} ${t(value === 1 ? singularKey : pluralKey)}`;
}

function localizeDurationText(text) {
  const source = String(text || '').trim();
  if (!source) return source;
  if (/^expired$/i.test(source)) return t('wordExpired');

  const parts = [];
  const regex = /(\d+)\s+(year|years|month|months|day|days)/gi;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const count = Number.parseInt(match[1], 10);
    const unit = match[2].toLowerCase();
    if (unit.startsWith('year')) parts.push(formatLocalizedCount(count, 'unitYearOne', 'unitYearMany'));
    else if (unit.startsWith('month')) parts.push(formatLocalizedCount(count, 'unitMonthOne', 'unitMonthMany'));
    else if (unit.startsWith('day')) parts.push(formatLocalizedCount(count, 'unitDayOne', 'unitDayMany'));
  }

  return parts.length > 0 ? parts.join(', ') : source;
}

function localizeMxRecordText(text) {
  return String(text || '').replace(/\(Priority\s+(\d+)\)/gi, `(${t('mxPriorityLabel')} $1)`);
}

function localizeRiskSummary(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'clean') return t('riskClean');
  if (normalized === 'warning') return t('riskWarning');
  if (normalized === 'elevatedrisk') return t('riskElevated');
  return value || t('unknown');
}

function localizeWhoisStatus(status) {
  const normalized = String(status || '').trim().toLowerCase();
  if (!normalized) return '';
  if (normalized === 'expired') return t('expired');
  return status;
}

function getLocalizedSpfRequirementSummary(result) {
  if (!result || !result.spfPresent) return null;
  if (result.spfHasRequiredInclude === false) return t('spfOutlookRequirementMissing');
  if (result.spfHasRequiredInclude === true) return t('spfOutlookRequirementPresent');
  return null;
}

function stripSpfRequirementSection(text) {
  const source = String(text || '');
  if (!source) return '';
  return source.replace(/\r?\n\r?\nACS Outlook SPF requirement:\r?\n[\s\S]*$/i, '').trim();
}

function getLocalizedMxProviderHint(provider, fallbackHint) {
  switch (String(provider || '')) {
    case 'Microsoft 365 / Exchange Online': return t('providerHintMicrosoft365');
    case 'Google Workspace / Gmail': return t('providerHintGoogleWorkspace');
    case 'Cloudflare Email Routing': return t('providerHintCloudflare');
    case 'Proofpoint': return t('providerHintProofpoint');
    case 'Mimecast': return t('providerHintMimecast');
    case 'Zoho Mail': return t('providerHintZoho');
    case 'Unknown': return t('providerHintUnknown');
    default: return fallbackHint || '';
  }
}

function getDmarcSecurityGuidance(dmarcRecord, domain, lookupDomain, inherited) {
  const guidance = [];
  if (!dmarcRecord) return guidance;

  const tags = {};
  String(dmarcRecord).split(';').forEach(part => {
    const text = String(part || '').trim();
    if (!text) return;
    const idx = text.indexOf('=');
    if (idx < 1) return;
    const name = text.slice(0, idx).trim().toLowerCase();
    const value = text.slice(idx + 1).trim();
    if (name) tags[name] = value;
  });

  const targetDomain = domain || lookupDomain || 'the domain';
  const policy = (tags.p || '').trim().toLowerCase();
  const subdomainPolicy = (tags.sp || '').trim().toLowerCase();
  const pct = Number.parseInt((tags.pct || '').trim(), 10);
  const adkim = (tags.adkim || '').trim().toLowerCase();
  const aspf = (tags.aspf || '').trim().toLowerCase();
  const rua = (tags.rua || '').trim();
  const ruf = (tags.ruf || '').trim();

  if (policy === 'none') {
    guidance.push({ type: 'attention', text: t('dmarcMonitorOnly', { domain: targetDomain }) });
  } else if (policy === 'quarantine') {
    guidance.push({ type: 'attention', text: t('dmarcQuarantine', { domain: targetDomain }) });
  }

  if (Number.isFinite(pct) && pct >= 0 && pct < 100) {
    guidance.push({ type: 'attention', text: t('dmarcPct', { domain: targetDomain, pct }) });
  }

  if (adkim === 'r') {
    guidance.push({ type: 'info', text: t('dmarcAdkimRelaxed', { domain: targetDomain }) });
  }

  if (aspf === 'r') {
    guidance.push({ type: 'info', text: t('dmarcAspfRelaxed', { domain: targetDomain }) });
  }

  if (domain && lookupDomain && inherited === true && lookupDomain !== domain && !Object.prototype.hasOwnProperty.call(tags, 'sp')) {
    guidance.push({ type: 'attention', text: t('dmarcMissingSp', { lookupDomain, domain }) });
  }

  if (!rua) {
    guidance.push({ type: 'attention', text: t('dmarcMissingRua', { domain: targetDomain }) });
  }

  if (!ruf) {
    guidance.push({ type: 'info', text: t('dmarcMissingRuf', { domain: targetDomain }) });
  }

  return guidance;
}

function getDnsTxtRecoveryState(r) {
  const loaded = r && r._loaded ? r._loaded : {};
  const domain = String(r && r.domain || '').trim().toLowerCase();
  const detailedARecords = loaded.records && Array.isArray(r && r.dnsRecords)
    ? r.dnsRecords.filter(record => record
      && String(record.type || '').toUpperCase() === 'A'
      && String(record.name || '').trim().toLowerCase() === domain)
      .map(record => String(record.data || '').trim())
      .filter(Boolean)
    : [];
  const detailedAaaaRecords = loaded.records && Array.isArray(r && r.dnsRecords)
    ? r.dnsRecords.filter(record => record
      && String(record.type || '').toUpperCase() === 'AAAA'
      && String(record.name || '').trim().toLowerCase() === domain)
      .map(record => String(record.data || '').trim())
      .filter(Boolean)
    : [];
  const detailedTxtRecords = loaded.records && Array.isArray(r && r.dnsRecords)
    ? r.dnsRecords.filter(record => record
      && String(record.type || '').toUpperCase() === 'TXT'
      && String(record.name || '').trim().toLowerCase() === domain)
      .map(record => String(record.data || '').trim())
      .filter(Boolean)
    : [];
  const recoveredFromDetailedRecords = !!(loaded.base && r && r.dnsFailed && detailedTxtRecords.length > 0);
  const recoveredAddressesFromDetailedRecords = !!(loaded.records && (detailedARecords.length > 0 || detailedAaaaRecords.length > 0));
  const txtRecords = recoveredFromDetailedRecords
    ? detailedTxtRecords
    : (Array.isArray(r && r.txtRecords) ? r.txtRecords.filter(Boolean) : []);
  const ipv4Addresses = recoveredAddressesFromDetailedRecords
    ? detailedARecords
    : (Array.isArray(r && r.ipv4Addresses) ? r.ipv4Addresses.filter(Boolean) : []);
  const ipv6Addresses = recoveredAddressesFromDetailedRecords
    ? detailedAaaaRecords
    : (Array.isArray(r && r.ipv6Addresses) ? r.ipv6Addresses.filter(Boolean) : []);
  const spfValue = recoveredFromDetailedRecords
    ? (txtRecords.find(value => /^v=spf1/i.test(String(value || '').trim())) || null)
    : (r ? r.spfValue : null);
  const acsValue = recoveredFromDetailedRecords
    ? (txtRecords.find(value => /ms-domain-verification/i.test(String(value || '').trim())) || null)
    : (r ? r.acsValue : null);
  const spfHasRequiredInclude = recoveredFromDetailedRecords && spfValue
    ? /(^|\s)include:spf\.protection\.outlook\.com(?=\s|$)/i.test(String(spfValue || ''))
    : (r ? r.spfHasRequiredInclude : null);

  return {
    recoveredFromDetailedRecords,
    recoveredAddressesFromDetailedRecords,
    txtLookupResolved: !!(loaded.base && (!r.dnsFailed || recoveredFromDetailedRecords)),
    txtRecords,
    ipv4Addresses,
    ipv6Addresses,
    ipLookupDomain: recoveredAddressesFromDetailedRecords ? (r && r.domain) : (r ? r.ipLookupDomain : null),
    ipUsedParent: recoveredAddressesFromDetailedRecords ? false : !!(r && r.ipUsedParent),
    spfValue,
    spfPresent: !!spfValue,
    spfHasRequiredInclude,
    acsValue,
    acsPresent: !!acsValue
  };
}

function buildGuidance(r) {
  const guidance = [];
  const loaded = r && r._loaded ? r._loaded : {};
  const dmarcHelpUrl = 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records';
  const txtRecovery = getDnsTxtRecoveryState(r);
  const guidanceWorkflowComplete = ['base', 'mx', 'records', 'whois', 'dmarc', 'dkim', 'cname', 'reputation'].every(key => loaded[key] === true);

  // Only surface a terminal TXT lookup failure once the broader lookup workflow
  // has settled, and suppress it when the detailed DNS records payload already
  // proves TXT records were successfully collected.
  if (loaded.base && r.dnsFailed && guidanceWorkflowComplete && !txtRecovery.recoveredFromDetailedRecords) {
    guidance.push({ type: 'error', text: t('guidanceDnsTxtFailed') });
  }

  if (loaded.base && txtRecovery.txtLookupResolved) {
    if (!txtRecovery.spfPresent) {
      if (r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceSpfMissingParent', { domain: r.domain || '', lookupDomain: r.txtLookupDomain }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceSpfMissing') });
      }
    }
    if (txtRecovery.spfPresent && txtRecovery.spfHasRequiredInclude !== true) {
      guidance.push({ type: 'attention', text: t('spfOutlookRequirementMissing') });
    }
    if (!txtRecovery.acsPresent) {
      if (r.parentAcsPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceAcsMissingParent', { domain: r.domain || '', lookupDomain: r.txtLookupDomain }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceAcsMissing') });
      }
    }
  }

  if (loaded.mx) {
    const mxList = r.mxRecords || [];
    const hasMx = Array.isArray(mxList) && mxList.length > 0;
    if (!hasMx) {
      if (r.mxFallbackDomainChecked && r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceMxMissingParentFallback', { domain: r.domain || '', lookupDomain: r.mxLookupDomain }) });
      } else if (r.mxFallbackDomainChecked && !r.mxFallbackUsed) {
        guidance.push({ type: 'attention', text: t('guidanceMxMissingCheckedParent', { domain: r.domain || '', parentDomain: r.mxFallbackDomainChecked }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceMxMissing') });
      }
    } else if (r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
      guidance.push({ type: 'info', text: t('guidanceMxParentShown', { domain: r.domain || '', lookupDomain: r.mxLookupDomain }) });
    }
    if (r.mxProvider && r.mxProvider !== 'Unknown') {
      guidance.push({ type: 'info', text: t('guidanceMxProviderDetected', { provider: r.mxProvider }) });
    }
  }

  if (loaded.whois) {
    if (r.whoisIsExpired === true) {
      guidance.push({ type: 'attention', text: t('guidanceDomainExpired') });
    } else if (r.whoisIsVeryYoungDomain === true) {
      const d = r.whoisNewDomainErrorThresholdDays || 90;
      guidance.push({ type: 'attention', text: t('guidanceDomainVeryYoung', { days: String(d) }) });
    } else if (r.whoisIsYoungDomain === true) {
      const d = r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180;
      guidance.push({ type: 'attention', text: t('guidanceDomainYoung', { days: String(d) }) });
    }
  }

  if (loaded.dmarc && !r.dmarc) {
    guidance.push({ type: 'attention', text: t('guidanceDmarcMissing', { domain: r.domain || '' }) });
  } else if (loaded.dmarc && r.dmarc && r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain) {
    guidance.push({ type: 'info', text: t('guidanceDmarcInherited', { lookupDomain: r.dmarcLookupDomain }) });
  }

  let dmarcActionable = false;
  if (loaded.dmarc && r.dmarc) {
    const dmarcSecurityGuidance = getDmarcSecurityGuidance(r.dmarc, r.domain, r.dmarcLookupDomain, r.dmarcInherited === true);
    if (dmarcSecurityGuidance.length > 0) dmarcActionable = true;
    guidance.push(...dmarcSecurityGuidance);
  }

  if ((loaded.dmarc && !r.dmarc) || dmarcActionable) {
    guidance.push({ type: 'info', text: t('guidanceDmarcMoreInfo', { url: dmarcHelpUrl }) });
  }

  if (loaded.dkim) {
    if (!r.dkim1) guidance.push({ type: 'attention', text: t('guidanceDkim1Missing') });
    if (!r.dkim2) guidance.push({ type: 'attention', text: t('guidanceDkim2Missing') });
  }

  if (loaded.cname && !r.cname) {
    guidance.push({ type: 'attention', text: t('guidanceCnameMissing') });
  }

  if (loaded.base && loaded.mx && r.mxProvider === 'Microsoft 365 / Exchange Online' && txtRecovery.spfPresent && txtRecovery.spfHasRequiredInclude === false) {
    guidance.push({ type: 'attention', text: t('guidanceMxMicrosoftSpf') });
  }
  if (loaded.base && loaded.mx && r.mxProvider === 'Google Workspace / Gmail' && txtRecovery.spfPresent && txtRecovery.spfValue && !/_spf\.google\.com/i.test(txtRecovery.spfValue)) {
    guidance.push({ type: 'attention', text: t('guidanceMxGoogleSpf') });
  }
  if (loaded.base && loaded.mx && r.mxProvider === 'Zoho Mail' && txtRecovery.spfPresent && txtRecovery.spfValue && !/include:zoho\.com/i.test(txtRecovery.spfValue)) {
    guidance.push({ type: 'attention', text: t('guidanceMxZohoSpf') });
  }

  if (loaded.base && r.acsReady) {
    guidance.push({ type: 'success', text: t('acsReadyMessage') });
  }

  return guidance;
}

function recomputeDerived(r) {
  const loaded = r && r._loaded ? r._loaded : {};
  r._txtRecovery = getDnsTxtRecoveryState(r);
  if (loaded.base) {
    r.acsReady = r._txtRecovery.txtLookupResolved && !!r._txtRecovery.acsPresent;
  } else {
    r.acsReady = false;
  }
  r.guidance = buildGuidance(r);
}

function buildTestSummaryHtml(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};
  const txtRecovery = getDnsTxtRecoveryState(r);

  const classForState = (state) => {
    switch (state) {
      case "pass": return "tag-pass";
      case "warn": return "tag-warn";
      case "fail": return "tag-fail";
      case "error": return "tag-fail";
      case "pending": return "tag-info";
      case "optional": return "tag-info";
      case "unavailable": return "tag-info";
      default: return "tag-info";
    }
  };

  const checks = [];
  const add = (name, state, isOptional = false) => checks.push({ name, state, isOptional });

  // ACS Readiness (derived from base)
  if (!loaded.base && !errors.base) {
    add("ACS Readiness", "pending");
  } else if (errors.base) {
    add("ACS Readiness", "error");
  } else if (!txtRecovery.txtLookupResolved) {
    add("ACS Readiness", "fail");
  } else {
    add("ACS Readiness", r.acsReady ? "pass" : "fail");
  }

  // Domain (base lookup sanity)
  if (!loaded.base && !errors.base) {
    add("Domain", "pending");
  } else if (errors.base) {
    add("Domain", "error");
  } else {
    add("Domain", txtRecovery.txtLookupResolved ? "pass" : "fail");
  }

  // MX (placed directly below Domain per UI request)
  if (!loaded.mx && !errors.mx) {
    add("MX", "pending");
  } else if (errors.mx) {
    add("MX", "error");
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    add("MX", hasMx ? "pass" : "fail", true);
  }

  // SPF + ACS TXT + root TXT list depend on base
  if (!loaded.base && !errors.base) {
    add("SPF (queried domain TXT)", "pending");
    add("ACS TXT", "pending");
    add("TXT Records", "pending");
  } else if (errors.base) {
    add("SPF (queried domain TXT)", "error");
    add("ACS TXT", "error");
    add("TXT Records", "error");
  } else if (!txtRecovery.txtLookupResolved) {
    add("SPF (queried domain TXT)", "unavailable", true);
    add("ACS TXT", "fail");
    add("TXT Records", "unavailable", true);
  } else {
    add("SPF (queried domain TXT)", (txtRecovery.spfPresent && txtRecovery.spfHasRequiredInclude === true) ? "pass" : "fail", true);
    add("ACS TXT", txtRecovery.acsPresent ? "pass" : "fail");
    const hasTxt = Array.isArray(txtRecovery.txtRecords) && txtRecovery.txtRecords.length > 0;
    add("TXT Records", hasTxt ? "pass" : "fail", true);
  }

  // WHOIS / Registration age check
  // Not required for ACS verification, but a newly-registered domain can be a risk signal.
  // Show as WARN (implemented using the existing 'optional' styling) when domain age < threshold.
  if (!loaded.whois && !errors.whois) {
    add("Registration", "pending");
  } else if (errors.whois) {
    add("Registration", "error");
  } else {
    if (r.whoisIsVeryYoungDomain === true) {
      add("Registration", "fail", false);
    } else if (r.whoisIsYoungDomain === true) {
      add("Registration", "warn", false);
    } else {
      add("Registration", "pass", true);
    }
  }

  // DMARC
  if (!loaded.dmarc && !errors.dmarc) {
    add("DMARC", "pending");
  } else if (errors.dmarc) {
    add("DMARC", "error");
  } else {
    add("DMARC", r.dmarc ? "pass" : "fail", true);
  }

  // DKIM selectors
  if (!loaded.dkim && !errors.dkim) {
    add("DKIM1", "pending");
    add("DKIM2", "pending");
  } else if (errors.dkim) {
    add("DKIM1", "error");
    add("DKIM2", "error");
  } else {
    add("DKIM1", r.dkim1 ? "pass" : "fail", true);
    add("DKIM2", r.dkim2 ? "pass" : "fail", true);
  }

  // CNAME
  if (!loaded.cname && !errors.cname) {
    add("CNAME", "pending");
  } else if (errors.cname) {
    add("CNAME", "error");
  } else {
    add("CNAME", r.cname ? "pass" : "fail", true);
  }

  const pills = checks.map(c => {
    const name = escapeHtml(c.name);
    const status = escapeHtml(String(c.state === 'optional' && c.name === 'Registration' ? 'WARN' : c.state).toUpperCase());
    const optionalBadge = c.isOptional ? `<span class="tag ${classForState('optional')} status-pill">OPTIONAL</span>` : "";
    return `<div class="status-row"><span class="status-name">${name}</span><span class="status-pills">${optionalBadge}<span class="tag ${classForState(c.state)} status-pill">${status}</span></span></div>`;
  });

  return '';
}

function applyTheme(theme) {
  const root = document.documentElement;
  const btn  = document.getElementById("themeToggleBtn");
  if (theme === "dark") {
    root.classList.add("dark");
    if (btn) btn.innerHTML = renderLabelWithIcon('themeLight');
  } else {
    root.classList.remove("dark");
    if (btn) btn.innerHTML = renderLabelWithIcon('themeDark');
  }
  // Only persist theme preference if functional cookies are consented
  consentAwareSetItem("acsTheme", theme, 'functional');
}

function toggleTheme() {
  const isDark = document.documentElement.classList.contains("dark");
  applyTheme(isDark ? "light" : "dark");
}

// Avoid multiple info bubbles showing at once when buttons stay focused
function clearInfoDotFocus(except) {
  const dots = document.querySelectorAll('.info-dot');
  dots.forEach(btn => {
    if (btn === except) return;
    if (btn.matches(':focus')) {
      btn.blur();
    }
  });
}

document.addEventListener('focusin', (e) => {
  const btn = e.target && e.target.closest ? e.target.closest('.info-dot') : null;
  if (btn) {
    clearInfoDotFocus(btn);
  }
});

document.addEventListener('mouseenter', (e) => {
  const btn = e.target && e.target.closest ? e.target.closest('.info-dot') : null;
  if (btn) {
    clearInfoDotFocus(btn);
  }
}, true);

document.addEventListener('click', (e) => {
  const dropdown = document.getElementById('languageDropdown');
  if (!dropdown) return;
  if (!dropdown.contains(e.target)) {
    closeLanguageMenu();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeLanguageMenu();
  }
});

function copyShareLink() {
  const btn = document.getElementById("copyLinkBtn");
  if (!navigator.clipboard) {
    setStatus(t('clipboardUnavailable'));
    return;
  }

  const input = document.getElementById("domainInput");
  const domain = normalizeDomain(input ? input.value : "");
  const url = new URL(window.location.href);
  if (domain && isValidDomain(domain)) {
    url.searchParams.set("domain", domain);
  } else {
    url.searchParams.delete("domain");
  }
  url.searchParams.set(LANG_PARAM, currentLanguage);

  navigator.clipboard.writeText(url.toString())
    .then(() => {
      if (btn) {
        const original = btn.innerHTML;
        btn.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { btn.innerHTML = original; }, 2000);
      } else {
        setStatus(t('linkCopiedToClipboard'));
      }
    })
    .catch(() => setStatus(t('failedCopyLink')));
}

function copyText(text, btn) {
  const payload = text;
  const plain = (payload && typeof payload === 'object' && payload !== null)
    ? (payload.plain ?? payload.text ?? '')
    : ((payload === null || payload === undefined) ? "" : String(payload));
  const html = (payload && typeof payload === 'object' && payload !== null) ? payload.html : null;

  if (!navigator.clipboard) {
    setStatus(t('clipboardUnavailable'));
    return;
  }

  const writePlain = () => navigator.clipboard.writeText(plain);

  const writeRich = () => {
    if (!html || typeof ClipboardItem === 'undefined') return Promise.reject();
    const item = new ClipboardItem({
      'text/html': new Blob([html], { type: 'text/html' }),
      'text/plain': new Blob([plain], { type: 'text/plain' })
    });
    return navigator.clipboard.write([item]);
  };

  (html ? writeRich().catch(writePlain) : writePlain())
    .then(() => {
      if (btn && btn.tagName === "BUTTON") {
        const originalText = btn.innerHTML;
        btn.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      } else {
        setStatus(t('copiedToClipboard'));
      }
    })
    .catch(() => setStatus(t('failedCopyToClipboard')));
}

function copyField(btn, key) {
  // Support legacy call (key only)
  let button = btn;
  let fieldKey = key;
  if (typeof btn === 'string') {
     fieldKey = btn;
     button = null;
  }

  const el = document.getElementById("field-" + fieldKey);
  if (!el) {
    setStatus(t('nothingToCopyFor', { field: fieldKey }));
    return;
  }

  let text = el.innerText || el.textContent || "";

  // If MX additional details are open, include them in the copied text.
  if (fieldKey === "mx") {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails) {
      const display = (window.getComputedStyle ? getComputedStyle(mxDetails).display : mxDetails.style.display);
      if (display && display !== "none") {
        const detailsText = (mxDetails.innerText || mxDetails.textContent || "").trim();
        if (detailsText) {
          text = (String(text || "").trimEnd() + "\n\n--- Additional Details ---\n" + detailsText).trim();
        }
      }
    }
  }
  if (fieldKey === "whois") {
    const rawWhois = document.getElementById("whoisRawData");
    if (rawWhois) {
      const display = (window.getComputedStyle ? getComputedStyle(rawWhois).display : rawWhois.style.display);
      if (display && display !== "none") {
        const rawText = (rawWhois.innerText || rawWhois.textContent || "").trim();
        if (rawText) {
          text = (String(text || "").trimEnd() + "\n\n--- Raw WHOIS / RDAP Data ---\n" + rawText).trim();
        }
      }
    }
  }
  if (!navigator.clipboard) {
    setStatus(t('clipboardUnavailable'));
    return;
  }
  navigator.clipboard.writeText(text)
    .then(() => {
      if (button && button.tagName === "BUTTON") {
        const originalText = button.innerHTML;
        button.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
      } else {
        setStatus(t('copiedFieldToClipboard', { field: fieldKey }));
      }
    })
    .catch(() => setStatus(t('failedCopyFieldToClipboard', { field: fieldKey })));
}

function screenshotPage() {
  if (!window.html2canvas || !navigator.clipboard || typeof ClipboardItem === "undefined") {
    setStatus(t('screenshotClipboardUnsupported'));
    return;
  }

  const statusEl = document.getElementById("status");
  const previousStatusHtml = statusEl ? statusEl.innerHTML : "";
  const myToken = ++screenshotStatusToken;

  // Capture only the container div instead of the entire body
  const container = document.querySelector(".container");
  if (!container) {
    setStatus(t('screenshotContainerNotFound'));
    return;
  }

  html2canvas(container, {
    backgroundColor: getComputedStyle(document.body).backgroundColor,
    onclone: (clonedDoc) => {
      // Hide marked buttons in the cloned DOM only (prevents visible flashing)
      clonedDoc.body.classList.add("screenshot-mode");
    }
  }).then(canvas => {
    canvas.toBlob(blob => {
      if (!blob) {
        setStatus(t('screenshotCaptureFailed'));
        return;
      }
      const item = new ClipboardItem({ "image/png": blob });
      navigator.clipboard.write([item])
        .then(() => {
          setStatus(t('screenshotCopiedToClipboard'));
          setTimeout(() => {
            if (myToken !== screenshotStatusToken) return;
            const el = document.getElementById("status");
            if (el && el.innerHTML === t('screenshotCopiedToClipboard')) {
              el.innerHTML = previousStatusHtml;
            }
          }, 2500);
        })
        .catch(() => setStatus(t('failedCopyScreenshot')));
    });
  }).catch(() => {
    setStatus(t('screenshotRenderFailed'));
  });
}

function buildIssueUrl(domain) {
  const raw = (acsIssueUrl || '').trim();
  if (!raw || raw.startsWith('__')) return null;
  try {
    const url = new URL(raw, window.location.origin);
    if (domain) {
      url.searchParams.set('domain', domain);
    }
    url.searchParams.set('source', 'acs-domain-checker');
    if (appVersion && !appVersion.startsWith('__')) {
      url.searchParams.set('environment-version', appVersion);
    }
    return url.toString();
  } catch {
    return null;
  }
}

function reportIssue() {
  const domain = normalizeDomain((document.getElementById("domainInput") || {}).value || "");
  const targetUrl = buildIssueUrl(domain);
  if (!targetUrl) {
    setStatus(t('issueReportingNotConfigured'));
    return;
  }

  const detail = domain ? t('issueReportDetailDomain', { domain }) : t('issueReportDetailInput');
  const ok = window.confirm(t('issueReportConfirm', { detail }));
  if (!ok) return;

  window.open(targetUrl, '_blank', 'noopener');
}

'@
