import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const root = process.argv[2];
const core = readFileSync(join(root, 'src', '20d-HtmlJsCore.ps1'), 'utf8');
const utilities = readFileSync(join(root, 'src', '20c-HtmlJsUtilities.ps1'), 'utf8');
const translations = readFileSync(join(root, 'src', '20b-HtmlTranslations.ps1'), 'utf8');

function between(source, start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first);
  assert.ok(first >= 0 && last > first, `Missing source boundaries: ${start}`);
  return source.slice(first, last);
}

const messages = vm.runInNewContext(
  between(translations, 'const MULTI_DOMAIN_TRANSLATION_OVERRIDES =', '\nObject.keys(MULTI_DOMAIN_TRANSLATION_OVERRIDES)')
    + '\nMULTI_DOMAIN_TRANSLATION_OVERRIDES.en;'
);
const source = [
  between(utilities, 'function cancelInflightLookup()', 'function toggleClearBtn()'),
  between(core, 'const DEFAULT_LOOKUP_DOMAIN_LIMIT =', '// Compute the overall Email Quota verdict'),
  between(core, '// Run a sweep over multiple domains.', '// Parse the assembled results markup'),
  between(core, 'function getAllIntakeSendingDomains(', 'function renderExtractedIntakeTable('),
  between(core, 'function parseDomainListParam(', 'function startPageInitialization(')
].join('\n');

let checks = 0;
function check(name, condition) {
  assert.ok(condition, name);
  checks++;
  console.log(`  PASS  ${name}`);
}

const websites = count => Array.from({ length: count }, (_, i) => `site${i + 1}.example.com`);
const response = body => ({
  ok: true, status: 200, statusText: 'OK',
  json: async () => body,
  arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(body)).buffer,
  text: async () => JSON.stringify(body)
});

function harness({ signedIn = false, actionGate = null, actionError = false } = {}) {
  const elements = Object.fromEntries(
    ['domainInput', 'lookupBtn', 'screenshotBtn', 'downloadBtn', 'results']
      .map(id => [id, { value: '', style: {}, innerHTML: '', disabled: false }])
  );
  const actions = [];
  const requests = [];
  const context = vm.createContext({
    URL, AbortController, TextDecoder, TextEncoder, console,
    document: { getElementById: id => elements[id] || null },
    window: {
      location: { href: 'http://localhost/' },
      history: { replaceState() {} },
      matchMedia: () => ({ matches: true })
    },
    acsApiKey: 'synthetic-api-key',
    msAuthAccount: signedIn ? { username: 'external@example.com' } : null,
    lastAuthData: signedIn ? { isMicrosoftEmployee: false } : null,
    msalInstance: { acquireTokenSilent: async () => ({ accessToken: 'synthetic-graph-token' }) },
    msAuthInitialization: Promise.resolve(),
    lookupActionController: null,
    GRAPH_SCOPES: ['User.Read'],
    domainChipTokens: [],
    multiDomainState: { domains: [], results: {}, active: null, running: false },
    multiRunToken: 0,
    activeLookup: { runId: 0, controllers: [] },
    checkProgress: {},
    dnsRecordsFilterState: {},
    selectedDnsRecordKeys: new Set(),
    lastResult: null,
    lookupInProgress: false,
    currentLanguage: 'en',
    LANG_PARAM: 'lang',
    status: '',
    chipRenders: 0,
    t: (key, values = {}) => String(messages[key] || key).replace(/\{(\w+)\}/g, (_, name) => values[name] ?? name),
    escapeHtml: text => String(text),
    setStatus(text) { context.status = text; },
    buildConsentRequestHeaders: headers => ({ ...headers, 'X-ACS-Analytics-Consent': '0' }),
    toggleClearBtn() {},
    updateDomainTabsUI() {},
    updatePageTitle() {},
    beginSectionAnimationCycle() {},
    recomputeDerived() {},
    render() {},
    rememberEndpointFields() {},
    saveHistory() {},
    markCheckProgress() {},
    setCheckProgressActive() {},
    repairObjectStrings: value => value,
    buildSpfOverrideQuery: () => '',
    buildDkimOverrideQuery: () => '',
    buildPropagationQuery: () => '',
    async fetch(path, options) {
      if (path.startsWith('/api/lookup-action?')) {
        actions.push({ path, options });
        if (actionGate) await actionGate;
        if (actionError) throw new Error('Synthetic admission failure');
        const count = Number(new URL(path, 'http://localhost').searchParams.get('count'));
        return response({ actionId: actions.length.toString(16).padStart(32, '0'), websiteCount: count });
      }
      const domain = new URL(path, 'http://localhost').searchParams.get('domain');
      requests.push({ path, options, domain });
      return response({ domain, records: [] });
    }
  });
  vm.runInContext(source, context);
  const renderChips = context.renderDomainChips;
  context.renderDomainChips = () => { context.chipRenders++; renderChips(); };
  return { context, elements, actions, requests };
}

async function addressBar(count, signedIn, accepted) {
  const h = harness({ signedIn });
  if (count === 1) {
    h.elements.domainInput.value = websites(count)[0];
  } else {
    h.context.handleDomainInputPaste({
      target: h.elements.domainInput,
      clipboardData: { getData: () => websites(count).join(', ') },
      preventDefault() {}
    });
  }
  check(`address bar preserves all ${count} entered websites`, h.context.getEnteredDomains().length === count);
  if (count > 1) check(`pasting ${count} websites repaints chips only once`, h.context.chipRenders === 1);
  const result = await h.context.runLookupFromInput();
  check(`${signedIn ? 'signed-in' : 'anonymous'} address bar ${count} boundary`, (result === true) === accepted);
  if (accepted) {
    check(`${count} websites issue exactly 11 checks each`, h.requests.length === count * 11);
    check(`${count} websites share one processing action`, h.actions.length === 1
      && new Set(h.requests.map(r => r.options.headers['X-ACS-Lookup-Action'])).size === 1
      && h.requests.every(r => /^[a-f0-9]{32}$/.test(r.options.headers['X-ACS-Lookup-Action'])));
    check(`${count} website checks complete without task errors`,
      count === 1 ? Object.keys(h.context.lastResult._errors).length === 0
        : Object.keys(h.context.multiDomainState.results).length === count
          && Object.values(h.context.multiDomainState.results).every(r => Object.keys(r._errors).length === 0));
    check('Graph token is never attached to individual website checks',
      h.requests.every(r => !r.options.headers.Authorization));
    check('API key is preserved on admission and website checks',
      [...h.actions, ...h.requests].every(r => r.options.headers['X-Api-Key'] === 'synthetic-api-key'));
    if (count > 100) {
      check('elevated admission sends the MSAL token for server verification',
        h.actions[0].options.headers.Authorization === 'Bearer synthetic-graph-token');
    }
  } else {
    check('oversized address-bar action starts no HTTP requests', h.actions.length === 0 && h.requests.length === 0);
    check('oversized action reports its actual count and limit',
      h.context.status.includes(String(count)) && h.context.status.includes(signedIn ? '1000' : '100'));
  }
  return h;
}

console.log('=== Browser Lookup Action Limits (actual source, offline) ===');
await addressBar(1, false, true);
await addressBar(100, false, true);
await addressBar(101, false, false);
const signed = await addressBar(1000, true, true);
await addressBar(1001, true, false);

for (const [count, signedIn, accepted] of [[100, false, true], [101, false, false], [1000, true, true], [1001, true, false]]) {
  const h = harness({ signedIn });
  const status = { textContent: 'Extracted fields.' };
  await h.context.maybeRunCheckerForIntakeDomain(websites(count).join('; '), status);
  check(`intake ${count}/${signedIn ? 1000 : 100} boundary`, h.requests.length === (accepted ? count * 11 : 0));
  check('intake does not truncate website extraction', h.context.getAllIntakeSendingDomains(websites(count).join(' ')).length === count);
  if (!accepted) check('intake keeps its explicit limit error', status.textContent.includes(String(count)));
}

const links = harness();
const parsed = links.context.parseDomainListParam(websites(101).join(' '));
check('shared links are not silently truncated', parsed.length === 101);
await links.context.runMultiDomainLookup(parsed);
check('shared links use the same anonymous boundary', links.actions.length === 0 && links.requests.length === 0);
check('normalization deduplicates URLs, uppercase domains and email addresses',
  links.context.parseDomainListParam('EXAMPLE.com https://example.com/a user@example.com').length === 1);
check('intake deduplicates repeated websites',
  links.context.getAllIntakeSendingDomains('EXAMPLE.com, example.com; example.com').length === 1);

signed.context.msAuthAccount = null;
signed.context.lastAuthData = null;
check('sign-out immediately restores the 100-website limit', signed.context.getLookupDomainLimit() === 100);
const beforeSignOut = signed.requests.length;
await signed.context.runMultiDomainLookup(websites(101));
check('a previously signed-in session cannot start an elevated action after sign-out', signed.requests.length === beforeSignOut);
signed.context.msAuthAccount = { username: 'cached@example.com' };
check('a cached account without confirmed sign-in does not unlock 1000', signed.context.getLookupDomainLimit() === 100);

const restored = harness();
let restoreAuth;
restored.context.msAuthInitialization = new Promise(resolve => { restoreAuth = resolve; });
const waiting = restored.context.runMultiDomainLookup(websites(1000));
check('large bootstrap waits for sign-in restoration', restored.actions.length === 0);
restored.context.msAuthAccount = { username: 'restored@example.com' };
restored.context.lastAuthData = {};
restoreAuth();
await waiting;
check('restored sign-in admits all 1000 websites', restored.requests.length === 11000);

let release;
const gate = new Promise(resolve => { release = resolve; });
const superseded = harness({ actionGate: gate });
const older = superseded.context.runMultiDomainLookup(websites(100));
const newer = superseded.context.runMultiDomainLookup(websites(2));
release();
await Promise.all([older, newer]);
check('a superseded admission cannot restart an older sweep', superseded.requests.length === 22);

let releaseClear;
const clearing = harness({ actionGate: new Promise(resolve => { releaseClear = resolve; }) });
const pendingClear = clearing.context.runMultiDomainLookup(websites(100));
clearing.context.resetMultiDomainState('');
releaseClear();
await pendingClear;
check('clearing the input cancels pending admission', clearing.requests.length === 0);

const failed = harness({ actionError: true });
await failed.context.runMultiDomainLookup(websites(2));
check('admission failures are visible and never start website checks',
  failed.requests.length === 0 && failed.context.status.includes('Synthetic admission failure'));

console.log(`PASS: ${checks} browser lookup limit checks passed.`);
