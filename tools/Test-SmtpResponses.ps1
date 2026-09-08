# Runs the actual browser parser with Node.js, without network access or a DOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFile = Join-Path $repoRoot 'src/20h-HtmlSmtpResponses.ps1'
$source = Get-Content $sourceFile -Raw
$scriptMatch = [regex]::Match($source, '(?s)<script nonce="__CSP_NONCE__">(.*?)</script>')
if (-not $scriptMatch.Success) {
    throw 'Could not isolate the SMTP response JavaScript.'
}

$translationSource = Get-Content (Join-Path $repoRoot 'src/20b-HtmlTranslations.ps1') -Raw
$translationMatch = [regex]::Match($translationSource, '(?s)const SMTP_RESPONSE_TRANSLATION_OVERRIDES = .*?(?=const LANG_PARAM)')
if (-not $translationMatch.Success) {
    throw 'Could not isolate SMTP response translations.'
}
if ($translationMatch.Value -match '[^\x00-\x7F]') {
  throw 'SMTP translation strings must use Unicode escapes for Windows PowerShell 5.1 compatibility.'
}
$javascript = 'const document = { addEventListener() {} };' + "`n" +
  'const TRANSLATIONS = {};' + "`n" + $translationMatch.Value + "`n" +
  'const smtpTranslations = TRANSLATIONS;' + "`n" +
    $scriptMatch.Groups[1].Value + @'

let currentLanguage = 'en';
function t(key, values = {}) {
  return (smtpTranslations[currentLanguage]?.[key] || smtpTranslations.en[key] || key).replace(/\{(\w+)\}/g, (_, name) => String(values[name]));
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

const assert = require('node:assert/strict');
const smtpLocales = ['en', 'es', 'fr', 'de', 'pt-BR', 'ar', 'zh-CN', 'hi-IN', 'ja-JP', 'ru-RU'];
let checks = 0;
function check(name, action) {
  action();
  checks++;
  console.log('  PASS  ' + name);
}
check('paired SMTP and enhanced response', () => {
  assert.deepEqual(parseSmtpResponses('550 5.1.1 User unknown').responses,
    [{ smtpCode: '550', enhancedCode: '5.1.1', classMismatch: false }]);
});
check('standalone SMTP response', () => {
  assert.equal(parseSmtpResponses('421').responses[0].smtpCode, '421');
});
check('standalone enhanced response', () => {
  assert.equal(parseSmtpResponses('5.7.26').responses[0].enhancedCode, '5.7.26');
});
check('DSN status and diagnostic fields', () => {
  const result = parseSmtpResponses('Status: 5.2.2\r\nDiagnostic-Code: smtp; 552 5.2.2 Mailbox full');
  assert.equal(result.responses.length, 2);
  assert.equal(result.responses[1].smtpCode, '552');
});
check('multiline replies are deduplicated by code pair', () => {
  const result = parseSmtpResponses('550-5.7.1 Blocked\n550 5.7.1 Contact administrator\n250 2.0.0 OK');
  assert.equal(result.responses.length, 2);
  assert.equal(result.responses[1].enhancedCode, '2.0.0');
});
check('temporary and permanent class conflicts remain visible', () => {
  assert.equal(parseSmtpResponses('450 5.1.1 User unknown').responses[0].classMismatch, true);
});
check('SMTP conversation prefixes', () => {
  assert.equal(parseSmtpResponses('S: 354 Start mail input').responses[0].smtpCode, '354');
  assert.equal(parseSmtpResponses('SMTP response: 535 5.7.8 Invalid credentials').responses[0].enhancedCode, '5.7.8');
});
check('quoted nondelivery report and application error replies', () => {
  assert.equal(parseSmtpResponses("Remote server returned '550 5.1.10 Recipient not found'").responses[0].enhancedCode, '5.1.10');
  assert.equal(parseSmtpResponses('The server response was: 5.7.57 Client was not authenticated').responses[0].enhancedCode, '5.7.57');
  assert.equal(parseSmtpResponses('Error: 550 5.1.1 User unknown').responses[0].smtpCode, '550');
});
check('IPs, dates, domains, addresses and prose are not response codes', () => {
  for (const value of ['192.168.1.1', '5.7.26.1', '2026-09-08', '550.example.com',
    '550@example.com', 'Quota is 550 messages', 'HTTP/1.1 500 Internal Server Error']) {
    assert.equal(parseSmtpResponses(value).responses.length, 0, value);
  }
});
check('malformed enhanced codes are not partially decoded', () => {
  for (const value of ['5.1234.1', '5.1.1234', '5.1.1x', '3.1.1', '5.7']) {
    assert.equal(parseSmtpResponses(value).responses.length, 0, value);
  }
});
check('unknown but well-formed codes are retained for generic guidance', () => {
  assert.equal(parseSmtpResponses('559 5.9.999 Unassigned code').responses[0].enhancedCode, '5.9.999');
});
check('empty and unrecognized input', () => {
  assert.equal(parseSmtpResponses('').responses.length, 0);
  assert.equal(parseSmtpResponses('not a response').responses.length, 0);
});
check('pasted text is bounded', () => {
  assert.equal(parseSmtpResponses('550 5.1.1 ' + 'x'.repeat(17000)).truncated, true);
});
check('result count is bounded', () => {
  const input = Array.from({ length: 60 }, (_, index) => '5.9.' + index).join('\n');
  const result = parseSmtpResponses(input);
  assert.equal(result.responses.length, 50);
  assert.equal(result.truncated, true);
});
const decode = value => getSmtpResponseDetails(parseSmtpResponses(value).responses[0]);
check('enhanced detail takes precedence without losing the basic reply', () => {
  const result = decode('550 5.7.23 SPF validation failed');
  assert.equal(result.meaning, 'SPF validation failed');
  assert.equal(result.smtpMeaning, 'Mailbox unavailable or action rejected');
  assert.equal(result.statusClass, '5');
});
check('temporary and permanent mailbox replies keep their actual class', () => {
  assert.equal(decode('452 4.2.2 Mailbox full').statusClass, '4');
  assert.equal(decode('552 5.2.2 Mailbox full').statusClass, '5');
});
check('mismatched codes never produce a success classification', () => {
  assert.equal(decode('250 5.1.1 User unknown').statusClass, 'mismatch');
});
check('success and intermediate replies are not delivery failures', () => {
  assert.equal(decode('250 2.0.0 OK').statusClass, '2');
  assert.equal(decode('354').statusClass, '3');
  assert.match(decode('250').fix, /does not guarantee inbox/);
});
check('unknown codes and unusual success details remain generic', () => {
  assert.equal(decode('559 5.9.999').known, false);
  assert.equal(decode('2.1.1').known, false);
  assert.doesNotMatch(decode('2.1.1').meaning, /not found/);
});
check('provider-specific usages are explicitly attributed', () => {
  assert.equal(decode('5.7.57').source, 'exchange');
  assert.equal(decode('5.7.520').source, 'exchange');
  assert.match(decode('5.1.10').causes, /standard meaning.*null|standard meaning.*not accept/i);
  assert.match(decode('5.1.10').causes, /Exchange Online/);
});
check('all reference rows have valid codes, guidance and trusted sources', () => {
  const rows = getSmtpResponseReference();
  assert.ok(rows.length > 100);
  for (const row of rows) {
    assert.equal(parseSmtpResponses(row.smtpCode || row.enhancedCode).responses.length, 1);
    assert.ok(row.meaning && row.causes && row.fix);
    assert.ok(SMTP_RESPONSE_SOURCES[row.source].url.startsWith('https://'));
    assert.notEqual(row.statusClass, 'mismatch');
  }
});
check('reference search combines words and status filters', () => {
  assert.ok(filterSmtpResponseReference('SPF', '5').some(row => row.enhancedCode === '5.7.23'));
  assert.ok(filterSmtpResponseReference('SPF', '4').every(row => row.statusClass === '4'));
  assert.equal(filterSmtpResponseReference('nonexistent entry xyz', '').length, 0);
  assert.equal(filterSmtpResponseReference('5.7.520', '')[0].source, 'exchange');
});
check('table shows both supplied codes and the conflict warning', () => {
  const html = buildSmtpResponseTableRows([decode('250 5.1.1')]);
  assert.match(html, /<code>250<\/code>/);
  assert.match(html, /<code>5\.1\.1<\/code>/);
  assert.match(html, /Conflicting classes/);
  assert.match(html, /classes disagree/);
  assert.doesNotMatch(html, /tag-pass/);
});
check('pasted markup and private response text never enter the table or copy', () => {
  const rows = parseSmtpResponses('550 5.1.1 <img src=x onerror=alert(1)> private@example.com').responses.map(getSmtpResponseDetails);
  const html = buildSmtpResponseTableRows(rows);
  const copied = formatSmtpResponseCopy(rows);
  assert.doesNotMatch(html + copied, /onerror|private@example/);
  assert.match(copied, /550\t5\.1\.1/);
  assert.match(copied, /Correct the reported cause/);
});
check('rendered guidance is HTML escaped', () => {
  const row = { ...decode('550'), meaning: '<img src=x>', causes: '<script>bad</script>' };
  const html = buildSmtpResponseTableRows([row]);
  assert.match(html, /&lt;img src=x&gt;/);
  assert.doesNotMatch(html, /<script>|<img/);
});
check('all supported locales have localized lookup controls', () => {
  for (const locale of smtpLocales) {
    for (const key of ['smtpToolTitle', 'smtpOpenLookup', 'smtpLookupTitle', 'smtpModeLookup', 'smtpModeReference', 'smtpAnalyze', 'smtpClear', 'smtpCopy', 'smtpClose']) {
      assert.ok(smtpTranslations[locale][key], locale + ': ' + key);
    }
  }
});
check('all guidance and state labels are explicitly translated with intact placeholders', () => {
  for (const locale of smtpLocales.filter(language => language !== 'en')) {
    for (const [key, english] of Object.entries(SMTP_RESPONSE_TRANSLATION_OVERRIDES.en)) {
      if (key === 'smtpColumnBasic') continue;
      const localized = SMTP_RESPONSE_TRANSLATION_OVERRIDES[locale][key];
      assert.ok(typeof localized === 'string' && localized.trim(), locale + ': missing ' + key);
      if (english.length > 30) assert.notEqual(localized, english, locale + ': English ' + key);
      assert.deepEqual((localized.match(/\{\w+\}/g) || []).sort(), (english.match(/\{\w+\}/g) || []).sort(), locale + ': placeholders in ' + key);
    }
  }
});
check('each translated catalog covers every basic, enhanced and provider entry', () => {
  const entries = new Map([...SMTP_BASIC_RESPONSES.values(), ...SMTP_ENHANCED_RESPONSES.values(), ...SMTP_PROVIDER_RESPONSES.values()]
    .map(entry => [entry.translationKey, entry]));
  assert.deepEqual(Object.keys(SMTP_RESPONSE_CATALOG_TRANSLATIONS).sort(), smtpLocales.filter(language => language !== 'en').sort());
  for (const [language, catalog] of Object.entries(SMTP_RESPONSE_CATALOG_TRANSLATIONS)) {
    assert.deepEqual(Object.keys(catalog).sort(), [...entries.keys()].sort(), language + ': catalog keys');
    for (const [key, entry] of entries) {
      assert.equal(catalog[key].length, 3, language + ': ' + key);
      for (const field of ['meaning', 'causes', 'fix']) {
        const translation = smtpTranslations[language][key + field[0].toUpperCase() + field.slice(1)];
        assert.ok(typeof translation === 'string' && translation.trim(), language + ': ' + key + ' ' + field);
        assert.notEqual(translation, entry[field], language + ': English fallback in ' + key + ' ' + field);
      }
    }
  }
});
check('Spanish selected language localizes the complete decoded row and copy', () => {
  const english = decode('550 5.1.1 Recipient not found');
  currentLanguage = 'es';
  try {
    const localized = decode('550 5.1.1 Recipient not found');
    for (const field of ['meaning', 'causes', 'fix', 'smtpMeaning']) {
      assert.notEqual(localized[field], english[field], field + ' stayed English');
    }
    const html = buildSmtpResponseTableRows([localized]);
    const copied = formatSmtpResponseCopy([localized]);
    assert.match(localized.meaning, /destinatario/i);
    assert.doesNotMatch(html, /lang="en"/);
    assert.doesNotMatch(html + copied, /Recipient mailbox not found|Correct the reported cause/);
  } finally { currentLanguage = 'en'; }
});
check('accents and non-Latin scripts survive source extraction', () => {
  assert.equal(smtpTranslations.es['smtpEnhanced1.1Meaning'], 'No se encuentra el buz\u00f3n del destinatario');
  assert.match(smtpTranslations['ja-JP']['smtpEnhanced1.1Meaning'], /\u53d7\u4fe1\u8005/);
  assert.match(smtpTranslations.ar['smtpEnhanced1.1Meaning'], /\u0635\u0646\u062f\u0648\u0642/);
  assert.match(smtpTranslations['hi-IN']['smtpEnhanced1.1Meaning'], /\u092a\u094d\u0930\u093e/);
  assert.match(smtpTranslations['ru-RU']['smtpEnhanced1.1Meaning'], /\u042f\u0449\u0438\u043a/);
});
check('language changes localize rows and copy without changing protocol results', () => {
  const samples = ['550 5.1.1', '421', '354', '250 2.0.0', '250 5.1.1', '559 5.9.999', '2.1.1', '5.7.57', '452 4.2.2'];
  const englishRows = samples.map(decode);
  try {
    for (const locale of smtpLocales.filter(language => language !== 'en')) {
      currentLanguage = locale;
      for (const [index, sample] of samples.entries()) {
        const row = decode(sample);
        const english = englishRows[index];
        for (const field of ['smtpCode', 'enhancedCode', 'classMismatch', 'statusClass', 'known', 'source']) {
          assert.equal(row[field], english[field], locale + ': changed ' + field + ' for ' + sample);
        }
        const html = buildSmtpResponseTableRows([row]);
        const copied = formatSmtpResponseCopy([row]);
        for (const field of ['meaning', 'causes', 'fix']) {
          assert.notEqual(row[field], english[field], locale + ': English ' + field + ' for ' + sample);
          assert.ok(html.includes(escapeHtml(row[field])) && copied.includes(row[field]), locale + ': missing ' + field);
        }
        if (english.smtpMeaning) assert.notEqual(row.smtpMeaning, english.smtpMeaning, locale + ': basic meaning');
        const status = SMTP_RESPONSE_STATUS[row.statusClass];
        assert.ok(html.includes(escapeHtml(t(status.advice))) && copied.includes(t(status.advice)), locale + ': retry advice');
        assert.ok(html.includes(escapeHtml(t(status.label))) && copied.includes(t(status.label)), locale + ': status label');
        assert.doesNotMatch(html, /lang="en"/);
        assert.doesNotMatch(html + copied, /\{subject\}|smtpUnknown|smtpAdvice|smtpStatus/);
      }
    }
  } finally { currentLanguage = 'en'; }
  assert.deepEqual(samples.map(decode), englishRows);
});
check('localized reference search and language switching preserve the canonical catalog', () => {
  const englishRows = getSmtpResponseReference();
  try {
    for (const locale of smtpLocales.filter(language => language !== 'en')) {
      currentLanguage = locale;
      const rows = getSmtpResponseReference();
      assert.equal(rows.length, englishRows.length);
      for (const [index, row] of rows.entries()) {
        const english = englishRows[index];
        for (const field of ['smtpCode', 'enhancedCode', 'statusClass', 'source']) assert.equal(row[field], english[field]);
        for (const field of ['meaning', 'causes', 'fix']) assert.notEqual(row[field], english[field], locale + ': ' + field);
      }
      for (const code of ['5.1.1', '5.7.57']) {
        const meaning = decode(code).meaning;
        assert.ok(filterSmtpResponseReference(meaning, '5').some(row => row.enhancedCode === code), locale + ': search ' + code);
        assert.ok(filterSmtpResponseReference(meaning, '4').every(row => row.statusClass === '4'));
      }
    }
  } finally { currentLanguage = 'en'; }
  assert.deepEqual(getSmtpResponseReference(), englishRows);
});
check('future catalog entries retain a readable English fallback', () => {
  const entry = { translationKey: 'smtpFutureEntry', meaning: 'Future meaning', causes: 'Future cause', fix: 'Future remedy', source: 'smtp' };
  currentLanguage = 'es';
  try {
    const localized = localizeSmtpResponseEntry(entry);
    assert.deepEqual(localized, entry);
    assert.notEqual(localized, entry);
  } finally { currentLanguage = 'en'; }
});
console.log('\nPASS: ' + checks + ' SMTP response checks passed.');
'@

$tempFile = Join-Path ([IO.Path]::GetTempPath()) ("acs-smtp-responses-{0}.js" -f [Guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($tempFile, $javascript, [Text.UTF8Encoding]::new($false))
    & node $tempFile
    if ($LASTEXITCODE -ne 0) {
        throw 'SMTP response validation failed.'
    }
} finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}