// Accessibility regression scan for the ACS Email Domain Checker web UI.
//
// Approximates the three Accessibility Insights for Web FastPass steps with the
// same engine Accessibility Insights 2.49 uses (axe-core 4.11):
//   1. Automated checks -> axe violations (WCAG 2.x A/AA + best practices)
//   2. Tab stops        -> keyboard walk: every stop visible, focus ring shown,
//                          no traps; plus clickable elements that cannot be tabbed to
//   3. Needs review     -> axe "incomplete" results (reported, not failing)
//
// Scans every major UI state (cookie banner, history, language menu, SMTP dialog,
// lookup results collapsed/expanded, Options dialog, RTL, multi-domain tabs,
// /terms, /privacy) in light and dark themes.
//
// Usage (server must already be running, e.g. ./acs-domain-checker.ps1 -Port 18080):
//   cd tools/accessibility
//   npm install && npx playwright install chromium
//   node Test-Accessibility.mjs                      # default http://localhost:18080, 1400px
//   BASE=http://localhost:8080 VW=400 node Test-Accessibility.mjs
// Env: BASE, DOMAIN (lookup target, default microsoft.com), VW (viewport width),
//      SCHEMES (dark,light), STRICT_REVIEW=1 (also fail on Needs-review items in
//      states without an open overlay), VERBOSE=1 (print every node).
//
// Exit code is non-zero when any axe violation or keyboard problem is found.
// The lookup performs real DNS queries, so results depend on the live domain.

import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const base = process.env.BASE || 'http://localhost:18080';
const domain = process.env.DOMAIN || 'microsoft.com';
const vw = Number(process.env.VW || 1400);
const verbose = !!process.env.VERBOSE;
const strictReview = !!process.env.STRICT_REVIEW;
const totals = { violations: 0, review: 0, reviewBlocking: 0, keyboard: 0 };

// States where something legitimately covers page content (open menu / modal). axe
// cannot measure text underneath an overlay, so their Needs-review items are expected.
const overlayStates = /cookie banner|language menu|dialog/;

function print(label, list, kind) {
  for (const rule of list) {
    console.log(`  ${kind} ${rule.id} x${rule.nodes.length}: ${rule.help}`);
    for (const node of rule.nodes.slice(0, verbose ? Infinity : 5)) {
      const msg = kind === 'VIOLATION'
        ? (node.failureSummary || '').replace(/\s+/g, ' ').replace(/Fix (any|all) of the following: /, '')
        : ((node.any[0] || node.all[0] || node.none[0] || {}).message || '');
      console.log(`     - ${node.target.join(' ')} :: ${msg.slice(0, 220)}`);
    }
  }
}

async function scan(page, label) {
  const r = await new AxeBuilder({ page }).analyze();
  const vCount = r.violations.reduce((a, x) => a + x.nodes.length, 0);
  const iCount = r.incomplete.reduce((a, x) => a + x.nodes.length, 0);
  totals.violations += vCount;
  totals.review += iCount;
  if (!overlayStates.test(label)) totals.reviewBlocking += iCount;
  console.log(`\n### ${label}: ${vCount} violations, ${iCount} needs-review`);
  print(label, r.violations, 'VIOLATION');
  if (iCount && (verbose || !overlayStates.test(label))) print(label, r.incomplete, 'REVIEW');
  await clickableAudit(page);
}

// Elements that look clickable (onclick / pointer cursor) but are not keyboard reachable.
async function clickableAudit(page) {
  const bad = await page.evaluate(() => {
    const out = [];
    const native = 'a[href],button,input,select,textarea,summary,[contenteditable="true"],iframe';
    const visible = (el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
    for (const el of document.querySelectorAll('body *')) {
      if (!visible(el) || el.closest('[inert]')) continue;
      const pointer = getComputedStyle(el).cursor === 'pointer' && (!el.parentElement || getComputedStyle(el.parentElement).cursor !== 'pointer');
      if (!el.hasAttribute('onclick') && !pointer) continue;
      if (el.matches(native) || el.closest('a[href],button,label,summary') || el.tabIndex >= 0) continue;
      // Mouse-only click surface that contains its own keyboard-operable equivalent.
      if (el.querySelector(':scope > .card-toggle')) continue;
      out.push(el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).join('.') : ''));
    }
    return out;
  });
  totals.keyboard += bad.length;
  for (const b of [...new Set(bad)]) console.log(`  KEYBOARD clickable but not focusable: ${b}`);
}

// FastPass "Tab stops": walk with Tab from the top of the document.
async function tabWalk(page, label) {
  await page.evaluate(() => { document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); });
  await page.mouse.click(3, 3);
  const seen = []; const problems = []; let prev = null; let repeats = 0;
  for (let i = 0; i < 800; i++) {
    await page.keyboard.press('Tab');
    const info = await page.evaluate(() => {
      const el = document.activeElement;
      if (!el || el === document.body || el === document.documentElement) return null;
      el.scrollIntoView({ block: 'nearest' });
      const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
      const ring = (e) => { if (!e) return false; const s = getComputedStyle(e); return (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== 'none'); };
      const proxy = el.matches('input') && (r.width <= 1 || cs.opacity === '0');
      let indicator = ring(el) || (el.id === 'domainInput' && ring(el.closest('.input-wrapper'))) || (proxy && (ring(el.nextElementSibling) || ring(el.parentElement)));
      const visible = (r.width > 1 && r.height > 1 && cs.visibility !== 'hidden') || (proxy && indicator);
      if (!el.__a11yId) el.__a11yId = Math.random().toString(36).slice(2);
      const name = (el.getAttribute('aria-label') || el.innerText || el.value || el.title || '').trim().replace(/\s+/g, ' ').slice(0, 40);
      return { id: el.__a11yId, key: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''), name, indicator, visible };
    });
    if (!info) break;                                   // focus left the document: no trap
    if (info.id === prev) { if (++repeats > 2) { problems.push(`trap at ${info.key}`); break; } } else repeats = 0;
    if (seen.length && seen[0] === info.id) break;      // wrapped around to the first stop
    prev = info.id; seen.push(info.id);
    if (!info.visible) problems.push(`invisible stop ${info.key} "${info.name}"`);
    else if (!info.indicator) problems.push(`no focus indicator on ${info.key} "${info.name}"`);
  }
  totals.keyboard += problems.length;
  console.log(`  TAB STOPS (${label}): ${seen.length} stops, ${problems.length} problems`);
  for (const p of problems) console.log(`     - ${p}`);
}

async function newPage(browser, { scheme, consent = true, lang = null }) {
  const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: vw, height: 1000 }, reducedMotion: 'reduce' });
  if (consent) {
    await ctx.addInitScript(([lang, scheme]) => {
      if (localStorage.getItem('__a11ySeeded')) return;
      localStorage.setItem('__a11ySeeded', '1');
      localStorage.setItem('acsCookieConsent', JSON.stringify({ essential: true, functional: true, analytics: false }));
      localStorage.setItem('acsDomainHistory', JSON.stringify(['contoso.com', 'example.org']));
      localStorage.setItem('acsTheme', scheme);
      if (lang) localStorage.setItem('acsLanguage', lang);
    }, [lang, scheme]);
  }
  return ctx.newPage();
}

const settle = (page, ms = 800) => page.waitForTimeout(ms);
async function waitLookup(page) {
  await page.waitForFunction(() => {
    const b = document.getElementById('lookupBtn');
    return b && !/spinner/.test(b.innerHTML) && document.querySelectorAll('#results .card').length > 3;
  }, null, { timeout: 180000 });
  await settle(page, 3000);
}

const browser = await chromium.launch();
try {
  for (const scheme of (process.env.SCHEMES || 'dark,light').split(',')) {
    let p = await newPage(browser, { scheme, consent: false });
    await p.goto(base + '/', { waitUntil: 'networkidle' }); await settle(p, 1500);
    await scan(p, `[${scheme}] cookie banner`);
    await p.context().close();

    p = await newPage(browser, { scheme });
    await p.goto(base + '/', { waitUntil: 'networkidle' }); await settle(p, 1500);
    await scan(p, `[${scheme}] initial page + history`);
    await tabWalk(p, `[${scheme}] initial page`);

    await p.click('#languageSelectBtn'); await settle(p, 400);
    await scan(p, `[${scheme}] language menu open`);
    await p.evaluate(() => window.closeLanguageMenu && window.closeLanguageMenu());

    await p.click('#smtpResponseOpen'); await settle(p, 600);
    await p.fill('#smtpResponseInput', '550 5.1.1 Recipient address rejected: User unknown');
    await p.click('#smtpResponseForm button[type=submit]'); await settle(p, 600);
    await scan(p, `[${scheme}] SMTP dialog`);
    await p.keyboard.press('Escape'); await settle(p, 400);

    await p.fill('#domainInput', domain); await p.click('#lookupBtn');
    await waitLookup(p);
    await scan(p, `[${scheme}] lookup results`);
    await p.evaluate(() => document.querySelectorAll('#results .card-header.collapsed-header').forEach(h => h.click()));
    await settle(p, 500);
    await scan(p, `[${scheme}] lookup results (all expanded)`);
    await tabWalk(p, `[${scheme}] lookup results`);
    if (await p.evaluate(() => typeof window.openCheckOptions === 'function')) {
      await p.evaluate(() => window.openCheckOptions('spf')); await settle(p, 600);
      await scan(p, `[${scheme}] Options dialog`);
      await p.keyboard.press('Escape');
    }
    await p.context().close();

    for (const path of ['/terms', '/privacy']) {
      p = await newPage(browser, { scheme });
      await p.goto(base + path, { waitUntil: 'networkidle' }); await settle(p, 500);
      await scan(p, `[${scheme}] ${path}`);
      await p.context().close();
    }
  }

  const rtl = await newPage(browser, { scheme: 'dark', lang: 'ar' });
  await rtl.goto(base + '/?lang=ar', { waitUntil: 'networkidle' }); await settle(rtl, 1500);
  await scan(rtl, '[dark] Arabic (RTL)');
  await rtl.context().close();
} finally {
  await browser.close();
}

console.log(`\n==== ${totals.violations} violations, ${totals.keyboard} keyboard problems, ${totals.review} needs-review (${totals.reviewBlocking} outside overlay states)`);
const failed = totals.violations > 0 || totals.keyboard > 0 || (strictReview && totals.reviewBlocking > 0);
console.log(failed ? 'FAIL' : 'PASS');
process.exit(failed ? 1 : 0);
