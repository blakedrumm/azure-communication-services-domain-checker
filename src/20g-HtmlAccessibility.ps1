# ===== HTML Accessibility Layer (CSS + JS) =====
#
# PURPOSE
#   Central, single-file home for the SPA's accessibility (a11y) code so it
#   lives in one place instead of being scattered across the other 20-* UI
#   files. This file appends a dedicated, nonce-bound <style> block and a
#   <script> helper module to the page, followed by the SMTP response tool in
#   20h-HtmlSmtpResponses.ps1, which emits the document-closing tags.
#
# LOAD ORDER / BUILD NOTES
#   This runs AFTER
#   20f-HtmlPostProcess.ps1, which performs the build-time "__TOKEN__ -> value"
#   replacements. Therefore do NOT use build-time template tokens in this file
#   (__APP_VERSION__, __ENTRA_CLIENT_ID__, __ENTRA_TENANT_ID__, __ACS_API_KEY__,
#   __ACS_ISSUE_URL__, __ACS_MSAL_SRI__) -- they will not be substituted here.
#   The request-time __CSP_NONCE__ token IS fine: it is replaced per request in
#   11-HttpHelpers.ps1 / 23-RequestHandler.ps1 for EVERY occurrence in the page.
#
# WHAT DELIBERATELY STAYS IN OTHER FILES
#   A few a11y attributes are part of static or dynamically-generated markup and
#   must remain where that markup is authored:
#     * <label>/aria-label on the search input, the clear (x) button, landmark
#       roles, heading levels, and the skip-link anchor -> 20a-HtmlScriptSetup.ps1
#     * ARIA baked into JS-generated result/card templates -> 20c/20d/20e.
#   This file provides the shared building blocks those call sites rely on:
#   CSS utilities (.sr-only, .skip-link, forced-colors focus) and JS helpers
#   (the live-region announcer, window.acsAnnounce).

$htmlPage += @'
<!-- ===================== Accessibility layer ===================== -->
<style nonce="__CSP_NONCE__">
/* Visually-hidden utility. Content stays in the accessibility tree (announced
   by screen readers) but is removed from the visual layout. Used for the ARIA
   live-region containers, off-screen labels, and skip-link text. */
.sr-only {
  position: absolute !important;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* Skip-to-content link (WCAG 2.4.1 Bypass Blocks). Off-screen until it receives
   keyboard focus, then it slides into view as the first focusable element on
   the page. The matching <a class="skip-link"> anchor and its #mainContent
   target are authored in 20a-HtmlScriptSetup.ps1. */
.skip-link {
  position: absolute;
  left: -9999px;
  top: 0;
  z-index: 2000;
  padding: 10px 16px;
  background: var(--button-bg);
  color: var(--button-fg);
  border-radius: 0 0 6px 0;
  text-decoration: none;
  font-size: 14px;
}
.skip-link:focus {
  left: 0;
}

/* <main id="mainContent" tabindex="-1"> is the skip-link target. It receives
   programmatic focus only, so suppress the focus ring on the container itself. */
#mainContent:focus {
  outline: none;
}

/* Decorative icon glyphs (chevrons, carets, x, arrows). The character lives in
   data-glyph and is painted by CSS, so it is never read by screen readers and is
   not evaluated as text by contrast checkers (axe "Needs review": "content
   contains only non-text characters"). Controls using it carry their own
   aria-label. Usage: <span class="acs-glyph" data-glyph="&#x2715;" aria-hidden="true"></span> */
.acs-glyph::before {
  content: attr(data-glyph);
}

/* Visible keyboard focus everywhere (WCAG 2.4.7 Focus Visible / 2.4.11). Several
   components replace the outline with a subtle border-color change, which is easy
   to miss; this restores a consistent 2px ring for keyboard focus only. --link is
   >= 5.6:1 against every page/card/code background in both themes (>= 3:1 needed). */
a:focus-visible,
button:focus-visible,
select:focus-visible,
textarea:focus-visible,
summary:focus-visible,
input:not(#domainInput):focus-visible,
[tabindex]:not([tabindex="-1"]):focus-visible,
[contenteditable="true"]:focus-visible {
  outline: 2px solid var(--link) !important;
  outline-offset: 2px;
}
/* The domain field draws its border on .input-wrapper (so chips can sit inside it),
   so ring the wrapper rather than the borderless inner input. */
.input-wrapper:focus-within {
  box-shadow: 0 0 0 2px var(--link);
}

/* Windows High Contrast / forced-colors mode: guarantee a visible keyboard
   focus indicator even when the app's custom colors are replaced by the OS.
   Scoped to :focus-visible so it only shows during keyboard navigation. */
@media (forced-colors: active) {
  a:focus-visible,
  button:focus-visible,
  input:focus-visible,
  select:focus-visible,
  textarea:focus-visible,
  [tabindex]:focus-visible,
  [contenteditable="true"]:focus-visible {
    outline: 2px solid Highlight;
    outline-offset: 2px;
  }
}
</style>

<script nonce="__CSP_NONCE__">
(function () {
  'use strict';
  // ---------------------------------------------------------------------------
  // Shared accessibility helpers for the SPA.
  //
  // window.acsAnnounce(message, opts): announce a short message to assistive
  // technology WITHOUT moving keyboard focus, using an ARIA live region. Call
  // it after asynchronous UI changes that are otherwise only conveyed visually
  // (e.g. "Results ready for example.com", "Some checks failed") so
  // screen-reader users are notified.
  //
  //   opts.assertive === true -> uses aria-live="assertive" (interrupts the
  //   current screen-reader output). Reserve this for errors; the default is
  //   the less disruptive aria-live="polite".
  // ---------------------------------------------------------------------------
  var politeRegion = null;
  var assertiveRegion = null;

  // Lazily create (once per politeness level) an off-screen live region.
  function ensureRegion(assertive) {
    var id = assertive ? 'acsA11yLiveAssertive' : 'acsA11yLivePolite';
    var existing = document.getElementById(id);
    if (existing) { return existing; }
    var region = document.createElement('div');
    region.id = id;
    region.className = 'sr-only';
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', assertive ? 'assertive' : 'polite');
    region.setAttribute('aria-atomic', 'true');
    (document.body || document.documentElement).appendChild(region);
    return region;
  }

  function announce(message, opts) {
    if (!message) { return; }
    var assertive = !!(opts && opts.assertive);
    var region = assertive
      ? (assertiveRegion = assertiveRegion || ensureRegion(true))
      : (politeRegion = politeRegion || ensureRegion(false));
    // Clear first, then set the text on a later tick. This re-announces even
    // identical consecutive messages and gives the screen reader time to
    // register the (empty) region before the text is injected into it.
    region.textContent = '';
    window.setTimeout(function () { region.textContent = String(message); }, 60);
  }

  // Single global entry point consumed by the render/lookup code.
  window.acsAnnounce = announce;

  // ---------------------------------------------------------------------------
  // Card collapse/expand toggles (WCAG 2.1.1 Keyboard, 4.1.2 Name/Role/Value).
  //
  // Every card header renders its chevron as <button class="chevron card-toggle">.
  // The button's click bubbles to the header's onclick="toggleCard(this)", so no
  // extra handler is needed; this helper only keeps the ARIA state truthful:
  //   aria-expanded  -> mirrors the header's .collapsed-header class
  //   aria-controls  -> the collapsible .card-content element (when it has an id)
  //   aria-label     -> the card title, so the control reads e.g. "SPF, expanded"
  // It runs from toggleCard() and, because cards are rendered via innerHTML in
  // many places, from a rAF-debounced MutationObserver after any DOM insertion.
  // ---------------------------------------------------------------------------
  function syncCardToggles(root) {
    var scope = (root && root.querySelectorAll) ? root : document;
    var toggles = scope.querySelectorAll('.card-header > .card-toggle');
    for (var i = 0; i < toggles.length; i++) {
      var btn = toggles[i];
      var header = btn.parentElement;
      var content = header.nextElementSibling;
      var collapsed = header.classList.contains('collapsed-header') ||
        !!(content && content.classList.contains('collapsed'));
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      if (content && content.id) btn.setAttribute('aria-controls', content.id);
      var titleEl = header.querySelector('strong');
      var title = titleEl ? (titleEl.textContent || '').replace(/\s+/g, ' ').trim() : '';
      if (!title && typeof window.t === 'function') title = window.t('toggleSection');
      if (title && btn.getAttribute('aria-label') !== title) btn.setAttribute('aria-label', title);
    }
  }
  window.acsSyncCardToggles = syncCardToggles;

  // Observe childList only (not attributes) so our own setAttribute calls can
  // never retrigger the observer.
  var syncScheduled = false;
  function scheduleSync() {
    if (syncScheduled) { return; }
    syncScheduled = true;
    window.requestAnimationFrame(function () {
      syncScheduled = false;
      syncCardToggles(document);
    });
  }
  if (window.MutationObserver && document.body) {
    new MutationObserver(scheduleSync).observe(document.body, { childList: true, subtree: true });
  }
  scheduleSync();
})();
</script>
'@
