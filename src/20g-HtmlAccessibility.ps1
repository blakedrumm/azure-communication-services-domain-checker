# ===== HTML Accessibility Layer (CSS + JS) =====
#
# PURPOSE
#   Central, single-file home for the SPA's accessibility (a11y) code so it
#   lives in one place instead of being scattered across the other 20-* UI
#   files. This file appends a dedicated, nonce-bound <style> block and a
#   <script> helper module to the page, then emits the document-closing
#   </body></html> tags (relocated here from 20e-HtmlAzureIntegration.ps1) so
#   this accessibility layer lands immediately before </body> -- the correct
#   place for shared a11y CSS/JS and ARIA live regions.
#
# LOAD ORDER / BUILD NOTES
#   This is the LAST file that appends to $htmlPage. It runs AFTER
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
})();
</script>

</body>
</html>
'@
