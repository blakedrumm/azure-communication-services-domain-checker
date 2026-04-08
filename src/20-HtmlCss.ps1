# ===== Embedded HTML / UI (Single Page Application) =====
# ------------------- HTML / UI -------------------
# The entire web UI is embedded as a PowerShell here-string below.
# This makes the script a single-file distribution — no external HTML, CSS, or JS files needed.
# The SPA (Single Page Application) calls the JSON endpoints served by this same script
# (/api/base, /api/mx, /api/dmarc, /api/dkim, /api/cname, /dns) and renders results client-side.
#
# Note: The UI references a CDN script (`html2canvas`) only for screenshot/export.

$htmlPage = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />
<title>Azure Communication Services - Email Domain Checker</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">

<style nonce="__CSP_NONCE__">
:root {
  --bg: #f4f6fb;
  --fg: #111827;
  --card-bg: #ffffff;
  --border: #e0e3ee;
  --status: #555555;
  --input-border: #c3c7d6;
  --button-bg: #2f80ed;
  --button-fg: #ffffff;
  --button-bg-secondary: #ffffff;
  --button-fg-secondary: #111827;
  --button-border-secondary: #c3c7d6;
  --code-bg: #0b1220;
  --code-fg: #c3d5ff;
}

.dark {
  --bg: #020617;
  --fg: #e5e7eb;
  --card-bg: #020617;
  --border: #1f2937;
  --status: #9ca3af;
  --input-border: #4b5563;
  --button-bg: #1d4ed8;
  --button-fg: #f9fafb;
  --button-bg-secondary: #111827;
  --button-fg-secondary: #e5e7eb;
  --button-border-secondary: #4b5563;
  --code-bg: #020617;
  --code-fg: #e5e7eb;
}

/* Hide marked buttons while screenshot is taken */
.screenshot-mode .hide-on-screenshot {
  visibility: hidden !important;
}

*, *::before, *::after {
  box-sizing: border-box;
}

html {
  width: 100%;
  overflow-x: hidden;
  -webkit-text-size-adjust: 100%;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  margin: 0;
  padding: 32px 24px;
  background: var(--bg);
  color: var(--fg);
  transition: 0.25s background-color ease-in-out;
  width: 100%;
  max-width: 100%;
  overflow-x: hidden;
}

.search-box, .card, input, button, .code, .mx-table, .history-chip {
  transition: 0.25s background-color ease-in-out;
}

.container {
  width: 100%;
  max-width: 1100px;
  margin: 0 auto;
  min-width: 0;
}

h1 {
  font-size: 22px;
  margin: 0 0 18px 0;
}

.top-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
  width: 100%;
  position: relative;
  z-index: 200;
  isolation: isolate;
}

.top-bar button {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

.top-bar button:hover:not(:disabled) {
  background: var(--border);
  border-color: var(--input-border);
  transform: translateY(-1px);
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.top-bar button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

.language-dropdown {
  position: relative;
  min-width: 0;
  z-index: 210;
}

.language-trigger {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  min-width: 150px;
  max-width: 100%;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

.language-trigger:hover {
  background: var(--border);
  border-color: var(--input-border);
  transform: translateY(-1px);
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.language-trigger .caret {
  margin-left: auto;
  font-size: 10px;
}

.language-menu {
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  min-width: 220px;
  padding: 6px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--card-bg);
  box-shadow: 0 10px 24px rgba(0,0,0,0.18);
  z-index: 220;
  display: none;
}

.language-menu.open {
  display: block;
}

html[dir="rtl"] .language-menu {
  left: auto;
  right: 0;
}

html[dir="rtl"] .language-option,
html[dir="rtl"] .language-trigger {
  text-align: right;
}

.language-option {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--fg);
  cursor: pointer;
  text-align: left;
  font-size: 12px;
}

.language-option:hover,
.language-option.active {
  background: var(--button-bg-secondary);
}

@media (prefers-reduced-motion: no-preference) {
  .language-option {
    transition: background-color 0.2s ease, transform 0.2s ease;
  }

  .language-option:hover,
  .language-option.active {
  transform: translateY(-1px);
  }
}

.language-flag {
  width: 20px;
  height: 20px;
  object-fit: cover;
  border-radius: 50%;
  border: 1px solid #eee;
  flex: 0 0 auto;
}

.top-bar select {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.top-bar select:hover {
  border-color: var(--input-border);
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.top-bar button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.search-box {
  background: var(--card-bg);
  border-radius: 8px;
  border: 1px solid var(--border);
  width: 100%;
  max-width: 760px;
  padding: 18px;
  margin: 0 auto 20px auto;
  min-width: 0;
}

.search-box h1 {
  margin: 0 0 12px 0;
  font-size: 22px;
  font-weight: 700;
  text-align: center;
}

.search-box h2 {
  margin: 0 0 12px 0;
  font-size: 16px;
  font-weight: 600;
}

.input-row {
  display: flex;
  gap: 8px;
  width: 100%;
  min-width: 0;
}

input[type=text] {
  flex: 1;
  height: 38px;
  padding: 8px 10px;
  line-height: 20px;
  border-radius: 4px;
  border: 1px solid var(--input-border);
  font-size: 16px;
  background: var(--card-bg);
  color: var(--fg);
  min-width: 0;
}

button.primary {
  height: 38px;
  padding: 8px 14px;
  background: var(--button-bg);
  color: var(--button-fg);
  border-radius: 4px;
  border: none;
  cursor: pointer;
  font-size: 16px;
  transition: background-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

button.primary:hover:not(:disabled) {
  filter: brightness(1.12);
  transform: translateY(-1px);
  box-shadow: 0 3px 8px rgba(47,128,237,0.3);
}

button.primary:disabled {
  opacity: 0.7;
  cursor: default;
}

#status {
  font-size: 13px;
  color: var(--status);
  min-height: 18px;
  margin-bottom: 10px;
  text-align: center;
}

.status-divider {
  margin: 10px auto 8px auto;
  width: min(860px, 100%);
  border-top: 1px solid var(--border);
}

.status-header {
  width: 100%;
  margin: 0 0 10px 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  text-align: center;
}

.status-header .title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--fg);
}

.status-header .hint {
  font-size: 12px;
  color: var(--status);
}

.status-summary {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  justify-content: center;
  gap: 6px;
  width: min(860px, 100%);
  margin: 0 auto;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--card-bg);
}

.status-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.status-pills {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
  flex-wrap: wrap;
}

.status-name {
  font-size: 12px;
  color: var(--fg);
  overflow: visible;
  text-overflow: clip;
  white-space: nowrap;
}

.status-pill {
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  border: 1px solid var(--border);
  padding: 3px 10px;
  white-space: nowrap;
}

.cards {
  display: flex;
  flex-direction: column;
  gap: 12px;
  transition: opacity 280ms ease;
}

.card {
  background: var(--card-bg);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 12px 14px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}

.tag {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 999px;
}

.tag-pass {
  background: #e1f7e6;
  color: #137333;
}

.tag-warn {
  background: #f9d976;
  color: #5c3c00;
}

.tag-fail {
  background: #fde2e2;
  color: #c5221f;
}

.tag-info {
  background: #e1ecff;
  color: #214a9b;
}

.info-dot {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 1px solid var(--border);
  font-size: 10px;
  color: var(--status);
  margin-left: 6px;
  cursor: pointer;
  background: transparent;
  padding: 0;
  position: relative;
}
.info-dot:hover {
  color: var(--fg);
  border-color: var(--status);
}
.info-dot::after {
  content: attr(data-info);
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--card-bg);
  color: var(--fg);
  border: 1px solid var(--border);
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.16);
  padding: 8px 10px;
  font-size: 11px;
  min-width: 180px;
  max-width: 280px;
  z-index: 10;
  opacity: 0;
  visibility: hidden;
  transition: opacity 120ms ease, visibility 120ms ease;
  pointer-events: none;
  white-space: normal;
}
.info-dot:focus::after,
.info-dot:focus-visible::after,
.info-dot:hover::after,
.info-dot.info-open::after {
  opacity: 1;
  visibility: visible;
}

.code {
  background: var(--code-bg);
  color: var(--code-fg);
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  padding: 8px 10px;
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-word;
}

.code-lite {
  background: transparent;
  color: var(--fg);
  padding: 0;
}

.guidance-code {
  display: inline-block;
  background: var(--code-bg);
  color: var(--code-fg);
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 0.92em;
  padding: 1px 6px;
  border-radius: 4px;
  white-space: nowrap;
}

.checked-domain {
  font-style: italic;
}

.kv-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 14px;
  align-items: start;
  font-size: 12px;
}

.kv-label {
  font-weight: 700;
  white-space: nowrap;
}

.kv-value {
  min-width: 0;
}

.kv-value em {
  font-style: italic;
}

.kv-spacer {
  grid-column: 1 / -1;
  height: 8px;
}

.mx-table {
  width: 100%;
  border-collapse: collapse;
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  background: var(--code-bg);
  color: var(--code-fg);
  border-radius: 6px;
  overflow: hidden;
}

.mx-table th {
  background: var(--border);
  color: var(--fg);
  padding: 6px 10px;
  text-align: left;
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.mx-table td {
  padding: 6px 10px;
  border-top: 1px solid var(--border);
}

.mx-table tr:first-child td {
  border-top: none;
}

.dns-records-table td.dns-record-data {
  white-space: pre-wrap;
  word-break: break-word;
}

.dns-records-table th {
  white-space: nowrap;
}

.dns-records-table th:first-child,
.dns-records-table td:first-child {
  white-space: nowrap;
}

.dns-records-table th:nth-child(3),
.dns-records-table td:nth-child(3) {
  white-space: nowrap;
}

.dns-records-table td.dns-record-ttl {
  white-space: nowrap;
}

.dns-record-detail-list {
  display: grid;
  gap: 4px;
}

.dns-record-detail-row {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 8px;
  align-items: start;
}

.dns-record-detail-label {
  font-weight: 700;
  white-space: nowrap;
}

.dns-record-detail-value {
  min-width: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

ul.guidance {
  margin: 0;
  padding-left: 18px;
  font-size: 13px;
}

ul.guidance li {
  margin-bottom: 4px;
}

.copy-btn {
  padding: 4px 8px;
  font-size: 11px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

.copy-btn:hover {
  background: var(--border);
  border-color: var(--input-border);
  transform: translateY(-1px);
  box-shadow: 0 2px 4px rgba(0,0,0,0.08);
}

/* --- New UI Polish --- */
.spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 50%;
  border-top-color: #fff;
  animation: spin 1s ease-in-out infinite;
  margin-left: 6px;
  vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }

.loading-dots .loading-dot {
  display: inline-block;
  opacity: 0.25;
  transition: opacity 0.3s ease;
}
.loading-dots .loading-dot.active {
  opacity: 1;
}

.input-wrapper {
  position: relative;
  flex: 1;
  display: flex;
}
.input-wrapper input {
  width: 100%;
  padding-right: 30px;
}
.clear-btn {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--status);
  font-size: 16px;
  cursor: pointer;
  padding: 0;
  display: none;
}
.clear-btn:hover { color: var(--fg); }

.history {
  margin-top: 12px;
  font-size: 12px;
  color: var(--status);
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
  width: 100%;
  min-width: 0;
}

.history-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--button-bg-secondary);
  will-change: transform;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.history-chip:hover {
  border-color: var(--input-border);
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}

.history-item {
  cursor: pointer;
  text-decoration: underline;
  color: var(--button-bg);
}
.history-item:hover { color: var(--fg); }

.history-remove {
  border: none;
  background: transparent;
  color: var(--status);
  cursor: pointer;
  font-size: 12px;
  line-height: 1;
  padding: 0;
}
.history-remove:hover { color: var(--fg); }

.card a {
  color: var(--button-bg);
}
.card a:hover {
  color: var(--fg);
}

.card-header { cursor: pointer; user-select: none; }
.card-header button:hover { opacity: 0.8; }
.card-content { display: block; }
.card-content.collapsed { display: none; }
.chevron {
  display: inline-block;
  transition: transform 0.2s;
  margin-right: 6px;
  font-size: 10px;
}
.card-header.collapsed-header .chevron { transform: rotate(-90deg); }

.footer {
  margin-top: 40px;
  text-align: center;
  font-size: 12px;
  color: var(--status);
  border-top: 1px solid var(--border);
  padding-top: 20px;
}

@media (max-width: 640px) {
  body {
    padding: max(16px, env(safe-area-inset-top)) max(12px, env(safe-area-inset-right)) max(16px, env(safe-area-inset-bottom)) max(12px, env(safe-area-inset-left));
  }
  .container { max-width: 100%; }
  .search-box { max-width: 100%; }
  .input-row { flex-direction: column; }
  .input-wrapper { width: 100%; }
  .input-row button:not(.search-box #clearBtn) { width: 100%; }
  .mx-table, .dns-records-table { display: block; max-width: 100%; overflow-x: auto; white-space: nowrap; }
  .top-bar { align-items: stretch; }
  .top-bar button, .language-dropdown, .language-trigger { width: 100%; height: 43px; }
  .language-trigger { min-width: 0; }
  .language-menu { width: 100%; min-width: 0; }
  .kv-grid { grid-template-columns: 1fr; gap: 4px 0; }
  .kv-label { white-space: normal; }
}

@media print {
  body { padding: 0; background: #ffffff; color: #000000; }
  .top-bar, .history, .hide-on-screenshot, #clearBtn { display: none !important; }
  .search-box { max-width: 100%; margin: 0 0 12px 0; }
  .card { break-inside: avoid; }
  .code, .mx-table, .dns-records-table { background: #ffffff; color: #000000; border: 1px solid #d1d5db; }
  .mx-table th, .dns-records-table th { background: #f3f4f6; color: #000000; }
}

@keyframes flashHighlight {
  0% { box-shadow: 0 0 0 0 rgba(47, 128, 237, 0); border-color: var(--border); }
  25% { box-shadow: 0 0 0 4px rgba(47, 128, 237, 0.3); border-color: var(--button-bg); }
  100% { box-shadow: 0 0 0 0 rgba(47, 128, 237, 0); border-color: var(--border); }
}

.card.flash-active {
  animation: flashHighlight 2.4s ease-out;
}

@media (prefers-reduced-motion: no-preference) {
  body.section-fade-enabled .engage-top-item {
    opacity: 0;
    transform: translateY(14px);
    will-change: opacity, transform;
  }

  body.section-fade-enabled .engage-top-item.engage-top-in {
    animation: topButtonFadeIn 620ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }

  body.section-fade-enabled .engage-section {
    opacity: 0;
    transform: translateY(20px);
    will-change: opacity, transform;
  }

  body.section-fade-enabled .engage-section.engage-in {
    animation: topSectionFadeIn 880ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }
}

@keyframes topButtonFadeIn {
  from {
    opacity: 0;
    transform: translateY(14px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes topSectionFadeIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (prefers-reduced-motion: no-preference) {
  .cards.results-fade-out {
    opacity: 0;
  }

  .cards > .card.result-card-prep {
    opacity: 0;
    transform: translateY(24px);
    will-change: opacity, transform;
  }

  .cards > .card.result-card-prep.result-card-in {
    animation: resultSectionFadeIn 980ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }
}

@keyframes resultSectionFadeIn {
  from {
    opacity: 0;
    transform: translateY(24px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Microsoft Auth UI */
.ms-sign-in-btn {
  background: #0078d4 !important;
  color: #ffffff !important;
  border: 1px solid #0078d4 !important;
  font-weight: 600;
}
.ms-sign-in-btn:hover {
  background: #106ebe !important;
  border-color: #106ebe !important;
}
.ms-auth-status {
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 999px;
  white-space: nowrap;
}
.ms-auth-status.ms-employee {
  background: #e1f7e6;
  color: #137333;
  border: 1px solid #137333;
}
.ms-auth-status.ms-external {
  background: #e1ecff;
  color: #214a9b;
  border: 1px solid #214a9b;
}
.dark .ms-auth-status.ms-employee {
  background: #064e1a;
  color: #a3e6b5;
  border-color: #2f8a4f;
}
.dark .ms-auth-status.ms-external {
  background: #1a2744;
  color: #a3bffa;
  border-color: #3b5bdb;
}

/* Base style for all status icons */
.status-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.inline-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.toolbar-icon {
  width: 13px;
  height: 13px;
  flex-shrink: 0;
}

.guidance-title-icon {
  width: 14px;
  height: 14px;
}

.azure-panel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}

.azure-panel-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.azure-panel-field label {
  font-size: 12px;
  color: var(--status);
}

.azure-panel-field select {
  width: 100%;
  min-width: 0;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--input-border);
  background: var(--card-bg);
  color: var(--fg);
}

.azure-panel-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.azure-panel-actions button {
  padding: 7px 10px;
  font-size: 12px;
  border-radius: 6px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

.azure-panel-actions button:hover:not(:disabled) {
  background: var(--border);
  border-color: var(--input-border);
  transform: translateY(-1px);
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.azure-panel-actions button.primary {
  background: var(--button-bg);
  color: var(--button-fg);
  border-color: var(--button-bg);
}

.azure-panel-actions button.primary:hover:not(:disabled) {
  background: var(--button-bg);
  filter: brightness(1.12);
  box-shadow: 0 3px 8px rgba(47,128,237,0.3);
}

#azureSwitchDirectoryBtn {
  padding: 7px 10px;
  font-size: 12px;
  border-radius: 6px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

#azureSwitchDirectoryBtn:hover {
  background: var(--border);
  border-color: var(--input-border);
  transform: translateY(-1px);
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.azure-note {
  font-size: 12px;
  color: var(--status);
  margin-bottom: 12px;
}

.azure-status {
  font-size: 12px;
  color: var(--status);
  margin-bottom: 10px;
  min-height: 18px;
}

.azure-status.error {
  color: #ef4444;
}

.azure-results-container {
  background: var(--code-bg);
  color: var(--code-fg);
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  padding: 8px 10px;
  border-radius: 6px;
  white-space: normal;
  word-break: normal;
}

.azure-results-container:empty {
  display: none;
}

.azure-result-table-wrap {
  overflow-x: auto;
  margin-bottom: 12px;
}

.azure-result-table {
  min-width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  white-space: nowrap;
}

.azure-result-table th,
.azure-result-table td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
  max-width: 400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.azure-result-table td.azure-cell-wrap {
  white-space: pre-wrap;
  word-break: break-all;
}

.azure-result-table th {
  background: var(--border);
  position: sticky;
  top: 0;
  z-index: 1;
}

.azure-result-meta {
  font-size: 12px;
  color: var(--status);
  margin-bottom: 8px;
}

/* Specific color filters */
.icon-error {
  filter: invert(26%) sepia(88%) saturate(2258%) hue-rotate(346deg) brightness(89%) contrast(93%);
}

.icon-warning {
  filter: invert(72%) sepia(55%) saturate(2852%) hue-rotate(1deg) brightness(105%) contrast(105%);
}

.icon-success {
  filter: invert(31%) sepia(81%) saturate(543%) hue-rotate(74deg) brightness(94%) contrast(97%);
}

.icon-info {
  filter: invert(31%) sepia(94%) saturate(1436%) hue-rotate(189deg) brightness(92%) contrast(101%);
}

/* Respect reduced-motion preferences: disable transform-based hover animations */
@media (prefers-reduced-motion: reduce) {
  .top-bar button:hover:not(:disabled),
  .language-trigger:hover,
  button.primary:hover:not(:disabled),
  .copy-btn:hover,
  .azure-panel-actions button:hover:not(:disabled),
  .azure-panel-actions button.primary:hover:not(:disabled),
  #azureSwitchDirectoryBtn:hover {
    transform: none;
    box-shadow: none;
  }
  .loading-dots .loading-dot {
    transition: none;
    transform: none !important;
  }
}
</style>
'@
