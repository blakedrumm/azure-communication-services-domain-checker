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

.dns-records-toolbar-group-search {
  grid-template-rows: minmax(14px, auto) 32px auto;
  align-self: start;
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

.kv-value-secondary {
  margin-top: 2px;
  font-size: 11px;
  color: var(--fg-muted);
  word-break: break-word;
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

/* SPF Expansion Records table.
   Extends .mx-table but switches cell font back to the main UI stack so that
   enum-style cells (Depth / Mechanism / Parent / Target / Lookups) read cleanly,
   while keeping the resolved TXT record cell in a monospace font for SPF
   readability. The table uses auto layout so Parent and Target size to fit
   the longest domain on a single line; long resolved TXT records are still
   constrained via max-width so the record column wraps instead of pushing
   the table to absurd widths. The card body wraps the table in an
   overflow-x: auto container so very wide chains scroll horizontally on
   narrow viewports. */
.spf-expansion-table {
  table-layout: auto;
  font-family: inherit;
  width: 100%;
}
.spf-expansion-table th,
.spf-expansion-table td {
  font-family: inherit;
  vertical-align: top;
  word-break: break-word;
}
.spf-expansion-table th {
  /* Header labels are short enums (DEPTH / MECHANISM / LOOKUPS); keeping
     them single-line avoids ugly mid-word wraps when uppercase styling is
     applied by the parent .mx-table rules. */
  white-space: nowrap;
}
.spf-expansion-table td.spf-col-depth {
  text-align: center;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.spf-expansion-table td.spf-col-lookups {
  text-align: right;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.spf-expansion-table td.spf-col-mechanism,
.spf-expansion-table td.spf-col-parent,
.spf-expansion-table td.spf-col-target {
  /* Show the full domain on a single line. If the chain is wide enough to
     exceed the card, the wrapping container scrolls horizontally rather
     than truncating values. */
  white-space: nowrap;
}
.spf-expansion-table td.spf-col-record {
  font-family: Consolas, "SF Mono", Menlo, monospace;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
  line-height: 1.45;
  /* Give the record column a soft cap so it keeps wrapping instead of
     stretching the table when other columns are narrow. min-width keeps
     it usable even when the chain is short and there's plenty of room. */
  min-width: 320px;
  max-width: 640px;
}
.spf-expansion-table .spf-chain-arrow {
  opacity: 0.55;
  margin-right: 4px;
}
.spf-expansion-table .spf-parent-repeat {
  opacity: 0.45;
}
.spf-expansion-table .spf-lookups-heavy {
  background: rgba(217, 119, 6, 0.18);
  border-radius: 4px;
  padding: 1px 6px;
  font-weight: 600;
}
/* Horizontally scrollable wrapper around the SPF expansion table. Lets very
   wide chains scroll inside the card instead of breaking the page layout. */
.spf-expansion-scroll {
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}

.dns-records-toolbar {
  /* Explicit grid: labels on row 1, controls on row 2, chips on row 3.
     This avoids nested grids so labels and controls always align. */
  display: grid;
  grid-template-columns: minmax(200px, 280px) minmax(130px, 170px) max-content 1fr;
  grid-template-rows: auto 32px;
  gap: 4px 12px;
  align-items: center;
  margin-bottom: 10px;
  font-size: 12px;
  color: var(--fg-muted);
  /* Stacking context so the search suggestions overlay the table below */
  position: relative;
  z-index: 1;
  /* Prevent the grid from clipping absolutely-positioned suggestions */
  overflow: visible;
}

.dns-records-toolbar-label {
  min-height: 14px;
  display: inline-flex;
  align-items: center;
  line-height: 1;
}

.dns-records-search-dropdown {
  position: relative;
  width: 100%;
  /* Own stacking context so suggestions paint above sibling grid items */
  z-index: 2;
  overflow: visible;
}

input.dns-records-search-input,
select.dns-records-filter-select {
  height: 32px;
  min-height: 32px;
  padding: 6px 10px;
  border-radius: 6px;
  border: 1px solid var(--input-border);
  background: var(--card-bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  font-size: 12px;
  font-weight: 400;
  line-height: 18px;
  vertical-align: middle;
  margin: 0;
  box-sizing: border-box;
}

input.dns-records-search-input {
  width: 100%;
  min-width: 0;
}

.dns-records-search-input::placeholder {
  color: var(--status);
  opacity: 1;
}

.dns-records-search-suggestions {
  position: absolute;
  top: 100%; /* Always below the dropdown container */
  margin-top: 4px; /* Visual gap between input and suggestions */
  left: 0;
  right: 0;
  z-index: 100;
  display: none;
  max-height: 180px;
  overflow-y: auto;
  border: 1px solid var(--input-border);
  border-radius: 8px;
  background: var(--card-bg);
  box-shadow: 0 8px 24px rgba(0,0,0,0.22);
}

.dns-records-search-suggestions.dns-records-search-suggestions-visible {
  display: block;
}

.dns-records-search-suggestion-item {
  display: block;
  width: 100%;
  padding: 8px 10px;
  border: none;
  background: var(--card-bg);
  color: var(--fg);
  font: inherit;
  text-align: left;
  white-space: nowrap;
  cursor: pointer;
}

.dns-records-search-suggestion-item:hover,
.dns-records-search-suggestion-item:focus-visible,
.dns-records-search-suggestion-item.active {
  background: rgba(47, 128, 237, 0.12);
  outline: none;
}

.whois-raw-panel {
  display: grid;
  gap: 10px;
}

.rdap-digest-wrapper {
  display: grid;
  gap: 10px;
}

.rdap-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 8px;
}

.rdap-summary-tile {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(47, 128, 237, 0.09), rgba(47, 128, 237, 0.03));
}

.rdap-summary-count {
  font-size: 18px;
  font-weight: 700;
  color: var(--fg);
}

.rdap-summary-label {
  font-size: 11px;
  color: var(--fg-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.rdap-digest-section {
  background: var(--code-bg);
  color: var(--code-fg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 12px;
}

.rdap-digest-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--fg-muted);
  margin-bottom: 8px;
}

.rdap-digest-list {
  margin: 0;
  padding-left: 18px;
  display: grid;
  gap: 6px;
}

.rdap-digest-list li {
  line-height: 1.45;
}

.rdap-pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.rdap-pill {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(47, 128, 237, 0.35);
  background: rgba(47, 128, 237, 0.12);
  color: var(--code-fg);
  font-size: 12px;
  line-height: 1.3;
}

.rdap-timeline {
  position: relative;
  display: grid;
  gap: 10px;
}

.rdap-timeline::before {
  content: '';
  position: absolute;
  left: 7px;
  top: 6px;
  bottom: 6px;
  width: 1px;
  background: rgba(47, 128, 237, 0.22);
}

.rdap-timeline-item {
  position: relative;
  display: grid;
  grid-template-columns: 16px 1fr;
  gap: 10px;
  align-items: start;
}

.rdap-timeline-marker {
  width: 14px;
  height: 14px;
  margin-top: 3px;
  border-radius: 999px;
  border: 2px solid rgba(47, 128, 237, 0.55);
  background: var(--code-bg);
  z-index: 1;
}

.rdap-timeline-content {
  min-width: 0;
}

.rdap-timeline-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--code-fg);
}

.rdap-timeline-meta {
  margin-top: 2px;
  font-size: 11px;
  color: var(--fg-muted);
}

.rdap-detail-card-list,
.rdap-link-card-list,
.rdap-notice-card-list {
  display: grid;
  gap: 8px;
}

/* ---------- DKIM card body layout ----------
 * Used by the DKIM1/DKIM2 cards to render published records in a grouped
 * "selector block" with a small Type | Value grid inside, instead of plain
 * text lines with arrows. Mirrors the visual rhythm of the RDAP detail
 * cards above so the DKIM body feels native. */
.dkim-record-list {
  display: grid;
  gap: 8px;
}

.dkim-selector-block {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  background: linear-gradient(180deg, rgba(47, 128, 237, 0.07), rgba(47, 128, 237, 0.02));
}

.dkim-selector-name {
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-weight: 600;
  font-size: 12px;
  color: var(--fg-muted);
  margin-bottom: 8px;
  word-break: break-all;
}

.dkim-record-grid {
  display: grid;
  grid-template-columns: 64px 1fr;
  gap: 6px 12px;
  align-items: start;
}

.dkim-record-type {
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-weight: 700;
  font-size: 11px;
  letter-spacing: 0.04em;
  color: #2f80ed;
  text-transform: uppercase;
  padding-top: 1px;
}

.dkim-record-value {
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
  line-height: 1.45;
}

.rdap-detail-card,
.rdap-notice-card {
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: rgba(255,255,255,0.03);
}

.rdap-detail-card-title {
  font-size: 12px;
  font-weight: 700;
  color: var(--code-fg);
}

.rdap-detail-primary {
  margin-top: 4px;
  font-size: 12px;
  color: var(--code-fg);
}

.rdap-detail-meta {
  margin-top: 3px;
  font-size: 11px;
  color: var(--fg-muted);
  word-break: break-word;
}

.rdap-link-card {
  background: rgba(47, 128, 237, 0.06);
}

.rdap-link {
  color: #6ea8ff;
  text-decoration: none;
  word-break: break-all;
}

.rdap-link:hover {
  text-decoration: underline;
}

.rdap-digest-muted {
  color: var(--fg-muted);
}

.rdap-raw-details {
  background: var(--code-bg);
  color: var(--code-fg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
}

.rdap-raw-details summary {
  cursor: pointer;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--fg-muted);
}

.rdap-raw-pre {
  margin-top: 10px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
}

.dns-records-filter-select {
  width: 100%;
  min-width: 150px;
  appearance: auto;
  color-scheme: light;
  margin: 0;
}

.dns-records-filter-select option {
  background: #ffffff;
  color: #111827;
}

html.dark .dns-records-filter-select {
  color-scheme: dark;
  background: #111827;
  color: #f9fafb;
}

html.dark .dns-records-filter-select option {
  background: #111827;
  color: #f9fafb;
}

.dns-records-clear-btn {
  height: 32px;
}

.dns-records-filter-summary {
  justify-self: end;
  font-size: 12px;
  color: var(--fg-muted);
  white-space: nowrap;
}

.dns-records-filter-chip-row {
  grid-column: 1 / -1;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  min-height: 0;
  padding-top: 4px;
}

.dns-records-filter-chip {
  max-width: 100%;
}

.dns-records-filter-chip-column {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--fg-muted);
  white-space: nowrap;
}

.dns-records-filter-chip-value {
  color: var(--button-bg);
  white-space: nowrap;
}

.dns-records-filter-remove {
  flex: 0 0 auto;
}

.dns-records-table .dns-record-row {
  cursor: pointer;
}

.dns-records-table .dns-record-row:hover td {
  background: rgba(47, 128, 237, 0.08);
}

.dns-records-table .dns-record-row:focus-visible td {
  outline: 2px solid #2f80ed;
  outline-offset: -2px;
}

.dns-records-table .dns-record-row.dns-record-row-selected td {
  background: #fff3a3;
  color: #4a3b00;
}

html.dark .dns-records-table .dns-record-row.dns-record-row-selected td {
  background: #8a6d00;
  color: #fff7d1;
}

/* Chain marker: small "down-and-right arrow" glyph prefixed to the Name
 * column when a TXT row is rendered directly under the CNAME row that
 * points at it (e.g., a DKIM public key on the resolved selector). The
 * indent + accent color mirrors the row hierarchy without changing layout. */
.dns-records-table .dns-record-row-chained td:first-child {
  padding-left: 18px;
}

.dns-records-table .dns-record-chain-marker {
  color: #2f80ed;
  font-weight: 600;
  margin-right: 2px;
  user-select: none;
}

.dns-records-no-matches {
  margin-top: 10px;
  font-size: 12px;
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

.status-loading-dots {
  margin-left: 6px;
  font-size: 1.15em;
  font-weight: 700;
  letter-spacing: 1px;
  color: var(--fg);
}

.status-loading-dots .loading-dot {
  min-width: 0.4em;
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
  .dns-records-toolbar { grid-template-columns: 1fr; }
  .dns-records-filter-summary { margin-left: 0; justify-self: start; }
  .dns-records-clear-btn { justify-self: start; }
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

/* ---- Cookie Consent Banner (EU GDPR / ePrivacy compliance) ---- */
.cookie-consent-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  z-index: 10000;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  padding: 0 16px 24px 16px;
  animation: cookieFadeIn 0.35s ease;
}

@keyframes cookieFadeIn {
  from { opacity: 0; }
  to   { opacity: 1; }
}

.cookie-consent-banner {
  background: var(--card-bg);
  color: var(--fg);
  border: 1px solid var(--border);
  border-radius: 14px;
  box-shadow: 0 -4px 24px rgba(0, 0, 0, 0.18);
  max-width: 620px;
  width: 100%;
  padding: 24px 28px 20px 28px;
  font-size: 14px;
  line-height: 1.55;
}

.cookie-consent-banner h2 {
  margin: 0 0 8px 0;
  font-size: 17px;
  font-weight: 700;
}

.cookie-consent-banner p {
  margin: 0 0 16px 0;
  color: var(--status);
  font-size: 13px;
}

.cookie-consent-banner a {
  color: var(--button-bg);
  text-decoration: underline;
}

/* Category toggle rows */
.cookie-categories {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 18px;
}

.cookie-category {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  border-radius: 8px;
  background: var(--bg);
  border: 1px solid var(--border);
  font-size: 13px;
}

.cookie-category-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.cookie-category-name {
  font-weight: 600;
  white-space: nowrap;
}

.cookie-category-desc {
  font-size: 11px;
  color: var(--status);
  line-height: 1.4;
}

/* Toggle switch */
.cookie-toggle {
  position: relative;
  flex-shrink: 0;
  width: 40px;
  height: 22px;
}

.cookie-toggle input {
  opacity: 0;
  width: 0;
  height: 0;
  position: absolute;
}

.cookie-toggle-slider {
  position: absolute;
  inset: 0;
  background: var(--input-border);
  border-radius: 22px;
  cursor: pointer;
  transition: background 0.25s ease;
}

.cookie-toggle-slider::before {
  content: '';
  position: absolute;
  width: 16px;
  height: 16px;
  left: 3px;
  bottom: 3px;
  background: #fff;
  border-radius: 50%;
  transition: transform 0.25s ease;
}

.cookie-toggle input:checked + .cookie-toggle-slider {
  background: var(--button-bg);
}

.cookie-toggle input:checked + .cookie-toggle-slider::before {
  transform: translateX(18px);
}

.cookie-toggle input:disabled + .cookie-toggle-slider {
  opacity: 0.55;
  cursor: not-allowed;
}

.cookie-toggle input:focus-visible + .cookie-toggle-slider {
  outline: 2px solid var(--button-bg);
  outline-offset: 2px;
}

/* Action buttons row */
.cookie-consent-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}

.cookie-consent-actions button {
  padding: 8px 18px;
  font-size: 13px;
  font-weight: 600;
  border-radius: 8px;
  cursor: pointer;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
}

.cookie-consent-actions button:hover {
  transform: translateY(-1px);
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.12);
}

.cookie-btn-accept-all {
  background: var(--button-bg);
  color: var(--button-fg);
  border: 1px solid var(--button-bg);
}

.cookie-btn-accept-all:hover {
  filter: brightness(1.12);
}

.cookie-btn-save {
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  border: 1px solid var(--button-border-secondary);
}

.cookie-btn-save:hover {
  background: var(--border);
  border-color: var(--input-border);
}

.cookie-btn-reject {
  background: transparent;
  color: var(--status);
  border: 1px solid var(--border);
}

.cookie-btn-reject:hover {
  background: var(--bg);
  border-color: var(--input-border);
}

/* Small footer link for re-opening preferences */
.cookie-settings-link {
  cursor: pointer;
  text-decoration: underline;
  color: inherit;
  font-size: inherit;
}

.cookie-settings-link:hover {
  color: var(--button-bg);
}

@media (prefers-reduced-motion: reduce) {
  .cookie-consent-overlay { animation: none; }
  .cookie-consent-actions button:hover { transform: none; box-shadow: none; }
}

@media (max-width: 480px) {
  .cookie-consent-banner { padding: 18px 16px 16px 16px; }
  .cookie-consent-actions { flex-direction: column; }
  .cookie-consent-actions button { width: 100%; text-align: center; }
}
</style>
'@
