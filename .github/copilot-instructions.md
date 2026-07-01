# Copilot Instructions — ACS Email Domain Checker

> **Purpose**: Guide GitHub Copilot (and developers) through the codebase structure so you know where to look, what each file does, and how the build pipeline works.

---

## Architecture Overview

This is a **single-file PowerShell web application** that runs a local HTTP server to check DNS records for Azure Communication Services email domain verification. The web UI is a Single Page Application (SPA) embedded directly inside the PowerShell script as a here-string.

### Runtime flow

1. **CLI mode** (`-TestDomain example.com`): runs DNS checks, outputs JSON, and exits.
2. **Server mode** (default): starts an HTTP listener, serves the SPA UI, and exposes routes such as `/`, `/index.html`, `/dns`, `/api/base`, `/api/mx`, `/api/records`, `/api/whois`, `/api/dmarc`, `/api/dkim`, `/api/cname`, `/api/reputation`, `/api/website`, `/api/nameservers`, `/api/metrics`, `/api/auth/event`, `/terms`, and `/privacy`.

---

## Build System

| File | Purpose |
|---|---|
| `Build-Release.ps1` | Optionally refreshes local UI assets via `Download-UiAssets.ps1`, then concatenates all `src/*.ps1` files (sorted by numeric prefix + optional letter suffix) into the monolithic `acs-domain-checker.ps1`. |

### How to rebuild

```powershell
pwsh -NoProfile -File ./Build-Release.ps1 -Force
```

By default, `Build-Release.ps1` also invokes `Download-UiAssets.ps1` first so local Lucide and flag SVG assets are present under `assets/vendor/...`. Use `-SkipUiAssetDownload` when rebuilding in an offline or restricted environment.

> **Important:** The build uses a custom sort key (numeric prefix then optional letter suffix) instead of plain `Sort-Object Name`. PowerShell's default culture-sensitive string comparison treats hyphens as ignorable, which causes `20a-*` to sort before `20-*` and breaks the HTML assembly order.

The `acs-domain-checker.ps1` at the repo root is the **built artifact** — do **not**
edit it directly. All changes go into `src/` files, then rebuild.

### Quick validation

```powershell
pwsh -NoProfile -File ./acs-domain-checker.ps1 -TestDomain example.com
```

---

## Source File Map (`src/`)

Files are numbered `NN-Name.ps1` to control concatenation order. The build sorts lexicographically, so `20a-*` sorts after `20-*` and before `21-*`.

### Script Header & Parameters

| File | Lines | Contents |
|---|---|---|
| `00-Header.ps1` | ~161 | Script-level `param()` block, parameter definitions (`-Port`, `-Bind`, `-TestDomain`, etc.), global variables, container detection |

### Domain Parsing & WHOIS

| File | Lines | Contents |
|---|---|---|
| `01-DomainParsing.ps1` | ~300 | `Get-RegistrableDomain`, `Get-ParentDomains` — extract registrable domain from FQDN. Registrable-domain resolution uses the official **Public Suffix List (PSL)** when available: `Get-PublicSuffixData` loads/parses a cached `public_suffix_list.dat` (path from `$env:ACS_PSL_FILE`, set in `00-Header.ps1`), only consulting the ICANN section so the result stays WHOIS-queryable (PRIVATE-domain suffixes like `blogspot.com` are skipped). The file is refreshed at build time by `Download-UiAssets.ps1` and lazily refreshed at runtime when missing or older than `ACS_PSL_MAX_AGE_DAYS` (default 30) unless `ACS_PSL_DISABLE_DOWNLOAD=1`. The parsed rule sets (exact/wildcard/exception) are cached in-process via `$script:PublicSuffixCache`, keyed by path + last-write time so a refresh re-parses. `Get-PublicSuffixFromLabels` implements the official PSL longest-match + exception + `*` default algorithm. When no PSL file can be loaded, `Get-RegistrableDomain` falls back to a small **inline** multi-label suffix list (kept inline, not in a `$script:` variable, so it works inside worker runspaces where only function definitions are copied). New PSL functions (`Get-PublicSuffixListPath`, `Update-PublicSuffixListFile`, `ConvertFrom-PublicSuffixListFile`, `Get-PublicSuffixData`, `Get-PublicSuffixFromLabels`) are registered in `22-RunspaceSetup.ps1`. |
| `02-WhoisProviders.ps1` | ~614 | Three WHOIS backends: `Invoke-SysinternalsWhoisLookup` (Windows), `Invoke-LinuxWhoisLookup` (Linux), `Invoke-TcpWhoisLookup` (raw TCP fallback) |
| `04-RdapLookups.ps1` | ~225 | RDAP protocol lookups (`Invoke-RdapLookup`), plus WhoisXML and GoDaddy API fallbacks. `Invoke-WhoisXmlLookup` sends the API key in the `Authorization: Bearer` header by default so it never lands in proxy/access logs or `Referer` headers. Set `ACS_WHOISXML_KEY_IN_QUERY=1` to fall back to the legacy `?apiKey=...` query-string behavior on networks whose proxies strip Authorization headers. |
| `07-DomainRegistration.ps1` | ~405 | `Get-DomainRegistrationStatus` — orchestrates RDAP → WHOIS → API fallback chain, returns creation/expiry dates; expose raw RDAP data when available. If raw WHOIS/RDAP data is the only available content, show it inline without a Raw button; only show the Raw WHOIS/RDAP button when structured WHOIS/RDAP fields are also present and the raw content is hidden behind a collapsible section. When the only response is the IANA "This TLD has no whois server" referral (e.g. `.gr` / `.ελ` via FORTH), the raw banner is suppressed and the registry's web-form URL is exposed via the `registryWebForm` field so the SPA can render a friendly link panel. The TCP WHOIS provider (`Invoke-TcpWhoisLookup` in `02-WhoisProviders.ps1`) also explicitly rejects IANA's own TLD-level delegation record (matched by the combined presence of the `% IANA WHOIS server` header and a `source: IANA` field) via `Test-WhoisRawTextHasUsableData` so registries that publish no port-43 referral (e.g. FORTH for `.gr`) don't accidentally surface IANA's TLD record (`domain: GR`, `created: 1989-02-19`, ...) as if it were the queried domain's registration data — that would have caused the WHOIS card to show a misleading raw blob while the Email Quota row still correctly reported ERROR because no real fields parsed out. |

### Metrics & Configuration

| File | Lines | Contents |
|---|---|---|
| `03-MetricsHashKey.ps1` | ~117 | `$script:AppVersion` (currently `2.8.8`), metrics hash key persistence, `Get-HashedDomain`, `Handle-MetricsRequest` |
| `03a-SecureLogging.ps1` | ~280 | Privacy-safe structured logging: approved-field allowlist, random non-semantic correlation IDs, centralized redaction, safe exception summaries, stack-trace hashes, console JSON events, optional JSONL file sink (`ACS_LOG_FILE`) with size cap/rotation (`ACS_LOG_MAX_BYTES`), and configurable minimum level (`ACS_LOG_LEVEL`). Do not bypass this module with raw `Write-Information`, `Write-Warning`, `Write-Error`, or serialized objects in application runtime code. |
| `09-AnonymousMetrics.ps1` | ~361 | Optional anonymous usage metrics — persistence, aggregation counters, file I/O |
| `10-SessionCookies.ps1` | ~288 | Anonymous session tracking, session cookie management, `Update-AnonymousMetrics`. The `Secure` attribute on `acs_session` only honors the `X-Forwarded-Proto` header when the immediate TCP peer is in `ACS_TRUSTED_PROXIES` (mirrors `Get-ClientIp`); otherwise it falls back to `Request.Url.Scheme` so an untrusted client cannot trick the server into stamping `Secure` on a plaintext cookie. |

### Utility Functions

| File | Lines | Contents |
|---|---|---|
| `05-DateUtilities.ps1` | ~145 | `ConvertTo-NullableUtcIso8601`, `Get-DomainAgeDays`, `Get-DomainAgeParts`, `Format-DomainAge`, `Get-TimeUntilParts`, `Format-ExpiryRemaining` |
| `06-DmarcGuidance.ps1` | ~85 | `Get-DmarcSecurityGuidance` — analyzes DMARC records and produces security recommendations |
| `11-HttpHelpers.ps1` | ~175 | HTTP response helpers: `Set-SecurityHeaders`, `Write-Json`, `Write-FileResponse`, `Write-Html`. The CSP in `Get-SecurityHeaderMap` must keep `frame-src 'self' https://login.microsoftonline.com`: MSAL's `ssoSilent()` and `acquireTokenSilent()` renew tokens via a hidden iframe to the Entra authorize endpoint, so dropping `frame-src` makes the browser fall back to `default-src 'self'`, block the iframe, and fail silent SSO with `redirect_bridge_timeout`. Framing headers are `X-Frame-Options: SAMEORIGIN` and `frame-ancestors 'self'` (NOT `DENY`/`'none'`): Entra redirects MSAL's hidden iframe back to our own `redirectUri` (same origin), so the page must be allowed to frame itself; `SAMEORIGIN`/`'self'` still blocks all cross-origin clickjacking. The SPA also skips its full bootstrap when `window.self !== window.top` (running inside MSAL's hidden frame) and runs an MSAL-only init there. `connect-src` must likewise keep the Microsoft Graph / login / ARM / Log Analytics origins for the client-side auth + Azure flows. |
| `12-DnsResolution.ps1` | ~194 | DNS resolution via DoH plus detailed DNS record collection, reverse-lookup supplements, related-name supplements (ACS DKIM selectors, `_dmarc.<domain>`, `www.<domain>`) so well-known subdomains surface in the records grid, TTL formatting helpers, readable decoding for escaped DNS labels, authoritative fallback collection for records like `HINFO` and `RRSIG`, a one-shot `Get-DohDnssecAnomaly` probe (without `cd=1`) so the SPA can surface a friendly informational note when an upstream DNSSEC validation failure (e.g. malformed TLD RRSIG) is silently being worked around, a one-shot `Get-DohResolutionStatus` probe (TXT-typed, **with** `cd=1` so it mirrors the real lookup path and is therefore NOT a DNSSEC failure) that returns `{ status, statusLabel, isServfail, summary }` only on **SERVFAIL** (Status 2) so the SPA can distinguish a broken/propagating authoritative zone from a genuine \"no record\" \u2014 this is what fixes the \"SPF resolves in MXToolbox but shows No Records here\" split-nameserver case (e.g. `zenithbank.com`), and a fast System-resolver-to-DoH fallback inside `ResolveSafely` and `Resolve-DnsRecordsDetailed` that short-circuits when the System resolver returns SERVFAIL/timeout (Win32 9002/9701) so single-name multi-type lookups don't pay the 15s timeout per type on broken zones such as during `.de` DNSSEC outages. NXDOMAIN/no-records (9003/9501) is preserved as a fast negative answer. Functions: `Resolve-DohName`, `ResolveSafely`, `Get-DnsIpString`, `Get-MxRecordObjects`, `Get-DohDnssecAnomaly`, `Get-DohResolutionStatus`, `Get-DnsRecordsStatus`. `Get-DohResolutionStatus` is registered in `22-RunspaceSetup.ps1`. `Get-DnsBaseStatus` (`16-DnsChecks.ps1`) runs it only when no SPF record is found (queried + parent) and exposes the result as `txtResolution`; `18-AggregatedDns.ps1` adds the SERVFAIL summary to guidance and suppresses the misleading \"SPF is missing\"/\"ACS TXT is missing\" advice in that case; the SPF card, TXT card, and Email-Quota SPF row in `20d-HtmlJsCore.ps1` render a SERVFAIL-specific WARN (keys `spfServfailDetected`/`txtServfailDetected`/`guidanceTxtServfail` in `20b`). |
| `13-InputValidation.ps1` | ~69 | `ConvertTo-NormalizedDomain`, `Test-DomainName` — domain input sanitization |
| `15-RequestUtilities.ps1` | ~324 | `Write-RequestLog`, `Get-RequestCorrelationId`, `Set-RequestCorrelationHeader`, `Get-ClientIp`, `Test-IsTrustedProxy`, `Get-ApiKeyFromRequest`, `Test-StringEqualsConstantTime`, `Test-ApiKey`, `Test-RateLimit`. `Write-RequestLog` emits only structured non-PII request events through `Write-AcsLogEvent`; it must never log domains, IPs, user agents, headers, query strings, bodies, or user-entered values. `Test-RateLimit` accepts a clamped `-Multiplier` so cheap, high-frequency endpoints (such as `/api/metrics`) can share the per-IP bucket with a more generous effective limit. `Test-ApiKey` uses `Test-StringEqualsConstantTime` to defeat timing-based key recovery. |

### DNS Analysis

| File | Lines | Contents |
|---|---|---|
passes `Get-SpfOutlookRequirementStatus` returns `matchType = 'flattened-include'` with a detail string explaining that the upstream EOP ranges were detected inline. Canonical ranges are **never hard-coded** — they always come from the live `spf.protection.outlook.com` TXT record so the check stays correct as Microsoft updates its published ranges. A fifth path handles **macro-delegated** SPF: when the customer uses a hosted/dynamic SPF service that publishes a macro-based include (e.g. `include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email`), the Outlook authorization is resolved per message from the live sending IP/HELO/MAIL FROM and cannot be statically confirmed or denied. After the flattening coverage check fails, `Find-SpfMacroDelegatedTarget` (raw-token scan first, then the expanded include/redirect nodes) detects the macro target and `Get-SpfMacroDelegationProvider` maps its suffix to a provider name (Valimail, OnDMARC, Sendmarc, EasyDMARC, dmarcian, Red Sift). `Get-SpfOutlookRequirementStatus` then returns `isPresent = $null`, `matchType = 'macro-delegated'`, plus `provider`/`macroTarget` fields and a provider-aware `error` string. This indeterminate verdict propagates through `16-DnsChecks.ps1` (`spfRequiredIncludeProvider`, `spfRequiredIncludeMacroTarget`), `18-AggregatedDns.ps1`, and the UI, where the SPF card and Email-Quota SPF row render **WARN** (not FAIL) and `getLocalizedSpfRequirementSummary`/`buildGuidance` show the `spfOutlookRequirementMacroDelegated[Provider]` translation telling the operator to verify Exchange Online is enabled in the provider console. New functions `Get-SpfMacroDelegationProvider` and `Find-SpfMacroDelegatedTarget` are registered in `22-RunspaceSetup.ps1`. |
| `16-DnsChecks.ps1` | ~848 | Individual check endpoints: `Get-DnsBaseStatus`, `Get-DnsMxStatus`, `Get-DnsDmarcStatus`, `Get-DnsDkimStatus`, `Get-DnsCnameStatus` |
All five functions are registered in `22-RunspaceSetup.ps1`. The rendered `card-website` is captured by the existing full-page `screenshotPage`, so the snapshot appears in the exported PNG automatically. |
The four top-level functions are registered in `22-RunspaceSetup.ps1`; the nested socket/parse helpers inside `Invoke-RawDnsTxtQuery` are not. The rendered `card-nameservers` (with its collapsible `toggleNameserverDetails` panel) is captured by `screenshotPage`. The `/api/nameservers` payload is ALSO consumed by `getDnsTxtRecoveryState` (`20c-HtmlJsUtilities.ps1`) as a **third TXT-recovery source**: when `/api/base` + `/api/records` return no queried-domain TXT (the public DoH resolver returned an empty answer for this lookup — typically a transient SERVFAIL/timeout from the authoritative DNS, OR genuinely out-of-sync nameservers), the union of TXT records across responding (NOERROR) nameservers backfills the SPF/ACS/TXT cards. Such records are flagged `recoveredFromNameservers` and render **WARN** (never PASS) with the `*RecoveredFromNameservers` notes, and `acsReady` is forced false (Azure verifies via public DNS), so the cards stop contradicting this card while still telling the operator the record is not resolving publicly. IMPORTANT: the recovery notes must NOT assert the nameservers are inconsistent — the Nameserver TXT Consistency card frequently reports `consistent` because the failure is an intermittent authoritative SERVFAIL (observed live for `zenithbank.com`: ~1 in 4 Cloudflare DoH TXT lookups returns SERVFAIL while the nameservers serve identical records), so the copy describes both possible causes and points at that card. |
| `17-DnsReputation.ps1` | ~430 | RBL/DNSBL reputation checking with caching: `Invoke-RblLookup`, `Get-DnsReputationStatus`. DNSBL zones are validated and bounded (`ACS_RBL_MAX_ZONES`), only public IPv4 targets are queried, target IP fan-out is bounded (`ACS_RBL_MAX_IPS`), parallelism is configurable (`ACS_RBL_MAX_PARALLELISM`), DNSBL policy-block replies are counted as errors instead of listings, positive listings attempt to include provider TXT reason text, and result ordering is stable for deterministic UI/API output. Nested helper functions inside `Get-DnsReputationStatus` do not need runspace registration. |
| `18-AggregatedDns.ps1` | ~171 | `Get-AcsDnsStatus` — aggregates all DNS check results into one response, including the DNS records table payload. When picking a single value out of a possibly-array branch (e.g., `$effectiveSpf`, `$effectiveAcs`), always wrap the **entire** `if/else` expression in `@(...)`: PowerShell unwraps a single-element array returned from an `if` expression back into a scalar, so the previous `if (...) { @(...) } else { @($base.spfValue) }` form silently collapsed to the raw SPF string and `[0]` then indexed the first character (`"v"` instead of the full `v=spf1 ...` record). Likewise wrap `$effectiveTxtRecords`, `$effectiveIpv4Addresses`, and `$effectiveIpv6Addresses` with `@(if ...)` so a 1-element collection survives as an array. |

### Web Server

| File | Lines | Contents |
|---|---|---|
| `08-ServerStartup.ps1` | ~215 | HTTP listener startup (HttpListener → TcpListener fallback), enables `Console.TreatControlCAsInput` during server mode so Ctrl+C can be polled and return to the prompt cleanly, port probing helpers (`Test-LocalHttpEndpoint`, `Get-ListenerStartupErrorMessage`) |
| `19-CliMode.ps1` | ~28 | CLI-only path — calls `Get-AcsDnsStatus` and outputs JSON when `-TestDomain` is set |
| `22-RunspaceSetup.ps1` | ~155 | PowerShell runspace pool setup for concurrent DNS lookups; imports helper functions used during HTTP request handling |
| `23-RequestHandler.ps1` | ~398 | HTTP request router — maps URL paths to handler logic, including `/api/records` for the DNS records table and `/assets/*` for same-origin static asset delivery |
| `24-RequestLoop.ps1` | ~250 | Main HTTP listener loop — accepts connections via short async waits, polls Ctrl+C/Q console input for graceful shutdown, dispatches to handler, and suppresses expected listener-stop exceptions during shutdown |
| `25-Shutdown.ps1` | ~17 | Cleanup on exit — dispose listeners, restore Ctrl+C console mode, unregister Ctrl+C handler, runspace pool |

### Embedded Web UI (SPA)

The web UI is split across seven files that build the `$htmlPage` here-string via concatenation (`$htmlPage = @'...'@` then `$htmlPage += @'...'@):

| File | Lines | Contents |
|---|---|---|
| `20-HtmlCss.ps1` | ~1,026 | Initializes `$htmlPage`. Contains `<!DOCTYPE html>`, `<head>`, and all CSS styles through `</style>` |
| `20a-HtmlScriptSetup.ps1` | ~146 | External script tags (html2canvas CDN, MSAL loader), HTML `<body>` structure, main `<script>` tag opening with global JS variables. The MSAL loader uses a local-first source list (`/assets/msal-browser.min.js` first, then CDN fallbacks) and applies optional Subresource Integrity (SRI) hashes from the `__ACS_MSAL_SRI__` template token (operator-supplied via `ACS_MSAL_SRI` env var as a JSON object: `{"<src>":"sha384-..."}`). The inline early-focus safety-net script under the search input is nonce-bound (`nonce="__CSP_NONCE__"`) so it executes under the strict CSP without `'unsafe-inline'`. |
| `20b-HtmlTranslations.ps1` | ~5,000 | All JavaScript i18n data: `TRANSLATIONS`, `TRANSLATION_EXTENSIONS`, `REMAINING_TRANSLATION_OVERRIDES`, `MX_PROVIDER_HINTS`, `WHOIS_STATUS_LABELS`, `RISK_SUMMARY_LABELS`, `RUNTIME_TRANSLATION_OVERRIDES`, `GUIDANCE_AND_AZURE_OVERRIDES`, `EXPLAINED_TRANSLATION_OVERRIDES` (SPF/DMARC Explained tables, per-row Expansion Explain, CIDR info labels, prefix qualifiers, and mechanism/tag/value descriptions), language config constants. Latin-script languages (`es`, `fr`, `de`, `pt-BR`) ship the full 71-key set; non-Latin scripts (`ar`, `zh-CN`, `hi-IN`, `ja-JP`, `ru-RU`) ship the 25 user-visible UI labels (column headers, button labels, CIDR labels, empty/show/hide states) and let the longer descriptive sentences fall back to English via the existing `t()` chain. |
| `20c-HtmlJsUtilities.ps1` | ~1,269 | JavaScript utility functions: language switching, domain normalization/validation, cookie consent management, history management, HTML escaping, localization helpers, guidance text formatting, test summary |
highlights the dominant in-view section's link (`.section-rail-link-active`). The rail can be **collapsed** via a chevron button in its header (`toggleSectionRailCollapsed()`): when collapsed the rail gains `.section-rail-collapsed`, tucks flush to the left edge (`left:0`), and shows only a slim vertical "Jump to Section" tab (`.section-rail-expand`, a rotated label + arrow) to re-expand it. The collapsed state is persisted via `consentAwareSetItem`/`consentAwareGetItem` under the functional-category key `acsSectionRailCollapsed` (`SECTION_RAIL_COLLAPSED_KEY`) and re-applied on every render by `applySectionRailCollapsedState()`. For both navs every result card must expose a `card-...` id and a `<strong>` title — the Guidance (`card-guidance`), Helpful Links (`card-helpfulLinks`), and External Tools (`card-tools`) cards were given ids specifically so they appear. Translation keys: `jumpToSection`, `jumpToTag`, `jumpToSectionCollapse`, `jumpToSectionExpand`. CSS: `.section-nav-*` and `.section-rail-*` in `20-HtmlCss.ps1`. |
| `20e-HtmlAzureIntegration.ps1` | ~924 | Azure/MSAL authentication, ARM API calls, subscription/resource/workspace discovery, Log Analytics query execution, closing `</script></body></html>` |
| `20f-HtmlPostProcess.ps1` | ~22 | PowerShell template replacements: injects `__APP_VERSION__`, `__ENTRA_CLIENT_ID__`, `__ENTRA_TENANT_ID__`, `__ACS_API_KEY__`, `__ACS_ISSUE_URL__`, and `__ACS_MSAL_SRI__`. Every value substituted into a JS string literal is run through `ConvertTo-JsStringLiteralBody` to escape `\`, `'`, `"`, control characters, and angle brackets so a hostile env var can never break out of the literal or close the surrounding `<script>` block. `__ACS_MSAL_SRI__` is round-tripped through `ConvertFrom-Json`/`ConvertTo-Json` and falls back to the literal `null` on malformed input. |

### Static Pages

| File | Lines | Contents |
|---|---|---|
| `21-StaticPages.ps1` | ~473 | `$script:TosPageHtml` (Terms of Service) and `$script:PrivacyPageHtml` (Privacy Policy) — standalone HTML pages served at `/terms` and `/privacy`, including localized cookie-management links back into the SPA |

---

## Key Variables

| Variable | Scope | Defined In | Purpose |
|---|---|---|---|
| `$htmlPage` | local | `20-HtmlCss.ps1` | The full SPA HTML string (assembled across `20-*` files) |
| `$script:AppVersion` | script | `03-MetricsHashKey.ps1` | Application version string (e.g., `2.0.0`) |
| `$script:TosPageHtml` | script | `21-StaticPages.ps1` | Terms of Service HTML page |
| `$script:PrivacyPageHtml` | script | `21-StaticPages.ps1` | Privacy Policy HTML page |
| `$script:IsContainer` | script | `00-Header.ps1` | Whether running inside Docker |
| `$script:AcsMetrics` | script | `03-MetricsHashKey.ps1` | Anonymous metrics hashtable |

---

## Commonly Used Functions (cross-file)

These PowerShell functions are defined in one file but called from multiple other files:

| Function | Defined In | Called From |
|---|---|---|
| `ConvertTo-NullableUtcIso8601` | `05-DateUtilities.ps1` | `02-WhoisProviders.ps1`, `07-DomainRegistration.ps1` |
| `Get-DomainAgeDays` | `05-DateUtilities.ps1` | `07-DomainRegistration.ps1` |
| `ResolveSafely` | `12-DnsResolution.ps1` | `14-SpfAnalysis.ps1`, `16-DnsChecks.ps1`, `17-DnsReputation.ps1` |
| `Get-RegistrableDomain` | `01-DomainParsing.ps1` | `07-DomainRegistration.ps1`, `16-DnsChecks.ps1`, `18-AggregatedDns.ps1` |
| `Write-Json` | `11-HttpHelpers.ps1` | `03-MetricsHashKey.ps1`, `23-RequestHandler.ps1` |
| `Write-Html` | `11-HttpHelpers.ps1` | `23-RequestHandler.ps1` |
| `Set-SecurityHeaders` | `11-HttpHelpers.ps1` | `23-RequestHandler.ps1` |
| `Write-RequestLog` | `15-RequestUtilities.ps1` | `23-RequestHandler.ps1` |
| `Test-ApiKey` | `15-RequestUtilities.ps1` | `23-RequestHandler.ps1` |
| `Test-RateLimit` | `15-RequestUtilities.ps1` | `23-RequestHandler.ps1` |
| `Test-DomainName` | `13-InputValidation.ps1` | `23-RequestHandler.ps1` |
| `Get-ListenerStartupErrorMessage` | `08-ServerStartup.ps1` | `08-ServerStartup.ps1` (internal) |

---

## Encoding & i18n Notes

- All non-ASCII characters in JavaScript translation strings use `\uXXXX` Unicode escape sequences to prevent encoding corruption on non-UTF-8 locales.
- The `looksLikeMojibake()` function in `20c-HtmlJsUtilities.ps1` uses precise regex requiring continuation-byte chars (U+0080–U+00BF) after lead-byte chars to avoid corrupting valid accented characters (Portuguese, French, Spanish).
- Supported languages: English, Spanish, French, German, Arabic (RTL), Portuguese (Brazil), Chinese (Simplified), Hindi, Japanese, Russian.

---

## Docker

| File | Purpose |
|---|---|
| `Dockerfile.linux` | Linux container image |
| `Dockerfile.windows` | Windows container image |
| `acs-domain-checker-dockerhub.ps1` | Docker Hub variant (standalone) |

---

## Tips for Copilot / Contributors

1. **Never edit `acs-domain-checker.ps1` directly** — edit `src/` files and run `Build-Release.ps1 -Force`.
2. **Adding a new source file?** Name it with the appropriate number prefix to control load order (e.g., `16a-NewFeature.ps1` loads after `16-DnsChecks.ps1`).
3. **Translations live in `20b-HtmlTranslations.ps1`** — this is the largest file (~3,400 lines) because it contains all 10 language translations.
4. **CSS is in `20-HtmlCss.ps1`** — all styling for the web UI.
5. **The JavaScript `render()` function** is in `20d-HtmlJsCore.ps1` — this is the main function that builds the results UI after a domain lookup.
6. **API endpoint routing** is in `23-RequestHandler.ps1` — look here to understand which URL path maps to which handler.
7. **DNS check logic** for each record type is in `16-DnsChecks.ps1`.
Active highlight classes are `.spf-record-token-active`, `.spf-explained-row-active`, and `.spf-expansion-row-active`; preserve these names if the CSS is refactored. **CIDR info button**: ip4/ip6 rows in the SPF Explained table render a small `.spf-cidr-info-btn` "i" button beside the value that is **click-to-expand** (not hover); clicking it toggles a hidden sibling `<tr class="spf-cidr-detail-row">` placed directly under the same row, which renders the Network/CIDR prefix/Subnet mask/Range/Size breakdown inside `<pre class="spf-cidr-detail-pre">` (monospace + `white-space: pre`) so the padded labels stay column-aligned. Parsing lives in `parseSpfIpv4` / `parseSpfIpv6` (both use BigInt mask math so `/0` and `/128` survive), formatting lives in `formatSpfCidrInfo`, and the toggle is `toggleSpfCidrDetail(element, detailId)` in `20d-HtmlJsCore.ps1`. The button gets a `.spf-cidr-info-btn--open` class while expanded so CSS can visually indicate the open state. Unique detail-row ids are minted from the module-level `__spfCidrDetailCounter` so multiple SPF Explained panels on the page (the queried-domain panel plus every per-row Expansion Explain panel) never collide. The labels are translation keys (`spfCidrLabelNetwork`, `spfCidrLabelPrefix`, `spfCidrLabelMask`, `spfCidrLabelRange`, `spfCidrLabelSize`, `spfCidrLabelAddresses`, `spfCidrRangeThrough`); locales without overrides fall back to English via `t()`.
9. **If you add a new PowerShell function that can be called during HTTP request handling**, also add it to the `$functionNames` list in `22-RunspaceSetup.ps1` so it is imported into the runspace pool. **This is a required step** — server-side functions execute inside worker runspaces that only have the functions registered in `$functionNames`; calling an unregistered (non-nested) function from a request path throws "command not recognized" and surfaces to the user as an **HTTP 500 Internal Server Error** for that specific check (e.g. the Domain Registration / WHOIS row). Note that **nested** functions (defined inside another function's body) and the TcpListener-shim helpers in `24-RequestLoop.ps1` that run only in the main runspace do **not** need registration. After adding or removing any server-side function, run the registration audit and confirm it reports `PASS`:

   ```powershell
   pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Audit-RunspaceFunctions.ps1
   ```

   `tools/Audit-RunspaceFunctions.ps1` statically walks the call graph from the request-handler entry point (`$handlerScript` in `23-RequestHandler.ps1`), computes the transitive closure of reachable server-side functions, and diffs it against `$functionNames`. It correctly ignores nested functions and strips comments/strings to avoid false positives. Treat any "MISSING REGISTRATIONS" output as a build blocker.
9a. **Secure logging validation is mandatory for logging/diagnostics changes.** Runtime application logging must go through `Write-AcsLogEvent` / `Write-AcsLogException` only. Do not log domains, IP addresses, headers, query strings, request/response bodies, user-entered text, local paths, environment variables, raw exception messages, raw stack traces, tokens, cookies, API keys, tenant/subscription/account/customer identifiers, or serialized objects. Correlation IDs must come from `New-AcsCorrelationId` and must never be derived from request data. After changing logging, exception handling, request handling, startup/shutdown diagnostics, or log configuration, run:

   ```powershell
   pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-SecureLogging.ps1
   ```

   Treat any prohibited-pattern failure as a security blocker.
10. If substantial changes are done, increment the version number. For example, if it was version 1.0.1, increment to 1.0.2. If the changes are breaking, increment to 1.1.0, and if it's a major change, increment to 2.0.0. This is important for metrics and for users to understand the level of change in each release. When the version is updated, also update the version shown in GitHub workflows and in `README.md`, and keep Copilot instructions in sync.
11. If there are any substantial changes to the application, please update this document to reflect the new structure or logic! This is meant to be a living document that evolves with the codebase. With it being so large, it needs a guide to navigate effectively.
12. In the DNS records table UI, ensure the Name and Type columns do not wrap; keep them single-line and rely on horizontal scrolling for readability. The Type column header and values should always stay on one line and not wrap. TTL values should show raw seconds plus a compact abbreviated duration such as `5d 2h 33s` when applicable, omitting zero-value units like `0m` and `0s` unless needed for a zero-duration value. The DNS records table should remain searchable/filterable, support toggling yellow row highlighting for screenshot-ready troubleshooting, and use a removable filter-chip workflow beneath the search box for clearer multi-filter behavior. Enum-style `Class` and `Type` filtering should continue to use exact-match dropdown suggestions with keyboard navigation. Default ordering should be `Type`, then `Name`, then `Data`, with a post-sort step that splices CNAME->TXT chains together so a resolved TXT record (e.g., a DKIM public key on the CNAME target) is rendered immediately under the CNAME row that points at it (`reorderDnsCnameTxtChains` in `20d-HtmlJsCore.ps1`).
13. When routes, API behavior, configuration, or other user-facing functionality changes, update `README.md` in the same change so repository documentation stays current. Additionally, maintain Copilot instructions to keep documentation in sync.
14. Local UI assets such as toolbar/status SVG icons and language flag SVGs can be downloaded with `Download-UiAssets.ps1`. Keep that script in sync with the asset names referenced by `20b-HtmlTranslations.ps1` and `20c-HtmlJsUtilities.ps1`.
15. Make sure any code changes performed have sufficient comments surround it so its easy to understand the intent and logic when coming back to it later, especially for complex sections like the SPF recursive expansion or the HTTP request handling logic. This will help both human readers and Copilot understand the code better in the future.
16. When exposing raw RDAP data in the domain registration UI, prefer a digestible grouped presentation (status, events, nameservers, contacts, links, then expandable raw JSON) rather than showing only an undifferentiated JSON blob, favor polished summary/timeline/card layouts over plain bullet lists when possible, and order RDAP events chronologically. In the Guidance section, avoid surfacing terminal DNS TXT timeout guidance until the lookup workflow has settled, and suppress that specific message when the detailed DNS records payload already confirms TXT records were collected. Likewise, TXT-dependent checks/cards and the Domain card address view should recover from the detailed DNS records payload when the dedicated base lookup data is incomplete but queried-domain DNS records are still available there.
17. **Screenshot capture (`screenshotPage` in `20c-HtmlJsUtilities.ps1`)**: the page is rendered at `html { zoom: 1.1 }` (in `20-HtmlCss.ps1`), but html2canvas 1.4.1 does **not** support the CSS `zoom` property — it measures boxes with zoom applied but paints glyphs un-zoomed, which garbles dense monospace content (e.g. base64 DKIM keys). The capture therefore resets `clonedDoc.documentElement.style.zoom = "1"` in the `onclone` hook and compensates with `scale = devicePixelRatio * pageZoom` so the output stays crisp. If you change the page zoom or upgrade html2canvas, re-validate the screenshot output. The Clipboard API write can reject (lost focus during the multi-second render, or a non-secure `http://` origin); `screenshotPage` re-focuses the window and **falls back to downloading the PNG** (`screenshotDownloadedFallback` translation) instead of dead-ending, so only require `window.html2canvas` up front, not the Clipboard API.
18. **Customer Intake form i18n (`20d-HtmlJsCore.ps1`)**: the intake questionnaire is localized via the `INTAKE_LOCALES` data table (keyed by language code; non-ASCII `\uXXXX`-escaped per repo convention). Each locale supplies section headers, per-field canonical question text (which doubles as both the inserted template line AND a primary extraction pattern so the two never drift), clarifier strings, and the replace-confirm prompt. `buildIntakeTemplateHtml(lang)` renders the localized **Insert template** output (mirrors the English `INTAKE_TEMPLATE_HTML` structure, `escapeHtml`-guarded, falls back to English for `en`/unsupported); `prefillIntakeForm()` calls it with `currentLanguage`. Extraction is **additive**: the `augmentIntakeExtractionForLocales()` IIFE merges every locale's question text into the matching `INTAKE_EXTRACT_FIELDS[].patterns` and builds `INTAKE_LOCALIZED_SECTION_HEADERS` (consumed by `isIntakeSectionHeader`) + `INTAKE_LOCALIZED_MARKERS` (appended to the `normalizeIntakePlainText` split markers, longest-first) — the English matching is never weakened. `parseIntakeNumeric` normalizes Arabic-Indic/Eastern Arabic-Indic/Devanagari/full-width digits to ASCII so localized numeric answers still drive throttling-tier inference. The extracted-field **labels** and the **Copy Email Quota** payload deliberately stay English (the canonical ACS questionnaire); only the inserted editor template and the recognized question phrasings are localized — the form does NOT machine-translate the customer's answer values. The extracted **Type of emails sent**, **Current tier level**, and **Expected tier level** rows use English dropdown suggestion values from `INTAKE_FIELD_OPTIONS` / `INTAKE_TIERS` only when empty, but the cell stays editable so custom text is always allowed; tier rows expose an `intake-tier-info-btn` that toggles the `buildIntakeTierTableHtml()` reference table. To add/adjust a language, edit `INTAKE_LOCALES` (author UTF-8 then `\u`-escape) and rebuild; no extractor changes are needed because the augmentation is data-driven.
