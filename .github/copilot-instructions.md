# Copilot Instructions — ACS Email Domain Checker

> **Purpose**: Guide GitHub Copilot (and developers) through the codebase structure so you know where to look, what each file does, and how the build pipeline works.

---

## Architecture Overview

This is a **single-file PowerShell web application** that runs a local HTTP server to check DNS records for Azure Communication Services email domain verification. The web UI is a Single Page Application (SPA) embedded directly inside the PowerShell script as a here-string.

### Runtime flow

1. **CLI mode** (`-TestDomain example.com`): runs DNS checks, outputs JSON, and exits.
2. **Server mode** (default): starts an HTTP listener, serves the SPA UI, and exposes routes such as `/`, `/index.html`, `/dns`, `/api/base`, `/api/mx`, `/api/records`, `/api/whois`, `/api/dmarc`, `/api/dkim`, `/api/cname`, `/api/reputation`, `/api/metrics`, `/api/auth/verify`, `/terms`, and `/privacy`.

---

## Build System

| File | Purpose |
|---|---|
| `Build-Release.ps1` | Concatenates all `src/*.ps1` files (sorted by filename) into the monolithic `acs-domain-checker.ps1`. |

### How to rebuild

```powershell
pwsh -NoProfile -File ./Build-Release.ps1 -Force
```

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
| `01-DomainParsing.ps1` | ~77 | `Get-RegistrableDomain`, `Get-ParentDomains` — extract registrable domain from FQDN |
| `02-WhoisProviders.ps1` | ~614 | Three WHOIS backends: `Invoke-SysinternalsWhoisLookup` (Windows), `Invoke-LinuxWhoisLookup` (Linux), `Invoke-TcpWhoisLookup` (raw TCP fallback) |
| `04-RdapLookups.ps1` | ~225 | RDAP protocol lookups (`Invoke-RdapLookup`), plus WhoisXML and GoDaddy API fallbacks |
| `07-DomainRegistration.ps1` | ~405 | `Get-DomainRegistrationStatus` — orchestrates RDAP → WHOIS → API fallback chain, returns creation/expiry dates; expose raw RDAP data when available. If raw WHOIS/RDAP data is the only available content, show it inline without a Raw button; only show the Raw WHOIS/RDAP button when structured WHOIS/RDAP fields are also present and the raw content is hidden behind a collapsible section. |

### Metrics & Configuration

| File | Lines | Contents |
|---|---|---|
| `03-MetricsHashKey.ps1` | ~117 | `$script:AppVersion` (currently `2.0.44`), metrics hash key persistence, `Get-HashedDomain`, `Handle-MetricsRequest` |
| `09-AnonymousMetrics.ps1` | ~361 | Optional anonymous usage metrics — persistence, aggregation counters, file I/O |
| `10-SessionCookies.ps1` | ~288 | Anonymous session tracking, session cookie management, `Update-AnonymousMetrics` |

### Utility Functions

| File | Lines | Contents |
|---|---|---|
| `05-DateUtilities.ps1` | ~145 | `ConvertTo-NullableUtcIso8601`, `Get-DomainAgeDays`, `Get-DomainAgeParts`, `Format-DomainAge`, `Get-TimeUntilParts`, `Format-ExpiryRemaining` |
| `06-DmarcGuidance.ps1` | ~85 | `Get-DmarcSecurityGuidance` — analyzes DMARC records and produces security recommendations |
| `11-HttpHelpers.ps1` | ~175 | HTTP response helpers: `Set-SecurityHeaders`, `Write-Json`, `Write-FileResponse`, `Write-Html` |
| `12-DnsResolution.ps1` | ~194 | DNS resolution via DoH plus detailed DNS record collection, reverse-lookup supplements, TTL formatting helpers, readable decoding for escaped DNS labels, and authoritative fallback collection for records like `HINFO` and `RRSIG`: `Resolve-DohName`, `ResolveSafely`, `Get-DnsIpString`, `Get-MxRecordObjects`, `Get-DnsRecordsStatus` |
| `13-InputValidation.ps1` | ~69 | `ConvertTo-NormalizedDomain`, `Test-DomainName` — domain input sanitization |
| `15-RequestUtilities.ps1` | ~170 | `Write-RequestLog`, `Get-ClientIp`, `Get-ApiKeyFromRequest`, `Test-ApiKey`, `Test-RateLimit` |

### DNS Analysis

| File | Lines | Contents |
|---|---|---|
| `14-SpfAnalysis.ps1` | ~824 | Deep SPF record analysis — recursive expansion, Outlook requirement matching, guidance generation |
| `16-DnsChecks.ps1` | ~848 | Individual check endpoints: `Get-DnsBaseStatus`, `Get-DnsMxStatus`, `Get-DnsDmarcStatus`, `Get-DnsDkimStatus`, `Get-DnsCnameStatus` |
| `17-DnsReputation.ps1` | ~372 | RBL/DNSBL reputation checking with caching: `Invoke-RblLookup`, `Get-DnsReputationStatus` |
| `18-AggregatedDns.ps1` | ~171 | `Get-AcsDnsStatus` — aggregates all DNS check results into one response, including the DNS records table payload |

### Web Server

| File | Lines | Contents |
|---|---|---|
| `08-ServerStartup.ps1` | ~215 | HTTP listener startup (HttpListener → TcpListener fallback), port probing helpers (`Test-LocalHttpEndpoint`, `Get-ListenerStartupErrorMessage`) |
| `19-CliMode.ps1` | ~28 | CLI-only path — calls `Get-AcsDnsStatus` and outputs JSON when `-TestDomain` is set |
| `22-RunspaceSetup.ps1` | ~132 | PowerShell runspace pool setup for concurrent DNS lookups; imports helper functions used during HTTP request handling |
| `23-RequestHandler.ps1` | ~398 | HTTP request router — maps URL paths to handler logic, including `/api/records` for the DNS records table |
| `24-RequestLoop.ps1` | ~250 | Main HTTP listener loop — accepts connections, dispatches to handler |
| `25-Shutdown.ps1` | ~17 | Cleanup on exit — dispose listeners, runspace pool |

### Embedded Web UI (SPA)

The web UI is split across seven files that build the `$htmlPage` here-string via concatenation (`$htmlPage = @'...'@` then `$htmlPage += @'...'@):

| File | Lines | Contents |
|---|---|---|
| `20-HtmlCss.ps1` | ~1,026 | Initializes `$htmlPage`. Contains `<!DOCTYPE html>`, `<head>`, and all CSS styles through `</style>` |
| `20a-HtmlScriptSetup.ps1` | ~146 | External script tags (html2canvas CDN, MSAL loader), HTML `<body>` structure, main `<script>` tag opening with global JS variables |
| `20b-HtmlTranslations.ps1` | ~3,431 | All JavaScript i18n data: `TRANSLATIONS`, `TRANSLATION_EXTENSIONS`, `REMAINING_TRANSLATION_OVERRIDES`, `MX_PROVIDER_HINTS`, `WHOIS_STATUS_LABELS`, `RISK_SUMMARY_LABELS`, `RUNTIME_TRANSLATION_OVERRIDES`, `GUIDANCE_AND_AZURE_OVERRIDES`, language config constants |
| `20c-HtmlJsUtilities.ps1` | ~1,269 | JavaScript utility functions: language switching, domain normalization/validation, history management, HTML escaping, localization helpers, guidance text formatting, test summary |
| `20d-HtmlJsCore.ps1` | ~1,385 | Core UI JavaScript: theme toggle, clipboard/copy, screenshot capture, `lookup()`, `render()`, `card()`, event listeners, initialization |
| `20e-HtmlAzureIntegration.ps1` | ~924 | Azure/MSAL authentication, ARM API calls, subscription/resource/workspace discovery, Log Analytics query execution, closing `</script></body></html>` |
| `20f-HtmlPostProcess.ps1` | ~22 | PowerShell template replacements: injects `__APP_VERSION__`, `__ENTRA_CLIENT_ID__`, `__ENTRA_TENANT_ID__`, `__ACS_API_KEY__`, `__ACS_ISSUE_URL__` |

### Static Pages

| File | Lines | Contents |
|---|---|---|
| `21-StaticPages.ps1` | ~473 | `$script:TosPageHtml` (Terms of Service) and `$script:PrivacyPageHtml` (Privacy Policy) — standalone HTML pages served at `/terms` and `/privacy` |

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
8. **SPF analysis** (recursive expansion, guidance) is in `14-SpfAnalysis.ps1`.
9. **If you add a new PowerShell function that can be called during HTTP request handling**, also add it to the `$functionNames` list in `22-RunspaceSetup.ps1` so it is imported into the runspace pool.
10. If substantial changes are done, increment the version number. For example, if it was version 1.0.1, increment to 1.0.2. If the changes are breaking, increment to 1.1.0, and if it's a major change, increment to 2.0.0. This is important for metrics and for users to understand the level of change in each release. When the version is updated, also update the version shown in GitHub workflows and in `README.md`, and keep Copilot instructions in sync.
11. If there are any substantial changes to the application, please update this document to reflect the new structure or logic! This is meant to be a living document that evolves with the codebase. With it being so large, it needs a guide to navigate effectively.
12. In the DNS records table UI, ensure the Name and Type columns do not wrap; keep them single-line and rely on horizontal scrolling for readability. The Type column header and values should always stay on one line and not wrap. TTL values should show raw seconds plus a compact abbreviated duration such as `5d 2h 33s` when applicable, omitting zero-value units like `0m` and `0s` unless needed for a zero-duration value. The DNS records table should remain searchable/filterable, support toggling yellow row highlighting for screenshot-ready troubleshooting, and use a removable filter-chip workflow beneath the search box for clearer multi-filter behavior. Enum-style `Class` and `Type` filtering should continue to use exact-match dropdown suggestions with keyboard navigation. Default ordering should be `Type`, then `Name`, then `Data`.
13. When routes, API behavior, configuration, or other user-facing functionality changes, update `README.md` in the same change so repository documentation stays current. Additionally, maintain Copilot instructions to keep documentation in sync.
14. Make sure any code changes performed have sufficient comments surround it so its easy to understand the intent and logic when coming back to it later, especially for complex sections like the SPF recursive expansion or the HTTP request handling logic. This will help both human readers and Copilot understand the code better in the future.
15. When exposing raw RDAP data in the domain registration UI, prefer a digestible grouped presentation (status, events, nameservers, contacts, links, then expandable raw JSON) rather than showing only an undifferentiated JSON blob, favor polished summary/timeline/card layouts over plain bullet lists when possible, and order RDAP events chronologically. In the Guidance section, avoid surfacing terminal DNS TXT timeout guidance until the lookup workflow has settled, and suppress that specific message when the detailed DNS records payload already confirms TXT records were collected. Likewise, TXT-dependent checks/cards and the Domain card address view should recover from the detailed DNS records payload when the dedicated base lookup data is incomplete but queried-domain DNS records are still available there.
