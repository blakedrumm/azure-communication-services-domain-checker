# 🌐 Azure Communication Services - Domain Checker Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

## 📖 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Quick Start (Local)](#-quick-start-local)
- [Quick Start (Docker)](#-quick-start-docker)
- [Command-Line Test Mode](#-command-line-test-mode)
- [Web UI Features](#-web-ui-features)
- [Localization / Multi-Language Support](#-localization--multi-language-support)
- [DNS Checks & Guidance](#-dns-checks--guidance)
- [DNSBL Reputation Checks](#-dnsbl-reputation-checks)
- [WHOIS / RDAP Diagnostics](#-whois--rdap-diagnostics)
- [API Endpoints](#-api-endpoints)
- [Authentication](#-authentication)
- [Configuration (Environment Variables)](#-configuration-environment-variables)
- [Issue Reporting](#-issue-reporting)
- [MSAL Browser Library Updates](#-msal-browser-library-updates)
- [Docker Hub Deployment](#-docker-hub-deployment)
- [External Repository Sync](#-external-repository-sync)
- [Terms of Service & Privacy Pages](#-terms-of-service--privacy-pages)
- [Security Notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Build & Local UI Assets](#-build--local-ui-assets)
- [Contributing](#-contributing)
- [License](#-license)

## 📋 Overview
`acs-domain-checker` is a powerful, single-file PowerShell web UI + REST API designed to validate Azure Communication Services (ACS) email domain readiness. It provides comprehensive DNS record verification including TXT/SPF, MX, DMARC, DKIM, and CNAME records, performs optional DNSBL reputation checks, and includes WHOIS/RDAP diagnostics for complete domain analysis.

**Perfect for:**
- 🏢 System administrators configuring ACS email domains
- 🔧 DevOps engineers automating domain verification
- 🧪 Developers testing email domain configurations
- 📊 IT teams troubleshooting domain setup issues

## ✨ Features
- 🚀 **Single-file PowerShell HTTP server** with an embedded SPA UI - no complex setup required!
- 🔍 **Comprehensive DNS checks:**
  - Root TXT/SPF records validation
  - ACS-specific verification TXT records (`ms-domain-verification`)
  - MX records with A/AAAA resolution and mail provider detection
  - DMARC policy verification (including inherited parent-domain DMARC)
  - DKIM selector validation (`selector1-azurecomm-prod-net`, `selector2-azurecomm-prod-net`)
  - CNAME record checks (root and `www` prefix)
- 🛡️ **DNSBL reputation lookup** with parallel queries and intelligent caching
- 🌍 **WHOIS/RDAP diagnostics** with multiple fallback providers (Sysinternals, Linux CLI, TCP whois, GoDaddy, WhoisXML, RDAP)
  - Raw WHOIS/RDAP source text can be opened from the Domain Registration card whenever raw provider output is available
- 🔐 **Optional API key authentication** and per-IP rate limiting
- 📊 **Anonymous metrics collection** (HMAC-hashed domains only, privacy-first)
- 👤 **Microsoft Entra ID sign-in** support for employee verification
- 🐳 **Container-ready** with Linux and Windows Dockerfiles
- ⚡ **Fast and lightweight** - minimal resource footprint
- 🎨 **Modern, responsive UI** - dark/light theme toggle, search history chips, shareable links, screenshot export, and JSON download
  - Direct `?domain=` URLs auto-run the lookup on initial page load for shareable troubleshooting links
  - A **Jump to Section** navigation card at the top of the results lists every returned card (Domain Registration, Domain, DNS records, MX, SPF, SPF Expansion, ACS Domain Verification TXT, etc.) and smooth-scrolls to the selected one
  - Intro sections start hidden so the top-bar/search-box sequence fades in cleanly without an initial flash before the animation begins
  - Top-bar controls and header sections use staged fade-in animations on page load, while lookup refreshes animate only the lower result sections
- 🧾 **Detailed DNS records table** - DomainDossier-style dataset with reverse-lookup supplements, DNSSEC record details, and expanded TTL formatting (`seconds (5d 2h 33s)` style when applicable)
  - Searchable/filterable table controls plus click-to-toggle yellow row highlighting for screenshot-ready customer troubleshooting
  - DNS records filtering uses removable filter chips beneath the search box for clearer multi-filter workflows, with exact-match dropdown suggestions for `Class` and `Type` values and keyboard navigation for faster filtering
  - Default table ordering is `Type`, then `Name`, then `Data` for easier record-family scanning
  - DNS records toolbar controls use the main UI font and aligned label/control rows instead of inheriting the monospace styling from the surrounding code container
  - DNS records search input explicitly overrides the broader `input[type=text]` styling so it stays visually aligned with the adjacent column selector
  - Active DNS records filter chips render on their own row beneath the search column so the search field stays visually clean while the toolbar remains aligned
  - DNS record `Name`, `Type`, and column headers stay single-line, with horizontal scrolling used on narrow layouts
  - Escaped DNS labels in display-oriented values (for example DNSSEC `NSEC` next-domain names like `\000`) are decoded into readable markers such as `[NUL]`
  - Includes richer `HINFO` and `RRSIG` coverage by using DNSSEC-aware lookups and authoritative fallback queries when direct recursive lookups omit those records
  - Raw RDAP output is grouped into digestible sections such as status, events, nameservers, contacts, and links before the full JSON view, with polished summary tiles and timeline/card layouts for easier review; RDAP events are displayed chronologically for clearer reading
  - Guidance waits for the lookup workflow to settle before surfacing terminal TXT timeout messaging, and suppresses that specific error when the detailed DNS records payload already confirms TXT results were collected
  - TXT/SPF/ACS verification cards and check summaries recover from the detailed DNS records payload when the dedicated base TXT lookup times out but DNS records already prove the queried-domain TXT values were collected
  - The TXT recovery view-model is shared by `render()` and the derived guidance/check-summary helpers so lookups continue rendering instead of failing client-side when the recovery state is available
  - The Domain card also recovers queried-domain `A` and `AAAA` addresses from the detailed DNS records payload so it stays consistent with the DNS records table when base lookup data is incomplete
  - Consolidates duplicate DNS rows from mixed resolver sources and keeps the strongest TTL for each unique record/value pair
- 🌍 **Multi-language support** - 10 languages with RTL support, language picker dropdown, and `?lang=` URL parameter
- 💻 **Command-line test mode** (`-TestDomain`) for one-shot headless domain validation

## 📦 Prerequisites

Before running the ACS Domain Checker, ensure you have:

- **PowerShell 5.1+** (Windows) or **PowerShell Core 7+** (cross-platform)
  - Windows: Pre-installed on Windows 10/11 and Windows Server 2016+
  - macOS/Linux: [Install PowerShell Core](https://github.com/PowerShell/PowerShell#get-powershell)
- **Docker** (optional, for containerized deployment)
  - [Download Docker Desktop](https://www.docker.com/products/docker-desktop)
- **Network access** to query DNS servers and WHOIS/RDAP services
- **Port 8080** available (or specify a custom port)

## 🚀 Quick Start (Local)

Running the application locally is simple and quick:

### Step 1: Clone the Repository
```bash
git clone https://github.com/blakedrumm/azure-communication-services-domain-checker.git
cd azure-communication-services-domain-checker
```

### Step 2: Run the Application
```powershell
# Run the UI and API on the default port (8080)
./acs-domain-checker.ps1
```

### Step 3: Access the Web UI
Open your web browser and navigate to:
```
http://localhost:8080
```

🎉 **That's it!** You can now start checking your domains.

### 🔧 Advanced Options
```powershell
# Run on a custom port
./acs-domain-checker.ps1 -Port 9000

# Bind to all network interfaces (useful for remote access)
./acs-domain-checker.ps1 -Bind Any

# Run with API key authentication
$env:ACS_API_KEY = "your-secret-key"
./acs-domain-checker.ps1
```

## 🐳 Quick Start (Docker)

Run the application in a Docker container for isolation and portability:

### 🐧 Linux Container
```bash
# Build the Docker image
docker build -f Dockerfile.linux -t acs-domain-checker .

# Run the container
docker run --rm -p 8080:8080 \
  -e ACS_API_KEY=your-secret-key \
  acs-domain-checker
```

### 🪟 Windows Container
```powershell
# Build the Docker image
docker build -f Dockerfile.windows -t acs-domain-checker:windows .

# Run the container
docker run --rm -p 8080:8080 `
  -e ACS_API_KEY=your-secret-key `
  acs-domain-checker:windows
```

### 🌐 Access the Application
Once the container is running, open your browser to:
```
http://localhost:8080
```

## 💻 Command-Line Test Mode

The `-TestDomain` parameter runs a one-shot domain validation without starting the HTTP server. This is useful for scripting, CI pipelines, or quick headless checks:

```powershell
# Validate a domain and output the results as JSON to stdout
./acs-domain-checker.ps1 -TestDomain example.com
```

**Example output:**
```json
{
  "domain": "example.com",
  "spfPresent": true,
  "acsTextPresent": false,
  "mxRecords": [...],
  "dmarcPresent": true,
  "dkim1": false,
  "dkim2": false,
  "reputation": { "riskLevel": 0, "rating": "Excellent" },
  "guidance": ["ACS verification TXT record (ms-domain-verification) is missing."],
  ...
}
```

The process exits with code `0` on success (domain info returned) or `1` on error. This makes it straightforward to integrate with automation workflows.

## 🎨 Web UI Features

The embedded single-page application includes a rich set of interactive features:

| Feature | Description |
|---------|-------------|
| 🌙 **Dark / Light theme** | Toggle between dark and light mode; preference is saved in `localStorage` |
| 🕑 **Search history** | Recent domain lookups appear as dismissible chips below the search box |
| 🔗 **Copy shareable link** | Copies a permalink to the current domain lookup so you can share it with teammates |
| 📥 **Download JSON report** | Downloads the full aggregated DNS check result as a `.json` file |
| 📸 **Copy page screenshot** | Captures the results page to the clipboard using `html2canvas` |
| 🐛 **Report issue button** | Visible after a lookup; opens the configured issue tracker with domain pre-filled |
| 📋 **Email Quota checklist** | Summary card showing MX, Reputation, Registration, and SPF pass/fail status |
| ✅ **Domain Verification checklist** | Shows whether the ACS verification TXT record and ACS readiness criteria are met |
| 🔑 **Microsoft sign-in** | Optional Entra ID sign-in for employee verification via MSAL |
| 🌍 **Multi-language UI** | 10 languages with a flag-icon dropdown; preference saved in `localStorage` and shareable via `?lang=` |
| 📄 **Terms of Service & Privacy** | Embedded `/terms` and `/privacy` pages, localized into all supported languages |

## 🌍 Localization / Multi-Language Support

The web UI is fully translated into **10 languages**. Users can switch languages at any time using the dropdown in the top bar. The selected language is persisted in `localStorage` and can also be set via the `?lang=` query parameter for shareable links.

### Supported Languages

| Code | Language | Direction |
|------|----------|-----------|
| `en` | English | LTR |
| `es` | Español | LTR |
| `fr` | Français | LTR |
| `de` | Deutsch | LTR |
| `pt-BR` | Português (Brasil) | LTR |
| `ar` | العربية | **RTL** |
| `zh-CN` | 中文（简体） | LTR |
| `hi-IN` | हिन्दी (भारत) | LTR |
| `ja-JP` | 日本語（日本） | LTR |
| `ru-RU` | Русский (Россия) | LTR |

### Setting the Language

```
# Via URL query parameter
http://localhost:8080/?lang=es

# The language picker in the top bar also sets this automatically.
# Arabic (ar) activates right-to-left layout automatically.
```

The `/terms` and `/privacy` pages also respect the `?lang=` parameter and render in the selected language.

## 🔍 DNS Checks & Guidance

The tool performs the following DNS checks and generates actionable guidance strings for any issues found:

| Check | DNS Record(s) | ACS Requirement |
|-------|--------------|-----------------|
| **SPF** | Root `TXT` | Must include ACS SPF policy |
| **ACS Verification TXT** | Root `TXT` | `ms-domain-verification=<value>` must be present |
| **MX** | `MX` + `A`/`AAAA` | Valid MX records required; mail provider detected automatically |
| **DMARC** | `_dmarc.<domain>` `TXT` | Recommended for deliverability; inherited from parent domain if absent |
| **DKIM selector 1** | `selector1-azurecomm-prod-net._domainkey.<domain>` `TXT` | Required for ACS email signing |
| **DKIM selector 2** | `selector2-azurecomm-prod-net._domainkey.<domain>` `TXT` | Required for ACS email signing |
| **CNAME** | Root + `www` `CNAME` | Informational; conflicts may prevent domain use |

Mail provider detection recognizes Microsoft 365, Google Workspace, Zoho, Proofpoint, Mimecast, and Cloudflare Email Routing out of the box.

A separate **SPF Expansion Records** card sits directly below the SPF card and lists every `include:` / `redirect=` target the recursive SPF resolver visited, the parent record that referenced it, and the actual TXT record returned by each lookup. This keeps the main DNS Records table scoped to the queried domain while still surfacing the third-party SPF chain (for example `_u.<domain>._spf.smart.ondmarc.com`, `spf.protection.outlook.com`, `_spf.google.com`) for troubleshooting. The expansion card also reports a per-row "Lookups" contribution and a chain-wide "N of 10 DNS lookups used" summary against the SPF 10-lookup limit (RFC 7208 §4.6.4). Because the structured table now owns the expansion view, the SPF card itself is intentionally kept lean: it shows just the queried-domain SPF record value and the ACS Outlook-include verdict, without duplicating the indented per-node text dump that older versions appended.

## 🛡️ DNSBL Reputation Checks

The `/api/reputation` endpoint queries multiple DNS-based Block Lists (DNSBLs) to assess the sending reputation of IP addresses associated with a domain's MX records.

### Default DNSBL Zones

| Zone | Provider |
|------|---------|
| `bl.spamcop.net` | SpamCop |
| `b.barracudacentral.org` | Barracuda Reputation Block List |
| `psbl.surriel.com` | Passive Spam Block List (PSBL) |
| `dnsbl.dronebl.org` | DroneBL |
| `bl.0spam.org` | 0spam (block list) |
| `rbl.0spam.org` | 0spam (reputation block list) |

### Custom DNSBL Zones

Override the defaults by setting `ACS_RBL_ZONES` to a comma-, semicolon-, or newline-delimited list of DNSBL zone names:

```powershell
$env:ACS_RBL_ZONES = "zen.spamhaus.org,bl.spamcop.net"
./acs-domain-checker.ps1
```

### Reputation Ratings

| Rating | Threshold | Risk Level |
|--------|-----------|-----------|
| 🟢 **Excellent** | ≥ 99 % clean | 0 |
| 🟢 **Great** | ≥ 90 % clean | 0 |
| 🟡 **Good** | ≥ 75 % clean | 1 (Warning) |
| 🟠 **Fair** | ≥ 50 % clean | 2+ (Elevated Risk) |
| 🔴 **Poor** | < 50 % clean | 2+ (Elevated Risk) |

## 🌍 WHOIS / RDAP Diagnostics

The tool enriches results with domain registration metadata (creation date, expiry, registrar, domain age) using a priority-ordered chain of fallback providers:

| Priority | Provider | Requires |
|----------|----------|---------|
| 1 | **RDAP** _(preferred)_ | None (uses IANA bootstrap + built-in TLD map for restrictive registries such as `.ch`/`.li`/`.de`/`.fr`/`.nl`/`.eu` + rdap.org fallback) |
| 2 | **GoDaddy API** | `GODADDY_API_KEY` + `GODADDY_API_SECRET` |
| 3 | **Linux whois CLI** | `LINUX_WHOIS_PATH` (Linux/macOS only) |
| 4 | **Sysinternals whois.exe** | `SYSINTERNALS_WHOIS_PATH` (Windows only) |
| 5 | **TCP whois** | None (pure PowerShell TCP client, port 43) |
| 6 | **WhoisXML API** | `ACS_WHOISXML_API_KEY` |

WHOIS data is used to populate the **Email Quota** checklist and to surface warnings for expired or newly-registered domains.

Registry refusal/rate-limit responses (for example SWITCH's `Requests of this client are not permitted` message for `.ch`/`.li`, or DENIC/AFNIC excessive-query notices) are detected and treated as a hard provider failure so the lookup chain continues to the next provider instead of presenting the block text as the registration record.

Several country-code registries deliberately omit domain expiry dates from public lookups (SWITCH for `.ch`/`.li`, DENIC for `.de`, EURid for `.eu`, SIDN for `.nl`, AFNIC for `.fr` and its overseas TLDs, auDA for `.au`). When the lookup succeeds but expiry is unavailable for one of these TLDs, the response includes a structured `expiryUnavailableReason` field and the Domain Registration card surfaces a short explanatory note so the missing date is not misread as a lookup failure.

The WHOIS normalization layer also recognizes registry-specific labels used by providers such as EDUCAUSE for `.edu` domains, including `Domain record activated`, `Domain expires`, and block-style `Registrant:` sections.

## 🔌 API Endpoints

The application exposes the following RESTful API endpoints:

| Endpoint | Description | 📝 Purpose |
|----------|-------------|------------|
| `/` | Web UI | Interactive single-page application for domain checking |
| `/dns` | Aggregated readiness JSON | Complete DNS readiness report for a domain |
| `/api/base` | Root TXT/SPF/ACS TXT | Validates SPF and ACS verification TXT records |
| `/api/mx` | MX + A/AAAA resolution | Checks mail exchange records and IP resolution |
| `/api/records` | Raw DNS records table payload | Returns the detailed DNS records dataset used by the UI table, including reverse-lookup supplements and TTL seconds for expanded display formatting |
| `/api/whois` | WHOIS / RDAP registration | Returns domain registration data (creation, expiry, registrar) |
| `/api/dmarc` | DMARC records | Validates DMARC email authentication policy |
| `/api/dkim` | DKIM selectors | Checks DomainKeys Identified Mail signatures |
| `/api/cname` | CNAME records | Validates canonical name records |
| `/api/reputation` | DNSBL reputation | Checks domain reputation against DNS blocklists |
| `/api/metrics` | Anonymous metrics | Returns aggregated usage metrics (if enabled) |
| `/api/auth/event` | Anonymous Microsoft Entra ID sign-in ping | Header-only, consent-gated. SPA POSTs an opaque SHA-256 account hash and a Microsoft-employee boolean after client-side MSAL/Graph verification; the server never sees access tokens, UPN, oid, or tenant id. |
| `/terms` | Terms of Service | Embedded, localized Terms of Service page |
| `/privacy` | Privacy Statement | Embedded, localized Privacy Statement page |

### 📖 Example API Usage
```bash
# Check complete DNS readiness for a domain
curl "http://localhost:8080/dns?domain=example.com"

# Check only MX records
curl "http://localhost:8080/api/mx?domain=example.com"

# With API key authentication
curl -H "X-Api-Key: your-secret-key" "http://localhost:8080/dns?domain=example.com"
```

## 🔐 Authentication

Protect your API endpoints with API key authentication:

If `ACS_API_KEY` environment variable is set, API endpoints require authentication via:

- **✅ Recommended - Header:** `X-Api-Key: <your-key>`
- **⚠️ Less Secure - Query Parameter:** `?apiKey=<your-key>` (avoid in production)

### 🔑 Setting Up Authentication
```powershell
# Set API key for the session
$env:ACS_API_KEY = "your-secret-key-here"
./acs-domain-checker.ps1
```

```bash
# Linux/macOS
export ACS_API_KEY="your-secret-key-here"
./acs-domain-checker.ps1
```

⚠️ **Security Best Practice:** Always use header-based authentication in production environments to prevent API keys from appearing in logs.

## ⚙️ Configuration (Environment Variables)
Customize the application behavior using these environment variables:

### 🌐 Network & Server
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Port for the web listener |
| `ACS_API_KEY` | _(none)_ | API key for securing `/api/*` and `/dns` endpoints |
| `ACS_RATE_LIMIT_PER_MIN` | `60` | Maximum requests per minute per client IP (set to `0` to disable) |
| `ACS_APP_VERSION` | _(from script)_ | Override the displayed application version string |

### 🔍 DNS Resolution
| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_DNS_RESOLVER` | `Auto` | DNS resolver mode: `Auto`, `System`, or `DoH` |
| `ACS_DNS_DOH_ENDPOINT` | _(auto)_ | Custom DNS-over-HTTPS endpoint URL |

### 🌐 Public Suffix List (registrable-domain resolution)
The registrable-domain resolver (used to pick the correct WHOIS/RDAP target for multi-label
zones such as `co.uk`, `com.au`, or `co.th`) uses a cached copy of the official
[Public Suffix List](https://publicsuffix.org/). The list is downloaded to
`public_suffix_list.dat` at build time by `Download-UiAssets.ps1` and is lazily refreshed at
runtime when the file is missing or older than the TTL. If no list is available (offline build
or download disabled), the resolver falls back to a small embedded set of common multi-label
suffixes.

| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_PSL_FILE` | `public_suffix_list.dat` next to the script | Path to the cached Public Suffix List file |
| `ACS_PSL_URL` | `https://publicsuffix.org/list/public_suffix_list.dat` | Source URL for runtime/build refresh |
| `ACS_PSL_MAX_AGE_DAYS` | `30` | Refresh the cached list when it is older than this many days |
| `ACS_PSL_DISABLE_DOWNLOAD` | `0` | Set to `1` to never download at runtime (offline / locked-down hosts) |

### 📊 Metrics & Analytics
| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_ENABLE_ANON_METRICS` | `0` | Set to `1` to enable anonymous metrics collection |
| `ACS_ANON_METRICS_FILE` | _(none)_ | File path to persist metrics data (JSON format) |
| `ACS_METRICS_HASH_KEY` | _(generated)_ | Stable HMAC key for domain hashing |

When browser-based anonymous metrics are enabled, the SPA now asks the user for cookie consent before storing optional preferences or sending analytics consent that allows the temporary `acs_session` analytics cookie. The consent banner is localized across all supported UI languages, and the `/terms` and `/privacy` pages now include links that reopen cookie management directly in the SPA.

To avoid browser tracking-prevention warnings from third-party SVG downloads, the SPA can also serve Lucide and flag SVG files from same-origin `/assets/*` paths. Use `Download-UiAssets.ps1` to fetch those files into the repository `assets/vendor/...` folders. The same script also refreshes the cached `public_suffix_list.dat` used for registrable-domain resolution.

```powershell
pwsh -NoProfile -File .\Download-UiAssets.ps1
```

### 🔐 Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_ENTRA_CLIENT_ID` | _(none)_ | Microsoft Entra ID (Azure AD) app client ID |
| `ACS_ENTRA_TENANT_ID` | _(none)_ | Entra ID tenant ID or domain (e.g., `contoso.onmicrosoft.com`) |
| `ACS_ENTRA_AUTO_SIGN_IN` | `1` | When `ACS_ENTRA_CLIENT_ID` is configured, quietly attempts MSAL browser/device SSO on page load before showing the manual sign-in fallback. Set to `0`, `false`, `no`, `off`, or `disabled` to require explicit sign-in. |

When automatic Entra sign-in is enabled, the SPA only calls MSAL `ssoSilent()` with `prompt: 'none'`; it never receives Windows credentials and does not force Windows Integrated Authentication. Entra ID decides whether an existing browser, device, PRT, WAM, or WIA-backed session can satisfy the request. MFA, consent, Conditional Access, missing sessions, or multiple-account ambiguity still fall back to the **Sign in with Microsoft** button.

### 🌍 WHOIS / RDAP Providers
| Variable | Default | Description |
|----------|---------|-------------|
| `SYSINTERNALS_WHOIS_PATH` | _(none)_ | Path to Sysinternals `whois.exe` (Windows WHOIS fallback) |
| `LINUX_WHOIS_PATH` | _(none)_ | Path to the Linux `whois` binary (Linux/macOS WHOIS fallback) |
| `ACS_LINUX_WHOIS_SERVERS` | _(none)_ | Comma/semicolon/newline-delimited fallback WHOIS server hostnames for Linux CLI (e.g., `whois.nic.us;us.whois-servers.net`) |
| `GODADDY_API_KEY` | _(none)_ | GoDaddy API key for WHOIS fallback |
| `GODADDY_API_SECRET` | _(none)_ | GoDaddy API secret for WHOIS fallback |
| `ACS_WHOISXML_API_KEY` | _(none)_ | WhoisXML API key for WHOIS fallback |

### 🛡️ DNSBL Reputation
| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_RBL_ZONES` | _(built-in defaults)_ | Comma/semicolon/newline-delimited DNSBL zone names to query |
| `ACS_RBL_MAX_ZONES` | `20` | Maximum DNSBL zones to query from `ACS_RBL_ZONES` or explicit API input (capped at 50) |
| `ACS_RBL_MAX_IPS` | `10` | Maximum public IPv4 targets to check per reputation lookup (capped at 50) |
| `ACS_RBL_MAX_PARALLELISM` | auto | Maximum concurrent DNSBL queries per reputation lookup (capped at 16) |

The reputation checker only queries public IPv4 addresses and validates DNSBL zone names before use. DNSBL policy-block responses are counted as errors rather than listings, and positive listings also attempt to collect DNSBL TXT reason text when the provider publishes it.

### 🐛 Issue Reporting
| Variable | Default | Description |
|----------|---------|-------------|
| `ACS_ISSUE_URL` | _(none)_ | Issue tracker URL for the "Report issue" button |

### 📝 Configuration Example
```powershell
# Windows PowerShell - comprehensive example
$env:PORT = "9000"
$env:ACS_API_KEY = "my-secret-key"
$env:ACS_RATE_LIMIT_PER_MIN = "30"
$env:ACS_ENABLE_ANON_METRICS = "1"
$env:ACS_DNS_RESOLVER = "DoH"
$env:ACS_WHOISXML_API_KEY = "your-whoisxml-key"
$env:ACS_ISSUE_URL = "https://github.com/blakedrumm/azure-communication-services-domain-checker/issues/new?template=bug-report.yml"
./acs-domain-checker.ps1
```

```bash
# Linux/macOS - comprehensive example
export PORT=9000
export ACS_API_KEY=my-secret-key
export ACS_RATE_LIMIT_PER_MIN=30
export ACS_ENABLE_ANON_METRICS=1
export ACS_DNS_RESOLVER=DoH
export ACS_WHOISXML_API_KEY=your-whoisxml-key
export ACS_ISSUE_URL="https://github.com/blakedrumm/azure-communication-services-domain-checker/issues/new?template=bug-report.yml"
./acs-domain-checker.ps1
```

## 🐛 Issue Reporting

To enable issue reporting from the web UI, set `ACS_ISSUE_URL` to your issue tracker's "new issue" URL. 

The application will:
- ✅ Append `domain` and `source` query parameters automatically
- ✅ Show a confirmation prompt before reporting
- ✅ Allow users to easily report domain configuration issues

### 📝 Using the GitHub Issue Template

This repository includes a GitHub Issue Form template (`bug-report.yml`) designed for seamless integration with the web UI's "Report issue" button.

**Template Filename:** `bug-report.yml`

**Configure the Issue URL:**
```powershell
# Use the template parameter to direct users to the bug report form
$env:ACS_ISSUE_URL = "https://github.com/blakedrumm/azure-communication-services-domain-checker/issues/new?template=bug-report.yml"
```

**Example Issue URL:**
```
https://github.com/blakedrumm/azure-communication-services-domain-checker/issues/new?template=bug-report.yml&domain=example.com&source=acs-domain-checker
```

**How It Works:**
1. 🖱️ User clicks "Report issue" button in the web UI
2. 🌐 The app automatically appends the current domain and source parameters to the URL
3. 📝 GitHub opens the issue form template
4. ✍️ The domain information is available in the URL, making it easy for users to copy/paste into the domain field
5. ✅ User fills out the remaining fields and submits the issue

**Query Parameters:**
- `template` - Specifies which issue template to use (e.g., `bug-report.yml`)
- `domain` - Domain information from the web UI (included in URL for user reference)
- `source` - Identifies the report source as `acs-domain-checker`

**💡 Note:** GitHub Issue Forms don't auto-populate fields from URL parameters, but the domain information is preserved in the URL for easy reference when filling out the form.

## 📚 MSAL Browser Library Updates

This repository uses the **Microsoft Authentication Library (MSAL)** for browser (`@azure/msal-browser`) to enable Microsoft Entra ID authentication. The library file `msal-browser.min.js` is checked into the repository root and served at `/assets/msal-browser.min.js`.

### 🤖 Automated Updates

A GitHub Actions workflow (`.github/workflows/update-msal-browser.yml`) automatically checks for new releases of `@azure/msal-browser` and creates pull requests when updates are available.

**⏰ Update Schedule:**
- ✅ Runs automatically every Monday at 9:00 AM UTC
- ✅ Can be triggered manually via GitHub Actions workflow dispatch

**⚙️ How It Works:**
1. 🔍 The workflow checks the latest version available on the npm registry
2. 🔄 Compares it with the current version in `msal-browser.min.js`
3. 📦 If an update is available:
   - Downloads the package from npm
   - Extracts `lib/msal-browser.min.js` from the package
   - Updates both `msal-browser.min.js` and `package.json`
   - Creates a pull request with the changes
4. ✅ Review and merge the PR after testing

**🔒 Security Features:**
- 📌 Pinned GitHub Actions versions for reproducibility
- 🌐 Downloads from official npm registry only
- ✔️ Version verification from package metadata
- 🚫 No arbitrary script execution

### 🔧 Manual Update

To manually update to a specific version:

1. 🌐 Navigate to **Actions** → **Update MSAL Browser Library** in the GitHub repository
2. ▶️ Click **Run workflow**
3. 📝 Enter the desired version (e.g., `5.3.0`) or leave empty for the latest
4. 🚀 Click **Run workflow**

### 📍 Pinning a Specific Version

If you need to prevent automatic updates and stay on a specific version:

1. 🛑 Disable the scheduled workflow run by editing `.github/workflows/update-msal-browser.yml`:
   ```yaml
   on:
     # schedule:  # Comment out the schedule trigger
     #   - cron: '0 9 * * 1'
     workflow_dispatch:  # Keep manual dispatch available
   ```

2. 🔧 Manually update to your desired version using the workflow dispatch method above

3. ✅ The application will continue to work with the checked-in version at that point

### 🌐 Fallback CDNs

The UI (in `acs-domain-checker.ps1`) also includes fallback CDN URLs in case the local file cannot be loaded:
- 🔗 `https://alcdn.msauth.net/browser/{version}/js/msal-browser.min.js`
- 🔗 `https://cdn.jsdelivr.net/npm/@azure/msal-browser@{version}/dist/msal-browser.min.js`

⚠️ **Note:** The CDN URLs in `acs-domain-checker.ps1` (in the `msalSources` array) have hardcoded versions and will need manual updates if you want them to match the latest version. The automated workflow only updates the checked-in `msal-browser.min.js` file.

## 🐳 Docker Hub Deployment

This repository includes automated workflows to build and publish Docker images to Docker Hub for both Linux and Windows containers.

### 🤖 Automated Deployment

A GitHub Actions workflow (`.github/workflows/docker-publish.yml`) automatically builds multi-platform Docker images and publishes them to Docker Hub.

**🚀 Deployment Triggers:**
- ✅ Automatically when a version tag is pushed (e.g., `v2.3.0`)
- ✅ Manually via GitHub Actions workflow dispatch

**📦 What Gets Published:**
- `linux-{version}` - Linux AMD64 image
- `windows-{version}` - Windows AMD64 image (nanoserver-ltsc2022)
- `{version}` - Multi-arch manifest (combines Linux + Windows)
- `latest` - Multi-arch manifest pointing to the latest release

### 🔧 Setup Instructions

To enable automatic deployment to Docker Hub, configure the following secrets in your GitHub repository:

1. 🔑 Navigate to **Settings** → **Secrets and variables** → **Actions**
2. 📝 Add the following repository secrets:
   - `DOCKERHUB_USERNAME` - Your Docker Hub username
   - `DOCKERHUB_TOKEN` - Your Docker Hub access token ([Create one here](https://hub.docker.com/settings/security))

### 🏷️ Publishing a New Release

**Method 1: Git Tag (Recommended)**
```bash
# Tag the release
git tag v2.3.0
git push origin v2.3.0

# The workflow will automatically:
# 1. Build Linux image on Ubuntu
# 2. Build Windows image on Windows Server 2022
# 3. Create multi-arch manifests for version tag and 'latest'
```

**Method 2: Manual Workflow Dispatch**
1. 🌐 Navigate to **Actions** → **Publish Docker Images to Docker Hub**
2. ▶️ Click **Run workflow**
3. 📝 Enter the version (e.g., `2.3.0`) or leave empty to extract from `acs-domain-checker.ps1`
4. 🚀 Click **Run workflow**

### 🔍 Using Published Images

Pull and run the latest version:
```bash
# Pull the latest multi-arch image (automatically selects platform)
docker pull limitlessworlds/acs-domain-checker:latest

# Run the container
docker run --rm -p 8080:8080 limitlessworlds/acs-domain-checker:latest
```

Pull a specific version:
```bash
# Pull specific version
docker pull limitlessworlds/acs-domain-checker:2.3.0

# Pull platform-specific image
docker pull limitlessworlds/acs-domain-checker:linux-2.3.0
docker pull limitlessworlds/acs-domain-checker:windows-2.3.0
```

### 🛠️ Manual Build Script

For local multi-platform builds and testing, use the included PowerShell script:

```powershell
# Build and publish (requires Docker Desktop with Windows containers support)
./acs-domain-checker-dockerhub.ps1

# Dry run (build only, no push)
./acs-domain-checker-dockerhub.ps1 -DryRun

# Specify custom version
./acs-domain-checker-dockerhub.ps1 -Version 2.3.0
```

**📋 Requirements for manual script:**
- Docker Desktop with Windows containers support
- Authenticated to Docker Hub (`docker login`)
- PowerShell 5.1 or later

## 🔄 External Repository Sync

This repository includes an automated workflow to sync code changes to:

- `https://github.com/blakedrumm/azure-communication-services-domain-checker`

Workflow file:

- `.github/workflows/sync-external-repo.yml`

### Trigger behavior

- Runs automatically on pushes to `main`
- Supports manual runs via **workflow_dispatch**

### Required setup

Configure these repository settings under **Settings → Secrets and variables → Actions**:

- `EXTERNAL_REPO_DEPLOY_KEY` (secret): private SSH key for a deploy key with **write** access on the external repository
- `EXTERNAL_SYNC_BRANCH` (variable, optional): target branch in the external repo (defaults to `main`)

### Excluded from sync

The workflow intentionally excludes MCAPS/internal-only files:

- `.github/acl/**`
- `.github/compliance/**`
- `.github/policies/**`
- `.github/ISSUE_TEMPLATE/JitAccess.yml`
- `.github/workflows/sync-external-repo.yml`

## 📄 Terms of Service & Privacy Pages

The application serves embedded **Terms of Service** (`/terms`) and **Privacy Statement** (`/privacy`) pages directly from the web server. Both pages are:

- 🌍 Fully localized into all [10 supported languages](#-localization--multi-language-support)
- 🔗 Accessible via the footer links in the web UI
- 📖 Rendered server-side with CSP nonce support
- 🔄 Language-aware via the `?lang=` query parameter (e.g., `/terms?lang=de`)

The Privacy Statement explains the tool's data handling practices, including the optional anonymous metrics system. The Terms of Service describe usage conditions for the tool.

## 🔒 Security Notes

Security is a top priority for the ACS Domain Checker:

- 🛡️ **Content Security Policy (CSP)** is enforced with nonces for inline scripts/styles
- 🔐 **Anonymous metrics** do not store Personally Identifiable Information (PII) - domains are HMAC-hashed
- ⚠️ **API key best practices:** Avoid using API keys in URLs for production environments to enhance security
- 🔒 **HTTPS recommended:** Always use HTTPS in production deployments
- 🚫 **No credential storage:** The application never stores credentials or sensitive data
- ✅ **Input validation:** All user inputs are validated and sanitized

### 🛡️ Security Recommendations

For production deployments:
1. ✅ Always enable `ACS_API_KEY` for authentication
2. ✅ Configure `ACS_RATE_LIMIT_PER_MIN` to prevent abuse
3. ✅ Use HTTPS with a valid SSL/TLS certificate
4. ✅ Keep the MSAL library updated via automated updates
5. ✅ Review logs regularly for suspicious activity
6. ✅ Run in a containerized environment for isolation

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 🚫 Port Already in Use
**Problem:** Error message "Port 8080 is already in use"
**Solution:**
```powershell
# Use a different port
./acs-domain-checker.ps1 -Port 9000
```

#### 🌐 DNS Resolution Failures
**Problem:** DNS queries are failing or timing out
**Solution:**
```powershell
# Try DNS-over-HTTPS for more reliable resolution
$env:ACS_DNS_RESOLVER = "DoH"
./acs-domain-checker.ps1
```

#### 🔐 Authentication Issues
**Problem:** API key authentication not working
**Solution:**
- Ensure `ACS_API_KEY` is set correctly
- Use header-based authentication: `X-Api-Key: your-key`
- Verify the API key is not expired or contains special characters

#### 🐳 Docker Container Issues
**Problem:** Container fails to start or crashes
**Solution:**
```bash
# Check container logs
docker logs <container-id>

# Ensure port is not in use
docker ps | grep 8080

# Run with interactive mode for debugging
docker run -it --rm -p 8080:8080 acs-domain-checker
```

#### 📊 WHOIS/RDAP Failures
**Problem:** WHOIS lookups are failing
**Solution:**
- Check network connectivity
- Verify firewall allows outbound WHOIS queries (TCP port 43)
- The tool includes a built-in TCP whois client that bypasses Linux CLI `getaddrinfo` issues in Docker containers
- Consider configuring API keys for fallback providers

### 💡 Getting Help

If you encounter issues:
1. 📖 Check the [documentation](#-table-of-contents)
2. 🔍 Search existing [GitHub Issues](https://github.com/blakedrumm/azure-communication-services-domain-checker/issues)
3. 🆕 [Open a new issue](https://github.com/blakedrumm/azure-communication-services-domain-checker/issues/new) with:
   - Detailed description of the problem
   - Steps to reproduce
   - Environment information (OS, PowerShell version, etc.)
   - Relevant error messages or logs

## 🛠️ Build & Local UI Assets

The repository ships both the **modular source** (under `src/NN-Name.ps1`) and a
**built monolithic artifact** (`acs-domain-checker.ps1` at the repo root). Edit
the modular sources, then rebuild — never edit the monolith directly.

### 🧩 Source layout

Source files in `src/` are numbered (`00-Header.ps1`, `01-DomainParsing.ps1`,
`20a-HtmlScriptSetup.ps1`, etc.) so the build can concatenate them in a stable
order. The build sorts by numeric prefix plus optional letter suffix, so
`20a-*` correctly loads after `20-*` and before `21-*`.

### 🏗️ Rebuilding `acs-domain-checker.ps1`

Use `Build-Release.ps1` to refresh local UI assets (optional) and concatenate
all `src/*.ps1` files into the monolithic script:

```powershell
# Standard rebuild (also refreshes local UI assets via Download-UiAssets.ps1)
pwsh -NoProfile -File ./Build-Release.ps1 -Force

# Offline / restricted environments — skip the asset download step
pwsh -NoProfile -File ./Build-Release.ps1 -Force -SkipUiAssetDownload
```

### 🎨 Local UI assets (`Download-UiAssets.ps1`)

To avoid third-party tracking-prevention warnings, the SPA can serve Lucide
icons and language flag SVGs from same-origin `/assets/*` paths. Run the asset
downloader once (or whenever new icons/flags are referenced) to populate
`assets/vendor/...`:

```powershell
pwsh -NoProfile -File ./Download-UiAssets.ps1
```

Keep `Download-UiAssets.ps1` in sync with the asset names referenced by
`src/20b-HtmlTranslations.ps1` and `src/20c-HtmlJsUtilities.ps1`.

### ✅ Quick validation after a build

```powershell
# CLI smoke test — runs DNS checks once and prints JSON
pwsh -NoProfile -File ./acs-domain-checker.ps1 -TestDomain example.com
```

For deeper guidance on the source layout, build pipeline, and conventions, see
[`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### 🎯 Ways to Contribute

- 🐛 **Report bugs:** Open an issue with detailed reproduction steps
- 💡 **Suggest features:** Share your ideas for improvements
- 📝 **Improve documentation:** Fix typos, add examples, clarify instructions
- 🔧 **Submit code:** Fix bugs, add features, improve performance
- ⭐ **Star the repository:** Show your support!

### 🚀 Getting Started

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. ✍️ Make your changes
4. ✅ Test your changes thoroughly
5. 📝 Commit your changes (`git commit -m 'Add amazing feature'`)
6. 📤 Push to the branch (`git push origin feature/amazing-feature`)
7. 🎉 Open a Pull Request

### 📋 Contribution Guidelines

- ✅ Follow PowerShell best practices
- ✅ Maintain backward compatibility when possible
- ✅ Add comments for complex logic
- ✅ Update documentation for new features
- ✅ Test your changes before submitting
- ✅ Keep commits focused and atomic

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 🌟 If you find this project helpful, please consider giving it a star! 🌟

**Made with ❤️ by [Blake Drumm](https://github.com/blakedrumm)**

**Useful for Azure Communication Services domain validation**

[Report Bug](https://github.com/blakedrumm/azure-communication-services-domain-checker/issues) · [Request Feature](https://github.com/blakedrumm/azure-communication-services-domain-checker/issues) · [Documentation](#-table-of-contents)

</div>
