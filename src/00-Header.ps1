<#
.SYNOPSIS
  Local web UI + REST API to inspect DNS records used for Azure Communication Services (ACS) domain verification.

.DESCRIPTION
  Starts a tiny HTTP listener (default: http://localhost:8080) that serves a single-page web UI and JSON endpoints.
  Checks whether a domain looks ready for ACS verification by inspecting:
  - Root TXT (SPF + ms-domain-verification)
  - MX (with A/AAAA resolution), DMARC, DKIM selectors, and root/`www` CNAME
  - Optional DNSBL reputation lookup helper (scripted in separate test harness)

  Endpoints:
  - /            : Web UI
  - /dns         : Aggregated DNS readiness JSON
  - /api/base    : Root TXT/SPF/ACS TXT JSON
  - /api/mx      : MX (plus A/AAAA resolution) JSON
  - /api/dmarc   : DMARC JSON
  - /api/dkim    : DKIM JSON
  - /api/cname   : CNAME JSON
  - /api/metrics : Anonymous metrics snapshot (hashed domains only; disabled with -DisableAnonymousMetrics)

.PARAMETER Port
  TCP port to listen on. Default is 8080 (also respects PORT env var).

.PARAMETER TestDomain
  Runs a one-shot domain check, writes JSON to stdout, and exits without starting the web server.

.EXAMPLE
  # Start on the default port
  .\acs-domain-checker.ps1

.EXAMPLE
  # Start on a different port and bind to all interfaces (e.g., container)
  .\acs-domain-checker.ps1 -Port 8090 -Bind Any

.EXAMPLE
  # Run a one-shot validation and exit
  .\acs-domain-checker.ps1 -TestDomain example.com

.NOTES
  Author: Blake Drumm (blakedrumm@microsoft.com)
  Intended for local troubleshooting. Ensure the chosen port is allowed by your firewall policy.

  Environment variables honored (optional):
  - PORT                         : Port override for the web listener (default 8080).
  - ACS_DNS_RESOLVER             : Force DNS resolver mode (Auto/System/DoH).
  - ACS_DNS_DOH_ENDPOINT         : Custom DoH endpoint when resolver is DoH or Auto without Resolve-DnsName.
  - CONTAINER_APP_NAME / CONTAINER_APP_REVISION / KUBERNETES_SERVICE_HOST : Hint the script to bind to 0.0.0.0 in container scenarios.
  - ACS_ENABLE_ANON_METRICS      : Set to 1 to enable anonymous metrics.
  - ACS_ANON_METRICS_FILE        : Path to persist anonymous metrics (used when metrics are enabled).
  - ACS_METRICS_HASH_KEY         : Stable hash key for anonymous domain hashing (optional; generated if absent).
  - SYSINTERNALS_WHOIS_PATH      : Path to Sysinternals whois.exe (Windows WHOIS fallback).
  - LINUX_WHOIS_PATH             : Path to Linux whois binary (Linux WHOIS fallback).
  - ACS_LINUX_WHOIS_SERVERS      : Optional comma/semicolon/newline-delimited Linux WHOIS fallback servers.
                                   Example: `whois.nic.us;us.whois-servers.net`.
  - ACS_WHOISXML_API_KEY         : API key for WhoisXML fallback.
  - GODADDY_API_KEY / GODADDY_API_SECRET : Credentials for GoDaddy WHOIS fallback.
  - ACS_ENTRA_CLIENT_ID          : Azure AD (Entra ID) app registration client ID for Microsoft employee authentication.
  - ACS_ENTRA_TENANT_ID          : Optional tenant ID or domain (e.g., contoso.onmicrosoft.com) for Entra ID authority.
  - ACS_API_KEY                  : Optional API key required for /api/* and /dns endpoints (send via X-Api-Key header).
                                   Example query usage (less secure): http://localhost:8080/api/base?domain=example.com&apiKey=YOUR_KEY
  - ACS_RATE_LIMIT_PER_MIN       : Max requests per minute per client IP (default 60; set to 0 to disable).
  - ACS_ISSUE_URL                : Optional issue URL for the "Report issue" button (domain name appended as query).
  - ACS_RBL_ZONES                : Optional comma/semicolon/newline-delimited DNSBL zones. If empty, safe built-in defaults are used.
                                   Example optional add-on: `zen.spamhaus.org` (user-supplied only; not enabled by default).

  Cross-platform / container notes:
  - Bind mode: Auto picks loopback on Windows; uses 0.0.0.0 in container scenarios. Override with -Bind Any/Localhost.
  - DNS resolver: Auto prefers Resolve-DnsName; falls back to DNS-over-HTTPS. Force via -DnsResolver DoH/System.
  - DoH override: set ACS_DNS_DOH_ENDPOINT.
  - Anonymous metrics: enabled by default (no PII). Domains are HMAC-hashed; persist metrics with -EnableAnonymousMetrics and ACS_ANON_METRICS_FILE.
#>

param(
  [int]$Port = $(if ($env:PORT -and $env:PORT -match '^\d+$') { [int]$env:PORT } else { 8080 }),
  [ValidateSet('Auto','System','DoH')]
  [string]$DnsResolver = 'Auto',
  [string]$DohEndpoint,
  [string]$TestDomain,
  # Listener binding mode:
  # - Auto      : preserve current behavior (Windows = all interfaces, non-Windows = localhost)
  # - Localhost : bind only to loopback (safest for local troubleshooting)
  # - Any       : bind to all interfaces (required for most container scenarios)
  [ValidateSet('Auto','Localhost','Any')]
  [string]$Bind = 'Auto',

  # Anonymous, in-memory usage metrics.
  # - Enabled by default; use -DisableAnonymousMetrics to turn off.
  # - Does not store IP addresses, user agents, hardware identifiers, or query values.
  [switch]$EnableAnonymousMetrics,
  [switch]$DisableAnonymousMetrics,

  # Optional persistence for anonymous metrics.
  # - Enabled only when `-EnableAnonymousMetrics` is used.
  # - Persists counters and first-seen/restart metadata to a local JSON file.
  # - Does not persist session ids.
  [string]$AnonymousMetricsFile
)

# ------------------- UTF-8 ENCODING FIX -------------------
# Ensure the PowerShell process uses UTF-8 for all output and string operations.
# Without this, non-ASCII characters in embedded HTML translations (e.g., Portuguese,
# French, German, Arabic, Chinese, Japanese, Russian, Hindi) may be corrupted when
# served over HTTP — especially in Linux containers where the default locale is C/POSIX.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Load the System.Net assembly so we can use HttpListener, IPAddress, and other networking types.
Add-Type -AssemblyName System.Net

# Heuristic: when running in Container Apps / Kubernetes on non-Windows, we generally must bind to all interfaces.
# Detect container environments by checking for well-known environment variables that Azure Container Apps
# and Kubernetes inject into running pods/containers.
$script:IsContainer = (
  -not [string]::IsNullOrWhiteSpace($env:CONTAINER_APP_NAME) -or
  -not [string]::IsNullOrWhiteSpace($env:CONTAINER_APP_REVISION) -or
  -not [string]::IsNullOrWhiteSpace($env:KUBERNETES_SERVICE_HOST)
)

# ------------------- CONFIG / STARTUP -------------------
# This script hosts a tiny local web server:
# - `GET /` serves an embedded single-page HTML UI.
# - `GET /api/*` returns individual DNS checks.
# - `GET /dns` returns an aggregated "readiness" JSON payload.
#
# DNS resolver selection is exposed via `-DnsResolver`:
# - Auto   : use `Resolve-DnsName` if available, else DoH.
# - System : force `Resolve-DnsName` (Windows/PowerShell with DnsClient module).
# - DoH    : force DNS-over-HTTPS via `Invoke-RestMethod`.

# Store the chosen DNS resolver mode (Auto/System/DoH) in script scope for use throughout the script.
$script:DnsResolverMode = $DnsResolver

# RunspacePool copies function *definitions* but not script-scoped variables.
# Use env vars for settings that must be visible inside request handler runspaces.
$env:ACS_DNS_RESOLVER = $DnsResolver

# Configure per-client rate limiting (default: 60 requests/minute). A value of 0 disables rate limiting.
$rateLimitPerMinute = 60
if ($env:ACS_RATE_LIMIT_PER_MIN -and $env:ACS_RATE_LIMIT_PER_MIN -match '^\d+$') {
  $rateLimitPerMinute = [int]$env:ACS_RATE_LIMIT_PER_MIN
}
if ($rateLimitPerMinute -lt 0) { $rateLimitPerMinute = 0 }
$env:ACS_RATE_LIMIT_PER_MIN = $rateLimitPerMinute.ToString()

# Telemetry flag must be visible in request handler runspaces (RunspacePool doesn't keep script scope).
# Anonymous metrics are enabled by default. The -DisableAnonymousMetrics switch takes precedence.
$anonMetricsEnabled = $true
if ($DisableAnonymousMetrics) { $anonMetricsEnabled = $false }
elseif ($EnableAnonymousMetrics) { $anonMetricsEnabled = $true }

$env:ACS_ENABLE_ANON_METRICS = $(if ($anonMetricsEnabled) { '1' } else { '0' })

# Also keep a script-scoped flag for same-process usage.
$script:EnableAnonymousMetrics = $anonMetricsEnabled

# Metrics file path must be visible in request handler runspaces.
if ([string]::IsNullOrWhiteSpace($AnonymousMetricsFile)) {
  $AnonymousMetricsFile = $env:ACS_ANON_METRICS_FILE
}

