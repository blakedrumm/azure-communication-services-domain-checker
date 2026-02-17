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

.EXAMPLE
  # Start on the default port
  .\acs-domain-checker.ps1

.EXAMPLE
  # Start on a different port and bind to all interfaces (e.g., container)
  .\acs-domain-checker.ps1 -Port 8090 -Bind Any

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
  - ACS_WHOISXML_API_KEY         : API key for WhoisXML fallback.
  - GODADDY_API_KEY / GODADDY_API_SECRET : Credentials for GoDaddy WHOIS fallback.
  - ACS_ENTRA_CLIENT_ID          : Azure AD (Entra ID) app registration client ID for Microsoft employee authentication.
  - ACS_ENTRA_TENANT_ID          : Optional tenant ID or domain (e.g., contoso.onmicrosoft.com) for Entra ID authority.
  - ACS_API_KEY                  : Optional API key required for /api/* and /dns endpoints (send via X-Api-Key header).
                                   Example query usage (less secure): http://localhost:8080/api/base?domain=example.com&apiKey=YOUR_KEY
  - ACS_RATE_LIMIT_PER_MIN       : Max requests per minute per client IP (default 60; set to 0 to disable).
  - ACS_ISSUE_URL                : Optional issue URL for the "Report issue" button (domain name appended as query).

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

Add-Type -AssemblyName System.Net

# Heuristic: when running in Container Apps / Kubernetes on non-Windows, we generally must bind to all interfaces.
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

$script:DnsResolverMode = $DnsResolver

# RunspacePool copies function *definitions* but not script-scoped variables.
# Use env vars for settings that must be visible inside request handler runspaces.
$env:ACS_DNS_RESOLVER = $DnsResolver

$rateLimitPerMinute = 60
if ($env:ACS_RATE_LIMIT_PER_MIN -and $env:ACS_RATE_LIMIT_PER_MIN -match '^\d+$') {
  $rateLimitPerMinute = [int]$env:ACS_RATE_LIMIT_PER_MIN
}
if ($rateLimitPerMinute -lt 0) { $rateLimitPerMinute = 0 }
$env:ACS_RATE_LIMIT_PER_MIN = $rateLimitPerMinute.ToString()

# Telemetry flag must be visible in request handler runspaces (RunspacePool doesn't keep script scope).
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

# Heuristic: derive a registrable domain (very small PSL subset)
function Get-RegistrableDomain {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  $d = ([string]$Domain).Trim().Trim('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $d.ToLowerInvariant() }

  $tld = $labels[$labels.Count - 1].ToLowerInvariant()
  $sld = $labels[$labels.Count - 2].ToLowerInvariant()
  $last3 = if ($labels.Count -ge 3) { ($labels[$labels.Count - 3] + '.' + $sld + '.' + $tld).ToLowerInvariant() } else { $null }

  $threeLabelZones = @(
    'co.uk','org.uk','ac.uk','gov.uk',
    'co.jp','or.jp','ne.jp',
    'com.au','net.au','org.au',
    'com.nz','net.nz','org.nz','gov.nz','ac.nz',
    'com.br','net.br','org.br',
    'com.mx',
    'com.sg','net.sg','org.sg',
    'com.tr','net.tr','org.tr',
    'com.hk','net.hk','org.hk'
  )

  if ($last3 -and $threeLabelZones -contains ($sld + '.' + $tld)) {
    return ($labels[($labels.Count - 3)..($labels.Count - 1)] -join '.').ToLowerInvariant()
  }

  # Default: use last two labels (e.g., example.com)
  return ($labels[($labels.Count - 2)..($labels.Count - 1)] -join '.').ToLowerInvariant()
}

function Invoke-SysinternalsWhoisLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$WhoisPath,

    [int]$TimeoutSec = 25,

    # Set this if you want errors to bubble up instead of returning $null
    [switch]$ThrowOnError
  )

  $exe = $WhoisPath
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = $env:SYSINTERNALS_WHOIS_PATH }
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = 'whois.exe' }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  # If caller provided a path (or env var did), validate it exists.
  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:SYSINTERNALS_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois.exe' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Sysinternals whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  # Ensure we can parse dates without crashing the whole lookup
  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe

    # Sysinternals whois usage supports -v to follow referrals; /accepteula avoids interactive prompt
    # Use ArgumentList (array form) to avoid shell injection via crafted domain names.
    try {
      $psi.ArgumentList.Add('/accepteula')
      $psi.ArgumentList.Add('-v')
      $psi.ArgumentList.Add($d)
    } catch {
      # Older .NET runtimes may not support ArgumentList; fall back to Arguments with validation.
      # Domain is already validated by Test-DomainName (alphanumeric, dots, hyphens only).
      $psi.Arguments = "/accepteula -v `"$d`""
    }

    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    # Best-effort encoding
    try {
      $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
      $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
    } catch { }

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) {
      $msg = "Failed to start whois process."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()

    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
      try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      $msg = "Sysinternals whois timed out after $TimeoutSec seconds for '$d'."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    # Some tools write normal output to stderr; combine both safely
    $text = (($out, $err) -join "`r`n").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = "Sysinternals whois returned no output for '$d'. ExitCode=$($p.ExitCode)."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    # Parse what we can (never fail the whole lookup on parse issues)
    $creation   = $null
    $expiry     = $null
    $registrar  = $null
    $registrant = $null

    foreach ($line in ($text -split "`r?`n")) {
      $l = $line.Trim()
      if (-not $l) { continue }

      if (-not $creation -and $l -match '(?i)^(Creation Date|Created On|Registered On|Domain Create Date):\s*(.+)$') {
        $val = $Matches[2].Trim()
        if ($canConvertDates) {
          try { $creation = ConvertTo-NullableUtcIso8601 $val } catch { $creation = $val }
        } else {
          $creation = $val
        }
        continue
      }

      if (-not $expiry -and $l -match '(?i)^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date):\s*(.+)$') {
        $val = $Matches[2].Trim()
        if ($canConvertDates) {
          try { $expiry = ConvertTo-NullableUtcIso8601 $val } catch { $expiry = $val }
        } else {
          $expiry = $val
        }
        continue
      }

      if (-not $registrar -and $l -match '(?i)^(Registrar|Registrar name|Registrar Name|Sponsoring Registrar):\s*(.+)$') {
        $registrar = $Matches[2].Trim()
        continue
      }

      if (-not $registrant -and $l -match '(?i)^Registrant (Organization|Organisation|Name):\s*(.+)$') {
        $registrant = $Matches[2].Trim()
        continue
      }
    }

    return [pscustomobject]@{
      creationDate = $creation
      expiryDate   = $expiry
      registrar    = $registrar
      registrant   = $registrant
      rawText      = $text
      exitCode     = $p.ExitCode
      whoisExe     = $exe
    }
  }
  catch {
    $msg = "Sysinternals whois failed: $($_.Exception.Message)"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }
}

function Invoke-LinuxWhoisLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$WhoisPath,

    [int]$TimeoutSec = 25,

    [switch]$ThrowOnError
  )

  $exe = $WhoisPath
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = $env:LINUX_WHOIS_PATH }
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = 'whois' }

  $cmdExists = $null
  try { $cmdExists = Get-Command -Name $exe -ErrorAction SilentlyContinue } catch { $cmdExists = $null }
  if (-not $cmdExists) {
    $msg = "Linux whois executable not found (expected '$exe'). Install the 'whois' package in the container image."
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:LINUX_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Linux whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    # Use ArgumentList (array form) to avoid shell injection via crafted domain names.
    try {
      $psi.ArgumentList.Add('--')
      $psi.ArgumentList.Add($d)
    } catch {
      # Older .NET runtimes may not support ArgumentList; fall back to Arguments with validation.
      # Domain is already validated by Test-DomainName (alphanumeric, dots, hyphens only).
      $psi.Arguments = "-- `"$d`""
    }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    try {
      $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
      $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
    } catch { }

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) {
      $msg = "Failed to start whois process."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()

    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
      try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      $msg = "whois timed out after $TimeoutSec seconds for '$d'."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $text = (($out, $err) -join "`r`n").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = "whois returned no output for '$d'. ExitCode=$($p.ExitCode)."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $creation   = $null
    $expiry     = $null
    $registrar  = $null
    $registrant = $null

    foreach ($line in ($text -split "`r?`n")) {
      $l = $line.Trim()
      if (-not $l) { continue }

      if (-not $creation -and $l -match '(?i)^(Creation Date|Created On|Registered On|Domain Create Date|Creation date):\s*(.+)$') {
        $val = $Matches[2].Trim()
        if ($canConvertDates) {
          try { $creation = ConvertTo-NullableUtcIso8601 $val } catch { $creation = $val }
        } else {
          $creation = $val
        }
        continue
      }

      if (-not $expiry -and $l -match '(?i)^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Registrar Registration Expiration date):\s*(.+)$') {
        $val = $Matches[2].Trim()
        if ($canConvertDates) {
          try { $expiry = ConvertTo-NullableUtcIso8601 $val } catch { $expiry = $val }
        } else {
          $expiry = $val
        }
        continue
      }

      if (-not $registrar -and $l -match '(?i)^(Registrar|Registrar name|Registrar Name|Sponsoring Registrar):\s*(.+)$') {
        $registrar = $Matches[2].Trim()
        continue
      }

      if (-not $registrant -and $l -match '(?i)^(Registrant Name|Registrant|Registrant Organisation|Registrant Organization):\s*(.+)$') {
        $registrant = $Matches[2].Trim()
        continue
      }
    }

    return [pscustomobject]@{
      creationDate = $creation
      expiryDate   = $expiry
      registrar    = $registrar
      registrant   = $registrant
      rawText      = $text
      exitCode     = $p.ExitCode
      whoisExe     = $exe
    }
  }
  catch {
    $msg = "whois failed: $($_.Exception.Message)"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }
}
if ([string]::IsNullOrWhiteSpace($AnonymousMetricsFile)) {
  $AnonymousMetricsFile = Join-Path -Path $PSScriptRoot -ChildPath 'acs-anon-metrics.json'
}
$AnonymousMetricsFile = [System.IO.Path]::GetFullPath($AnonymousMetricsFile)
$env:ACS_ANON_METRICS_FILE = $AnonymousMetricsFile

if ([string]::IsNullOrWhiteSpace($DohEndpoint)) {
  if (-not [string]::IsNullOrWhiteSpace($env:ACS_DNS_DOH_ENDPOINT)) {
    $DohEndpoint = $env:ACS_DNS_DOH_ENDPOINT
  }
}

# Anonymous metrics: choose a stable hash key (reuse from env or persisted metrics file).
function Get-PersistedMetricsHashKey {
  param([string]$Path)
  try {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $data = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($data.PSObject.Properties.Match('hashKey').Count -gt 0) {
      $k = [string]$data.hashKey
      if (-not [string]::IsNullOrWhiteSpace($k)) { return $k }
    }
  } catch { }
  return $null
}

$script:MetricsHashKey = $env:ACS_METRICS_HASH_KEY
if ([string]::IsNullOrWhiteSpace($script:MetricsHashKey)) {
  $persistedKey = Get-PersistedMetricsHashKey -Path $AnonymousMetricsFile
  if (-not [string]::IsNullOrWhiteSpace($persistedKey)) {
    $script:MetricsHashKey = $persistedKey
  } else {
    $script:MetricsHashKey = [Guid]::NewGuid().ToString('N')
  }
  $env:ACS_METRICS_HASH_KEY = $script:MetricsHashKey
}
$MetricsHashKey = $script:MetricsHashKey

# Application version (for metrics/reporting)
$script:AppVersion = '1.2.12'
if (-not [string]::IsNullOrWhiteSpace($env:ACS_APP_VERSION)) {
  $script:AppVersion = $env:ACS_APP_VERSION
}

# Single-instance only; multi-replica metrics are not supported.
# Cross-process file lock for metrics persistence (prevents concurrent writers from clobbering uptime counters).
function Acquire-MetricsFileMutex {
  param([int]$TimeoutMs = 5000)

  $names = @(
    'Global\\ACSAnonMetricsFileLock',
    'Local\\ACSAnonMetricsFileLock',
    'ACSAnonMetricsFileLock'
  )

  foreach ($n in $names) {
    try {
      $mtx = [System.Threading.Mutex]::new($false, $n)
      if ($mtx.WaitOne($TimeoutMs)) { return $mtx }
    } catch { try { if ($mtx) { $mtx.Dispose() } } catch { } }
  }
  return $null
}

# Capture GoDaddy creds (env) once so they can be passed into handler runspaces.
$script:GoDaddyApiKey = $env:GODADDY_API_KEY
$script:GoDaddyApiSecret = $env:GODADDY_API_SECRET

function Get-HashedDomain {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  $d = $Domain.Trim().ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $key = $MetricsHashKey
  if ([string]::IsNullOrWhiteSpace($key)) { $key = $env:ACS_METRICS_HASH_KEY }
  if ([string]::IsNullOrWhiteSpace($key)) { return $null }

  $keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
  $dataBytes = [Text.Encoding]::UTF8.GetBytes($d)
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
  try {
    return [Convert]::ToBase64String($hmac.ComputeHash($dataBytes))
  }
  finally {
    try { $hmac.Dispose() } catch { }
  }
}

function Handle-MetricsRequest {
  param($Context, [bool]$MetricsEnabled)

  $snap = $null
  try { $snap = Get-AnonymousMetricsSnapshot } catch { $snap = $null }
  if ($null -eq $snap) { $snap = @{ enabled = $false } }

  try {
    if ($snap -is [hashtable]) {
      $snap.enabled = $MetricsEnabled
    } else {
      $snap | Add-Member -NotePropertyName enabled -NotePropertyValue $MetricsEnabled -Force
    }
  } catch { }

  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $Context.Response.Headers['X-ACS-AnonMetrics-Enabled'] = ($(if ($MetricsEnabled) { '1' } else { '0' }))
    }
  } catch { }

  Write-Json -Context $Context -Object $snap
}
if (-not [string]::IsNullOrWhiteSpace($DohEndpoint)) {
  $env:ACS_DNS_DOH_ENDPOINT = $DohEndpoint
}

# ============================
# RDAP lookup helpers (fixed)
# - Safer URL joining (no operator precedence surprises)
# - Better error handling (return $null instead of throwing, unless -ThrowOnError)
# - Handles IANA bootstrap download/caching failures gracefully
# - Falls back to rdap.org if authoritative fails
# ============================

$script:RdapBootstrapCache     = $null
$script:RdapBootstrapFetchedAt = $null

function Get-RdapBootstrapData {
  [CmdletBinding()]
  param(
    [int]$CacheMinutes = 1440,
    [int]$TimeoutSec = 20,
    [switch]$ForceRefresh
  )

  try {
    if (-not $ForceRefresh -and $script:RdapBootstrapCache -and $script:RdapBootstrapFetchedAt) {
      $age = (Get-Date) - $script:RdapBootstrapFetchedAt
      if ($age.TotalMinutes -lt $CacheMinutes) {
        return $script:RdapBootstrapCache
      }
    }
  } catch {
    # Ignore cache issues and continue to fetch fresh
  }

  # IANA RDAP bootstrap file (JSON) maps TLDs to RDAP base URLs.
  $uri = 'https://data.iana.org/rdap/dns.json'

  try {
    $data = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop
    if ($null -eq $data -or $null -eq $data.services) {
      return $null
    }

    $script:RdapBootstrapCache     = $data
    $script:RdapBootstrapFetchedAt = Get-Date
    return $data
  }
  catch {
    return $null
  }
}

function Get-RdapBaseUrlForDomain {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain
  )

  $d = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $parts = $d.Split('.')
  if ($parts.Count -lt 2) { return $null }

  $tld = $parts[$parts.Count - 1]
  if ([string]::IsNullOrWhiteSpace($tld)) { return $null }

  $bootstrap = $null
  try { $bootstrap = Get-RdapBootstrapData } catch { $bootstrap = $null }
  if (-not $bootstrap -or -not $bootstrap.services) { return $null }

  foreach ($svc in @($bootstrap.services)) {
    # Each service entry is typically: [ [ "tld1","tld2"... ], [ "https://rdap.server/", ... ] ]
    if ($null -eq $svc -or $svc.Count -lt 2) { continue }

    $tlds = @($svc[0])
    $urls = @($svc[1])

    if ($tlds -contains $tld) {
      foreach ($candidate in $urls) {
        $s = [string]$candidate
        if (-not [string]::IsNullOrWhiteSpace($s)) {
          # Ensure trailing slash for URI base
          return ($s.TrimEnd('/') + '/')
        }
      }

      return $null
    }
  }

  return $null
}

function Invoke-RdapLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [int]$TimeoutSec = 15,

    # If set, throw the final error instead of returning $null
    [switch]$ThrowOnError
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $escaped = [uri]::EscapeDataString($d)

  # 1) Prefer authoritative RDAP servers discovered via IANA bootstrap.
  $base = $null
  try { $base = Get-RdapBaseUrlForDomain -Domain $d } catch { $base = $null }

  if (-not [string]::IsNullOrWhiteSpace($base)) {
    try {
      # Use System.Uri joining to avoid string concatenation bugs
      $baseUri = [System.Uri]::new($base, [System.UriKind]::Absolute)
      $uri     = [System.Uri]::new($baseUri, ("domain/{0}" -f $escaped)).AbsoluteUri

      return (Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop)
    }
    catch {
      # Authoritative lookup failed; fall through to rdap.org fallback.
    }
  }

  # 2) Fallback to rdap.org proxy (will usually redirect to the authoritative server).
  try {
    $uri2 = "https://rdap.org/domain/$escaped"
    return (Invoke-RestMethod -Method Get -Uri $uri2 -TimeoutSec $TimeoutSec -MaximumRedirection 5 -ErrorAction Stop)
  }
  catch {
    if ($ThrowOnError) { throw }
    return $null
  }
}


function Invoke-WhoisXmlLookup {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain
  )

  $apiKey = $env:ACS_WHOISXML_API_KEY
  if ([string]::IsNullOrWhiteSpace($apiKey)) {
    throw "ACS_WHOISXML_API_KEY is not set. Configure it to use WhoisXML fallback."
  }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $uri = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$([uri]::EscapeDataString($apiKey))&domainName=$([uri]::EscapeDataString($d))&outputFormat=JSON"
  $resp = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 20 -ErrorAction Stop
  if ($null -eq $resp) { return $null }
  return $resp
}

function Invoke-GoDaddyWhoisLookup {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain
  )

  $apiKey = $env:GODADDY_API_KEY
  $apiSecret = $env:GODADDY_API_SECRET

  if ([string]::IsNullOrWhiteSpace($apiKey) -and -not [string]::IsNullOrWhiteSpace($script:GoDaddyApiKey)) {
    $apiKey = $script:GoDaddyApiKey
  }
  if ([string]::IsNullOrWhiteSpace($apiSecret) -and -not [string]::IsNullOrWhiteSpace($script:GoDaddyApiSecret)) {
    $apiSecret = $script:GoDaddyApiSecret
  }
  if ([string]::IsNullOrWhiteSpace($apiKey) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiKey)) {
    $apiKey = $GoDaddyApiKey
  }
  if ([string]::IsNullOrWhiteSpace($apiSecret) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiSecret)) {
    $apiSecret = $GoDaddyApiSecret
  }
  if ([string]::IsNullOrWhiteSpace($apiKey) -or [string]::IsNullOrWhiteSpace($apiSecret)) {
    throw "GODADDY_API_KEY or GODADDY_API_SECRET is not set. Configure both to use GoDaddy WHOIS fallback."
  }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $uri = "https://api.godaddy.com/v1/domains/$([uri]::EscapeDataString($d))"
  $headers = @{ Authorization = "sso-key $apiKey`:$apiSecret" }
  try {
    Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 20 -ErrorAction Stop
  }
  catch [System.Net.WebException] {
    # Surface HTTP status code + response body for debugging (e.g., 403 Forbidden vs quota/auth).
    $resp = $_.Exception.Response
    $status = $null
    $body = $null
    try { if ($resp -and $resp.StatusCode) { $status = [int]$resp.StatusCode } } catch { $status = $null }
    try {
      if ($resp -and $resp.GetResponseStream()) {
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd()
        $reader.Dispose()
      }
    } catch { $body = $null }

    $msg = "GoDaddy WHOIS HTTP error" + $(if ($status) { " ($status)" } else { '' })
    if (-not [string]::IsNullOrWhiteSpace($body)) { $msg += ": $body" }
    elseif ($_.Exception.Message) { $msg += ": $($_.Exception.Message)" }
    throw $msg
  }
}

function ConvertTo-NullableUtcIso8601 {
  param([object]$Value)

  if ($null -eq $Value) { return $null }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  # Normalize common timezone abbreviations that DateTime parsing often fails on (e.g., CLST/CLT from Sysinternals whois).
  $normalized = $s.Trim()
  $tzMap = @{
    'CLST' = '-03:00'  # Chile Summer Time (UTC-3)
    'CLT'  = '-04:00'  # Chile Standard Time (UTC-4)
  }
  foreach ($kv in $tzMap.GetEnumerator()) {
    $abbr = [regex]::Escape($kv.Key)
    if ([regex]::IsMatch($normalized, "(?i)\b$abbr\b")) {
      $normalized = [regex]::Replace($normalized, "(?i)\b$abbr\b", " $($kv.Value)")
      $normalized = $normalized.Trim()
      break
    }
  }
  $s = $normalized

  $dt = [DateTimeOffset]::MinValue
  if ([DateTimeOffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
    return $dt.UtcDateTime.ToString('o')
  }

  $dt2 = [DateTime]::MinValue
  if ([DateTime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt2)) {
    return ([DateTime]::SpecifyKind($dt2, [DateTimeKind]::Utc)).ToString('o')
  }

  # Explicit format fallbacks (helps strings like "yyyy-MM-dd HH:mm:ss -03:00" that sometimes fail generic parsing).
  $patterns = @(
    'yyyy-MM-dd HH:mm:ss zzz',
    'yyyy-MM-dd HH:mm:sszzz',
    'yyyy-MM-dd HH:mm:ssK'
  )
  foreach ($fmt in $patterns) {
    if ([DateTimeOffset]::TryParseExact($s, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
      return $dt.UtcDateTime.ToString('o')
    }
  }

  return $null
}

function Get-DomainAgeDays {
  param([string]$CreationDateUtc)

  if ([string]::IsNullOrWhiteSpace($CreationDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($CreationDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }
  $age = [DateTimeOffset]::UtcNow - $dto.ToUniversalTime()
  return [int][Math]::Floor($age.TotalDays)
}

function Get-DomainAgeParts {
  param([string]$CreationDateUtc)

  if ([string]::IsNullOrWhiteSpace($CreationDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($CreationDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }

  $start = $dto.UtcDateTime.Date
  $now   = [DateTime]::UtcNow.Date
  if ($now -lt $start) { return $null }

  $years = $now.Year - $start.Year
  if ($now -lt $start.AddYears($years)) { $years-- }

  $months = $now.Month - $start.Month
  if ($now.Day -lt $start.Day) { $months-- }
  if ($months -lt 0) { $months += 12 }

  $days = ($now - $start.AddYears($years).AddMonths($months)).Days
  if ($days -lt 0) { $days = 0 }

  [pscustomobject]@{ years = $years; months = $months; days = $days }
}

function Format-DomainAge {
  param([string]$CreationDateUtc)

  $parts = Get-DomainAgeParts -CreationDateUtc $CreationDateUtc
  if (-not $parts) { return $null }

  $segments = New-Object System.Collections.Generic.List[string]
  if ($parts.years -gt 0)   { $segments.Add(('{0} year{1}'   -f $parts.years,  $(if ($parts.years  -eq 1) { '' } else { 's' }))) }
  if ($parts.months -gt 0)  { $segments.Add(('{0} month{1}'  -f $parts.months, $(if ($parts.months -eq 1) { '' } else { 's' }))) }
  if ($parts.days -gt 0 -or $segments.Count -eq 0) { $segments.Add(('{0} day{1}' -f $parts.days,   $(if ($parts.days   -eq 1) { '' } else { 's' }))) }

  return ($segments -join ', ')
}

function Get-TimeUntilParts {
  param([string]$ExpiryDateUtc)

  if ([string]::IsNullOrWhiteSpace($ExpiryDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($ExpiryDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }

  $start = [DateTime]::UtcNow.Date
  $end   = $dto.UtcDateTime.Date
  if ($end -le $start) { return $null }

  $years = $end.Year - $start.Year
  if ($end -lt $start.AddYears($years)) { $years-- }

  $months = $end.Month - $start.Month
  if ($end.Day -lt $start.Day) { $months-- }
  if ($months -lt 0) { $months += 12 }

  $days = ($end - $start.AddYears($years).AddMonths($months)).Days
  if ($days -lt 0) { $days = 0 }

  [pscustomobject]@{ years = $years; months = $months; days = $days }
}

function Format-ExpiryRemaining {
  param([string]$ExpiryDateUtc)

  if ([string]::IsNullOrWhiteSpace($ExpiryDateUtc)) { return $null }

  $parts = Get-TimeUntilParts -ExpiryDateUtc $ExpiryDateUtc
  if (-not $parts) { return 'Expired' }

  $segments = New-Object System.Collections.Generic.List[string]
  if ($parts.years -gt 0)   { $segments.Add(('{0} year{1}'   -f $parts.years,  $(if ($parts.years  -eq 1) { '' } else { 's' }))) }
  if ($parts.months -gt 0)  { $segments.Add(('{0} month{1}'  -f $parts.months, $(if ($parts.months -eq 1) { '' } else { 's' }))) }
  if ($parts.days -gt 0 -or $segments.Count -eq 0) { $segments.Add(('{0} day{1}' -f $parts.days,   $(if ($parts.days   -eq 1) { '' } else { 's' }))) }

  return ($segments -join ', ')
}

function Get-DomainRegistrationStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [int]$NewDomainWarnThresholdDays = 180,
    [int]$NewDomainErrorThresholdDays = 90
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) {
    return [pscustomobject]@{
      domain = $Domain
      source = $null
      creationDateUtc = $null
      expiryDateUtc = $null
      registrar = $null
      registrant = $null
      ageDays = $null
      isYoungDomain = $null
      isVeryYoungDomain = $null
      newDomainThresholdDays = $NewDomainWarnThresholdDays
      newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
      newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
      error = 'Missing domain'
    }
  }

  # Use registrable domain for WHOIS/RDAP to avoid subdomain lookups failing (common in ACA scenarios)
  $whoisDomain = Get-RegistrableDomain -Domain $d
  if ([string]::IsNullOrWhiteSpace($whoisDomain)) { $whoisDomain = $d }

  $creation = $null
  $expiry = $null
  $registrar = $null
  $registrant = $null
  $source = $null
  $raw = $null
  $whoisError = $null
  $rawWhoisText = $null

  $rdapError = $null
  try {
    # Throw on RDAP failures so fallback providers can be invoked.
    $raw = Invoke-RdapLookup -Domain $whoisDomain -ThrowOnError
    $source = 'RDAP'

    if ($raw -and $raw.events) {
      foreach ($ev in @($raw.events)) {
        $action = [string]$ev.eventAction
        if (-not $creation -and $action -eq 'registration') {
          $creation = ConvertTo-NullableUtcIso8601 $ev.eventDate
        }
        elseif (-not $expiry -and $action -eq 'expiration') {
          $expiry = ConvertTo-NullableUtcIso8601 $ev.eventDate
        }
      }
    }

    if (-not $registrar -and $raw -and $raw.registrarName) {
      $registrar = [string]$raw.registrarName
    } elseif ($raw -and $raw.entities) {
      foreach ($ent in @($raw.entities)) {
        $roles = @($ent.roles)
        if (-not $registrar -and $roles -contains 'registrar') {
          if ($ent.vcardArray -and $ent.vcardArray.Count -ge 2) {
            foreach ($kv in @($ent.vcardArray[1])) {
              if ($kv.Count -ge 4 -and [string]$kv[0] -eq 'fn') { $registrar = [string]$kv[3] }
            }
          }
        }
        if (-not $registrant -and $roles -contains 'registrant') {
          if ($ent.vcardArray -and $ent.vcardArray.Count -ge 2) {
            foreach ($kv in @($ent.vcardArray[1])) {
              if ($kv.Count -ge 4 -and [string]$kv[0] -eq 'fn') { $registrant = [string]$kv[3] }
            }
          }
        }
      }
    }
  }
  catch {
    $rdapError = $_.Exception.Message
    $usedFallback = $false
    $goDaddyError = $null
    $sysWhoisError = $null
    $linuxWhoisError = $null
    $whoisXmlError = $null

    # Prefer GoDaddy fallback when API key/secret are available.
    $gdKey = $env:GODADDY_API_KEY
    $gdSecret = $env:GODADDY_API_SECRET
    if ([string]::IsNullOrWhiteSpace($gdKey) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiKey)) { $gdKey = $GoDaddyApiKey }
    if ([string]::IsNullOrWhiteSpace($gdSecret) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiSecret)) { $gdSecret = $GoDaddyApiSecret }
    if (-not [string]::IsNullOrWhiteSpace($gdKey) -and -not [string]::IsNullOrWhiteSpace($gdSecret)) {
      try {
        $raw = Invoke-GoDaddyWhoisLookup -Domain $whoisDomain
        $source = 'GoDaddy'
        # GoDaddy domain API returns createdAt / expires fields (ISO8601).
        $creation = ConvertTo-NullableUtcIso8601 $raw.createdAt
        $expiry   = ConvertTo-NullableUtcIso8601 $raw.expires
        if (-not $registrar) { $registrar = 'GoDaddy' }
        $usedFallback = $true
      }
      catch {
        $goDaddyError = $_.Exception.Message
      }
    }

    # Platform detection: prefer runtime API; fall back to $IsWindows/PSVersionTable
    $isWindowsPlatform = $false
    try {
      $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    } catch { }
    if (-not $isWindowsPlatform) {
      try { if ($IsWindows -eq $true) { $isWindowsPlatform = $true } } catch { }
    }
    if (-not $isWindowsPlatform) {
      try { if ($PSVersionTable.Platform -eq 'Win32NT') { $isWindowsPlatform = $true } } catch { }
    }
    $isLinuxPlatform = -not $isWindowsPlatform

    # Linux whois fallback (generic CLI)
    if (-not $usedFallback -and $isLinuxPlatform) {
      try {
        $raw = Invoke-LinuxWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $linCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $linCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $linCreation = $raw.creationDate }

          $linExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $linExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $linExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $linCreation }
          if (-not $expiry)   { $expiry   = $linExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          # Best-effort: if creation/expiry still null, re-parse from raw text.
          if (-not $creation -and $rawWhoisText -match '(?im)^Creation date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $creation = if ($parsed) { $parsed } else { $val }
          }
          if (-not $expiry -and $rawWhoisText -match '(?im)^Expiration date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $expiry = if ($parsed) { $parsed } else { $val }
          }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)

          if ($hasParsedFields) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          elseif ($hasRawText) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          else {
            $linuxWhoisError = "Linux whois returned output but no registrant/registrar/dates could be parsed."
          }
        }
      }
      catch {
        $linuxWhoisError = $_.Exception.Message
      }
    }

    # Sysinternals whois fallback (Windows-only)
    if (-not $usedFallback -and $isWindowsPlatform) {
      try {
        $raw = Invoke-SysinternalsWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $sysCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $sysCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $sysCreation = $raw.creationDate }

          $sysExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $sysExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $sysExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $sysCreation }
          if (-not $expiry)   { $expiry   = $sysExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          # Best-effort: if creation/expiry still null, re-parse from raw text (Sysinternals label casing varies).
          if (-not $creation -and $rawWhoisText -match '(?im)^Creation date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $creation = if ($parsed) { $parsed } else { $val }
          }
          if (-not $expiry -and $rawWhoisText -match '(?im)^Expiration date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $expiry = if ($parsed) { $parsed } else { $val }
          }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)

          if ($hasParsedFields) {
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          elseif ($hasRawText) {
            # Treat raw output as success (no error) so the UI can show the text instead of an error-only state.
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          else {
            $sysWhoisError = "Sysinternals whois returned output but no registrant/registrar/dates could be parsed."
          }
        }
      }
      catch {
        $sysWhoisError = $_.Exception.Message
      }
    }

    # Secondary fallback: WhoisXML if configured.
    if (-not $usedFallback) {
      $apiKey = $env:ACS_WHOISXML_API_KEY
      if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
        try {
          $raw = Invoke-WhoisXmlLookup -Domain $d
          $source = 'WhoisXML'
          $w = $raw.WhoisRecord

          if ($w) {
            $creation = ConvertTo-NullableUtcIso8601 $w.createdDate
            if (-not $creation) { $creation = ConvertTo-NullableUtcIso8601 $w.registryData.createdDate }

            $expiry = ConvertTo-NullableUtcIso8601 $w.expiresDate
            if (-not $expiry) { $expiry = ConvertTo-NullableUtcIso8601 $w.registryData.expiresDate }

            if ($w.registrarName) { $registrar = [string]$w.registrarName }
            elseif ($w.registrar) { $registrar = [string]$w.registrar }
            elseif ($w.registryData.registrarName) { $registrar = [string]$w.registryData.registrarName }

            if ($w.registrant -and $w.registrant.name) { $registrant = [string]$w.registrant.name }
            elseif ($w.registryData.registrant -and $w.registryData.registrant.name) { $registrant = [string]$w.registryData.registrant.name }
          }
          $usedFallback = $true
        }
        catch {
          $whoisXmlError = $_.Exception.Message
        }
      }
    }

    if (-not $usedFallback) {
      $err = "RDAP lookup failed."
      if ($rdapError) { $err += " RDAP error: $rdapError." }
      if ($goDaddyError) { $err += " GoDaddy error: $goDaddyError." }
      elseif ([string]::IsNullOrWhiteSpace($gdKey) -or [string]::IsNullOrWhiteSpace($gdSecret)) { $err += " GoDaddy not configured." }
      if ($sysWhoisError) { $err += " Sysinternals whois error: $sysWhoisError." }
      if ($whoisXmlError) { $err += " WhoisXML error: $whoisXmlError." }
      elseif ([string]::IsNullOrWhiteSpace($apiKey)) { $err += " WhoisXML not configured." }

      return [pscustomobject]@{
        domain = $d
        source = $null
        creationDateUtc = $null
        expiryDateUtc = $null
        registrar = $null
        registrant = $null
        ageDays = $null
        ageHuman = $null
        isYoungDomain = $null
        isVeryYoungDomain = $null
        newDomainThresholdDays = $NewDomainWarnThresholdDays
        newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
        newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
        error = $err.Trim()
      }
    }
  }

  $ageDays = Get-DomainAgeDays -CreationDateUtc $creation
  $ageHuman = Format-DomainAge -CreationDateUtc $creation
  $isYoungWarn = if ($null -ne $ageDays) { $ageDays -lt $NewDomainWarnThresholdDays } else { $null }
  $isYoungError = if ($null -ne $ageDays) { $ageDays -lt $NewDomainErrorThresholdDays } else { $null }

  $expiryDays = $null
  $isExpired = $null
  $expiryHuman = $null
  if (-not [string]::IsNullOrWhiteSpace($expiry)) {
    $dtoExpiry = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($expiry, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dtoExpiry)) {
      $expiryDays = [int][Math]::Floor(($dtoExpiry.ToUniversalTime() - [DateTimeOffset]::UtcNow).TotalDays)
      $isExpired = ($expiryDays -le 0)
      $expiryHuman = Format-ExpiryRemaining -ExpiryDateUtc $expiry
    }
  }

  # Only surface raw whois text when no structured fields were parsed (prevents noise when data was already extracted).
  $hasStructuredWhois = $creation -or $expiry -or $registrar -or $registrant
  if ($hasStructuredWhois) { $rawWhoisText = $null }

  # If we obtained a source (success from any provider), suppress earlier fallback errors to avoid misleading UI.
  if ($source) {
    $rdapError = $null
    $goDaddyError = $null
    $sysWhoisError = $null
    $whoisXmlError = $null
  }

  if ($sysWhoisError -and -not $whoisError) { $whoisError = $sysWhoisError }
  if ($linuxWhoisError -and -not $whoisError) { $whoisError = $linuxWhoisError }
  if ($goDaddyError -and -not $whoisError) { $whoisError = $goDaddyError }
  if ($whoisXmlError -and -not $whoisError) { $whoisError = $whoisXmlError }
  if ($rdapError -and -not $whoisError) { $whoisError = $rdapError }

  [pscustomobject]@{
    domain = $d
    source = $source
    creationDateUtc = $creation
    expiryDateUtc = $expiry
    registrar = $registrar
    registrant = $registrant
    ageDays = $ageDays
    ageHuman = $ageHuman
    isYoungDomain = $isYoungWarn
    isVeryYoungDomain = $isYoungError
    expiryDays = $expiryDays
    isExpired = $isExpired
    expiryHuman = $expiryHuman
    newDomainThresholdDays = $NewDomainWarnThresholdDays
    newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
    newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
    rawWhoisText = $rawWhoisText
    error = $whoisError
  }
}

if (-not [string]::IsNullOrWhiteSpace($DohEndpoint)) {
  $env:ACS_DNS_DOH_ENDPOINT = $DohEndpoint
}

$serverMode = 'HttpListener'
$listener = $null
$tcpListener = $null
$serverStarted = $false

$displayUrl = "http://localhost:$Port"

try {
  $listener = [System.Net.HttpListener]::new()

  # Choose the listener prefix based on the requested binding mode.
  # - On Windows, `+` is commonly used for "all interfaces".
  # - Cross-platform, `*` is the most portable wildcard hostname in HttpListener prefixes.
  # - `localhost` is loopback-only.
  $prefix = switch ($Bind) {
    'Localhost' { "http://localhost:$Port/" }
    'Any'       { if ($IsWindows) { "http://+:$Port/" } else { "http://*:$Port/" } }
    default     {
      # Auto: prefer loopback on Windows to avoid URL ACL requirements unless explicitly bound to Any.
      if ($IsWindows -and -not $script:IsContainer) { "http://localhost:$Port/" }
      elseif ($IsWindows) { "http://+:$Port/" }
      elseif ($script:IsContainer) { "http://*:$Port/" }
      else { "http://localhost:$Port/" }
    }
  }
  $listener.Prefixes.Add($prefix)
  $listener.Start()
  $serverStarted = $true
}
catch {
  # HttpListener may be unavailable (Linux/macOS) or blocked by URL ACL permissions on Windows.
  $listener = $null
  $exc = $_.Exception
  $deny = $false
  if ($exc -is [System.UnauthorizedAccessException]) { $deny = $true }
  elseif ($exc -is [System.Net.HttpListenerException] -and $exc.ErrorCode -eq 5) { $deny = $true }

  if (-not $IsWindows -or $deny) {
    $serverMode = 'TcpListener'
  } else {
    Write-Error -Message "HttpListener failed to start on $prefix : $($_.Exception.Message)" -ErrorAction Continue
    throw
  }
}

if ($serverMode -eq 'TcpListener') {
  # TcpListener fallback should match the binding intent:
  # - Localhost/Auto -> loopback only
  # - Any            -> all interfaces (0.0.0.0)
  $effectiveAny = ($Bind -eq 'Any') -or (($Bind -eq 'Auto') -and (-not $IsWindows) -and $script:IsContainer)
  $bindAddress = if ($effectiveAny) { [System.Net.IPAddress]::Any } else { [System.Net.IPAddress]::Loopback }
  $tcpListener = [System.Net.Sockets.TcpListener]::new($bindAddress, $Port)
  try {
    $tcpListener.Start()
    $serverStarted = $true
  }
  catch {
    # If the socket cannot be opened (e.g., ACL/port in use), fall back to stopped mode so the loop doesn't crash.
    Write-Error -Message "TcpListener failed to start on $bindAddress`:$Port : $($_.Exception.Message)" -ErrorAction Continue
    $tcpListener = $null
    $serverMode = 'Stopped'
  }
}

if ($serverStarted) {
  Write-Information -InformationAction Continue -MessageData "ACS Email Domain Checker running at $displayUrl"

  # Also write version to the console for quick visibility during startup.
  Write-Information -InformationAction Continue -MessageData "ACS Email Domain Checker version: $($script:AppVersion)"

  if ($env:ACS_ENABLE_ANON_METRICS -eq '1') {
    Write-Information -InformationAction Continue -MessageData "Anonymous metrics: ENABLED (no PII). Metrics file: $([System.IO.Path]::GetFullPath($env:ACS_ANON_METRICS_FILE))"
  } else {
    Write-Information -InformationAction Continue -MessageData "Anonymous metrics: DISABLED. Start with -EnableAnonymousMetrics to enable /api/metrics counters."
  }

  if (-not [string]::IsNullOrWhiteSpace($env:ACS_API_KEY)) {
    Write-Information -InformationAction Continue -MessageData 'API key authentication: ENABLED (send X-Api-Key to /api/* and /dns).'
  } else {
    Write-Information -InformationAction Continue -MessageData 'API key authentication: DISABLED.'
  }

  if ($rateLimitPerMinute -gt 0) {
    Write-Information -InformationAction Continue -MessageData "Rate limiting: $rateLimitPerMinute requests/min per client IP."
  } else {
    Write-Information -InformationAction Continue -MessageData 'Rate limiting: DISABLED.'
  }
} else {
  Write-Error -Message "Server did not start. The port may be in use or requires additional permissions. Try a different -Port or adjust -Bind (Auto/Localhost/Any)." -ErrorAction Continue
  return
}

# ------------------- ANONYMOUS METRICS (IN-MEMORY) -------------------
# Metrics are kept in-memory for this process lifetime only.
# No PII: do not store IP addresses, user agents, domains, or request query strings/headers.

# Domain-centric counters (no domain names persisted)
$AcsMetrics = @{
  startedAtUtc        = ([DateTime]::UtcNow.ToString('o'))
  totalDomains        = [ref][int64]0      # Session count of domain lookups (one per lookup)
  totalUniqueDomains  = [ref][int64]0      # Session unique domains (in-memory only)
  uniqueDomains       = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  lifetimeUniqueHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  activeLookups       = [ref][int64]0      # In-flight domain lookups (session only)
  sessions            = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Microsoft employee ID hashes (no PII, only HMAC-SHA256 hashes)
  msEmployeeIdHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  lifetimeMsEmployeeIdHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Auth counters (no PII; counts only)
  totalMsAuthVerifications = [ref][int64]0

  # Persisted, lifetime counters (no domain names stored)
  lifetimeFirstSeenUtc   = $null
  lifetimeTotalDomains   = [ref][int64]0
  lifetimeUniqueDomains  = [ref][int64]0
  lifetimeTotalUptimeBase = [int64]0

  lifetimeMsAuthVerifications = [ref][int64]0

  _lastPersistUtc        = $null
  _lastPersistDomains    = [ref][int64]0
}

# Monotonic uptime tracker (avoids skew from persisted timestamps or clock changes).
$AcsUptime = [System.Diagnostics.Stopwatch]::StartNew()

$AcsMetricsPersistLock = [object]::new()

# CRITICAL: Store these in global scope so they can be referenced when creating InitialSessionState
$global:AcsMetrics = $AcsMetrics
$global:AcsMetricsPersistLock = $AcsMetricsPersistLock
$global:AcsUptime = $AcsUptime

$AcsRateLimitStore = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$AcsRateLimitLock = [object]::new()
$global:AcsRateLimitStore = $AcsRateLimitStore
$global:AcsRateLimitLock = $AcsRateLimitLock

function Get-AnonymousMetricsPersistPath {
  $p = $env:ACS_ANON_METRICS_FILE
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  return $p
}

function Load-AnonymousMetricsPersisted {
  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  $path = Get-AnonymousMetricsPersistPath
  if ([string]::IsNullOrWhiteSpace($path)) { return }

  $mtx = Acquire-MetricsFileMutex
  if (-not $mtx) { return }

  $nowUtc = [DateTime]::UtcNow.ToString('o')

  try {
    if (-not (Test-Path -LiteralPath $path)) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
      return
    }

    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
      return
    }

    $data = $raw | ConvertFrom-Json -ErrorAction Stop

    $script:AcsMetrics['lifetimeFirstSeenUtc'] = [string]$data.firstSeenUtc
    if ([string]::IsNullOrWhiteSpace($script:AcsMetrics['lifetimeFirstSeenUtc'])) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
    }

    # If no env hash key was provided, reuse persisted hashKey for stable unique-domain counting across restarts.
    if ([string]::IsNullOrWhiteSpace($script:MetricsHashKey) -and $data.PSObject.Properties.Match('hashKey').Count -gt 0) {
      $k = [string]$data.hashKey
      if (-not [string]::IsNullOrWhiteSpace($k)) {
        $script:MetricsHashKey = $k
        $env:ACS_METRICS_HASH_KEY = $k
        $MetricsHashKey = $k
      }
    }

    # Backward compatibility: schemaVersion 1 used lifetimeTotalRequests
    $td = [int64]0
    $tud = [int64]0
    $ttu = [int64]0
    $tma = [int64]0
    $tme = [int64]0
    $tmx = [int64]0
    try {
      if ($data.PSObject.Properties.Match('lifetimeTotalDomains').Count -gt 0) {
        $td = [int64]$data.lifetimeTotalDomains
      } elseif ($data.PSObject.Properties.Match('lifetimeTotalRequests').Count -gt 0) {
        $td = [int64]$data.lifetimeTotalRequests
      }

      if ($data.PSObject.Properties.Match('lifetimeUniqueDomains').Count -gt 0) {
        $tud = [int64]$data.lifetimeUniqueDomains
      } elseif ($td -gt 0) {
        # Best-effort: if no unique field, assume all were unique historically.
        $tud = $td
      }

      if ($data.PSObject.Properties.Match('lifetimeTotalUptimeSeconds').Count -gt 0) {
        $ttu = [int64]$data.lifetimeTotalUptimeSeconds
      } elseif ($data.PSObject.Properties.Match('lifetimeTotalUptime').Count -gt 0) {
        # Backward compat (older field name)
        $ttu = [int64]$data.lifetimeTotalUptime
      }

      if ($data.PSObject.Properties.Match('lifetimeMsAuthVerifications').Count -gt 0) {
        $tma = [int64]$data.lifetimeMsAuthVerifications
      }
      if ($data.PSObject.Properties.Match('lifetimeMsEmployeeVerifications').Count -gt 0) {
        $tme = [int64]$data.lifetimeMsEmployeeVerifications
      }
      if ($data.PSObject.Properties.Match('lifetimeMsExternalVerifications').Count -gt 0) {
        $tmx = [int64]$data.lifetimeMsExternalVerifications
      }
    } catch { $td = 0; $tud = 0 }
    $script:AcsMetrics['lifetimeTotalDomains'].Value = $td
    $script:AcsMetrics['lifetimeTotalUptimeBase'] = $ttu
    $script:AcsMetrics['lifetimeMsAuthVerifications'].Value = $tma
    $script:AcsMetrics['lifetimeMsEmployeeVerifications'].Value = $tme
    $script:AcsMetrics['lifetimeMsExternalVerifications'].Value = $tmx

    # Restore lifetime unique hash set (hashed domains only; no plaintext stored).
    try {
      $hashes = @()
      if ($data.PSObject.Properties.Match('lifetimeUniqueHashes').Count -gt 0) {
        $hashes = @($data.lifetimeUniqueHashes)
      }
      if (-not $hashes -or $hashes.Count -eq 0) {
        # Backward compatibility: if not present, fall back to count only.
        $script:AcsMetrics['lifetimeUniqueDomains'].Value = $tud
      } else {
        foreach ($h in $hashes) {
          $s = [string]$h
          if ([string]::IsNullOrWhiteSpace($s)) { continue }
          $null = $script:AcsMetrics['lifetimeUniqueHashes'].TryAdd($s, 0)
        }
        $script:AcsMetrics['lifetimeUniqueDomains'].Value = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count
      }
    } catch {
      $script:AcsMetrics['lifetimeUniqueDomains'].Value = $tud
    }
  }
  catch {
    # If the file is corrupt/unreadable, start fresh (still no PII persisted).
    $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
  }
  finally {
    try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { }
  }

}

# Refresh in-memory instance heartbeat and prune stale entries (no file write).
function Save-AnonymousMetricsPersisted {
  param(
    [switch]$Force
  )

  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  $path = Get-AnonymousMetricsPersistPath
  if ([string]::IsNullOrWhiteSpace($path)) { return }

  $mtx = Acquire-MetricsFileMutex
  if (-not $mtx) { return }

  $now = [DateTime]::UtcNow

  # Throttle writes unless forced, but always write when domain count changed.
  try {
    $domainsNow = $script:AcsMetrics['lifetimeTotalDomains'].Value
    if (-not $Force -and $script:AcsMetrics['_lastPersistDomains'].Value -ne $domainsNow) {
      $Force = $true
    }

    if (-not $Force -and $script:AcsMetrics['_lastPersistUtc']) {
      $age = $now - [DateTime]::Parse($script:AcsMetrics['_lastPersistUtc'])
      if ($age.TotalSeconds -lt 5) { return }
    }
  } catch { }

  try {
    [System.Threading.Monitor]::Enter($script:AcsMetricsPersistLock)

    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $existingLifetimeTotalDomains = [int64]0
    $existingLifetimeUniqueDomains = [int64]0
    $existingLifetimeTotalUptimeSeconds = [int64]0
    try {
      if (Test-Path -LiteralPath $path) {
        $existingRaw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($existingRaw)) {
          $existingData = $existingRaw | ConvertFrom-Json -ErrorAction Stop
          if ($existingData.PSObject.Properties.Match('lifetimeTotalDomains').Count -gt 0) {
            $existingLifetimeTotalDomains = [int64]$existingData.lifetimeTotalDomains
          }
          if ($existingData.PSObject.Properties.Match('lifetimeUniqueDomains').Count -gt 0) {
            $existingLifetimeUniqueDomains = [int64]$existingData.lifetimeUniqueDomains
          }
          if ($existingData.PSObject.Properties.Match('lifetimeTotalUptimeSeconds').Count -gt 0) {
            $existingLifetimeTotalUptimeSeconds = [int64]$existingData.lifetimeTotalUptimeSeconds
          } elseif ($existingData.PSObject.Properties.Match('lifetimeTotalUptime').Count -gt 0) {
            $existingLifetimeTotalUptimeSeconds = [int64]$existingData.lifetimeTotalUptime
          }
          if ($existingData.PSObject.Properties.Match('lifetimeUniqueHashes').Count -gt 0 -and $existingData.lifetimeUniqueHashes) {
            foreach ($h in @($existingData.lifetimeUniqueHashes)) {
              $s = [string]$h
              if ([string]::IsNullOrWhiteSpace($s)) { continue }
              $null = $script:AcsMetrics['lifetimeUniqueHashes'].TryAdd($s, 0)
            }
          }
        }
      }
    } catch { }

    $currentUptime = 0
    try {
      if ($AcsUptime) { $currentUptime = [int64][Math]::Floor($AcsUptime.Elapsed.TotalSeconds) }
    } catch { $currentUptime = 0 }

    $mergedLifetimeTotalDomains = [int64]([Math]::Max($script:AcsMetrics['lifetimeTotalDomains'].Value, $existingLifetimeTotalDomains))
    $mergedLifetimeUniqueDomains = [int64]([Math]::Max($script:AcsMetrics['lifetimeUniqueDomains'].Value, $existingLifetimeUniqueDomains))
    $currentLifetimeUptime = [int64]($script:AcsMetrics['lifetimeTotalUptimeBase'] + $currentUptime)
    $mergedLifetimeTotalUptimeSeconds = [int64]([Math]::Max($currentLifetimeUptime, $existingLifetimeTotalUptimeSeconds))

    # lifetimeMsEmployeeVerifications is derived from lifetimeMsEmployeeIdHashes.Count, so
    # we do not need to merge per-counter values from the file. We keep only lifetimeMsAuthVerifications
    # for coarse-grained auth usage and rely on the hash set for unique employee counts.
    $existingLifetimeMsAuthVerifications = [int64]0
    try {
      if (Test-Path -LiteralPath $path) {
        $existingRaw2 = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($existingRaw2)) {
          $existingData2 = $existingRaw2 | ConvertFrom-Json -ErrorAction Stop
          if ($existingData2.PSObject.Properties.Match('lifetimeMsAuthVerifications').Count -gt 0) {
            $existingLifetimeMsAuthVerifications = [int64]$existingData2.lifetimeMsAuthVerifications
          }
        }
      }
    } catch { }

    $mergedLifetimeMsAuthVerifications = [int64]([Math]::Max($script:AcsMetrics['lifetimeMsAuthVerifications'].Value, $existingLifetimeMsAuthVerifications))

    if ($mergedLifetimeMsAuthVerifications -gt $script:AcsMetrics['lifetimeMsAuthVerifications'].Value) {
      $script:AcsMetrics['lifetimeMsAuthVerifications'].Value = $mergedLifetimeMsAuthVerifications
    }

    if ($mergedLifetimeTotalDomains -gt $script:AcsMetrics['lifetimeTotalDomains'].Value) {
      $script:AcsMetrics['lifetimeTotalDomains'].Value = $mergedLifetimeTotalDomains
    }
    if ($mergedLifetimeUniqueDomains -gt $script:AcsMetrics['lifetimeUniqueDomains'].Value) {
      $script:AcsMetrics['lifetimeUniqueDomains'].Value = $mergedLifetimeUniqueDomains
    }
    if ($mergedLifetimeTotalUptimeSeconds -gt $currentLifetimeUptime) {
      $script:AcsMetrics['lifetimeTotalUptimeBase'] = [int64]([Math]::Max($script:AcsMetrics['lifetimeTotalUptimeBase'], ($mergedLifetimeTotalUptimeSeconds - $currentUptime)))
    }

    $payload = [pscustomobject]@{
      schemaVersion = 3
      appVersion = $script:AppVersion
      firstSeenUtc = $script:AcsMetrics['lifetimeFirstSeenUtc']
      lastStartedAtUtc = $script:AcsMetrics['startedAtUtc']
      lifetimeTotalDomains = $mergedLifetimeTotalDomains
      lifetimeUniqueDomains = $mergedLifetimeUniqueDomains
      lifetimeUniqueHashes = @($script:AcsMetrics['lifetimeUniqueHashes'].Keys)
      lifetimeTotalUptimeSeconds = $mergedLifetimeTotalUptimeSeconds
      lifetimeMsAuthVerifications = $script:AcsMetrics['lifetimeMsAuthVerifications'].Value
      hashKey = $script:MetricsHashKey
      lifetimeMsEmployeeIdHashes = @($script:AcsMetrics['lifetimeMsEmployeeIdHashes'].Keys)
    }

    $tmp = "$path.tmp"
    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    $script:AcsMetrics['_lastPersistUtc'] = $now.ToString('o')
    try { $script:AcsMetrics['_lastPersistDomains'].Value = $script:AcsMetrics['lifetimeTotalDomains'].Value } catch { }
  }
  catch {
    $null = $_
  }
  finally {
    try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { }
    try { [System.Threading.Monitor]::Exit($script:AcsMetricsPersistLock) } catch { }
  }
}

function New-AnonSessionId {
  # Anonymous, random session id (no derivation from PII).
  [Guid]::NewGuid().ToString('N')
}

function Get-RequestCookies {
  param([string]$CookieHeader)

  $dict = @{}
  if ([string]::IsNullOrWhiteSpace($CookieHeader)) { return $dict }
  foreach ($pair in ($CookieHeader -split ';')) {
    $p = if ($null -eq $pair) { '' } else { [string]$pair }
    $p = $p.Trim()
    if (-not $p) { continue }
    $kv = $p -split '=', 2
    if ($kv.Count -ne 2) { continue }
    $name = if ($null -eq $kv[0]) { '' } else { [string]$kv[0] }
    $name = $name.Trim()
    $val  = if ($null -eq $kv[1]) { '' } else { [string]$kv[1] }
    $val  = $val.Trim()
    if (-not $name) { continue }
    $dict[$name] = $val
  }
  return $dict
}

function Get-OrCreate-AnonymousSessionId {
  param($Context)

  try {
    $cookieHeader = $null
    $props = $Context.Request.PSObject.Properties
    if ($props.Match('Headers').Count -gt 0 -and $Context.Request.Headers) {
      # TcpListener shim uses a hashtable headers dictionary
      if ($Context.Request.Headers.ContainsKey('cookie')) { $cookieHeader = [string]$Context.Request.Headers['cookie'] }
      elseif ($Context.Request.Headers.ContainsKey('Cookie')) { $cookieHeader = [string]$Context.Request.Headers['Cookie'] }
    } elseif ($Context.Request -is [System.Net.HttpListenerRequest]) {
      try { $cookieHeader = [string]$Context.Request.Headers['Cookie'] } catch { $cookieHeader = $null }
    }

    $cookies = Get-RequestCookies -CookieHeader $cookieHeader
    $sid = $null
    if ($cookies.ContainsKey('acs_session')) { $sid = [string]$cookies['acs_session'] }
    if ([string]::IsNullOrWhiteSpace($sid) -or ($sid -notmatch '^[a-fA-F0-9]{32}$')) {
      $sid = New-AnonSessionId
      # Set cookie on response.
      if ($Context.Response -is [System.Net.HttpListenerResponse]) {
        try {
          # HttpOnly prevents JS access to the cookie; Secure ensures it's only sent over HTTPS.
          $isSecure = $false
          try {
            $fwdProto = [string]$Context.Request.Headers['X-Forwarded-Proto']
            if ($fwdProto -eq 'https') { $isSecure = $true }
            elseif ($Context.Request.Url.Scheme -eq 'https') { $isSecure = $true }
          } catch { }
          $securePart = if ($isSecure) { '; Secure' } else { '' }
          $Context.Response.Headers.Add('Set-Cookie', "acs_session=$sid; Path=/; SameSite=Lax; HttpOnly$securePart")
        } catch { }
      } else {
        # TcpListener shim doesn't currently support response headers.
        # Metrics still work, but unique session counting may be lower in this mode.
      }
    }

    # Track unique sessions (in-memory only)
    if (-not [string]::IsNullOrWhiteSpace($sid)) {
      $null = $script:AcsMetrics['sessions'].TryAdd($sid, 0)
    }
    return $sid
  } catch {
    return $null
  }
}

function Update-AnonymousMetrics {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Domain,
    [switch]$Started,
    [switch]$Completed
  )

  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  try {
    if ($Started) {
      [System.Threading.Interlocked]::Increment($script:AcsMetrics['totalDomains']) | Out-Null
      [System.Threading.Interlocked]::Increment($script:AcsMetrics['activeLookups']) | Out-Null
      [System.Threading.Interlocked]::Increment($script:AcsMetrics['lifetimeTotalDomains']) | Out-Null

      if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $hash = Get-HashedDomain $Domain
        if (-not [string]::IsNullOrWhiteSpace($hash)) {
          if ($script:AcsMetrics['uniqueDomains'].TryAdd($hash, 0)) {
            [System.Threading.Interlocked]::Increment($script:AcsMetrics['totalUniqueDomains']) | Out-Null
          }
          if ($script:AcsMetrics['lifetimeUniqueHashes'].TryAdd($hash, 0)) {
            [System.Threading.Interlocked]::Increment($script:AcsMetrics['lifetimeUniqueDomains']) | Out-Null
          }
        }
      }
    }

    if ($Completed) {
      [System.Threading.Interlocked]::Decrement($script:AcsMetrics['activeLookups']) | Out-Null
      Save-AnonymousMetricsPersisted
    }
  } catch {
    $null = $_
  }
}

function Get-AnonymousMetricsSnapshot {
  $uptimeSeconds = 0
  $uptimeFormatted = $null
  $nowSnap = [DateTime]::UtcNow
  try {
    $u = $AcsUptime
    if (-not $u -and $global:AcsUptime) { $u = $global:AcsUptime }

    if ($u -and $u -is [System.Diagnostics.Stopwatch]) {
      $uptimeSeconds = [int][Math]::Floor($u.Elapsed.TotalSeconds)
    } else {
      $started = [DateTimeOffset]::MinValue
      if ([DateTimeOffset]::TryParse([string]$script:AcsMetrics['startedAtUtc'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$started)) {
        $uptimeSeconds = [int][Math]::Floor(([DateTimeOffset]::UtcNow - $started.ToUniversalTime()).TotalSeconds)
      }
    }

    if ($uptimeSeconds -lt 0) { $uptimeSeconds = 0 }

    $ts = [TimeSpan]::FromSeconds($uptimeSeconds)
    $totalDays = [int][Math]::Floor($ts.TotalDays)
    $years = [int][Math]::Floor($totalDays / 365)
    $days  = $totalDays % 365
    $uptimeFormatted = ('{0:D2} year{1}, {2:D2} day{3}, {4:D2} hour{5}, {6:D2} minute{7}, {8:D2} second{9}' -f
      $years,     $(if ($years     -eq 1) { '' } else { 's' }),
      $days,      $(if ($days      -eq 1) { '' } else { 's' }),
      $ts.Hours,   $(if ($ts.Hours   -eq 1) { '' } else { 's' }),
      $ts.Minutes, $(if ($ts.Minutes -eq 1) { '' } else { 's' }),
      $ts.Seconds, $(if ($ts.Seconds -eq 1) { '' } else { 's' }))
  } catch { }

  $shouldPersistHeartbeat = $false
  try {
    $metricsEnabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
    if ($metricsEnabled) {
      $lastPersistUtc = [string]$script:AcsMetrics['_lastPersistUtc']
      if ([string]::IsNullOrWhiteSpace($lastPersistUtc)) {
        $shouldPersistHeartbeat = $true
      } else {
        $lastPersist = [DateTime]::MinValue
        if ([DateTime]::TryParse($lastPersistUtc, [ref]$lastPersist)) {
          if (([DateTime]::UtcNow - $lastPersist).TotalSeconds -ge 15) {
            $shouldPersistHeartbeat = $true
          }
        } else {
          $shouldPersistHeartbeat = $true
        }
      }
    }
  } catch { $shouldPersistHeartbeat = $false }

  if ($shouldPersistHeartbeat) {
    try { Save-AnonymousMetricsPersisted -Force } catch { $null = $_ }
  }

  $lifetimeTotalUptimeSeconds = [int64]($script:AcsMetrics['lifetimeTotalUptimeBase'] + $uptimeSeconds)
  $lifetimeTotalDomains = [int64]$script:AcsMetrics['lifetimeTotalDomains'].Value
  $lifetimeUniqueDomains = [int64]$script:AcsMetrics['lifetimeUniqueDomains'].Value
  $persistedTotals = $null
  try {
    $path = Get-AnonymousMetricsPersistPath
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
      $mtx = Acquire-MetricsFileMutex
      if ($mtx) {
        try {
          $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
          if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $data = $raw | ConvertFrom-Json -ErrorAction Stop
            $ptd = [int64]0
            $ptu = [int64]0
            $ptt = [int64]0
            try {
              if ($data.PSObject.Properties.Match('lifetimeTotalDomains').Count -gt 0) { $ptd = [int64]$data.lifetimeTotalDomains }
              if ($data.PSObject.Properties.Match('lifetimeUniqueDomains').Count -gt 0) { $ptu = [int64]$data.lifetimeUniqueDomains }
              if ($data.PSObject.Properties.Match('lifetimeTotalUptimeSeconds').Count -gt 0) { $ptt = [int64]$data.lifetimeTotalUptimeSeconds }
              elseif ($data.PSObject.Properties.Match('lifetimeTotalUptime').Count -gt 0) { $ptt = [int64]$data.lifetimeTotalUptime }
            } catch { }
            $persistedTotals = @{ totalDomains = $ptd; uniqueDomains = $ptu; totalUptimeSeconds = $ptt }
          }
        } finally { try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { } }
      }
    }
  } catch { $persistedTotals = $null }
  if ($persistedTotals) {
    $lifetimeTotalDomains = [int64]([Math]::Max($lifetimeTotalDomains, [int64]$persistedTotals.totalDomains))
    $lifetimeUniqueDomains = [int64]([Math]::Max($lifetimeUniqueDomains, [int64]$persistedTotals.uniqueDomains))
    $lifetimeTotalUptimeSeconds = [int64]([Math]::Max($lifetimeTotalUptimeSeconds, [int64]$persistedTotals.totalUptimeSeconds))
  }
  if (-not $script:LastLifetimeSnapshot) {
    $script:LastLifetimeSnapshot = @{
      totalDomains = $lifetimeTotalDomains
      uniqueDomains = $lifetimeUniqueDomains
      totalUptimeSeconds = $lifetimeTotalUptimeSeconds
    }
  } else {
    $lifetimeTotalDomains = [int64]([Math]::Max($lifetimeTotalDomains, [int64]$script:LastLifetimeSnapshot.totalDomains))
    $lifetimeUniqueDomains = [int64]([Math]::Max($lifetimeUniqueDomains, [int64]$script:LastLifetimeSnapshot.uniqueDomains))
    $lifetimeTotalUptimeSeconds = [int64]([Math]::Max($lifetimeTotalUptimeSeconds, [int64]$script:LastLifetimeSnapshot.totalUptimeSeconds))
    $script:LastLifetimeSnapshot.totalDomains = $lifetimeTotalDomains
    $script:LastLifetimeSnapshot.uniqueDomains = $lifetimeUniqueDomains
    $script:LastLifetimeSnapshot.totalUptimeSeconds = $lifetimeTotalUptimeSeconds
  }
  $lifetimeTotalUptimeFormatted = $null
  try {
    $lts = [TimeSpan]::FromSeconds($lifetimeTotalUptimeSeconds)
    $ltTotalDays = [int][Math]::Floor($lts.TotalDays)
    $ltYears = [int][Math]::Floor($ltTotalDays / 365)
    $ltDays  = $ltTotalDays % 365
    $lifetimeTotalUptimeFormatted = ('{0:D2} year{1}, {2:D2} day{3}, {4:D2} hour{5}, {6:D2} minute{7}, {8:D2} second{9}' -f
      $ltYears,     $(if ($ltYears     -eq 1) { '' } else { 's' }),
      $ltDays,      $(if ($ltDays      -eq 1) { '' } else { 's' }),
      $lts.Hours,   $(if ($lts.Hours   -eq 1) { '' } else { 's' }),
      $lts.Minutes, $(if ($lts.Minutes -eq 1) { '' } else { 's' }),
      $lts.Seconds, $(if ($lts.Seconds -eq 1) { '' } else { 's' }))
  } catch { }

  [pscustomobject]@{
    enabled = ($script:EnableAnonymousMetrics -or ($env:ACS_ENABLE_ANON_METRICS -eq '1'))
    appVersion = $script:AppVersion
    startedAtUtc = $script:AcsMetrics['startedAtUtc']
    uptimeSeconds = $uptimeSeconds
    uptimeFormatted = $uptimeFormatted
    firstSeenUtc = $script:AcsMetrics['lifetimeFirstSeenUtc']
    totalDomains = $script:AcsMetrics['totalDomains'].Value
    totalUniqueDomains = $script:AcsMetrics['totalUniqueDomains'].Value
    lifetimeTotalDomains = $lifetimeTotalDomains
    lifetimeUniqueDomains = $lifetimeUniqueDomains
    lifetimeTotalUptimeSeconds = $lifetimeTotalUptimeSeconds
    lifetimeTotalUptimeFormatted = $lifetimeTotalUptimeFormatted

    totalMsAuthVerifications = $script:AcsMetrics['totalMsAuthVerifications'].Value
    lifetimeMsAuthVerifications = $script:AcsMetrics['lifetimeMsAuthVerifications'].Value
    lifetimeMsEmployeeVerifications = [int64]$script:AcsMetrics['lifetimeMsEmployeeIdHashes'].Count
  }
}

# Initialize persisted metrics once at startup (only when enabled).
if ($env:ACS_ENABLE_ANON_METRICS -eq '1') {
  try {
    Load-AnonymousMetricsPersisted

    if ([string]::IsNullOrWhiteSpace($script:AcsMetrics['lifetimeFirstSeenUtc'])) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = ([DateTime]::UtcNow.ToString('o'))
    }

    Save-AnonymousMetricsPersisted -Force
  } catch { $null = $_ }
}

function Set-SecurityHeaders {
  param(
    $Context,
    [string]$Nonce
  )
  # Apply security headers to all responses:
  # - CORS: restrict to same-origin only (no cross-origin API access)
  # - CSP: restrict script sources to self and known CDNs
  # - X-Content-Type-Options: prevent MIME-sniffing
  # - X-Frame-Options: prevent clickjacking
  # - Referrer-Policy: minimize referrer leakage
  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $origin = $null
      try { $origin = [string]$Context.Request.Headers['Origin'] } catch { $origin = $null }
      if (-not [string]::IsNullOrWhiteSpace($origin)) {
        # Only reflect the origin if it matches the listener's own origin
        $requestHost = $null
        try { $requestHost = $Context.Request.Url.GetLeftPart([System.UriPartial]::Authority) } catch { $requestHost = $null }
        if ($origin -eq $requestHost) {
          $Context.Response.Headers['Access-Control-Allow-Origin'] = $origin
          $Context.Response.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
          $Context.Response.Headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Api-Key, X-ACS-API-Key'
          $Context.Response.Headers['Access-Control-Max-Age'] = '3600'
          $Context.Response.Headers['Vary'] = 'Origin'
        }
        # If origin does not match, no CORS headers are set (browser blocks the response)
      }
      $Context.Response.Headers['X-Content-Type-Options'] = 'nosniff'
      $Context.Response.Headers['X-Frame-Options'] = 'DENY'
      $Context.Response.Headers['Referrer-Policy'] = 'no-referrer'

      $nonceToken = if ([string]::IsNullOrWhiteSpace($Nonce)) { $null } else { "'nonce-$Nonce'" }
      $scriptSrcParts = @("'self'", $nonceToken, 'https://cdn.jsdelivr.net', 'https://alcdn.msauth.net') | Where-Object { $_ }
      $styleSrcParts = @("'self'", $nonceToken) | Where-Object { $_ }
      $scriptSrc = 'script-src ' + ($scriptSrcParts -join ' ')
      $styleSrc = 'style-src ' + ($styleSrcParts -join ' ')
      $Context.Response.Headers['Content-Security-Policy'] = "default-src 'self'; $scriptSrc; script-src-attr 'unsafe-inline'; $styleSrc; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com; frame-ancestors 'none'"
    }
  } catch { }
}

function Write-Json {
    param(
    $Context,
    [object]$Object,
    [int]$StatusCode = 200
    )

    # Serialize to JSON and write to the current response type.
    # The script can run in 2 server modes:
    # - HttpListener: native `HttpListenerContext`/`HttpListenerResponse` objects
    # - TcpListener : a minimal compatibility layer that mimics a subset of those APIs
    $json  = $Object | ConvertTo-Json -Depth 8
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)

  Set-SecurityHeaders -Context $Context

  if ($Context.Response -is [System.Net.HttpListenerResponse]) {
    $Context.Response.ContentType = "application/json; charset=utf-8"
    $Context.Response.StatusCode  = $StatusCode
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
    return
  }

  # TcpListener fallback response
  $Context.Response.ContentType = "application/json; charset=utf-8"
  $Context.Response.StatusCode  = $StatusCode
  $Context.Response.ContentLength64 = $bytes.Length
  $Context.Response.SendBody($bytes)
}

function Write-FileResponse {
    param(
        $Context,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$ContentType = 'application/octet-stream'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($Context.Response -is [System.Net.HttpListenerResponse]) {
            $Context.Response.StatusCode = 404
            $Context.Response.StatusDescription = 'Not Found'
            $Context.Response.Close()
            return
        }
        $Context.Response.StatusCode = 404
        $Context.Response.StatusDescription = 'Not Found'
        $Context.Response.SendBody([byte[]]@())
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    Set-SecurityHeaders -Context $Context

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
        $Context.Response.ContentType = $ContentType
        $Context.Response.StatusCode  = 200
        $Context.Response.ContentLength64 = $bytes.Length
        $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Context.Response.OutputStream.Close()
        return
    }

    $Context.Response.ContentType = $ContentType
    $Context.Response.StatusCode  = 200
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.SendBody($bytes)
}

function Write-Html {
    param(
        $Context,
        [string]$Html,
        [string]$Nonce
    )

    # Serve the embedded SPA HTML. (All dynamic data is fetched from JSON endpoints.)
    if ([string]::IsNullOrWhiteSpace($Nonce)) {
      $Html = $Html.Replace('nonce="__CSP_NONCE__"', '')
    } else {
      $Html = $Html.Replace('__CSP_NONCE__', $Nonce)
    }

    $bytes = [Text.Encoding]::UTF8.GetBytes($Html)

    Set-SecurityHeaders -Context $Context -Nonce $Nonce

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      try {
        $Context.Response.Headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        $Context.Response.Headers['Pragma'] = 'no-cache'
        $Context.Response.Headers['Expires'] = '0'
      } catch { }
      $Context.Response.ContentType = "text/html; charset=utf-8"
      $Context.Response.StatusCode  = 200
      $Context.Response.ContentLength64 = $bytes.Length
      $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
      $Context.Response.OutputStream.Close()
      return
    }

    # TcpListener fallback response
    $Context.Response.ContentType = "text/html; charset=utf-8"
    $Context.Response.StatusCode  = 200
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.SendBody($bytes)
}

function Resolve-DohName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [ValidateSet('A','AAAA','CNAME','MX','TXT')]
    [string]$Type
  )

  # DNS-over-HTTPS resolver.
  # Returns objects shaped similarly to `Resolve-DnsName` output so downstream code can stay uniform.
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
    $env:ACS_DNS_DOH_ENDPOINT = $endpoint
  }

  $uri = "{0}?name={1}&type={2}" -f $endpoint, ([uri]::EscapeDataString($Name)), $Type

  # Cloudflare-style DoH JSON response (RFC 8484 compatible JSON format).
  $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10 -ErrorAction Stop
  if ($null -eq $resp -or $null -eq $resp.Answer) { return $null }

  $answers = @($resp.Answer)
  if (-not $answers) { return $null }

  switch ($Type) {
    'TXT' {
      foreach ($a in $answers) {
        # Cloudflare DoH can return CNAME answers alongside the requested TXT type.
        # Only treat actual TXT (type 16) answers as TXT records to avoid leaking CNAME targets.
        $recType = $a.type
        if ($recType -ne 16 -and [string]$recType -ne 'TXT') { continue }

        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $data = $data.Trim()
        if ($data.StartsWith('"') -and $data.EndsWith('"') -and $data.Length -ge 2) {
          $data = $data.Substring(1, $data.Length - 2)
        }
        $data = $data -replace '\\"','"'
        [pscustomobject]@{ Strings = @($data) }
      }
    }
    'MX' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $parts = $data.Trim() -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $pref = 0
        [int]::TryParse($parts[0], [ref]$pref) | Out-Null
        [pscustomobject]@{ Preference = $pref; NameExchange = $parts[1] }
      }
    }
    'CNAME' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ CanonicalName = $data.Trim() }
      }
    }
    'A' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP4Address = $data.Trim() }
      }
    }
    'AAAA' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP6Address = $data.Trim() }
      }
    }
  }
}

function ResolveSafely {
    param(
        [string]$Name,
        [string]$Type,
        [switch]$ThrowOnError
    )
    # One stop DNS lookup wrapper:
    # - picks System vs DoH vs Auto
    # - optionally throws (when the caller wants to surface DNS failures)
    try {
        $mode = $env:ACS_DNS_RESOLVER
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Auto' }

        switch ($mode) {
          'DoH' {
            return (Resolve-DohName -Name $Name -Type $Type)
          }
          'System' {
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if (-not $cmd) {
              throw "DnsResolver=System requires Resolve-DnsName (DnsClient module)."
            }
            return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
          }
          default {
            # Auto
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if ($cmd) {
              return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
            }
            return (Resolve-DohName -Name $Name -Type $Type)
          }
        }
    } catch {
        if ($ThrowOnError) { throw }
        $null
    }
}

function Get-DnsIpString {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Record
  )

  begin {
    $results = [System.Collections.Generic.List[string]]::new()
  }

  process {
    if ($null -eq $Record) { return }

    $value = $null

    # Resolve-DnsName outputs vary by PS/DnsClient version: IP4Address/IP6Address are common,
    # and some versions expose an AliasProperty named IPAddress.
    $props = $Record.PSObject.Properties
    if ($props.Match('IPAddress').Count -gt 0) { $value = $Record.IPAddress }
    elseif ($props.Match('IP4Address').Count -gt 0) { $value = $Record.IP4Address }
    elseif ($props.Match('IP6Address').Count -gt 0) { $value = $Record.IP6Address }
    elseif ($Record -is [System.Net.IPAddress]) { $value = $Record.ToString() }

    foreach ($v in @($value)) {
      $s = [string]$v
      if ([string]::IsNullOrWhiteSpace($s)) { continue }
      $s = $s.Trim().TrimEnd('.')

      $ipObj = $null
      if ([System.Net.IPAddress]::TryParse($s, [ref]$ipObj)) {
        # Normalize formatting (also ensures IPv6 is compressed consistently)
        $results.Add($ipObj.ToString())
      }
    }
  }

  end {
    $results | Select-Object -Unique
  }
}

function ConvertTo-NormalizedDomain {
  param([string]$Raw)

  # Normalize user input into a plain domain name:
  # - accepts: domain, email address, or URL
  # - strips: wildcard prefix and surrounding dots
  # - outputs: lowercase domain

  $domain = if ($null -eq $Raw) { "" } else { [string]$Raw }
  $domain = $domain.Trim()
  if ([string]::IsNullOrWhiteSpace($domain)) { return "" }

  # If user provided an email address, take everything after the last '@'
  $at = $domain.LastIndexOf("@")
  if ($at -ge 0 -and $at -lt ($domain.Length - 1)) {
    $domain = $domain.Substring($at + 1)
  }

  # If user provided a URL, extract hostname
  if ($domain -match '^(?i)https?://') {
    try {
      $domain = ([Uri]$domain).Host
    } catch {
      $null = $_
    }
  }

  # Remove wildcard prefix and surrounding dots/spaces
  $domain = $domain -replace '^\*\.', ''
  $domain = $domain.Trim().Trim('.')

  return $domain.ToLowerInvariant()
}

function Test-DomainName {
  param([string]$Domain)

  # Lightweight validation to avoid:
  # - obviously invalid domains
  # - path/query injection through the query string

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

  $d = $Domain.Trim().ToLowerInvariant()
  if ($d.Length -gt 253) { return $false }
  if ($d -notmatch '^[a-z0-9.-]+$') { return $false }
  if ($d.Contains('..')) { return $false }
  if ($d.StartsWith('-') -or $d.EndsWith('-')) { return $false }

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $false }
  foreach ($label in $labels) {
    if ([string]::IsNullOrWhiteSpace($label)) { return $false }
    if ($label.Length -gt 63) { return $false }
    if ($label.StartsWith('-') -or $label.EndsWith('-')) { return $false }
  }
  return $true
}

function Write-RequestLog {
  param(
    $Context,
    [string]$Action,
    [string]$Domain
  )

  # Do not log IP addresses or user agents (PII). Only log minimal non-identifying data.
  Write-Information -InformationAction Continue -MessageData "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Action for '$Domain'"
}

function Get-ClientIp {
  param($Context)

  $headers = $null
  try {
    if ($Context.Request -is [System.Net.HttpListenerRequest]) {
      $headers = $Context.Request.Headers
    } elseif ($Context.Request.Headers) {
      $headers = $Context.Request.Headers
    }
  } catch { $headers = $null }

  $xff = $null
  if ($headers) {
    try { $xff = [string]$headers['X-Forwarded-For'] } catch { $xff = $null }
    if ([string]::IsNullOrWhiteSpace($xff)) {
      try { $xff = [string]$headers['x-forwarded-for'] } catch { $xff = $null }
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($xff)) {
    $first = ($xff -split ',')[0]
    $first = [string]$first
    $first = $first.Trim()
    if (-not [string]::IsNullOrWhiteSpace($first)) { return $first }
  }

  try {
    if ($Context.Request -is [System.Net.HttpListenerRequest]) {
      return [string]$Context.Request.RemoteEndPoint.Address
    }
    if ($Context.Request.RemoteEndPoint) {
      return [string]$Context.Request.RemoteEndPoint.Address
    }
  } catch { }

  return $null
}

function Get-ApiKeyFromRequest {
  param($Context)

  $headers = $null
  try {
    if ($Context.Request -is [System.Net.HttpListenerRequest]) {
      $headers = $Context.Request.Headers
    } elseif ($Context.Request.Headers) {
      $headers = $Context.Request.Headers
    }
  } catch { $headers = $null }

  $key = $null
  if ($headers) {
    foreach ($name in @('X-Api-Key','x-api-key','X-ACS-API-Key','x-acs-api-key')) {
      try {
        $key = [string]$headers[$name]
      } catch { $key = $null }
      if (-not [string]::IsNullOrWhiteSpace($key)) { return $key.Trim() }
    }

    $authHeader = $null
    try { $authHeader = [string]$headers['Authorization'] } catch { $authHeader = $null }
    if ([string]::IsNullOrWhiteSpace($authHeader)) {
      try { $authHeader = [string]$headers['authorization'] } catch { $authHeader = $null }
    }
    if ($authHeader -and $authHeader -match '^(?i)ApiKey\s+(.+)$') {
      return $Matches[1].Trim()
    }
  }

  try {
    if ($Context.Request.QueryString) {
      $key = [string]$Context.Request.QueryString['apiKey']
      if ([string]::IsNullOrWhiteSpace($key)) { $key = [string]$Context.Request.QueryString['apikey'] }
      if (-not [string]::IsNullOrWhiteSpace($key)) { return $key.Trim() }
    }
  } catch { }

  return $null
}

function Test-ApiKey {
  param($Context)

  $expected = [string]$env:ACS_API_KEY
  if ([string]::IsNullOrWhiteSpace($expected)) { return $true }

  $provided = Get-ApiKeyFromRequest -Context $Context
  if ([string]::IsNullOrWhiteSpace($provided)) { return $false }

  return [string]::Equals($provided, $expected, [System.StringComparison]::Ordinal)
}

function Test-RateLimit {
  param($Context)

  $limit = 0
  if ($env:ACS_RATE_LIMIT_PER_MIN -and $env:ACS_RATE_LIMIT_PER_MIN -match '^\d+$') {
    $limit = [int]$env:ACS_RATE_LIMIT_PER_MIN
  }
  if ($limit -le 0) {
    return [pscustomobject]@{ allowed = $true; remaining = $null; retryAfterSec = $null; limit = $limit }
  }

  $clientIp = Get-ClientIp -Context $Context
  if ([string]::IsNullOrWhiteSpace($clientIp)) { $clientIp = 'unknown' }

  if (-not $AcsRateLimitStore) {
    $AcsRateLimitStore = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }
  if (-not $AcsRateLimitLock) {
    $AcsRateLimitLock = [object]::new()
  }

  $now = [DateTimeOffset]::UtcNow
  $windowSeconds = 60

  [System.Threading.Monitor]::Enter($AcsRateLimitLock)
  try {
    $entry = $null
    if (-not $AcsRateLimitStore.TryGetValue($clientIp, [ref]$entry)) {
      $entry = [pscustomobject]@{ windowStart = $now; count = 0 }
      $AcsRateLimitStore[$clientIp] = $entry
    } elseif (($now - $entry.windowStart).TotalSeconds -ge $windowSeconds) {
      $entry.windowStart = $now
      $entry.count = 0
    }

    if ($entry.count -ge $limit) {
      $retryAfter = [int][Math]::Ceiling(($entry.windowStart.AddSeconds($windowSeconds) - $now).TotalSeconds)
      if ($retryAfter -lt 1) { $retryAfter = 1 }
      return [pscustomobject]@{ allowed = $false; remaining = 0; retryAfterSec = $retryAfter; limit = $limit }
    }

    $entry.count++
    $remaining = [Math]::Max(0, $limit - $entry.count)
    return [pscustomobject]@{ allowed = $true; remaining = $remaining; retryAfterSec = $null; limit = $limit }
  }
  finally {
    [System.Threading.Monitor]::Exit($AcsRateLimitLock)
  }
}

function Get-DnsBaseStatus {
  param([string]$Domain)

  # Base/root TXT checks.
  # - Collect all root TXT strings.
  # - Detect SPF (v=spf1...) and ACS verification token (ms-domain-verification...).

  $spf        = $null
  $acsTxt     = $null
  $txtRecords = @()
  $dnsFailed  = $false
  $dnsError   = $null
  $ipv4Addrs  = @()
  $ipv6Addrs  = @()
  $ipLookupDomain = $Domain
  $ipUsedParent = $false

  try {
    $records = ResolveSafely $Domain "TXT" -ThrowOnError
    foreach ($r in $records) {
      $joined = ($r.Strings -join "").Trim()
      if ($joined) { $txtRecords += $joined }
    }

    $aRecs = ResolveSafely $Domain "A"
    if ($aRecs) { $ipv4Addrs = @($aRecs | Get-DnsIpString) }
    $aaaaRecs = ResolveSafely $Domain "AAAA"
    if ($aaaaRecs) { $ipv6Addrs = @($aaaaRecs | Get-DnsIpString) }
  } catch {
    $dnsFailed = $true
    $dnsError  = $_.Exception.Message
  }

  if (-not $dnsFailed -and $ipv4Addrs.Count -eq 0 -and $ipv6Addrs.Count -eq 0) {
    $parent = Get-RegistrableDomain -Domain $Domain
    if (-not [string]::IsNullOrWhiteSpace($parent) -and $parent -ne $Domain) {
      try {
        $aRecsParent = ResolveSafely $parent "A"
        $aaaaRecsParent = ResolveSafely $parent "AAAA"
        $v4p = if ($aRecsParent) { @($aRecsParent | Get-DnsIpString) } else { @() }
        $v6p = if ($aaaaRecsParent) { @($aaaaRecsParent | Get-DnsIpString) } else { @() }
        if ($v4p.Count -gt 0 -or $v6p.Count -gt 0) {
          $ipv4Addrs = $v4p
          $ipv6Addrs = $v6p
          $ipLookupDomain = $parent
          $ipUsedParent = $true
        }
      } catch { }
    }
  }

  if (-not $dnsFailed) {
    foreach ($t in $txtRecords) {
      if (-not $spf    -and $t -match '(?i)^v=spf1')                { $spf    = $t }
      if (-not $acsTxt -and $t -match '(?i)ms-domain-verification') { $acsTxt = $t }
    }
  }

  $spfPresent = -not $dnsFailed -and [bool]$spf
  $acsPresent = -not $dnsFailed -and [bool]$acsTxt

  [pscustomobject]@{
    domain     = $Domain
    dnsFailed  = $dnsFailed
    dnsError   = $dnsError

    ipLookupDomain = $ipLookupDomain
    ipUsedParent   = $ipUsedParent

    ipv4Addresses = $ipv4Addrs
    ipv6Addresses = $ipv6Addrs

    spfPresent = $spfPresent
    spfValue   = $spf
    acsPresent = $acsPresent
    acsValue   = $acsTxt

    txtRecords = $txtRecords
  }
}

function Get-DnsMxStatus {
  param([string]$Domain)

  # MX checks.
  # - Resolve MX records.
  # - Guess the mail provider based on the lowest-preference MX host.
  # - Resolve A/AAAA for each MX host to show concrete IP targets.

  $mxLookupDomain = $Domain
  $mxFallbackDomainChecked = $null
  $mxFallbackUsed = $false

  function Invoke-MxLookupCore {
    param([string]$LookupDomain)

    $result = [pscustomobject]@{
      mxRecords = @()
      mxRecordsDetailed = @()
      mxProvider = $null
      mxProviderHint = $null
    }

    if ($mx = ResolveSafely $LookupDomain "MX") {
      $mxSorted = $mx | Sort-Object Preference, NameExchange

      $primaryMx = $null
      try { $primaryMx = ($mxSorted | Select-Object -First 1 -ExpandProperty NameExchange) } catch { $primaryMx = $null }

      if ($primaryMx) {
        $mxHost = $primaryMx.ToString().Trim().TrimEnd('.').ToLowerInvariant()
        switch -Regex ($mxHost) {
          'mail\.protection\.outlook\.com\.?$' {
            $result.mxProvider = 'Microsoft 365 / Exchange Online'
            $result.mxProviderHint = 'MX points to Exchange Online Protection (EOP).'
            break
          }
          'aspmx\.l\.google\.com\.?$|\.aspmx\.l\.google\.com\.?$|google\.com\.?$' {
            $result.mxProvider = 'Google Workspace / Gmail'
            $result.mxProviderHint = 'MX points to Google mail exchangers.'
            break
          }
          '(^|\.)mx\.cloudflare\.net\.?$' {
            $result.mxProvider = 'Cloudflare Email Routing'
            $result.mxProviderHint = 'MX points to Cloudflare (mx.cloudflare.net).'
            break
          }
          'pphosted\.com\.?$' {
            $result.mxProvider = 'Proofpoint'
            $result.mxProviderHint = 'MX points to Proofpoint-hosted mail.'
            break
          }
          'mimecast\.com\.?$' {
            $result.mxProvider = 'Mimecast'
            $result.mxProviderHint = 'MX points to Mimecast.'
            break
          }
          'zoho\.com\.?$' {
            $result.mxProvider = 'Zoho Mail'
            $result.mxProviderHint = 'MX points to Zoho Mail.'
            break
          }
          default {
            $result.mxProvider = 'Unknown'
            $result.mxProviderHint = 'Provider not recognized from MX hostname.'
          }
        }
      }

      foreach ($m in $mxSorted) {
        $mxHost = [string]$m.NameExchange
        if ([string]::IsNullOrWhiteSpace($mxHost)) { continue }
        $mxHost = $mxHost.Trim().TrimEnd('.')

        $result.mxRecords += "$mxHost (Priority $($m.Preference))"

        $ipv4 = @()
        $ipv6 = @()

        if ($aRecs = ResolveSafely $mxHost "A") {
          $ipv4 += $aRecs | Get-DnsIpString
        }
        if ($aaaaRecs = ResolveSafely $mxHost "AAAA") {
          $ipv6 += $aaaaRecs | Get-DnsIpString
        }

        if (-not $ipv4 -and -not $ipv6) {
          $result.mxRecordsDetailed += [pscustomobject]@{
            Hostname = $mxHost
            Priority = $m.Preference
            Type = "N/A"
            IPAddress = "(none found)"
          }
        } else {
          foreach ($ip in $ipv4) {
            $result.mxRecordsDetailed += [pscustomobject]@{
              Hostname = $mxHost
              Priority = $m.Preference
              Type = "IPv4"
              IPAddress = $ip
            }
          }
          foreach ($ip in $ipv6) {
            $result.mxRecordsDetailed += [pscustomobject]@{
              Hostname = $mxHost
              Priority = $m.Preference
              Type = "IPv6"
              IPAddress = $ip
            }
          }
        }
      }
    }

    return $result
  }

  # First, try the exact domain.
  $mxResult = Invoke-MxLookupCore -LookupDomain $Domain

  # If none found, try the registrable (parent) domain as a fallback.
  if (($mxResult.mxRecords.Count -eq 0) -and ($mxResult.mxRecordsDetailed.Count -eq 0)) {
    $parent = Get-RegistrableDomain -Domain $Domain
    if ($parent -and $parent -ne $Domain) {
      $parent = $parent.Trim().TrimEnd('.')
      $mxFallbackDomainChecked = $parent
      $parentResult = Invoke-MxLookupCore -LookupDomain $parent
      if (($parentResult.mxRecords.Count -gt 0) -or ($parentResult.mxRecordsDetailed.Count -gt 0)) {
        $mxResult = $parentResult
        $mxLookupDomain = $parent
        $mxFallbackUsed = $true
      }
    }
  }

  if ($mxLookupDomain) { $mxLookupDomain = $mxLookupDomain.Trim().TrimEnd('.') }

  [pscustomobject]@{
    domain                  = $Domain
    mxLookupDomain          = $mxLookupDomain
    mxFallbackDomainChecked = $mxFallbackDomainChecked
    mxFallbackUsed          = $mxFallbackUsed
    mxRecords               = $mxResult.mxRecords
    mxRecordsDetailed       = $mxResult.mxRecordsDetailed
    mxProvider              = $mxResult.mxProvider
    mxProviderHint          = $mxResult.mxProviderHint
  }
}

function Get-DnsDmarcStatus {
  param([string]$Domain)

  # DMARC is a TXT record at `_dmarc.<domain>`.

  $dmarc = $null
  if ($dm = ResolveSafely "_dmarc.$Domain" "TXT") {
    foreach ($r in $dm) {
      $j = ($r.Strings -join "").Trim()
      if ($j -match '(?i)^v=dmarc') { $dmarc = $j }
    }
  }

  [pscustomobject]@{ domain = $Domain; dmarc = $dmarc }
}

function Get-DnsDkimStatus {
  param([string]$Domain)

  # ACS guidance expects these two DKIM selector TXT records.

  $dkim1 = $null
  if ($d1 = ResolveSafely "selector1-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim1 = (($d1.Strings -join "") -replace '\s+', '').Trim()
  }

  $dkim2 = $null
  if ($d2 = ResolveSafely "selector2-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim2 = (($d2.Strings -join "") -replace '\s+', '').Trim()
  }

  [pscustomobject]@{ domain = $Domain; dkim1 = $dkim1; dkim2 = $dkim2 }
}

function Get-CnameTargetFromRecords {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Records
  )

  foreach ($r in @($Records)) {
    if ($null -eq $r) { continue }

    $props = $r.PSObject.Properties

    # `Resolve-DnsName -Type CNAME` may return SOA in the Authority section when no CNAME exists.
    # Only treat actual CNAME records as a match.
    $typeValue = $null
    if ($props.Match('Type').Count -gt 0) { $typeValue = $r.Type }
    elseif ($props.Match('TypeName').Count -gt 0) { $typeValue = $r.TypeName }
    elseif ($props.Match('QueryType').Count -gt 0) { $typeValue = $r.QueryType }

    $typeString = [string]$typeValue
    if (-not [string]::IsNullOrWhiteSpace($typeString) -and $typeString -ne 'CNAME') {
      continue
    }

    $target = $null
    if ($props.Match('CanonicalName').Count -gt 0) { $target = $r.CanonicalName }
    elseif ($props.Match('NameHost').Count -gt 0) { $target = $r.NameHost }
    elseif ($props.Match('NameTarget').Count -gt 0) { $target = $r.NameTarget }
    elseif ($props.Match('Target').Count -gt 0) { $target = $r.Target }

    $targetString = [string]$target
    if ([string]::IsNullOrWhiteSpace($targetString)) { continue }

    return $targetString.Trim().TrimEnd('.')
  }

  return $null
}

function Get-DnsCnameStatus {
  param([string]$Domain)

  # Root CNAME check (not required for ACS verification; included as guidance).

  $cname = $null

  $lookupNames = if ($Domain -match '^(?i)www\.') { @($Domain) } else { @($Domain, "www.$Domain") }
  foreach ($name in $lookupNames) {
    $target = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
    if (-not [string]::IsNullOrWhiteSpace($target)) {
      $cname = $target
      break
    }
  }

  [pscustomobject]@{ domain = $Domain; cname = $cname }
}

function ConvertTo-ReversedIpv4 {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IPv4
  )

  $ipText = $IPv4.Trim()
  if ([string]::IsNullOrWhiteSpace($ipText)) { return $null }

  $ipObj = $null
  if (-not [System.Net.IPAddress]::TryParse($ipText, [ref]$ipObj)) { return $null }
  if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }

  $bytes = $ipObj.GetAddressBytes()
  [array]::Reverse($bytes)
  return ($bytes | ForEach-Object { $_.ToString() }) -join '.'
}

# In-memory DNSBL cache (per runspace). Short TTL to avoid stale reputation while reducing repeated queries.
if (-not $script:RblCacheTtlSec) { $script:RblCacheTtlSec = 180 }
if (-not $script:RblCache) {
  $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}

function Get-RblCacheEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [int]$TtlSec = 180
  )

  $entry = $null
  if (-not $script:RblCache.TryGetValue($Key, [ref]$entry)) { return $null }
  $age = [DateTime]::UtcNow - $entry.cachedAt
  if ($age.TotalSeconds -gt $TtlSec) {
    $null = $script:RblCache.TryRemove($Key, [ref]$null)
    return $null
  }
  return $entry.value
}

function Set-RblCacheEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [Parameter(Mandatory = $true)][object]$Value
  )

  if (-not $script:RblCache) {
    $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }

  $script:RblCache[$Key] = [pscustomobject]@{
    cachedAt = [DateTime]::UtcNow
    value    = $Value
  }
}

function Invoke-RblLookup {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IPv4,
    [Parameter(Mandatory = $true)]
    [string]$Zone
  )

  $rev = ConvertTo-ReversedIpv4 -IPv4 $IPv4
  if ([string]::IsNullOrWhiteSpace($rev)) {
    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $false
      response = $null
      listedAddress = $null
      error = "Invalid IPv4 address"
    }
  }

  $query = "$rev.$Zone".TrimEnd('.')

  try {
    $a = ResolveSafely $query 'A'
    if (-not $a) {
      return [pscustomobject]@{
        ip = $IPv4
        queriedZone = $Zone
        listed = $false
        response = $query
        listedAddress = $null
        error = $null
      }
    }

    $ips = @($a | Get-DnsIpString)
    $listedAddr = if ($ips.Count -gt 0) { $ips[0] } else { $null }

    # Spamhaus and some DNSBLs return policy-block addresses (e.g., 127.255.255.240-255) when queries are blocked
    # via public resolvers or without auth. Treat those as errors, not listings.
    $isPolicyBlock = $false
    if (-not [string]::IsNullOrWhiteSpace($listedAddr)) {
      if ($listedAddr -match '^127\.255\.255\.(24[0-9]|25[0-5])$') {
        $isPolicyBlock = $true
      }
    }

    if ($isPolicyBlock) {
      return [pscustomobject]@{
        ip = $IPv4
        queriedZone = $Zone
        listed = $false
        response = $query
        listedAddress = $listedAddr
        error = 'DNSBL query returned policy-block response (try an authenticated resolver)'
      }
    }

    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $true
      response = $query
      listedAddress = $listedAddr
      error = $null
    }
  }
  catch {
    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $false
      response = $query
      listedAddress = $null
      error = $_.Exception.Message
    }
  }
}

function Get-DnsReputationStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string[]]$RblZones,
    [int]$MaxTargets = 5
  )

  $defaultZones = @(
    # Common DNSBL zones used by similar tooling.
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'dnsbl.sorbs.net',
    'psbl.surriel.com',
    'rbl.efnetrbl.org',
    'dnsbl.dronebl.org'
  )

  $zones = if ($RblZones -and $RblZones.Count -gt 0) { @($RblZones) } else { $defaultZones }
  $zones = @($zones | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().TrimEnd('.') } | Select-Object -Unique)

  $lookupDomain = $Domain
  $usedParent = $false

  function Get-IPv4FromHost {
    param([string]$HostName)

    $ips = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($HostName)) { return @() }

    $name = $HostName.Trim().TrimEnd('.')

    $aRecs = ResolveSafely $name 'A'
    if ($aRecs) { $ips.AddRange([string[]](@($aRecs | Get-DnsIpString))) }

    if ($ips.Count -eq 0) {
      $cnameTarget = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
      if (-not [string]::IsNullOrWhiteSpace($cnameTarget)) {
        $aRecs2 = ResolveSafely $cnameTarget 'A'
        if ($aRecs2) { $ips.AddRange([string[]](@($aRecs2 | Get-DnsIpString))) }
      }
    }

    return @($ips | Where-Object { $_ -and ($_ -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') } | Select-Object -Unique)
  }

  if (-not $script:RblCacheTtlSec -or $script:RblCacheTtlSec -le 0) { $script:RblCacheTtlSec = 180 }
  if (-not $script:RblCache) {
    $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }

  $targets = @()
  $ipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Prefer MX hosts, otherwise fall back to A on the root domain.
  $mx = ResolveSafely $Domain 'MX'
  $hosts = @()
  if ($mx) {
    $hosts = @($mx | Sort-Object Preference, NameExchange | Select-Object -First $MaxTargets -ExpandProperty NameExchange)
  }
  if (-not $hosts -or $hosts.Count -eq 0) {
    $hosts = @($Domain)
  }

  foreach ($h in $hosts) {
    $hostName = ([string]$h).Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($hostName)) { continue }

    $v4 = Get-IPv4FromHost -HostName $hostName
    foreach ($ip in $v4) { $null = $ipSet.Add($ip) }

    $targets += [pscustomobject]@{
      hostname = $hostName
      ipAddresses = $v4
    }
  }

  if ($ipSet.Count -eq 0) {
    $parentDomain = Get-RegistrableDomain -Domain $Domain
    if ($parentDomain -and $parentDomain -ne $Domain) {
      $lookupDomain = $parentDomain
      $usedParent = $true
      $parentHosts = @()
      $parentMx = ResolveSafely $parentDomain 'MX'
      if ($parentMx) {
        $parentHosts = @($parentMx | Sort-Object Preference, NameExchange | Select-Object -First $MaxTargets -ExpandProperty NameExchange)
      }
      if (-not $parentHosts -or $parentHosts.Count -eq 0) { $parentHosts = @($parentDomain) }

      foreach ($ph in $parentHosts) {
        $phName = ([string]$ph).Trim().TrimEnd('.')
        if ([string]::IsNullOrWhiteSpace($phName)) { continue }
        $v4p = Get-IPv4FromHost -HostName $phName
        foreach ($ip in $v4p) { $null = $ipSet.Add($ip) }
        $targets += [pscustomobject]@{
          hostname = $phName
          ipAddresses = $v4p
        }
      }
    }
  }

  $ips = @($ipSet)
  $pairs = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($ip in $ips) {
    foreach ($z in $zones) {
      $pairs.Add([pscustomobject]@{ ip = $ip; zone = $z })
    }
  }

  $resultsBag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
  $maxParallel = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount * 2))
  $options = [System.Threading.Tasks.ParallelOptions]::new()
  $options.MaxDegreeOfParallelism = $maxParallel
  $ttl = [int]$script:RblCacheTtlSec

  try {
    [System.Threading.Tasks.Parallel]::ForEach(
      $pairs,
      $options,
      [System.Action[object]]{
        param($pair)
        if ($null -eq $pair) { return }
        $cacheKey = "{0}|{1}" -f $pair.ip, $pair.zone
        $cached = Get-RblCacheEntry -Key $cacheKey -TtlSec $ttl
        if ($cached) { $resultsBag.Add($cached); return }

        $res = Invoke-RblLookup -IPv4 $pair.ip -Zone $pair.zone
        Set-RblCacheEntry -Key $cacheKey -Value $res
        $resultsBag.Add($res)
      }
    )
  }
  catch {
    # Fallback to sequential processing if Parallel.ForEach fails for any reason.
    foreach ($pair in $pairs) {
      if ($null -eq $pair) { continue }
      $cacheKey = "{0}|{1}" -f $pair.ip, $pair.zone
      $cached = Get-RblCacheEntry -Key $cacheKey -TtlSec $ttl
      if ($cached) { $resultsBag.Add($cached); continue }

      $res = Invoke-RblLookup -IPv4 $pair.ip -Zone $pair.zone
      Set-RblCacheEntry -Key $cacheKey -Value $res
      $resultsBag.Add($res)
    }
  }

  $resultsArray = $resultsBag.ToArray()
  $listedCount = @($resultsArray | Where-Object { $_.listed -eq $true }).Count
  $errorCount = @($resultsArray | Where-Object { -not [string]::IsNullOrWhiteSpace($_.error) }).Count
  $totalCount = $resultsArray.Count
  $notListedCount = $totalCount - $listedCount - $errorCount

  [pscustomobject]@{
    domain = $Domain
    lookupDomain = $lookupDomain
    lookupUsedParent = $usedParent
    generatedAtUtc = ([DateTime]::UtcNow.ToString('o'))
    targets = $targets
    rblZones = $zones
    results = $resultsArray
    summary = [pscustomobject]@{
      totalQueries = $totalCount
      listedCount = $listedCount
      notListedCount = $notListedCount
      errorCount = $errorCount
    }
  }
}

function Get-AcsDnsStatus {
    param([string]$Domain)

  # Aggregated status used by the UI.
  # Combines the individual checks + generates human-friendly guidance strings.

  $base  = Get-DnsBaseStatus  -Domain $Domain
  $mx    = Get-DnsMxStatus    -Domain $Domain
  $whois = Get-DomainRegistrationStatus -Domain $Domain
  $dmarc = Get-DnsDmarcStatus -Domain $Domain
  $dkim  = Get-DnsDkimStatus  -Domain $Domain
  $cname = Get-DnsCnameStatus -Domain $Domain

  # ACS domain verification readiness is primarily based on the ms-domain-verification TXT record.
  # Other checks (SPF/MX/DMARC/DKIM/CNAME) are useful guidance but not required for ACS verification.
  $acsReady = (-not $base.dnsFailed) -and $base.acsPresent

    # Guidance
    $guidance = New-Object System.Collections.Generic.List[string]

    if ($base.dnsFailed) {
        $guidance.Add("DNS TXT lookup failed or timed out. Other DNS records may still resolve.")
    } else {
      if (-not $base.spfPresent) { $guidance.Add("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).") }
      if (-not $base.acsPresent) { $guidance.Add("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.") }
      if (-not $mx.mxRecords)    {
        if ($mx.mxFallbackDomainChecked -and $mx.mxFallbackUsed -and $mx.mxLookupDomain) {
          $guidance.Add("No MX records found on $Domain; using parent domain $($mx.mxLookupDomain) MX records as a fallback.")
        }
        elseif ($mx.mxFallbackDomainChecked -and -not $mx.mxFallbackUsed) {
          $guidance.Add("No MX records detected for $Domain or its parent $($mx.mxFallbackDomainChecked). Mail flow will not function until MX records are configured.")
        }
        else {
          $guidance.Add("No MX records detected. Mail flow will not function until MX records are configured.")
        }
      }
      elseif ($mx.mxFallbackUsed -and $mx.mxLookupDomain -and $mx.mxLookupDomain -ne $Domain) {
        $guidance.Add("No MX records found on $Domain; results shown are from parent domain $($mx.mxLookupDomain).")
      }
      if (-not $dmarc.dmarc)     { $guidance.Add("DMARC is missing. Add a _dmarc.$Domain TXT record to reduce spoofing risk.") }
      if (-not $dkim.dkim1)      { $guidance.Add("DKIM selector1 (selector1-azurecomm-prod-net) is missing.") }
      if (-not $dkim.dkim2)      { $guidance.Add("DKIM selector2 (selector2-azurecomm-prod-net) is missing.") }
      if (-not $cname.cname)     { $guidance.Add("CNAME is not configured (root or www). Validate this is expected for your scenario.") }

      # Provider-aware hints
      if ($mx.mxProvider -and $mx.mxProvider -ne 'Unknown') {
        $guidance.Add("Detected MX provider: $($mx.mxProvider)")
      }
      if ($mx.mxProvider -eq 'Microsoft 365 / Exchange Online' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)spf\.protection\.outlook\.com')) {
        $guidance.Add("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Google Workspace / Gmail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)_spf\.google\.com')) {
        $guidance.Add("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Zoho Mail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)include:zoho\.com')) {
        $guidance.Add("Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.")
      }
      if ($whois -and $whois.isExpired -eq $true) {
        $guidance.Add("Domain registration appears expired (expires/expired: $($whois.expiryDateUtc)). Renew the domain before proceeding.")
      }
      elseif ($whois -and $whois.isVeryYoungDomain -eq $true -and $whois.newDomainErrorThresholdDays -gt 0) {
        $guidance.Add("Domain was registered very recently (within $($whois.newDomainErrorThresholdDays) days). This is treated as an error signal for verification; ask the customer to allow more time.")
      }
      elseif ($whois -and $whois.isYoungDomain -eq $true -and $whois.newDomainWarnThresholdDays -gt 0) {
        $guidance.Add("Domain was registered recently (within $($whois.newDomainWarnThresholdDays) days). Ask the customer to allow more time; Microsoft uses this signal to help prevent spammers from setting up new web addresses.")
      }
        if ($acsReady)        { $guidance.Add("This domain appears ready for Azure Communication Services domain verification.") }
    }

    [pscustomobject]@{
        domain     = $Domain
      resolver   = $env:ACS_DNS_RESOLVER
      dohEndpoint = $(if ($env:ACS_DNS_RESOLVER -eq 'DoH' -or ($env:ACS_DNS_RESOLVER -eq 'Auto' -and -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue))) { $env:ACS_DNS_DOH_ENDPOINT } else { $null })
        dnsFailed  = $base.dnsFailed
        dnsError   = $base.dnsError

        spfPresent = $base.spfPresent
        spfValue   = $base.spfValue
        acsPresent = $base.acsPresent
        acsValue   = $base.acsValue

        txtRecords = $base.txtRecords
        acsReady   = $acsReady

        mxRecords         = $mx.mxRecords
        mxRecordsDetailed = $mx.mxRecordsDetailed
        mxProvider        = $mx.mxProvider
        mxProviderHint    = $mx.mxProviderHint
        mxLookupDomain          = $mx.mxLookupDomain
        mxFallbackDomainChecked = $mx.mxFallbackDomainChecked
        mxFallbackUsed          = $mx.mxFallbackUsed

        whoisSource       = $whois.source
        whoisCreationDateUtc = $whois.creationDateUtc
        whoisExpiryDateUtc   = $whois.expiryDateUtc
        whoisRegistrar     = $whois.registrar
        whoisRegistrant    = $whois.registrant
        whoisAgeDays       = $whois.ageDays
        whoisAgeHuman      = $whois.ageHuman
        whoisIsYoungDomain = $whois.isYoungDomain
        whoisIsVeryYoungDomain = $whois.isVeryYoungDomain
        whoisExpiryDays    = $whois.expiryDays
        whoisIsExpired     = $whois.isExpired
        whoisExpiryHuman   = $whois.expiryHuman
        whoisNewDomainWarnThresholdDays = $whois.newDomainWarnThresholdDays
        whoisNewDomainErrorThresholdDays = $whois.newDomainErrorThresholdDays
        whoisError         = $whois.error

        dmarc      = $dmarc.dmarc
        dkim1      = $dkim.dkim1
        dkim2      = $dkim.dkim2
        cname      = $cname.cname

        guidance   = $guidance
    }
}

# ------------------- HTML / UI -------------------
# The UI is embedded as a here-string for easy, single-file distribution.
# It calls the JSON endpoints in this script and renders results client-side.
#
# Note: The UI references a CDN script (`html2canvas`) only for screenshot/export.

$htmlPage = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  margin: 0;
  padding: 32px 24px;
  background: var(--bg);
  color: var(--fg);
  transition: 0.25s background-color ease-in-out;
}

.search-box, .card, input, button, .code, .mx-table, .history-chip {
  transition: 0.25s background-color ease-in-out;
}

.container {
  width: 100%;
  max-width: 1100px;
  margin: 0 auto;
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
}

.top-bar button {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
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
  body { padding: 16px 12px; }
  .container { max-width: 100%; }
  .search-box { max-width: 100%; }
  .input-row { flex-direction: column; }
  .input-wrapper { width: 100%; }
  .input-row button:not(.search-box #clearBtn) { width: 100%; }
  .mx-table { display: block; overflow-x: auto; white-space: nowrap; }
  .top-bar button { width: 100%; height: 43px; }
}

@media print {
  body { padding: 0; background: #ffffff; color: #000000; }
  .top-bar, .history, .hide-on-screenshot, #clearBtn { display: none !important; }
  .search-box { max-width: 100%; margin: 0 0 12px 0; }
  .card { break-inside: avoid; }
  .code, .mx-table { background: #ffffff; color: #000000; border: 1px solid #d1d5db; }
  .mx-table th { background: #f3f4f6; color: #000000; }
}

@keyframes flashHighlight {
  0% { box-shadow: 0 0 0 0 rgba(47, 128, 237, 0); border-color: var(--border); }
  25% { box-shadow: 0 0 0 4px rgba(47, 128, 237, 0.3); border-color: var(--button-bg); }
  100% { box-shadow: 0 0 0 0 rgba(47, 128, 237, 0); border-color: var(--border); }
}

.card.flash-active {
  animation: flashHighlight 2.4s ease-out;
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
</style>

<!-- html2canvas for screenshot capture -->
<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js" integrity="sha384-ZZ1pncU3bQe8y31yfZdMFdSpttDoPmOZg2wguVK9almUodir1PghgT0eY7Mrty8H" crossorigin="anonymous"></script>
<!-- MSAL.js v2 for Microsoft Entra ID authentication (Authorization Code + PKCE) -->
<script nonce="__CSP_NONCE__">
const entraTenant = '__ENTRA_TENANT_ID__';
const acsApiKey = '__ACS_API_KEY__';
const acsIssueUrl = '__ACS_ISSUE_URL__';
const msalSources = [
  '/assets/msal-browser.min.js',
  'https://alcdn.msauth.net/browser/2.38.3/js/msal-browser.min.js',
  'https://cdn.jsdelivr.net/npm/@azure/msal-browser@2.38.3/dist/msal-browser.min.js'
];
let msalLoadPromise = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = false;
    s.onload = () => resolve(true);
    s.onerror = () => reject(new Error('Failed to load ' + src));
    document.head.appendChild(s);
  });
}

async function ensureMsalLoaded() {
  if (window.msal) return true;
  if (msalLoadPromise) return msalLoadPromise;

  msalLoadPromise = (async () => {
    const errors = [];
    for (const src of msalSources) {
      try {
        await loadScript(src);
        if (window.msal) return true;
      } catch (e) {
        errors.push(e.message || String(e));
      }
    }
    throw new Error(errors.join(' | '));
  })();

  return msalLoadPromise;
}
</script>
<script nonce="__CSP_NONCE__">
(function() {
  try {
    var local = localStorage.getItem('acsTheme');
    var support = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (local === 'dark' || (!local && support)) {
      document.documentElement.classList.add('dark');
    }
  } catch (e) {}
})();
</script>
</head>

<body>

<div class="container">

<div class="top-bar">
  <button id="themeToggleBtn" type="button" class="hide-on-screenshot" onclick="toggleTheme()">Dark mode &#x1F319;</button>
  <button id="copyLinkBtn" type="button" class="hide-on-screenshot" onclick="copyShareLink()">Copy link &#x1F517;</button>
  <button id="screenshotBtn" type="button" class="hide-on-screenshot" onclick="screenshotPage()">Copy page screenshot &#x1F4F8;</button>
  <button id="downloadBtn" type="button" class="hide-on-screenshot" onclick="downloadReport()" style="display:none;">Download JSON &#x1F4E5;</button>
  <button id="reportIssueBtn" type="button" class="hide-on-screenshot" onclick="reportIssue()" style="display:none;" title="Report an issue (includes the domain name)">Report issue &#x1F41B;</button>
  <button id="msSignInBtn" type="button" class="hide-on-screenshot ms-sign-in-btn" onclick="msSignIn()">Sign in with Microsoft &#x1F512;</button>
  <span id="msAuthStatus" class="ms-auth-status hide-on-screenshot" style="display:none;"></span>
  <button id="msSignOutBtn" type="button" class="hide-on-screenshot" onclick="msSignOut()" style="display:none;">Sign out</button>
</div>

<div class="search-box">
  <img src="data:image/png;base64,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" alt="ACS Logo" style="height: 64px; display: block; margin: 0 auto 12px auto;">
  <h1>Azure Communication Services<br/>Email Domain Checker</h1>
  <div class="input-row">
    <div class="input-wrapper">
      <input id="domainInput" type="text" placeholder="example.com" oninput="toggleClearBtn()" />
      <button id="clearBtn" class="clear-btn" type="button" onclick="clearInput()">&#x2715;</button>
    </div>
    <button id="lookupBtn" class="primary hide-on-screenshot" type="button" onclick="lookup()">Lookup</button>
  </div>
  <div id="history" class="history hide-on-screenshot"></div>
</div>
<div id="status"></div>
<div id="results" class="cards"></div>

<div class="footer">
  ACS Email Domain Checker v__APP_VERSION__ &bull; Written by: Blake Drumm &bull; Generated by PowerShell &bull; <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Back to Top</a>
</div>

</div>

<script nonce="__CSP_NONCE__">
let lastResult = null;
const HISTORY_KEY = "acsDomainHistory";

let screenshotStatusToken = 0;

let activeLookup = { runId: 0, controllers: [] };

function cancelInflightLookup() {
  for (const c of (activeLookup.controllers || [])) {
    try { c.abort(); } catch {}
  }
  activeLookup.controllers = [];
}

function normalizeDomain(raw) {
  raw = (raw === null || raw === undefined) ? "" : String(raw);
  raw = raw.trim();

  // If user pasted an email, use the part after @
  const at = raw.lastIndexOf("@");
  if (at > -1 && at < raw.length - 1) {
    raw = raw.slice(at + 1);
  }

  // If user pasted a URL, extract hostname
  try {
    if (/^https?:\/\//i.test(raw)) {
      raw = new URL(raw).hostname;
    }
  } catch {
    // ignore
  }

  // Remove wildcard prefix and surrounding dots/spaces
  raw = raw.replace(/^\*\./, "");
  raw = raw.replace(/^\.+/, "").replace(/\.+$/, "");

  return raw.toLowerCase();
}

function isValidDomain(domain) {
  domain = (domain === null || domain === undefined) ? "" : String(domain);
  domain = domain.trim();
  if (!domain) return false;

  // Basic charset + structure checks (lenient, supports punycode)
  if (domain.length > 253) return false;
  if (!/^[a-z0-9.-]+$/.test(domain)) return false;
  if (domain.includes("..")) return false;
  if (domain.startsWith("-") || domain.endsWith("-")) return false;

  const labels = domain.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!label) return false;
    if (label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return true;
}

function toggleClearBtn() {
  const input = document.getElementById("domainInput");
  const btn = document.getElementById("clearBtn");
  if (btn) btn.style.display = input.value ? "block" : "none";
}

function clearInput() {
  const input = document.getElementById("domainInput");
  input.value = "";
  input.focus();
  toggleClearBtn();
}

function readHistoryItems() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const items = raw ? JSON.parse(raw) : [];
    return Array.isArray(items) ? items.map(String) : [];
  } catch {
    return [];
  }
}

function writeHistoryItems(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

function captureHistoryChipRects(container) {
  const rects = new Map();
  if (!container) return rects;
  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;
    rects.set(key, chip.getBoundingClientRect());
  }
  return rects;
}

function playHistoryFlip(container, beforeRects) {
  if (!container || !beforeRects || beforeRects.size === 0) return;

  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;

    const first = beforeRects.get(key);
    if (!first) continue;

    const last = chip.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (dx === 0 && dy === 0) continue;

    chip.style.transition = 'transform 0s';
    chip.style.transform = `translate(${dx}px, ${dy}px)`;
    chip.getBoundingClientRect();

    chip.style.transition = 'transform 180ms ease';
    chip.style.transform = '';

    const cleanup = () => {
      chip.style.transition = '';
      chip.style.transform = '';
      chip.removeEventListener('transitionend', cleanup);
    };
    chip.addEventListener('transitionend', cleanup);
    setTimeout(cleanup, 250);
  }
}

function promoteHistory(domain, animate) {
  const d = (domain === null || domain === undefined) ? "" : String(domain).trim();
  if (!d) return;

  const current = readHistoryItems();
  const lower = d.toLowerCase();
  let next = current.filter(i => String(i).toLowerCase() !== lower);
  next.unshift(d);
  if (next.length > 5) next = next.slice(0, 5);

  const changed =
    current.length !== next.length ||
    current.some((v, idx) => String(v).toLowerCase() !== String(next[idx]).toLowerCase());
  if (!changed) return;

  const container = document.getElementById('history');
  const before = animate ? captureHistoryChipRects(container) : null;

  writeHistoryItems(next);
  renderHistory(next);

  if (animate) {
    requestAnimationFrame(() => playHistoryFlip(container, before));
  }
}

function loadHistory() {
  try {
    renderHistory(readHistoryItems());
  } catch (e) { console.error(e); }
}

function saveHistory(domain) {
  try {
    promoteHistory(domain, false);
  } catch (e) { console.error(e); }
}

function renderHistory(items) {
  const container = document.getElementById("history");
  if (!items || items.length === 0) {
    container.innerHTML = "";
    return;
  }
  const chips = items.map(d => {
    const text = (d === null || d === undefined) ? "" : String(d);
    const safe = escapeHtml(text);
    const key = escapeHtml(text.toLowerCase());
    const arg = JSON.stringify(text);
    return `<span class="history-chip" data-domain="${key}">
      <span class="history-item" onclick='runHistory(${arg})'>${safe}</span>
      <button type="button" class="history-remove" title="Remove" aria-label="Remove" onclick='event.stopPropagation(); removeHistory(${arg})'>&#x2715;</button>
    </span>`;
  }).join(" ");
  container.innerHTML = "Recent: " + chips;
}

function removeHistory(domain) {
  const d = (domain === null || domain === undefined) ? "" : String(domain);
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return;
    let items = JSON.parse(raw);
    items = (items || []).filter(i => String(i).toLowerCase() !== d.toLowerCase());
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
    renderHistory(items);
  } catch (e) { console.error(e); }
}

function runHistory(domain) {
  promoteHistory(domain, true);
  document.getElementById("domainInput").value = domain;
  toggleClearBtn();
  lookup();
}
function downloadReport() {
  if (!lastResult) return;
  const json = JSON.stringify(lastResult, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "acs-check-" + lastResult.domain + ".json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toggleCard(header) {
  header.classList.toggle("collapsed-header");
  const content = header.nextElementSibling;
  if (content) {
    content.classList.toggle("collapsed");
  }

  // If the MX card is being collapsed, also hide the additional details and reset the button label.
  const isNowCollapsed = header.classList.contains("collapsed-header") || (content && content.classList.contains("collapsed"));
  if (isNowCollapsed) {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails && header.parentElement && header.parentElement.contains(mxDetails)) {
      mxDetails.style.display = "none";
      const btns = header.querySelectorAll("button");
      for (const b of btns) {
        const t = (b.textContent || "").trim();
        if (t.startsWith("Additional Details")) {
          b.textContent = "Additional Details +";
          break;
        }
      }
    }
  }
}

function setStatus(html) {
  document.getElementById("status").innerHTML = html;
}

function escapeHtml(text) {
  text = (text === null || text === undefined) ? "" : String(text);
  return text.replace(/[&<>\"]/g, function(ch) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[ch];
  });
}

function formatLocalDateTime(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return null;

  const fmt = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZoneName: 'short'
  });

  const parts = fmt.formatToParts(d).reduce((acc, p) => {
    acc[p.type] = p.value;
    return acc;
  }, {});

  const tzRaw = parts.timeZoneName || '';
  const month = parts.month || '';
  const dayNum = parseInt(parts.day, 10);
  const ordinal = (n) => {
    const v = n % 100;
    if (v >= 11 && v <= 13) return 'th';
    switch (n % 10) {
      case 1: return 'st';
      case 2: return 'nd';
      case 3: return 'rd';
      default: return 'th';
    }
  };
  const day = isNaN(dayNum) ? (parts.day || '') : `${dayNum}${ordinal(dayNum)}`;
  const year = parts.year || '';
  const hour = parts.hour || '';
  const minute = parts.minute || '';
  const dayPeriod = parts.dayPeriod || '';

  const offsetMinutes = d.getTimezoneOffset();
  const sign = offsetMinutes <= 0 ? '+' : '-';
  const absMinutes = Math.abs(offsetMinutes);
  const offsetHours = String(Math.floor(absMinutes / 60)).padStart(2, '0');
  const offsetMins = String(absMinutes % 60).padStart(2, '0');
  const offsetLabel = `UTC${sign}${offsetHours}:${offsetMins}`;

  let tzAbbr = tzRaw;
  const tzUpper = tzRaw.toUpperCase();
  if (!/[A-Z]{2,4}/.test(tzUpper) || tzUpper.startsWith('UTC')) {
    if (offsetMinutes === 300) tzAbbr = 'EST';
    else if (offsetMinutes === 240) tzAbbr = 'EDT';
    else tzAbbr = offsetLabel;
  }

  return `${month} ${day}, ${year} at ${hour}:${minute} ${dayPeriod} ${tzAbbr ? `(${tzAbbr})` : ''}`.trim();
}

function buildTestSummaryHtml(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};

  const classForState = (state) => {
    switch (state) {
      case "pass": return "tag-pass";
      case "warn": return "tag-warn";
      case "fail": return "tag-fail";
      case "error": return "tag-fail";
      case "pending": return "tag-info";
      case "optional": return "tag-info";
      case "unavailable": return "tag-info";
      default: return "tag-info";
    }
  };

  const checks = [];
  const add = (name, state, isOptional = false) => checks.push({ name, state, isOptional });

  // ACS Readiness (derived from base)
  if (!loaded.base && !errors.base) {
    add("ACS Readiness", "pending");
  } else if (errors.base) {
    add("ACS Readiness", "error");
  } else if (r.dnsFailed) {
    add("ACS Readiness", "fail");
  } else {
    add("ACS Readiness", r.acsReady ? "pass" : "fail");
  }

  // Domain (base lookup sanity)
  if (!loaded.base && !errors.base) {
    add("Domain", "pending");
  } else if (errors.base) {
    add("Domain", "error");
  } else {
    add("Domain", r.dnsFailed ? "fail" : "pass");
  }

  // MX (placed directly below Domain per UI request)
  if (!loaded.mx && !errors.mx) {
    add("MX", "pending");
  } else if (errors.mx) {
    add("MX", "error");
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    add("MX", hasMx ? "pass" : "fail", true);
  }

  // SPF + ACS TXT + root TXT list depend on base
  if (!loaded.base && !errors.base) {
    add("SPF (root TXT)", "pending");
    add("ACS TXT", "pending");
    add("TXT Records", "pending");
  } else if (errors.base) {
    add("SPF (root TXT)", "error");
    add("ACS TXT", "error");
    add("TXT Records", "error");
  } else if (r.dnsFailed) {
    add("SPF (root TXT)", "unavailable", true);
    add("ACS TXT", "fail");
    add("TXT Records", "unavailable", true);
  } else {
    add("SPF (root TXT)", r.spfPresent ? "pass" : "fail", true);
    add("ACS TXT", r.acsPresent ? "pass" : "fail");
    const hasTxt = Array.isArray(r.txtRecords) && r.txtRecords.length > 0;
    add("TXT Records", hasTxt ? "pass" : "fail", true);
  }

  // WHOIS / Registration age check
  // Not required for ACS verification, but a newly-registered domain can be a risk signal.
  // Show as WARN (implemented using the existing 'optional' styling) when domain age < threshold.
  if (!loaded.whois && !errors.whois) {
    add("Registration", "pending");
  } else if (errors.whois) {
    add("Registration", "error");
  } else {
    if (r.whoisIsVeryYoungDomain === true) {
      add("Registration", "fail", false);
    } else if (r.whoisIsYoungDomain === true) {
      add("Registration", "warn", false);
    } else {
      add("Registration", "pass", true);
    }
  }

  // DMARC
  if (!loaded.dmarc && !errors.dmarc) {
    add("DMARC", "pending");
  } else if (errors.dmarc) {
    add("DMARC", "error");
  } else {
    add("DMARC", r.dmarc ? "pass" : "fail", true);
  }

  // DKIM selectors
  if (!loaded.dkim && !errors.dkim) {
    add("DKIM1", "pending");
    add("DKIM2", "pending");
  } else if (errors.dkim) {
    add("DKIM1", "error");
    add("DKIM2", "error");
  } else {
    add("DKIM1", r.dkim1 ? "pass" : "fail", true);
    add("DKIM2", r.dkim2 ? "pass" : "fail", true);
  }

  // CNAME
  if (!loaded.cname && !errors.cname) {
    add("CNAME", "pending");
  } else if (errors.cname) {
    add("CNAME", "error");
  } else {
    add("CNAME", r.cname ? "pass" : "fail", true);
  }

  const pills = checks.map(c => {
    const name = escapeHtml(c.name);
    const status = escapeHtml(String(c.state === 'optional' && c.name === 'Registration' ? 'WARN' : c.state).toUpperCase());
    const optionalBadge = c.isOptional ? `<span class="tag ${classForState('optional')} status-pill">OPTIONAL</span>` : "";
    return `<div class="status-row"><span class="status-name">${name}</span><span class="status-pills">${optionalBadge}<span class="tag ${classForState(c.state)} status-pill">${status}</span></span></div>`;
  });

  return '';
}

function applyTheme(theme) {
  const root = document.documentElement;
  const btn  = document.getElementById("themeToggleBtn");
  if (theme === "dark") {
    root.classList.add("dark");
    if (btn) btn.innerHTML = "Light mode &#x2600;&#xFE0F;";
  } else {
    root.classList.remove("dark");
    if (btn) btn.innerHTML = "Dark mode &#x1F319;";
  }
  localStorage.setItem("acsTheme", theme);
}

function toggleTheme() {
  const isDark = document.documentElement.classList.contains("dark");
  applyTheme(isDark ? "light" : "dark");
}

// Avoid multiple info bubbles showing at once when buttons stay focused
function clearInfoDotFocus(except) {
  const dots = document.querySelectorAll('.info-dot');
  dots.forEach(btn => {
    if (btn === except) return;
    if (btn.matches(':focus')) {
      btn.blur();
    }
  });
}

document.addEventListener('focusin', (e) => {
  const btn = e.target && e.target.closest ? e.target.closest('.info-dot') : null;
  if (btn) {
    clearInfoDotFocus(btn);
  }
});

document.addEventListener('mouseenter', (e) => {
  const btn = e.target && e.target.closest ? e.target.closest('.info-dot') : null;
  if (btn) {
    clearInfoDotFocus(btn);
  }
}, true);

function copyShareLink() {
  const btn = document.getElementById("copyLinkBtn");
  if (!navigator.clipboard) {
    setStatus("Clipboard API not available in this browser.");
    return;
  }

  const input = document.getElementById("domainInput");
  const domain = normalizeDomain(input ? input.value : "");
  const url = new URL(window.location.href);
  if (domain && isValidDomain(domain)) {
    url.searchParams.set("domain", domain);
  } else {
    url.searchParams.delete("domain");
  }

  navigator.clipboard.writeText(url.toString())
    .then(() => {
      if (btn) {
        const original = btn.innerHTML;
        btn.innerHTML = "Copied! &#x2714;";
        setTimeout(() => { btn.innerHTML = original; }, 2000);
      } else {
        setStatus("Link copied to clipboard.");
      }
    })
    .catch(() => setStatus("Failed to copy link to clipboard."));
}

function copyText(text, btn) {
  const payload = text;
  const plain = (payload && typeof payload === 'object' && payload !== null)
    ? (payload.plain ?? payload.text ?? '')
    : ((payload === null || payload === undefined) ? "" : String(payload));
  const html = (payload && typeof payload === 'object' && payload !== null) ? payload.html : null;

  if (!navigator.clipboard) {
    setStatus("Clipboard API not available in this browser.");
    return;
  }

  const writePlain = () => navigator.clipboard.writeText(plain);

  const writeRich = () => {
    if (!html || typeof ClipboardItem === 'undefined') return Promise.reject();
    const item = new ClipboardItem({
      'text/html': new Blob([html], { type: 'text/html' }),
      'text/plain': new Blob([plain], { type: 'text/plain' })
    });
    return navigator.clipboard.write([item]);
  };

  (html ? writeRich().catch(writePlain) : writePlain())
    .then(() => {
      if (btn && btn.tagName === "BUTTON") {
        const originalText = btn.innerHTML;
        btn.innerHTML = "Copied! &#x2714;";
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      } else {
        setStatus("Copied to clipboard.");
      }
    })
    .catch(() => setStatus("Failed to copy to clipboard."));
}

function copyField(btn, key) {
  // Support legacy call (key only)
  let button = btn;
  let fieldKey = key;
  if (typeof btn === 'string') {
     fieldKey = btn;
     button = null;
  }

  const el = document.getElementById("field-" + fieldKey);
  if (!el) {
    setStatus("Nothing to copy for " + escapeHtml(fieldKey) + ".");
    return;
  }

  let text = el.innerText || el.textContent || "";

  // If MX additional details are open, include them in the copied text.
  if (fieldKey === "mx") {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails) {
      const display = (window.getComputedStyle ? getComputedStyle(mxDetails).display : mxDetails.style.display);
      if (display && display !== "none") {
        const detailsText = (mxDetails.innerText || mxDetails.textContent || "").trim();
        if (detailsText) {
          text = (String(text || "").trimEnd() + "\n\n--- Additional Details ---\n" + detailsText).trim();
        }
      }
    }
  }
  if (!navigator.clipboard) {
    setStatus("Clipboard API not available in this browser.");
    return;
  }
  navigator.clipboard.writeText(text)
    .then(() => {
      if (button && button.tagName === "BUTTON") {
        const originalText = button.innerHTML;
        button.innerHTML = "Copied! &#x2714;";
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
      } else {
        setStatus("Copied " + escapeHtml(fieldKey) + " to clipboard.");
      }
    })
    .catch(() => setStatus("Failed to copy " + escapeHtml(fieldKey) + " to clipboard."));
}

function screenshotPage() {
  if (!window.html2canvas || !navigator.clipboard || typeof ClipboardItem === "undefined") {
    setStatus("Screenshot clipboard support is not available in this browser.");
    return;
  }

  const statusEl = document.getElementById("status");
  const previousStatusHtml = statusEl ? statusEl.innerHTML : "";
  const myToken = ++screenshotStatusToken;

  // Capture only the container div instead of the entire body
  const container = document.querySelector(".container");
  if (!container) {
    setStatus("Container not found for screenshot.");
    return;
  }

  html2canvas(container, {
    backgroundColor: getComputedStyle(document.body).backgroundColor,
    onclone: (clonedDoc) => {
      // Hide marked buttons in the cloned DOM only (prevents visible flashing)
      clonedDoc.body.classList.add("screenshot-mode");
    }
  }).then(canvas => {
    canvas.toBlob(blob => {
      if (!blob) {
        setStatus("Failed to capture screenshot.");
        return;
      }
      const item = new ClipboardItem({ "image/png": blob });
      navigator.clipboard.write([item])
        .then(() => {
          setStatus("Screenshot copied to clipboard.");
          setTimeout(() => {
            if (myToken !== screenshotStatusToken) return;
            const el = document.getElementById("status");
            if (el && el.innerHTML === "Screenshot copied to clipboard.") {
              el.innerHTML = previousStatusHtml;
            }
          }, 2500);
        })
        .catch(() => setStatus("Failed to copy screenshot to clipboard."));
    });
  }).catch(() => {
    setStatus("Screenshot capture failed.");
  });
}

function buildIssueUrl(domain) {
  const raw = (acsIssueUrl || '').trim();
  if (!raw || raw.startsWith('__')) return null;
  try {
    const url = new URL(raw, window.location.origin);
    if (domain) {
      url.searchParams.set('domain', domain);
    }
    url.searchParams.set('source', 'acs-domain-checker');
    return url.toString();
  } catch {
    return null;
  }
}

function reportIssue() {
  const domain = normalizeDomain((document.getElementById("domainInput") || {}).value || "");
  const targetUrl = buildIssueUrl(domain);
  if (!targetUrl) {
    setStatus("Issue reporting is not configured.");
    return;
  }

  const detail = domain ? `the domain name "${domain}"` : "the domain name from the input box";
  const ok = window.confirm(`This will open the issue tracker and include ${detail}. Continue?`);
  if (!ok) return;

  window.open(targetUrl, '_blank', 'noopener');
}

function lookup() {
  const input = document.getElementById("domainInput");
  const btn   = document.getElementById("lookupBtn");
  const screenshotBtn = document.getElementById("screenshotBtn");
  const dlBtn = document.getElementById("downloadBtn");
  const domain = normalizeDomain(input.value);
  input.value = domain;
  toggleClearBtn();

  if (!domain) {
    setStatus("Please enter a domain.");
    return;
  }

  if (!isValidDomain(domain)) {
    setStatus("Please enter a valid domain name (example: example.com).");
    return;
  }

  // Cancel any previous lookup's requests and start a new run
  const runId = ++activeLookup.runId;
  cancelInflightLookup();

  // Clear previous results and hide download button
  document.getElementById("results").innerHTML = "";
  setStatus("");
  if (dlBtn) dlBtn.style.display = "none";

  const url = new URL(window.location.href);
  url.searchParams.set("domain", domain);
  window.history.replaceState({}, "", url);

  // Keep Lookup clickable so another click can cancel/restart
  btn.disabled = false;
  if (screenshotBtn) screenshotBtn.disabled = true;
  btn.innerHTML = 'Checking <span class="spinner"></span>';
  // setStatus("Checking " + escapeHtml(domain) + " &#x23F3;");

  function parseHttpError(r, bodyText) {
    const details = (bodyText || "").trim();
    return `HTTP ${r.status}${r.statusText ? " " + r.statusText : ""}${details ? ": " + details : ""}`;
  }

  async function fetchJson(path) {
    const controller = new AbortController();
    activeLookup.controllers.push(controller);
    try {
      const headers = {};
      const apiKey = (acsApiKey || '').trim();
      if (apiKey && !apiKey.startsWith('__')) {
        headers['X-Api-Key'] = apiKey;
      }
      const r = await fetch(path + "?domain=" + encodeURIComponent(domain), { signal: controller.signal, headers: headers });
      if (!r.ok) {
        let body = "";
        try { body = await r.text(); } catch {}
        throw new Error(parseHttpError(r, body));
      }
      return r.json();
    } finally {
      // Remove controller to avoid leaks
      activeLookup.controllers = (activeLookup.controllers || []).filter(c => c !== controller);
    }
  }

  function ensureResultObject() {
    if (!lastResult || typeof lastResult !== "object") {
      lastResult = {};
    }
    if (!lastResult._loaded) {
      lastResult._loaded = { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false };
    }
    if (!lastResult._errors) {
      lastResult._errors = {};
    }
  }

  function buildGuidance(r) {
    const guidance = [];
    const loaded = r._loaded || {};

    if (loaded.base && r.dnsFailed) {
      guidance.push("DNS TXT lookup failed or timed out. Other DNS records may still resolve.");
      return guidance;
    }

    if (loaded.base) {
      if (!r.spfPresent) guidance.push("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent). ");
      if (!r.acsPresent) guidance.push("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.");
    }

    if (loaded.mx) {
      const mxList = (r.mxRecords || []);
      const hasMx = mxList && mxList.length > 0;
      if (!hasMx) {
        if (r.mxFallbackDomainChecked && r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
          guidance.push("No MX records found on " + (r.domain || "") + "; using parent domain " + r.mxLookupDomain + " MX records as a fallback.");
        } else if (r.mxFallbackDomainChecked && !r.mxFallbackUsed) {
          guidance.push("No MX records detected for " + (r.domain || "") + " or its parent " + r.mxFallbackDomainChecked + ". Mail flow will not function until MX records are configured.");
        } else {
          guidance.push("No MX records detected. Mail flow will not function until MX records are configured.");
        }
      } else if (r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
        guidance.push("No MX records found on " + (r.domain || "") + "; results shown are from parent domain " + r.mxLookupDomain + ".");
      }
      if (r.mxProvider && r.mxProvider !== "Unknown") {
        guidance.push("Detected MX provider: " + r.mxProvider);
      }
    }

    if (loaded.whois) {
      if (r.whoisIsExpired === true) {
        guidance.push("Domain registration appears expired. Renew the domain before proceeding.");
      } else if (r.whoisIsVeryYoungDomain === true) {
        const d = (r.whoisNewDomainErrorThresholdDays || 90);
        guidance.push("Domain was registered very recently (within " + String(d) + " days). This is treated as an error signal for verification; ask the customer to allow more time.");
      } else if (r.whoisIsYoungDomain === true) {
        const d = (r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180);
        guidance.push("Domain was registered recently (within " + String(d) + " days). Ask the customer to allow more time; Microsoft uses this signal to help prevent spammers from setting up new web addresses.");
      }
    }

    if (loaded.dmarc && !r.dmarc) {
      guidance.push("DMARC is missing. Add a _dmarc." + (r.domain || "") + " TXT record to reduce spoofing risk.");
    }

    if (loaded.dkim) {
      if (!r.dkim1) guidance.push("DKIM selector1 (selector1-azurecomm-prod-net) is missing.");
      if (!r.dkim2) guidance.push("DKIM selector2 (selector2-azurecomm-prod-net) is missing.");
    }

    if (loaded.cname && !r.cname) {
      guidance.push("Root CNAME is not configured. Validate this is expected for your scenario.");
    }

    if (loaded.base && loaded.mx && r.mxProvider === "Microsoft 365 / Exchange Online" && r.spfPresent && r.spfValue && !/spf\.protection\.outlook\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.");
    }
    if (loaded.base && loaded.mx && r.mxProvider === "Google Workspace / Gmail" && r.spfPresent && r.spfValue && !/_spf\.google\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.");
    }
    if (loaded.base && loaded.mx && r.mxProvider === "Zoho Mail" && r.spfPresent && r.spfValue && !/include:zoho\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.");
    }

    if (loaded.base && r.acsReady) {
      guidance.push("This domain appears ready for Azure Communication Services domain verification.");
    }

    return guidance;
  }

  function recomputeDerived(r) {
    const loaded = r._loaded || {};
    if (loaded.base) {
      // ACS domain verification readiness is primarily based on the ms-domain-verification TXT record
      // (SPF is best-practice guidance but not required for ACS verification).
      r.acsReady = (!r.dnsFailed) && !!r.acsPresent;
    } else {
      r.acsReady = false;
    }
    r.guidance = buildGuidance(r);
  }

  ensureResultObject();
  lastResult = {
    domain,
    _loaded: { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false },
    _errors: {},
    guidance: [],
    acsReady: false
  };
  recomputeDerived(lastResult);
  render(lastResult);

  const requests = [
    { key: "base",  path: "/api/base"  },
    { key: "mx",    path: "/api/mx"    },
    { key: "whois", path: "/api/whois" },
    { key: "dmarc", path: "/api/dmarc" },
    { key: "dkim",  path: "/api/dkim"  },
    { key: "cname", path: "/api/cname" },
    { key: "reputation", path: "/api/reputation" }
  ];

  let savedHistory = false;
  let downloadShown = false;

  const tasks = requests.map(async ({ key, path }) => {
    try {
      const data = await fetchJson(path);

      // Ignore late results from older runs
      if (runId !== activeLookup.runId) return;

      ensureResultObject();
      if (key === 'whois') {
        // Namespace WHOIS fields to avoid collisions with DNS fields.
        lastResult.whoisSource = data.source;
        lastResult.whoisCreationDateUtc = data.creationDateUtc;
        lastResult.whoisExpiryDateUtc = data.expiryDateUtc;
        lastResult.whoisRegistrar = data.registrar;
        lastResult.whoisRegistrant = data.registrant;
        lastResult.whoisAgeDays = data.ageDays;
        lastResult.whoisAgeHuman = data.ageHuman;
        lastResult.whoisIsYoungDomain = data.isYoungDomain;
        lastResult.whoisIsVeryYoungDomain = data.isVeryYoungDomain;
        lastResult.whoisExpiryDays = data.expiryDays;
        lastResult.whoisIsExpired = data.isExpired;
        lastResult.whoisExpiryHuman = data.expiryHuman;
        lastResult.whoisNewDomainThresholdDays = data.newDomainThresholdDays;
        lastResult.whoisNewDomainWarnThresholdDays = data.newDomainWarnThresholdDays;
        lastResult.whoisNewDomainErrorThresholdDays = data.newDomainErrorThresholdDays;
        lastResult.whoisError = data.error;
        lastResult.whoisRawText = data.rawWhoisText;
      } else if (key === 'reputation') {
        lastResult.reputation = data;
      } else {
        Object.assign(lastResult, data);
      }
      lastResult._loaded[key] = true;
      delete lastResult._errors[key];

      if (!downloadShown) {
        const dlBtn2 = document.getElementById("downloadBtn");
        if (dlBtn2) dlBtn2.style.display = "inline-block";
        downloadShown = true;
      }

      if (!savedHistory && key === "base") {
        saveHistory(domain);
        savedHistory = true;
      }

      recomputeDerived(lastResult);
      render(lastResult);
    } catch (err) {
      if (err && err.name === "AbortError") return;
      if (runId !== activeLookup.runId) return;

      const reason = (err && err.message) ? err.message : String(err);
      ensureResultObject();
      lastResult._loaded[key] = true;
      lastResult._errors[key] = reason;
      recomputeDerived(lastResult);
      render(lastResult);
    }
  });

  Promise.allSettled(tasks)
    .catch(() => {})
    .finally(() => {
      if (runId !== activeLookup.runId) return;
      btn.disabled = false;
      if (screenshotBtn) screenshotBtn.disabled = false;
      btn.innerHTML = "Lookup";
    });
}

function scrollToSection(key) {
  if (!key) return;
  const el = document.getElementById(`card-${key}`);
  if (el) {
    // If the card was collapsed, open it
    const header = el.querySelector('.card-header');
    if (header && header.classList.contains('collapsed-header')) {
        toggleCard(header);
    }

    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

    // Reset animation if already playing
    el.classList.remove('flash-active');
    void el.offsetWidth; // Trigger reflow
    el.classList.add('flash-active');

    setTimeout(() => {
      el.classList.remove('flash-active');
    }, 2400);
  }
}

function card(title, value, label, cls, key, showCopy = true, titleSuffixHtml = '') {
  const cardId = key ? `card-${key}` : '';
  // Always escape the title text to prevent XSS via crafted DNS responses.
  // Use titleSuffixHtml for trusted HTML additions (e.g., info-dot buttons, links).
  const safeTitle = escapeHtml(title);
  return `
  <div class="card"${cardId ? ` id="${cardId}"` : ''}>
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      ${label ? `<span class="tag ${cls}">${label}</span>` : ""}
      <strong>${safeTitle}</strong>${titleSuffixHtml ? ' ' + titleSuffixHtml : ''}
      ${showCopy ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, '${key}')">Copy</button>` : ""}
    </div>
    <div id="field-${key}" class="code card-content">${escapeHtml(value || "No Records Available.")}</div>
  </div>`;
}

// Toggle for MX additional details
function toggleMxDetails(element) {
  const el = document.getElementById("mxDetails");
  if (!el) return;

  // If the MX card is collapsed, expand it first and force details open.
  const header = element && element.closest ? element.closest(".card-header") : null;
  const content = header ? header.nextElementSibling : null;
  const isCollapsed = !!(header && header.classList && header.classList.contains("collapsed-header")) ||
                      !!(content && content.classList && content.classList.contains("collapsed"));
  if (isCollapsed && header) {
    toggleCard(header);
    el.style.display = "block";
    element.textContent = 'Additional Details -';
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === "none");
  if (isOpen) {
    element.textContent = 'Additional Details -';
  } else {
    element.textContent = 'Additional Details +';
  }
  el.style.display = isOpen ? "block" : "none";
}

function render(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};
  const mxLookupDomain = r && r.mxLookupDomain ? r.mxLookupDomain : (r ? r.domain : null);
  const mxFallbackUsed = !!(r && r.mxFallbackUsed);
  const mxFallbackChecked = r && r.mxFallbackDomainChecked ? r.mxFallbackDomainChecked : null;
  const allLoaded = !!(loaded.base && loaded.mx && loaded.whois && loaded.dmarc && loaded.dkim && loaded.cname && loaded.reputation);
  const anyError = !!(errors && Object.keys(errors).length > 0);
  let gatheredAtLocal = r.collectedAt ? formatLocalDateTime(r.collectedAt) : null;

  // Ensure collectedAt is stamped once all checks complete (for display + copy text)
  if (!r.collectedAt && allLoaded) {
    r.collectedAt = new Date().toISOString();
    gatheredAtLocal = formatLocalDateTime(r.collectedAt);
  }

  let statusText = "";

  if (!allLoaded) {
    statusText = "Checking " + escapeHtml(r.domain || "") + " &#x23F3;";
  } else if (anyError) {
    statusText = "Some checks failed &#x274C;";
  } else if (loaded.base && r.dnsFailed) {
    statusText = "TXT lookup failed &#x274C; &mdash; other DNS records may still resolve.";
  } else {
    // Determine overall status for Email Quota and Domain Verification

    // Domain Verification: strictly based on ACS readiness (ms-domain-verification TXT)
    let domainVerStatus = "Failed &#x274C;";
    if (r.acsReady) {
      domainVerStatus = "Passing &#x2705;";
    }

    // Email Quota: aggregation of MX, SPF, DMARC, DKIM, Reputation, Registration
    // Logic:
    // - If any required check fails (MX, SPF, DMARC, DKIM) -> Failed (or Warning if it's just reputation/registration warning)
    // - If partial issues -> Warning
    // - If all good -> Passing

    // Let's refine Quota status based on the "Email Quota" card logic:
    // MX: Pass if records exist. Warn otherwise.
    // Reputation: Pass if >=75% or no listings. Warn if listed or poor.
    // Registration: Pass if valid. Fail if expired/new.
    // SPF: Pass if present. Warn if missing.
    // Note: DMARC/DKIM are not strictly in the "Email Quota" card in the current UI (they are separate cards),
    // but often considered part of email readiness. The user said "Email Quota checks".
    // Looking at the 'Email Quota' card implementation in render(): it lists MX, Reputation, Registration, SPF.

    let quotaFail = false;
    let quotaWarn = false;

    // 1. MX
    if (!r.mxRecords || r.mxRecords.length === 0) { quotaFail = true; }

    // 2. Reputation
    // Logic from card: state is 'warn' if listed or poor reputation.
    if (r.reputation) {
        const repSum = r.reputation.summary || {};
        const repValid = (repSum.totalQueries || 0) - (repSum.errorCount || 0);
        const repPercent = (repValid > 0) ? ((repSum.notListedCount || 0) / repValid * 100) : null;
        if ((repSum.listedCount > 0) || (repPercent !== null && repPercent < 75)) {
            quotaWarn = true;
        }
    }

    // 3. Registration
    const whoisErrorText = errors.whois || r.whoisError || '';
    const whoisHasData = !!(r.whoisSource || r.whoisCreationDateUtc || r.whoisExpiryDateUtc || r.whoisRegistrar || r.whoisRegistrant || r.whoisAgeHuman || r.whoisExpiryHuman);
    if (whoisErrorText || !whoisHasData) {
        quotaWarn = true; // missing/failed WHOIS should not show PASS
    }
    if (r.whoisIsExpired === true || r.whoisIsVeryYoungDomain === true || r.whoisIsYoungDomain === true) {
        // Expired is bad. Very young is an error. Young is warning.
        if (r.whoisIsExpired === true || r.whoisIsVeryYoungDomain === true) quotaFail = true;
        else quotaWarn = true;
    }

    // 4. SPF
    if (!r.spfPresent) { quotaWarn = true; }

    let emailQuotaStatus = "Passing &#x2705;";
    if (quotaFail) {
        emailQuotaStatus = "Failed &#x274C;";
    } else if (quotaWarn) {
        emailQuotaStatus = "Warning &#x26A0;&#xFE0F;";
    }

    statusText = `Email Quota: ${emailQuotaStatus} | Domain Verification: ${domainVerStatus}`;
  }

  const statusWithTime = gatheredAtLocal
    ? `${statusText}<div style="font-size:12px;color:var(--status);margin-top:2px;">Collected on: ${escapeHtml(gatheredAtLocal)}</div>`
    : statusText;

  setStatus(statusWithTime);

  const cards = [];

  // Email Quota box (ordered requirements)
  const quotaItems = [];
  let quotaCopyText = '';
  const quotaLines = [];
  const quotaLinesHtml = [];
  const quotaCopyPlainLines = [];
  const quotaCopyHtmlLines = [];
  const quotaStateClass = (state) => {
    switch (state) {
      case 'pass': return 'tag-pass';
      case 'fail':
      case 'error': return 'tag-fail';
      case 'warn': return 'tag-warn';
      case 'pending':
      default: return 'tag-info';
    }
  };
  const quotaRow = (name, state, detail, infoTitle = null, targetId = null, extraHtml = '') => {
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(state.toUpperCase())}</span>`;
    const nameHtml = escapeHtml(name)
      + (infoTitle ? ` <button type="button" class="info-dot" aria-label="${escapeHtml(infoTitle)}" data-info="${escapeHtml(infoTitle)}">i</button>` : "")
      + (extraHtml ? ` ${extraHtml}` : '');
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">View</button>` : '';
    return `<div class="status-row"><span class="status-name">${nameHtml}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  let mxCopyDetail = '';
  let repCopyDetail = '';
  let repStats = null;

  const domainForCopy = r.domain || '';
  quotaLines.push(`**Email Quota for:** ${domainForCopy}`.trim());
  quotaLinesHtml.push(`<strong>Email Quota for:</strong> ${escapeHtml(domainForCopy)}`.trim());
  quotaCopyPlainLines.push(`Domain Name: ${domainForCopy}`);
  quotaCopyPlainLines.push('----------------------------------');
  quotaCopyHtmlLines.push(`<div><strong>Domain Name:</strong> ${escapeHtml(domainForCopy)}</div>`);
  quotaCopyHtmlLines.push('<div>----------------------------------</div>');


  // 1) MX Records
  let mxStatusText = '';
    if (!loaded.mx && !errors.mx) {
    mxCopyDetail = 'Checking MX records...';
    quotaItems.push(quotaRow('MX Records', 'pending', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** PENDING${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> PENDING${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = 'Checking...';
  } else if (errors.mx) {
    mxCopyDetail = errors.mx;
    quotaItems.push(quotaRow('MX Records', 'error', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ERROR${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ERROR${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = 'Error';
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    const mxRecordsText = (r.mxRecords || []).join(', ');
    if (hasMx) {
      let note = '';
      if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
        note = ` (using MX from ${mxLookupDomain})`;
      }
      mxCopyDetail = (mxRecordsText || 'MX records detected.') + note;
    } else {
      mxCopyDetail = 'No MX records detected.';
      if (mxFallbackChecked && mxFallbackChecked !== r.domain) {
        mxCopyDetail += ` Checked parent ${mxFallbackChecked} (no MX).`;
      }
    }
    const mxState = hasMx ? 'PASS' : 'FAIL';
    quotaItems.push(quotaRow('MX Records', hasMx ? 'pass' : 'fail', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ${mxState}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ${escapeHtml(mxState)}${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = hasMx ? 'Yes' : 'No';
  }

  quotaCopyPlainLines.push(`MX Records:   ${mxStatusText || 'Unknown'}`);
  if (mxCopyDetail) { quotaCopyPlainLines.push(`  ${mxCopyDetail}`); }
  quotaCopyHtmlLines.push(`<div><strong>MX Records:</strong> ${escapeHtml(mxStatusText || 'Unknown')}</div>` + (mxCopyDetail ? `<div style="margin-left:12px;">${escapeHtml(mxCopyDetail)}</div>` : ''));

  const multiRblLink = `https://multirbl.valli.org/dnsbl-lookup/${encodeURIComponent(r.domain || "")}.html`;
  const multiRblHtml = `<a href="${multiRblLink}" target="_blank" rel="noopener" style="font-size:11px; color:#2f80ed; text-decoration:none;">(MultiRBL &#x2197;)</a>`;

  // 2) Reputation
  const reputationInfo = "Reputation = percent of not-listed over successful DNSBL queries. Ratings: Excellent ≥99%, Great ≥90%, Good ≥75%, Fair ≥50%, Poor otherwise. Listed entries are shown when present; errors reduce confidence.";
  let repStateForCopy = '';
  if (!loaded.reputation && !errors.reputation) {
    repCopyDetail = 'Checking DNSBL reputation...';
    // Only pass plain name to quotaRow if we modify quotaRow or pass raw HTML differently.
    // However, quotaRow escapes name. Let's look at quotaRow definition in the user code above.
    // quotaRow calculates: const nameHtml = escapeHtml(name) + ...
    // So we cannot just append HTML to 'name'.

    // Changing strategy: We modify quotaRow call to include the link if it allows HTML or we modify quotaRow.
    // But modifying quotaRow is harder with replace_string.
    // Let's look at how quotaRow is defined:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => { ... const nameHtml = escapeHtml(name) ... }

    // Wait, I can redefine quotaRow or pass a special marker. Or simpler:
    // The user wants the link "beside the text (Reputation (DNSBL))".

    // Let's modify the usage of quotaRow for Reputation to hack it? No, escapeHtml prevents that.

    // I need to modify the quotaRow definition or the specific calls.
    // Since I can only replace strings, and the quotaRow definition is local to render(), I can modify quotaRow safely if I find it.

    // Let's see where quotaRow is defined.
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => {
    //   const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(state.toUpperCase())}</span>`;
    //   const nameHtml = escapeHtml(name) + (infoTitle ? ` <span class="info-dot" title="${escapeHtml(infoTitle)}">i</span>` : "");
    //   ...

    // I will modify `quotaRow` to accept an optional `extraHtml` argument or similar, OR just handle the link insertion inside the Reputation items.
    // But `quotaRow` is used for MX, Domain Reg, SPF too.

    // Actually, looking at `quotaRow` definition again:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null) => {

    // If I change the definition of quotaRow to:
    // const quotaRow = (name, state, detail, infoTitle = null, targetId = null, nameSuffixHtml = '') => {

    // This seems valuable.

    // However, I also need to update the "Copy Email Quota" text.
    // That is constructed via `quotaCopyPlainLines` and `quotaCopyHtmlLines`.

    // Let's start by modifying the quotaRow definition to support a suffix.

    quotaItems.push(quotaRow('Reputation (DNSBL)', 'pending', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** PENDING${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> PENDING${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}`);
    repStateForCopy = 'PENDING';
  } else if (errors.reputation) {
    repCopyDetail = errors.reputation;
    quotaItems.push(quotaRow('Reputation (DNSBL)', 'error', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** ERROR${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> ERROR${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}`);
    repStateForCopy = 'ERROR';
  } else {
    const rep = r.reputation || {};
    const summary = rep.summary || {};
    const listed = summary.listedCount || 0;
    const notListed = summary.notListedCount || 0;
    const errorCount = summary.errorCount || 0;
    const total = summary.totalQueries || 0;
    const repUsedParent = rep.lookupUsedParent === true && rep.lookupDomain && rep.lookupDomain !== (r.domain || '');
    const valid = Math.max(0, total - errorCount);
    const percent = (valid > 0) ? Math.max(0, Math.min(100, Math.round((notListed / valid) * 100))) : null;
    const rating = percent === null ? 'unknown' : (percent >= 99 ? 'excellent' : percent >= 90 ? 'great' : percent >= 75 ? 'good' : percent >= 50 ? 'fair' : 'poor');
    const ratingLabel = rating.charAt(0).toUpperCase() + rating.slice(1);
    const state = listed > 0 ? 'warn' : (percent === null ? 'warn' : (percent >= 75 ? 'pass' : 'warn'));
    const baseDetail = percent === null
      ? `Queries: ${total}, Not listed: ${notListed}`
      : `Rating: ${ratingLabel} (${percent}%) | Listed: ${listed}, Not listed: ${notListed}`;
    const parentNote = repUsedParent ? `Used parent domain ${rep.lookupDomain} (no IP targets found for ${r.domain || ''}).` : '';
    const detail = parentNote ? `${baseDetail} | ${parentNote}` : baseDetail;
    repCopyDetail = detail;
    repStats = {
      zones: Array.isArray(rep.rblZones) ? rep.rblZones.length : 0,
      total,
      errors: errorCount,
      percent,
      rating: ratingLabel,
      listed,
      notListed: summary.notListedCount || 0
    };
    quotaItems.push(quotaRow('Reputation (DNSBL)', state, detail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** ${state.toUpperCase()}${detail ? ' - ' + detail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> ${escapeHtml(state.toUpperCase())}${detail ? ' - ' + escapeHtml(detail) : ''}`);
    repStateForCopy = state.toUpperCase();
  }

  // 3) Domain Registration
  let regState = 'PENDING';
  const whoisErrorText = errors.whois || r.whoisError || '';
  const whoisHasData = !!(r.whoisSource || r.whoisCreationDateUtc || r.whoisExpiryDateUtc || r.whoisRegistrar || r.whoisRegistrant || r.whoisAgeHuman || r.whoisExpiryHuman);

  if (!loaded.whois && !errors.whois) {
    quotaItems.push(quotaRow('Domain Registration', 'pending', 'WHOIS/RDAP lookup in progress...', null, 'whois'));
    regState = 'PENDING';
  } else if (whoisErrorText) {
    quotaItems.push(quotaRow('Domain Registration', 'error', whoisErrorText, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState}${whoisErrorText ? ' - ' + whoisErrorText : ''}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${whoisErrorText ? ' - ' + escapeHtml(whoisErrorText) : ''}`);
  } else if (!whoisHasData) {
    const msg = 'Registration details unavailable.';
    quotaItems.push(quotaRow('Domain Registration', 'error', msg, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState} - ${msg}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)} - ${escapeHtml(msg)}`);
  } else {
    if (r.whoisIsExpired === true) {
      const expText = r.whoisExpiryDateUtc ? `Expired on ${r.whoisExpiryDateUtc}` : 'Registration appears expired.';
      quotaItems.push(quotaRow('Domain Registration', 'fail', expText, null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${expText ? ' - ' + expText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${expText ? ' - ' + escapeHtml(expText) : ''}`);
    } else if (r.whoisIsVeryYoungDomain === true) {
      const text = `New domain (under ${String(r.whoisNewDomainErrorThresholdDays || 90)} days)${r.whoisAgeHuman ? ': ' + r.whoisAgeHuman : ''}`.trim();
      quotaItems.push(quotaRow('Domain Registration', 'fail', text || 'New domain under 90 days.', null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else if (r.whoisIsYoungDomain === true) {
      const text = `New domain (under ${String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180)} days)${r.whoisAgeHuman ? ': ' + r.whoisAgeHuman : ''}`.trim();
      quotaItems.push(quotaRow('Domain Registration', 'warn', text || 'New domain under 180 days.', null, 'whois'));
      regState = 'WARN';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else {
      const parts = [];
      if (r.whoisAgeHuman) { parts.push(`Age: ${r.whoisAgeHuman}`); }
      if (r.whoisExpiryHuman) { parts.push(`Expires in: ${r.whoisExpiryHuman}`); }
      const ageText = parts.join(' | ') || 'Registration details available.';
      quotaItems.push(quotaRow('Domain Registration', 'pass', ageText, null, 'whois'));
      regState = 'PASS';
      quotaLines.push(`**Domain Registration:** ${regState}${ageText ? ' - ' + ageText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${ageText ? ' - ' + escapeHtml(ageText) : ''}`);
    }
  }

  // 4) SPF
  if (!loaded.base && !errors.base) {
    quotaItems.push(quotaRow('SPF (root TXT)', 'pending', 'Waiting for TXT lookup...', null, 'spf'));
    quotaLines.push('**SPF (root TXT):** PENDING - Waiting for TXT lookup...');
    quotaLinesHtml.push('<strong>SPF (root TXT):</strong> PENDING - Waiting for TXT lookup...');
  } else if (errors.base) {
    quotaItems.push(quotaRow('SPF (root TXT)', 'error', errors.base, null, 'spf'));
    quotaLines.push(`**SPF (root TXT):** ERROR${errors.base ? ' - ' + errors.base : ''}`);
    quotaLinesHtml.push(`<strong>SPF (root TXT):</strong> ERROR${errors.base ? ' - ' + escapeHtml(errors.base) : ''}`);
  } else if (r.dnsFailed) {
    quotaItems.push(quotaRow('SPF (root TXT)', 'warn', r.dnsError || 'TXT lookup failed.', null, 'spf'));
    quotaLines.push(`**SPF (root TXT):** WARN${r.dnsError ? ' - ' + r.dnsError : ' - TXT lookup failed.'}`);
    quotaLinesHtml.push(`<strong>SPF (root TXT):</strong> WARN${r.dnsError ? ' - ' + escapeHtml(r.dnsError) : ' - TXT lookup failed.'}`);
  } else {
    quotaItems.push(quotaRow('SPF (root TXT)', r.spfPresent ? 'pass' : 'warn', r.spfPresent ? r.spfValue : 'No SPF record detected.', null, 'spf'));
    const spfState = r.spfPresent ? 'PASS' : 'WARN';
    quotaLines.push(`**SPF (root TXT):** ${spfState}${r.spfPresent ? ' - ' + r.spfValue : ' - No SPF record detected.'}`);
    quotaLinesHtml.push(`<strong>SPF (root TXT):</strong> ${escapeHtml(spfState)}${r.spfPresent ? ' - ' + escapeHtml(r.spfValue) : ' - No SPF record detected.'}`);
  }

  // Domain age / expiry for copy block
  const ageText = r.whoisAgeHuman || 'Unknown';
  const expiryText = r.whoisIsExpired === true ? 'Expired' : (r.whoisExpiryHuman || 'Unknown');
  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`Domain Age:  ${ageText}`);
  quotaCopyPlainLines.push(`Domain Expires in: ${expiryText}`);
  quotaCopyHtmlLines.push(`<div><strong>Domain Age:</strong> ${escapeHtml(ageText)}</div>`);
  quotaCopyHtmlLines.push(`<div><strong>Domain Expires in:</strong> ${escapeHtml(expiryText)}</div>`);

  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`Reputation (DNSBL) [MultiRBL: ${multiRblLink}] - ${repStateForCopy || 'UNKNOWN'}${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
  quotaCopyHtmlLines.push(`<div><strong>Reputation (DNSBL) - ${escapeHtml(repStateForCopy || 'UNKNOWN')}</strong>&nbsp;${multiRblHtml}${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}</div>`);

  if (repStats) {
    const repLines = [
      `Zones queried: ${repStats.zones}`,
      `Total queries: ${repStats.total}`,
      `Errors: ${repStats.errors}`,
      `Reputation: ${repStats.rating}${repStats.percent !== null ? ` (${repStats.percent}%)` : ''}`,
      `Listed: ${repStats.listed}`,
      `Not listed: ${repStats.notListed}`
    ];
    quotaCopyPlainLines.push(...repLines);
    quotaCopyHtmlLines.push('<div>' + repLines.map(l => escapeHtml(l)).join('<br>') + '</div>');
  }

  const repSummaryText = `${(repStateForCopy || 'UNKNOWN')}${repCopyDetail ? ' - ' + repCopyDetail : ''}` + (repStats
    ? ` | Zones queried: ${repStats.zones} | Total queries: ${repStats.total} | Listed: ${repStats.listed} | Not listed: ${repStats.notListed}`
    : '');

  const domainStatusText = (!loaded.base && !errors.base)
    ? 'PENDING'
    : (errors.base
      ? 'ERROR'
      : (r.acsPresent ? 'VERIFIED' : 'NOT VERIFIED'));

  const spfStatusText = (!loaded.base && !errors.base)
    ? 'PENDING'
    : (errors.base
      ? 'ERROR'
      : (r.spfPresent ? 'VERIFIED' : 'NOT STARTED'));

  const dkim1StatusText = (!loaded.dkim && !errors.dkim)
    ? 'PENDING'
    : (errors.dkim
      ? 'ERROR'
      : (r.dkim1 ? 'VERIFIED' : 'NOT STARTED'));

  const dkim2StatusText = (!loaded.dkim && !errors.dkim)
    ? 'PENDING'
    : (errors.dkim
      ? 'ERROR'
      : (r.dkim2 ? 'VERIFIED' : 'NOT STARTED'));

  const dmarcStatusText = (!loaded.dmarc && !errors.dmarc)
    ? 'PENDING'
    : (errors.dmarc
      ? 'ERROR'
      : (r.dmarc ? 'VERIFIED' : 'NOT STARTED'));

  const plainTable = [];
  plainTable.push('| Field | Value |');
  plainTable.push('| --- | --- |');
  plainTable.push(`| Domain Name | ${domainForCopy || 'Unknown'} |`);
  plainTable.push(`| Domain Status | ${domainStatusText} |`);
  plainTable.push(`| MX Records | ${mxStatusText || 'Unknown'}${mxCopyDetail ? ` - ${mxCopyDetail}` : ''} |`);
  plainTable.push(`| Domain Age | ${ageText} |`);
  plainTable.push(`| Domain Expires in | ${expiryText} |`);
  plainTable.push(`| SPF Status | ${spfStatusText} |`);
  plainTable.push(`| DKIM1 Status | ${dkim1StatusText} |`);
  plainTable.push(`| DKIM2 Status | ${dkim2StatusText} |`);
  plainTable.push(`| DMARC Status | ${dmarcStatusText} |`);
  plainTable.push(`| Reputation (DNSBL) | ${repSummaryText} [MultiRBL: ${multiRblLink}] |`);

  const htmlTableRows = [];
  const addRow = (name, value) => { htmlTableRows.push(`<tr><th>${escapeHtml(name)}</th><td>${escapeHtml(value)}</td></tr>`); };
  addRow('Domain Name', domainForCopy || 'Unknown');
  addRow('Domain Status', domainStatusText);
  addRow('MX Records', `${mxStatusText || 'Unknown'}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
  addRow('Domain Age', ageText);
  addRow('Domain Expires in', expiryText);
  addRow('SPF Status', spfStatusText);
  addRow('DKIM1 Status', dkim1StatusText);
  addRow('DKIM2 Status', dkim2StatusText);
  addRow('DMARC Status', dmarcStatusText);
  // Manual push for Reputation to include parsed HTML link (multiRblHtml)
  htmlTableRows.push(`<tr><th>Reputation (DNSBL)</th><td>${escapeHtml(repSummaryText)}<br>${multiRblHtml}</td></tr>`);

  const quotaCopyTextPlain = plainTable.join('\n');
  const quotaCopyTextHtml = `<table style="border-collapse:collapse;min-width:260px;">${htmlTableRows.map(r => r.replace('<th>', '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">').replace('<td>', '<td style="padding:4px 8px;border:1px solid #ddd;">')).join('')}</table>`;
  quotaCopyText = quotaCopyTextPlain;
  // Expose for inline copy handler with rich + plain variants
  window.quotaCopyText = { plain: quotaCopyTextPlain, html: quotaCopyTextHtml };

  cards.push(`
  <div class="card" id="card-email-quota">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">CHECKLIST</span>
      <strong>Email Quota</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left:auto;" onclick="event.stopPropagation(); copyText(window.quotaCopyText, this)">Copy Email Quota</button>
    </div>
    <div class="card-content">
      <div class="status-summary">${quotaItems.join('')}</div>
    </div>
  </div>
  `);

  // Domain Verification box (ACS requirements)
  const verificationItems = [];
  const verifyRow = (name, state, detail, targetId = null) => {
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(state.toUpperCase())}</span>`;
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">View</button>` : '';
    return `<div class="status-row"><span class="status-name">${escapeHtml(name)}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  if (!loaded.base && !errors.base) {
    verificationItems.push(verifyRow('DNS TXT Lookup', 'pending', 'Waiting for base TXT lookup...', 'txtRecords'));
    verificationItems.push(verifyRow('ACS TXT (ms-domain-verification)', 'pending', 'Waiting for base TXT lookup...', 'acsTxt'));
  } else if (errors.base) {
    verificationItems.push(verifyRow('DNS TXT Lookup', 'error', errors.base, 'txtRecords'));
    verificationItems.push(verifyRow('ACS TXT (ms-domain-verification)', 'error', 'Unable to determine ACS TXT value.', 'acsTxt'));
  } else if (r.dnsFailed) {
    verificationItems.push(verifyRow('DNS TXT Lookup', 'fail', r.dnsError || 'TXT lookup failed or timed out.', 'txtRecords'));
    verificationItems.push(verifyRow('ACS TXT (ms-domain-verification)', 'fail', 'Missing ms-domain-verification TXT.', 'acsTxt'));
  } else {
    verificationItems.push(verifyRow('DNS TXT Lookup', 'pass', 'Resolved successfully.', 'txtRecords'));
    verificationItems.push(verifyRow('ACS TXT (ms-domain-verification)', r.acsPresent ? 'pass' : 'fail', r.acsPresent ? 'ms-domain-verification TXT found.' : 'Add the ACS TXT from the Azure portal.', 'acsTxt'));
  }

  // Overall ACS readiness
  verificationItems.push(verifyRow('ACS Readiness', (loaded.base && !errors.base && !r.dnsFailed && r.acsPresent) ? 'pass' : (loaded.base && !errors.base ? 'fail' : 'pending'), r.acsReady ? 'Domain appears ready for ACS verification.' : 'Missing required ACS TXT.', 'verification'));

  cards.push(`
  <div class="card" id="card-verification">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">VERIFICATION</span>
      <strong>Domain Verification</strong>
    </div>
    <div class="card-content">
      <div class="status-summary">${verificationItems.join('')}</div>
    </div>
  </div>
  `);

  const basePending = !loaded.base && !errors.base;
  const baseError = !!errors.base;

  // Domain Registration card now appears second
  if (!loaded.whois && !errors.whois) {
    cards.push(card(
      "Domain Registration (WHOIS/RDAP)",
      "Loading...",
      "LOADING",
      "tag-info",
      "whois",
      true
    ));
  } else if (errors.whois) {
    cards.push(card(
      "Domain Registration (WHOIS/RDAP)",
      errors.whois,
      "ERROR",
      "tag-fail",
      "whois",
      true
    ));
  } else {
    const isExpired = r.whoisIsExpired === true;
    const isYoung = r.whoisIsYoungDomain === true;
    const isVeryYoung = r.whoisIsVeryYoungDomain === true;
    const whoisLines = [];
    if (r.whoisSource) whoisLines.push("Source: " + r.whoisSource);
    if (r.whoisCreationDateUtc) whoisLines.push("Creation Date: " + r.whoisCreationDateUtc);
    if (r.whoisExpiryDateUtc) whoisLines.push("Registry Expiry Date: " + r.whoisExpiryDateUtc);
    if (r.whoisRegistrar) whoisLines.push("Registrar: " + r.whoisRegistrar);
    if (r.whoisRegistrant) whoisLines.push("Registrant: " + r.whoisRegistrant);
    if (r.whoisAgeHuman) {
      whoisLines.push("Domain Age: " + r.whoisAgeHuman);
    } else if (r.whoisAgeDays !== null && r.whoisAgeDays !== undefined) {
      whoisLines.push("Domain Age (days): " + String(r.whoisAgeDays));
    }
    if (r.whoisExpiryHuman) {
      whoisLines.push("Domain Expiring in: " + r.whoisExpiryHuman);
    }
    if (isExpired) {
      whoisLines.push("Status: EXPIRED");
    } else if (isVeryYoung) {
      whoisLines.push("Note: Domain is less than " + String(r.whoisNewDomainErrorThresholdDays || 90) + " days old.");
    } else if (isYoung) {
      whoisLines.push("Note: Domain is less than " + String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180) + " days old.");
    }
    if (r.whoisExpiryDays !== null && r.whoisExpiryDays !== undefined) {
      whoisLines.push("Days until expiry: " + String(r.whoisExpiryDays));
    }
    if (r.whoisRawText) {
      whoisLines.push("Raw (Sysinternals whois):\n" + r.whoisRawText);
    }
    if (r.whoisError) whoisLines.push("Error: " + r.whoisError);

    let whoisLabel = "INFO";
    let whoisTagClass = "tag-info";
    if (isExpired) {
      whoisLabel = "EXPIRED";
      whoisTagClass = "tag-fail";
    } else if (isVeryYoung) {
      whoisLabel = "NEW DOMAIN";
      whoisTagClass = "tag-fail";
    } else if (isYoung) {
      whoisLabel = "NEW DOMAIN";
      whoisTagClass = "tag-warn";
    }

    cards.push(card(
      "Domain Registration (WHOIS/RDAP)",
      whoisLines.join("\n") || "No registration information available.",
      whoisLabel,
      whoisTagClass,
      "whois",
      true
    ));
  }

  {
    const baseLoaded = loaded.base && !errors.base && !r.dnsFailed;
    const ipv4List = Array.isArray(r.ipv4Addresses) ? r.ipv4Addresses.filter(x => x) : [];
    const ipv6List = Array.isArray(r.ipv6Addresses) ? r.ipv6Addresses.filter(x => x) : [];
    const ipLookupDomain = r.ipLookupDomain || r.domain;
    const ipUsedParent = r.ipUsedParent === true && ipLookupDomain && ipLookupDomain !== r.domain;
    const domainLabel = basePending ? "PENDING" : (baseError ? "ERROR" : (r.dnsFailed ? "DNS ERROR" : "LOOKED UP"));
    const domainClass = basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info");

    const ipNote = baseLoaded && ipUsedParent
      ? `<div class="code" style="margin-top:6px;">Using IP addresses from parent domain ${escapeHtml(ipLookupDomain)} (no A/AAAA on ${escapeHtml(r.domain || '')}).</div>`
      : '';

    const ipvTable = baseLoaded ? `
      <div class="code" style="margin-top:6px; padding:0;">
        <table class="mx-table">
          <thead>
            <tr>
              <th style="width: 120px;">Type</th>
              <th>Addresses</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>IPv4</td><td>${ipv4List.length ? ipv4List.map(escapeHtml).join(', ') : 'None'}</td></tr>
            <tr><td>IPv6</td><td>${ipv6List.length ? ipv6List.map(escapeHtml).join(', ') : 'None'}</td></tr>
          </tbody>
        </table>
      </div>
    ` : '';

    cards.push(`
      <div class="card" id="card-domain">
        <div class="card-header" onclick="toggleCard(this)">
          <span class="chevron">&#x25BC;</span>
          <span class="tag ${domainClass}">${domainLabel}</span>
          <strong>Domain</strong>
        </div>
        <div class="card-content">
          <div id="field-domain" class="code">${escapeHtml(r.domain || 'No Records Available.')}</div>
          ${ipNote}${ipvTable}
        </div>
      </div>
    `);
  }

  // MX (placed directly below Domain per UI request)
  if (!loaded.mx && !errors.mx) {
    cards.push(card(
      "MX Records",
      "Loading...",
      "LOADING",
      "tag-info",
      "mx",
      false
    ));
  } else if (errors.mx) {
    cards.push(card(
      "MX Records",
      errors.mx,
      "ERROR",
      "tag-fail",
      "mx",
      false
    ));
  } else {
    let mxFallbackNote = '';
    if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">No MX records found on ${escapeHtml(r.domain || '')}; showing MX for parent domain ${escapeHtml(mxLookupDomain)}.</div>`;
    } else if ((!r.mxRecords || r.mxRecords.length === 0) && mxFallbackChecked && mxFallbackChecked !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">No MX records found on ${escapeHtml(r.domain || '')} or parent ${escapeHtml(mxFallbackChecked)}.</div>`;
    }

    const ipv4Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv4");
    const ipv6Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv6");
    const noIpRecords = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "N/A");

    let mxDetailsContent = "";

    if (ipv4Records.length > 0) {
      const ipv4Rows = ipv4Records.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">IPv4 Addresses</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>${ipv4Rows}</tbody>
        </table>
      </div>`;
    }

    if (ipv6Records.length > 0) {
      const ipv6Rows = ipv6Records.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">IPv6 Addresses</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>${ipv6Rows}</tbody>
        </table>
      </div>`;
    }

    if (noIpRecords.length > 0) {
      const noIpRows = noIpRecords.map(record =>
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");

      mxDetailsContent += `<div>
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">No IP Addresses Found</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>${noIpRows}</tbody>
        </table>
      </div>`;
    }

    if (!mxDetailsContent) {
      mxDetailsContent = '<div class="code">No additional MX details available.</div>';
    }

    cards.push(`
  <div class="card" id="card-mx">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">INFO</span>
      <strong>MX Records</strong>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              style="margin-left: auto;"
              onclick="event.stopPropagation(); toggleMxDetails(this)">
        Additional Details +
      </button>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              onclick="event.stopPropagation(); copyField(this, 'mx')">
        Copy
      </button>
    </div>
    <div class="card-content">
      ${mxFallbackNote}
      ${r.mxProvider ? `<div class="code" style="margin-bottom:6px;">Detected provider: ${escapeHtml(r.mxProvider)}${r.mxProviderHint ? " — " + escapeHtml(r.mxProviderHint) : ""}</div>` : ""}
      <div id="field-mx" class="code">${escapeHtml((r.mxRecords || []).join("\n") || "No Records Available.")}</div>
      <div id="mxDetails" style="margin-top:6px; display:none;">${mxDetailsContent}</div>
    </div>
  </div>
    `);
  }

  // Match card order to the Check Summary.
  cards.push(card(
    "SPF (root TXT)",
    loaded.base ? r.spfValue : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.spfPresent ? "PASS" : "OPTIONAL")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.spfPresent ? "tag-pass" : "tag-info")),
    "spf"
  ));

  cards.push(card(
    "ACS Domain Verification TXT",
    loaded.base ? r.acsValue : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.acsPresent ? "PASS" : "MISSING")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.acsPresent ? "tag-pass" : "tag-fail")),
    "acsTxt"
  ));

  cards.push(card(
    "TXT Records (root)",
    loaded.base ? (r.txtRecords || []).join("\n") : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : "INFO"),
    basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info"),
    "txtRecords",
    false
  ));

  cards.push(card(
    "DMARC",
    loaded.dmarc ? r.dmarc : (errors.dmarc ? errors.dmarc : "Loading..."),
    (!loaded.dmarc && !errors.dmarc) ? "LOADING" : (errors.dmarc ? "ERROR" : (r.dmarc ? "PASS" : "OPTIONAL")),
    (!loaded.dmarc && !errors.dmarc) ? "tag-info" : (errors.dmarc ? "tag-fail" : (r.dmarc ? "tag-pass" : "tag-info")),
    "dmarc"
  ));

  // include full selector host with domain in title
  cards.push(card(
    `DKIM1 (selector1-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim1 : (errors.dkim ? errors.dkim : "Loading..."),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim1 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim1 ? "tag-pass" : "tag-info")),
    "dkim1"
  ));

  cards.push(card(
    `DKIM2 (selector2-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim2 : (errors.dkim ? errors.dkim : "Loading..."),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim2 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim2 ? "tag-pass" : "tag-info")),
    "dkim2"
  ));

  // Reputation / DNSBL
  if (!loaded.reputation && !errors.reputation) {
    cards.push(card(
      'Reputation (DNSBL)',
      "Loading...",
      "LOADING",
      "tag-info",
      "reputation",
      false,
      multiRblHtml
    ));
  } else if (errors.reputation) {
    cards.push(card(
      'Reputation (DNSBL)',
      errors.reputation,
      "ERROR",
      "tag-fail",
      "reputation",
      false,
      `<button type="button" class="info-dot" aria-label="${escapeHtml(reputationInfo)}" data-info="${escapeHtml(reputationInfo)}">i</button> ${multiRblHtml}`
    ));
  } else {
    const rep = r.reputation || {};
    const summary = rep.summary || {};
    const listed = summary.listedCount || 0;
    const errorCount = summary.errorCount || 0;
    const notListed = summary.notListedCount || 0;
    const total = summary.totalQueries || 0;
    const repUsedParent = rep.lookupUsedParent === true && rep.lookupDomain && rep.lookupDomain !== (r.domain || '');
    const validQueries = Math.max(0, total - errorCount);

    let percent = null;
    if (validQueries > 0) {
      percent = Math.max(0, Math.min(100, Math.round((notListed / validQueries) * 100)));
    }

    let rating = "Unknown";
    if (percent !== null) {
      if (percent >= 99) rating = "Excellent";
      else if (percent >= 90) rating = "Great";
      else if (percent >= 75) rating = "Good";
      else if (percent >= 50) rating = "Fair";
      else rating = "Poor";
    }

    const statusLabel = percent === null ? "UNKNOWN" : `${rating.toUpperCase()} (${percent}%)`;
    const statusClass = percent === null ? "tag-info"
      : (percent >= 90 ? "tag-pass"
      : (percent >= 75 ? "tag-info" : "tag-fail"));

    // Show only listed entries to avoid noise
    const listedItems = (rep.results || []).filter(x => x && x.listed === true);
    let body = `Zones queried: ${rep.rblZones ? rep.rblZones.length : 0}\n` +
               `Total queries: ${total}\n` +
               `Errors: ${errorCount}`;
    if (percent !== null) {
      body += `\nReputation: ${rating} (${percent}%)`;
      body += `\nListed: ${listed}\nNot listed: ${notListed}`;
    } else {
      body += "\nReputation: Unknown (no successful queries)";
    }
    if (listedItems.length > 0) {
      const lines = listedItems.map(x => `IP ${x.ip} listed on ${x.queriedZone}${x.listedAddress ? ` (${x.listedAddress})` : ''}`);
      body += "\n\nListings:\n" + lines.join("\n");
    }

    cards.push(card(
      'Reputation (DNSBL)',
      body,
      statusLabel,
      statusClass,
      "reputation",
      false,
      `<button type="button" class="info-dot" aria-label="${escapeHtml(reputationInfo)}" data-info="${escapeHtml(reputationInfo)}">i</button> ${multiRblHtml}`
    ));
  }

  cards.push(card(
    "CNAME",
    loaded.cname ? r.cname : (errors.cname ? errors.cname : "Loading..."),
    (!loaded.cname && !errors.cname) ? "LOADING" : (errors.cname ? "ERROR" : (r.cname ? "PASS" : "FAIL")),
    (!loaded.cname && !errors.cname) ? "tag-info" : (errors.cname ? "tag-fail" : (r.cname ? "tag-pass" : "tag-fail")),
    "cname"
  ));

  const guidanceItems = (r.guidance || []).map(g => "<li>" + escapeHtml(g) + "</li>").join("");
  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">READINESS TIPS</span>
        <strong>Guidance &#x1F4A1;</strong>
      </div>
      <div id="field-guidance" class="card-content">
        <ul class="guidance">
          ${guidanceItems || "<li>No additional guidance.</li>"}
        </ul>
      </div>
    </div>
  `);

  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">DOCS</span>
        <strong>Helpful Links</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="https://learn.microsoft.com/search/?terms=Azure%20Communication%20Services%20email%20domain%20verification" target="_blank" rel="noopener">ACS email domain verification</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=SPF%20record" target="_blank" rel="noopener">SPF record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=DMARC%20record" target="_blank" rel="noopener">DMARC record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=DKIM%20record" target="_blank" rel="noopener">DKIM record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=MX%20record" target="_blank" rel="noopener">MX record basics</a></li>
        </ul>
      </div>
    </div>
  `);

  const domainForLinks = encodeURIComponent(r.domain || "");
  const centralOps = `https://centralops.net/co/DomainDossier.aspx?addr=${domainForLinks}&dom_whois=true&dom_dns=true&traceroute=true&net_whois=true&svc_scan=true`;
  const multiRbl = `https://multirbl.valli.org/dnsbl-lookup/${domainForLinks}.html`;
  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">TOOLS</span>
        <strong>External Tools</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="${centralOps}" target="_blank" rel="noopener">Domain Dossier (CentralOps)</a></li>
          <li><a href="${multiRbl}" target="_blank" rel="noopener">MultiRBL DNSBL Lookup</a></li>
        </ul>
      </div>
    </div>
  `);

  document.getElementById("results").innerHTML = cards.join("");
}

document.getElementById("domainInput").addEventListener("keyup", function (e) {
  if (e.key === "Enter") {
    lookup();
  }
});

// Theme + query-domain initialization
window.addEventListener("load", function () {
  // 1. Check for saved theme
  // 2. If none, check system preference (Dark vs Light)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = systemPrefersDark ? "dark" : "light";

  const savedTheme = localStorage.getItem("acsTheme") || defaultTheme;

  applyTheme(savedTheme);
  loadHistory();
  toggleClearBtn();

  const params = new URLSearchParams(window.location.search);
  const d = params.get("domain");
  if (d) {
    document.getElementById("domainInput").value = d;
    toggleClearBtn();
    lookup();
  }

  const reportBtn = document.getElementById("reportIssueBtn");
  const issueUrl = (acsIssueUrl || '').trim();
  if (reportBtn) {
    reportBtn.style.display = (!issueUrl || issueUrl.startsWith('__')) ? 'none' : '';
  }

  // Initialize Microsoft Entra ID authentication
  initMsAuth();
});

// ------------------- Microsoft Entra ID Authentication -------------------
// Uses MSAL.js v2 with Authorization Code + PKCE (most secure SPA flow).
// The client ID must match an Azure AD app registration configured as a
// Single-Page Application with redirect URI matching this app's origin.
// Set the ACS_ENTRA_CLIENT_ID env var or update the placeholder below.

let msalInstance = null;
let msAuthAccount = null;
let isMsEmployee = false;
let msalInitError = null;

function getMsalConfig() {
  // The client ID is injected server-side from ACS_ENTRA_CLIENT_ID env var.
  // If not set, auth buttons remain visible but disabled with guidance.
  const rawClientId = '__ENTRA_CLIENT_ID__';
  const clientId = (rawClientId || '').trim();
  if (!clientId || clientId.startsWith('__')) return null;

  const tenant = (entraTenant || '').trim();
  const authorityTenant = tenant || 'organizations';

  return {
    auth: {
      clientId: clientId,
      authority: `https://login.microsoftonline.com/${authorityTenant}`,
      redirectUri: window.location.origin + window.location.pathname,
      postLogoutRedirectUri: window.location.origin + window.location.pathname
    },
    cache: {
      cacheLocation: 'sessionStorage',
      storeAuthStateInCookie: false
    }
  };
}

async function initMsAuth() {
  const config = getMsalConfig();
  if (!config) {
    // No client ID configured; keep button visible and show guidance on click
    const btn = document.getElementById('msSignInBtn');
    if (btn) {
      btn.style.display = '';
      btn.disabled = false;
      btn.innerHTML = 'Sign in with Microsoft &#x1F512;';
    }
    msalInitError = 'Missing ACS_ENTRA_CLIENT_ID in the served HTML.';
    setStatus('Microsoft sign-in is not configured. Confirm the ACS_ENTRA_CLIENT_ID was injected into the page and refresh.');
    return;
  }

  try {
    await ensureMsalLoaded();
  } catch (e) {
    msalInitError = e?.message || 'MSAL library not loaded.';
    setStatus('Microsoft sign-in library failed to load. Verify access to the MSAL CDN or provide a local msal-browser.min.js file.');
    return;
  }

  if (typeof msal === 'undefined') {
    msalInitError = 'MSAL library not loaded.';
    setStatus('Microsoft sign-in library failed to load. Verify access to the MSAL CDN or provide a local msal-browser.min.js file.');
    return;
  }

  try {
    msalInitError = null;
    msalInstance = new msal.PublicClientApplication(config);
    await msalInstance.initialize();

    // Handle redirect response (if returning from auth flow)
    let response = null;
    try {
      response = await msalInstance.handleRedirectPromise();
    } catch (e) {
      // MSAL throws this when the app is loaded normally (not from a redirect) but no request state exists.
      // Treat it as non-fatal so the sign-in button remains usable.
      const msg = (e && (e.errorMessage || e.message)) ? String(e.errorMessage || e.message) : '';
      const code = e && e.errorCode ? String(e.errorCode) : '';
      const isNoCache = (code === 'no_token_request_cache_error') || msg.includes('no_token_request_cache_error');
      if (!isNoCache) { throw e; }
      response = null;
    }

    if (response && response.account && response.accessToken) {
      // Redirect-based login just completed in this window
      msAuthAccount = response.account;
      await verifyMsAccount(response.accessToken);
      return;
    }

    // No redirect in progress: restore existing session, if any
    const accounts = msalInstance.getAllAccounts();
    if (accounts.length > 0) {
      msAuthAccount = accounts[0];
      try {
        const silentResult = await msalInstance.acquireTokenSilent({
          scopes: ['User.Read'],
          account: msAuthAccount
        });
        await verifyMsAccount(silentResult.accessToken);
      } catch (e) {
        // Silent acquisition failed; user needs to sign in again
        updateAuthUI(null);
      }
    } else {
      // No existing account; ensure buttons are in a clean state
      updateAuthUI(null);
    }
  } catch (e) {
    console.error('MSAL initialization error:', e);
    msalInitError = e?.message || 'Unknown initialization error.';
    setStatus('Microsoft sign-in failed to initialize. Check the browser console for details.');
  }
}

async function msSignIn() {
  if (!msalInstance) {
    if (msalInitError) {
      setStatus('Microsoft sign-in failed to initialize: ' + msalInitError);
    } else {
      setStatus('Microsoft sign-in is not configured. Set the ACS_ENTRA_CLIENT_ID environment variable and restart.');
    }
    return;
  }

  try {
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Signing in...'; }

    // Use redirect flow for best compatibility with browser / popup blockers.
    await msalInstance.loginRedirect({
      scopes: ['User.Read'],
      prompt: 'select_account'
    });
  } catch (e) {
    console.error('Sign-in error:', e);
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = false; btn.innerHTML = 'Sign in with Microsoft &#x1F512;'; }

    if (e && e.errorCode === 'user_cancelled') {
      setStatus('Sign-in was cancelled.');
    } else {
      setStatus('Sign-in failed: ' + (e?.errorMessage || e?.message || 'Unknown error'));
    }
  }
}

async function msSignOut() {
  if (!msalInstance) return;

  try {
    msAuthAccount = null;
    isMsEmployee = false;
    updateAuthUI(null);
    await msalInstance.logoutRedirect({
      postLogoutRedirectUri: window.location.origin + window.location.pathname
    });
  } catch (e) {
    console.error('Sign-out error:', e);
  }
}

async function verifyMsAccount(accessToken) {
  try {
    const resp = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessToken
      }
    });

    if (!resp.ok) {
      console.error('Auth verify failed:', resp.status);
      updateAuthUI(null);
      return;
    }

    const data = await resp.json();
    isMsEmployee = data.isMicrosoftEmployee === true;
    updateAuthUI(data);
  } catch (e) {
    console.error('Auth verify error:', e);
    updateAuthUI(null);
  }
}

function updateAuthUI(authData) {
  const signInBtn = document.getElementById('msSignInBtn');
  const signOutBtn = document.getElementById('msSignOutBtn');
  const statusEl = document.getElementById('msAuthStatus');

  if (authData && msAuthAccount) {
    if (signInBtn) signInBtn.style.display = 'none';
    if (signOutBtn) signOutBtn.style.display = '';
    if (statusEl) {
      statusEl.style.display = '';
      const name = escapeHtml(authData.displayName || msAuthAccount.name || '');
      if (authData.isMicrosoftEmployee) {
        statusEl.className = 'ms-auth-status ms-employee hide-on-screenshot';
        statusEl.innerHTML = '&#x2705; ' + name + ' (Microsoft)';
      } else {
        statusEl.className = 'ms-auth-status ms-external hide-on-screenshot';
        statusEl.innerHTML = '&#x1F464; ' + name;
      }
    }
  } else {
    if (signInBtn) {
      signInBtn.style.display = '';
      signInBtn.disabled = false;
      signInBtn.innerHTML = 'Sign in with Microsoft &#x1F512;';
    }
    if (signOutBtn) signOutBtn.style.display = 'none';
    if (statusEl) statusEl.style.display = 'none';
    isMsEmployee = false;
  }
}
</script>

</body>
</html>
'@

$htmlPage = $htmlPage.Replace('__APP_VERSION__', $script:AppVersion)

# Inject Entra ID (Azure AD) client ID for Microsoft employee authentication.
# Set ACS_ENTRA_CLIENT_ID env var to an Azure AD app registration configured as a
# Single-Page Application (SPA) with redirect URI matching this app's origin.
$entraClientId = $env:ACS_ENTRA_CLIENT_ID
if ([string]::IsNullOrWhiteSpace($entraClientId)) { $entraClientId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_CLIENT_ID__', $entraClientId)

$entraTenantId = $env:ACS_ENTRA_TENANT_ID
if ([string]::IsNullOrWhiteSpace($entraTenantId)) { $entraTenantId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_TENANT_ID__', $entraTenantId)

$apiKey = $env:ACS_API_KEY
if ([string]::IsNullOrWhiteSpace($apiKey)) { $apiKey = '' }
$htmlPage = $htmlPage.Replace('__ACS_API_KEY__', $apiKey)

$issueUrl = $env:ACS_ISSUE_URL
if ([string]::IsNullOrWhiteSpace($issueUrl)) { $issueUrl = '' }
$htmlPage = $htmlPage.Replace('__ACS_ISSUE_URL__', $issueUrl)

# Optional local MSAL script path (for environments that block CDNs)
$msalLocalPath = $env:ACS_MSAL_LOCAL_PATH
if ([string]::IsNullOrWhiteSpace($msalLocalPath)) {
  $msalLocalPath = Join-Path -Path $PSScriptRoot -ChildPath 'msal-browser.min.js'
}
$msalLocalPath = [System.IO.Path]::GetFullPath($msalLocalPath)

if (-not (Test-Path -LiteralPath $msalLocalPath)) {
  $msalNodePath = Join-Path -Path $PSScriptRoot -ChildPath 'node_modules\@azure\msal-browser\lib\msal-browser.min.js'
  if (Test-Path -LiteralPath $msalNodePath) {
    $msalLocalPath = [System.IO.Path]::GetFullPath($msalNodePath)
  }
}

if (-not (Test-Path -LiteralPath $msalLocalPath) -and $env:ACS_MSAL_AUTO_INSTALL -eq '1') {
  $npmCmd = $null
  try { $npmCmd = Get-Command -Name npm -ErrorAction SilentlyContinue } catch { $npmCmd = $null }
  if ($npmCmd) {
    try {
      Write-Information -InformationAction Continue -MessageData "MSAL bundle missing. Running npm install @azure/msal-browser@latest in $PSScriptRoot..."
      & $npmCmd.Source install --no-fund --no-audit --prefix $PSScriptRoot @azure/msal-browser@latest | Out-Null
      if ($LASTEXITCODE -ne 0) {
        Write-Information -InformationAction Continue -MessageData "MSAL auto-install exited with code $LASTEXITCODE."
      }
    } catch {
      Write-Information -InformationAction Continue -MessageData "MSAL auto-install failed: $($_.Exception.Message)"
    }
  } else {
    Write-Information -InformationAction Continue -MessageData 'MSAL auto-install skipped: npm not found in PATH.'
  }

  $npmRoot = $null
  try {
    $npmRoot = (& $npmCmd.Source root --prefix $PSScriptRoot 2>$null | Select-Object -First 1)
  } catch { $npmRoot = $null }
  if (-not [string]::IsNullOrWhiteSpace($npmRoot)) {
    Write-Information -InformationAction Continue -MessageData "npm root (local): $npmRoot"
  }
  if (-not [string]::IsNullOrWhiteSpace($npmRoot)) {
    $msalNodePath = Join-Path -Path $npmRoot -ChildPath '@azure\msal-browser\lib\msal-browser.min.js'
  } else {
    $msalNodePath = Join-Path -Path $PSScriptRoot -ChildPath 'node_modules\@azure\msal-browser\lib\msal-browser.min.js'
  }

  $npmGlobalRoot = $null
  try {
    $npmGlobalRoot = (& $npmCmd.Source root -g 2>$null | Select-Object -First 1)
  } catch { $npmGlobalRoot = $null }
  if (-not [string]::IsNullOrWhiteSpace($npmGlobalRoot)) {
    Write-Information -InformationAction Continue -MessageData "npm root (global): $npmGlobalRoot"
  }

  if (Test-Path -LiteralPath $msalNodePath) {
    $msalLocalPath = [System.IO.Path]::GetFullPath($msalNodePath)
  } else {
    $globalCandidate = if ($npmGlobalRoot) { Join-Path -Path $npmGlobalRoot -ChildPath '@azure\msal-browser\lib\msal-browser.min.js' } else { $null }
    if ($globalCandidate -and (Test-Path -LiteralPath $globalCandidate)) {
      $msalLocalPath = [System.IO.Path]::GetFullPath($globalCandidate)
    } else {
      Write-Information -InformationAction Continue -MessageData "MSAL bundle not found after npm install. Expected at: $msalNodePath"
    }
  }
}

if (Test-Path -LiteralPath $msalLocalPath) {
  Write-Information -InformationAction Continue -MessageData "MSAL local script detected at: $msalLocalPath"
} else {
  Write-Information -InformationAction Continue -MessageData "MSAL local script not found at: $msalLocalPath"
}

if ([string]::IsNullOrWhiteSpace($entraClientId)) {
  Write-Information -InformationAction Continue -MessageData 'ACS_ENTRA_CLIENT_ID not detected. Microsoft sign-in will be disabled.'
} else {
  Write-Information -InformationAction Continue -MessageData "ACS_ENTRA_CLIENT_ID detected"
}

if ([string]::IsNullOrWhiteSpace($entraTenantId)) {
  Write-Information -InformationAction Continue -MessageData 'ACS_ENTRA_TENANT_ID not set. Using organizations authority.'
} else {
  Write-Information -InformationAction Continue -MessageData "ACS_ENTRA_TENANT_ID detected"
}

# ------------------- MAIN LOOP -------------------
# Request handling uses a RunspacePool to process multiple HTTP requests concurrently.
# This keeps the UI responsive while DNS lookups are in flight.

$maxConcurrentRequests = 64

# Per-domain throttling: only one lookup per domain at a time.
# This prevents a single browser from hammering DNS (e.g., repeated refreshes) for the same domain.

$domainLocks = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Threading.SemaphoreSlim]]::new([System.StringComparer]::OrdinalIgnoreCase)

$functionNames = @(
  'Set-SecurityHeaders','Write-Json','Write-Html','Write-FileResponse',
  'New-AnonSessionId','Get-RequestCookies','Get-OrCreate-AnonymousSessionId',
  'Get-HashedDomain',
  'Get-AnonymousMetricsPersistPath','Load-AnonymousMetricsPersisted','Save-AnonymousMetricsPersisted',
  'Update-AnonymousMetrics','Get-AnonymousMetricsSnapshot',
  'Get-RegistrableDomain',
  'Resolve-DohName','ResolveSafely','Get-DnsIpString','ConvertTo-NormalizedDomain','Test-DomainName','Write-RequestLog',
  'Get-ClientIp','Get-ApiKeyFromRequest','Test-ApiKey','Test-RateLimit',
  'Get-DnsBaseStatus','Get-DnsMxStatus','Get-DnsDmarcStatus','Get-DnsDkimStatus','Get-CnameTargetFromRecords','Get-DnsCnameStatus','Invoke-RblLookup','ConvertTo-ReversedIpv4','Get-DnsReputationStatus',
  'Get-RblCacheEntry','Set-RblCacheEntry',
  'Get-RdapBootstrapData','Get-RdapBaseUrlForDomain','Invoke-RdapLookup','Invoke-WhoisXmlLookup','Invoke-GoDaddyWhoisLookup','ConvertTo-NullableUtcIso8601','Get-DomainAgeDays','Get-DomainRegistrationStatus',
  'Invoke-SysinternalsWhoisLookup','Invoke-LinuxWhoisLookup','Get-DomainAgeParts','Format-DomainAge','Get-TimeUntilParts','Format-ExpiryRemaining',
  'Get-AcsDnsStatus'
)

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

# Provide a stable flag inside handler runspaces.
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsAnonMetricsEnabled', $anonMetricsEnabled, 'Anonymous metrics enabled flag'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('MetricsHashKey', $MetricsHashKey, 'Hash key used for anonymous domain hashing'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('GoDaddyApiKey', $script:GoDaddyApiKey, 'GoDaddy API key'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('GoDaddyApiSecret', $script:GoDaddyApiSecret, 'GoDaddy API secret'))

# Share the global metrics objects with handler runspaces (must be added before pool creation).
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsMetrics', $global:AcsMetrics, 'Shared metrics object'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsMetricsPersistLock', $global:AcsMetricsPersistLock, 'Shared metrics persist lock'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsUptime', $global:AcsUptime, 'Shared uptime stopwatch'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsRateLimitStore', $global:AcsRateLimitStore, 'Shared rate limit store'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsRateLimitLock', $global:AcsRateLimitLock, 'Shared rate limit lock'))

foreach ($name in $functionNames) {
  # Copy function *definitions* into the runspace pool so handler runspaces can call them.
  $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
  if (-not $cmd -and $name -eq 'Invoke-LinuxWhoisLookup') {
    # Define a no-op placeholder for Windows hosts where Invoke-LinuxWhoisLookup isn't defined/needed.
    function Invoke-LinuxWhoisLookup { param([string]$Domain,[string]$WhoisPath,[int]$TimeoutSec = 25,[switch]$ThrowOnError) return $null }
    $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
  }
  if (-not $cmd) { continue }
  $def = $cmd.Definition
  $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $def))
}

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxConcurrentRequests, $iss, $Host)
$pool.Open()

$inflight = New-Object System.Collections.Generic.List[object]

function Invoke-InflightCleanup {
  # Reap completed async PowerShell invocations to avoid unbounded memory growth.
  for ($i = $inflight.Count - 1; $i -ge 0; $i--) {
    $item = $inflight[$i]
    if ($item.Async.IsCompleted) {
      try { $item.Ps.EndInvoke($item.Async) } catch { $null = $_ }
      $item.Ps.Dispose()
      $inflight.RemoveAt($i)
    }
  }
}

$handlerScript = @'
param($ctx, $htmlPage, $domainLocks, $msalLocalPath)

# TcpListener shim may not always provide a fully populated Url object.
$path = $null
try { if ($ctx -and $ctx.Request -and $ctx.Request.Url) { $path = $ctx.Request.Url.AbsolutePath } } catch { $path = $null }
if ([string]::IsNullOrWhiteSpace($path)) {
  try {
    $raw = $null
    try { if ($ctx -and $ctx.Request -and $ctx.Request.Url) { $raw = [string]$ctx.Request.Url } } catch { $raw = $null }
    if ([string]::IsNullOrWhiteSpace($raw)) {
      # Some shims expose only a raw target string
      try { if ($ctx -and $ctx.Request -and $ctx.Request.RawUrl) { $raw = [string]$ctx.Request.RawUrl } } catch { $raw = $null }
    }
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
      if ($raw.StartsWith('/')) {
        # Raw targets like "/api/metrics?x=y" are not absolute URIs
        $qIdx = $raw.IndexOf('?')
        $path = if ($qIdx -ge 0) { $raw.Substring(0, $qIdx) } else { $raw }
      } else {
        $u = [uri]$raw
        $path = $u.AbsolutePath
      }
    }
  } catch { $path = $null }
}
if ([string]::IsNullOrWhiteSpace($path)) { $path = '/' }

# This script block runs inside the RunspacePool for each incoming request.
# Inputs:
# - $ctx         : the request/response context (HttpListenerContext or TcpListener shim)
# - $htmlPage    : the embedded SPA HTML (string)
# - $domainLocks : shared dictionary of per-domain semaphores

function Get-DomainSemaphore([string]$domain) {
  # Get/create a per-domain semaphore so concurrent requests for the same domain serialize.
  $sem = $null
  if (-not $domainLocks.TryGetValue($domain, [ref]$sem)) {
    $newSem = [System.Threading.SemaphoreSlim]::new(1, 1)
    if ($domainLocks.TryAdd($domain, $newSem)) {
      $sem = $newSem
    } else {
      $null = $domainLocks.TryGetValue($domain, [ref]$sem)
    }
  }
  return $sem
}

try {
# Anonymous metrics: create / track an anonymous session id via cookie (no PII).
$metricsEnabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled)
if ($metricsEnabled) {
  $null = Get-OrCreate-AnonymousSessionId -Context $ctx
}

  # 1) Serve the UI
  if ($path -eq "/" -or $path -eq "/index.html") {
    $nonceBytes = [byte[]]::new(16)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      $rng.GetBytes($nonceBytes)
    } finally {
      try { $rng.Dispose() } catch { }
    }
    $nonce = [Convert]::ToBase64String($nonceBytes)
    Write-Html -Context $ctx -Html $htmlPage -Nonce $nonce
    return
  }

  # 1a) Serve local MSAL bundle (optional)
  if ($path -eq "/assets/msal-browser.min.js") {
    Write-FileResponse -Context $ctx -Path $msalLocalPath -ContentType 'application/javascript'
    return
  }

  # 1b) Metrics endpoint handled by caller (fast-path in main loop). Keep here as safety net only.
  if ($path -eq "/api/metrics") {
    Handle-MetricsRequest -Context $ctx -MetricsEnabled $metricsEnabled
    return
  }

  # 2) Serve individual API endpoints (/api/*)
  if ($path -in @("/api/base","/api/mx","/api/whois","/api/dmarc","/api/dkim","/api/cname","/api/reputation")) {
    if (-not (Test-ApiKey -Context $ctx)) {
      Write-Json -Context $ctx -Object @{ error = 'Missing or invalid API key.' } -StatusCode 401
      return
    }

    $rate = Test-RateLimit -Context $ctx
    if (-not $rate.allowed) {
      try {
        if ($ctx.Response -is [System.Net.HttpListenerResponse] -and $rate.retryAfterSec) {
          $ctx.Response.Headers['Retry-After'] = [string]$rate.retryAfterSec
        }
      } catch { }
      Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $rate.retryAfterSec } -StatusCode 429
      return
    }

    $domainRaw = $null
    try { if ($ctx -and $ctx.Request -and $ctx.Request.QueryString) { $domainRaw = $ctx.Request.QueryString["domain"] } } catch { $domainRaw = $null }
    $domain    = ConvertTo-NormalizedDomain $domainRaw

    Write-RequestLog -Context $ctx -Action "API $path" -Domain $domain

    if ([string]::IsNullOrWhiteSpace($domain)) {
      Write-Json -Context $ctx -Object @{ error = "Missing domain parameter." } -StatusCode 400
      return
    }
    if (-not (Test-DomainName -Domain $domain)) {
      Write-Json -Context $ctx -Object @{ error = "Invalid domain parameter." } -StatusCode 400
      return
    }

    # Serialize work for this domain, do the lookup, then release.
    $sem = Get-DomainSemaphore -domain $domain
    $null = $sem.Wait()
    try {
      switch ($path) {
        "/api/base"  {
          if ($metricsEnabled) { Update-AnonymousMetrics -Domain $domain -Started }
          Write-Json -Context $ctx -Object (Get-DnsBaseStatus  -Domain $domain)
          if ($metricsEnabled) { Update-AnonymousMetrics -Domain $domain -Completed }
        }
        "/api/mx"    { Write-Json -Context $ctx -Object (Get-DnsMxStatus    -Domain $domain) }
        "/api/whois" { Write-Json -Context $ctx -Object (Get-DomainRegistrationStatus -Domain $domain) }
        "/api/dmarc" { Write-Json -Context $ctx -Object (Get-DnsDmarcStatus -Domain $domain) }
        "/api/dkim"  { Write-Json -Context $ctx -Object (Get-DnsDkimStatus  -Domain $domain) }
        "/api/cname" { Write-Json -Context $ctx -Object (Get-DnsCnameStatus -Domain $domain) }
        "/api/reputation" { Write-Json -Context $ctx -Object (Get-DnsReputationStatus -Domain $domain) }
        default       { Write-Json -Context $ctx -Object @{ error = "Unknown endpoint." } -StatusCode 404 }
      }
    }
    finally {
      try { $null = $sem.Release() } catch {}
    }
    return
  }

  # 2b) Microsoft Entra ID authentication verification endpoint
  if ($path -eq '/api/auth/verify') {
    # Validate the Bearer token by calling Microsoft Graph /me endpoint.
    # This ensures the token is valid and lets us check the user's domain.
    $authHeader = $null
    try {
      if ($ctx.Request -is [System.Net.HttpListenerRequest]) {
        $authHeader = [string]$ctx.Request.Headers['Authorization']
      } elseif ($ctx.Request.Headers) {
        if ($ctx.Request.Headers.ContainsKey('Authorization')) { $authHeader = [string]$ctx.Request.Headers['Authorization'] }
        elseif ($ctx.Request.Headers.ContainsKey('authorization')) { $authHeader = [string]$ctx.Request.Headers['authorization'] }
      }
    } catch { $authHeader = $null }

    if ([string]::IsNullOrWhiteSpace($authHeader) -or -not $authHeader.StartsWith('Bearer ', [System.StringComparison]::OrdinalIgnoreCase)) {
      Write-Json -Context $ctx -Object @{ error = 'Missing or invalid Authorization header. Expected: Bearer <token>' } -StatusCode 401
      return
    }

    $accessToken = $authHeader.Substring(7).Trim()
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
      Write-Json -Context $ctx -Object @{ error = 'Empty access token.' } -StatusCode 401
      return
    }

    # Validate JWT audience claim before forwarding the token anywhere.
    # NOTE: The UI acquires a Microsoft Graph access token (scope: User.Read) to validate the user via /me.
    # That means the token audience (aud) is typically Microsoft Graph, not this SPA's client id.
    # We allow:
    # - Microsoft Graph (00000003-0000-0000-c000-000000000000)
    # - this app's client id (ACS_ENTRA_CLIENT_ID)
    try {
      $expectedClientId = $env:ACS_ENTRA_CLIENT_ID
      if (-not [string]::IsNullOrWhiteSpace($expectedClientId)) {
        $jwtParts = $accessToken.Split('.')
        if ($jwtParts.Count -ge 2) {
          $payloadBase64 = $jwtParts[1]
          # Base64url decode (JWT uses '-' '_' and may omit padding)
          $payloadBase64 = $payloadBase64.Replace('-', '+').Replace('_', '/')
          switch ($payloadBase64.Length % 4) {
            0 { }
            2 { $payloadBase64 += '==' }
            3 { $payloadBase64 += '=' }
            default { throw 'Malformed JWT payload (invalid base64 length).' }
          }
          $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadBase64))
          $payload = $payloadJson | ConvertFrom-Json -ErrorAction Stop
          $graphAud = '00000003-0000-0000-c000-000000000000'

          # JWT aud can be a string or an array
          $audValues = @()
          try {
            if ($null -eq $payload.aud) {
              $audValues = @()
            }
            elseif ($payload.aud -is [System.Array]) {
              $audValues = @($payload.aud | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            else {
              $audValues = @([string]$payload.aud)
            }
          } catch {
            $audValues = @()
          }

          $audOk = $false
          foreach ($a in $audValues) {
            if ([string]::Equals($a, $expectedClientId, [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals($a, $graphAud, [System.StringComparison]::OrdinalIgnoreCase)) {
              $audOk = $true
              break
            }
          }

          if (-not $audOk) {
            Write-Json -Context $ctx -Object @{ error = 'Token audience mismatch. Expected token for Microsoft Graph or this application.'; authenticated = $false; tokenAudiences = $audValues } -StatusCode 401
            return
          }
        } else {
          Write-Json -Context $ctx -Object @{ error = 'Malformed JWT token.'; authenticated = $false } -StatusCode 401
          return
        }
      }
    } catch {
      Write-Json -Context $ctx -Object @{ error = "Token audience validation failed: $($_.Exception.Message)"; authenticated = $false } -StatusCode 401
      return
    }

    try {
      # Call Microsoft Graph /me to validate the token and get user info.
      # This is the most secure server-side validation approach for SPAs:
      # - The token is validated by Microsoft's own infrastructure
      # - We get verified user claims (email, tenant, display name)
      # - No need to manually validate JWT signatures/keys
      $graphHeaders = @{ Authorization = "Bearer $accessToken"; 'Content-Type' = 'application/json' }
      $graphResp = Invoke-RestMethod -Method Get -Uri 'https://graph.microsoft.com/v1.0/me' -Headers $graphHeaders -TimeoutSec 15 -ErrorAction Stop

      $userPrincipalName = [string]$graphResp.userPrincipalName
      $mail = [string]$graphResp.mail
      $displayName = [string]$graphResp.displayName
      $id = [string]$graphResp.id

      # Determine if this is a Microsoft employee:
      # Check both UPN and mail for @microsoft.com domain
      $isMsEmployee = $false
      $emailDomain = $null

      if (-not [string]::IsNullOrWhiteSpace($userPrincipalName)) {
        $atIdx = $userPrincipalName.LastIndexOf('@')
        if ($atIdx -ge 0) {
          $emailDomain = $userPrincipalName.Substring($atIdx + 1).Trim().ToLowerInvariant()
          if ($emailDomain -eq 'microsoft.com') { $isMsEmployee = $true }
        }
      }

      if (-not $isMsEmployee -and -not [string]::IsNullOrWhiteSpace($mail)) {
        $atIdx2 = $mail.LastIndexOf('@')
        if ($atIdx2 -ge 0) {
          $mailDomain = $mail.Substring($atIdx2 + 1).Trim().ToLowerInvariant()
          if ($mailDomain -eq 'microsoft.com') { $isMsEmployee = $true }
          if (-not $emailDomain) { $emailDomain = $mailDomain }
        }
      }

      # Anonymous metrics: count successful auth verifications (no PII stored).

      try {
        if ($metricsEnabled -and $isMsEmployee -and $id) {
          # Hash the AAD object ID (id) and store in the hash sets
          $hash = $null
          try {
            $key = $MetricsHashKey
            if ([string]::IsNullOrWhiteSpace($key)) { $key = $env:ACS_METRICS_HASH_KEY }
            if (-not [string]::IsNullOrWhiteSpace($key)) {
              $keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
              $dataBytes = [Text.Encoding]::UTF8.GetBytes($id)
              $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
              try {
                $hash = [Convert]::ToBase64String($hmac.ComputeHash($dataBytes))
              } finally { try { $hmac.Dispose() } catch { } }
            }
          } catch { $hash = $null }
          if ($hash) {
            $addedSession = $script:AcsMetrics['msEmployeeIdHashes'].TryAdd($hash, 0)
            $addedLifetime = $script:AcsMetrics['lifetimeMsEmployeeIdHashes'].TryAdd($hash, 0)
            if ($addedSession -or $addedLifetime) {
              [System.Threading.Interlocked]::Increment($script:AcsMetrics['lifetimeMsAuthVerifications']) | Out-Null
              Save-AnonymousMetricsPersisted
            }
          }
        }
      } catch { $null = $_ }

      Write-Json -Context $ctx -Object ([pscustomobject]@{
        authenticated = $true
        isMicrosoftEmployee = $isMsEmployee
        displayName = $displayName
        emailDomain = $emailDomain
        userId = $id
      })
    }
    catch {
      $errMsg = $_.Exception.Message
      $statusCode = 401

      # Try to extract HTTP status from WebException
      try {
        if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
          $httpStatus = [int]$_.Exception.Response.StatusCode
          if ($httpStatus -ge 400) { $statusCode = $httpStatus }
        }
      } catch { }

      Write-Json -Context $ctx -Object @{ error = "Token validation failed: $errMsg"; authenticated = $false } -StatusCode $statusCode
    }
    return
  }

  # 3) Serve the aggregated endpoint used by the UI (/dns)
  if ($path -eq "/dns") {
    if (-not (Test-ApiKey -Context $ctx)) {
      Write-Json -Context $ctx -Object @{ error = 'Missing or invalid API key.'; acsReady = $false } -StatusCode 401
      return
    }

    $rate = Test-RateLimit -Context $ctx
    if (-not $rate.allowed) {
      try {
        if ($ctx.Response -is [System.Net.HttpListenerResponse] -and $rate.retryAfterSec) {
          $ctx.Response.Headers['Retry-After'] = [string]$rate.retryAfterSec
        }
      } catch { }
      Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $rate.retryAfterSec; acsReady = $false } -StatusCode 429
      return
    }

    $domainRaw = $null
    try { if ($ctx -and $ctx.Request -and $ctx.Request.QueryString) { $domainRaw = $ctx.Request.QueryString["domain"] } } catch { $domainRaw = $null }
    $domain    = ConvertTo-NormalizedDomain $domainRaw

    Write-RequestLog -Context $ctx -Action "DNS Lookup" -Domain $domain

    if ([string]::IsNullOrWhiteSpace($domain)) {
      Write-Json -Context $ctx -Object @{ error = "Missing domain parameter."; acsReady = $false } -StatusCode 400
      return
    }
    if (-not (Test-DomainName -Domain $domain)) {
      Write-Json -Context $ctx -Object @{ error = "Invalid domain parameter."; acsReady = $false } -StatusCode 400
      return
    }

    # Serialize work for this domain, do the lookup, then release.
    $sem = Get-DomainSemaphore -domain $domain
    $null = $sem.Wait()
    try {
      $result = Get-AcsDnsStatus -Domain $domain
      Write-Json -Context $ctx -Object $result
    }
    finally {
      try { $null = $sem.Release() } catch {}
    }
    return
  }

  if ($ctx -and $ctx.Response) {
    $ctx.Response.StatusCode = 404
    $ctx.Response.StatusDescription = "Not Found"
    $ctx.Response.Close()
  }
}
catch {
  # Last-resort error handler: attempt to return a JSON error payload.
  try { Write-Json -Context $ctx -Object @{ error = $_.Exception.Message } -StatusCode 500 } catch {}
  try { if ($ctx -and $ctx.Response) { $ctx.Response.Close() } } catch {}
}
'@

try {
  function ConvertFrom-QueryString {
    param([string]$Query)
    # Minimal query-string parser used by the TcpListener fallback.
    $nvc = [System.Collections.Specialized.NameValueCollection]::new()
    if ([string]::IsNullOrWhiteSpace($Query)) { return $nvc }
    $q = $Query.TrimStart('?')
    if ([string]::IsNullOrWhiteSpace($q)) { return $nvc }
    foreach ($pair in ($q -split '&')) {
      if ([string]::IsNullOrWhiteSpace($pair)) { continue }
      $kv = $pair -split '=', 2
      $k = ($kv[0] -replace '\+',' ')
      $k = [uri]::UnescapeDataString($k)
      $v = ''
      if ($kv.Count -gt 1) {
        $v = ($kv[1] -replace '\+',' ')
        $v = [uri]::UnescapeDataString($v)
      }
      $nvc.Add($k, $v)
    }
    return $nvc
  }

  function New-TcpContext {
    param(
      [Parameter(Mandatory = $true)]
      [System.Net.Sockets.TcpClient]$Client,
      [Parameter(Mandatory = $true)]
      [string]$RawTarget,
      [Parameter(Mandatory = $true)]
      [hashtable]$Headers
    )

    $remote = $Client.Client.RemoteEndPoint
    $ua = if ($Headers.ContainsKey('user-agent')) { [string]$Headers['user-agent'] } else { $null }

    $pathOnly = $RawTarget
    $query = ''
    $qm = $RawTarget.IndexOf('?')
    if ($qm -ge 0) {
      $pathOnly = $RawTarget.Substring(0, $qm)
      $query = $RawTarget.Substring($qm)
    }

    $url = [uri]::new("http://localhost:$Port$pathOnly$query")
    $qs = ConvertFrom-QueryString -Query $query

    $networkStream = $Client.GetStream()

    # TcpListener fallback response object.
    # It exposes a subset of `HttpListenerResponse`-like properties and a `SendBody()` method.
    $resp = [pscustomobject]@{
      StatusCode = 200
      StatusDescription = 'OK'
      ContentType = 'text/plain; charset=utf-8'
      ContentLength64 = [int64]0
      _client = $Client
      _stream = $networkStream
      _sent = $false
    }

    $resp | Add-Member -MemberType ScriptMethod -Name SendBody -Value {
      param([byte[]]$Bytes)
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }

      $statusText = if ([string]::IsNullOrWhiteSpace($this.StatusDescription)) { 'OK' } else { $this.StatusDescription }
      $headers = "HTTP/1.1 {0} {1}\r\nContent-Type: {2}\r\nContent-Length: {3}\r\nConnection: close\r\n\r\n" -f $this.StatusCode, $statusText, $this.ContentType, $Bytes.Length
      $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)

      try {
        $this._stream.Write($headerBytes, 0, $headerBytes.Length)
        if ($Bytes.Length -gt 0) {
          $this._stream.Write($Bytes, 0, $Bytes.Length)
        }
        $this._stream.Flush()
      } finally {
        $this._sent = $true
        try { $this._stream.Dispose() } catch { }
        try { $this._client.Close() } catch { }
      }
    } | Out-Null

    $resp | Add-Member -MemberType ScriptMethod -Name Close -Value {
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }
      $this.SendBody([byte[]]@())
    } | Out-Null

    $req = [pscustomobject]@{
      Url = $url
      QueryString = $qs
      UserAgent = $ua
      RemoteEndPoint = $remote
    }

    return [pscustomobject]@{ Request = $req; Response = $resp }
  }

  function Read-TcpHttpRequest {
    param(
      [Parameter(Mandatory = $true)]
      [System.Net.Sockets.TcpClient]$Client
    )

    # Extremely small HTTP/1.1 request reader (GET only).
    # We only need the request line + headers to route GET requests and read query strings.
    $stream = $Client.GetStream()
    $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 8192, $true)
    $line1 = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line1)) { return $null }

    $parts = $line1 -split '\s+'
    if ($parts.Count -lt 2) { return $null }

    $method = $parts[0].Trim().ToUpperInvariant()
    $target = $parts[1].Trim()

    $headers = @{}
    while ($true) {
      $line = $reader.ReadLine()
      if ($null -eq $line) { break }
      if ($line -eq '') { break }
      $idx = $line.IndexOf(':')
      if ($idx -le 0) { continue }
      $hName = $line.Substring(0, $idx).Trim().ToLowerInvariant()
      $hValue = $line.Substring($idx + 1).Trim()
      $headers[$hName] = $hValue
    }

    return [pscustomobject]@{ Method = $method; Target = $target; Headers = $headers }
  }

  if ($serverMode -eq 'HttpListener') {
    # Primary server mode: HttpListener (best supported on Windows).
    while ($listener.IsListening) {
      try {
        $ctx = $listener.GetContext()

        # Handle CORS preflight (OPTIONS) requests inline to avoid RunspacePool overhead.
        try {
          if ($ctx.Request.HttpMethod -eq 'OPTIONS') {
            Set-SecurityHeaders -Context $ctx
            $ctx.Response.StatusCode = 204
            $ctx.Response.ContentLength64 = 0
            $ctx.Response.Close()
            continue
          }
        } catch { }

        # Fast-path metrics to avoid runspace contention during lookups.
        try { $absPath = $ctx.Request.Url.AbsolutePath } catch { $absPath = $null }
        if ($absPath -and ($absPath.TrimEnd('/') -ieq '/api/metrics')) {
          # Respond inline (fast and avoids ThreadPool runspace issues).
          Handle-MetricsRequest -Context $ctx -MetricsEnabled $anonMetricsEnabled
          continue
        }

        # Run the handler in the RunspacePool so multiple requests can be processed concurrently.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath)

        $async = $ps.BeginInvoke()
        $inflight.Add([pscustomobject]@{ Ps = $ps; Async = $async })

        Invoke-InflightCleanup
      }
      catch [System.Net.HttpListenerException] {
        Write-Error -Message "HttpListenerException: $($_.Exception.Message)" -ErrorAction Continue
        break
      }
      catch {
        Write-Error -Message "HttpListener loop error: $($_.Exception.Message)" -ErrorAction Continue
        break
      }
    }
  }
  elseif ($serverMode -eq 'TcpListener' -and $tcpListener) {
    # Fallback server mode: TcpListener (for platforms where HttpListener is unavailable).
    # Only GET is supported here; it's enough for the SPA + JSON endpoints.
    while ($true) {
      $client = $tcpListener.AcceptTcpClient()
      if ($null -eq $client) { continue }

      $req = $null
      try {
        $req = Read-TcpHttpRequest -Client $client
        if ($null -eq $req) {
          try { $client.Close() } catch { }
          continue
        }

        if ($req.Method -ne 'GET' -and $req.Method -ne 'POST') {
          $ctx = New-TcpContext -Client $client -RawTarget ($req.Target) -Headers $req.Headers
          $ctx.Response.StatusCode = 405
          $ctx.Response.StatusDescription = 'Method Not Allowed'
          $ctx.Response.ContentType = 'text/plain; charset=utf-8'
          $ctx.Response.SendBody([Text.Encoding]::UTF8.GetBytes('Method Not Allowed'))
          continue
        }

        $ctx = New-TcpContext -Client $client -RawTarget ($req.Target) -Headers $req.Headers

        # Fast-path metrics for TcpListener fallback as well.
        try { $absPath = $ctx.Request.Url.AbsolutePath } catch { $absPath = $null }
        if ($absPath -and ($absPath.TrimEnd('/') -ieq '/api/metrics')) {
          Handle-MetricsRequest -Context $ctx -MetricsEnabled $anonMetricsEnabled
          continue
        }

        # Run the same handler script used by HttpListener.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath)

        $async = $ps.BeginInvoke()
        $inflight.Add([pscustomobject]@{ Ps = $ps; Async = $async })

        Invoke-InflightCleanup
      }
      catch [System.Net.Sockets.SocketException] {
        Write-Error -Message "TcpListener SocketException: $($_.Exception.Message)" -ErrorAction Continue
        try { $client.Close() } catch { }
      }
      catch {
        Write-Error -Message "TcpListener loop error: $($_.Exception.Message)" -ErrorAction Continue
        try { $client.Close() } catch { }
      }
    }
  }
  else {
    Write-Error -Message "Server did not start. HttpListener unavailable and TcpListener could not be initialized." -ErrorAction Continue
  }
}
catch {
  Write-Error -ErrorRecord $_
}
finally {
  # Graceful shutdown: stop listeners and dispose runspaces.
  try { if ($listener -and $listener.IsListening) { $listener.Stop() } } catch { $null = $_ }
  try { if ($tcpListener) { $tcpListener.Stop() } } catch { $null = $_ }

  # Persist metrics one last time.
  try { Save-AnonymousMetricsPersisted -Force } catch { $null = $_ }

  Invoke-InflightCleanup
  foreach ($item in @($inflight)) {
    if ($item -and $item.PSObject.Properties['Ps']) {
      try { $item.Ps.Dispose() } catch { $null = $_ }
    }
  }
  try { $pool.Close(); $pool.Dispose() } catch { $null = $_ }
  Write-Information -InformationAction Continue -MessageData "Server stopped."
}
