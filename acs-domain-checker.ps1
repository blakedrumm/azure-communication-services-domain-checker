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

# ===== Domain Parsing Utilities =====
# ------------------- DOMAIN PARSING UTILITIES -------------------
# Heuristic: derive a registrable ("pay-level") domain from an arbitrary subdomain.
# Uses a small hardcoded subset of the Public Suffix List (PSL) to handle common
# two-level TLDs like co.uk, com.au, etc.  Falls back to the last two labels.
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

# Walk up the label hierarchy of a domain and return all parent domains.
# For example, "sub.example.co.uk" returns @("example.co.uk", "co.uk").
# Used for fallback DNS lookups when the exact subdomain has no records.
function Get-ParentDomains {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return @() }

  $d = ([string]$Domain).Trim().Trim('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return @() }

  $labels = $d.Split('.')
  if ($labels.Count -lt 3) { return @() }

  $parents = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -lt ($labels.Count - 1); $i++) {
    $candidate = ($labels[$i..($labels.Count - 1)] -join '.').ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
      $parents.Add($candidate)
    }
  }

  return @($parents | Select-Object -Unique)
}

# ------------------- WHOIS / RDAP LOOKUP PROVIDERS -------------------
# These functions attempt to retrieve domain registration data (creation date, expiry,
# registrar, registrant) from multiple sources. The fallback chain is:
#   1. RDAP (IANA bootstrap) - preferred, structured JSON
#   2. GoDaddy API           - if credentials are configured
#   3. Linux whois CLI       - on Linux platforms
#   4. Sysinternals whois    - on Windows platforms
#   5. Pure TCP whois        - cross-platform fallback (bypasses CLI issues in containers)
#   6. WhoisXML API          - if API key is configured

# Quick check: does the raw whois text contain actual registration data,
# or is it an error/"not found" response from the whois server?
# ===== WHOIS Lookup Providers =====
function Test-WhoisRawTextHasUsableData {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  if ($Text -match '(?im)\b(No Data Found|No match for|NOT FOUND|Status:\s*AVAILABLE|Malformed request\.?|Invalid query|Invalid domain name|This query returned 0 objects)\b') {
    return $false
  }

  if ($Text -match '(?im)\b(getaddrinfo\(|Name or service not known|Temporary failure in name resolution|Connection timed out|Network is unreachable|No route to host|Connection refused|Servname not supported for ai_socktype|socket error|connect\s+failed|No such host is known|The remote name could not be resolved|Unable to connect)\b') {
    return $false
  }

  return $true
}

# Windows-only WHOIS lookup using the Sysinternals whois.exe tool.
# Launches whois.exe as a child process, captures stdout/stderr, and parses
# registration fields (creation date, expiry, registrar, registrant) from the raw output.
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

  $p = $null

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
  finally {
    try { if ($p) { $p.Dispose() } } catch { }
  }
}

# Linux WHOIS lookup using the system `whois` CLI binary.
# Tries the default whois server first, then cycles through TLD-specific fallback servers
# (e.g., whois.verisign-grs.com for .com/.net) if the initial query returns no useful data.
function Invoke-LinuxWhoisLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$WhoisPath,

    [int]$TimeoutSec = 25,

    [switch]$ThrowOnError
  )

  # Inner helper: execute a single whois query against a specific server.
  function Invoke-LinuxWhoisQuery {
    param(
      [Parameter(Mandatory = $true)]
      [string]$Exe,

      [Parameter(Mandatory = $true)]
      [string]$LookupDomain,

      [string]$Server,

      [int]$ServerPort = 43,

      [int]$QueryTimeoutSec = 25
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Exe

    try {
      if ([string]::IsNullOrWhiteSpace($Server)) {
        $psi.ArgumentList.Add('--')
        $psi.ArgumentList.Add($LookupDomain)
      } else {
        $psi.ArgumentList.Add('-h')
        $psi.ArgumentList.Add($Server)
        if ($ServerPort -ne 43) {
          $psi.ArgumentList.Add('-p')
          $psi.ArgumentList.Add($ServerPort.ToString())
        }
        $psi.ArgumentList.Add('--')
        $psi.ArgumentList.Add($LookupDomain)
      }
    } catch {
      if ([string]::IsNullOrWhiteSpace($Server)) {
        $psi.Arguments = "-- `"$LookupDomain`""
      } else {
        if ($ServerPort -ne 43) {
          $psi.Arguments = "-h `"$Server`" -p $ServerPort -- `"$LookupDomain`""
        } else {
          $psi.Arguments = "-h `"$Server`" -- `"$LookupDomain`""
        }
      }
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
      throw 'Failed to start whois process.'
    }

    try {
      $out = $p.StandardOutput.ReadToEnd()
      $err = $p.StandardError.ReadToEnd()

      if (-not $p.WaitForExit($QueryTimeoutSec * 1000)) {
        try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
        throw "whois timed out after $QueryTimeoutSec seconds for '$LookupDomain'."
      }

      return [pscustomobject]@{
        text = (($out, $err) -join "`r`n").Trim()
        exitCode = $p.ExitCode
        server = $Server
        port = $ServerPort
      }
    }
    finally {
      try { $p.Dispose() } catch { }
    }
  }

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

  $serverList = New-Object System.Collections.Generic.List[string]
  $null = $serverList.Add($null)

  $envServerText = [string]$env:ACS_LINUX_WHOIS_SERVERS
  if (-not [string]::IsNullOrWhiteSpace($envServerText)) {
    foreach ($serverCandidate in @($envServerText -split '[,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      $normalizedServer = ([string]$serverCandidate).Trim()
      if (-not [string]::IsNullOrWhiteSpace($normalizedServer) -and -not $serverList.Contains($normalizedServer)) {
        $null = $serverList.Add($normalizedServer)
      }
    }
  }

  $defaultFallbackServers = @()
  switch -Regex ($d) {
    '(?i)\.com$|\.net$' { $defaultFallbackServers = @('whois.verisign-grs.com'); break }
    '(?i)\.org$'         { $defaultFallbackServers = @('whois.pir.org'); break }
    '(?i)\.info$'        { $defaultFallbackServers = @('whois.afilias.net'); break }
    '(?i)\.biz$'         { $defaultFallbackServers = @('whois.biz'); break }
    '(?i)\.io$'          { $defaultFallbackServers = @('whois.nic.io'); break }
    '(?i)\.ai$'          { $defaultFallbackServers = @('whois.nic.ai'); break }
    '(?i)\.app$|\.dev$' { $defaultFallbackServers = @('whois.nic.google'); break }
    '(?i)\.uk$|\.co\.uk$|\.org\.uk$|\.gov\.uk$|\.ac\.uk$' { $defaultFallbackServers = @('whois.nic.uk'); break }
    '(?i)\.de$'          { $defaultFallbackServers = @('whois.denic.de'); break }
    '(?i)\.fr$'          { $defaultFallbackServers = @('whois.nic.fr'); break }
    '(?i)\.au$|\.com\.au$|\.net\.au$|\.org\.au$' { $defaultFallbackServers = @('whois.auda.org.au'); break }
    '(?i)\.ca$'          { $defaultFallbackServers = @('whois.cira.ca'); break }
    '(?i)\.jp$|\.co\.jp$|\.ne\.jp$|\.or\.jp$' { $defaultFallbackServers = @('whois.jprs.jp'); break }
    '(?i)\.us$'          { $defaultFallbackServers = @('whois.nic.us', 'us.whois-servers.net'); break }
    '(?i)\.co$'          { $defaultFallbackServers = @('whois.registry.co'); break }
    '(?i)\.gov$'         { $defaultFallbackServers = @('whois.dotgov.gov'); break }
    '(?i)\.edu$'         { $defaultFallbackServers = @('whois.educause.edu'); break }
    '(?i)\.mil$'         { $defaultFallbackServers = @('whois.nic.mil'); break }
  }

  foreach ($defaultServer in $defaultFallbackServers) {
    if (-not [string]::IsNullOrWhiteSpace($defaultServer) -and -not $serverList.Contains($defaultServer)) {
      if (-not $serverList.Contains($defaultServer)) {
        $null = $serverList.Add($defaultServer)
      }
    }
  }

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
    $text = $null
    $exitCode = $null
    $usedServer = $null
    $lastQueryError = $null

    foreach ($server in $serverList) {
      try {
        $queryResult = Invoke-LinuxWhoisQuery -Exe $exe -LookupDomain $d -Server $server -ServerPort 43 -QueryTimeoutSec $TimeoutSec
        $exitCode = $queryResult.exitCode

        if (Test-WhoisRawTextHasUsableData -Text $queryResult.text) {
          $text = $queryResult.text
          $usedServer = $queryResult.server
          break
        }

        if (-not [string]::IsNullOrWhiteSpace($queryResult.text)) {
          $lastQueryError = ($queryResult.text -split "`r?`n" | Select-Object -First 1)
        }
      }
      catch {
        $lastQueryError = $_.Exception.Message
      }
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = if (-not [string]::IsNullOrWhiteSpace($lastQueryError)) {
        "whois failed for '$d'. $lastQueryError"
      } else {
        "whois returned no output for '$d'." + $(if ($null -ne $exitCode) { " ExitCode=$exitCode." } else { '' })
      }
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
      exitCode     = $exitCode
      whoisExe     = $exe
      whoisServer  = $usedServer
    }
  }
  catch {
    $innerMsg = $_.Exception.Message
    # Avoid double-wrapping errors that were explicitly thrown from the no-data path above
    $msg = if ($innerMsg -match '^whois (failed for|returned no output for)\b') { $innerMsg } else { "whois failed: $innerMsg" }
    if ($ThrowOnError) { throw $msg } else { return $null }
  }
}

function Invoke-TcpWhoisLookup {
  <#
  .SYNOPSIS
    Pure PowerShell TCP-based whois client that connects directly to port 43.
    Bypasses the Linux whois CLI getaddrinfo() service-name resolution issue
    ("Servname not supported for ai_socktype") that occurs in minimal Docker containers.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [int]$TimeoutSec = 15,

    [switch]$ThrowOnError
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  # Build server list based on TLD (same mapping as Invoke-LinuxWhoisLookup).
  $servers = New-Object System.Collections.Generic.List[string]

  switch -Regex ($d) {
    '(?i)\.com$|\.net$'                                     { $servers.Add('whois.verisign-grs.com'); break }
    '(?i)\.org$'                                            { $servers.Add('whois.pir.org'); break }
    '(?i)\.info$'                                           { $servers.Add('whois.afilias.net'); break }
    '(?i)\.biz$'                                            { $servers.Add('whois.biz'); break }
    '(?i)\.io$'                                             { $servers.Add('whois.nic.io'); break }
    '(?i)\.ai$'                                             { $servers.Add('whois.nic.ai'); break }
    '(?i)\.app$|\.dev$'                                     { $servers.Add('whois.nic.google'); break }
    '(?i)\.uk$|\.co\.uk$|\.org\.uk$|\.gov\.uk$|\.ac\.uk$'  { $servers.Add('whois.nic.uk'); break }
    '(?i)\.de$'                                             { $servers.Add('whois.denic.de'); break }
    '(?i)\.fr$'                                             { $servers.Add('whois.nic.fr'); break }
    '(?i)\.au$|\.com\.au$|\.net\.au$|\.org\.au$'            { $servers.Add('whois.auda.org.au'); break }
    '(?i)\.ca$'                                             { $servers.Add('whois.cira.ca'); break }
    '(?i)\.jp$|\.co\.jp$|\.ne\.jp$|\.or\.jp$'               { $servers.Add('whois.jprs.jp'); break }
    '(?i)\.us$'                                             { $servers.Add('whois.nic.us'); break }
    '(?i)\.co$'                                             { $servers.Add('whois.registry.co'); break }
    '(?i)\.gov$'                                            { $servers.Add('whois.dotgov.gov'); break }
    '(?i)\.edu$'                                            { $servers.Add('whois.educause.edu'); break }
    '(?i)\.mil$'                                            { $servers.Add('whois.nic.mil'); break }
  }

  # For TLDs not in the mapping, try IANA referral to discover the authoritative server.
  if ($servers.Count -eq 0) {
    $servers.Add('whois.iana.org')
  }

  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  $lastError = $null

  foreach ($server in $servers) {
    $tcpClient = $null
    try {
      $tcpClient = [System.Net.Sockets.TcpClient]::new()
      $connectTask = $tcpClient.ConnectAsync($server, 43)
      if (-not $connectTask.Wait($TimeoutSec * 1000)) {
        throw "TCP connection to ${server}:43 timed out after $TimeoutSec seconds."
      }
      if ($connectTask.IsFaulted) {
        throw $connectTask.Exception.InnerException
      }

      $stream = $tcpClient.GetStream()
      $stream.ReadTimeout  = $TimeoutSec * 1000
      $stream.WriteTimeout = $TimeoutSec * 1000

      $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
      $writer.AutoFlush = $true
      $writer.WriteLine($d)

      $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
      $text   = $reader.ReadToEnd()

      if ([string]::IsNullOrWhiteSpace($text)) { continue }

      # If IANA returned a referral, follow it with a recursive call using the referred server.
      if ($server -eq 'whois.iana.org' -and $text -match '(?im)^whois:\s*(.+)$') {
        $referralServer = $Matches[1].Trim()
        if (-not [string]::IsNullOrWhiteSpace($referralServer) -and $referralServer -ne 'whois.iana.org') {
          try { $reader.Dispose() } catch { }
          try { $writer.Dispose() } catch { }
          try { $stream.Dispose() } catch { }
          try { $tcpClient.Close() } catch { }
          try { $tcpClient.Dispose() } catch { }
          $tcpClient = $null

          # Query the referral server directly.
          $tcpClient = [System.Net.Sockets.TcpClient]::new()
          $refTask = $tcpClient.ConnectAsync($referralServer, 43)
          if (-not $refTask.Wait($TimeoutSec * 1000)) {
            throw "TCP connection to ${referralServer}:43 timed out after $TimeoutSec seconds."
          }
          if ($refTask.IsFaulted) { throw $refTask.Exception.InnerException }

          $stream = $tcpClient.GetStream()
          $stream.ReadTimeout  = $TimeoutSec * 1000
          $stream.WriteTimeout = $TimeoutSec * 1000
          $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
          $writer.AutoFlush = $true
          $writer.WriteLine($d)
          $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
          $text   = $reader.ReadToEnd()
          $server = $referralServer

          if ([string]::IsNullOrWhiteSpace($text)) { continue }
        }
      }

      # Skip responses that indicate no data or invalid queries / malformed subdomain lookups.
      if ($text -match '(?im)\b(No Data Found|No match for|NOT FOUND|Status:\s*AVAILABLE|Malformed request\.?|Invalid query|Invalid domain name|This query returned 0 objects)\b') { continue }

      # Parse registration fields (same patterns as Invoke-LinuxWhoisLookup).
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
          } else { $creation = $val }
          continue
        }

        if (-not $expiry -and $l -match '(?i)^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Registrar Registration Expiration date):\s*(.+)$') {
          $val = $Matches[2].Trim()
          if ($canConvertDates) {
            try { $expiry = ConvertTo-NullableUtcIso8601 $val } catch { $expiry = $val }
          } else { $expiry = $val }
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
        whoisServer  = $server
      }
    }
    catch {
      $lastError = $_.Exception.Message
    }
    finally {
      if ($tcpClient) {
        try { $tcpClient.Close() } catch { }
        try { $tcpClient.Dispose() } catch { }
      }
    }
  }

  $msg = if ($lastError) { "TCP whois failed for '$d'. $lastError" } else { "TCP whois returned no usable data for '$d'." }
  if ($ThrowOnError) { throw $msg } else { return $null }
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

# ===== Anonymous Metrics Hash Key & App Version =====
# ------------------- ANONYMOUS METRICS HASH KEY -------------------
# The hash key is used to HMAC-SHA256 domain names before storing them in metrics.
# This ensures no plaintext domain names are ever persisted, only irreversible hashes.
# The key is reused across restarts to keep unique-domain counts consistent.
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
$script:AppVersion = '2.0.0'
if (-not [string]::IsNullOrWhiteSpace($env:ACS_APP_VERSION)) {
  $script:AppVersion = $env:ACS_APP_VERSION
}

# Acquire a cross-process mutex to protect the metrics JSON file from concurrent writes.
# Tries multiple mutex naming strategies for compatibility across Windows, Linux, and containers.
# Returns the held mutex (caller must release), or $null if acquisition timed out.
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

# Compute an HMAC-SHA256 hash of a domain name using the metrics hash key.
# Returns a Base64 string. This is a one-way hash so the original domain cannot be recovered.
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

# Handle an incoming HTTP request to /api/metrics. Returns the current anonymous metrics snapshot.
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

# ===== RDAP / Whois API Lookup Providers =====
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

# Perform an RDAP (Registration Data Access Protocol) lookup for a domain.
# RDAP is the modern replacement for WHOIS and returns structured JSON data.
# Strategy:
#   1. Look up the authoritative RDAP server for the domain's TLD using the IANA bootstrap file.
#   2. If the authoritative lookup fails, fall back to rdap.org (a public RDAP proxy).
function Invoke-RdapLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [int]$TimeoutSec = 30,

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


# Query the WhoisXML API (a paid/freemium web service) for domain registration data.
# Requires the ACS_WHOISXML_API_KEY environment variable to be set.
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

# Query the GoDaddy domain API for registration data.
# Requires both GODADDY_API_KEY and GODADDY_API_SECRET environment variables.
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

# ------------------- DATE / AGE UTILITIES -------------------
# Try to parse a date string (from WHOIS/RDAP output) into a normalized UTC ISO 8601 format.
# Handles common timezone abbreviations (e.g., CLST, CLT) that .NET's parser often rejects.
# Returns $null if parsing fails entirely.
# ===== Date / Age Formatting Utilities =====
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

# Calculate the age of a domain in whole days from its creation date to now.
function Get-DomainAgeDays {
  param([string]$CreationDateUtc)

  if ([string]::IsNullOrWhiteSpace($CreationDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($CreationDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }
  $age = [DateTimeOffset]::UtcNow - $dto.ToUniversalTime()
  return [int][Math]::Floor($age.TotalDays)
}

# Break domain age into years, months, and days for human-friendly display.
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

# Format domain age as a human-readable string like "2 years, 3 months, 15 days".
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

# Break time until domain expiry into years, months, and days.
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

# Format time until expiry as a human-readable string, or return "Expired" if past due.
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
# ===== DMARC Security Guidance =====
function Get-DmarcSecurityGuidance {
  param(
    [string]$DmarcRecord,
    [string]$Domain,
    [string]$LookupDomain,
    [bool]$Inherited = $false
  )

  $messages = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($DmarcRecord)) { return @() }

  $recordText = ([string]$DmarcRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($recordText)) { return @() }

  $tagMap = @{}
  foreach ($segment in ($recordText -split ';')) {
    $part = ([string]$segment).Trim()
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $kv = $part -split '=', 2
    if ($kv.Count -ne 2) { continue }
    $name = ([string]$kv[0]).Trim().ToLowerInvariant()
    $value = ([string]$kv[1]).Trim()
    if (-not [string]::IsNullOrWhiteSpace($name)) {
      $tagMap[$name] = $value
    }
  }

  $targetDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } elseif (-not [string]::IsNullOrWhiteSpace($LookupDomain)) { $LookupDomain } else { 'the domain' }

  $policy = $null
  if ($tagMap.ContainsKey('p')) { $policy = ([string]$tagMap['p']).Trim().ToLowerInvariant() }
  $subdomainPolicy = $null
  if ($tagMap.ContainsKey('sp')) { $subdomainPolicy = ([string]$tagMap['sp']).Trim().ToLowerInvariant() }
  $pct = $null
  if ($tagMap.ContainsKey('pct')) {
    $pctValue = 0
    if ([int]::TryParse(([string]$tagMap['pct']).Trim(), [ref]$pctValue)) {
      $pct = $pctValue
    }
  }
  $adkim = if ($tagMap.ContainsKey('adkim')) { ([string]$tagMap['adkim']).Trim().ToLowerInvariant() } else { $null }
  $aspf = if ($tagMap.ContainsKey('aspf')) { ([string]$tagMap['aspf']).Trim().ToLowerInvariant() } else { $null }
  $rua = if ($tagMap.ContainsKey('rua')) { ([string]$tagMap['rua']).Trim() } else { $null }
  $ruf = if ($tagMap.ContainsKey('ruf')) { ([string]$tagMap['ruf']).Trim() } else { $null }

  if ($policy -eq 'none') {
    $messages.Add("DMARC for $targetDomain is monitor-only (`p=none`). For stronger protection against spoofing, move to enforcement with `p=quarantine` or `p=reject` after validating legitimate mail sources.")
  }
  elseif ($policy -eq 'quarantine') {
    $messages.Add("DMARC for $targetDomain is set to `p=quarantine`. For the strongest anti-spoofing posture, consider `p=reject` once you confirm valid mail is fully aligned.")
  }

  if ($null -ne $pct -and $pct -lt 100) {
    $messages.Add("DMARC enforcement for $targetDomain is only applied to $pct% of messages (`pct=$pct`). Use `pct=100` for full protection once rollout is validated.")
  }

  if ($adkim -eq 'r') {
    $messages.Add("DKIM alignment for $targetDomain uses relaxed mode (`adkim=r`). Consider strict alignment (`adkim=s`) if your sending infrastructure supports it for tighter domain protection.")
  }

  if ($aspf -eq 'r') {
    $messages.Add("SPF alignment for $targetDomain uses relaxed mode (`aspf=r`). Consider strict alignment (`aspf=s`) if your senders consistently use the exact domain.")
  }

  if (-not [string]::IsNullOrWhiteSpace($Domain) -and -not [string]::IsNullOrWhiteSpace($LookupDomain) -and $Inherited -and ($LookupDomain -ne $Domain) -and -not $tagMap.ContainsKey('sp')) {
    $messages.Add("DMARC for subdomains of $LookupDomain does not define an explicit subdomain policy (`sp=`). If you send from subdomains like $Domain, consider adding `sp=quarantine` or `sp=reject` for clearer protection.")
  }

  if ([string]::IsNullOrWhiteSpace($rua)) {
    $messages.Add("DMARC for $targetDomain does not publish aggregate reporting (`rua=`). Adding a reporting mailbox improves visibility into spoofing attempts and enforcement impact.")
  }

  if ([string]::IsNullOrWhiteSpace($ruf)) {
    $messages.Add("DMARC for $targetDomain does not publish forensic reporting (`ruf=`). If your process allows it, forensic reports can provide additional failure detail for investigations.")
  }

  return @($messages)
}

# ------------------- DOMAIN REGISTRATION STATUS -------------------
# Orchestrate domain registration lookups across all available providers (RDAP, GoDaddy,
# Sysinternals whois, Linux whois, TCP whois, WhoisXML). Returns a unified object with
# creation/expiry dates, registrar, domain age assessment, and any errors.
# If the exact domain fails, walks up parent domains as a last resort.
# ===== Domain Registration Status =====
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

  # WHOIS/RDAP operates on the registrable domain, not arbitrary subdomains.
  # Use the registrable domain first, then fall back through parent domains if needed.
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
    $tcpWhoisError = $null
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
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          else {
            $linuxWhoisError = if ($hasRawText) { "Linux whois returned no usable registration data for '$whoisDomain'." } else { "Linux whois returned output but no registrant/registrar/dates could be parsed." }
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
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            # Treat raw output as success when it contains registration output even if not fully parsed.
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          else {
            $sysWhoisError = if ($hasRawText) { "Sysinternals whois returned no usable registration data for '$whoisDomain'." } else { "Sysinternals whois returned output but no registrant/registrar/dates could be parsed." }
          }
        }
      }
      catch {
        $sysWhoisError = $_.Exception.Message
      }
    }

    # TCP whois fallback (pure PowerShell; bypasses CLI getaddrinfo service-name issues in Docker).
    if (-not $usedFallback) {
      try {
        $raw = Invoke-TcpWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $tcpCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $tcpCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $tcpCreation = $raw.creationDate }

          $tcpExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $tcpExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $tcpExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $tcpCreation }
          if (-not $expiry)   { $expiry   = $tcpExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'TcpWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            $source = 'TcpWhois'
            $usedFallback = $true
          }
          else {
            $tcpWhoisError = if ($hasRawText) { "TCP whois returned no usable registration data for '$whoisDomain'." } else { "TCP whois returned output but no registrant/registrar/dates could be parsed." }
          }
        }
      }
      catch {
        $tcpWhoisError = $_.Exception.Message
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
      if ($linuxWhoisError) { $err += " Linux whois error: $linuxWhoisError." }
      if ($tcpWhoisError) { $err += " TCP whois error: $tcpWhoisError." }
      if ($whoisXmlError) { $err += " WhoisXML error: $whoisXmlError." }
      elseif ([string]::IsNullOrWhiteSpace($apiKey)) { $err += " WhoisXML not configured." }

      $parentDomains = @(Get-ParentDomains -Domain $d)
      foreach ($parentDomain in $parentDomains) {
        $parentStatus = Get-DomainRegistrationStatus -Domain $parentDomain -NewDomainWarnThresholdDays $NewDomainWarnThresholdDays -NewDomainErrorThresholdDays $NewDomainErrorThresholdDays
        if ($parentStatus -and (
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.source) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.creationDateUtc) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.expiryDateUtc) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.registrar) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.registrant) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.rawWhoisText)
          )) {
          try { $parentStatus.domain = $d } catch { }
          return $parentStatus
        }
      }

      return [pscustomobject]@{
        domain = $d
        lookupDomain = $whoisDomain
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

  # If we obtained a source (success from any provider), suppress earlier fallback errors to avoid misleading UI.
  if ($source) {
    $rdapError = $null
    $goDaddyError = $null
    $sysWhoisError = $null
    $tcpWhoisError = $null
    $whoisXmlError = $null
  }

  if ($sysWhoisError -and -not $whoisError) { $whoisError = $sysWhoisError }
  if ($linuxWhoisError -and -not $whoisError) { $whoisError = $linuxWhoisError }
  if ($tcpWhoisError -and -not $whoisError) { $whoisError = $tcpWhoisError }
  if ($goDaddyError -and -not $whoisError) { $whoisError = $goDaddyError }
  if ($whoisXmlError -and -not $whoisError) { $whoisError = $whoisXmlError }
  if ($rdapError -and -not $whoisError) { $whoisError = $rdapError }

  [pscustomobject]@{
    domain = $d
    lookupDomain = $whoisDomain
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

# ------------------- WEB SERVER STARTUP -------------------
# ===== Web Server Startup =====
# ------------------- SERVER STARTUP HELPERS -------------------
# Probe a local URL to check if something is already listening (used during startup
# to give a more helpful error message if the port is occupied).
function Test-LocalHttpEndpoint {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [int]$TimeoutSec = 3
  )

  try {
    $previousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
      $resp = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
    }
    finally {
      $ProgressPreference = $previousProgressPreference
    }
    return [pscustomobject]@{
      reachable = $true
      statusCode = [int]$resp.StatusCode
      statusDescription = [string]$resp.StatusDescription
      content = [string]$resp.Content
      error = $null
    }
  }
  catch {
    $webResp = $null
    try { $webResp = $_.Exception.Response } catch { $webResp = $null }

    if ($webResp) {
      $statusCode = $null
      $statusDescription = $null
      $content = $null
      try { $statusCode = [int]$webResp.StatusCode } catch { $statusCode = $null }
      try { $statusDescription = [string]$webResp.StatusDescription } catch { $statusDescription = $null }
      try {
        $stream = $webResp.GetResponseStream()
        if ($stream) {
          $reader = [System.IO.StreamReader]::new($stream)
          try { $content = $reader.ReadToEnd() } finally { try { $reader.Dispose() } catch { } }
        }
      } catch { $content = $null }

      return [pscustomobject]@{
        reachable = $true
        statusCode = $statusCode
        statusDescription = $statusDescription
        content = $content
        error = $null
      }
    }

    return [pscustomobject]@{
      reachable = $false
      statusCode = $null
      statusDescription = $null
      content = $null
      error = $_.Exception.Message
    }
  }
}

# Build a user-friendly error message when the HTTP listener fails to start.
# Probes the port to determine whether another ACS instance, a different service,
# or a permission issue is the cause.
function Get-ListenerStartupErrorMessage {
  param(
    [Parameter(Mandatory = $true)]
    [int]$Port,

    [string]$DisplayUrl,

    [string]$BindMode,

    [string]$AttemptedPrefix,

    [string]$AttemptedAddress,

    [string]$FailureMessage
  )

  $baseUrl = if ([string]::IsNullOrWhiteSpace($DisplayUrl)) { "http://localhost:$Port" } else { $DisplayUrl.TrimEnd('/') }
  $probe = $null
  try { $probe = Test-LocalHttpEndpoint -Url "$baseUrl/" -TimeoutSec 2 } catch { $probe = $null }

  if ($probe -and $probe.reachable) {
    $looksLikeChecker = $false
    if (-not [string]::IsNullOrWhiteSpace([string]$probe.content)) {
      if ($probe.content -match 'ACS Email Domain Checker|Azure Communication Services\s*-\s*Email Domain Checker') {
        $looksLikeChecker = $true
      }
    }

    if ($looksLikeChecker) {
      return "An ACS Email Domain Checker instance appears to already be running on port $Port at $baseUrl/. Reuse that instance, stop the existing process, or start this script with a different -Port value."
    }

    $statusPart = if ($null -ne $probe.statusCode) { " HTTP $($probe.statusCode)" } else { '' }
    return "Port $Port is already in use by another HTTP service at $baseUrl/.$statusPart Stop the process using that port or start this script with a different -Port value."
  }

  $attemptTarget = if (-not [string]::IsNullOrWhiteSpace($AttemptedPrefix)) { $AttemptedPrefix }
    elseif (-not [string]::IsNullOrWhiteSpace($AttemptedAddress)) { "$AttemptedAddress`:$Port" }
    else { "port $Port" }

  $reason = if ([string]::IsNullOrWhiteSpace($FailureMessage)) { 'The listener could not be started.' } else { $FailureMessage.Trim() }
  return "Could not start the local web server on $attemptTarget. $reason Try a different -Port or adjust -Bind ($BindMode)."
}

# Attempt to start a local HTTP listener. The script tries HttpListener first (native .NET HTTP server).
# If that fails (e.g., on Linux without root, or URL ACL issues on Windows), it falls back to a
# raw TcpListener-based server that manually parses HTTP/1.1 requests.
$serverMode = 'HttpListener'
$listener = $null
$tcpListener = $null
$serverStarted = $false
$startupErrorMessage = $null

$displayUrl = "http://localhost:$Port"

if ([string]::IsNullOrWhiteSpace($TestDomain)) {
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
      $startupErrorMessage = Get-ListenerStartupErrorMessage -Port $Port -DisplayUrl $displayUrl -BindMode $Bind -AttemptedPrefix $prefix -FailureMessage $_.Exception.Message
      Write-Error -Message $startupErrorMessage -ErrorAction Continue
      return
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
      # If the socket cannot be opened (e.g., ACL/port in use), stop cleanly and surface a targeted message.
      $startupErrorMessage = Get-ListenerStartupErrorMessage -Port $Port -DisplayUrl $displayUrl -BindMode $Bind -AttemptedAddress $bindAddress.ToString() -FailureMessage $_.Exception.Message
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
    if (-not [string]::IsNullOrWhiteSpace($startupErrorMessage)) {
      Write-Error -Message $startupErrorMessage -ErrorAction Continue
    } else {
      Write-Error -Message "Server did not start. The port may be in use or requires additional permissions. Try a different -Port or adjust -Bind (Auto/Localhost/Any)." -ErrorAction Continue
    }
    return
  }
}
# ===== Anonymous Metrics (In-Memory & Persistence) =====

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

# Normalize a value (possibly [DateTime] from ConvertFrom-Json) to ISO 8601 round-trip string.
function ConvertTo-Iso8601Utc {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [DateTime]) {
    return $Value.ToUniversalTime().ToString('o')
  }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $dt = [DateTime]::MinValue
  if ([DateTime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
    return $dt.ToUniversalTime().ToString('o')
  }
  return $s
}

# Load previously persisted anonymous metrics from the JSON file on disk.
# Restores lifetime counters, the hash key, and unique domain hash sets so that
# metrics survive process restarts.
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

    $script:AcsMetrics['lifetimeFirstSeenUtc'] = ConvertTo-Iso8601Utc $data.firstSeenUtc
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
    } catch { $td = 0; $tud = 0 }
    $script:AcsMetrics['lifetimeTotalDomains'].Value = $td
    $script:AcsMetrics['lifetimeTotalUptimeBase'] = $ttu
    $script:AcsMetrics['lifetimeMsAuthVerifications'].Value = $tma

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

    # Restore lifetime Microsoft employee verification hash set.
    try {
      if ($data.PSObject.Properties.Match('lifetimeMsEmployeeIdHashes').Count -gt 0 -and $data.lifetimeMsEmployeeIdHashes) {
        foreach ($h in @($data.lifetimeMsEmployeeIdHashes)) {
          $s = [string]$h
          if ([string]::IsNullOrWhiteSpace($s)) { continue }
          $null = $script:AcsMetrics['lifetimeMsEmployeeIdHashes'].TryAdd($s, 0)
        }
      }
    } catch { }
  }
  catch {
    # If the file is corrupt/unreadable, start fresh (still no PII persisted).
    $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
  }
  finally {
    try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { }
  }

}

# Persist the current anonymous metrics to the JSON file on disk.
# Uses a cross-process mutex to prevent concurrent writers from clobbering data.
# Merges in-memory counters with any values already in the file (max-wins strategy)
# to handle race conditions across restarts or multiple saves.
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
    $existingLifetimeUniqueHashCount = [int64]0
    $existingFirstSeenUtc = $null
    try {
      if (Test-Path -LiteralPath $path) {
        $existingRaw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($existingRaw)) {
          $existingData = $existingRaw | ConvertFrom-Json -ErrorAction Stop
          if ($existingData.PSObject.Properties.Match('firstSeenUtc').Count -gt 0 -and $null -ne $existingData.firstSeenUtc) {
            $existingFirstSeenUtc = ConvertTo-Iso8601Utc $existingData.firstSeenUtc
          }
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
            $existingLifetimeUniqueHashCount = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count
          }
        }
      }
    } catch { }

    # Preserve the earliest firstSeenUtc: keep whichever is older between in-memory and on-disk.
    if ($existingFirstSeenUtc) {
      try {
        $existingDt = [DateTimeOffset]::Parse($existingFirstSeenUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        $memoryFirstSeen = $script:AcsMetrics['lifetimeFirstSeenUtc']
        if ([string]::IsNullOrWhiteSpace($memoryFirstSeen)) {
          $script:AcsMetrics['lifetimeFirstSeenUtc'] = $existingFirstSeenUtc
        } else {
          $memoryDt = [DateTimeOffset]::Parse($memoryFirstSeen, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
          if ($existingDt -lt $memoryDt) {
            $script:AcsMetrics['lifetimeFirstSeenUtc'] = $existingFirstSeenUtc
          }
        }
      } catch { }
    }

    $currentUptime = 0
    try {
      if ($AcsUptime) { $currentUptime = [int64][Math]::Floor($AcsUptime.Elapsed.TotalSeconds) }
    } catch { $currentUptime = 0 }

    $mergedLifetimeTotalDomains = [int64]([Math]::Max($script:AcsMetrics['lifetimeTotalDomains'].Value, $existingLifetimeTotalDomains))
    $mergedLifetimeUniqueDomains = [int64]([Math]::Max(
      [Math]::Max($script:AcsMetrics['lifetimeUniqueDomains'].Value, $existingLifetimeUniqueDomains),
      $existingLifetimeUniqueHashCount))
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

# ------------------- SESSION & COOKIE HANDLING -------------------
# Generate a random 32-character hex session ID. Used only for metrics counting;
# not derived from any PII.
# ===== Session & Cookie Handling =====
function New-AnonSessionId {
  [Guid]::NewGuid().ToString('N')
}

# Parse a Cookie header string into a name-value dictionary.
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

# Read the acs_session cookie from the request, or create a new one and set it on the response.
# Also registers the session in the in-memory metrics session tracker.
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

# Increment anonymous metrics counters when a domain lookup starts or completes.
# -Started: increments total/active/lifetime counters and tracks unique domain hashes.
# -Completed: decrements the active counter and triggers a metrics file persist.
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
      # If a metrics file was moved from another server and contains lifetime hash history,
      # ensure the in-memory lifetime unique counter is synchronized from the restored set
      # before evaluating the current domain. This prevents undercounting when the counter
      # value is stale relative to the persisted hash collection.
      try {
        $lifetimeHashCount = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count
        if ($lifetimeHashCount -gt $script:AcsMetrics['lifetimeUniqueDomains'].Value) {
          $script:AcsMetrics['lifetimeUniqueDomains'].Value = $lifetimeHashCount
        }
      } catch { }

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

# Build a point-in-time snapshot of all anonymous metrics for the /api/metrics endpoint.
# Merges in-memory counters with persisted lifetime data from the metrics file.
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
  # The hash set is the authoritative source for lifetime unique domains; the counter
  # may lag behind after a metrics file is moved from another server.
  $lifetimeUniqueHashCount = [int64]0
  try { $lifetimeUniqueHashCount = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count } catch { }
  $lifetimeUniqueDomains = [int64]([Math]::Max($script:AcsMetrics['lifetimeUniqueDomains'].Value, $lifetimeUniqueHashCount))
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

# ------------------- HTTP RESPONSE HELPERS -------------------
# Set security-related HTTP headers on every response:
# CORS, Content Security Policy, X-Frame-Options, etc.
# ===== HTTP Response Helpers =====
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
      $Context.Response.Headers['Content-Security-Policy'] = "default-src 'self'; $scriptSrc; script-src-attr 'unsafe-inline'; $styleSrc; style-src-attr 'unsafe-inline'; img-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com https://management.azure.com https://api.loganalytics.io; frame-ancestors 'none'"
    }
  } catch { }
}

# Serialize an object to JSON and write it as the HTTP response body.
# Works with both HttpListener (native) and TcpListener (shim) server modes.
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
    try { $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8 } catch { }
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

# Serve a static file from disk as the HTTP response (used for favicon, etc.).
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
        try {
          if ($ContentType -match '(?i)charset\s*=\s*utf-8') {
            $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8
          }
        } catch { }
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

# Serve the embedded single-page HTML UI.
# Replaces the CSP nonce placeholder in the HTML template before sending.
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
      try { $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8 } catch { }
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

# ------------------- DNS RESOLUTION LAYER -------------------
# Two DNS backends are supported:
#   1. Resolve-DnsName (Windows DnsClient module) - fast, uses the OS resolver.
#   2. DNS-over-HTTPS (DoH) via Cloudflare (or custom endpoint) - cross-platform fallback.
# The "Auto" mode tries Resolve-DnsName first and falls back to DoH.

# Perform a DNS query using DNS-over-HTTPS (DoH).
# Sends a JSON-format query (RFC 8484) to the configured DoH endpoint (default: Cloudflare).
# Returns objects shaped like Resolve-DnsName output for downstream compatibility.
# ===== DNS Resolution Layer =====
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

# Unified DNS lookup wrapper: selects the appropriate resolver (System vs DoH vs Auto)
# based on the ACS_DNS_RESOLVER env var, and optionally throws on failure.
# All DNS lookups in the script go through this function.
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

# Extract IP address strings from DNS resolution result objects.
# Handles the different property names used by Resolve-DnsName (IP4Address, IP6Address, IPAddress)
# and the DoH shim objects. Returns deduplicated, normalized IP strings.
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

# Filter DNS result objects to only those that are actual MX records (have Preference + NameExchange).
function Get-MxRecordObjects {
  param([object[]]$Records)

  $filtered = New-Object System.Collections.Generic.List[object]
  foreach ($rec in @($Records)) {
    if ($null -eq $rec) { continue }

    $props = $rec.PSObject.Properties
    if ($props.Match('NameExchange').Count -le 0 -or $props.Match('Preference').Count -le 0) { continue }

    $typeValue = $null
    if ($props.Match('Type').Count -gt 0) { $typeValue = [string]$rec.Type }
    elseif ($props.Match('TypeName').Count -gt 0) { $typeValue = [string]$rec.TypeName }
    elseif ($props.Match('QueryType').Count -gt 0) { $typeValue = [string]$rec.QueryType }

    if (-not [string]::IsNullOrWhiteSpace($typeValue) -and $typeValue -ne 'MX') { continue }

    $filtered.Add($rec)
  }

  return $filtered.ToArray()
}

# ------------------- INPUT NORMALIZATION -------------------
# Normalize raw user input into a clean domain name.
# Accepts: plain domain, email address (takes part after @), or URL (extracts hostname).
# Strips wildcard prefixes (*.) and surrounding dots, then lowercases the result.
# ===== Input Normalization & Validation =====
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

# Validate that a string looks like a legitimate domain name.
# Rejects obviously invalid input, prevents path/query injection, and enforces RFC label rules.
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

# ------------------- SPF ANALYSIS ENGINE -------------------
# Functions to parse, walk, and analyze SPF (Sender Policy Framework) records.
# The engine resolves nested includes and redirects up to 8 levels deep,
# detects SPF macros, counts DNS lookup terms, and checks for the ACS-required
# "include:spf.protection.outlook.com".

# Split an SPF record string into individual whitespace-delimited tokens.
# ===== SPF Analysis Engine =====
function Get-SpfTokens {
  param([string]$SpfRecord)

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return @() }

  $text = ([string]$SpfRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { return @() }

  return @($text -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

# Check whether a string contains SPF macro syntax (e.g., %{s}, %{d}, %%)
# which requires sender-specific context to expand.
function Test-SpfMacroText {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  return (([string]$Text) -match '%\{' -or ([string]$Text) -match '%%|%_|%-')
}

# Extract the target domain from an SPF mechanism's domain-spec (e.g., "a:mail.example.com/24").
# Strips CIDR notation and returns the domain portion, or falls back to the queried domain.
function Get-SpfDomainSpecTarget {
  param(
    [string]$Spec,
    [string]$Domain
  )

  $fallbackDomain = if ([string]::IsNullOrWhiteSpace($Domain)) { $null } else { ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant() }
  if ([string]::IsNullOrWhiteSpace($Spec)) { return $fallbackDomain }

  $candidate = ([string]$Spec).Trim()
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $fallbackDomain }

  $slashIndex = $candidate.IndexOf('/')
  if ($slashIndex -ge 0) {
    $candidate = $candidate.Substring(0, $slashIndex)
  }

  $candidate = $candidate.Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $fallbackDomain }

  return $candidate.ToLowerInvariant()
}

# Classify an SPF token into its mechanism type (include, redirect, exists, a, mx, ptr).
# Returns $null for tokens that are not DNS-lookup mechanisms (e.g., ip4, ip6, all).
function Get-SpfMechanismType {
  param([string]$Token)

  if ([string]::IsNullOrWhiteSpace($Token)) { return $null }

  $normalized = ([string]$Token).Trim()
  if ([string]::IsNullOrWhiteSpace($normalized)) { return $null }
  $normalized = $normalized -replace '^[\+\-~\?]', ''

  if ($normalized -match '^(?i)include:') { return 'include' }
  if ($normalized -match '^(?i)redirect=') { return 'redirect' }
  if ($normalized -match '^(?i)exists:') { return 'exists' }
  if ($normalized -match '^(?i)a(?=$|:|/)') { return 'a' }
  if ($normalized -match '^(?i)mx(?=$|:|/)') { return 'mx' }
  if ($normalized -match '^(?i)ptr(?=$|:|/)') { return 'ptr' }

  return $null
}

# Check whether an SPF record string contains a direct "include:spf.protection.outlook.com" token.
function Test-SpfOutlookIncludeToken {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  foreach ($token in @(Get-SpfTokens -SpfRecord $Text)) {
    $normalized = ([string]$token).Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) { continue }

    $normalized = $normalized -replace '^[\+\-~\?]', ''
    if ($normalized -notmatch '^(?i)include:') { continue }

    $target = ($normalized -replace '^(?i)include:', '')
    $slashIndex = $target.IndexOf('/')
    if ($slashIndex -ge 0) {
      $target = $target.Substring(0, $slashIndex)
    }
    $target = $target.Trim().TrimEnd('.').ToLowerInvariant()
    if ($target -eq 'spf.protection.outlook.com') {
      return $true
    }
  }

  return $false
}

# Recursively search the entire expanded SPF analysis tree for any reference to
# spf.protection.outlook.com — whether via direct include, nested include, redirect, exists,
# a/mx mechanism, or macro. Returns the first match found with its match type.
function Find-SpfOutlookRequirementMatch {
  param([object]$Analysis)

  if (-not $Analysis) { return $null }

  if (Test-SpfOutlookIncludeToken -Text ([string]$Analysis.record)) {
    return [pscustomobject]@{
      matchType = 'direct-include'
      value = 'include:spf.protection.outlook.com'
    }
  }

  foreach ($include in @($Analysis.includes)) {
    $includeDomain = ([string]$include.domain).Trim().TrimEnd('.').ToLowerInvariant()
    if ($includeDomain -eq 'spf.protection.outlook.com') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = $include.domain
      }
    }

    if (Test-SpfOutlookIncludeToken -Text ([string]$include.record)) {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    if (([string]$include.domain) -match '(?i)(^|\.)spf\.protection\.outlook\.com$') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = $include.domain
      }
    }

    if ($include.record -and ([string]$include.record) -match '(?i)\binclude:spf\.protection\.outlook\.com\b') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    $childMatch = Find-SpfOutlookRequirementMatch -Analysis $include.analysis
    if ($childMatch) { return $childMatch }
  }

  if ($Analysis.redirect) {
    $redirectDomain = ([string]$Analysis.redirect.domain).Trim().TrimEnd('.').ToLowerInvariant()
    if ($redirectDomain -eq 'spf.protection.outlook.com') {
      return [pscustomobject]@{
        matchType = 'redirect-reference'
        value = $Analysis.redirect.domain
      }
    }

    if (Test-SpfOutlookIncludeToken -Text ([string]$Analysis.redirect.record)) {
      return [pscustomobject]@{
        matchType = 'redirect-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    if ($Analysis.redirect.record -and ([string]$Analysis.redirect.record) -match '(?i)\binclude:spf\.protection\.outlook\.com\b') {
      return [pscustomobject]@{
        matchType = 'redirect-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    $redirectMatch = Find-SpfOutlookRequirementMatch -Analysis $Analysis.redirect.analysis
    if ($redirectMatch) { return $redirectMatch }
  }

  foreach ($existsTerm in @($Analysis.existsTerms)) {
    if (([string]$existsTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'exists-reference'
        value = $existsTerm.target
      }
    }
  }

  foreach ($aTerm in @($Analysis.aTerms)) {
    if (([string]$aTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'a-reference'
        value = $aTerm.target
      }
    }
  }

  foreach ($mxTerm in @($Analysis.mxTerms)) {
    if (([string]$mxTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'mx-reference'
        value = $mxTerm.target
      }
    }
  }

  foreach ($macro in @($Analysis.macros)) {
    if (([string]$macro) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'macro-reference'
        value = $macro
      }
    }
  }

  return $null
}

# Determine whether the ACS-required "include:spf.protection.outlook.com" is present
# in the domain's SPF record (directly or through nested includes/redirects).
# Returns an object with isPresent, matchType, detail, and error.
function Get-SpfOutlookRequirementStatus {
  param(
    [string]$Domain,
    [string]$SpfRecord,
    [object]$SpfAnalysis
  )

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) {
    return [pscustomobject]@{
      isPresent = $false
      matchType = 'missing-spf'
      detail = 'No SPF record was found.'
      error = 'SPF record is missing, so the required include:spf.protection.outlook.com could not be validated.'
    }
  }

  if (Test-SpfOutlookIncludeToken -Text $SpfRecord) {
    return [pscustomobject]@{
      isPresent = $true
      matchType = 'direct-include'
      detail = 'Found direct include:spf.protection.outlook.com in the SPF record.'
      error = $null
    }
  }

  $match = Find-SpfOutlookRequirementMatch -Analysis $SpfAnalysis
  if ($match) {
    switch ($match.matchType) {
      'nested-include' {
        return [pscustomobject]@{
          isPresent = $true
          matchType = $match.matchType
          detail = "Found include:spf.protection.outlook.com in the expanded SPF chain ($($match.value))."
          error = $null
        }
      }
      'redirect-include' {
        return [pscustomobject]@{
          isPresent = $true
          matchType = $match.matchType
          detail = 'Found include:spf.protection.outlook.com through an SPF redirect target.'
          error = $null
        }
      }
      default {
        return [pscustomobject]@{
          isPresent = $false
          matchType = $match.matchType
          detail = $null
          error = "SPF for $targetDomain references spf.protection.outlook.com indirectly ($($match.value)), but the required include:spf.protection.outlook.com could not be confirmed in the expanded SPF chain."
        }
      }
    }
  }

  $targetDomain = if ([string]::IsNullOrWhiteSpace($Domain)) { 'the domain' } else { $Domain }
  $analysisScope = if ($SpfAnalysis -and $SpfAnalysis.analysisScope) { [string]$SpfAnalysis.analysisScope } else { 'full-static' }
  $error = if ($analysisScope -eq 'message-context-required' -or $analysisScope -eq 'partial-static') {
    "SPF for $targetDomain could not be confirmed to include include:spf.protection.outlook.com. The record uses nested or macro-based logic, and the required Outlook include was not found during static analysis."
  } else {
    "SPF for $targetDomain does not include include:spf.protection.outlook.com in the expanded SPF chain. This is required for ACS SPF validation."
  }

  return [pscustomobject]@{
    isPresent = $false
    matchType = 'not-found'
    detail = 'Did not find include:spf.protection.outlook.com in the expanded SPF chain.'
    error = $error
  }
}

# Recursively parse an SPF record, resolving includes and redirects up to MaxDepth levels.
# For each mechanism (include, redirect, a, mx, exists, ptr), performs live DNS lookups
# and builds a tree of results. Tracks visited domains to detect include loops.
# Also counts total DNS-lookup-style terms to warn about the SPF 10-lookup limit.
function Get-SpfNestedAnalysis {
  param(
    [string]$SpfRecord,
    [string]$Domain,
    [int]$MaxDepth = 8,
    [hashtable]$Visited
  )

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return $null }
  if ($MaxDepth -lt 0) { $MaxDepth = 0 }
  if ($null -eq $Visited) { $Visited = @{} }

  $tokens = @(Get-SpfTokens -SpfRecord $SpfRecord)
  if ($tokens.Count -eq 0) { return $null }

  $includes = New-Object System.Collections.Generic.List[object]
  $redirect = $null
  $existsTerms = New-Object System.Collections.Generic.List[object]
  $aTerms = New-Object System.Collections.Generic.List[object]
  $mxTerms = New-Object System.Collections.Generic.List[object]
  $ptrTerms = New-Object System.Collections.Generic.List[object]
  $macros = New-Object System.Collections.Generic.List[string]
  $warnings = New-Object System.Collections.Generic.List[string]
  $errors = New-Object System.Collections.Generic.List[string]
  $lookupTerms = 0
  $nestedLookupTerms = 0
  $analysisScope = 'full-static'

  foreach ($token in $tokens) {
    $item = ([string]$token).Trim()
    if ([string]::IsNullOrWhiteSpace($item)) { continue }

    if (Test-SpfMacroText -Text $item) {
      if (-not $macros.Contains($item)) { $macros.Add($item) }
      if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
    }

    $mechanismType = Get-SpfMechanismType -Token $item
    if ($mechanismType) {
      $lookupTerms++
    }

    if ($mechanismType -eq 'include' -and $item -match '^(?i)[+\-~?]?include:(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      if ([string]::IsNullOrWhiteSpace($target)) { continue }

      $includeRecord = $null
      $includeError = $null
      $includeResult = $null
      $visitedKey = $target.ToLowerInvariant()

      if ($Visited.ContainsKey($visitedKey)) {
        $includeError = "Include loop detected for $target."
      }
      elseif ($MaxDepth -le 0) {
        $includeError = "Maximum SPF include depth reached at $target."
      }
      elseif (Test-SpfMacroText -Text $target) {
        $includeError = "Include target $target uses SPF macros and requires sender-specific context to expand."
        if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
      }
      else {
        $Visited[$visitedKey] = $true
        try {
          $txtRecords = ResolveSafely $target 'TXT'
          foreach ($txt in @($txtRecords)) {
            $joined = ($txt.Strings -join '').Trim()
            if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
              $joined = $joined.Substring(1, $joined.Length - 2)
            }
            if ($joined -match '(?i)^v=spf1\b') {
              $includeRecord = $joined
              break
            }
          }

          if ($includeRecord) {
            $includeResult = Get-SpfNestedAnalysis -SpfRecord $includeRecord -Domain $target -MaxDepth ($MaxDepth - 1) -Visited $Visited
            if ($includeResult -and $includeResult.totalLookupTerms -ne $null) {
              $nestedLookupTerms += [int]$includeResult.totalLookupTerms
            }
          }
          else {
            $includeError = "No SPF TXT record found for include target $target."
          }
        }
        catch {
          $includeError = $_.Exception.Message
        }
        finally {
          $Visited.Remove($visitedKey) | Out-Null
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($includeError) -and -not $errors.Contains($includeError)) {
        $errors.Add($includeError)
      }

      $includes.Add([pscustomobject]@{
        domain = $target
        record = $includeRecord
        error = $includeError
        analysis = $includeResult
      })
      continue
    }

    if ($mechanismType -eq 'redirect' -and $item -match '^(?i)redirect=(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      if ([string]::IsNullOrWhiteSpace($target)) { continue }

      $redirectRecord = $null
      $redirectError = $null
      $redirectAnalysis = $null
      $visitedKey = $target.ToLowerInvariant()

      if ($Visited.ContainsKey($visitedKey)) {
        $redirectError = "Redirect loop detected for $target."
      }
      elseif ($MaxDepth -le 0) {
        $redirectError = "Maximum SPF redirect depth reached at $target."
      }
      elseif (Test-SpfMacroText -Text $target) {
        $redirectError = "Redirect target $target uses SPF macros and requires sender-specific context to expand."
        if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
      }
      else {
        $Visited[$visitedKey] = $true
        try {
          $txtRecords = ResolveSafely $target 'TXT'
          foreach ($txt in @($txtRecords)) {
            $joined = ($txt.Strings -join '').Trim()
            if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
              $joined = $joined.Substring(1, $joined.Length - 2)
            }
            if ($joined -match '(?i)^v=spf1\b') {
              $redirectRecord = $joined
              break
            }
          }

          if ($redirectRecord) {
            $redirectAnalysis = Get-SpfNestedAnalysis -SpfRecord $redirectRecord -Domain $target -MaxDepth ($MaxDepth - 1) -Visited $Visited
            if ($redirectAnalysis -and $redirectAnalysis.totalLookupTerms -ne $null) {
              $nestedLookupTerms += [int]$redirectAnalysis.totalLookupTerms
            }
          }
          else {
            $redirectError = "No SPF TXT record found for redirect target $target."
          }
        }
        catch {
          $redirectError = $_.Exception.Message
        }
        finally {
          $Visited.Remove($visitedKey) | Out-Null
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($redirectError) -and -not $errors.Contains($redirectError)) {
        $errors.Add($redirectError)
      }

      $redirect = [pscustomobject]@{
        domain = $target
        record = $redirectRecord
        error = $redirectError
        analysis = $redirectAnalysis
      }
      continue
    }

    if ($mechanismType -eq 'exists' -and $item -match '^(?i)[+\-~?]?exists:(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      $existsError = $null
      $resolved = @()
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $existsError = 'SPF exists mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $existsError = "Exists target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $resolved = @((ResolveSafely $target 'A' | Get-DnsIpString) + (ResolveSafely $target 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
        }
        catch {
          $analysisStatus = 'error'
          $existsError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($existsError) -and -not $errors.Contains($existsError)) {
        $errors.Add($existsError)
      }

      $existsTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedAddresses = @($resolved)
        error = $existsError
      })
      continue
    }

    if ($mechanismType -eq 'a') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(1)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $aError = $null
      $resolved = @()
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $aError = 'SPF a mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $aError = "A mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $resolved = @((ResolveSafely $target 'A' | Get-DnsIpString) + (ResolveSafely $target 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
        }
        catch {
          $analysisStatus = 'error'
          $aError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($aError) -and -not $errors.Contains($aError)) {
        $errors.Add($aError)
      }

      $aTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedAddresses = @($resolved)
        error = $aError
      })
      continue
    }

    if ($mechanismType -eq 'mx') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(2)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $mxError = $null
      $resolvedHosts = New-Object System.Collections.Generic.List[object]
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $mxError = 'SPF mx mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $mxError = "MX mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $mxRecords = @(Get-MxRecordObjects -Records (ResolveSafely $target 'MX'))
          foreach ($mxRecord in $mxRecords) {
            $mxHost = ([string]$mxRecord.NameExchange).Trim().TrimEnd('.')
            if ([string]::IsNullOrWhiteSpace($mxHost)) { continue }
            $hostAddresses = @((ResolveSafely $mxHost 'A' | Get-DnsIpString) + (ResolveSafely $mxHost 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
            $resolvedHosts.Add([pscustomobject]@{
              hostname = $mxHost
              preference = $mxRecord.Preference
              addresses = @($hostAddresses)
            })
          }
        }
        catch {
          $analysisStatus = 'error'
          $mxError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($mxError) -and -not $errors.Contains($mxError)) {
        $errors.Add($mxError)
      }

      $mxTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedHosts = @($resolvedHosts)
        error = $mxError
      })
      continue
    }

    if ($mechanismType -eq 'ptr') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(3)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $ptrMessage = if ([string]::IsNullOrWhiteSpace($target)) {
        'PTR mechanism present. Static analysis cannot validate PTR authorization safely and SPF PTR is discouraged.'
      } elseif (Test-SpfMacroText -Text $target) {
        $analysisScope = 'message-context-required'
        "PTR mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
      } else {
        "PTR mechanism target $target requires sender IP context and reverse DNS evaluation; only presence is reported."
      }

      if (-not $warnings.Contains($ptrMessage)) { $warnings.Add($ptrMessage) }
      $ptrTerms.Add([pscustomobject]@{
        target = $target
        message = $ptrMessage
      })
      continue
    }
  }

  $totalLookupTerms = $lookupTerms + $nestedLookupTerms
  if ($totalLookupTerms -gt 10) {
    $warnings.Add("SPF record for $Domain may exceed the 10-DNS-lookup guidance limit. Detected lookup-style terms across the expanded chain: $totalLookupTerms.")
  }
  if ($analysisScope -eq 'partial-static') {
    $warnings.Add("SPF record for $Domain includes macro-based targets. This tool performs best-effort static analysis, but some nested paths require sender-specific context to expand fully.")
  }
  elseif ($analysisScope -eq 'message-context-required') {
    $warnings.Add("SPF record for $Domain includes mechanisms that require sender-specific context (for example macros, exists, or ptr). Full SPF evaluation requires message inputs such as sender IP, HELO, and MAIL FROM.")
  }

  [pscustomobject]@{
    domain = $Domain
    record = $SpfRecord
    includes = @($includes)
    redirect = $redirect
    existsTerms = @($existsTerms)
    aTerms = @($aTerms)
    mxTerms = @($mxTerms)
    ptrTerms = @($ptrTerms)
    macros = @($macros | Select-Object -Unique)
    lookupTerms = $lookupTerms
    nestedLookupTerms = $nestedLookupTerms
    totalLookupTerms = $totalLookupTerms
    analysisScope = $analysisScope
    warnings = @($warnings)
    errors = @($errors | Select-Object -Unique)
  }
}

# Render the SPF analysis tree as indented plain-text lines for display in the UI's
# "expanded SPF" section. Each level of nesting adds two spaces of indentation.
function Format-SpfNestedAnalysisText {
  param(
    [object]$Analysis,
    [int]$Depth = 0
  )

  if (-not $Analysis) { return @() }

  $lines = New-Object System.Collections.Generic.List[string]
  $indent = ('  ' * $Depth)
  $domainLabel = if (-not [string]::IsNullOrWhiteSpace([string]$Analysis.domain)) { [string]$Analysis.domain } else { 'SPF' }
  $lines.Add("${indent}Domain: $domainLabel")
  if ($Analysis.record) {
    $lines.Add("${indent}Record: $([string]$Analysis.record)")
  }
  if ($Analysis.lookupTerms -ne $null) {
    $lines.Add("${indent}Lookup-style terms: $([string]$Analysis.lookupTerms)")
  }
  if ($Analysis.totalLookupTerms -ne $null -and [int]$Analysis.totalLookupTerms -ne [int]$Analysis.lookupTerms) {
    $lines.Add("${indent}Expanded-chain lookup terms: $([string]$Analysis.totalLookupTerms)")
  }
  foreach ($macro in @($Analysis.macros)) {
    $lines.Add("${indent}Macro term: $([string]$macro)")
  }
  foreach ($warning in @($Analysis.warnings)) {
    $lines.Add("${indent}Warning: $([string]$warning)")
  }
  foreach ($errorText in @($Analysis.errors)) {
    $lines.Add("${indent}Note: $([string]$errorText)")
  }

  foreach ($existsTerm in @($Analysis.existsTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$existsTerm.target)) { [string]$existsTerm.target } else { '(empty)' }
    $existsLine = "${indent}Exists: $target"
    if ($existsTerm.status) { $existsLine += " [$([string]$existsTerm.status)]" }
    if ($existsTerm.error) {
      $existsLine += " (note: $([string]$existsTerm.error))"
    }
    elseif (@($existsTerm.resolvedAddresses).Count -gt 0) {
      $existsLine += ": $((@($existsTerm.resolvedAddresses) -join ', '))"
    }
    $lines.Add($existsLine)
  }

  foreach ($aTerm in @($Analysis.aTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$aTerm.target)) { [string]$aTerm.target } else { '(empty)' }
    $aLine = "${indent}A: $target"
    if ($aTerm.status) { $aLine += " [$([string]$aTerm.status)]" }
    if ($aTerm.error) {
      $aLine += " (note: $([string]$aTerm.error))"
    }
    elseif (@($aTerm.resolvedAddresses).Count -gt 0) {
      $aLine += ": $((@($aTerm.resolvedAddresses) -join ', '))"
    }
    $lines.Add($aLine)
  }

  foreach ($mxTerm in @($Analysis.mxTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$mxTerm.target)) { [string]$mxTerm.target } else { '(empty)' }
    $mxLine = "${indent}MX: $target"
    if ($mxTerm.status) { $mxLine += " [$([string]$mxTerm.status)]" }
    if ($mxTerm.error) {
      $mxLine += " (note: $([string]$mxTerm.error))"
      $lines.Add($mxLine)
      continue
    }

    $lines.Add($mxLine)
    foreach ($host in @($mxTerm.resolvedHosts)) {
      $hostLine = "${indent}  Host: $([string]$host.hostname)"
      if ($null -ne $host.preference) { $hostLine += " (priority $([string]$host.preference))" }
      if (@($host.addresses).Count -gt 0) {
        $hostLine += ": $((@($host.addresses) -join ', '))"
      }
      $lines.Add($hostLine)
    }
  }

  foreach ($ptrTerm in @($Analysis.ptrTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$ptrTerm.target)) { [string]$ptrTerm.target } else { '(queried domain)' }
    $lines.Add("${indent}PTR: $target ($([string]$ptrTerm.message))")
  }

  foreach ($include in @($Analysis.includes)) {
    $includeDomain = [string]$include.domain
    if ($include.error) {
      $lines.Add("${indent}Include: $includeDomain (error: $([string]$include.error))")
    }
    else {
      $lines.Add("${indent}Include: $includeDomain")
      foreach ($childLine in @(Format-SpfNestedAnalysisText -Analysis $include.analysis -Depth ($Depth + 1))) {
        $lines.Add($childLine)
      }
    }
  }

  if ($Analysis.redirect) {
    $redirectDomain = [string]$Analysis.redirect.domain
    if ($Analysis.redirect.error) {
      $lines.Add("${indent}Redirect: $redirectDomain (error: $([string]$Analysis.redirect.error))")
    }
    else {
      $lines.Add("${indent}Redirect: $redirectDomain")
      foreach ($childLine in @(Format-SpfNestedAnalysisText -Analysis $Analysis.redirect.analysis -Depth ($Depth + 1))) {
        $lines.Add($childLine)
      }
    }
  }

  return @($lines)
}

# Generate human-readable SPF security recommendations based on the record content
# and the analysis results. Warns about +all, ?all, ~all, macros, many lookup terms,
# and the ACS Outlook include requirement.
function Get-SpfGuidance {
  param(
    [string]$SpfRecord,
    [string]$Domain,
    [object]$SpfAnalysis,
    [object]$OutlookRequirementStatus
  )

  $messages = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return @() }

  $recordText = ([string]$SpfRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($recordText)) { return @() }

  $targetDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } else { 'the domain' }

  if ($recordText -match '(?i)\s\+all(\s|$)') {
    $messages.Add("SPF for $targetDomain allows all senders (`+all`), which is insecure. Replace it with a restrictive qualifier such as `-all` or `~all` after validating legitimate senders.")
  }
  elseif ($recordText -match '(?i)\s\?all(\s|$)') {
    $messages.Add("SPF for $targetDomain ends with `?all`, which is neutral and provides little protection. Consider `~all` during rollout or `-all` for strict enforcement.")
  }
  elseif ($recordText -match '(?i)\s~all(\s|$)') {
    $messages.Add("SPF for $targetDomain ends with soft fail (`~all`). For a stricter anti-spoofing posture, consider `-all` once all valid senders are confirmed.")
  }
  elseif ($recordText -notmatch '(?i)\s[-~?+]all(\s|$)') {
    $messages.Add("SPF for $targetDomain does not appear to end with an `all` mechanism. Add an explicit `~all` or `-all` so unauthorized senders are handled predictably.")
  }

  if ($recordText -match '%\{' -or $recordText -match '%%|%_|%-') {
    $messages.Add("SPF for $targetDomain uses macros. This tool performs best-effort static analysis, but macro-based SPF can require sender-specific context to evaluate fully.")
  }

  if ($SpfAnalysis) {
    if ($SpfAnalysis.totalLookupTerms -gt 8) {
      $messages.Add("SPF for $targetDomain uses many DNS-lookup-style terms ($($SpfAnalysis.totalLookupTerms) detected across the expanded chain). Complex nested SPF records can approach the SPF 10-lookup evaluation limit.")
    }
    if (@($SpfAnalysis.includes).Count -gt 0) {
      $messages.Add("SPF for $targetDomain includes nested sender policies. Review the expanded SPF chain in the SPF card to confirm all included services are expected.")
    }
    if (@($SpfAnalysis.existsTerms).Count -gt 0) {
      $messages.Add("SPF for $targetDomain uses `exists:` mechanisms. These can be analyzed structurally, but full authorization depends on sender-specific evaluation context.")
    }
    if (@($SpfAnalysis.ptrTerms).Count -gt 0) {
      $messages.Add("SPF for $targetDomain uses `ptr`, which is discouraged and cannot be fully evaluated by this static domain checker without sender context.")
    }
    if ($SpfAnalysis.analysisScope -eq 'message-context-required') {
      $messages.Add("SPF for $targetDomain requires message context for full evaluation. Use a sender IP, HELO, and MAIL FROM if you need a true SPF pass/fail simulation.")
    }
    foreach ($warning in @($SpfAnalysis.warnings)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$warning)) { $messages.Add([string]$warning) }
    }
  }

  if ($OutlookRequirementStatus) {
    if ($OutlookRequirementStatus.isPresent -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$OutlookRequirementStatus.detail)) {
      $messages.Add([string]$OutlookRequirementStatus.detail)
    }
    elseif ($OutlookRequirementStatus.isPresent -ne $true -and -not [string]::IsNullOrWhiteSpace([string]$OutlookRequirementStatus.error)) {
      $messages.Add([string]$OutlookRequirementStatus.error)
    }
  }

  return @($messages | Select-Object -Unique)
}

# ------------------- REQUEST HANDLING UTILITIES -------------------
# Log a request to the console. Intentionally omits IP addresses and user agents (PII).
# ===== Request Handling Utilities =====
function Write-RequestLog {
  param(
    $Context,
    [string]$Action,
    [string]$Domain
  )

  # Do not log IP addresses or user agents (PII). Only log minimal non-identifying data.
  Write-Information -InformationAction Continue -MessageData "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Action for '$Domain'"
}

# Extract the client's IP address from the request, preferring X-Forwarded-For when present
# (for reverse-proxy/container scenarios). Used only for rate limiting, never logged.
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

# Extract the API key from the request. Checks headers (X-Api-Key, X-ACS-API-Key, Authorization: ApiKey ...)
# and query string (?apiKey=...) as a less-secure fallback.
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

# Validate the API key from the request against ACS_API_KEY env var.
# Returns $true if no API key is configured (open access) or if the provided key matches.
function Test-ApiKey {
  param($Context)

  $expected = [string]$env:ACS_API_KEY
  if ([string]::IsNullOrWhiteSpace($expected)) { return $true }

  $provided = Get-ApiKeyFromRequest -Context $Context
  if ([string]::IsNullOrWhiteSpace($provided)) { return $false }

  return [string]::Equals($provided, $expected, [System.StringComparison]::Ordinal)
}

# Enforce per-client-IP rate limiting using a sliding 60-second window.
# Returns an object with allowed (bool), remaining count, and retry-after seconds.
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

# ------------------- DNS CHECK FUNCTIONS -------------------
# Each Get-Dns*Status function performs a specific DNS check for a domain and returns
# a structured result object. These are called individually by the /api/* endpoints
# and collectively by Get-AcsDnsStatus for the aggregated /dns endpoint.

# Check root TXT records for SPF (v=spf1...) and ACS verification (ms-domain-verification...).
# Also resolves A/AAAA for the domain and falls back to parent domains if needed.
# ===== Individual DNS Check Functions =====
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
  $txtLookupDomain = $Domain
  $txtUsedParent = $false
  $parentTxtRecords = @()
  $parentSpf = $null
  $parentAcsTxt = $null
  $spfAnalysis = $null
  $spfExpandedText = $null
  $spfGuidance = @()
  $spfOutlookRequirement = $null

  try {
    $records = ResolveSafely $Domain "TXT" -ThrowOnError
    foreach ($r in $records) {
      $joined = ($r.Strings -join "").Trim()
      if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
        $joined = $joined.Substring(1, $joined.Length - 2)
      }
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
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

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
          break
        }
      } catch { }
    }
  }

  if (-not $dnsFailed) {
    foreach ($t in $txtRecords) {
      if (-not $spf    -and $t -match '(?i)^v=spf1')                { $spf    = $t }
      if (-not $acsTxt -and $t -match '(?i)ms-domain-verification') { $acsTxt = $t }
    }

    if ($txtRecords.Count -eq 0) {
      foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

        try {
          $parentTxt = @()
          $parentRecords = ResolveSafely $parent "TXT"
          foreach ($pr in $parentRecords) {
            $joinedParent = ($pr.Strings -join "").Trim()
            if ($joinedParent.StartsWith('"') -and $joinedParent.EndsWith('"') -and $joinedParent.Length -ge 2) {
              $joinedParent = $joinedParent.Substring(1, $joinedParent.Length - 2)
            }
            if ($joinedParent) { $parentTxt += $joinedParent }
          }

          if ($parentTxt.Count -gt 0) {
            $parentTxtRecords = $parentTxt
            $txtLookupDomain = $parent
            $txtUsedParent = $true

            foreach ($t in $parentTxtRecords) {
              if (-not $parentSpf -and $t -match '(?i)^v=spf1') { $parentSpf = $t }
              if (-not $parentAcsTxt -and $t -match '(?i)ms-domain-verification') { $parentAcsTxt = $t }
            }
            break
          }
        } catch { }
      }
    }
  }

  $spfPresent = -not $dnsFailed -and [bool]$spf
  $acsPresent = -not $dnsFailed -and [bool]$acsTxt

  if ($spfPresent -and -not [string]::IsNullOrWhiteSpace($spf)) {
    try {
      $spfAnalysis = Get-SpfNestedAnalysis -SpfRecord $spf -Domain $Domain
      $spfOutlookRequirement = Get-SpfOutlookRequirementStatus -Domain $Domain -SpfRecord $spf -SpfAnalysis $spfAnalysis
      $spfExpandedLines = @(Format-SpfNestedAnalysisText -Analysis $spfAnalysis)
      if ($spfOutlookRequirement -and -not [string]::IsNullOrWhiteSpace([string]$spfOutlookRequirement.detail)) {
        $spfExpandedLines += ''
        $spfExpandedLines += 'ACS Outlook SPF requirement:'
        $spfExpandedLines += [string]$spfOutlookRequirement.detail
      }
      elseif ($spfOutlookRequirement -and -not [string]::IsNullOrWhiteSpace([string]$spfOutlookRequirement.error)) {
        $spfExpandedLines += ''
        $spfExpandedLines += 'ACS Outlook SPF requirement:'
        $spfExpandedLines += [string]$spfOutlookRequirement.error
      }
      if ($spfExpandedLines.Count -gt 0) {
        $spfExpandedText = ($spfExpandedLines -join "`n")
      }
      $spfGuidance = @(Get-SpfGuidance -SpfRecord $spf -Domain $Domain -SpfAnalysis $spfAnalysis -OutlookRequirementStatus $spfOutlookRequirement)
    } catch {
      try {
        $spfOutlookRequirement = Get-SpfOutlookRequirementStatus -Domain $Domain -SpfRecord $spf -SpfAnalysis $null
        $spfGuidance = @(Get-SpfGuidance -SpfRecord $spf -Domain $Domain -SpfAnalysis $null -OutlookRequirementStatus $spfOutlookRequirement)
      } catch { }
    }
  }

  [pscustomobject]@{
    domain     = $Domain
    dnsFailed  = $dnsFailed
    dnsError   = $dnsError

    txtLookupDomain = $txtLookupDomain
    txtUsedParent   = $txtUsedParent

    ipLookupDomain = $ipLookupDomain
    ipUsedParent   = $ipUsedParent

    ipv4Addresses = $ipv4Addrs
    ipv6Addresses = $ipv6Addrs

    spfPresent = $spfPresent
    spfValue   = $spf
    spfAnalysis = $spfAnalysis
    spfExpandedText = $spfExpandedText
    spfGuidance = $spfGuidance
    spfHasRequiredInclude = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.isPresent } else { $null })
    spfRequiredInclude = 'spf.protection.outlook.com'
    spfRequiredIncludeMatchType = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.matchType } else { $null })
    spfRequiredIncludeDetail = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.detail } else { $null })
    spfRequiredIncludeError = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.error } else { $null })
    acsPresent = $acsPresent
    acsValue   = $acsTxt

    parentSpfPresent = (-not $dnsFailed) -and [bool]$parentSpf
    parentSpfValue   = $parentSpf
    parentAcsPresent = (-not $dnsFailed) -and [bool]$parentAcsTxt
    parentAcsValue   = $parentAcsTxt
    parentTxtRecords = $parentTxtRecords

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
      $mxRecordsOnly = @(Get-MxRecordObjects -Records $mx)
      if (-not $mxRecordsOnly -or $mxRecordsOnly.Count -eq 0) {
        return $result
      }

      $mxSorted = $mxRecordsOnly | Sort-Object Preference, NameExchange

      $primaryMx = $null
      try { $primaryMx = ($mxSorted | Select-Object -First 1 -ExpandProperty NameExchange) } catch { $primaryMx = $null }

      if ($primaryMx) {
        $mxHost = $primaryMx.ToString().Trim().TrimEnd('.').ToLowerInvariant()
switch -Regex ($mxHost) {
          # --- Microsoft & Google ---
          'mail\.protection\.outlook\.com\.?$' {
            $result.mxProvider = 'Microsoft 365 / Exchange Online'
            $result.mxProviderHint = 'MX points to Exchange Online Protection (EOP).'
            break
          }
          '(^|\.)protection\.outlook\.com\.?$' {
            $result.mxProvider = 'Microsoft Defender for Office 365 / EOP'
            $result.mxProviderHint = 'MX points to Microsoft filtering service.'
            break
          }
          'aspmx\.l\.google\.com\.?$|\.aspmx\.l\.google\.com\.?$|google\.com\.?$' {
            $result.mxProvider = 'Google Workspace / Gmail'
            $result.mxProviderHint = 'MX points to Google mail exchangers.'
            break
          }

          # --- Major Commercial Email (Yahoo, Apple, Zoho, etc.) ---
          '(^|\.)yahoodns\.net\.?$|(^|\.)yahoodns\.com\.?$|(^|\.)bizmail\.yahoo\.com\.?$' {
            $result.mxProvider = 'Yahoo Mail'
            $result.mxProviderHint = 'MX points to Yahoo Mail.'
            break
          }
          '(^|\.)mail\.icloud\.com\.?$' {
            $result.mxProvider = 'Apple iCloud Mail'
            $result.mxProviderHint = 'MX points to Apple iCloud Mail.'
            break
          }
          'zoho\.com\.?$' {
            $result.mxProvider = 'Zoho Mail'
            $result.mxProviderHint = 'MX points to Zoho Mail.'
            break
          }
          '(^|\.)messagingengine\.com\.?$' {
            $result.mxProvider = 'Fastmail'
            $result.mxProviderHint = 'MX points to Fastmail.'
            break
          }

          # --- Privacy-Focused & Secure Webmail ---
          '(^|\.)protonmail\.ch\.?$|(^|\.)protonmail\.net\.?$' {
            $result.mxProvider = 'Proton Mail'
            $result.mxProviderHint = 'MX points to Proton Mail.'
            break
          }
          '(^|\.)tutanota\.de\.?$|(^|\.)tuta\.com\.?$' {
            $result.mxProvider = 'Tuta (Tutanota)'
            $result.mxProviderHint = 'MX points to Tuta secure email.'
            break
          }
          '(^|\.)hushmail\.com\.?$' {
            $result.mxProvider = 'Hushmail'
            $result.mxProviderHint = 'MX points to Hushmail encrypted email.'
            break
          }
          '(^|\.)runbox\.com\.?$' {
            $result.mxProvider = 'Runbox'
            $result.mxProviderHint = 'MX points to Runbox secure email.'
            break
          }
          '(^|\.)mailfence\.com\.?$' {
            $result.mxProvider = 'Mailfence'
            $result.mxProviderHint = 'MX points to Mailfence secure email.'
            break
          }
          '(^|\.)startmail\.com\.?$' {
            $result.mxProvider = 'StartMail'
            $result.mxProviderHint = 'MX points to StartMail private email.'
            break
          }

          # --- Security, Cloud Filtering & Gateways ---
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
          '(^|\.)ppe-hosted\.com\.?$|(^|\.)pphostedmail\.com\.?$' {
            $result.mxProvider = 'Proofpoint Essentials'
            $result.mxProviderHint = 'MX points to Proofpoint Essentials.'
            break
          }
          'mimecast\.com\.?$' {
            $result.mxProvider = 'Mimecast'
            $result.mxProviderHint = 'MX points to Mimecast.'
            break
          }
          '(^|\.)iphmx\.com\.?$|(^|\.)esa\d*\..*\.iphmx\.com\.?$|(^|\.)ironport\.com\.?$' {
            $result.mxProvider = 'Cisco Secure Email / IronPort'
            $result.mxProviderHint = 'MX points to Cisco Secure Email (IronPort).'
            break
          }
          '(^|\.)mailcontrol\.com\.?$' {
            $result.mxProvider = 'Forcepoint / Websense Email Security'
            $result.mxProviderHint = 'MX points to Forcepoint-hosted email security.'
            break
          }
          '(^|\.)mailspamprotection\.com\.?$|(^|\.)spamh\.eu\.?$' {
            $result.mxProvider = 'SpamHero'
            $result.mxProviderHint = 'MX points to SpamHero email filtering.'
            break
          }
          '(^|\.)trendmicro\.eu\.?$|(^|\.)trendmicro\.com\.?$|(^|\.)hes\.ms$|(^|\.)mxthunder\.net\.?$' {
            $result.mxProvider = 'Trend Micro Hosted Email Security'
            $result.mxProviderHint = 'MX points to Trend Micro hosted email security.'
            break
          }
          '(^|\.)protection\.messagelabs\.com\.?$' {
            $result.mxProvider = 'Broadcom / Symantec Email Security.cloud'
            $result.mxProviderHint = 'MX points to Symantec Email Security.cloud.'
            break
          }
          '(^|\.)messagelabs\.com\.?$' {
            $result.mxProvider = 'Symantec MessageLabs'
            $result.mxProviderHint = 'MX points to Symantec MessageLabs.'
            break
          }
          '(^|\.)antispamcloud\.com\.?$' {
            $result.mxProvider = 'SpamExperts / N-able Mail Assure'
            $result.mxProviderHint = 'MX points to SpamExperts / Mail Assure filtering.'
            break
          }
          '(^|\.)mailfiltering\.com\.?$|(^|\.)spamtitan\.com\.?$' {
            $result.mxProvider = 'SpamTitan'
            $result.mxProviderHint = 'MX points to SpamTitan filtering.'
            break
          }
          '(^|\.)protection\.mailguard\.com\.au\.?$|(^|\.)mailguard\.com\.au\.?$' {
            $result.mxProvider = 'MailGuard'
            $result.mxProviderHint = 'MX points to MailGuard filtering.'
            break
          }
          '(^|\.)sophos\.com\.?$|(^|\.)sophosxl\.net\.?$' {
            $result.mxProvider = 'Sophos Email'
            $result.mxProviderHint = 'MX points to Sophos Email security.'
            break
          }
          '(^|\.)tessian\.com\.?$' {
            $result.mxProvider = 'Tessian'
            $result.mxProviderHint = 'MX points to Tessian email security.'
            break
          }
          '(^|\.)barracudanetworks\.com\.?$' {
            $result.mxProvider = 'Barracuda Networks'
            $result.mxProviderHint = 'MX points to Barracuda Email Security Gateway.'
            break
          }
          '(^|\.)appriver\.com\.?$' {
            $result.mxProvider = 'AppRiver / Zix'
            $result.mxProviderHint = 'MX points to AppRiver secure email.'
            break
          }
          '(^|\.)hornetsecurity\.com\.?$' {
            $result.mxProvider = 'Hornetsecurity'
            $result.mxProviderHint = 'MX points to Hornetsecurity cloud filtering.'
            break
          }
          '(^|\.)fortinet\.com\.?$' {
            $result.mxProvider = 'Fortinet FortiMail'
            $result.mxProviderHint = 'MX points to Fortinet email security.'
            break
          }
          '(^|\.)trustifi\.com\.?$' {
            $result.mxProvider = 'Trustifi'
            $result.mxProviderHint = 'MX points to Trustifi email security.'
            break
          }
          '(^|\.)halon\.io\.?$' {
            $result.mxProvider = 'Halon'
            $result.mxProviderHint = 'MX points to Halon MTA / Security.'
            break
          }
          '(^|\.)fireeye\.com\.?$' {
            $result.mxProvider = 'FireEye'
            $result.mxProviderHint = 'MX points to FireEye Email Security.'
            break
          }

          # --- Transactional, Delivery APIs & Marketing ---
          '(^|\.)mailgun\.org\.?$' {
            $result.mxProvider = 'Mailgun'
            $result.mxProviderHint = 'MX points to Mailgun.'
            break
          }
          '(^|\.)sendgrid\.net\.?$' {
            $result.mxProvider = 'SendGrid'
            $result.mxProviderHint = 'MX points to SendGrid.'
            break
          }
          '(^|\.)amazonses\.com\.?$' {
            $result.mxProvider = 'Amazon SES'
            $result.mxProviderHint = 'MX points to Amazon SES.'
            break
          }
          '(^|\.)inbound-smtp\.[a-z0-9-]+\.amazonaws\.com\.?$' {
            $result.mxProvider = 'Amazon SES'
            $result.mxProviderHint = 'MX points to Amazon SES inbound mail.'
            break
          }
          '(^|\.)postmarkapp\.com\.?$' {
            $result.mxProvider = 'Postmark'
            $result.mxProviderHint = 'MX points to Postmark inbound processing.'
            break
          }
          '(^|\.)sparkpostmail\.com\.?$' {
            $result.mxProvider = 'SparkPost'
            $result.mxProviderHint = 'MX points to SparkPost inbound.'
            break
          }
          '(^|\.)hubspotemail\.net\.?$' {
            $result.mxProvider = 'HubSpot'
            $result.mxProviderHint = 'MX points to HubSpot inbound routing.'
            break
          }

          # --- Web Hosting, Registrars & Hosted Email ---
          '(^|\.)secureserver\.net\.?$|(^|\.)hosteurope\.de\.?$' {
            $result.mxProvider = 'GoDaddy Email / Workspace Email'
            $result.mxProviderHint = 'MX points to GoDaddy-hosted email.'
            break
          }
          '(^|\.)mailstore1\.secureserver\.net\.?$|(^|\.)smtp\.secureserver\.net\.?$' {
            $result.mxProvider = 'GoDaddy Email / Workspace Email'
            $result.mxProviderHint = 'MX points to GoDaddy-hosted email.'
            break
          }
          '(^|\.)emailsrvr\.com\.?$' {
            $result.mxProvider = 'Rackspace Email'
            $result.mxProviderHint = 'MX points to Rackspace Email.'
            break
          }
          '(^|\.)mxroute\.com\.?$' {
            $result.mxProvider = 'Mxroute'
            $result.mxProviderHint = 'MX points to Mxroute.'
            break
          }
          '(^|\.)mailhostbox\.com\.?$' {
            $result.mxProvider = 'Titan Email'
            $result.mxProviderHint = 'MX points to Titan Email.'
            break
          }
          '(^|\.)titan\.email\.?$' {
            $result.mxProvider = 'Titan Email'
            $result.mxProviderHint = 'MX points to Titan Email.'
            break
          }
          '(^|\.)prolocation\.(nl|net)\.?$' {
            $result.mxProvider = 'Prolocation'
            $result.mxProviderHint = 'MX points to Prolocation-hosted mail.'
            break
          }
          '(^|\.)intermedia\.net\.?$' {
            $result.mxProvider = 'Intermedia'
            $result.mxProviderHint = 'MX points to Intermedia-hosted email.'
            break
          }
          '(^|\.)hostedemail\.com\.?$' {
            $result.mxProvider = 'Intermedia'
            $result.mxProviderHint = 'MX points to Intermedia-hosted email.'
            break
          }
          '(^|\.)ovh\.net\.?$|(^|\.)mail\.ovh\.net\.?$' {
            $result.mxProvider = 'OVH Mail'
            $result.mxProviderHint = 'MX points to OVH Mail.'
            break
          }
          '(^|\.)ionos\.com\.?$|(^|\.)kundenserver\.de\.?$' {
            $result.mxProvider = 'IONOS Mail'
            $result.mxProviderHint = 'MX points to IONOS-hosted mail.'
            break
          }
          '(^|\.)1and1\.(com|de)\.?$' {
            $result.mxProvider = 'IONOS Mail'
            $result.mxProviderHint = 'MX points to IONOS-hosted mail.'
            break
          }
          '(^|\.)privateemail\.com\.?$' {
            $result.mxProvider = 'Namecheap Private Email'
            $result.mxProviderHint = 'MX points to Namecheap Private Email.'
            break
          }
          '(^|\.)registrar-servers\.com\.?$' {
            $result.mxProvider = 'Namecheap (Default)'
            $result.mxProviderHint = 'MX points to Namecheap default mail routing.'
            break
          }
          '(^|\.)hostinger\.com\.?$|(^|\.)tigomail\.net\.?$' {
            $result.mxProvider = 'Hostinger Email'
            $result.mxProviderHint = 'MX points to Hostinger-hosted email.'
            break
          }
          '(^|\.)mxlogin\.com\.?$|(^|\.)myregistersite\.com\.?$' {
            $result.mxProvider = 'Fasthosts / Newfold Email'
            $result.mxProviderHint = 'MX points to Fasthosts / Newfold-hosted email.'
            break
          }
          '(^|\.)websitewelcome\.com\.?$' {
            $result.mxProvider = 'Newfold Digital (Bluehost/HostGator)'
            $result.mxProviderHint = 'MX points to Newfold Digital shared hosting.'
            break
          }
          '(^|\.)gandi\.net\.?$' {
            $result.mxProvider = 'Gandi Mail'
            $result.mxProviderHint = 'MX points to Gandi-hosted email.'
            break
          }
          '(^|\.)dreamhost\.com\.?$' {
            $result.mxProvider = 'DreamHost'
            $result.mxProviderHint = 'MX points to DreamHost email.'
            break
          }
          '(^|\.)siteground\.com\.?$|(^|\.)sgvps\.net\.?$' {
            $result.mxProvider = 'SiteGround'
            $result.mxProviderHint = 'MX points to SiteGround hosting.'
            break
          }
          '(^|\.)a2hosting\.com\.?$' {
            $result.mxProvider = 'A2 Hosting'
            $result.mxProviderHint = 'MX points to A2 Hosting.'
            break
          }
          '(^|\.)inmotionhosting\.com\.?$|(^|\.)servconfig\.com\.?$' {
            $result.mxProvider = 'InMotion Hosting'
            $result.mxProviderHint = 'MX points to InMotion Hosting.'
            break
          }
          '(^|\.)liquidweb\.com\.?$' {
            $result.mxProvider = 'Liquid Web'
            $result.mxProviderHint = 'MX points to Liquid Web hosting.'
            break
          }
          '(^|\.)squarespace\.com\.?$' {
            $result.mxProvider = 'Squarespace'
            $result.mxProviderHint = 'MX points to Squarespace default routing.'
            break
          }

          # --- International & ISPs ---
          '(^|\.)yandex\.(ru|net|com)\.?$' {
            $result.mxProvider = 'Yandex Mail'
            $result.mxProviderHint = 'MX points to Yandex Mail.'
            break
          }
          '(^|\.)mail\.ru\.?$' {
            $result.mxProvider = 'Mail.ru'
            $result.mxProviderHint = 'MX points to Mail.ru.'
            break
          }
          '(^|\.)comcast\.net\.?$' {
            $result.mxProvider = 'Comcast'
            $result.mxProviderHint = 'MX points to Comcast / Xfinity.'
            break
          }
          '(^|\.)verizon\.net\.?$' {
            $result.mxProvider = 'Verizon'
            $result.mxProviderHint = 'MX points to Verizon.'
            break
          }
          '(^|\.)att\.net\.?$|(^|\.)sbcglobal\.net\.?$' {
            $result.mxProvider = 'AT&T'
            $result.mxProviderHint = 'MX points to AT&T / Yahoo infrastructure.'
            break
          }
          '(^|\.)charter\.net\.?$|(^|\.)spectrum\.com\.?$' {
            $result.mxProvider = 'Spectrum / Charter'
            $result.mxProviderHint = 'MX points to Spectrum.'
            break
          }
          '(^|\.)btinternet\.com\.?$' {
            $result.mxProvider = 'BT Group'
            $result.mxProviderHint = 'MX points to BT Internet (UK).'
            break
          }
          '(^|\.)virginmedia\.com\.?$' {
            $result.mxProvider = 'Virgin Media'
            $result.mxProviderHint = 'MX points to Virgin Media (UK).'
            break
          }
          '(^|\.)optusnet\.com\.au\.?$' {
            $result.mxProvider = 'Optus'
            $result.mxProviderHint = 'MX points to Optus (Australia).'
            break
          }
          '(^|\.)telstra\.com\.?$' {
            $result.mxProvider = 'Telstra'
            $result.mxProviderHint = 'MX points to Telstra (Australia).'
            break
          }

          # --- Default Catch-All ---
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
    $parentsChecked = New-Object System.Collections.Generic.List[string]
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

      $parent = $parent.Trim().TrimEnd('.')
      $parentsChecked.Add($parent)
      $parentResult = Invoke-MxLookupCore -LookupDomain $parent
      if (($parentResult.mxRecords.Count -gt 0) -or ($parentResult.mxRecordsDetailed.Count -gt 0)) {
        $mxResult = $parentResult
        $mxLookupDomain = $parent
        $mxFallbackUsed = $true
        break
      }
    }

    if ($parentsChecked.Count -gt 0) {
      $mxFallbackDomainChecked = ($parentsChecked -join ', ')
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
  $dmarcLookupDomain = $Domain
  $dmarcInherited = $false
  $organizationalDomain = Get-RegistrableDomain -Domain $Domain

  function Get-DmarcRecordValue {
    param([string]$LookupDomain)

    $recordValue = $null
    if ($dm = ResolveSafely "_dmarc.$LookupDomain" "TXT") {
      foreach ($r in $dm) {
        $j = ($r.Strings -join "").Trim()
        if ($j -match '(?i)^v=dmarc') {
          $recordValue = $j
          break
        }
      }
    }
    return $recordValue
  }

  $dmarc = Get-DmarcRecordValue -LookupDomain $Domain
  if (-not $dmarc) {
    $orgLabelCount = if ([string]::IsNullOrWhiteSpace($organizationalDomain)) { 0 } else { $organizationalDomain.Trim('.').Split('.').Count }
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

      $parentLabelCount = $parent.Trim('.').Split('.').Count
      if ($orgLabelCount -gt 0 -and $parentLabelCount -lt $orgLabelCount) { continue }

      $candidate = Get-DmarcRecordValue -LookupDomain $parent
      if ($candidate) {
        $dmarc = $candidate
        $dmarcLookupDomain = $parent
        $dmarcInherited = $true
        break
      }
    }
  }

  [pscustomobject]@{
    domain = $Domain
    dmarc = $dmarc
    dmarcLookupDomain = $dmarcLookupDomain
    dmarcInherited = $dmarcInherited
    dmarcOrganizationalDomain = $organizationalDomain
  }
}

# Check for the two ACS-specific DKIM selector CNAME/TXT records:
#   selector1-azurecomm-prod-net._domainkey.<domain>
#   selector2-azurecomm-prod-net._domainkey.<domain>
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

# Extract the CNAME target from DNS resolution result objects.
# Handles multiple property-name variants (CanonicalName, NameHost, NameTarget, Target)
# and filters out non-CNAME record types (e.g., SOA in authority section).
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
  $cnameLookupDomain = $Domain
  $cnameUsedWwwFallback = $false
  $normalizedDomain = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant()
  $labelCount = if ([string]::IsNullOrWhiteSpace($normalizedDomain)) { 0 } else { $normalizedDomain.Split('.').Count }
  $checkWwwFallback = ($normalizedDomain -notmatch '^(?i)www\.') -and ($labelCount -le 3)

  $lookupNames = if ($normalizedDomain -match '^(?i)www\.') { @($normalizedDomain) } elseif ($checkWwwFallback) { @($normalizedDomain, "www.$normalizedDomain") } else { @($normalizedDomain) }
  foreach ($name in $lookupNames) {
    $target = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
    if (-not [string]::IsNullOrWhiteSpace($target)) {
      $cname = $target
      $cnameLookupDomain = $name
      $cnameUsedWwwFallback = ($name -ne $normalizedDomain)
      break
    }
  }

  [pscustomobject]@{
    domain = $Domain
    cname = $cname
    cnameLookupDomain = $cnameLookupDomain
    cnameUsedWwwFallback = $cnameUsedWwwFallback
  }
}

# ------------------- DNSBL / REPUTATION CHECK -------------------
# Check whether the mail-server IPs for a domain are listed on DNS-based blocklists (DNSBLs).
# DNSBL queries work by reversing the IPv4 octets and appending the blocklist zone
# (e.g., 2.1.168.192.bl.spamcop.net). An A record response means the IP is listed.

# Reverse the octets of an IPv4 address for DNSBL queries.
# ===== DNSBL / Reputation Checking =====
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

function Clear-ExpiredRblCacheEntries {
  param(
    [int]$TtlSec = 180,
    [int]$MaxRemovalsPerPass = 256
  )

  if (-not $script:RblCache -or $script:RblCache.Count -eq 0) { return 0 }
  if ($TtlSec -le 0) { $TtlSec = 180 }
  if ($MaxRemovalsPerPass -le 0) { $MaxRemovalsPerPass = 1 }

  $cutoff = [DateTime]::UtcNow.AddSeconds(-1 * $TtlSec)
  $removed = 0

  foreach ($entry in @($script:RblCache.GetEnumerator())) {
    if ($removed -ge $MaxRemovalsPerPass) { break }

    $shouldRemove = $false
    if ($null -eq $entry.Value) {
      $shouldRemove = $true
    } else {
      try {
        $cachedAt = $entry.Value.cachedAt
        if ($null -eq $cachedAt -or $cachedAt -lt $cutoff) {
          $shouldRemove = $true
        }
      } catch {
        $shouldRemove = $true
      }
    }

    if ($shouldRemove) {
      $removedEntry = $null
      if ($script:RblCache.TryRemove($entry.Key, [ref]$removedEntry)) {
        $removed++
      }
    }
  }

  return $removed
}

# Query a single IPv4 address against a single DNSBL zone.
# Returns a result object indicating whether the IP is listed, along with the response address.
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

    # Some DNSBLs (including optional user-supplied zones) return policy-block addresses
    # (e.g., 127.255.255.240-255) when queries are blocked via public resolvers or without auth.
    # Treat those as errors, not listings.
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

# Perform DNSBL reputation checks for a domain by:
#   1. Resolving MX hosts (or A records as fallback) to get IPv4 addresses.
#   2. Querying each IP against each DNSBL zone (parallelized where possible).
#   3. Caching results with a short TTL to avoid repeated queries.
# Returns a summary with listed/clean/error counts and a risk assessment.
function Get-DnsReputationStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string[]]$RblZones,
    [int]$MaxTargets = 5
  )

  # Safer free/no-budget default DNSBL zones.
  $defaultZones = @(
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'psbl.surriel.com',
    'dnsbl.dronebl.org',
    'bl.0spam.org',
    'rbl.0spam.org'
  )

  $envZones = @()
  if ([string]::IsNullOrWhiteSpace(($RblZones -join ''))) {
    $envZoneText = [string]$env:ACS_RBL_ZONES
    if (-not [string]::IsNullOrWhiteSpace($envZoneText)) {
      $envZones = @($envZoneText -split '[,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
  }

  $zones = if ($RblZones -and $RblZones.Count -gt 0) { @($RblZones) } elseif ($envZones -and $envZones.Count -gt 0) { @($envZones) } else { $defaultZones }
  $zones = @($zones | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
  if (-not $zones -or $zones.Count -eq 0) {
    $zones = @($defaultZones)
  }

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
  $null = Clear-ExpiredRblCacheEntries -TtlSec $script:RblCacheTtlSec

  $targets = @()
  $ipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Prefer MX hosts, otherwise fall back to A on the root domain.
  $mx = @(Get-MxRecordObjects -Records (ResolveSafely $Domain 'MX'))
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
    foreach ($parentDomain in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parentDomain) -or $parentDomain -eq $Domain) { continue }

      $lookupDomain = $parentDomain
      $usedParent = $true
      $parentHosts = @()
      $parentMx = @(Get-MxRecordObjects -Records (ResolveSafely $parentDomain 'MX'))
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

      if ($ipSet.Count -gt 0) { break }
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
  $riskSummary = if ($listedCount -ge 2) { 'ElevatedRisk' } elseif ($listedCount -eq 1) { 'Warning' } else { 'Clean' }

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
      riskSummary = $riskSummary
    }
  }
}

# ===== Aggregated DNS Readiness =====
# ------------------- AGGREGATED DNS READINESS -------------------
# The main "check everything" function called by /dns and the CLI -TestDomain mode.
# Runs all individual checks (TXT/SPF, MX, DMARC, DKIM, CNAME, WHOIS) and assembles
# a single result object with guidance strings for the UI.
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
  $dmarcHelpUrl = 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records'

    # Guidance
    $guidance = New-Object System.Collections.Generic.List[string]

    if ($base.dnsFailed) {
        $guidance.Add("DNS TXT lookup failed or timed out. Other DNS records may still resolve.")
    } else {
      if (-not $base.spfPresent) {
        if ($base.parentSpfPresent -and $base.txtUsedParent -and $base.txtLookupDomain -and $base.txtLookupDomain -ne $Domain) {
          $guidance.Add("SPF is missing on $Domain. Parent domain $($base.txtLookupDomain) publishes SPF, but SPF does not automatically apply to the queried subdomain.")
        } else {
          $guidance.Add("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).")
        }
      }
      foreach ($spfMessage in @($base.spfGuidance)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$spfMessage)) { $guidance.Add([string]$spfMessage) }
      }
      if (-not $base.acsPresent) {
        if ($base.parentAcsPresent -and $base.txtUsedParent -and $base.txtLookupDomain -and $base.txtLookupDomain -ne $Domain) {
          $guidance.Add("ACS ms-domain-verification TXT is missing on $Domain. Parent domain $($base.txtLookupDomain) has an ACS TXT record, but it does not verify the queried subdomain.")
        } else {
          $guidance.Add("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.")
        }
      }
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
      elseif ($dmarc.dmarcInherited -and $dmarc.dmarcLookupDomain -and $dmarc.dmarcLookupDomain -ne $Domain) { $guidance.Add("Effective DMARC policy is inherited from parent domain $($dmarc.dmarcLookupDomain).") }
      $dmarcGuidance = @(Get-DmarcSecurityGuidance -DmarcRecord $dmarc.dmarc -Domain $Domain -LookupDomain $dmarc.dmarcLookupDomain -Inherited $dmarc.dmarcInherited)
      foreach ($dmarcMessage in $dmarcGuidance) {
        if (-not [string]::IsNullOrWhiteSpace($dmarcMessage)) { $guidance.Add($dmarcMessage) }
      }
      if ((-not $dmarc.dmarc) -or ($dmarcGuidance.Count -gt 0)) { $guidance.Add("For more information about DMARC TXT record syntax, see: $dmarcHelpUrl") }
      if (-not $dkim.dkim1)      { $guidance.Add("DKIM selector1 (selector1-azurecomm-prod-net) is missing.") }
      if (-not $dkim.dkim2)      { $guidance.Add("DKIM selector2 (selector2-azurecomm-prod-net) is missing.") }
      if (-not $cname.cname)     {
        if ($cname.cnameLookupDomain -and $cname.cnameLookupDomain -ne $Domain) {
          $guidance.Add("CNAME is not configured on $Domain. Validate whether the queried host or its www alias should resolve for your scenario.")
        } else {
          $guidance.Add("CNAME is not configured. Validate this is expected for your scenario.")
        }
      }

      # Provider-aware hints
      if ($mx.mxProvider -and $mx.mxProvider -ne 'Unknown') {
        $guidance.Add("Detected MX provider: $($mx.mxProvider)")
      }
      if ($mx.mxProvider -eq 'Microsoft 365 / Exchange Online' -and $base.spfPresent -and ($base.spfHasRequiredInclude -eq $false)) {
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

        txtLookupDomain = $base.txtLookupDomain
        txtUsedParent   = $base.txtUsedParent

        spfPresent = $base.spfPresent
        spfValue   = $base.spfValue
        spfAnalysis = $base.spfAnalysis
        spfExpandedText = $base.spfExpandedText
        spfGuidance = $base.spfGuidance
        spfHasRequiredInclude = $base.spfHasRequiredInclude
        spfRequiredInclude = $base.spfRequiredInclude
        spfRequiredIncludeMatchType = $base.spfRequiredIncludeMatchType
        spfRequiredIncludeDetail = $base.spfRequiredIncludeDetail
        spfRequiredIncludeError = $base.spfRequiredIncludeError
        parentSpfPresent = $base.parentSpfPresent
        parentSpfValue   = $base.parentSpfValue
        acsPresent = $base.acsPresent
        acsValue   = $base.acsValue
        parentAcsPresent = $base.parentAcsPresent
        parentAcsValue   = $base.parentAcsValue

        txtRecords = $base.txtRecords
        parentTxtRecords = $base.parentTxtRecords
        acsReady   = $acsReady

        mxRecords         = $mx.mxRecords
        mxRecordsDetailed = $mx.mxRecordsDetailed
        mxProvider        = $mx.mxProvider
        mxProviderHint    = $mx.mxProviderHint
        mxLookupDomain          = $mx.mxLookupDomain
        mxFallbackDomainChecked = $mx.mxFallbackDomainChecked
        mxFallbackUsed          = $mx.mxFallbackUsed

        whoisSource       = $whois.source
        whoisLookupDomain = $whois.lookupDomain
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
        dmarcLookupDomain = $dmarc.dmarcLookupDomain
        dmarcInherited = $dmarc.dmarcInherited
        dkim1      = $dkim.dkim1
        dkim2      = $dkim.dkim2
        cname      = $cname.cname
        cnameLookupDomain = $cname.cnameLookupDomain
        cnameUsedWwwFallback = $cname.cnameUsedWwwFallback

        guidance   = $guidance
    }
}

# ===== CLI One-Shot Mode =====
# ------------------- CLI ONE-SHOT MODE -------------------
# When -TestDomain is provided, run a full check, print JSON to stdout, and exit
# without starting the web server.
if (-not [string]::IsNullOrWhiteSpace($TestDomain)) {
  $cliDomain = ConvertTo-NormalizedDomain -Raw $TestDomain
  if ([string]::IsNullOrWhiteSpace($cliDomain) -or -not (Test-DomainName -Domain $cliDomain)) {
    [pscustomobject]@{
      mode = 'CliTest'
      error = 'Invalid domain parameter.'
      input = $TestDomain
    } | ConvertTo-Json -Depth 8
    return
  }

  $aggregate = Get-AcsDnsStatus -Domain $cliDomain
  $reputation = Get-DnsReputationStatus -Domain $cliDomain

  [pscustomobject]@{
    mode = 'CliTest'
    domain = $cliDomain
    collectedAtUtc = ([DateTime]::UtcNow.ToString('o'))
    aggregate = $aggregate
    reputation = $reputation
  } | ConvertTo-Json -Depth 8
  return
}

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

.language-dropdown {
  position: relative;
  min-width: 0;
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
  z-index: 50;
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
  .mx-table { display: block; max-width: 100%; overflow-x: auto; white-space: nowrap; }
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
# ===== HTML Body Structure & Script Setup =====
$htmlPage += @'

<!-- html2canvas for screenshot capture -->
<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js" integrity="sha384-ZZ1pncU3bQe8y31yfZdMFdSpttDoPmOZg2wguVK9almUodir1PghgT0eY7Mrty8H" crossorigin="anonymous"></script>
<!-- MSAL.js v2 for Microsoft Entra ID authentication (Authorization Code + PKCE) -->
<script nonce="__CSP_NONCE__">
const entraTenant = '__ENTRA_TENANT_ID__';
const acsApiKey = '__ACS_API_KEY__';
const acsIssueUrl = '__ACS_ISSUE_URL__';
const appVersion = '__APP_VERSION__';
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
  <div id="languageDropdown" class="language-dropdown hide-on-screenshot">
    <button id="languageSelectBtn" type="button" class="language-trigger" onclick="toggleLanguageMenu()" aria-haspopup="listbox" aria-expanded="false"></button>
    <div id="languageSelectMenu" class="language-menu" role="listbox"></div>
  </div>
  <button id="themeToggleBtn" type="button" class="hide-on-screenshot" onclick="toggleTheme()">Dark mode</button>
  <button id="copyLinkBtn" type="button" class="hide-on-screenshot" onclick="copyShareLink()">Copy link</button>
  <button id="screenshotBtn" type="button" class="hide-on-screenshot" onclick="screenshotPage()">Copy page screenshot</button>
  <button id="downloadBtn" type="button" class="hide-on-screenshot" onclick="downloadReport()" style="display:none;">Download JSON</button>
  <button id="reportIssueBtn" type="button" class="hide-on-screenshot" onclick="reportIssue()" style="display:none;" title="Report an issue (includes the domain name)">Report issue</button>
  <button id="msSignInBtn" type="button" class="hide-on-screenshot ms-sign-in-btn" onclick="msSignIn()">Sign in with Microsoft</button>
  <span id="msAuthStatus" class="ms-auth-status hide-on-screenshot" style="display:none;"></span>
  <button id="msSignOutBtn" type="button" class="hide-on-screenshot" onclick="msSignOut()" style="display:none;">Sign out</button>
</div>

<div class="search-box">
  <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAlgAAAE7CAYAAAAB7v+1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAACzzSURBVHhe7d15dFVVnujx+s+/3vLN9Htd3a7Vq1bZr/v1872uwXLEseiqrirEARzBGUUFlSEECAHFiAooCAEBCUOIiooiiiAKThXnaKkMQkiYcnMz3YyEIXD22/tyYiH+gAznnrP3ud/vWp/l6lZyz7mVs/ePc29ufkL2VJTfePry3Jb+y3Nb8wEAPVc8rmVo8bi2s/zllYiyrWXjms9ePr5tRklua1nJuDYFAAhQbmu7/ueGkrGtI1aMauvjL71EFNf036yGlOS2lf5oMQAAZE7uvkXmL7b+UkxEcWlZTmvf5bmtieW5bQoAEI3isW0rzdsy/KWZiFytaKI6rWTsvgLpQgcARKE1Yf7S6y/TRORaR9+83lb644sbABC1ZbktOf5yTUSulB6uxraWSRc1AMAODFlEDvX9cDVWX8AAAKsV57QN8ZdvIrI5fcFuOP4CBgDYa+nYtn7+Ek5ENmb+JiRdvAAAexWPbaswP5TkL+VEZFNFo9r6FI9tTWn6YgUAOKbAX86JyKaKx7aUCBcsAMAFOS3t/JodIstK373KMRcoAMBVy3JaC/1lnYhsqHhMa4F0sQIAHDKmpZ33YhFZkrkYi3NaEuLFCgBwy+iWof7yTkRRZn7lgniRAgBctMZf3okoypbktOToIcu8dg8AcF5Lwl/eiSjKlo1uKVk2Rl+UAIBYKBrReLq/xBNRVC0d01ImXaAAADctHdXEJ7sTRd2y0S3t0gUKAHDT0lHN/H5CoqiTLk4AgLsYsIgsSLo4AQDuYsAisqBlo/UFCQCIDQYsIgtaai5GAEB8MGARRd/S0S36ggQAxAYDFlH0iRcnAMBdDFhE0SdenAAAdzFgEUXf0lHmYgQAxAcDFlHkyRcnAMBdDFhEkbdEX4wAgPgoYsAiij7p4gQAuIsBi8iCpIsTAOAuBiwiC1oyUl+QAIDYKHqQAYso8qSLEwDgLgYsIgtaMrJZX5AAgLgoerCRAYso6qSLEwDgLgYsIgtarC9GAEB8MGARWdDiB/UFCQCIDQYsIguSLk4AgLsYsIgsSLo4AQDuYsAisiDp4gQAuIsBi8iCpIsTAOAuBiwiCyp6QF+MAID4GMGARRR54sUJAHAXAxZR9IkXJwDAXQxYRNEnXpwAAHcxYBFFX9H9+mIEAMQHAxZR9IkXJwDAXQxYRNEnXpwAAHcxYBFF36L7mxQAID4WMmARRZ90cQIA3MWARWRBi0boCxIAEBsMWEQWJF2cAAB3MWARWZB0cQIA3MWARWRB0sUJAHAXAxaRBT2rL0YAQHwwYBFZ0LPD9QUJAIiNhfcyYBFFnnRxAgDcxYBFZEHSxQkAcBcDFpEFSRcnAMBdDFhEFiRdnAAAdzFgEVnQs/fpCxIAEBsMWEQWtNBcjACA+GDAIoq+hfc16gsSABAbDFhE0SdenAAAdzFgEUWfeHECANzFgEUUffpCNBcjACA+GLCIok64MAEAbmPAIoq6BfpiBADEx3wGLKLoky5OAIC7GLCILEi6OAEA7mLAIrKgBffoCxIAEBvzhzFgEUWedHECANzFgEVkQQvuSekLEgAQF/OH1TNgEUWddHECANzFgEVkQfPNxQgAiA8GLKLomz/MXIwAgPhgwCKKPPniBAC4iwGLKPLkixMA4C4GLKLIky9OAIC7GLCIIk++OAEA7mLAIoq8Z+5OKQBAfMwdyoBFFHnSxQkAcBcDFpEFSRcnAMBdDFhEFiRdnAAAdzFgEVnQM3fpCxIAEBsMWEQWJF2cAAB3MWARWZB0cQIA3MWARWRB8+5qUACA+GDAIrIg6eIEALiLAYvIguYN1RckACA2GLCILEi6OAEA7mLAIrIg6eIEALiLAYvIgqSLEwDgLgYsIguam74YAQDxwYBFFHlz79QXIwAgPm5nwCKKPPHiBAC4iwGLKPrEixMA4C4GLKLoEy9OAIC7GLCIok+8OAEA7mLAIoq+uXfoixEAEB8MWETRV6gvRtivaExKvTSj6QeeuUf+b/FDS8f/+LmT/jscZb6vOp+n9cUt6t0XW79n/m/z/zfPqfRnYYfZDFhE0Vd4R72+IGGT5x5J6c2sRX31/j5VsWm/2rnlwAmZf1/2blv6v1/xWKP49bKJeQ4+XNWafu6k5+tY277arz5/p02981xL+jmXvl62eGnG0edty2ft4nMl6Xz+1i1uVgsfMBu7/LURPgYsIguSLk6Ez2xwn6xtS29a0mbWVVu/aE8PDEfvMMiPFTevFTapT99qU+Vf9+65M8NFNg0LRWMa0t9zvX3eDDPom6/FkG8HBiwiC5IuToSneFIqfRdA2rR6y2x4ZhOVHjcOzGbelTtV3WWGhfdXtsR20DLnZc7vVHdHe8p8P2fTgG8jBiwiCyq8XV+QCF3R6AZV+nqruEEF6fth4X49LAjH4aKl4zI3lB7L3E1cv6xZPAZXmTt0QdyxOpXO77tnhsnHgcxiwCKyIOniRGaZOy+9fSmwu8zLX8X5KfF4XPLanKZQBoRjmbtkrg+oZtAxL6NK55dJ337cnh6IpWNC5jBgEVnQHH0xIjxrFzdn7KWZUzGDyepnmsTjcsHGF1vE8wqDeW/bC3owlo7Ldkv0gGMGHem8wmC+716a7uZz5yoGLCILki5OZIb5KS1pAwrbmoVuDVnzIrr7cjwzGK+c6dagYAabsO/4SVx87lzGgEVkQdLFieDZMlx1cmnICuP9Vl1lBoXnpqTE47TNsvyUFcNVJ4as8DBgEVnQnNv0BYmMWlvULG44UVs9Tw9ZwvHa5L2Xo3tZ8ETM0JIesoTjtcWCEQ3plzWl449Sxbf71QtT9ZAlHDOCM/tWBiyiyJMuTgTnpWmN6U1F2myiZgYF8/4c6bhtYAZA6bhtsPnTdjXvbvm4bVC20Z67fsez/bmLAwYsIguac1udviCRCYtG1attX5m7CGbAstNX77eJxx61ZRMb/MHUXh+/2Soee9SO3vWTj9kWpa+3iMeOYMy+tYYBiyjqpIsTwTAbsLS52OatZealQvkcomIGP+lYbbNqjnm5Sz6HKJih3vbBtNPKp+x67uKEAYvIgmabixGBK5nSoCr1JuICc5dt7t3yeUThVT20SMdpo28/2ieeQ1Q+WNUiHqeNbHvuYoUBiyj6Zt9qLkYE7fO328RNxVbmLpZ0HlEwG690jLZ6dXajeB5hMy+r7vhWPkZb2fLcxQ8DFlHkyRcneqPkYXfuXnXa9mW7mnuXfD5hMhuudHw2S9+JEc4lbJ+uaxWPz2Zff2jHcxc/DFhEkSdfnOgN894raTOx3RsLor+LZd57JR2b7V6clhLPJyxmOHbt7lWnxbkN4jmhNxiwiCJPvjjRG+bjD6SNxHbmR/ul8wnL/OH14nG54M+rW8RzCot5w7h0XC54u6RZPCcbLZ7VqJbMbRItfDTaIfuHGLCIIk++ONFT5k6GtIm4wNwBMUOOdF5hMHfQpONygXmJVTqnsJgBTzouF0T9MqEZjMyA9NLb+9Sqj9rV2q0H095rOKLeb1a9sqH68Pdfb+XGfWrFa23px3pmXKbv2jFgEUXe7Fv0xYjAmM8gkjYRV6ye2yieVxhcfA/RsV4wdzCE8wqD+dR26ZhcMf8+PdgL5xWkhQUp9dwLrelBas2mg+qtyg5xKAqTGbxWlx1IH1Px4pajg5dw7N02hAGLKPLEixM95tpPwB3PDIjSeYXB1ZdWO71Z1CSeV6YtHuveD1UcLxPD6fz8lCrRA5UZYN6pPqze0wONC9bv6kjfSVumB665D/Rw8GTAIoq+p/XFiOC4+kbjTp+93SaeV6YtHOnu+686ffBqi3humbbiCXdflu5khlPp3Lpj3rgGVVzSkh5O3q5yZ6A6lXWVHemXF5csbFZz7qkXz/14sxiwiKJPujjRM4VD68TNwyXm98RJ55Zpyx38aIvjfbExmuH0dYffu9app8OpGaqee6VVvbWrQ72rh5FssPovB9KD5MmGLQYsIgt6+mZ9QSIQRealms16w3CcdG6Z9vKTjeKxuGTr53o4Fc4t095e3iwej0s+XtMqnptkzrB6Vby8JT1oSANItthQd0St+my/WlzY9KPniAGLyIKOvzDRc+mXaoTNwzXSuWVa+i6McCwuiWrAMnd/pONxSfqlaeHcjmUGiVc+2a/erj2iNjYpHGPd3sPqxY371IKCVPq5YsAisqDjFzH0HANWz214wf27MFENWObuj3Q8LvnyPXnAKnygXq14a59aqweIDXqQwKmtqehQKz/ev8Bf4okoqp6+uVYvZAjCiifi8hKhfH6Z9OaiOLxEuE88t0yLw3B6dMD66znNy61XL7+/T62vPSIOETi1d5q8ircbvREblDrNX+6JKMyOXdTQO0sn1Iubh0u2f23uwsjnl0mvzXV/wPrmIwasnjr6Hqyjg9VLZrBqOKIHBDMkoLfebvISDFpEEfT0EL1IIxBFOe4PWOkhQTi3TFvxuPt3/z5br4cE4dwy7fX57g+nG15vTb+/ShoQEAw9aKXeaVT5GxvV6f7yT0SZTFqw0TOFd9Ye/RwsYQNxRVRDQhyG0w9eaRbPLdOWT3Z3ON3+3QH1WXWH3vzNAIAwrNeD1noGLaLMJy3Y6DnzXhJpI3GFeblJOq8wmPcwScfkCnMnSTqvTHNxsK/Ysl99uUcPVo2eOAQg8/SglXi7UfX3twIiCrpZeoFGcFx/P4x5qU46rzB85PhPwy3KqRfPKwwuDfabKw6q9+qP6A3ebPKI2lvN3pq1LepMf0sgoqCSFmv0nMvvJTJ3QebcKZ9XGFx+L9GWz/eJ5xQWFwZ783LgR8nD6i2zqcMq65q8dj1oFfBGeKIAmzVYL9AI1HdftosbjO2+2NAqnk9Y5t3j/y5H4dhs9+FrLeI5hWXBA3XicdmizLwcmPLEzR028SrWNnn9/O2BiHqTtFijd959yc2XCV+ZlRLPJ0yfrHXzZcLiyQ3i+YTJDMjSsUVpS/lB9W79EbVOb95wSLO35vU21cffJoioJ0kLNXpn0Rj3fiLO3HWTziVsLr7Ean7yUjqXsJkBWTq+qHy565Ba1+jJGzgc4CXebFR9/a2CiLqbtFCj98ymK206tlq3pEk8jyh8U+rWTxPacOevkw3P3Y6tB1Rp8rBaqzdpuE8PWfn+dkFE3UlapNF75j0xrryfyNy9mnOHfB5RMC+3ScdpI/PTe9I5RCXqO4DmJcF3Go6IGzVc5m3gJUOibjbrJr0wIyNceS9W+g6McPxRcuG9WGaAXjKuXjz+KEV19/SLPR3qzUZPvak3ZMSRl3idN8ATdb2ZekFGZsy+vVZt+sTul7s+1oOMdOxRm39/nfU/jbm+uEk89qiF/dyVbz2gPqg9rNboTRjx92azV+BvH0R0smbeVKMXZWTK4nF1avtf7BwUzGc3zR1mNmX52KP2wmMNase3dj535if2Zt8uH7cNwnruvtt+IP2LmaWNGDHW7K15hV+1Q3TypMUZwbLtp7sMM/Q9O7pOPF6brF1i34ePflPaZvVg2inTz93W7QfV2pSn3tAbLrKRV8aQRXSSpIUZwVv9jD1DlrmzYe5wSMdpo3eebxLPIwrmrp8Lg2mnTD1331YwXEGp15u8ijcb1Rn+dkJExzbzRr0QIxRmyNrxTbQveZk7VyVT6sXjs5l5v5N0PmEyd67Sw5VwfDYLerj/uuKQeqPR05ur2WCR7VabN783qrP8LYWIOpMWZGTOS9MbIntPlnnDvYsDQqcoB9Qv321Vc++uFY/LBavmpAL5vvty5yG9oZpNFTiWl1rNh5IS/bCn9OKLcM0fUavK9IZdoTessJS+0aIK9YAgHY9LisbVqa9L28RzzAQz0JmX2Z6+TT4el/T2++7TPR3Cxgoc9VqT1/5ao+rvby1EJC3ECMdbxU3puwrSZhYUc9fq+ccaxMd3lRl2Nr7YlB5+pHMOylcftKUHOukYXLZ2caP6rmyfeM4n8okerl5Lb6LAya1qVEP87YUou5MWYITH3FUyd0iCHrTMm7HfeLYxFndeTsTckXlvZXPgg5YZrFbOSomPGRfm+6KrgxbDFbprFR9ISqQHrBv0govIFd5Vq95Y2Kg+f6fnL+GYQePTt1rUypl6OBAeI67mD69NDwu9eenQDLgfr21J/wCA9BhxZr5fzEvI0pBftvOQuSMRG8/tPaRW1nviv0NwXm302lfVe2f72wxRdiYtuIiWGbbMG7rNy2DmPTMnustgBgrz781dnBenNYhfK9s8O6ouPWyZ58Q8Nye6M2j+nWGe42wcqk7k+akN33/v/fmr/XqjNJul25btPqiGrtijznlsq/rJ2G/TzsjbpO5duTf976Q/gwCkvNQr/HQhZXNP3ZDUCysA/NX8eSn1Sv0ReeN0yIwvmtLDVOdgdTzz7574NCX+WQQg5VXoIYvPyaLsTFpcAWSvwqkNaqUervTG6KwVtYfVrct3iUOVZPY3LeLXQRC8zfqffOI7ZV9P6gUVAIzZk+vVi8kjaqXeGF1VuLlN/eaYlwO74l+mbFEl1R3i10PvvZzyyooq1Wn+tkOUHT15vV5YAWS9WQ/WqhW73R0yXqr31Mg3qsUBqity1iXFr4ugeGv8bYcoO5IWWgDZp2TTQfWy3ghd9KIerm7uxkuCkr/P26SWV3eIXx+Byfe3HqL4Jy20ALLLonVt6iW9Abqqt8NVpzHrkuLXR3Be5FfqULYkLbYAskfhtAb1Yv0RcTN0wfBVCXFY6onOu1jS4yAgR3+ykDe9U/yTFlwA2WHmvbXq+d0d5q6Ck+4LcLjqNHpdUnwsBCjlrfS3IKL4NuO6pAKQnZaV7Zc3QAdkYrgyzF2s4mp3h05XrGj0RvjbEFE8kxZdAPE3/9UWvcmZjc49EzbWisNRUMxdLOlxESSv/Xl+nQ7FOWnhBRBvs6c1qBfqjwibnv0WVB5I32WSBqOgmK+/rLpDfHwEiPdjUZyTFl8A8fXkLTVqeWWHeiGlnPTHeeXiUBS0UeuS4uMjaN4ifzsiilczrtWLLoCsMf/1VvW83thcNPH9OnEYyoRfP7ZVldR54nEgYLxUSHFMWoABxNPMB2rVc3VH5E3Ocgt3HVR/l+GXBo83ubRBPBYErMEr87ckovgkLcIA4mlx2X71nN7QXHTlwgpxCMokcxdreZ0nHg+CVVLPTxVSzJp+bbUCEH9zFjSKG5sLJpU2iANQGMxjS8eEoHntK2pUH39rInI/aSEGEC8zbk6qpbs6VIneyFxTXOepXz22VRx+wmAe2xyDdGwImlfib01E7jd9kF6AAcTa/Ddbhc3MDdO+bhEHnzDllzaIx4bgPcfvKqS4JC3GAOJjZn6dKq47opbrzctFg5bsFIeeMJm7WMvqPPH4EKzilLe5qFKd5m9RRO4mLcgA4uPZsv160zIbl3vmVBwQB54oTCxtEI8RwVvGG94pDkkLMoB4mFVQL25grrh/XVIcdqJg7mItrfPE40TQvAR3scj5pulFGEA8LSzbr5bpDctFi2oOq5+G/LlXp1LwZbN4rAjeEu5iketNG6gXYgCx82RurbhxuSIvwo9mOJHfzysXjxUZ0OBV+NsUkZtJCzMA9z2zsU0t1RuVq66I4INFu2Lq1y3i8SID6lR/f6sici9pYQbgthn316gldUfkTcsBhbsOisONDW57ea94zMgAfoUOuZy0OANwm7l7tURvUK4avbFWHG5s8L+mbBGPGZlRxF0scjVpcQbgLnP3qqjuiFqsNydXXfL0dnG4scXcPYfE40YGcBeLXG3aNXpRBhAb8za2yRuVIxbUHBaHGptIx43M4S4WOdkTekEGEB8Lqw6rIrMpOarAgl+NczK/eGyreNzInEX8jkJysSeuSehFGUAczCxsEDcol4y0+P1Xxn3rkuJxI3P0gNVe1KhO97ctIjeSFmkAbpr3abvejMyG5K5rl+8SBxsb/G3eJjU30SEeNzJrYYM31N+2iNxIWqQBuGfaXUm1sO6IuDm55I+Wfv6VMeb9OvGYkXnPprxSf9sicqMnrtaLMwDnzSpu0puQ2Yjcdu6MbeJwE7WJn8fj+XVZUaM6w9+6iOxPWqgBuGfepgNqod6EXPePU7aIA05ULn56u3pie7t4rAjXggaV729dRPb3uF6YAbhtek6NuCG5SBpyomAGvVHv14nHiIjw+wnJpaTFGoBbZq1qMX+7jwVp2Anb4Jf3qtlVHeLxIVrz672z/e2LyO6kxRqAW+ZVHBI3IxdJA09YLpq1XU3dsk88Llgi5RX62xeR3T1+lV6gAThrWk6Nmq83nriQBp9M+595m9TI9+rUvDpPPCZYpJ6XCcmRpAUbgDueKm6SNyJHnRPyTxFesXinerqqQzwW2GkuP01ILvT4VVV6kQbgqtl/3qee0ZtOXJiBRxqEMqHvrO1qTvKweByw19x6NcTfwojsTVqwAbhjbuKImqc3nbi45dWEOAwF7edTtqgndx8SjwG281b6WxiRvT2mF2gAbpr2UK2w+bht+IZwfhehGeSkx4cD6r2Uv4UR2dtjV+qFGoCTnny5Sc3VG06c5H/dIg5EQbtPD3LS48MNs2vUWf42RmRn0qINwA1Pf7Ff3HxcNmP3IXEgCto96xmwXFZY743wtzEiO5MWbQBumJM4ogrNZhMzZ4fwk4S/W1ghPjZcwfuwyPKkRRuA/Z54qFbYdOJh0At7xKEoaE9WdYiPDwfwPiyyPWnhBmC/6S83qTl6o4mj0R+nxIEoaOZxpMeHG3gfFlnd1AFVCoB7nny3Tc2u15tMDE3f2yEOREG7sniX+Phww9O13iB/KyOyL2nhBmC/p77cL246cfHHED5w9G/yNqlZtZ74+LDfrDqV429lRPYlLdwA7Ddzz2H1tN5k4mrkR+G8TJj7RbP4+LDfrHqvxN/KiOxLWrgBWO6OanHDiZNpIb1MeNOrCfHxYT89YJX5WxmRfU29Qi/WAJzy2ORavbmYDSbe/hDCy4Q/e3iLeqrWEx8flqvjJwnJ4qTFG4Ddnng2JW84MRPWy4STNu8THx/2m12j+vjbGZFdSYs3ALtNX9uqZurNJe6eCOllwiGrq8XHhwNqvH7+dkZkV49esVcBcMuMj/epp/Tmkg2uej7zHzr6qxnbxMeGA+q8of52RmRX0uINwG4zvjsobzYxlPuXcH7586Tv2sXHh+UavBn+dkZkV4/21ws2AKdM39mhntSbS7a4aG65OBQF6ZY3k+Jjw24zGrxF/nZGZFfS4g3Abk/WHBE3m7i678MGcSgK0r88tlVNr/XEx4fNvDX+dkZkV9LiDcBuM/TGkk2m6cHnf+sBSBqMgjT6i2bx8WEzb4O/nRHZlbR4A7DYdVXCJhN/5iU8aSgK0uULK8THhsXqvFJ/OyOyqwK9YANwx6Ojk2q63liyzaN7O1SfvE3iYBSkSeUHxMeHnabVexX+dkZkVwV/0os2AGc8OiqpNxWzsWSfASF8ZMONq6vFx4atGLDI0qQFHIC9pj5aK2wy2SG//IA4FAXJ3CV7vNYTHx828tr97YzIrqQFHIC9Hp1ep57QG0u2uiKEu1jDPmwQHxt28rczIruSFnAA9np0Zr24yWSLiSHcxbpwbrn42LDTxEp1mr+lEdmTtIADsNfUpY3qcb2pZLMbVleLg1GQcjfvEx8b9nm0UZ3hb2lE9lTwR71oA3AGA5ZSU/Z2qP+e4Z8ovPqlveJjwz4MWGRlj+gFG4A7CmbWq8f0ppLtbsrw52KZAe5hPchJjw278BIhWZm0gAOw2LQ6NVVvKtnuoRDuYt2ohzjpsWEXfzsjsqtH/rhHL9oAXFHwaI24yWQjMwBJg1FQzAA3sfKg+NiwBR/TQJYmLeAALDaqWj2qNxYoNXlvh/qnDP+Owj89v0d8bNihgA8aJVt75A96wQbgjpHVelMxGwuMOz9sEAejIN3/lxbxsRG9RxiwyNbEBRyAvQbuVQV1enNB2pQaT50/t1wcjILyf2dsSz+O9PiIGr/smSxtil6wAbjlEb2x4K/u/6pFHIyCdNu7deJjI2K13gZ/OyOyK2nxBmC55BE1RW8u+Ks/ZPhX6Pw384b3PR3iYyNK3hp/OyOyK3HxBmC3Sjb6443dfiA9BEnDUVDMECc9NqLzSJ23yN/OiOxqyr/rBQOAUx7aelA9rDcX/NB1Gf7YBmPkpn3iYyMq3gx/OyOyK2nxBmC3hz7apx7Smwt+aMKeDvWPGf7YhnPnlqtJNZ74+Ajf5KQ31N/OiOxqyr/v1gs2AJc8vLJJ3Gyg1G0fZP5jG8xjSI+N8OUnvbP97YzIrqTFG4DdHlpQrybrzQU/ll/jqXMy/LEN/zVvkxq/p0N8fIQrv0b18bczIrt6WC/WANzyUH5S3Gxw1L0hfGzDgFcS4mMjRLVeyt/KiOzr4d/rBRuAW67eoybpDQYn9vsMf2yDcY8e5KTHRlj4kFGyOHHxBmC9/MoOla83GchGbj+g/kuGP7bh7x/eokZXHBQfH5k3kY9oIJuTFm4A9ssv2y9uOvirgSF8bMMvZm1XeTWe+PjIsBqV429lRPYlLdwA7DdpfYuaWKv/Fo8TGru7Q/18amY/tsHo/0pCfHxk1oSk6u9vZUT2JS3cAOw3uTglbjr4oaGfN4tDUdDu+KRJfHxkTn6dOtPfyojs66Hf7VYA3DN5YlLl6U0Gp3bZsl3iUBQk836vkTsOio+P4E2o4ScIyfKkhRuAGybsOSxuPvihB7YdEIeioP3rzO1qfNITjwFB81b62xiRnT30u116oQbgorxP9qkJerPBqV29JvNveDf+9EpCfHwEaxy/IodsT1q0Abghv6hBjdebDU5t9O4O9XcPbxGHoqDdXJoSjwHByalWZ/jbGJGdPfRveqEG4KTJw6vEzQeywSH8nkLjP+dtUsO3tIvHgCB4Ff4WRmRv0qINwB3jKzrUOL3p4NTGJj31/2ZuF4eioP3z9G3pu2bScaB3cmv5gFFyIGnBBuCOCe+3iZsQZHd+mfnfU9jp13PL1Ziqw+JxoBdq1BB/CyOyt8l6gQbgrryiBv03evO3enTVJSF8bEOnC4t2qpykJx4Heob3X5ET6QU6dfyCDcAdk4ZXiZsQTmx4SB/b0Ony5/aIx4Ge4P1X5EiTf7urdHI/vVADcNa4LQfVWL35oOsGhPSxDZ3+/ZWEeBy9NXJ3h7p70z41JumJ/z5+vAJ/+yKyu4d+u7tQWrABuCPv+ZSwEeFkzGDy05A+tqHTwLdrxWPprlFVh9UNHzSocxZU/OgxzCA3Ykd8B+5xNeosf/sisrv8fpVDpQUbgDsm3blXjUkcUTk1Ct1w/fvhfGzDsW76c0o8lq4YXe2lj/lnXfgF1kM+bhK/htOSXpm/dRHZX/7llWdN7rdTL9IAXJb7WbsaozchdN0oPbCcFdLHNhzrls+axeM5mcF6YPqn6dvEr3ci5s9IX8tVo6pVjr91EbnRpH47yzQFwF15z9SJmxJO7ray8D62odN/ytuk7vhLm3g8xzP/3S8Ly8Wvcyrmce7ZdkD8ui4aVaP6+NsWkRvl/7ZyxKTf6kUagLsG7FJjdh9Wo/VGhO7puzS8j23o9LcPb1HD9PAjHY9x1+Z2dX7RTvHPdscv9HA2stoTH8MpSW+Nv2URudPECypP0wt0+48WbABOyX2nRd6ccFLDKw+l7/ZIA0ommce87v0G9eDevw7GZrC69Lk94n/fU1evr/3B+bpID4mD/C2LyK3yL6/MlxZsAO7Im5o0L6OgBwZurBOHkzhIv1RYflA8bxeMrPHaJ1aq0/ztisit0nexLt+5WVq0AbhjzI5D4iaFk3uw2ku/nCYNKHFw9oIK8bxdMJrfPUiul39Z5dnSgg3AHeOeS+m/8Zu/9aO77tzcLg4ncXHNxjrxvG2nhyw++4rcb9LlO2doCoCjrtilRlZ2qAf1xoTu+/2qanE4iYP/mLdJ3V1+UDxvWz1Q4630tyci95t42c5F+XqhBuCmseuaxc0KpzZi72H1D134IE9X/XpBhXje1kqq/v7WRBSPGLIAd028Y4+6P3FE/+3f3AFAd934WbM4nMTFwPcbxPO2Dp/cTnFt4uU7Z0iLNwD7mbtY4qaFLrko4I9KsIl5qXBY5SHxvG0ygrtXFOfyL63spwethLSAA7BX512s+/VGhe67b+9hdWY3fzWNS84p2imetzW4e0XZUH7fyj4TL9tZkn+ZXrgBOCNnbbO8eaFLbv12nzicxMWgP6fE87YBd68oq8rvV3nGxEt3FuhhKyUt5gDskuffxRphNiz0SP/1teJwEgfmpcK7Kg+J5x2l4dy9omzNfCjpePPS4aUVetiq2DDxskoFwE6j1zar4WbTQo/9ckGFOKDEwW+KdornHKV7uXtF9MPyL6w8Pf/Syr5w04RLKgflXVpRJm3S6ImKlXmXVQ6Vnusw5T5VM2B40jsgbWTomqGVh9T/eHiLOKDEwbUfN4nnHYX7uHtFRHHM3J3krmTv6CF1s/mtCP5TakV60xpxn9m80GOD9BAiDSdxYIbHu3Z1iOcdtmF8ajsRxTVz12PipXpYQLfowao9/bK5HlL9p9KqzJ0BaUND1/WL8ae8n7d0l3jOYbq3xpvhf7sSEcUzaYDAieVdUlGa37fyTP/pszI9YJ19b3oTQ29cEOPPxxr4cZN4zqFIeokRjep0/9uViCieSUMEfszctcq7uDLHf9qs775ab5G4uaHLhlV76uyineKA4rq/eXiLGrqrQzzvjKtWQ/xvUyKi+CYNE/ghF+5aHd+wGtXnnqSXuEdvaOi5u/YeVv+nsFwcUlxn7tBJ55xJw2q8Df63KBFRvMszAwREExy7a3V8dye9oXrQMm8mRi/cVnlI/Symn/R+a/lB8Zwzw2vX/+SN7USUHeVdoocJCNy7ayWlh6yyH2906C4ziJiX1aQhxWX91iTF882Eu2u9Av/bkogo/snDRfaacInbd62O784qdaYestrvTuoNDr0y5LsDsRuyfrVop3iugav2SgdXKit/6paIKCNJQ0b2isddq+MbWq2GiJseuu2W7Qdj9XJhGAPWXUkvpb8Hz/C/HYmIsiN50MguEy6pSMXprpWU3uQW3ZXe7NBbd+w5rH6pBxNpYHGNOQ/pHIOkhyx+HQ4RZV/SwJFVLq5Yk9+3so//dMQ28/KMHrI2Sxsguu/OhKcuXpkQhxaX/NvaWvH8gnI3HyhKRNnahIsrVTYaf3FFakLfyqz6PB7zfqyhSa99qN74EIw/bKgTBxdX3FJxSDyvINzJ+66IKJuTho/4y467VlK3V6shd5rND4G55osW1cfBN7//bn2teD7B4H1XRJTl6WHDDBxZYfzFO1IT+pZn/adI681vkbwpoqdu2dmhzl+xVxxkbJTZ4SqN910RUXYnDSIxlbV3rY7PvGxzR9Iru0NvhAjWwK/a1D9Y/FOGv1i0U139RYt47IHhfVdERHrAukgPHzE2/iLuWkkNblSn3570NosbJHrtio+a1D9b9Ct2zN21G747IB5rkPT3VIn/LUZElN1JQ0mMcNfqJJn3yOgNseL29MaITLjqixb1m5I94tCTaf8hb5O69I2kGlxxSDy24HlreFM7EZGfMJQ4b/xFOxLctepaQ6rUmbclvdRteoNE5ty857Dq/1FTetj66dSt4kAUhJ/P3K4uWJlIP5Z5TOlYMuHWpFdm7or631ZERDQ+PZDEyqL8CytZ6LvR7UnvbD1ktUsbJzLDDD8Dv9mn+q2vVZe8kVT/umhnejiShqaTMX/molXVasCnzWrwzg7xsTLPqxhSo7hTTER0bMKA4qRxF+1IjO+7vZ9/WtTNbkt4/W6t9tpvrVYK0bpxxyF1zdf71J9Km9Rv36pVV37Rkv6/jzVk92Hxz4bPSw3h4xiIiH7c+L56QHHdhdy1CiK9UQ65RW+aQNd47UP2qrP8bx8iIjo2cWBxxLgLuWsVdEMS3lB5MwWOpYerhMe1R0R0oqTBxQnctcpY5k7WzXoDvVlvpMCPeSnuXBERnaLxfXfogcUd4y4s565VCJm7E4PNXQq9oQKdBie8Cv1P3nNFRHSqxpmhxRG5F+7grlWImbsUesgyb2IWN1tkF/29UMZPCxIRdbFxF+rhxXYXlFeMPZ+7VlFkPifrpoRXMTi9wSJrJbwNgyv5nCsioi4nDjRWKS+YeEElnw4dYUOq1Rk3VXtlN+mNFlko6ZXwCe1ERN1MHmoscEH55nF9t53tHyZFnLl7cVPCKxU3YMTWjdVeof8tQERE3UkcbiLHXStbuzHpFdyY3ngRZzdUe6kb93qD/P/ZiYiou8kDTkS4a+VENya8fukNWNiYEQde2XVV6kz/f24iIupJ4y4wg40FzueulUuZnya7PuGV3qA3ZMSJV8j7rYiIAihXDzdRGnt++eYx53HXytWuT3oF8kYNl1xf7aWu4yVBIqLgkoaesOjhirtWMejahNfvOr1BX5/eqOEa/b8dLwkSEQWdNPhk2tgLdpRx1ypeDapWZ+iNes116Q0brrg26RXwkiARUQaSBqBMGXt+ebv+Z47/0BTDrqtS/a9LeAlpM4dFEt4G7loREWWw3PP18BOO0txzKlnQsyBzR8TcGRlU7bVfqzdzWEQPvwN5rxURUeYTBqFAjT2vvD33PO5aZWPmDokestaIGz3Cd/TlQH7dDRFRGI09v9y8dJcppbnnbOWuVZY3sEr1H5TwEoP0Jo/wDeTlQCKi8BOGol7LOW97e85527hrRd9nXjYcWOWNYNAKk1dmhlv/fwIiIgozaUDqJe5a0QnrHLQGmvcC6SEAmcBgRUQUeWPP00NRAHLO5a4VdT0zaF2tB62r9aB1jR4K0HtXM1gREdmTHo7Kjh+Wuu3c8g3ctaKepoeDIXrQqjh+YEAXJbwNV1Wrvv7TSURENqSHowJxaOqKc7encs4tH+J/KaJepYcFM2htuFoPDTi5q6q99quSXgmDFRGRpY3qW9nHvLwnDlAnoQerNebP+l+GKLAGVaszrqxSOVdXe5ul4SKr6QHUDKL9+bgFIiL7M3ehcszQ1BXctaIQ04PWmVclvBlXVnmJqxJKZSdv84Aqb8Q1NYq/0BARudboc7cNHXPO9nY9PJm7UyeyZtQvuWtF0WReDtPDxqLsGLa8zVqBGTD90yciIlczw1POOTsKx5xbXtE5VPlD15pRv9nez//PiCLPDB5X7PWGDkh4K69MeKkr9VDitCqvQp/LogF7vUHcqSIiIiIr6r9XnXVFlcq5ospbc0XCax+ghxab6eNM6OMsMUNi/2p1hn8aRERERPamh5a+5m7QgCqVb+5y6WGmVBp0Ms9LaRsGVHuF5ljMcfGyHxEREcUqc7fIDDnpu10Jb4a24TilV+jB6NS89uP+3AZz96y/GaL2qiHmMcyHqfoPS2RZP/nJ/wdOq0pFwlWT9QAAAABJRU5ErkJggg==" alt="ACS Logo" style="height: 64px; display: block; margin: 0 auto 12px auto;">
  <h1 id="appHeading">Azure Communication Services<br/>Email Domain Checker</h1>
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
<div id="azureDiagnosticsCard" class="card hide-on-screenshot" style="display:none; margin-bottom: 12px;">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="chevron">&#x25BC;</span>
    <span class="tag tag-info" id="azureDiagnosticsTag">AZURE</span>
    <strong id="azureDiagnosticsTitle">Azure Workspace Diagnostics</strong>
  </div>
  <div class="card-content">
    <div id="azureDiagnosticsHint" class="azure-note">Sign in to query customer Azure subscriptions and Log Analytics workspaces directly from your browser session.</div>
    <div id="azureSwitchDirectoryRow" class="azure-panel-field" style="display:none; margin-bottom:10px;">
      <label for="azureTenantInput" id="azureSwitchDirectoryLabel" style="font-size:12px;">Switch directory (tenant ID or domain)</label>
      <div style="display:flex; gap:6px;">
        <input id="azureTenantInput" type="text" placeholder="e.g. contoso.onmicrosoft.com" style="flex:1; padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--input-bg); color:var(--fg); font-size:13px;" />
        <button id="azureSwitchDirectoryBtn" type="button" onclick="switchAzureDirectory()" style="white-space:nowrap;">Switch</button>
      </div>
    </div>
    <div class="azure-panel-grid">
      <div class="azure-panel-field">
        <label for="azureSubscriptionSelect" id="azureSubscriptionLabel">Subscription</label>
        <select id="azureSubscriptionSelect"></select>
      </div>
      <div class="azure-panel-field">
        <label for="azureResourceSelect" id="azureResourceLabel">ACS Resource</label>
        <select id="azureResourceSelect"></select>
      </div>
      <div class="azure-panel-field">
        <label for="azureWorkspaceSelect" id="azureWorkspaceLabel">Workspace</label>
        <select id="azureWorkspaceSelect"></select>
      </div>
    </div>
    <div class="azure-panel-actions">
      <button id="azureRunInventoryBtn" type="button" class="primary" onclick="runAzureQueryTemplate('workspaceInventory')">Run workspace inventory</button>
      <button id="azureRunDomainSearchBtn" type="button" onclick="runAzureQueryTemplate('domainSearch')">Run domain search</button>
      <button id="azureRunAcsSearchBtn" type="button" onclick="runAzureQueryTemplate('acsSearch')">Run ACS search</button>
    </div>
    <div id="azureDiagnosticsStatus" class="azure-status"></div>
    <div id="azureDiagnosticsResults" class="azure-results-container"></div>
  </div>
</div>
<div id="results" class="cards"></div>

<div class="footer" id="footerText">
  ACS Email Domain Checker v__APP_VERSION__ &bull; Written by: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> &bull; Generated by PowerShell &bull; <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Back to Top</a>
</div>

</div>

<script nonce="__CSP_NONCE__">
let lastResult = null;
const HISTORY_KEY = "acsDomainHistory";
const LANG_KEY = "acsLanguage";

'@
# ===== JavaScript Translations & i18n Data =====
$htmlPage += @'
const TRANSLATIONS = {
  en: {
    languageName: 'English',
    appHeading: 'Azure Communication Services<br/>Email Domain Checker',
    placeholderDomain: 'example.com',
    lookup: 'Lookup',
    checkingShort: 'Checking',
    themeDark: 'Dark mode \uD83C\uDF19',
    themeLight: 'Light mode \u2600\uFE0F',
    copyLink: 'Copy link \uD83D\uDD17',
    copyScreenshot: 'Copy page screenshot \uD83D\uDCF8',
    downloadJson: 'Download JSON \uD83D\uDCE5',
    reportIssue: 'Report issue \uD83D\uDC1B',
    signInMicrosoft: 'Sign in with Microsoft \uD83D\uDD12',
    signOut: 'Sign out',
    termsOfService: 'Terms of Service',
    privacyStatement: 'Privacy',
    recent: 'Recent',
    footer: 'ACS Email Domain Checker v{version} \u2022 Written by: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 Generated by PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Back to Top</a>',
    statusChecking: 'Checking {domain} \u23F3',
    statusSomeChecksFailed: 'Some checks failed \u274C',
    statusTxtFailed: 'TXT lookup failed \u274C \u2014 other DNS records may still resolve.',
    statusCollectedOn: 'Collected on: {value}',
    emailQuota: 'Email Quota',
    domainVerification: 'Domain Verification',
    domainRegistration: 'Domain Registration (WHOIS/RDAP)',
    domain: 'Domain',
    mxRecords: 'MX Records',
    spfQueried: 'SPF (queried domain TXT)',
    acsDomainVerificationTxt: 'ACS Domain Verification TXT',
    txtRecordsQueried: 'TXT Records (queried domain)',
    dmarc: 'DMARC',
    reputationDnsbl: 'Reputation (DNSBL)',
    cname: 'CNAME',
    guidance: 'Guidance',
    helpfulLinks: 'Helpful Links',
    externalTools: 'External Tools',
    checklist: 'CHECKLIST',
    verificationTag: 'VERIFICATION',
    docs: 'DOCS',
    tools: 'TOOLS',
    readinessTips: 'READINESS TIPS',
    lookedUp: 'LOOKED UP',
    loading: 'LOADING',
    missing: 'MISSING',
    optional: 'OPTIONAL',
    info: 'INFO',
    error: 'ERROR',
    pass: 'PASS',
    fail: 'FAIL',
    warn: 'WARN',
    pending: 'PENDING',
    dnsError: 'DNS ERROR',
    newDomain: 'NEW DOMAIN',
    expired: 'EXPIRED',
    noRecordsAvailable: 'No Records Available.',
    noAdditionalGuidance: 'No additional guidance.',
    noAdditionalMxDetails: 'No additional MX details available.',
    additionalDetailsPlus: 'Additional Details +',
    additionalDetailsMinus: 'Additional Details -',
    copy: 'Copy',
    copyEmailQuota: 'Copy Email Quota',
    view: 'View',
    type: 'Type',
    addresses: 'Addresses',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    none: 'None',
    hostname: 'Hostname',
    priority: 'Priority',
    ipAddress: 'IP Address',
    status: 'Status',
    ipv4Addresses: 'IPv4 Addresses',
    ipv6Addresses: 'IPv6 Addresses',
    noIpAddressesFound: 'No IP Addresses Found',
    detectedProvider: 'Detected provider',
    loadingValue: 'Loading...',
    usingIpParent: 'Using IP addresses from parent domain {domain} (no A/AAAA on {queryDomain}).',
    noMxParentShowing: 'No MX records found on {domain}; showing MX for parent domain {lookupDomain}.',
    noMxParentChecked: 'No MX records found on {domain} or parent {parentDomain}.',
    resolvedUsingGuidance: 'Resolved using {lookupDomain} for guidance.',
    effectivePolicyInherited: 'Effective policy inherited from parent domain {lookupDomain}.',
    acsEmailDomainVerification: 'ACS Email Domain Verification',
    acsEmailQuotaLimitIncrease: 'ACS Email Quota Limit Increase',
    spfRecordBasics: 'SPF Record Basics',
    dmarcRecordBasics: 'DMARC Record Basics',
    dkimRecordBasics: 'DKIM Record Basics',
    mxRecordBasics: 'MX Record Basics',
    domainDossier: 'Domain Dossier (CentralOps)',
    multiRblLookup: 'MultiRBL DNSBL Lookup',
    copied: 'Copied! \u2714',
    languageLabel: 'Language',
    pageTitle: 'Azure Communication Services - Email Domain Checker',
    passing: 'Passing',
    failed: 'Failed',
    warningState: 'Warning',
    verified: 'VERIFIED',
    notVerified: 'NOT VERIFIED',
    notStarted: 'NOT STARTED',
    unknown: 'UNKNOWN',
    checkingMxRecords: 'Checking MX records...',
    checkingDnsblReputation: 'Checking DNSBL reputation...',
    waitingForTxtLookup: 'Waiting for TXT lookup...',
    waitingForBaseTxtLookup: 'Waiting for base TXT lookup...',
    dnsTxtLookup: 'DNS TXT Lookup',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    acsReadiness: 'ACS Readiness',
    resolvedSuccessfully: 'Resolved successfully.',
    addAcsTxtFromPortal: 'Add the ACS TXT from the Azure portal.',
    missingRequiredAcsTxt: 'Missing required ACS TXT.',
    unableDetermineAcsTxtValue: 'Unable to determine ACS TXT value.',
    txtLookupFailedOrTimedOut: 'TXT lookup failed or timed out.',
    msDomainVerificationFound: 'ms-domain-verification TXT found.',
    noSpfRecordDetected: 'No SPF record detected.',
    noMxRecordsDetected: 'No MX records detected.',
    checkingValue: 'Checking...',
    yes: 'Yes',
    no: 'No',
    source: 'Source',
    lookupDomainLabel: 'Lookup Domain',
    creationDate: 'Creation Date',
    registryExpiryDate: 'Registry Expiry Date',
    registrarLabel: 'Registrar',
    registrantLabel: 'Registrant',
    domainAgeLabel: 'Domain Age',
    domainExpiringIn: 'Domain Expiring in',
    daysUntilExpiry: 'Days until expiry',
    statusLabel: 'Status',
    noRegistrationInformation: 'No registration information available.',
    registrationDetailsUnavailable: 'Registration details unavailable.',
    newDomainUnderDays: 'New domain (under {days} days){suffix}',
    noteDomainLessThanDays: 'Domain is less than {days} days old.',
    rawLabel: 'Raw',
    zonesQueried: 'Zones queried',
    totalQueries: 'Total queries',
    errorsCount: 'Errors',
    listed: 'Listed',
    notListed: 'Not listed',
    riskLabel: 'Risk',
    reputationWord: 'Reputation',
    noSuccessfulQueries: 'Unknown (no successful queries)',
    listingsLabel: 'Listings',
    clean: 'Clean',
    excellent: 'Excellent',
    great: 'Great',
    good: 'Good',
    fair: 'Fair',
    poor: 'Poor',
    ageLabel: 'Age',
    expiresInLabel: 'Expires in',
    acsReadyMessage: 'This domain appears ready for Azure Communication Services domain verification.',
    guidanceDnsTxtFailed: 'DNS TXT lookup failed or timed out. Other DNS records may still resolve.',
    guidanceSpfMissingParent: 'SPF is missing on {domain}. Parent domain {lookupDomain} publishes SPF, but SPF does not automatically apply to the queried subdomain.',
    guidanceSpfMissing: 'SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).',
    guidanceAcsMissingParent: 'ACS ms-domain-verification TXT is missing on {domain}. Parent domain {lookupDomain} has an ACS TXT record, but it does not verify the queried subdomain.',
    guidanceAcsMissing: 'ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.',
    guidanceMxMissingParentFallback: 'No MX records found on {domain}; using parent domain {lookupDomain} MX records as a fallback.',
    guidanceMxMissingCheckedParent: 'No MX records detected for {domain} or its parent {parentDomain}. Mail flow will not function until MX records are configured.',
    guidanceMxMissing: 'No MX records detected. Mail flow will not function until MX records are configured.',
    guidanceMxParentShown: 'No MX records found on {domain}; results shown are from parent domain {lookupDomain}.',
    guidanceDmarcMissing: 'DMARC is missing. Add a _dmarc.{domain} TXT record to reduce spoofing risk.',
    guidanceDmarcInherited: 'Effective DMARC policy is inherited from parent domain {lookupDomain}.',
    guidanceDmarcMoreInfo: 'For more information about DMARC TXT record syntax, see: {url}',
    guidanceDkim1Missing: 'DKIM selector1 (selector1-azurecomm-prod-net) is missing.',
    guidanceDkim2Missing: 'DKIM selector2 (selector2-azurecomm-prod-net) is missing.',
    guidanceCnameMissing: 'CNAME is not configured on the queried host. Validate this is expected for your scenario.',
    guidanceMxProviderDetected: 'Detected MX provider: {provider}',
    guidanceMxMicrosoftSpf: 'Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.',
    guidanceMxGoogleSpf: 'Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.',
    guidanceMxZohoSpf: 'Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.',
    guidanceDomainExpired: 'Domain registration appears expired. Renew the domain before proceeding.',
    guidanceDomainVeryYoung: 'Domain was registered very recently (within {days} days). This is treated as an error signal for verification; ask the customer to allow more time.',
    guidanceDomainYoung: 'Domain was registered recently (within {days} days). Ask the customer to allow more time; Microsoft uses this signal to help prevent spammers from setting up new web addresses.',
    promptEnterDomain: 'Please enter a domain.',
    promptEnterValidDomain: 'Please enter a valid domain name (example: example.com).',
    clipboardUnavailable: 'Clipboard API not available in this browser.',
    linkCopiedToClipboard: 'Link copied to clipboard.',
    failedCopyLink: 'Failed to copy link to clipboard.',
    copiedToClipboard: 'Copied to clipboard.',
    failedCopyToClipboard: 'Failed to copy to clipboard.',
    nothingToCopyFor: 'Nothing to copy for {field}.',
    copiedFieldToClipboard: 'Copied {field} to clipboard.',
    failedCopyFieldToClipboard: 'Failed to copy {field} to clipboard.',
    screenshotClipboardUnsupported: 'Screenshot clipboard support is not available in this browser.',
    screenshotContainerNotFound: 'Container not found for screenshot.',
    screenshotCaptureFailed: 'Failed to capture screenshot.',
    screenshotCopiedToClipboard: 'Screenshot copied to clipboard.',
    failedCopyScreenshot: 'Failed to copy screenshot to clipboard.',
    screenshotRenderFailed: 'Screenshot capture failed.',
    issueReportingNotConfigured: 'Issue reporting is not configured.',
    issueReportConfirm: 'This will open the issue tracker and include {detail}. Continue?',
    issueReportDetailDomain: 'the domain name "{domain}"',
    issueReportDetailInput: 'the domain name from the input box',
    authSignInNotConfigured: 'Microsoft sign-in is not configured. Confirm the ACS_ENTRA_CLIENT_ID was injected into the page and refresh.',
    authLibraryLoadFailed: 'Microsoft sign-in library failed to load. Verify access to the MSAL CDN or provide a local msal-browser.min.js file.',
    authInitFailed: 'Microsoft sign-in failed to initialize. Check the browser console for details.',
    authInitFailedWithReason: 'Microsoft sign-in failed to initialize: {reason}',
    authSetClientIdAndRestart: 'Microsoft sign-in is not configured. Set the ACS_ENTRA_CLIENT_ID environment variable and restart.',
    authSigningIn: 'Signing in...',
    authSignInCancelled: 'Sign-in was cancelled.',
    authSignInFailed: 'Sign-in failed: {reason}',
    authUnknownError: 'Unknown error',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois',
    dmarcMonitorOnly: 'DMARC for {domain} is monitor-only (p=none). For stronger protection against spoofing, move to enforcement with p=quarantine or p=reject after validating legitimate mail sources.',
    dmarcQuarantine: 'DMARC for {domain} is set to p=quarantine. For the strongest anti-spoofing posture, consider p=reject once you confirm valid mail is fully aligned.',
    dmarcPct: 'DMARC enforcement for {domain} is only applied to {pct}% of messages (pct={pct}). Use pct=100 for full protection once rollout is validated.',
    dmarcAdkimRelaxed: 'DKIM alignment for {domain} uses relaxed mode (adkim=r). Consider strict alignment (adkim=s) if your sending infrastructure supports it for tighter domain protection.',
    dmarcAspfRelaxed: 'SPF alignment for {domain} uses relaxed mode (aspf=r). Consider strict alignment (aspf=s) if your senders consistently use the exact domain.',
    dmarcMissingSp: 'DMARC for subdomains of {lookupDomain} does not define an explicit subdomain policy (sp=). If you send from subdomains like {domain}, consider adding sp=quarantine or sp=reject for clearer protection.',
    dmarcMissingRua: 'DMARC for {domain} does not publish aggregate reporting (rua=). Adding a reporting mailbox improves visibility into spoofing attempts and enforcement impact.',
    dmarcMissingRuf: 'DMARC for {domain} does not publish forensic reporting (ruf=). If your process allows it, forensic reports can provide additional failure detail for investigations.',
    mxUsingParentNote: '(using MX from parent domain {lookupDomain})',
    parentCheckedNoMx: 'Checked parent domain {parentDomain} (no MX).',
    expiredOn: 'Expired on {date}',
    registrationAppearsExpired: 'Domain registration appears expired.',
    newDomainUnder90Days: 'New domain under 90 days old.',
    newDomainUnder180Days: 'New domain under 180 days old.',
    domainNameLabel: 'Domain Name',
    domainStatusLabel: 'Domain Status',
    mxRecordsLabel: 'MX Records',
    spfStatusLabel: 'SPF Status',
    dkim1StatusLabel: 'DKIM1 Status',
    dkim2StatusLabel: 'DKIM2 Status',
    dmarcStatusLabel: 'DMARC Status',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Azure Workspace Diagnostics',
    azureDiagnosticsHint: 'Sign in to query customer Azure subscriptions and Log Analytics workspaces directly from your browser session. No customer query data is sent to the local server.',
    azureSubscription: 'Subscription',
    azureAcsResource: 'ACS Resource',
    azureWorkspace: 'Workspace',
    azureLoadSubscriptions: 'Load subscriptions',
    azureDiscoverResources: 'Discover ACS resources',
    azureDiscoverWorkspaces: 'Discover workspaces',
    azureRunInventory: 'Run workspace inventory',
    azureRunDomainSearch: 'Run domain search',
    azureRunAcsSearch: 'Run ACS search',
    azureSignInRequired: 'Sign in with Microsoft to query Azure subscriptions and Log Analytics from the browser.',
    azureLoadingSubscriptions: 'Loading subscriptions...',
    azureLoadingTenants: 'Discovering tenants...',
    azureLoadingTenantSubscriptions: 'Loading subscriptions for tenant {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'Checking {current}/{total} subscriptions for ACS resources...',
    azureLoadingResources: 'Discovering ACS resources...',
    azureLoadingWorkspaces: 'Discovering connected workspaces...',
    azureRunningQuery: 'Running query: {name}',
    azureNoSubscriptions: 'No Azure subscriptions were returned for this user.',
    azureNoResources: 'No ACS resources were found in the selected subscription.',
    azureSubscriptionNotEnabled: 'The selected subscription is {state}. Resource discovery requires an Enabled subscription.',
    azureNoWorkspaces: 'No connected Log Analytics workspaces were found. Check diagnostic settings on the selected ACS resources.',
    azureSelectSubscriptionFirst: 'Select a subscription first.',
    azureSelectWorkspaceFirst: 'Select a workspace first.',
    azureDomainRequired: 'Enter a domain before running the domain search query.',
    azureWorkspaceInventory: 'Workspace inventory',
    azureDomainSearch: 'Domain search',
    azureAcsSearch: 'ACS search',
    azureResultsSummary: 'Tenant: {tenant} \u2022 Subscription: {subscription} \u2022 Workspace: {workspace}',
    azureQueryReturnedNoTables: 'The query completed but returned no tables.',
    azureQueryFailed: 'Azure query failed: {reason}',
    azureDiscoverSuccess: 'Discovery complete. Select a workspace and run a query.',
    azureSignedInAs: 'Signed in as {user}',
    azureConsentRequired: 'Additional Azure permissions are required. Approve the consent prompt to continue.',
    azureQueryTextLabel: 'Executed query',
    azureSwitchDirectory: 'Switch directory (tenant ID or domain)',
    azureSwitchBtn: 'Switch',
    guidanceIconInformational: 'Informational',
    guidanceIconError: 'Error',
    guidanceIconAttention: 'Needs Attention',
    guidanceIconSuccess: 'Success',
    guidanceLegendAttention: 'Attention',
    guidanceLegendInformational: 'Informational'
  },
  es: {
    languageName: 'Espa\u00F1ol',
    appHeading: 'Azure Communication Services<br/>Comprobador de dominio de correo',
    placeholderDomain: 'ejemplo.com',
    lookup: 'Buscar',
    checkingShort: 'Comprobando',
    themeDark: 'Modo oscuro \uD83C\uDF19',
    themeLight: 'Modo claro \u2600\uFE0F',
    copyLink: 'Copiar v\u00EDnculo \uD83D\uDD17',
    copyScreenshot: 'Copiar captura \uD83D\uDCF8',
    downloadJson: 'Descargar JSON \uD83D\uDCE5',
    reportIssue: 'Reportar problema \uD83D\uDC1B',
    signInMicrosoft: 'Iniciar sesi\u00F3n con Microsoft \uD83D\uDD12',
    signOut: 'Cerrar sesi\u00F3n',
    termsOfService: 'T\u00E9rminos de servicio',
    privacyStatement: 'Privacidad',
    recent: 'Recientes',
    footer: 'ACS Email Domain Checker v{version} \u2022 Escrito por: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 Generado por PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Volver arriba</a>',
    statusChecking: 'Comprobando {domain} \u23F3',
    statusSomeChecksFailed: 'Algunas comprobaciones fallaron \u274C',
    statusTxtFailed: 'La b\u00FAsqueda TXT fall\u00F3 \u274C \u2014 otros registros DNS a\u00FAn pueden resolverse.',
    statusCollectedOn: 'Recopilado el: {value}',
    emailQuota: 'Cuota de correo',
    domainVerification: 'Verificaci\u00F3n del dominio',
    domainRegistration: 'Registro del dominio (WHOIS/RDAP)',
    domain: 'Dominio',
    mxRecords: 'Registros MX',
    spfQueried: 'SPF (TXT del dominio consultado)',
    acsDomainVerificationTxt: 'TXT de verificaci\u00F3n de dominio ACS',
    txtRecordsQueried: 'Registros TXT (dominio consultado)',
    dmarc: 'DMARC',
    reputationDnsbl: 'Reputaci\u00F3n (DNSBL)',
    cname: 'CNAME',
    guidance: 'Gu\u00EDa',
    helpfulLinks: 'Enlaces \u00FAtiles',
    externalTools: 'Herramientas externas',
    checklist: 'LISTA',
    verificationTag: 'VERIFICACI\u00D3N',
    docs: 'DOCS',
    tools: 'HERRAMIENTAS',
    readinessTips: 'CONSEJOS',
    lookedUp: 'CONSULTADO',
    loading: 'CARGANDO',
    missing: 'FALTA',
    optional: 'OPCIONAL',
    info: 'INFO',
    error: 'ERROR',
    pass: 'OK',
    fail: 'FALLO',
    warn: 'AVISO',
    pending: 'PENDIENTE',
    dnsError: 'ERROR DNS',
    newDomain: 'DOMINIO NUEVO',
    expired: 'VENCIDO',
    noRecordsAvailable: 'No hay registros disponibles.',
    noAdditionalGuidance: 'No hay orientaci\u00F3n adicional.',
    noAdditionalMxDetails: 'No hay detalles MX adicionales disponibles.',
    additionalDetailsPlus: 'Detalles adicionales +',
    additionalDetailsMinus: 'Detalles adicionales -',
    copy: 'Copiar',
    copyEmailQuota: 'Copiar cuota de correo',
    view: 'Ver',
    type: 'Tipo',
    addresses: 'Direcciones',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    none: 'Ninguno',
    hostname: 'Nombre de host',
    priority: 'Prioridad',
    ipAddress: 'Direcci\u00F3n IP',
    status: 'Estado',
    ipv4Addresses: 'Direcciones IPv4',
    ipv6Addresses: 'Direcciones IPv6',
    noIpAddressesFound: 'No se encontraron IP',
    detectedProvider: 'Proveedor detectado',
    loadingValue: 'Cargando...',
    usingIpParent: 'Usando direcciones IP del dominio primario {domain} (sin A/AAAA en {queryDomain}).',
    noMxParentShowing: 'No se encontraron MX en {domain}; se muestran los MX del dominio primario {lookupDomain}.',
    noMxParentChecked: 'No se encontraron MX en {domain} ni en el dominio primario {parentDomain}.',
    resolvedUsingGuidance: 'Resuelto usando {lookupDomain} como referencia.',
    effectivePolicyInherited: 'La directiva efectiva se hereda del dominio primario {lookupDomain}.',
    acsEmailDomainVerification: 'Verificaci\u00F3n de dominio de correo ACS',
    acsEmailQuotaLimitIncrease: 'Aumento del l\u00EDmite de cuota de correo ACS',
    spfRecordBasics: 'Conceptos b\u00E1sicos de SPF',
    dmarcRecordBasics: 'Conceptos b\u00E1sicos de DMARC',
    dkimRecordBasics: 'Conceptos b\u00E1sicos de DKIM',
    mxRecordBasics: 'Conceptos b\u00E1sicos de MX',
    domainDossier: 'Domain Dossier (CentralOps)',
    multiRblLookup: 'Consulta DNSBL de MultiRBL',
    copied: '\u00A1Copiado! \u2714',
    languageLabel: 'Idioma',
    pageTitle: 'Azure Communication Services - Comprobador de dominio de correo',
    passing: 'Correcto',
    failed: 'Fall\u00F3',
    warningState: 'Aviso',
    verified: 'VERIFICADO',
    notVerified: 'NO VERIFICADO',
    notStarted: 'NO INICIADO',
    unknown: 'DESCONOCIDO',
    checkingMxRecords: 'Comprobando registros MX...',
    checkingDnsblReputation: 'Comprobando reputaci\u00F3n DNSBL...',
    waitingForTxtLookup: 'Esperando la b\u00FAsqueda TXT...',
    waitingForBaseTxtLookup: 'Esperando la b\u00FAsqueda TXT base...',
    dnsTxtLookup: 'B\u00FAsqueda DNS TXT',
    acsTxtMsDomainVerification: 'TXT ACS (ms-domain-verification)',
    acsReadiness: 'Estado de ACS',
    resolvedSuccessfully: 'Resuelto correctamente.',
    addAcsTxtFromPortal: 'Agregue el TXT de ACS desde Azure Portal.',
    missingRequiredAcsTxt: 'Falta el TXT de ACS requerido.',
    unableDetermineAcsTxtValue: 'No se pudo determinar el valor TXT de ACS.',
    txtLookupFailedOrTimedOut: 'La b\u00FAsqueda TXT fall\u00F3 o agot\u00F3 el tiempo.',
    msDomainVerificationFound: 'Se encontr\u00F3 el TXT ms-domain-verification.',
    noSpfRecordDetected: 'No se detect\u00F3 ning\u00FAn registro SPF.',
    noMxRecordsDetected: 'No se detectaron registros MX.',
    checkingValue: 'Comprobando...',
    yes: 'S\u00ED',
    no: 'No',
    source: 'Origen',
    lookupDomainLabel: 'Dominio consultado',
    creationDate: 'Fecha de creaci\u00F3n',
    registryExpiryDate: 'Fecha de expiraci\u00F3n del registro',
    registrarLabel: 'Registrador',
    registrantLabel: 'Titular',
    domainAgeLabel: 'Edad del dominio',
    domainExpiringIn: 'El dominio vence en',
    daysUntilExpiry: 'D\u00EDas hasta el vencimiento',
    statusLabel: 'Estado',
    noRegistrationInformation: 'No hay informaci\u00F3n de registro disponible.',
    registrationDetailsUnavailable: 'Detalles de registro no disponibles.',
    newDomainUnderDays: 'Dominio nuevo (menos de {days} d\u00EDas){suffix}',
    noteDomainLessThanDays: 'El dominio tiene menos de {days} d\u00EDas.',
    rawLabel: 'Sin procesar',
    zonesQueried: 'Zonas consultadas',
    totalQueries: 'Consultas totales',
    errorsCount: 'Errores',
    listed: 'En listas',
    notListed: 'No listado',
    riskLabel: 'Riesgo',
    reputationWord: 'Reputaci\u00F3n',
    noSuccessfulQueries: 'Desconocida (sin consultas correctas)',
    listingsLabel: 'Listados',
    clean: 'Limpio',
    excellent: 'Excelente',
    great: 'Muy buena',
    good: 'Buena',
    fair: 'Regular',
    poor: 'Mala',
    ageLabel: 'Edad',
    expiresInLabel: 'Vence en',
    acsReadyMessage: 'Este dominio parece listo para la verificaci\u00F3n de dominio de Azure Communication Services.',
    guidanceDnsTxtFailed: 'La b\u00FAsqueda DNS TXT fall\u00F3 o agot\u00F3 el tiempo. Otros registros DNS a\u00FAn pueden resolverse.',
    guidanceSpfMissingParent: 'Falta SPF en {domain}. El dominio primario {lookupDomain} publica SPF, pero SPF no se aplica autom\u00E1ticamente al subdominio consultado.',
    guidanceSpfMissing: 'Falta SPF. Agregue v=spf1 include:spf.protection.outlook.com -all (o el equivalente de su proveedor).',
    guidanceAcsMissingParent: 'Falta el TXT ACS ms-domain-verification en {domain}. El dominio primario {lookupDomain} tiene un TXT ACS, pero no verifica el subdominio consultado.',
    guidanceAcsMissing: 'Falta el TXT ACS ms-domain-verification. Agregue el valor desde Azure Portal.',
    guidanceMxMissingParentFallback: 'No se encontraron registros MX en {domain}; se usar\u00E1n los MX del dominio primario {lookupDomain} como alternativa.',
    guidanceMxMissingCheckedParent: 'No se detectaron registros MX para {domain} ni para su dominio primario {parentDomain}. El flujo de correo no funcionar\u00E1 hasta configurar MX.',
    guidanceMxMissing: 'No se detectaron registros MX. El flujo de correo no funcionar\u00E1 hasta configurar MX.',
    guidanceMxParentShown: 'No se encontraron registros MX en {domain}; los resultados mostrados son del dominio primario {lookupDomain}.',
    guidanceDmarcMissing: 'Falta DMARC. Agregue un registro TXT _dmarc.{domain} para reducir el riesgo de suplantaci\u00F3n.',
    guidanceDmarcInherited: 'La directiva DMARC efectiva se hereda del dominio primario {lookupDomain}.',
    guidanceDmarcMoreInfo: 'Para m\u00E1s informaci\u00F3n sobre la sintaxis del registro TXT DMARC, vea: {url}',
    guidanceDkim1Missing: 'Falta DKIM selector1 (selector1-azurecomm-prod-net).',
    guidanceDkim2Missing: 'Falta DKIM selector2 (selector2-azurecomm-prod-net).',
    guidanceCnameMissing: 'CNAME no est\u00E1 configurado en el host consultado. Valide si esto es lo esperado para su escenario.',
    guidanceMxProviderDetected: 'Proveedor MX detectado: {provider}',
    guidanceMxMicrosoftSpf: 'Su MX indica Microsoft 365, pero SPF no incluye spf.protection.outlook.com. Verifique que SPF incluya el include correcto del proveedor.',
    guidanceMxGoogleSpf: 'Su MX indica Google Workspace, pero SPF no incluye _spf.google.com. Verifique que SPF incluya el include correcto del proveedor.',
    guidanceMxZohoSpf: 'Su MX indica Zoho, pero SPF no incluye include:zoho.com. Verifique que SPF incluya el include correcto del proveedor.',
    guidanceDomainExpired: 'El registro del dominio parece expirado. Renu\u00E9velo antes de continuar.',
    guidanceDomainVeryYoung: 'El dominio se registr\u00F3 muy recientemente (dentro de {days} d\u00EDas). Esto se trata como una se\u00F1al de error para la verificaci\u00F3n; pida al cliente que espere m\u00E1s tiempo.',
    guidanceDomainYoung: 'El dominio se registr\u00F3 recientemente (dentro de {days} d\u00EDas). Pida al cliente que espere m\u00E1s tiempo; Microsoft usa esta se\u00F1al para ayudar a evitar que los remitentes maliciosos configuren nuevos dominios.',
    dmarcMonitorOnly: 'DMARC para {domain} est\u00E1 en modo solo supervisi\u00F3n (p=none). Para una protecci\u00F3n m\u00E1s s\u00F3lida contra la suplantaci\u00F3n, cambie a enforcement con p=quarantine o p=reject despu\u00E9s de validar las fuentes leg\u00EDtimas de correo.',
    dmarcQuarantine: 'DMARC para {domain} est\u00E1 configurado con p=quarantine. Para la protecci\u00F3n m\u00E1s fuerte contra la suplantaci\u00F3n, considere p=reject cuando confirme que el correo leg\u00EDtimo est\u00E1 completamente alineado.',
    dmarcPct: 'La aplicaci\u00F3n de DMARC para {domain} solo se aplica al {pct}% de los mensajes (pct={pct}). Use pct=100 para una protecci\u00F3n completa cuando termine la validaci\u00F3n del despliegue.',
    dmarcAdkimRelaxed: 'La alineaci\u00F3n DKIM para {domain} usa modo relajado (adkim=r). Considere alineaci\u00F3n estricta (adkim=s) si su infraestructura de env\u00EDo lo permite para una protecci\u00F3n m\u00E1s fuerte del dominio.',
    dmarcAspfRelaxed: 'La alineaci\u00F3n SPF para {domain} usa modo relajado (aspf=r). Considere alineaci\u00F3n estricta (aspf=s) si sus remitentes usan siempre el dominio exacto.',
    dmarcMissingSp: 'DMARC para subdominios de {lookupDomain} no define una directiva expl\u00EDcita para subdominios (sp=). Si env\u00EDa desde subdominios como {domain}, considere agregar sp=quarantine o sp=reject para una protecci\u00F3n m\u00E1s clara.',
    dmarcMissingRua: 'DMARC para {domain} no publica informes agregados (rua=). Agregar un buz\u00F3n de informes mejora la visibilidad sobre intentos de suplantaci\u00F3n y el impacto de la aplicaci\u00F3n.',
    dmarcMissingRuf: 'DMARC para {domain} no publica informes forenses (ruf=). Si su proceso lo permite, estos informes pueden aportar m\u00E1s detalle para investigaciones.'
  },
  fr: {
    languageName: 'Fran\u00E7ais',
    appHeading: 'Azure Communication Services<br/>V\u00E9rificateur de domaine e-mail',
    placeholderDomain: 'exemple.com',
    lookup: 'Rechercher',
    checkingShort: 'V\u00E9rification',
    themeDark: 'Mode sombre \uD83C\uDF19',
    themeLight: 'Mode clair \u2600\uFE0F',
    copyLink: 'Copier le lien \uD83D\uDD17',
    copyScreenshot: 'Copier la capture \uD83D\uDCF8',
    downloadJson: 'T\u00E9l\u00E9charger le JSON \uD83D\uDCE5',
    reportIssue: 'Signaler un probl\u00E8me \uD83D\uDC1B',
    signInMicrosoft: 'Se connecter avec Microsoft \uD83D\uDD12',
    signOut: 'Se d\u00E9connecter',
    termsOfService: 'Conditions d\'utilisation',
    privacyStatement: 'Confidentialit\u00E9',
    recent: 'R\u00E9cents',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u00C9crit par : <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 G\u00E9n\u00E9r\u00E9 par PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Retour en haut</a>',
    statusChecking: 'V\u00E9rification de {domain} \u23F3',
    statusSomeChecksFailed: 'Certaines v\u00E9rifications ont \u00E9chou\u00E9 \u274C',
    statusTxtFailed: 'La recherche TXT a \u00E9chou\u00E9 \u274C \u2014 les autres enregistrements DNS peuvent encore r\u00E9pondre.',
    statusCollectedOn: 'Collect\u00E9 le : {value}',
    emailQuota: 'Quota e-mail',
    domainVerification: 'V\u00E9rification du domaine',
    domainRegistration: 'Enregistrement du domaine (WHOIS/RDAP)',
    domain: 'Domaine',
    mxRecords: 'Enregistrements MX',
    spfQueried: 'SPF (TXT du domaine interrog\u00E9)',
    acsDomainVerificationTxt: 'TXT de v\u00E9rification de domaine ACS',
    txtRecordsQueried: 'Enregistrements TXT (domaine interrog\u00E9)',
    dmarc: 'DMARC',
    reputationDnsbl: 'R\u00E9putation (DNSBL)',
    cname: 'CNAME',
    guidance: 'Conseils',
    helpfulLinks: 'Liens utiles',
    externalTools: 'Outils externes',
    checklist: 'CHECKLIST',
    verificationTag: 'V\u00C9RIFICATION',
    docs: 'DOCS',
    tools: 'OUTILS',
    readinessTips: 'CONSEILS',
    lookedUp: 'CONSULT\u00C9',
    loading: 'CHARGEMENT',
    missing: 'MANQUANT',
    optional: 'OPTIONNEL',
    info: 'INFO',
    error: 'ERREUR',
    pass: 'OK',
    fail: '\u00C9CHEC',
    warn: 'AVERT.',
    pending: 'EN ATTENTE',
    dnsError: 'ERREUR DNS',
    newDomain: 'NOUVEAU DOMAINE',
    expired: 'EXPIR\u00C9',
    noRecordsAvailable: 'Aucun enregistrement disponible.',
    noAdditionalGuidance: 'Aucun conseil suppl\u00E9mentaire.',
    noAdditionalMxDetails: 'Aucun d\u00E9tail MX suppl\u00E9mentaire disponible.',
    additionalDetailsPlus: 'D\u00E9tails suppl\u00E9mentaires +',
    additionalDetailsMinus: 'D\u00E9tails suppl\u00E9mentaires -',
    copy: 'Copier',
    copyEmailQuota: 'Copier le quota e-mail',
    view: 'Voir',
    type: 'Type',
    addresses: 'Adresses',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    none: 'Aucune',
    hostname: 'Nom d\u2019h\u00F4te',
    priority: 'Priorit\u00E9',
    ipAddress: 'Adresse IP',
    status: 'Statut',
    ipv4Addresses: 'Adresses IPv4',
    ipv6Addresses: 'Adresses IPv6',
    noIpAddressesFound: 'Aucune adresse IP trouv\u00E9e',
    detectedProvider: 'Fournisseur d\u00E9tect\u00E9',
    loadingValue: 'Chargement...',
    usingIpParent: 'Utilisation des adresses IP du domaine parent {domain} (aucun A/AAAA sur {queryDomain}).',
    noMxParentShowing: 'Aucun MX trouv\u00E9 sur {domain} ; affichage des MX du domaine parent {lookupDomain}.',
    noMxParentChecked: 'Aucun MX trouv\u00E9 sur {domain} ni sur le domaine parent {parentDomain}.',
    resolvedUsingGuidance: 'R\u00E9solu avec {lookupDomain} \u00E0 titre indicatif.',
    effectivePolicyInherited: 'La strat\u00E9gie effective est h\u00E9rit\u00E9e du domaine parent {lookupDomain}.',
    acsEmailDomainVerification: 'V\u00E9rification du domaine e-mail ACS',
    acsEmailQuotaLimitIncrease: 'Augmentation de la limite de quota e-mail ACS',
    spfRecordBasics: 'Notions de base SPF',
    dmarcRecordBasics: 'Notions de base DMARC',
    dkimRecordBasics: 'Notions de base DKIM',
    mxRecordBasics: 'Notions de base MX',
    domainDossier: 'Domain Dossier (CentralOps)',
    multiRblLookup: 'Recherche DNSBL MultiRBL',
    copied: 'Copi\u00E9 ! \u2714',
    languageLabel: 'Langue',
    promptEnterDomain: 'Veuillez saisir un domaine.',
    promptEnterValidDomain: 'Veuillez saisir un nom de domaine valide (exemple : example.com).',
    clipboardUnavailable: 'L\u2019API du presse-papiers n\u2019est pas disponible dans ce navigateur.',
    linkCopiedToClipboard: 'Lien copi\u00E9 dans le presse-papiers.',
    failedCopyLink: '\u00C9chec de la copie du lien dans le presse-papiers.',
    copiedToClipboard: 'Copi\u00E9 dans le presse-papiers.',
    failedCopyToClipboard: '\u00C9chec de la copie dans le presse-papiers.',
    nothingToCopyFor: 'Rien \u00E0 copier pour {field}.',
    copiedFieldToClipboard: '{field} copi\u00E9 dans le presse-papiers.',
    failedCopyFieldToClipboard: '\u00C9chec de la copie de {field} dans le presse-papiers.',
    screenshotClipboardUnsupported: 'La prise en charge de la copie de capture d\u2019\u00E9cran n\u2019est pas disponible dans ce navigateur.',
    screenshotContainerNotFound: 'Conteneur introuvable pour la capture d\u2019\u00E9cran.',
    screenshotCaptureFailed: '\u00C9chec de la capture d\u2019\u00E9cran.',
    screenshotCopiedToClipboard: 'Capture d\u2019\u00E9cran copi\u00E9e dans le presse-papiers.',
    failedCopyScreenshot: '\u00C9chec de la copie de la capture d\u2019\u00E9cran dans le presse-papiers.',
    screenshotRenderFailed: 'La capture d\u2019\u00E9cran a \u00E9chou\u00E9.',
    issueReportingNotConfigured: 'Le signalement de probl\u00E8me n\u2019est pas configur\u00E9.',
    issueReportConfirm: 'Le suivi des probl\u00E8mes va s\u2019ouvrir et inclure {detail}. Continuer ?',
    issueReportDetailDomain: 'le nom de domaine \u00AB {domain} \u00BB',
    issueReportDetailInput: 'le nom de domaine du champ de saisie',
    authSignInNotConfigured: 'La connexion Microsoft n\u2019est pas configur\u00E9e. V\u00E9rifiez que ACS_ENTRA_CLIENT_ID a bien \u00E9t\u00E9 inject\u00E9 dans la page puis actualisez.',
    authLibraryLoadFailed: 'La biblioth\u00E8que de connexion Microsoft n\u2019a pas pu \u00EAtre charg\u00E9e. V\u00E9rifiez l\u2019acc\u00E8s au CDN MSAL ou fournissez un fichier local msal-browser.min.js.',
    authInitFailed: 'L\u2019initialisation de la connexion Microsoft a \u00E9chou\u00E9. V\u00E9rifiez la console du navigateur pour plus de d\u00E9tails.',
    authInitFailedWithReason: 'L\u2019initialisation de la connexion Microsoft a \u00E9chou\u00E9 : {reason}',
    authSetClientIdAndRestart: 'La connexion Microsoft n\u2019est pas configur\u00E9e. D\u00E9finissez la variable d\u2019environnement ACS_ENTRA_CLIENT_ID puis red\u00E9marrez.',
    authSigningIn: 'Connexion en cours...',
    authSignInCancelled: 'La connexion a \u00E9t\u00E9 annul\u00E9e.',
    authSignInFailed: '\u00C9chec de la connexion : {reason}',
    authUnknownError: 'Erreur inconnue',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois'
  },
  de: {
    languageName: 'Deutsch',
    appHeading: 'Azure Communication Services<br/>E-Mail-Domain-Pr\u00FCfer',
    placeholderDomain: 'beispiel.de',
    lookup: 'Pr\u00FCfen',
    checkingShort: 'Pr\u00FCfung',
    themeDark: 'Dunkler Modus \uD83C\uDF19',
    themeLight: 'Heller Modus \u2600\uFE0F',
    copyLink: 'Link kopieren \uD83D\uDD17',
    copyScreenshot: 'Seitenbild kopieren \uD83D\uDCF8',
    downloadJson: 'JSON herunterladen \uD83D\uDCE5',
    reportIssue: 'Problem melden \uD83D\uDC1B',
    signInMicrosoft: 'Mit Microsoft anmelden \uD83D\uDD12',
    signOut: 'Abmelden',
    termsOfService: 'Nutzungsbedingungen',
    privacyStatement: 'Datenschutz',
    recent: 'Zuletzt verwendet',
    footer: 'ACS Email Domain Checker v{version} \u2022 Erstellt von: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 Generiert mit PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Nach oben</a>',
    statusChecking: 'Pr\u00FCfe {domain} \u23F3',
    statusSomeChecksFailed: 'Einige Pr\u00FCfungen sind fehlgeschlagen \u274C',
    statusTxtFailed: 'TXT-Abfrage fehlgeschlagen \u274C \u2014 andere DNS-Eintr\u00E4ge k\u00F6nnen trotzdem aufl\u00F6sbar sein.',
    statusCollectedOn: 'Erfasst am: {value}',
    emailQuota: 'E-Mail-Kontingent',
    domainVerification: 'Domain\u00FCberpr\u00FCfung',
    domainRegistration: 'Domainregistrierung (WHOIS/RDAP)',
    domain: 'Domain',
    mxRecords: 'MX-Eintr\u00E4ge',
    spfQueried: 'SPF (TXT der abgefragten Domain)',
    acsDomainVerificationTxt: 'ACS-Domainverifizierungs-TXT',
    txtRecordsQueried: 'TXT-Eintr\u00E4ge (abgefragte Domain)',
    dmarc: 'DMARC',
    reputationDnsbl: 'Reputation (DNSBL)',
    cname: 'CNAME',
    guidance: 'Hinweise',
    helpfulLinks: 'Hilfreiche Links',
    externalTools: 'Externe Tools',
    checklist: 'CHECKLISTE',
    verificationTag: 'VERIFIZIERUNG',
    docs: 'DOKS',
    tools: 'TOOLS',
    readinessTips: 'TIPPS',
    lookedUp: 'ABGEFRAGT',
    loading: 'LADEN',
    missing: 'FEHLT',
    optional: 'OPTIONAL',
    info: 'INFO',
    error: 'FEHLER',
    pass: 'OK',
    fail: 'FEHLER',
    warn: 'WARNUNG',
    pending: 'AUSSTEHEND',
    dnsError: 'DNS-FEHLER',
    newDomain: 'NEUE DOMAIN',
    expired: 'ABGELAUFEN',
    noRecordsAvailable: 'Keine Eintr\u00E4ge verf\u00FCgbar.',
    noAdditionalGuidance: 'Keine weiteren Hinweise.',
    noAdditionalMxDetails: 'Keine zus\u00E4tzlichen MX-Details verf\u00FCgbar.',
    additionalDetailsPlus: 'Zus\u00E4tzliche Details +',
    additionalDetailsMinus: 'Zus\u00E4tzliche Details -',
    copy: 'Kopieren',
    copyEmailQuota: 'E-Mail-Kontingent kopieren',
    view: 'Anzeigen',
    type: 'Typ',
    addresses: 'Adressen',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    none: 'Keine',
    hostname: 'Hostname',
    priority: 'Priorit\u00E4t',
    ipAddress: 'IP-Adresse',
    status: 'Status',
    ipv4Addresses: 'IPv4-Adressen',
    ipv6Addresses: 'IPv6-Adressen',
    noIpAddressesFound: 'Keine IP-Adressen gefunden',
    detectedProvider: 'Erkannter Anbieter',
    loadingValue: 'Wird geladen...',
    usingIpParent: 'IP-Adressen der \u00FCbergeordneten Domain {domain} werden verwendet (kein A/AAAA f\u00FCr {queryDomain}).',
    noMxParentShowing: 'Keine MX-Eintr\u00E4ge f\u00FCr {domain}; MX der \u00FCbergeordneten Domain {lookupDomain} werden angezeigt.',
    noMxParentChecked: 'Keine MX-Eintr\u00E4ge f\u00FCr {domain} oder die \u00FCbergeordnete Domain {parentDomain} gefunden.',
    resolvedUsingGuidance: 'Zur Orientierung mit {lookupDomain} aufgel\u00F6st.',
    effectivePolicyInherited: 'Die wirksame Richtlinie wird von der \u00FCbergeordneten Domain {lookupDomain} geerbt.',
    acsEmailDomainVerification: 'ACS-E-Mail-Domainverifizierung',
    acsEmailQuotaLimitIncrease: 'ACS-E-Mail-Kontingenterh\u00F6hung',
    spfRecordBasics: 'SPF-Grundlagen',
    dmarcRecordBasics: 'DMARC-Grundlagen',
    dkimRecordBasics: 'DKIM-Grundlagen',
    mxRecordBasics: 'MX-Grundlagen',
    domainDossier: 'Domain Dossier (CentralOps)',
    multiRblLookup: 'MultiRBL-DNSBL-Abfrage',
    copied: 'Kopiert! \u2714',
    languageLabel: 'Sprache',
    promptEnterDomain: 'Bitte geben Sie eine Domain ein.',
    promptEnterValidDomain: 'Bitte geben Sie einen g\u00FCltigen Domainnamen ein (Beispiel: example.com).',
    clipboardUnavailable: 'Die Zwischenablage-API ist in diesem Browser nicht verf\u00FCgbar.',
    linkCopiedToClipboard: 'Link in die Zwischenablage kopiert.',
    failedCopyLink: 'Der Link konnte nicht in die Zwischenablage kopiert werden.',
    copiedToClipboard: 'In die Zwischenablage kopiert.',
    failedCopyToClipboard: 'Kopieren in die Zwischenablage fehlgeschlagen.',
    nothingToCopyFor: 'F\u00FCr {field} gibt es nichts zu kopieren.',
    copiedFieldToClipboard: '{field} wurde in die Zwischenablage kopiert.',
    failedCopyFieldToClipboard: '{field} konnte nicht in die Zwischenablage kopiert werden.',
    screenshotClipboardUnsupported: 'Die Zwischenablageunterst\u00FCtzung f\u00FCr Screenshots ist in diesem Browser nicht verf\u00FCgbar.',
    screenshotContainerNotFound: 'Container f\u00FCr Screenshot nicht gefunden.',
    screenshotCaptureFailed: 'Screenshot konnte nicht erstellt werden.',
    screenshotCopiedToClipboard: 'Screenshot in die Zwischenablage kopiert.',
    failedCopyScreenshot: 'Screenshot konnte nicht in die Zwischenablage kopiert werden.',
    screenshotRenderFailed: 'Die Screenshot-Erstellung ist fehlgeschlagen.',
    issueReportingNotConfigured: 'Die Problemmeldung ist nicht konfiguriert.',
    issueReportConfirm: 'Der Issue-Tracker wird ge\u00F6ffnet und enth\u00E4lt {detail}. Fortfahren?',
    issueReportDetailDomain: 'den Domainnamen \u201E{domain}\u201C',
    issueReportDetailInput: 'den Domainnamen aus dem Eingabefeld',
    authSignInNotConfigured: 'Microsoft-Anmeldung ist nicht konfiguriert. Pr\u00FCfen Sie, ob ACS_ENTRA_CLIENT_ID in die Seite eingef\u00FCgt wurde, und laden Sie sie neu.',
    authLibraryLoadFailed: 'Die Microsoft-Anmeldebibliothek konnte nicht geladen werden. Pr\u00FCfen Sie den Zugriff auf das MSAL-CDN oder stellen Sie eine lokale Datei `msal-browser.min.js` bereit.',
    authInitFailed: 'Die Microsoft-Anmeldung konnte nicht initialisiert werden. Pr\u00FCfen Sie die Browserkonsole auf Details.',
    authInitFailedWithReason: 'Die Microsoft-Anmeldung konnte nicht initialisiert werden: {reason}',
    authSetClientIdAndRestart: 'Microsoft-Anmeldung ist nicht konfiguriert. Legen Sie die Umgebungsvariable ACS_ENTRA_CLIENT_ID fest und starten Sie neu.',
    authSigningIn: 'Anmeldung l\u00E4uft...',
    authSignInCancelled: 'Die Anmeldung wurde abgebrochen.',
    authSignInFailed: 'Anmeldung fehlgeschlagen: {reason}',
    authUnknownError: 'Unbekannter Fehler',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois'
  },
  'pt-BR': {
    languageName: 'Portugu\u00EAs (Brasil)',
    appHeading: 'Azure Communication Services<br/>Verificador de dom\u00EDnio de e-mail',
    placeholderDomain: 'exemplo.com.br',
    lookup: 'Verificar',
    checkingShort: 'Verificando',
    themeDark: 'Modo escuro \uD83C\uDF19',
    themeLight: 'Modo claro \u2600\uFE0F',
    copyLink: 'Copiar link \uD83D\uDD17',
    copyScreenshot: 'Copiar captura da p\u00E1gina \uD83D\uDCF8',
    downloadJson: 'Baixar JSON \uD83D\uDCE5',
    reportIssue: 'Relatar problema \uD83D\uDC1B',
    signInMicrosoft: 'Entrar com Microsoft \uD83D\uDD12',
    signOut: 'Sair',
    termsOfService: 'Termos de servi\u00E7o',
    privacyStatement: 'Privacidade',
    recent: 'Recentes',
    footer: 'ACS Email Domain Checker v{version} \u2022 Escrito por: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 Gerado por PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Voltar ao topo</a>',
    statusChecking: 'Verificando {domain} \u23F3',
    statusSomeChecksFailed: 'Algumas verifica\u00E7\u00F5es falharam \u274C',
    statusTxtFailed: 'A consulta TXT falhou \u274C \u2014 outros registros DNS ainda podem resolver.',
    statusCollectedOn: 'Coletado em: {value}',
    emailQuota: 'Cota de e-mail',
    domainVerification: 'Verifica\u00E7\u00E3o de dom\u00EDnio',
    domainRegistration: 'Registro de dom\u00EDnio (WHOIS/RDAP)',
    domain: 'Dom\u00EDnio',
    mxRecords: 'Registros MX',
    spfQueried: 'SPF (TXT do dom\u00EDnio consultado)',
    acsDomainVerificationTxt: 'TXT de verifica\u00E7\u00E3o de dom\u00EDnio ACS',
    txtRecordsQueried: 'Registros TXT (dom\u00EDnio consultado)',
    dmarc: 'DMARC',
    reputationDnsbl: 'Reputa\u00E7\u00E3o (DNSBL)',
    cname: 'CNAME',
    guidance: 'Orienta\u00E7\u00F5es',
    helpfulLinks: 'Links \u00FAteis',
    externalTools: 'Ferramentas externas',
    checklist: 'CHECKLIST',
    verificationTag: 'VERIFICA\u00C7\u00C3O',
    docs: 'DOCS',
    tools: 'FERRAMENTAS',
    readinessTips: 'DICAS',
    lookedUp: 'CONSULTADO',
    loading: 'CARREGANDO',
    missing: 'AUSENTE',
    optional: 'OPCIONAL',
    info: 'INFO',
    error: 'ERRO',
    pass: 'OK',
    fail: 'FALHA',
    warn: 'AVISO',
    pending: 'PENDENTE',
    dnsError: 'ERRO DNS',
    newDomain: 'DOM\u00CDNIO NOVO',
    expired: 'EXPIRADO',
    noRecordsAvailable: 'Nenhum registro dispon\u00EDvel.',
    noAdditionalGuidance: 'Nenhuma orienta\u00E7\u00E3o adicional.',
    noAdditionalMxDetails: 'Nenhum detalhe MX adicional dispon\u00EDvel.',
    additionalDetailsPlus: 'Detalhes adicionais +',
    additionalDetailsMinus: 'Detalhes adicionais -',
    copy: 'Copiar',
    copyEmailQuota: 'Copiar cota de e-mail',
    view: 'Ver',
    type: 'Tipo',
    addresses: 'Endere\u00E7os',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    none: 'Nenhum',
    hostname: 'Hostname',
    priority: 'Prioridade',
    ipAddress: 'Endere\u00E7o IP',
    status: 'Status',
    ipv4Addresses: 'Endere\u00E7os IPv4',
    ipv6Addresses: 'Endere\u00E7os IPv6',
    noIpAddressesFound: 'Nenhum endere\u00E7o IP encontrado',
    detectedProvider: 'Provedor detectado',
    loadingValue: 'Carregando...',
    usingIpParent: 'Usando endere\u00E7os IP do dom\u00EDnio pai {domain} (sem A/AAAA em {queryDomain}).',
    noMxParentShowing: 'Nenhum MX encontrado em {domain}; exibindo MX do dom\u00EDnio pai {lookupDomain}.',
    noMxParentChecked: 'Nenhum MX encontrado em {domain} ou no dom\u00EDnio pai {parentDomain}.',
    resolvedUsingGuidance: 'Resolvido usando {lookupDomain} como refer\u00EAncia.',
    effectivePolicyInherited: 'A pol\u00EDtica efetiva \u00E9 herdada do dom\u00EDnio pai {lookupDomain}.',
    acsEmailDomainVerification: 'Verifica\u00E7\u00E3o de dom\u00EDnio de e-mail ACS',
    acsEmailQuotaLimitIncrease: 'Aumento do limite de cota de e-mail ACS',
    spfRecordBasics: 'No\u00E7\u00F5es b\u00E1sicas de SPF',
    dmarcRecordBasics: 'No\u00E7\u00F5es b\u00E1sicas de DMARC',
    dkimRecordBasics: 'No\u00E7\u00F5es b\u00E1sicas de DKIM',
    mxRecordBasics: 'No\u00E7\u00F5es b\u00E1sicas de MX',
    domainDossier: 'Domain Dossier (CentralOps)',
    multiRblLookup: 'Consulta DNSBL MultiRBL',
    copied: 'Copiado! \u2714',
    languageLabel: 'Idioma',
    promptEnterDomain: 'Insira um dom\u00EDnio.',
    promptEnterValidDomain: 'Insira um nome de dom\u00EDnio v\u00E1lido (exemplo: example.com).',
    clipboardUnavailable: 'A API da \u00E1rea de transfer\u00EAncia n\u00E3o est\u00E1 dispon\u00EDvel neste navegador.',
    linkCopiedToClipboard: 'Link copiado para a \u00E1rea de transfer\u00EAncia.',
    failedCopyLink: 'Falha ao copiar o link para a \u00E1rea de transfer\u00EAncia.',
    copiedToClipboard: 'Copiado para a \u00E1rea de transfer\u00EAncia.',
    failedCopyToClipboard: 'Falha ao copiar para a \u00E1rea de transfer\u00EAncia.',
    nothingToCopyFor: 'N\u00E3o h\u00E1 nada para copiar em {field}.',
    copiedFieldToClipboard: '{field} copiado para a \u00E1rea de transfer\u00EAncia.',
    failedCopyFieldToClipboard: 'Falha ao copiar {field} para a \u00E1rea de transfer\u00EAncia.',
    screenshotClipboardUnsupported: 'O suporte para copiar capturas de tela para a \u00E1rea de transfer\u00EAncia n\u00E3o est\u00E1 dispon\u00EDvel neste navegador.',
    screenshotContainerNotFound: 'Cont\u00EAiner n\u00E3o encontrado para a captura de tela.',
    screenshotCaptureFailed: 'Falha ao capturar a imagem da tela.',
    screenshotCopiedToClipboard: 'Captura de tela copiada para a \u00E1rea de transfer\u00EAncia.',
    failedCopyScreenshot: 'Falha ao copiar a captura de tela para a \u00E1rea de transfer\u00EAncia.',
    screenshotRenderFailed: 'Falha na captura da tela.',
    issueReportingNotConfigured: 'O relat\u00F3rio de problemas n\u00E3o est\u00E1 configurado.',
    issueReportConfirm: 'Isso abrir\u00E1 o rastreador de problemas e incluir\u00E1 {detail}. Continuar?',
    issueReportDetailDomain: 'o nome de dom\u00EDnio "{domain}"',
    issueReportDetailInput: 'o nome de dom\u00EDnio da caixa de entrada',
    authSignInNotConfigured: 'O login com Microsoft n\u00E3o est\u00E1 configurado. Confirme se ACS_ENTRA_CLIENT_ID foi injetado na p\u00E1gina e atualize.',
    authLibraryLoadFailed: 'A biblioteca de login da Microsoft n\u00E3o p\u00F4de ser carregada. Verifique o acesso ao CDN do MSAL ou forne\u00E7a um arquivo local `msal-browser.min.js`.',
    authInitFailed: 'Falha ao inicializar o login com Microsoft. Verifique o console do navegador para mais detalhes.',
    authInitFailedWithReason: 'Falha ao inicializar o login com Microsoft: {reason}',
    authSetClientIdAndRestart: 'O login com Microsoft n\u00E3o est\u00E1 configurado. Defina a vari\u00E1vel de ambiente ACS_ENTRA_CLIENT_ID e reinicie.',
    authSigningIn: 'Entrando...',
    authSignInCancelled: 'O login foi cancelado.',
    authSignInFailed: 'Falha no login: {reason}',
    authUnknownError: 'Erro desconhecido',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois'
  },
  ar: {
    languageName: '\u0627\u0644\u0639\u0631\u0628\u064A\u0629',
    appHeading: 'Azure Communication Services<br/>\u0645\u062F\u0642\u0642 \u0646\u0637\u0627\u0642 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A',
    placeholderDomain: 'example.sa',
    lookup: '\u062A\u062D\u0642\u0642',
    checkingShort: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642',
    themeDark: '\u0627\u0644\u0648\u0636\u0639 \u0627\u0644\u062F\u0627\u0643\u0646 \uD83C\uDF19',
    themeLight: '\u0627\u0644\u0648\u0636\u0639 \u0627\u0644\u0641\u0627\u062A\u062D \u2600\uFE0F',
    copyLink: '\u0646\u0633\u062E \u0627\u0644\u0631\u0627\u0628\u0637 \uD83D\uDD17',
    copyScreenshot: '\u0646\u0633\u062E \u0644\u0642\u0637\u0629 \u0627\u0644\u0635\u0641\u062D\u0629 \uD83D\uDCF8',
    downloadJson: '\u062A\u0646\u0632\u064A\u0644 JSON \uD83D\uDCE5',
    reportIssue: '\u0627\u0644\u0625\u0628\u0644\u0627\u063A \u0639\u0646 \u0645\u0634\u0643\u0644\u0629 \uD83D\uDC1B',
    signInMicrosoft: '\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft \uD83D\uDD12',
    signOut: '\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062E\u0631\u0648\u062C',
    termsOfService: '\u0634\u0631\u0648\u0637 \u0627\u0644\u062E\u062F\u0645\u0629',
    privacyStatement: '\u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629',
    recent: '\u0627\u0644\u0623\u062E\u064A\u0631\u0629',
    languageLabel: '\u0627\u0644\u0644\u063A\u0629',
    pageTitle: 'Azure Communication Services - \u0645\u062F\u0642\u0642 \u0646\u0637\u0627\u0642 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A',
    promptEnterDomain: '\u064A\u0631\u062C\u0649 \u0625\u062F\u062E\u0627\u0644 \u0646\u0637\u0627\u0642.',
    promptEnterValidDomain: '\u064A\u0631\u062C\u0649 \u0625\u062F\u062E\u0627\u0644 \u0627\u0633\u0645 \u0646\u0637\u0627\u0642 \u0635\u0627\u0644\u062D (\u0645\u062B\u0627\u0644: example.com).',
    clipboardUnavailable: '\u0648\u0627\u062C\u0647\u0629 \u0628\u0631\u0645\u062C\u0629 \u062A\u0637\u0628\u064A\u0642\u0627\u062A \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u063A\u064A\u0631 \u0645\u062A\u0648\u0641\u0631\u0629 \u0641\u064A \u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D.',
    linkCopiedToClipboard: '\u062A\u0645 \u0646\u0633\u062E \u0627\u0644\u0631\u0627\u0628\u0637 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    failedCopyLink: '\u062A\u0639\u0630\u0631 \u0646\u0633\u062E \u0627\u0644\u0631\u0627\u0628\u0637 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    copiedToClipboard: '\u062A\u0645 \u0627\u0644\u0646\u0633\u062E \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    failedCopyToClipboard: '\u062A\u0639\u0630\u0631 \u0627\u0644\u0646\u0633\u062E \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    nothingToCopyFor: '\u0644\u0627 \u064A\u0648\u062C\u062F \u0645\u0627 \u064A\u0645\u0643\u0646 \u0646\u0633\u062E\u0647 \u0644\u0644\u062D\u0642\u0644 {field}.',
    copiedFieldToClipboard: '\u062A\u0645 \u0646\u0633\u062E {field} \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    failedCopyFieldToClipboard: '\u062A\u0639\u0630\u0631 \u0646\u0633\u062E {field} \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    screenshotClipboardUnsupported: '\u0646\u0633\u062E \u0644\u0642\u0637\u0627\u062A \u0627\u0644\u0634\u0627\u0634\u0629 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645 \u0641\u064A \u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D.',
    screenshotContainerNotFound: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0627\u0644\u062D\u0627\u0648\u064A\u0629 \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0644\u0642\u0637\u0629 \u0627\u0644\u0634\u0627\u0634\u0629.',
    screenshotCaptureFailed: '\u062A\u0639\u0630\u0631 \u0627\u0644\u062A\u0642\u0627\u0637 \u0644\u0642\u0637\u0629 \u0627\u0644\u0634\u0627\u0634\u0629.',
    screenshotCopiedToClipboard: '\u062A\u0645 \u0646\u0633\u062E \u0644\u0642\u0637\u0629 \u0627\u0644\u0634\u0627\u0634\u0629 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    failedCopyScreenshot: '\u062A\u0639\u0630\u0631 \u0646\u0633\u062E \u0644\u0642\u0637\u0629 \u0627\u0644\u0634\u0627\u0634\u0629 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629.',
    screenshotRenderFailed: '\u0641\u0634\u0644 \u0627\u0644\u062A\u0642\u0627\u0637 \u0644\u0642\u0637\u0629 \u0627\u0644\u0634\u0627\u0634\u0629.',
    issueReportingNotConfigured: '\u0627\u0644\u0625\u0628\u0644\u0627\u063A \u0639\u0646 \u0627\u0644\u0645\u0634\u0643\u0644\u0627\u062A \u063A\u064A\u0631 \u0645\u0643\u0648\u0651\u0646.',
    issueReportConfirm: '\u0633\u064A\u062A\u0645 \u0641\u062A\u062D \u0645\u062A\u0639\u0642\u0628 \u0627\u0644\u0645\u0634\u0643\u0644\u0627\u062A \u0648\u0633\u064A\u0634\u0645\u0644 {detail}. \u0647\u0644 \u062A\u0631\u064A\u062F \u0627\u0644\u0645\u062A\u0627\u0628\u0639\u0629\u061F',
    issueReportDetailDomain: '\u0627\u0633\u0645 \u0627\u0644\u0646\u0637\u0627\u0642 "{domain}"',
    issueReportDetailInput: '\u0627\u0633\u0645 \u0627\u0644\u0646\u0637\u0627\u0642 \u0645\u0646 \u0645\u0631\u0628\u0639 \u0627\u0644\u0625\u062F\u062E\u0627\u0644',
    authSignInNotConfigured: '\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft \u063A\u064A\u0631 \u0645\u0643\u0648\u0651\u0646. \u062A\u0623\u0643\u062F \u0645\u0646 \u062D\u0642\u0646 ACS_ENTRA_CLIENT_ID \u0641\u064A \u0627\u0644\u0635\u0641\u062D\u0629 \u062B\u0645 \u062D\u062F\u0651\u062B\u0647\u0627.',
    authLibraryLoadFailed: '\u062A\u0639\u0630\u0631 \u062A\u062D\u0645\u064A\u0644 \u0645\u0643\u062A\u0628\u0629 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft. \u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 \u0634\u0628\u0643\u0629 CDN \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0640 MSAL \u0623\u0648 \u0648\u0641\u0651\u0631 \u0645\u0644\u0641 `msal-browser.min.js` \u0645\u062D\u0644\u064A\u064B\u0627.',
    authInitFailed: '\u0641\u0634\u0644 \u062A\u0647\u064A\u0626\u0629 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft. \u0631\u0627\u062C\u0639 \u0648\u062D\u062F\u0629 \u062A\u062D\u0643\u0645 \u0627\u0644\u0645\u062A\u0635\u0641\u062D \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0627\u0644\u062A\u0641\u0627\u0635\u064A\u0644.',
    authInitFailedWithReason: '\u0641\u0634\u0644 \u062A\u0647\u064A\u0626\u0629 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft: {reason}',
    authSetClientIdAndRestart: '\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft \u063A\u064A\u0631 \u0645\u0643\u0648\u0651\u0646. \u0639\u064A\u0651\u0646 \u0645\u062A\u063A\u064A\u0631 \u0627\u0644\u0628\u064A\u0626\u0629 ACS_ENTRA_CLIENT_ID \u062B\u0645 \u0623\u0639\u062F \u0627\u0644\u062A\u0634\u063A\u064A\u0644.',
    authSigningIn: '\u062C\u0627\u0631\u064D \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644...',
    authSignInCancelled: '\u062A\u0645 \u0625\u0644\u063A\u0627\u0621 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644.',
    authSignInFailed: '\u0641\u0634\u0644 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644: {reason}',
    authUnknownError: '\u062E\u0637\u0623 \u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois'
  },
  'zh-CN': {
    languageName: '\u4E2D\u6587\uFF08\u7B80\u4F53\uFF09',
    appHeading: 'Azure Communication Services<br/>\u7535\u5B50\u90AE\u4EF6\u57DF\u68C0\u67E5\u5668',
    placeholderDomain: 'example.cn',
    lookup: '\u68C0\u67E5',
    checkingShort: '\u68C0\u67E5\u4E2D',
    themeDark: '\u6DF1\u8272\u6A21\u5F0F \uD83C\uDF19',
    themeLight: '\u6D45\u8272\u6A21\u5F0F \u2600\uFE0F',
    copyLink: '\u590D\u5236\u94FE\u63A5 \uD83D\uDD17',
    copyScreenshot: '\u590D\u5236\u9875\u9762\u622A\u56FE \uD83D\uDCF8',
    downloadJson: '\u4E0B\u8F7D JSON \uD83D\uDCE5',
    reportIssue: '\u62A5\u544A\u95EE\u9898 \uD83D\uDC1B',
    signInMicrosoft: '\u4F7F\u7528 Microsoft \u767B\u5F55 \uD83D\uDD12',
    signOut: '\u9000\u51FA\u767B\u5F55',
    termsOfService: '\u670D\u52A1\u6761\u6B3E',
    privacyStatement: '\u9690\u79C1\u58F0\u660E',
    recent: '\u6700\u8FD1\u4F7F\u7528',
    languageLabel: '\u8BED\u8A00',
    pageTitle: 'Azure Communication Services - \u7535\u5B50\u90AE\u4EF6\u57DF\u68C0\u67E5\u5668',
    promptEnterDomain: '\u8BF7\u8F93\u5165\u57DF\u540D\u3002',
    promptEnterValidDomain: '\u8BF7\u8F93\u5165\u6709\u6548\u7684\u57DF\u540D\uFF08\u4F8B\u5982\uFF1Aexample.com\uFF09\u3002',
    clipboardUnavailable: '\u6B64\u6D4F\u89C8\u5668\u4E0D\u652F\u6301\u526A\u8D34\u677F API\u3002',
    linkCopiedToClipboard: '\u94FE\u63A5\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    failedCopyLink: '\u65E0\u6CD5\u5C06\u94FE\u63A5\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    copiedToClipboard: '\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    failedCopyToClipboard: '\u590D\u5236\u5230\u526A\u8D34\u677F\u5931\u8D25\u3002',
    nothingToCopyFor: '\u6CA1\u6709\u53EF\u590D\u5236\u7684 {field}\u3002',
    copiedFieldToClipboard: '\u5DF2\u5C06 {field} \u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    failedCopyFieldToClipboard: '\u65E0\u6CD5\u5C06 {field} \u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    screenshotClipboardUnsupported: '\u6B64\u6D4F\u89C8\u5668\u4E0D\u652F\u6301\u5C06\u622A\u56FE\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    screenshotContainerNotFound: '\u672A\u627E\u5230\u622A\u56FE\u5BB9\u5668\u3002',
    screenshotCaptureFailed: '\u622A\u56FE\u5931\u8D25\u3002',
    screenshotCopiedToClipboard: '\u622A\u56FE\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    failedCopyScreenshot: '\u65E0\u6CD5\u5C06\u622A\u56FE\u590D\u5236\u5230\u526A\u8D34\u677F\u3002',
    screenshotRenderFailed: '\u622A\u56FE\u6E32\u67D3\u5931\u8D25\u3002',
    issueReportingNotConfigured: '\u672A\u914D\u7F6E\u95EE\u9898\u62A5\u544A\u529F\u80FD\u3002',
    issueReportConfirm: '\u8FD9\u5C06\u6253\u5F00\u95EE\u9898\u8DDF\u8E2A\u5668\uFF0C\u5E76\u5305\u542B{detail}\u3002\u662F\u5426\u7EE7\u7EED\uFF1F',
    issueReportDetailDomain: '\u57DF\u540D\u201C{domain}\u201D',
    issueReportDetailInput: '\u8F93\u5165\u6846\u4E2D\u7684\u57DF\u540D',
    authSignInNotConfigured: '\u672A\u914D\u7F6E Microsoft \u767B\u5F55\u3002\u8BF7\u786E\u8BA4\u9875\u9762\u4E2D\u5DF2\u6CE8\u5165 ACS_ENTRA_CLIENT_ID\uFF0C\u7136\u540E\u5237\u65B0\u3002',
    authLibraryLoadFailed: 'Microsoft \u767B\u5F55\u5E93\u52A0\u8F7D\u5931\u8D25\u3002\u8BF7\u68C0\u67E5\u662F\u5426\u53EF\u4EE5\u8BBF\u95EE MSAL CDN\uFF0C\u6216\u63D0\u4F9B\u672C\u5730 `msal-browser.min.js` \u6587\u4EF6\u3002',
    authInitFailed: 'Microsoft \u767B\u5F55\u521D\u59CB\u5316\u5931\u8D25\u3002\u8BF7\u67E5\u770B\u6D4F\u89C8\u5668\u63A7\u5236\u53F0\u4E86\u89E3\u8BE6\u7EC6\u4FE1\u606F\u3002',
    authInitFailedWithReason: 'Microsoft \u767B\u5F55\u521D\u59CB\u5316\u5931\u8D25\uFF1A{reason}',
    authSetClientIdAndRestart: '\u672A\u914D\u7F6E Microsoft \u767B\u5F55\u3002\u8BF7\u8BBE\u7F6E ACS_ENTRA_CLIENT_ID \u73AF\u5883\u53D8\u91CF\u5E76\u91CD\u65B0\u542F\u52A8\u3002',
    authSigningIn: '\u6B63\u5728\u767B\u5F55...',
    authSignInCancelled: '\u767B\u5F55\u5DF2\u53D6\u6D88\u3002',
    authSignInFailed: '\u767B\u5F55\u5931\u8D25\uFF1A{reason}',
    authUnknownError: '\u672A\u77E5\u9519\u8BEF',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois'
  }
};

['es', 'fr', 'de', 'pt-BR', 'ar', 'zh-CN', 'hi-IN', 'ja-JP', 'ru-RU'].forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS.en, TRANSLATIONS[code]);
});

const TRANSLATION_EXTENSIONS = {
  en: {
    unitYearOne: 'year',
    unitYearMany: 'years',
    unitMonthOne: 'month',
    unitMonthMany: 'months',
    unitDayOne: 'day',
    unitDayMany: 'days',
    wordExpired: 'Expired',
    mxPriorityLabel: 'Priority',
    providerHintMicrosoft365: 'MX points to Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'MX points to Google mail exchangers.',
    providerHintCloudflare: 'MX points to Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'MX points to Proofpoint-hosted mail.',
    providerHintMimecast: 'MX points to Mimecast.',
    providerHintZoho: 'MX points to Zoho Mail.',
    providerHintUnknown: 'Provider not recognized from MX hostname.',
    riskClean: 'Clean',
    riskWarning: 'Warning',
    riskElevated: 'Elevated risk'
  },
  fr: {
    passing: 'Conforme',
    failed: '\u00C9chec',
    warningState: 'Avertissement',
    dnsTxtLookup: 'Recherche DNS TXT',
    acsTxtMsDomainVerification: 'TXT ACS (ms-domain-verification)',
    acsReadiness: '\u00C9tat ACS',
    resolvedSuccessfully: 'R\u00E9solution r\u00E9ussie.',
    msDomainVerificationFound: 'TXT ms-domain-verification trouv\u00E9.',
    addAcsTxtFromPortal: 'Ajoutez le TXT ACS depuis le portail Azure.',
    source: 'Source',
    lookupDomainLabel: 'Domaine interrog\u00E9',
    creationDate: 'Date de cr\u00E9ation',
    registryExpiryDate: 'Date d\u2019expiration du registre',
    registrarLabel: 'Bureau d\u2019enregistrement',
    registrantLabel: 'Titulaire',
    domainAgeLabel: '\u00C2ge du domaine',
    domainExpiringIn: 'Le domaine expire dans',
    daysUntilExpiry: 'Jours avant expiration',
    ageLabel: '\u00C2ge',
    expiresInLabel: 'Expire dans',
    zonesQueried: 'Zones interrog\u00E9es',
    totalQueries: 'Requ\u00EAtes totales',
    errorsCount: 'Erreurs',
    listed: 'List\u00E9',
    notListed: 'Non list\u00E9',
    riskLabel: 'Risque',
    reputationWord: 'R\u00E9putation',
    clean: 'Saine',
    excellent: 'Excellente',
    great: 'Tr\u00E8s bonne',
    good: 'Bonne',
    fair: 'Moyenne',
    poor: 'Faible',
    yes: 'Oui',
    no: 'Non',
    none: 'Aucune',
    priority: 'Priorit\u00E9',
    detectedProvider: 'Fournisseur d\u00E9tect\u00E9',
    rawLabel: 'Brut',
    noRegistrationInformation: 'Aucune information d\u2019enregistrement disponible.',
    registrationDetailsUnavailable: 'D\u00E9tails d\u2019enregistrement indisponibles.',
    unitYearOne: 'an',
    unitYearMany: 'ans',
    unitMonthOne: 'mois',
    unitMonthMany: 'mois',
    unitDayOne: 'jour',
    unitDayMany: 'jours',
    wordExpired: 'Expir\u00E9',
    mxPriorityLabel: 'Priorit\u00E9',
    providerHintMicrosoft365: 'Le MX pointe vers Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'Le MX pointe vers les serveurs de messagerie Google.',
    providerHintCloudflare: 'Le MX pointe vers Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'Le MX pointe vers une messagerie h\u00E9berg\u00E9e par Proofpoint.',
    providerHintMimecast: 'Le MX pointe vers Mimecast.',
    providerHintZoho: 'Le MX pointe vers Zoho Mail.',
    providerHintUnknown: 'Fournisseur non reconnu \u00E0 partir du nom d\u2019h\u00F4te MX.',
    riskClean: 'Sain',
    riskWarning: 'Avertissement',
    riskElevated: 'Risque \u00E9lev\u00E9'
  },
  de: {
    passing: 'Erfolgreich',
    failed: 'Fehlgeschlagen',
    warningState: 'Warnung',
    dnsTxtLookup: 'DNS-TXT-Abfrage',
    acsTxtMsDomainVerification: 'ACS-TXT (ms-domain-verification)',
    acsReadiness: 'ACS-Status',
    resolvedSuccessfully: 'Erfolgreich aufgel\u00F6st.',
    msDomainVerificationFound: 'ms-domain-verification-TXT gefunden.',
    addAcsTxtFromPortal: 'F\u00FCgen Sie das ACS-TXT aus dem Azure-Portal hinzu.',
    source: 'Quelle',
    lookupDomainLabel: 'Abfragedomain',
    creationDate: 'Erstellungsdatum',
    registryExpiryDate: 'Ablaufdatum der Registrierung',
    registrarLabel: 'Registrar',
    registrantLabel: 'Inhaber',
    domainAgeLabel: 'Domainalter',
    domainExpiringIn: 'Domain l\u00E4uft ab in',
    daysUntilExpiry: 'Tage bis Ablauf',
    ageLabel: 'Alter',
    expiresInLabel: 'L\u00E4uft ab in',
    zonesQueried: 'Abgefragte Zonen',
    totalQueries: 'Gesamtabfragen',
    errorsCount: 'Fehler',
    listed: 'Gelistet',
    notListed: 'Nicht gelistet',
    riskLabel: 'Risiko',
    reputationWord: 'Reputation',
    clean: 'Sauber',
    excellent: 'Ausgezeichnet',
    great: 'Sehr gut',
    good: 'Gut',
    fair: 'Mittel',
    poor: 'Schwach',
    yes: 'Ja',
    no: 'Nein',
    none: 'Keine',
    priority: 'Priorit\u00E4t',
    detectedProvider: 'Erkannter Anbieter',
    rawLabel: 'Rohdaten',
    noRegistrationInformation: 'Keine Registrierungsinformationen verf\u00FCgbar.',
    registrationDetailsUnavailable: 'Registrierungsdetails nicht verf\u00FCgbar.',
    unitYearOne: 'Jahr',
    unitYearMany: 'Jahre',
    unitMonthOne: 'Monat',
    unitMonthMany: 'Monate',
    unitDayOne: 'Tag',
    unitDayMany: 'Tage',
    wordExpired: 'Abgelaufen',
    mxPriorityLabel: 'Priorit\u00E4t',
    providerHintMicrosoft365: 'MX verweist auf Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'MX verweist auf Google-Mail-Exchanger.',
    providerHintCloudflare: 'MX verweist auf Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'MX verweist auf von Proofpoint gehostete E-Mail.',
    providerHintMimecast: 'MX verweist auf Mimecast.',
    providerHintZoho: 'MX verweist auf Zoho Mail.',
    providerHintUnknown: 'Anbieter konnte anhand des MX-Hostnamens nicht erkannt werden.',
    riskClean: 'Sauber',
    riskWarning: 'Warnung',
    riskElevated: 'Erh\u00F6htes Risiko'
  },
  'pt-BR': {
    passing: 'Aprovado',
    failed: 'Falhou',
    warningState: 'Aviso',
    dnsTxtLookup: 'Consulta DNS TXT',
    acsTxtMsDomainVerification: 'TXT ACS (ms-domain-verification)',
    acsReadiness: 'Prontid\u00E3o do ACS',
    resolvedSuccessfully: 'Resolvido com sucesso.',
    msDomainVerificationFound: 'TXT ms-domain-verification encontrado.',
    addAcsTxtFromPortal: 'Adicione o TXT do ACS no portal do Azure.',
    source: 'Fonte',
    lookupDomainLabel: 'Dom\u00EDnio consultado',
    creationDate: 'Data de cria\u00E7\u00E3o',
    registryExpiryDate: 'Data de expira\u00E7\u00E3o do registro',
    registrarLabel: 'Registrador',
    registrantLabel: 'Titular',
    domainAgeLabel: 'Idade do dom\u00EDnio',
    domainExpiringIn: 'O dom\u00EDnio expira em',
    daysUntilExpiry: 'Dias at\u00E9 a expira\u00E7\u00E3o',
    ageLabel: 'Idade',
    expiresInLabel: 'Expira em',
    zonesQueried: 'Zonas consultadas',
    totalQueries: 'Consultas totais',
    errorsCount: 'Erros',
    listed: 'Listado',
    notListed: 'N\u00E3o listado',
    riskLabel: 'Risco',
    reputationWord: 'Reputa\u00E7\u00E3o',
    clean: 'Limpo',
    excellent: 'Excelente',
    great: '\u00D3tima',
    good: 'Boa',
    fair: 'Razo\u00E1vel',
    poor: 'Ruim',
    yes: 'Sim',
    no: 'N\u00E3o',
    none: 'Nenhum',
    priority: 'Prioridade',
    detectedProvider: 'Provedor detectado',
    rawLabel: 'Bruto',
    noRegistrationInformation: 'Nenhuma informa\u00E7\u00E3o de registro dispon\u00EDvel.',
    registrationDetailsUnavailable: 'Detalhes de registro indispon\u00EDveis.',
    unitYearOne: 'ano',
    unitYearMany: 'anos',
    unitMonthOne: 'm\u00EAs',
    unitMonthMany: 'meses',
    unitDayOne: 'dia',
    unitDayMany: 'dias',
    wordExpired: 'Expirado',
    mxPriorityLabel: 'Prioridade',
    providerHintMicrosoft365: 'O MX aponta para o Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'O MX aponta para os trocadores de e-mail do Google.',
    providerHintCloudflare: 'O MX aponta para a Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'O MX aponta para e-mail hospedado pela Proofpoint.',
    providerHintMimecast: 'O MX aponta para a Mimecast.',
    providerHintZoho: 'O MX aponta para o Zoho Mail.',
    providerHintUnknown: 'Provedor n\u00E3o reconhecido pelo nome do host MX.',
    riskClean: 'Limpo',
    riskWarning: 'Aviso',
    riskElevated: 'Risco elevado'
  },
  ar: {
    passing: '\u0646\u0627\u062C\u062D',
    failed: '\u0641\u0634\u0644',
    warningState: '\u062A\u062D\u0630\u064A\u0631',
    dnsTxtLookup: '\u0627\u0633\u062A\u0639\u0644\u0627\u0645 DNS TXT',
    acsTxtMsDomainVerification: 'TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u200F(ms-domain-verification)',
    acsReadiness: '\u062C\u0627\u0647\u0632\u064A\u0629 ACS',
    resolvedSuccessfully: '\u062A\u0645 \u0627\u0644\u062D\u0644 \u0628\u0646\u062C\u0627\u062D.',
    msDomainVerificationFound: '\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ms-domain-verification.',
    addAcsTxtFromPortal: '\u0623\u0636\u0641 TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u0645\u0646 \u0645\u062F\u062E\u0644 Azure.',
    source: '\u0627\u0644\u0645\u0635\u062F\u0631',
    lookupDomainLabel: '\u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647',
    creationDate: '\u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
    registryExpiryDate: '\u062A\u0627\u0631\u064A\u062E \u0627\u0646\u062A\u0647\u0627\u0621 \u0627\u0644\u062A\u0633\u062C\u064A\u0644',
    registrarLabel: '\u0627\u0644\u0645\u0633\u062C\u0644',
    registrantLabel: '\u0635\u0627\u062D\u0628 \u0627\u0644\u062A\u0633\u062C\u064A\u0644',
    domainAgeLabel: '\u0639\u0645\u0631 \u0627\u0644\u0646\u0637\u0627\u0642',
    domainExpiringIn: '\u064A\u0646\u062A\u0647\u064A \u0627\u0644\u0646\u0637\u0627\u0642 \u062E\u0644\u0627\u0644',
    daysUntilExpiry: '\u0639\u062F\u062F \u0627\u0644\u0623\u064A\u0627\u0645 \u062D\u062A\u0649 \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621',
    ageLabel: '\u0627\u0644\u0639\u0645\u0631',
    expiresInLabel: '\u064A\u0646\u062A\u0647\u064A \u062E\u0644\u0627\u0644',
    zonesQueried: '\u0627\u0644\u0645\u0646\u0627\u0637\u0642 \u0627\u0644\u062A\u064A \u062A\u0645 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0639\u0646\u0647\u0627',
    totalQueries: '\u0625\u062C\u0645\u0627\u0644\u064A \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A',
    errorsCount: '\u0627\u0644\u0623\u062E\u0637\u0627\u0621',
    listed: '\u0645\u062F\u0631\u062C',
    notListed: '\u063A\u064A\u0631 \u0645\u062F\u0631\u062C',
    riskLabel: '\u0627\u0644\u0645\u062E\u0627\u0637\u0631',
    reputationWord: '\u0627\u0644\u0633\u0645\u0639\u0629',
    clean: '\u0646\u0638\u064A\u0641',
    excellent: '\u0645\u0645\u062A\u0627\u0632',
    great: '\u0631\u0627\u0626\u0639',
    good: '\u062C\u064A\u062F',
    fair: '\u0645\u0642\u0628\u0648\u0644',
    poor: '\u0636\u0639\u064A\u0641',
    yes: '\u0646\u0639\u0645',
    no: '\u0644\u0627',
    none: '\u0644\u0627 \u064A\u0648\u062C\u062F',
    priority: '\u0627\u0644\u0623\u0648\u0644\u0648\u064A\u0629',
    detectedProvider: '\u0645\u0648\u0641\u0631 \u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641\u0647',
    rawLabel: '\u062E\u0627\u0645',
    noRegistrationInformation: '\u0644\u0627 \u062A\u062A\u0648\u0641\u0631 \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u062A\u0633\u062C\u064A\u0644.',
    registrationDetailsUnavailable: '\u062A\u0641\u0627\u0635\u064A\u0644 \u0627\u0644\u062A\u0633\u062C\u064A\u0644 \u063A\u064A\u0631 \u0645\u062A\u0648\u0641\u0631\u0629.',
    unitYearOne: '\u0633\u0646\u0629',
    unitYearMany: '\u0633\u0646\u0648\u0627\u062A',
    unitMonthOne: '\u0634\u0647\u0631',
    unitMonthMany: '\u0623\u0634\u0647\u0631',
    unitDayOne: '\u064A\u0648\u0645',
    unitDayMany: '\u0623\u064A\u0627\u0645',
    wordExpired: '\u0645\u0646\u062A\u0647\u064A \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629',
    mxPriorityLabel: '\u0627\u0644\u0623\u0648\u0644\u0648\u064A\u0629',
    providerHintMicrosoft365: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Exchange Online Protection \u200F(EOP).',
    providerHintGoogleWorkspace: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 \u062E\u0648\u0627\u062F\u0645 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0640 Google.',
    providerHintCloudflare: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Cloudflare \u200F(mx.cloudflare.net).',
    providerHintProofpoint: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 \u0628\u0631\u064A\u062F \u0645\u0633\u062A\u0636\u0627\u0641 \u0644\u062F\u0649 Proofpoint.',
    providerHintMimecast: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Mimecast.',
    providerHintZoho: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Zoho Mail.',
    providerHintUnknown: '\u062A\u0639\u0630\u0631 \u0627\u0644\u062A\u0639\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0645\u0648\u0641\u0631 \u0645\u0646 \u0627\u0633\u0645 \u0645\u0636\u064A\u0641 MX.',
    riskClean: '\u0646\u0638\u064A\u0641',
    riskWarning: '\u062A\u062D\u0630\u064A\u0631',
    riskElevated: '\u0645\u062E\u0627\u0637\u0631 \u0645\u0631\u062A\u0641\u0639\u0629',
    mxUsingParentNote: '(\u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 MX \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain})',
    parentCheckedNoMx: '\u062A\u0645 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {parentDomain} (\u0644\u0627 \u064A\u0648\u062C\u062F MX).',
    expiredOn: '\u0645\u0646\u062A\u0647\u064A \u0641\u064A {date}',
    registrationAppearsExpired: '\u064A\u0628\u062F\u0648 \u0623\u0646 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u0646\u0637\u0627\u0642 \u0642\u062F \u0627\u0646\u062A\u0647\u062A \u0635\u0644\u0627\u062D\u064A\u062A\u0647.',
    newDomainUnder90Days: '\u0646\u0637\u0627\u0642 \u062C\u062F\u064A\u062F \u0623\u0642\u0644 \u0645\u0646 90 \u064A\u0648\u0645\u064B\u0627.',
    newDomainUnder180Days: '\u0646\u0637\u0627\u0642 \u062C\u062F\u064A\u062F \u0623\u0642\u0644 \u0645\u0646 180 \u064A\u0648\u0645\u064B\u0627.',
    domainNameLabel: '\u0627\u0633\u0645 \u0627\u0644\u0646\u0637\u0627\u0642',
    domainStatusLabel: '\u062D\u0627\u0644\u0629 \u0627\u0644\u0646\u0637\u0627\u0642',
    mxRecordsLabel: '\u0633\u062C\u0644\u0627\u062A MX',
    spfStatusLabel: '\u062D\u0627\u0644\u0629 SPF',
    dkim1StatusLabel: '\u062D\u0627\u0644\u0629 DKIM1',
    dkim2StatusLabel: '\u062D\u0627\u0644\u0629 DKIM2',
    dmarcStatusLabel: '\u062D\u0627\u0644\u0629 DMARC'
  },
  'zh-CN': {
    passing: '\u901A\u8FC7',
    failed: '\u5931\u8D25',
    warningState: '\u8B66\u544A',
    dnsTxtLookup: 'DNS TXT \u67E5\u8BE2',
    acsTxtMsDomainVerification: 'ACS TXT\uFF08ms-domain-verification\uFF09',
    acsReadiness: 'ACS \u5C31\u7EEA\u72B6\u6001',
    resolvedSuccessfully: '\u89E3\u6790\u6210\u529F\u3002',
    msDomainVerificationFound: '\u5DF2\u627E\u5230 ms-domain-verification TXT\u3002',
    addAcsTxtFromPortal: '\u8BF7\u4ECE Azure \u95E8\u6237\u6DFB\u52A0 ACS TXT\u3002',
    source: '\u6765\u6E90',
    lookupDomainLabel: '\u67E5\u8BE2\u57DF',
    creationDate: '\u521B\u5EFA\u65E5\u671F',
    registryExpiryDate: '\u6CE8\u518C\u5230\u671F\u65E5\u671F',
    registrarLabel: '\u6CE8\u518C\u5546',
    registrantLabel: '\u6CE8\u518C\u4EBA',
    domainAgeLabel: '\u57DF\u540D\u5E74\u9F84',
    domainExpiringIn: '\u57DF\u540D\u5C06\u5728\u4EE5\u4E0B\u65F6\u95F4\u540E\u5230\u671F',
    daysUntilExpiry: '\u8DDD\u5230\u671F\u5929\u6570',
    ageLabel: '\u5E74\u9F84',
    expiresInLabel: '\u5230\u671F\u65F6\u95F4',
    zonesQueried: '\u5DF2\u67E5\u8BE2\u533A\u57DF',
    totalQueries: '\u67E5\u8BE2\u603B\u6570',
    errorsCount: '\u9519\u8BEF',
    listed: '\u5DF2\u5217\u5165',
    notListed: '\u672A\u5217\u5165',
    riskLabel: '\u98CE\u9669',
    reputationWord: '\u4FE1\u8A89',
    clean: '\u5E72\u51C0',
    excellent: '\u4F18\u79C0',
    great: '\u5F88\u597D',
    good: '\u826F\u597D',
    fair: '\u4E00\u822C',
    poor: '\u8F83\u5DEE',
    yes: '\u662F',
    no: '\u5426',
    none: '\u65E0',
    priority: '\u4F18\u5148\u7EA7',
    detectedProvider: '\u68C0\u6D4B\u5230\u7684\u63D0\u4F9B\u5546',
    rawLabel: '\u539F\u59CB',
    noRegistrationInformation: '\u6CA1\u6709\u53EF\u7528\u7684\u6CE8\u518C\u4FE1\u606F\u3002',
    registrationDetailsUnavailable: '\u6CE8\u518C\u8BE6\u7EC6\u4FE1\u606F\u4E0D\u53EF\u7528\u3002',
    unitYearOne: '\u5E74',
    unitYearMany: '\u5E74',
    unitMonthOne: '\u4E2A\u6708',
    unitMonthMany: '\u4E2A\u6708',
    unitDayOne: '\u5929',
    unitDayMany: '\u5929',
    wordExpired: '\u5DF2\u8FC7\u671F',
    mxPriorityLabel: '\u4F18\u5148\u7EA7',
    providerHintMicrosoft365: 'MX \u6307\u5411 Exchange Online Protection (EOP)\u3002',
    providerHintGoogleWorkspace: 'MX \u6307\u5411 Google \u90AE\u4EF6\u4EA4\u6362\u670D\u52A1\u5668\u3002',
    providerHintCloudflare: 'MX \u6307\u5411 Cloudflare\uFF08mx.cloudflare.net\uFF09\u3002',
    providerHintProofpoint: 'MX \u6307\u5411\u7531 Proofpoint \u6258\u7BA1\u7684\u90AE\u4EF6\u670D\u52A1\u3002',
    providerHintMimecast: 'MX \u6307\u5411 Mimecast\u3002',
    providerHintZoho: 'MX \u6307\u5411 Zoho Mail\u3002',
    providerHintUnknown: '\u65E0\u6CD5\u4ECE MX \u4E3B\u673A\u540D\u8BC6\u522B\u63D0\u4F9B\u5546\u3002',
    riskClean: '\u5E72\u51C0',
    riskWarning: '\u8B66\u544A',
    riskElevated: '\u9AD8\u98CE\u9669',
    mxUsingParentNote: '\uFF08\u4F7F\u7528\u7236\u57DF {lookupDomain} \u7684 MX\uFF09',
    parentCheckedNoMx: '\u5DF2\u68C0\u67E5\u7236\u57DF {parentDomain}\uFF08\u65E0 MX\uFF09\u3002',
    expiredOn: '\u5DF2\u4E8E {date} \u8FC7\u671F',
    registrationAppearsExpired: '\u57DF\u540D\u6CE8\u518C\u4F3C\u4E4E\u5DF2\u8FC7\u671F\u3002',
    newDomainUnder90Days: '\u65B0\u57DF\u540D\uFF0C\u5C11\u4E8E 90 \u5929\u3002',
    newDomainUnder180Days: '\u65B0\u57DF\u540D\uFF0C\u5C11\u4E8E 180 \u5929\u3002',
    domainNameLabel: '\u57DF\u540D',
    domainStatusLabel: '\u57DF\u72B6\u6001',
    mxRecordsLabel: 'MX \u8BB0\u5F55',
    spfStatusLabel: 'SPF \u72B6\u6001',
    dkim1StatusLabel: 'DKIM1 \u72B6\u6001',
    dkim2StatusLabel: 'DKIM2 \u72B6\u6001',
    dmarcStatusLabel: 'DMARC \u72B6\u6001'
  },
  'hi-IN': {
    languageName: '\u0939\u093F\u0928\u094D\u0926\u0940 (\u092D\u093E\u0930\u0924)',
    appHeading: 'Azure Communication Services<br/>\u0908\u092E\u0947\u0932 \u0921\u094B\u092E\u0947\u0928 \u092A\u0930\u0940\u0915\u094D\u0937\u0915',
    placeholderDomain: 'example.in',
    lookup: '\u091C\u093E\u0901\u091A\u0947\u0902',
    checkingShort: '\u091C\u093E\u0901\u091A \u0939\u094B \u0930\u0939\u0940 \u0939\u0948',
    themeDark: '\u0921\u093E\u0930\u094D\u0915 \u092E\u094B\u0921 \uD83C\uDF19',
    themeLight: '\u0932\u093E\u0907\u091F \u092E\u094B\u0921 \u2600\uFE0F',
    copyLink: '\u0932\u093F\u0902\u0915 \u0915\u0949\u092A\u0940 \u0915\u0930\u0947\u0902 \uD83D\uDD17',
    copyScreenshot: '\u092A\u0947\u091C \u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u0949\u092A\u0940 \u0915\u0930\u0947\u0902 \uD83D\uDCF8',
    downloadJson: 'JSON \u0921\u093E\u0909\u0928\u0932\u094B\u0921 \u0915\u0930\u0947\u0902 \uD83D\uDCE5',
    reportIssue: '\u0938\u092E\u0938\u094D\u092F\u093E \u0930\u093F\u092A\u094B\u0930\u094D\u091F \u0915\u0930\u0947\u0902 \uD83D\uDC1B',
    signInMicrosoft: 'Microsoft \u0938\u0947 \u0938\u093E\u0907\u0928 \u0907\u0928 \u0915\u0930\u0947\u0902 \uD83D\uDD12',
    signOut: '\u0938\u093E\u0907\u0928 \u0906\u0909\u091F',
    termsOfService: '\u0938\u0947\u0935\u093E \u0915\u0940 \u0936\u0930\u094D\u0924\u0947\u0902',
    privacyStatement: '\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E',
    recent: '\u0939\u093E\u0932 \u0915\u0947',
    languageLabel: '\u092D\u093E\u0937\u093E',
    pageTitle: 'Azure Communication Services - \u0908\u092E\u0947\u0932 \u0921\u094B\u092E\u0947\u0928 \u092A\u0930\u0940\u0915\u094D\u0937\u0915',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u0932\u0947\u0916\u0915: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 PowerShell \u0926\u094D\u0935\u093E\u0930\u093E \u091C\u0928\u0930\u0947\u091F\u0947\u0921 \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">\u090A\u092A\u0930 \u091C\u093E\u090F\u0901</a>',
    promptEnterDomain: '\u0915\u0943\u092A\u092F\u093E \u090F\u0915 \u0921\u094B\u092E\u0947\u0928 \u0926\u0930\u094D\u091C \u0915\u0930\u0947\u0902\u0964',
    promptEnterValidDomain: '\u0915\u0943\u092A\u092F\u093E \u090F\u0915 \u092E\u093E\u0928\u094D\u092F \u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E \u0926\u0930\u094D\u091C \u0915\u0930\u0947\u0902 (\u0909\u0926\u093E\u0939\u0930\u0923: example.com)\u0964',
    clipboardUnavailable: '\u0907\u0938 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u092E\u0947\u0902 Clipboard API \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    linkCopiedToClipboard: '\u0932\u093F\u0902\u0915 \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0939\u094B \u0917\u092F\u093E\u0964',
    failedCopyLink: '\u0932\u093F\u0902\u0915 \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u093E\u0964',
    copiedToClipboard: '\u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0915\u093F\u092F\u093E \u0917\u092F\u093E\u0964',
    failedCopyToClipboard: '\u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0915\u0930\u0928\u093E \u0935\u093F\u092B\u0932 \u0930\u0939\u093E\u0964',
    nothingToCopyFor: '{field} \u0915\u0947 \u0932\u093F\u090F \u0915\u0949\u092A\u0940 \u0915\u0930\u0928\u0947 \u0939\u0947\u0924\u0941 \u0915\u0941\u091B \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    copiedFieldToClipboard: '{field} \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0915\u093F\u092F\u093E \u0917\u092F\u093E\u0964',
    failedCopyFieldToClipboard: '{field} \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0928\u0939\u0940\u0902 \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u093E\u0964',
    screenshotClipboardUnsupported: '\u0907\u0938 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u092E\u0947\u0902 \u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u0938\u092E\u0930\u094D\u0925\u0928 \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    screenshotContainerNotFound: '\u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u0947 \u0932\u093F\u090F \u0915\u0902\u091F\u0947\u0928\u0930 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964',
    screenshotCaptureFailed: '\u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u0948\u092A\u094D\u091A\u0930 \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u093E\u0964',
    screenshotCopiedToClipboard: '\u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0939\u094B \u0917\u092F\u093E\u0964',
    failedCopyScreenshot: '\u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u094D\u0932\u093F\u092A\u092C\u094B\u0930\u094D\u0921 \u092E\u0947\u0902 \u0915\u0949\u092A\u0940 \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u093E\u0964',
    screenshotRenderFailed: '\u0938\u094D\u0915\u094D\u0930\u0940\u0928\u0936\u0949\u091F \u0915\u0948\u092A\u094D\u091A\u0930 \u0935\u093F\u092B\u0932 \u0939\u0941\u0906\u0964',
    issueReportingNotConfigured: '\u0938\u092E\u0938\u094D\u092F\u093E \u0930\u093F\u092A\u094B\u0930\u094D\u091F\u093F\u0902\u0917 \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    issueReportConfirm: '\u092F\u0939 issue tracker \u0916\u094B\u0932\u0947\u0917\u093E \u0914\u0930 \u0907\u0938\u092E\u0947\u0902 {detail} \u0936\u093E\u092E\u093F\u0932 \u0939\u094B\u0917\u093E\u0964 \u091C\u093E\u0930\u0940 \u0930\u0916\u0947\u0902?',
    issueReportDetailDomain: '\u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E "{domain}"',
    issueReportDetailInput: '\u0907\u0928\u092A\u0941\u091F \u092C\u0949\u0915\u094D\u0938 \u0915\u093E \u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E',
    authSignInNotConfigured: 'Microsoft \u0938\u093E\u0907\u0928-\u0907\u0928 \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 \u0938\u0941\u0928\u093F\u0936\u094D\u091A\u093F\u0924 \u0915\u0930\u0947\u0902 \u0915\u093F ACS_ENTRA_CLIENT_ID \u092A\u0947\u091C \u092E\u0947\u0902 inject \u0915\u093F\u092F\u093E \u0917\u092F\u093E \u0939\u0948 \u0914\u0930 \u092B\u093F\u0930 refresh \u0915\u0930\u0947\u0902\u0964',
    authLibraryLoadFailed: 'Microsoft \u0938\u093E\u0907\u0928-\u0907\u0928 \u0932\u093E\u0907\u092C\u094D\u0930\u0947\u0930\u0940 \u0932\u094B\u0921 \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u0940\u0964 MSAL CDN \u0915\u0940 \u092A\u0939\u0941\u0901\u091A \u091C\u093E\u0901\u091A\u0947\u0902 \u092F\u093E \u0938\u094D\u0925\u093E\u0928\u0940\u092F msal-browser.min.js \u092B\u093C\u093E\u0907\u0932 \u0909\u092A\u0932\u092C\u094D\u0927 \u0915\u0930\u093E\u090F\u0901\u0964',
    authInitFailed: 'Microsoft \u0938\u093E\u0907\u0928-\u0907\u0928 \u092A\u094D\u0930\u093E\u0930\u0902\u092D \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u093E\u0964 \u0905\u0927\u093F\u0915 \u0935\u093F\u0935\u0930\u0923 \u0915\u0947 \u0932\u093F\u090F \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 console \u0926\u0947\u0916\u0947\u0902\u0964',
    authInitFailedWithReason: 'Microsoft \u0938\u093E\u0907\u0928-\u0907\u0928 \u092A\u094D\u0930\u093E\u0930\u0902\u092D \u0928\u0939\u0940\u0902 \u0939\u094B \u0938\u0915\u093E: {reason}',
    authSetClientIdAndRestart: 'Microsoft \u0938\u093E\u0907\u0928-\u0907\u0928 \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 ACS_ENTRA_CLIENT_ID environment variable \u0938\u0947\u091F \u0915\u0930\u0947\u0902 \u0914\u0930 \u092A\u0941\u0928\u0903 \u092A\u094D\u0930\u093E\u0930\u0902\u092D \u0915\u0930\u0947\u0902\u0964',
    authSigningIn: '\u0938\u093E\u0907\u0928 \u0907\u0928 \u0939\u094B \u0930\u0939\u093E \u0939\u0948...',
    authSignInCancelled: '\u0938\u093E\u0907\u0928-\u0907\u0928 \u0930\u0926\u094D\u0926 \u0915\u0930 \u0926\u093F\u092F\u093E \u0917\u092F\u093E\u0964',
    authSignInFailed: '\u0938\u093E\u0907\u0928-\u0907\u0928 \u0935\u093F\u092B\u0932: {reason}',
    authUnknownError: '\u0905\u091C\u094D\u091E\u093E\u0924 \u0924\u094D\u0930\u0941\u091F\u093F',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois',
    passing: '\u0938\u092B\u0932',
    failed: '\u0935\u093F\u092B\u0932',
    warningState: '\u091A\u0947\u0924\u093E\u0935\u0928\u0940',
    dnsTxtLookup: 'DNS TXT \u0932\u0941\u0915\u0905\u092A',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    acsReadiness: 'ACS \u0924\u0924\u094D\u092A\u0930\u0924\u093E',
    resolvedSuccessfully: '\u0938\u092B\u0932\u0924\u093E\u092A\u0942\u0930\u094D\u0935\u0915 resolved\u0964',
    msDomainVerificationFound: 'ms-domain-verification TXT \u092E\u093F\u0932\u093E\u0964',
    addAcsTxtFromPortal: 'Azure portal \u0938\u0947 ACS TXT \u091C\u094B\u0921\u093C\u0947\u0902\u0964',
    source: '\u0938\u094D\u0930\u094B\u0924',
    lookupDomainLabel: '\u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u092F\u093E \u0917\u092F\u093E \u0921\u094B\u092E\u0947\u0928',
    creationDate: '\u0928\u093F\u0930\u094D\u092E\u093E\u0923 \u0924\u093F\u0925\u093F',
    registryExpiryDate: '\u0930\u091C\u093F\u0938\u094D\u091F\u094D\u0930\u0940 \u0938\u092E\u093E\u092A\u094D\u0924\u093F \u0924\u093F\u0925\u093F',
    registrarLabel: '\u0930\u091C\u093F\u0938\u094D\u091F\u094D\u0930\u093E\u0930',
    registrantLabel: '\u092A\u0902\u091C\u0940\u092F\u0915',
    domainAgeLabel: '\u0921\u094B\u092E\u0947\u0928 \u0906\u092F\u0941',
    domainExpiringIn: '\u0921\u094B\u092E\u0947\u0928 \u0938\u092E\u093E\u092A\u094D\u0924 \u0939\u094B\u0917\u093E',
    daysUntilExpiry: '\u0938\u092E\u093E\u092A\u094D\u0924\u093F \u0924\u0915 \u0926\u093F\u0928',
    ageLabel: '\u0906\u092F\u0941',
    expiresInLabel: '\u0938\u092E\u093E\u092A\u094D\u0924\u093F',
    zonesQueried: '\u092A\u0942\u091B\u0947 \u0917\u090F \u091C\u093C\u094B\u0928',
    totalQueries: '\u0915\u0941\u0932 \u0915\u094D\u0935\u0947\u0930\u0940',
    errorsCount: '\u0924\u094D\u0930\u0941\u091F\u093F\u092F\u093E\u0901',
    listed: '\u0938\u0942\u091A\u0940\u092C\u0926\u094D\u0927',
    notListed: '\u0938\u0942\u091A\u0940\u092C\u0926\u094D\u0927 \u0928\u0939\u0940\u0902',
    riskLabel: '\u091C\u094B\u0916\u093F\u092E',
    reputationWord: '\u092A\u094D\u0930\u0924\u093F\u0937\u094D\u0920\u093E',
    clean: '\u0938\u094D\u0935\u091A\u094D\u091B',
    excellent: '\u0909\u0924\u094D\u0915\u0943\u0937\u094D\u091F',
    great: '\u092C\u0939\u0941\u0924 \u0905\u091A\u094D\u091B\u093E',
    good: '\u0905\u091A\u094D\u091B\u093E',
    fair: '\u0938\u093E\u092E\u093E\u0928\u094D\u092F',
    poor: '\u0915\u092E\u091C\u093C\u094B\u0930',
    yes: '\u0939\u093E\u0901',
    no: '\u0928\u0939\u0940\u0902',
    none: '\u0915\u094B\u0908 \u0928\u0939\u0940\u0902',
    priority: '\u092A\u094D\u0930\u093E\u0925\u092E\u093F\u0915\u0924\u093E',
    detectedProvider: '\u092A\u0939\u091A\u093E\u0928\u093E \u0917\u092F\u093E \u092A\u094D\u0930\u0926\u093E\u0924\u093E',
    rawLabel: '\u0930\u0949',
    noRegistrationInformation: '\u0915\u094B\u0908 \u092A\u0902\u091C\u0940\u0915\u0930\u0923 \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    registrationDetailsUnavailable: '\u092A\u0902\u091C\u0940\u0915\u0930\u0923 \u0935\u093F\u0935\u0930\u0923 \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    unitYearOne: '\u0935\u0930\u094D\u0937',
    unitYearMany: '\u0935\u0930\u094D\u0937',
    unitMonthOne: '\u092E\u093E\u0939',
    unitMonthMany: '\u092E\u093E\u0939',
    unitDayOne: '\u0926\u093F\u0928',
    unitDayMany: '\u0926\u093F\u0928',
    wordExpired: '\u0938\u092E\u093E\u092A\u094D\u0924',
    mxPriorityLabel: '\u092A\u094D\u0930\u093E\u0925\u092E\u093F\u0915\u0924\u093E',
    providerHintMicrosoft365: 'MX Exchange Online Protection (EOP) \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintGoogleWorkspace: 'MX Google mail exchangers \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintCloudflare: 'MX Cloudflare (mx.cloudflare.net) \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintProofpoint: 'MX Proofpoint-hosted mail \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintMimecast: 'MX Mimecast \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintZoho: 'MX Zoho Mail \u0915\u0940 \u0913\u0930 \u0907\u0902\u0917\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    providerHintUnknown: 'MX hostname \u0938\u0947 provider \u092A\u0939\u091A\u093E\u0928\u093E \u0928\u0939\u0940\u0902 \u0917\u092F\u093E\u0964',
    riskClean: '\u0938\u094D\u0935\u091A\u094D\u091B',
    riskWarning: '\u091A\u0947\u0924\u093E\u0935\u0928\u0940',
    riskElevated: '\u0909\u091A\u094D\u091A \u091C\u094B\u0916\u093F\u092E',
    mxUsingParentNote: '(\u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0938\u0947 MX \u0909\u092A\u092F\u094B\u0917 \u0915\u093F\u092F\u093E \u091C\u093E \u0930\u0939\u093E \u0939\u0948)',
    parentCheckedNoMx: '\u092E\u0942\u0932 {parentDomain} \u0915\u0940 \u091C\u093E\u0901\u091A \u0915\u0940 \u0917\u0908 (MX \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E)\u0964',
    expiredOn: '{date} \u0915\u094B \u0938\u092E\u093E\u092A\u094D\u0924',
    registrationAppearsExpired: '\u092A\u0902\u091C\u0940\u0915\u0930\u0923 \u0938\u092E\u093E\u092A\u094D\u0924 \u092A\u094D\u0930\u0924\u0940\u0924 \u0939\u094B\u0924\u093E \u0939\u0948\u0964',
    newDomainUnder90Days: '90 \u0926\u093F\u0928\u094B\u0902 \u0938\u0947 \u0915\u092E \u092A\u0941\u0930\u093E\u0928\u093E \u0928\u092F\u093E \u0921\u094B\u092E\u0947\u0928\u0964',
    newDomainUnder180Days: '180 \u0926\u093F\u0928\u094B\u0902 \u0938\u0947 \u0915\u092E \u092A\u0941\u0930\u093E\u0928\u093E \u0928\u092F\u093E \u0921\u094B\u092E\u0947\u0928\u0964',
    domainNameLabel: '\u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E',
    domainStatusLabel: '\u0921\u094B\u092E\u0947\u0928 \u0938\u094D\u0925\u093F\u0924\u093F',
    mxRecordsLabel: 'MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921',
    spfStatusLabel: 'SPF \u0938\u094D\u0925\u093F\u0924\u093F',
    dkim1StatusLabel: 'DKIM1 \u0938\u094D\u0925\u093F\u0924\u093F',
    dkim2StatusLabel: 'DKIM2 \u0938\u094D\u0925\u093F\u0924\u093F',
    dmarcStatusLabel: 'DMARC \u0938\u094D\u0925\u093F\u0924\u093F'
  },
  'ja-JP': {
    languageName: '\u65E5\u672C\u8A9E\uFF08\u65E5\u672C\uFF09',
    appHeading: 'Azure Communication Services<br/>\u30E1\u30FC\u30EB \u30C9\u30E1\u30A4\u30F3 \u30C1\u30A7\u30C3\u30AB\u30FC',
    placeholderDomain: 'example.jp',
    lookup: '\u78BA\u8A8D',
    checkingShort: '\u78BA\u8A8D\u4E2D',
    themeDark: '\u30C0\u30FC\u30AF \u30E2\u30FC\u30C9 \uD83C\uDF19',
    themeLight: '\u30E9\u30A4\u30C8 \u30E2\u30FC\u30C9 \u2600\uFE0F',
    copyLink: '\u30EA\u30F3\u30AF\u3092\u30B3\u30D4\u30FC \uD83D\uDD17',
    copyScreenshot: '\u30DA\u30FC\u30B8\u306E\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u3092\u30B3\u30D4\u30FC \uD83D\uDCF8',
    downloadJson: 'JSON \u3092\u30C0\u30A6\u30F3\u30ED\u30FC\u30C9 \uD83D\uDCE5',
    reportIssue: '\u554F\u984C\u3092\u5831\u544A \uD83D\uDC1B',
    signInMicrosoft: 'Microsoft \u3067\u30B5\u30A4\u30F3\u30A4\u30F3 \uD83D\uDD12',
    signOut: '\u30B5\u30A4\u30F3\u30A2\u30A6\u30C8',
    termsOfService: '\u5229\u7528\u898F\u7D04',
    privacyStatement: '\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC',
    recent: '\u6700\u8FD1',
    languageLabel: '\u8A00\u8A9E',
    pageTitle: 'Azure Communication Services - \u30E1\u30FC\u30EB \u30C9\u30E1\u30A4\u30F3 \u30C1\u30A7\u30C3\u30AB\u30FC',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u4F5C\u6210\u8005: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 PowerShell \u306B\u3088\u308A\u751F\u6210 \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">\u5148\u982D\u3078\u623B\u308B</a>',
    promptEnterDomain: '\u30C9\u30E1\u30A4\u30F3\u3092\u5165\u529B\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    promptEnterValidDomain: '\u6709\u52B9\u306A\u30C9\u30E1\u30A4\u30F3\u540D\u3092\u5165\u529B\u3057\u3066\u304F\u3060\u3055\u3044\uFF08\u4F8B: example.com\uFF09\u3002',
    clipboardUnavailable: '\u3053\u306E\u30D6\u30E9\u30A6\u30B6\u30FC\u3067\u306F Clipboard API \u3092\u5229\u7528\u3067\u304D\u307E\u305B\u3093\u3002',
    linkCopiedToClipboard: '\u30EA\u30F3\u30AF\u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F\u3002',
    failedCopyLink: '\u30EA\u30F3\u30AF\u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    copiedToClipboard: '\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F\u3002',
    failedCopyToClipboard: '\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u3078\u306E\u30B3\u30D4\u30FC\u306B\u5931\u6557\u3057\u307E\u3057\u305F\u3002',
    nothingToCopyFor: '{field} \u306B\u30B3\u30D4\u30FC\u3059\u308B\u5185\u5BB9\u304C\u3042\u308A\u307E\u305B\u3093\u3002',
    copiedFieldToClipboard: '{field} \u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F\u3002',
    failedCopyFieldToClipboard: '{field} \u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    screenshotClipboardUnsupported: '\u3053\u306E\u30D6\u30E9\u30A6\u30B6\u30FC\u3067\u306F\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u306E\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u6A5F\u80FD\u3092\u5229\u7528\u3067\u304D\u307E\u305B\u3093\u3002',
    screenshotContainerNotFound: '\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u7528\u306E\u30B3\u30F3\u30C6\u30CA\u30FC\u304C\u898B\u3064\u304B\u308A\u307E\u305B\u3093\u3002',
    screenshotCaptureFailed: '\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u306E\u53D6\u5F97\u306B\u5931\u6557\u3057\u307E\u3057\u305F\u3002',
    screenshotCopiedToClipboard: '\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F\u3002',
    failedCopyScreenshot: '\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u3092\u30AF\u30EA\u30C3\u30D7\u30DC\u30FC\u30C9\u306B\u30B3\u30D4\u30FC\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    screenshotRenderFailed: '\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8\u306E\u53D6\u5F97\u306B\u5931\u6557\u3057\u307E\u3057\u305F\u3002',
    issueReportingNotConfigured: '\u554F\u984C\u5831\u544A\u304C\u69CB\u6210\u3055\u308C\u3066\u3044\u307E\u305B\u3093\u3002',
    issueReportConfirm: 'Issue tracker \u3092\u958B\u304D\u3001{detail} \u3092\u542B\u3081\u307E\u3059\u3002\u7D9A\u884C\u3057\u307E\u3059\u304B?',
    issueReportDetailDomain: '\u30C9\u30E1\u30A4\u30F3\u540D "{domain}"',
    issueReportDetailInput: '\u5165\u529B\u30DC\u30C3\u30AF\u30B9\u306E\u30C9\u30E1\u30A4\u30F3\u540D',
    authSignInNotConfigured: 'Microsoft \u30B5\u30A4\u30F3\u30A4\u30F3\u304C\u69CB\u6210\u3055\u308C\u3066\u3044\u307E\u305B\u3093\u3002ACS_ENTRA_CLIENT_ID \u304C\u30DA\u30FC\u30B8\u306B\u57CB\u3081\u8FBC\u307E\u308C\u3066\u3044\u308B\u3053\u3068\u3092\u78BA\u8A8D\u3057\u3001\u66F4\u65B0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    authLibraryLoadFailed: 'Microsoft \u30B5\u30A4\u30F3\u30A4\u30F3 \u30E9\u30A4\u30D6\u30E9\u30EA\u306E\u8AAD\u307F\u8FBC\u307F\u306B\u5931\u6557\u3057\u307E\u3057\u305F\u3002MSAL CDN \u3078\u306E\u30A2\u30AF\u30BB\u30B9\u3092\u78BA\u8A8D\u3059\u308B\u304B\u3001\u30ED\u30FC\u30AB\u30EB\u306E msal-browser.min.js \u3092\u7528\u610F\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    authInitFailed: 'Microsoft \u30B5\u30A4\u30F3\u30A4\u30F3\u306E\u521D\u671F\u5316\u306B\u5931\u6557\u3057\u307E\u3057\u305F\u3002\u8A73\u7D30\u306F\u30D6\u30E9\u30A6\u30B6\u30FC \u30B3\u30F3\u30BD\u30FC\u30EB\u3092\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    authInitFailedWithReason: 'Microsoft \u30B5\u30A4\u30F3\u30A4\u30F3\u306E\u521D\u671F\u5316\u306B\u5931\u6557\u3057\u307E\u3057\u305F: {reason}',
    authSetClientIdAndRestart: 'Microsoft \u30B5\u30A4\u30F3\u30A4\u30F3\u304C\u69CB\u6210\u3055\u308C\u3066\u3044\u307E\u305B\u3093\u3002ACS_ENTRA_CLIENT_ID \u74B0\u5883\u5909\u6570\u3092\u8A2D\u5B9A\u3057\u3066\u518D\u8D77\u52D5\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    authSigningIn: '\u30B5\u30A4\u30F3\u30A4\u30F3\u4E2D...',
    authSignInCancelled: '\u30B5\u30A4\u30F3\u30A4\u30F3\u306F\u30AD\u30E3\u30F3\u30BB\u30EB\u3055\u308C\u307E\u3057\u305F\u3002',
    authSignInFailed: '\u30B5\u30A4\u30F3\u30A4\u30F3\u306B\u5931\u6557\u3057\u307E\u3057\u305F: {reason}',
    authUnknownError: '\u4E0D\u660E\u306A\u30A8\u30E9\u30FC',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois',
    passing: '\u6210\u529F',
    failed: '\u5931\u6557',
    warningState: '\u8B66\u544A',
    dnsTxtLookup: 'DNS TXT \u53C2\u7167',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    acsReadiness: 'ACS \u6E96\u5099\u72B6\u6CC1',
    resolvedSuccessfully: '\u6B63\u5E38\u306B\u89E3\u6C7A\u3055\u308C\u307E\u3057\u305F\u3002',
    msDomainVerificationFound: 'ms-domain-verification TXT \u304C\u898B\u3064\u304B\u308A\u307E\u3057\u305F\u3002',
    addAcsTxtFromPortal: 'Azure portal \u304B\u3089 ACS TXT \u3092\u8FFD\u52A0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    source: '\u30BD\u30FC\u30B9',
    lookupDomainLabel: '\u7167\u4F1A\u30C9\u30E1\u30A4\u30F3',
    creationDate: '\u4F5C\u6210\u65E5',
    registryExpiryDate: '\u30EC\u30B8\u30B9\u30C8\u30EA\u6709\u52B9\u671F\u9650',
    registrarLabel: '\u30EC\u30B8\u30B9\u30C8\u30E9',
    registrantLabel: '\u767B\u9332\u8005',
    domainAgeLabel: '\u30C9\u30E1\u30A4\u30F3\u5E74\u9F62',
    domainExpiringIn: '\u6709\u52B9\u671F\u9650\u307E\u3067',
    daysUntilExpiry: '\u6709\u52B9\u671F\u9650\u307E\u3067\u306E\u65E5\u6570',
    ageLabel: '\u5E74\u9F62',
    expiresInLabel: '\u671F\u9650\u307E\u3067',
    zonesQueried: '\u7167\u4F1A\u3057\u305F\u30BE\u30FC\u30F3',
    totalQueries: '\u7DCF\u30AF\u30A8\u30EA\u6570',
    errorsCount: '\u30A8\u30E9\u30FC',
    listed: '\u63B2\u8F09\u3042\u308A',
    notListed: '\u63B2\u8F09\u306A\u3057',
    riskLabel: '\u30EA\u30B9\u30AF',
    reputationWord: '\u8A55\u4FA1',
    clean: '\u30AF\u30EA\u30FC\u30F3',
    excellent: '\u512A\u79C0',
    great: '\u3068\u3066\u3082\u826F\u3044',
    good: '\u826F\u3044',
    fair: '\u666E\u901A',
    poor: '\u4F4E\u3044',
    yes: '\u306F\u3044',
    no: '\u3044\u3044\u3048',
    none: '\u306A\u3057',
    priority: '\u512A\u5148\u5EA6',
    detectedProvider: '\u691C\u51FA\u3055\u308C\u305F\u30D7\u30ED\u30D0\u30A4\u30C0\u30FC',
    rawLabel: '\u751F\u30C7\u30FC\u30BF',
    noRegistrationInformation: '\u767B\u9332\u60C5\u5831\u306F\u5229\u7528\u3067\u304D\u307E\u305B\u3093\u3002',
    registrationDetailsUnavailable: '\u767B\u9332\u8A73\u7D30\u306F\u5229\u7528\u3067\u304D\u307E\u305B\u3093\u3002',
    unitYearOne: '\u5E74',
    unitYearMany: '\u5E74',
    unitMonthOne: '\u304B\u6708',
    unitMonthMany: '\u304B\u6708',
    unitDayOne: '\u65E5',
    unitDayMany: '\u65E5',
    wordExpired: '\u671F\u9650\u5207\u308C',
    mxPriorityLabel: '\u512A\u5148\u5EA6',
    providerHintMicrosoft365: 'MX \u306F Exchange Online Protection (EOP) \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintGoogleWorkspace: 'MX \u306F Google mail exchangers \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintCloudflare: 'MX \u306F Cloudflare (mx.cloudflare.net) \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintProofpoint: 'MX \u306F Proofpoint-hosted mail \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintMimecast: 'MX \u306F Mimecast \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintZoho: 'MX \u306F Zoho Mail \u3092\u6307\u3057\u3066\u3044\u307E\u3059\u3002',
    providerHintUnknown: 'MX \u30DB\u30B9\u30C8\u540D\u304B\u3089\u30D7\u30ED\u30D0\u30A4\u30C0\u30FC\u3092\u7279\u5B9A\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    riskClean: '\u30AF\u30EA\u30FC\u30F3',
    riskWarning: '\u8B66\u544A',
    riskElevated: '\u9AD8\u30EA\u30B9\u30AF',
    mxUsingParentNote: '\uFF08\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E MX \u3092\u4F7F\u7528\uFF09',
    parentCheckedNoMx: '\u89AA\u30C9\u30E1\u30A4\u30F3 {parentDomain} \u3092\u78BA\u8A8D\u3057\u307E\u3057\u305F\uFF08MX \u306A\u3057\uFF09\u3002',
    expiredOn: '{date} \u306B\u671F\u9650\u5207\u308C',
    registrationAppearsExpired: '\u767B\u9332\u306F\u671F\u9650\u5207\u308C\u306E\u3088\u3046\u3067\u3059\u3002',
    newDomainUnder90Days: '90 \u65E5\u672A\u6E80\u306E\u65B0\u3057\u3044\u30C9\u30E1\u30A4\u30F3\u3002',
    newDomainUnder180Days: '180 \u65E5\u672A\u6E80\u306E\u65B0\u3057\u3044\u30C9\u30E1\u30A4\u30F3\u3002',
    domainNameLabel: '\u30C9\u30E1\u30A4\u30F3\u540D',
    domainStatusLabel: '\u30C9\u30E1\u30A4\u30F3\u306E\u72B6\u614B',
    mxRecordsLabel: 'MX \u30EC\u30B3\u30FC\u30C9',
    spfStatusLabel: 'SPF \u72B6\u614B',
    dkim1StatusLabel: 'DKIM1 \u72B6\u614B',
    dkim2StatusLabel: 'DKIM2 \u72B6\u614B',
    dmarcStatusLabel: 'DMARC \u72B6\u614B'
  },
  'ru-RU': {
    languageName: '\u0420\u0443\u0441\u0441\u043A\u0438\u0439 (\u0420\u043E\u0441\u0441\u0438\u044F)',
    appHeading: 'Azure Communication Services<br/>\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u043F\u043E\u0447\u0442\u043E\u0432\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430',
    placeholderDomain: 'example.ru',
    lookup: '\u041F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C',
    checkingShort: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430',
    themeDark: '\u0422\u0451\u043C\u043D\u044B\u0439 \u0440\u0435\u0436\u0438\u043C \uD83C\uDF19',
    themeLight: '\u0421\u0432\u0435\u0442\u043B\u044B\u0439 \u0440\u0435\u0436\u0438\u043C \u2600\uFE0F',
    copyLink: '\u041A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0441\u044B\u043B\u043A\u0443 \uD83D\uDD17',
    copyScreenshot: '\u041A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u043D\u0438\u043C\u043E\u043A \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u044B \uD83D\uDCF8',
    downloadJson: '\u0421\u043A\u0430\u0447\u0430\u0442\u044C JSON \uD83D\uDCE5',
    reportIssue: '\u0421\u043E\u043E\u0431\u0449\u0438\u0442\u044C \u043E \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0435 \uD83D\uDC1B',
    signInMicrosoft: '\u0412\u043E\u0439\u0442\u0438 \u0447\u0435\u0440\u0435\u0437 Microsoft \uD83D\uDD12',
    signOut: '\u0412\u044B\u0439\u0442\u0438',
    termsOfService: '\u0423\u0441\u043B\u043E\u0432\u0438\u044F \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F',
    privacyStatement: '\u041A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u044C',
    recent: '\u041D\u0435\u0434\u0430\u0432\u043D\u0438\u0435',
    missing: '\u041E\u0422\u0421\u0423\u0422\u0421\u0422\u0412\u0423\u0415\u0422',
    pass: '\u0423\u0421\u041F\u0415\u0425',
    fail: '\u041E\u0428\u0418\u0411\u041A\u0410',
    warn: '\u041F\u0420\u0415\u0414\u0423\u041F\u0420\u0415\u0416\u0414\u0415\u041D\u0418\u0415',
    newDomain: '\u041D\u041E\u0412\u042B\u0419 \u0414\u041E\u041C\u0415\u041D',
    languageLabel: '\u042F\u0437\u044B\u043A',
    pageTitle: 'Azure Communication Services - \u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u043F\u043E\u0447\u0442\u043E\u0432\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u0410\u0432\u0442\u043E\u0440: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 \u0421\u0433\u0435\u043D\u0435\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u043E PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">\u041D\u0430\u0432\u0435\u0440\u0445</a>',
    promptEnterDomain: '\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0434\u043E\u043C\u0435\u043D.',
    promptEnterValidDomain: '\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0434\u043E\u043F\u0443\u0441\u0442\u0438\u043C\u043E\u0435 \u0434\u043E\u043C\u0435\u043D\u043D\u043E\u0435 \u0438\u043C\u044F (\u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440: example.com).',
    clipboardUnavailable: 'Clipboard API \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u0435\u043D \u0432 \u044D\u0442\u043E\u043C \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435.',
    linkCopiedToClipboard: '\u0421\u0441\u044B\u043B\u043A\u0430 \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u0430 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    failedCopyLink: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0441\u044B\u043B\u043A\u0443 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    copiedToClipboard: '\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u043E \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    failedCopyToClipboard: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    nothingToCopyFor: '\u041D\u0435\u0442 \u0434\u0430\u043D\u043D\u044B\u0445 \u0434\u043B\u044F \u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F \u0434\u043B\u044F {field}.',
    copiedFieldToClipboard: '{field} \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u043E \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    failedCopyFieldToClipboard: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C {field} \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    screenshotClipboardUnsupported: '\u041F\u043E\u0434\u0434\u0435\u0440\u0436\u043A\u0430 \u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F \u0441\u043D\u0438\u043C\u043A\u043E\u0432 \u044D\u043A\u0440\u0430\u043D\u0430 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0432 \u044D\u0442\u043E\u043C \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435.',
    screenshotContainerNotFound: '\u041A\u043E\u043D\u0442\u0435\u0439\u043D\u0435\u0440 \u0434\u043B\u044F \u0441\u043D\u0438\u043C\u043A\u0430 \u044D\u043A\u0440\u0430\u043D\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.',
    screenshotCaptureFailed: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0441\u043D\u0438\u043C\u043E\u043A \u044D\u043A\u0440\u0430\u043D\u0430.',
    screenshotCopiedToClipboard: '\u0421\u043D\u0438\u043C\u043E\u043A \u044D\u043A\u0440\u0430\u043D\u0430 \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    failedCopyScreenshot: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u043D\u0438\u043C\u043E\u043A \u044D\u043A\u0440\u0430\u043D\u0430 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.',
    screenshotRenderFailed: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0441\u043D\u0438\u043C\u043E\u043A \u044D\u043A\u0440\u0430\u043D\u0430.',
    issueReportingNotConfigured: '\u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0439 \u043E \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u043D\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u0430.',
    issueReportConfirm: '\u0411\u0443\u0434\u0435\u0442 \u043E\u0442\u043A\u0440\u044B\u0442 \u0442\u0440\u0435\u043A\u0435\u0440 \u0437\u0430\u0434\u0430\u0447, \u0432\u043A\u043B\u044E\u0447\u0430\u044F {detail}. \u041F\u0440\u043E\u0434\u043E\u043B\u0436\u0438\u0442\u044C?',
    issueReportDetailDomain: '\u0438\u043C\u044F \u0434\u043E\u043C\u0435\u043D\u0430 "{domain}"',
    issueReportDetailInput: '\u0438\u043C\u044F \u0434\u043E\u043C\u0435\u043D\u0430 \u0438\u0437 \u043F\u043E\u043B\u044F \u0432\u0432\u043E\u0434\u0430',
    authSignInNotConfigured: '\u0412\u0445\u043E\u0434 \u0447\u0435\u0440\u0435\u0437 Microsoft \u043D\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D. \u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044C, \u0447\u0442\u043E ACS_ENTRA_CLIENT_ID \u0432\u043D\u0435\u0434\u0440\u0451\u043D \u0432 \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0443, \u0438 \u043E\u0431\u043D\u043E\u0432\u0438\u0442\u0435 \u0435\u0451.',
    authLibraryLoadFailed: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u0431\u0438\u0431\u043B\u0438\u043E\u0442\u0435\u043A\u0443 \u0432\u0445\u043E\u0434\u0430 Microsoft. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0434\u043E\u0441\u0442\u0443\u043F \u043A MSAL CDN \u0438\u043B\u0438 \u043F\u0440\u0435\u0434\u043E\u0441\u0442\u0430\u0432\u044C\u0442\u0435 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0439 \u0444\u0430\u0439\u043B msal-browser.min.js.',
    authInitFailed: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0438\u043D\u0438\u0446\u0438\u0430\u043B\u0438\u0437\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0432\u0445\u043E\u0434 \u0447\u0435\u0440\u0435\u0437 Microsoft. \u041F\u043E\u0434\u0440\u043E\u0431\u043D\u043E\u0441\u0442\u0438 \u0441\u043C\u043E\u0442\u0440\u0438\u0442\u0435 \u0432 \u043A\u043E\u043D\u0441\u043E\u043B\u0438 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430.',
    authInitFailedWithReason: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0438\u043D\u0438\u0446\u0438\u0430\u043B\u0438\u0437\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0432\u0445\u043E\u0434 \u0447\u0435\u0440\u0435\u0437 Microsoft: {reason}',
    authSetClientIdAndRestart: '\u0412\u0445\u043E\u0434 \u0447\u0435\u0440\u0435\u0437 Microsoft \u043D\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D. \u0423\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 \u043F\u0435\u0440\u0435\u043C\u0435\u043D\u043D\u0443\u044E \u0441\u0440\u0435\u0434\u044B ACS_ENTRA_CLIENT_ID \u0438 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0435.',
    authSigningIn: '\u0412\u044B\u043F\u043E\u043B\u043D\u044F\u0435\u0442\u0441\u044F \u0432\u0445\u043E\u0434...',
    authSignInCancelled: '\u0412\u0445\u043E\u0434 \u0431\u044B\u043B \u043E\u0442\u043C\u0435\u043D\u0451\u043D.',
    authSignInFailed: '\u041E\u0448\u0438\u0431\u043A\u0430 \u0432\u0445\u043E\u0434\u0430: {reason}',
    authUnknownError: '\u041D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u043E\u0448\u0438\u0431\u043A\u0430',
    authMicrosoftLabel: 'Microsoft',
    rawWhoisLabel: 'whois',
    passing: '\u0423\u0441\u043F\u0435\u0448\u043D\u043E',
    failed: '\u041E\u0448\u0438\u0431\u043A\u0430',
    warningState: '\u041F\u0440\u0435\u0434\u0443\u043F\u0440\u0435\u0436\u0434\u0435\u043D\u0438\u0435',
    dnsTxtLookup: '\u041F\u043E\u0438\u0441\u043A DNS TXT',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    acsReadiness: '\u0413\u043E\u0442\u043E\u0432\u043D\u043E\u0441\u0442\u044C ACS',
    resolvedSuccessfully: '\u0423\u0441\u043F\u0435\u0448\u043D\u043E \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043D\u043E.',
    msDomainVerificationFound: 'TXT ms-domain-verification \u043D\u0430\u0439\u0434\u0435\u043D.',
    addAcsTxtFromPortal: '\u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 ACS TXT \u0438\u0437 \u043F\u043E\u0440\u0442\u0430\u043B\u0430 Azure.',
    source: '\u0418\u0441\u0442\u043E\u0447\u043D\u0438\u043A',
    lookupDomainLabel: '\u0417\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u044B\u0439 \u0434\u043E\u043C\u0435\u043D',
    creationDate: '\u0414\u0430\u0442\u0430 \u0441\u043E\u0437\u0434\u0430\u043D\u0438\u044F',
    registryExpiryDate: '\u0414\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438',
    registrarLabel: '\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440',
    registrantLabel: '\u0412\u043B\u0430\u0434\u0435\u043B\u0435\u0446',
    domainAgeLabel: '\u0412\u043E\u0437\u0440\u0430\u0441\u0442 \u0434\u043E\u043C\u0435\u043D\u0430',
    domainExpiringIn: '\u0421\u0440\u043E\u043A \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044F \u0438\u0441\u0442\u0435\u043A\u0430\u0435\u0442 \u0447\u0435\u0440\u0435\u0437',
    daysUntilExpiry: '\u0414\u043D\u0435\u0439 \u0434\u043E \u0438\u0441\u0442\u0435\u0447\u0435\u043D\u0438\u044F',
    ageLabel: '\u0412\u043E\u0437\u0440\u0430\u0441\u0442',
    expiresInLabel: '\u0418\u0441\u0442\u0435\u043A\u0430\u0435\u0442 \u0447\u0435\u0440\u0435\u0437',
    zonesQueried: '\u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D\u043E \u0437\u043E\u043D',
    totalQueries: '\u0412\u0441\u0435\u0433\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432',
    errorsCount: '\u041E\u0448\u0438\u0431\u043A\u0438',
    listed: '\u0412 \u0441\u043F\u0438\u0441\u043A\u0430\u0445',
    notListed: '\u041D\u0435 \u0432 \u0441\u043F\u0438\u0441\u043A\u0430\u0445',
    riskLabel: '\u0420\u0438\u0441\u043A',
    reputationWord: '\u0420\u0435\u043F\u0443\u0442\u0430\u0446\u0438\u044F',
    clean: '\u0427\u0438\u0441\u0442\u043E',
    excellent: '\u041E\u0442\u043B\u0438\u0447\u043D\u043E',
    great: '\u041E\u0447\u0435\u043D\u044C \u0445\u043E\u0440\u043E\u0448\u043E',
    good: '\u0425\u043E\u0440\u043E\u0448\u043E',
    fair: '\u0423\u0434\u043E\u0432\u043B\u0435\u0442\u0432\u043E\u0440\u0438\u0442\u0435\u043B\u044C\u043D\u043E',
    poor: '\u041F\u043B\u043E\u0445\u043E',
    yes: '\u0414\u0430',
    no: '\u041D\u0435\u0442',
    none: '\u041D\u0435\u0442',
    priority: '\u041F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442',
    detectedProvider: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u043D\u044B\u0439 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440',
    rawLabel: '\u0418\u0441\u0445\u043E\u0434\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435',
    noRegistrationInformation: '\u0418\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u044F \u043E \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430.',
    registrationDetailsUnavailable: '\u0421\u0432\u0435\u0434\u0435\u043D\u0438\u044F \u043E \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B.',
    unitYearOne: '\u0433\u043E\u0434',
    unitYearMany: '\u043B\u0435\u0442',
    unitMonthOne: '\u043C\u0435\u0441\u044F\u0446',
    unitMonthMany: '\u043C\u0435\u0441\u044F\u0446\u0435\u0432',
    unitDayOne: '\u0434\u0435\u043D\u044C',
    unitDayMany: '\u0434\u043D\u0435\u0439',
    wordExpired: '\u0418\u0441\u0442\u0451\u043A',
    mxPriorityLabel: '\u041F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442',
    providerHintMicrosoft365: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 \u043F\u043E\u0447\u0442\u043E\u0432\u044B\u0435 \u0441\u0435\u0440\u0432\u0435\u0440\u044B Google.',
    providerHintCloudflare: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 \u043F\u043E\u0447\u0442\u0443, \u0440\u0430\u0437\u043C\u0435\u0449\u0451\u043D\u043D\u0443\u044E \u0432 Proofpoint.',
    providerHintMimecast: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Mimecast.',
    providerHintZoho: 'MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Zoho Mail.',
    providerHintUnknown: '\u041F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440 \u043D\u0435 \u0440\u0430\u0441\u043F\u043E\u0437\u043D\u0430\u043D \u043F\u043E \u0438\u043C\u0435\u043D\u0438 \u0445\u043E\u0441\u0442\u0430 MX.',
    riskClean: '\u0427\u0438\u0441\u0442\u043E',
    riskWarning: '\u041F\u0440\u0435\u0434\u0443\u043F\u0440\u0435\u0436\u0434\u0435\u043D\u0438\u0435',
    riskElevated: '\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u0439 \u0440\u0438\u0441\u043A',
    mxUsingParentNote: '(\u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442\u0441\u044F MX \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain})',
    parentCheckedNoMx: '\u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u0438\u0439 \u0434\u043E\u043C\u0435\u043D {parentDomain} (MX \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D).',
    expiredOn: '\u0418\u0441\u0442\u0451\u043A {date}',
    registrationAppearsExpired: '\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044F \u0434\u043E\u043C\u0435\u043D\u0430, \u043F\u043E\u0445\u043E\u0436\u0435, \u0438\u0441\u0442\u0435\u043A\u043B\u0430.',
    newDomainUnder90Days: '\u041D\u043E\u0432\u044B\u0439 \u0434\u043E\u043C\u0435\u043D \u043C\u043B\u0430\u0434\u0448\u0435 90 \u0434\u043D\u0435\u0439.',
    newDomainUnder180Days: '\u041D\u043E\u0432\u044B\u0439 \u0434\u043E\u043C\u0435\u043D \u043C\u043B\u0430\u0434\u0448\u0435 180 \u0434\u043D\u0435\u0439.',
    domainNameLabel: '\u0418\u043C\u044F \u0434\u043E\u043C\u0435\u043D\u0430',
    domainStatusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441 \u0434\u043E\u043C\u0435\u043D\u0430',
    mxRecordsLabel: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438',
    spfStatusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441 SPF',
    dkim1StatusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441 DKIM1',
    dkim2StatusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441 DKIM2',
    dmarcStatusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441 DMARC'
  }
};

Object.keys(TRANSLATION_EXTENSIONS).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, TRANSLATION_EXTENSIONS[code]);
});

const REMAINING_TRANSLATION_OVERRIDES = {
  'zh-CN': {
    emailQuota: '\u7535\u5B50\u90AE\u4EF6\u914D\u989D',
    domainVerification: '\u57DF\u9A8C\u8BC1',
    domainRegistration: '\u57DF\u6CE8\u518C (WHOIS/RDAP)',
    mxRecords: 'MX \u8BB0\u5F55',
    spfQueried: 'SPF\uFF08\u67E5\u8BE2\u57DF TXT\uFF09',
    acsDomainVerificationTxt: 'ACS \u57DF\u9A8C\u8BC1 TXT',
    txtRecordsQueried: 'TXT \u8BB0\u5F55\uFF08\u67E5\u8BE2\u57DF\uFF09',
    dmarc: 'DMARC',
    cname: 'CNAME',
    guidance: '\u6307\u5BFC',
    helpfulLinks: '\u6709\u7528\u94FE\u63A5',
    externalTools: '\u5916\u90E8\u5DE5\u5177',
    acsReadyMessage: '\u6B64\u57DF\u770B\u8D77\u6765\u5DF2\u51C6\u5907\u597D\u8FDB\u884C Azure Communication Services \u57DF\u9A8C\u8BC1\u3002',
    guidanceMxProviderDetected: '\u68C0\u6D4B\u5230\u7684 MX \u63D0\u4F9B\u5546: {provider}',
    guidanceDomainExpired: '\u57DF\u540D\u6CE8\u518C\u4F3C\u4E4E\u5DF2\u8FC7\u671F\u3002\u8BF7\u5148\u7EED\u8BA2\u57DF\u540D\u3002',
    guidanceDomainVeryYoung: '\u8BE5\u57DF\u540D\u6CE8\u518C\u65F6\u95F4\u975E\u5E38\u8FD1\uFF08{days} \u5929\u5185\uFF09\u3002\u8FD9\u4F1A\u88AB\u89C6\u4E3A\u9A8C\u8BC1\u9519\u8BEF\u4FE1\u53F7\uFF1B\u8BF7\u8BA9\u5BA2\u6237\u518D\u7B49\u5F85\u4E00\u6BB5\u65F6\u95F4\u3002',
    guidanceDomainYoung: '\u8BE5\u57DF\u540D\u6CE8\u518C\u65F6\u95F4\u8F83\u8FD1\uFF08{days} \u5929\u5185\uFF09\u3002\u8BF7\u8BA9\u5BA2\u6237\u518D\u7B49\u5F85\u4E00\u6BB5\u65F6\u95F4\uFF1BMicrosoft \u4F7F\u7528\u6B64\u4FE1\u53F7\u5E2E\u52A9\u9632\u6B62\u5783\u573E\u90AE\u4EF6\u53D1\u9001\u8005\u5EFA\u7ACB\u65B0\u57DF\u540D\u3002',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  'hi-IN': {
    emailQuota: '\u0908\u092E\u0947\u0932 \u0915\u094B\u091F\u093E',
    domainVerification: '\u0921\u094B\u092E\u0947\u0928 \u0938\u0924\u094D\u092F\u093E\u092A\u0928',
    domainRegistration: '\u0921\u094B\u092E\u0947\u0928 \u092A\u0902\u091C\u0940\u0915\u0930\u0923 (WHOIS/RDAP)',
    mxRecords: 'MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921',
    spfQueried: 'SPF (\u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u090F \u0917\u090F \u0921\u094B\u092E\u0947\u0928 \u0915\u093E TXT)',
    acsDomainVerificationTxt: 'ACS \u0921\u094B\u092E\u0947\u0928 \u0938\u0924\u094D\u092F\u093E\u092A\u0928 TXT',
    txtRecordsQueried: 'TXT \u0930\u093F\u0915\u0949\u0930\u094D\u0921 (\u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u092F\u093E \u0917\u092F\u093E \u0921\u094B\u092E\u0947\u0928)',
    dmarc: 'DMARC',
    cname: 'CNAME',
    guidance: '\u092E\u093E\u0930\u094D\u0917\u0926\u0930\u094D\u0936\u0928',
    helpfulLinks: '\u0909\u092A\u092F\u094B\u0917\u0940 \u0932\u093F\u0902\u0915',
    externalTools: '\u092C\u093E\u0939\u0930\u0940 \u091F\u0942\u0932',
    acsReadyMessage: '\u092F\u0939 \u0921\u094B\u092E\u0947\u0928 Azure Communication Services \u0921\u094B\u092E\u0947\u0928 \u0938\u0924\u094D\u092F\u093E\u092A\u0928 \u0915\u0947 \u0932\u093F\u090F \u0924\u0948\u092F\u093E\u0930 \u092A\u094D\u0930\u0924\u0940\u0924 \u0939\u094B\u0924\u093E \u0939\u0948\u0964',
    guidanceMxProviderDetected: '\u092A\u0924\u093E \u091A\u0932\u093E MX \u092A\u094D\u0930\u0926\u093E\u0924\u093E: {provider}',
    guidanceDomainExpired: '\u0921\u094B\u092E\u0947\u0928 \u092A\u0902\u091C\u0940\u0915\u0930\u0923 \u0938\u092E\u093E\u092A\u094D\u0924 \u092A\u094D\u0930\u0924\u0940\u0924 \u0939\u094B\u0924\u093E \u0939\u0948\u0964 \u0906\u0917\u0947 \u092C\u0922\u093C\u0928\u0947 \u0938\u0947 \u092A\u0939\u0932\u0947 \u0921\u094B\u092E\u0947\u0928 \u0928\u0935\u0940\u0928\u0940\u0915\u0943\u0924 \u0915\u0930\u0947\u0902\u0964',
    guidanceDomainVeryYoung: '\u0921\u094B\u092E\u0947\u0928 \u092C\u0939\u0941\u0924 \u0939\u093E\u0932 \u0939\u0940 \u092E\u0947\u0902 \u092A\u0902\u091C\u0940\u0915\u0943\u0924 \u0939\u0941\u0906 \u0939\u0948 ({days} \u0926\u093F\u0928\u094B\u0902 \u0915\u0947 \u092D\u0940\u0924\u0930)\u0964 \u0907\u0938\u0947 \u0938\u0924\u094D\u092F\u093E\u092A\u0928 \u0915\u0947 \u0932\u093F\u090F \u0924\u094D\u0930\u0941\u091F\u093F \u0938\u0902\u0915\u0947\u0924 \u092E\u093E\u0928\u093E \u091C\u093E\u0924\u093E \u0939\u0948; \u0917\u094D\u0930\u093E\u0939\u0915 \u0938\u0947 \u0915\u0941\u091B \u0914\u0930 \u0938\u092E\u092F \u092A\u094D\u0930\u0924\u0940\u0915\u094D\u0937\u093E \u0915\u0930\u0928\u0947 \u0915\u094B \u0915\u0939\u0947\u0902\u0964',
    guidanceDomainYoung: '\u0921\u094B\u092E\u0947\u0928 \u0939\u093E\u0932 \u0939\u0940 \u092E\u0947\u0902 \u092A\u0902\u091C\u0940\u0915\u0943\u0924 \u0939\u0941\u0906 \u0939\u0948 ({days} \u0926\u093F\u0928\u094B\u0902 \u0915\u0947 \u092D\u0940\u0924\u0930)\u0964 \u0917\u094D\u0930\u093E\u0939\u0915 \u0938\u0947 \u0915\u0941\u091B \u0914\u0930 \u0938\u092E\u092F \u092A\u094D\u0930\u0924\u0940\u0915\u094D\u0937\u093E \u0915\u0930\u0928\u0947 \u0915\u094B \u0915\u0939\u0947\u0902; Microsoft \u0907\u0938 \u0938\u0902\u0915\u0947\u0924 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0938\u094D\u092A\u0948\u092E\u0930 \u0915\u094B \u0928\u090F \u0935\u0947\u092C \u092A\u0924\u0947 \u0938\u0947\u091F \u0915\u0930\u0928\u0947 \u0938\u0947 \u0930\u094B\u0915\u0928\u0947 \u092E\u0947\u0902 \u092E\u0926\u0926 \u0915\u0947 \u0932\u093F\u090F \u0915\u0930\u0924\u093E \u0939\u0948\u0964',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  'ja-JP': {
    emailQuota: '\u30E1\u30FC\u30EB \u30AF\u30A9\u30FC\u30BF',
    domainVerification: '\u30C9\u30E1\u30A4\u30F3\u691C\u8A3C',
    domainRegistration: '\u30C9\u30E1\u30A4\u30F3\u767B\u9332 (WHOIS/RDAP)',
    mxRecords: 'MX \u30EC\u30B3\u30FC\u30C9',
    spfQueried: 'SPF\uFF08\u7167\u4F1A\u30C9\u30E1\u30A4\u30F3 TXT\uFF09',
    acsDomainVerificationTxt: 'ACS \u30C9\u30E1\u30A4\u30F3\u691C\u8A3C TXT',
    txtRecordsQueried: 'TXT \u30EC\u30B3\u30FC\u30C9\uFF08\u7167\u4F1A\u30C9\u30E1\u30A4\u30F3\uFF09',
    dmarc: 'DMARC',
    cname: 'CNAME',
    guidance: '\u30AC\u30A4\u30C0\u30F3\u30B9',
    helpfulLinks: '\u53C2\u8003\u30EA\u30F3\u30AF',
    externalTools: '\u5916\u90E8\u30C4\u30FC\u30EB',
    acsReadyMessage: '\u3053\u306E\u30C9\u30E1\u30A4\u30F3\u306F Azure Communication Services \u306E\u30C9\u30E1\u30A4\u30F3\u691C\u8A3C\u306E\u6E96\u5099\u304C\u3067\u304D\u3066\u3044\u308B\u3088\u3046\u3067\u3059\u3002',
    guidanceMxProviderDetected: '\u691C\u51FA\u3055\u308C\u305F MX \u30D7\u30ED\u30D0\u30A4\u30C0\u30FC: {provider}',
    guidanceDomainExpired: '\u30C9\u30E1\u30A4\u30F3\u767B\u9332\u306F\u671F\u9650\u5207\u308C\u306E\u3088\u3046\u3067\u3059\u3002\u7D9A\u884C\u3059\u308B\u524D\u306B\u30C9\u30E1\u30A4\u30F3\u3092\u66F4\u65B0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceDomainVeryYoung: '\u30C9\u30E1\u30A4\u30F3\u306F\u3054\u304F\u6700\u8FD1\u767B\u9332\u3055\u308C\u307E\u3057\u305F\uFF08{days} \u65E5\u4EE5\u5185\uFF09\u3002\u3053\u308C\u306F\u691C\u8A3C\u4E0A\u306E\u30A8\u30E9\u30FC \u30B7\u30B0\u30CA\u30EB\u3068\u3057\u3066\u6271\u308F\u308C\u307E\u3059\u3002\u9867\u5BA2\u306B\u3082\u3046\u5C11\u3057\u5F85\u3064\u3088\u3046\u6848\u5185\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceDomainYoung: '\u30C9\u30E1\u30A4\u30F3\u306F\u6700\u8FD1\u767B\u9332\u3055\u308C\u307E\u3057\u305F\uFF08{days} \u65E5\u4EE5\u5185\uFF09\u3002\u9867\u5BA2\u306B\u3082\u3046\u5C11\u3057\u5F85\u3064\u3088\u3046\u6848\u5185\u3057\u3066\u304F\u3060\u3055\u3044\u3002Microsoft \u306F\u3053\u306E\u30B7\u30B0\u30CA\u30EB\u3092\u4F7F\u7528\u3057\u3066\u30B9\u30D1\u30DE\u30FC\u306B\u3088\u308B\u65B0\u3057\u3044 Web \u30A2\u30C9\u30EC\u30B9\u306E\u8A2D\u5B9A\u9632\u6B62\u306B\u5F79\u7ACB\u3066\u3066\u3044\u307E\u3059\u3002',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  'ru-RU': {
    emailQuota: '\u041A\u0432\u043E\u0442\u0430 \u044D\u043B\u0435\u043A\u0442\u0440\u043E\u043D\u043D\u043E\u0439 \u043F\u043E\u0447\u0442\u044B',
    domainVerification: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u0434\u043E\u043C\u0435\u043D\u0430',
    domainRegistration: '\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044F \u0434\u043E\u043C\u0435\u043D\u0430 (WHOIS/RDAP)',
    mxRecords: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438',
    spfQueried: 'SPF (TXT \u0437\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430)',
    acsDomainVerificationTxt: 'TXT \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u0434\u043E\u043C\u0435\u043D\u0430 ACS',
    txtRecordsQueried: 'TXT-\u0437\u0430\u043F\u0438\u0441\u0438 (\u0437\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u044B\u0439 \u0434\u043E\u043C\u0435\u043D)',
    dmarc: 'DMARC',
    cname: 'CNAME',
    guidance: '\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438',
    helpfulLinks: '\u041F\u043E\u043B\u0435\u0437\u043D\u044B\u0435 \u0441\u0441\u044B\u043B\u043A\u0438',
    externalTools: '\u0412\u043D\u0435\u0448\u043D\u0438\u0435 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u044B',
    acsReadyMessage: '\u042D\u0442\u043E\u0442 \u0434\u043E\u043C\u0435\u043D \u0432\u044B\u0433\u043B\u044F\u0434\u0438\u0442 \u0433\u043E\u0442\u043E\u0432\u044B\u043C \u043A \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0435 \u0434\u043E\u043C\u0435\u043D\u0430 Azure Communication Services.',
    guidanceMxProviderDetected: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D MX-\u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440: {provider}',
    guidanceDomainExpired: '\u0421\u0440\u043E\u043A \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438 \u0434\u043E\u043C\u0435\u043D\u0430, \u043F\u043E\u0445\u043E\u0436\u0435, \u0438\u0441\u0442\u0451\u043A. \u041F\u0440\u043E\u0434\u043B\u0438\u0442\u0435 \u0434\u043E\u043C\u0435\u043D \u043F\u0435\u0440\u0435\u0434 \u043F\u0440\u043E\u0434\u043E\u043B\u0436\u0435\u043D\u0438\u0435\u043C.',
    guidanceDomainVeryYoung: '\u0414\u043E\u043C\u0435\u043D \u0431\u044B\u043B \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043E\u0432\u0430\u043D \u0441\u043E\u0432\u0441\u0435\u043C \u043D\u0435\u0434\u0430\u0432\u043D\u043E (\u0432 \u043F\u0440\u0435\u0434\u0435\u043B\u0430\u0445 {days} \u0434\u043D\u0435\u0439). \u042D\u0442\u043E \u0441\u0447\u0438\u0442\u0430\u0435\u0442\u0441\u044F \u0441\u0438\u0433\u043D\u0430\u043B\u043E\u043C \u043E\u0448\u0438\u0431\u043A\u0438 \u0434\u043B\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438; \u043F\u043E\u043F\u0440\u043E\u0441\u0438\u0442\u0435 \u043A\u043B\u0438\u0435\u043D\u0442\u0430 \u043F\u043E\u0434\u043E\u0436\u0434\u0430\u0442\u044C \u0435\u0449\u0451 \u043D\u0435\u043C\u043D\u043E\u0433\u043E.',
    guidanceDomainYoung: '\u0414\u043E\u043C\u0435\u043D \u0431\u044B\u043B \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043E\u0432\u0430\u043D \u043D\u0435\u0434\u0430\u0432\u043D\u043E (\u0432 \u043F\u0440\u0435\u0434\u0435\u043B\u0430\u0445 {days} \u0434\u043D\u0435\u0439). \u041F\u043E\u043F\u0440\u043E\u0441\u0438\u0442\u0435 \u043A\u043B\u0438\u0435\u043D\u0442\u0430 \u043F\u043E\u0434\u043E\u0436\u0434\u0430\u0442\u044C \u0435\u0449\u0451 \u043D\u0435\u043C\u043D\u043E\u0433\u043E; Microsoft \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 \u044D\u0442\u043E\u0442 \u0441\u0438\u0433\u043D\u0430\u043B, \u0447\u0442\u043E\u0431\u044B \u043F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0442\u044C \u0441\u043E\u0437\u0434\u0430\u043D\u0438\u0435 \u043D\u043E\u0432\u044B\u0445 \u0430\u0434\u0440\u0435\u0441\u043E\u0432 \u0441\u043F\u0430\u043C\u0435\u0440\u0430\u043C\u0438.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  'ar': {
    emailQuota: '\u062D\u0635\u0629 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A',
    domainVerification: '\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642',
    domainRegistration: '\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u0646\u0637\u0627\u0642 (WHOIS/RDAP)',
    mxRecords: '\u0633\u062C\u0644\u0627\u062A MX',
    spfQueried: 'SPF (TXT \u0644\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647)',
    acsDomainVerificationTxt: 'TXT \u0644\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0646\u0637\u0627\u0642 ACS',
    txtRecordsQueried: '\u0633\u062C\u0644\u0627\u062A TXT (\u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647)',
    guidance: '\u0625\u0631\u0634\u0627\u062F\u0627\u062A',
    helpfulLinks: '\u0631\u0648\u0627\u0628\u0637 \u0645\u0641\u064A\u062F\u0629',
    externalTools: '\u0623\u062F\u0648\u0627\u062A \u062E\u0627\u0631\u062C\u064A\u0629',
    acsReadyMessage: '\u064A\u0628\u062F\u0648 \u0623\u0646 \u0647\u0630\u0627 \u0627\u0644\u0646\u0637\u0627\u0642 \u062C\u0627\u0647\u0632 \u0644\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0646\u0637\u0627\u0642 Azure Communication Services.',
    guidanceMxProviderDetected: '\u0645\u0648\u0641\u0631 MX \u0627\u0644\u0645\u0643\u062A\u0634\u0641: {provider}',
    guidanceDomainExpired: '\u064A\u0628\u062F\u0648 \u0623\u0646 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u0646\u0637\u0627\u0642 \u0642\u062F \u0627\u0646\u062A\u0647\u062A \u0635\u0644\u0627\u062D\u064A\u062A\u0647. \u062C\u062F\u0651\u062F \u0627\u0644\u0646\u0637\u0627\u0642 \u0642\u0628\u0644 \u0627\u0644\u0645\u062A\u0627\u0628\u0639\u0629.',
    guidanceDomainVeryYoung: '\u062A\u0645 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u0646\u0637\u0627\u0642 \u0645\u0624\u062E\u0631\u064B\u0627 \u062C\u062F\u064B\u0627 (\u062E\u0644\u0627\u0644 {days} \u064A\u0648\u0645\u064B\u0627). \u064A\u064F\u0639\u0627\u0645\u0644 \u0647\u0630\u0627 \u0643\u0625\u0634\u0627\u0631\u0629 \u062E\u0637\u0623 \u0644\u0644\u062A\u062D\u0642\u0642\u061B \u0627\u0637\u0644\u0628 \u0645\u0646 \u0627\u0644\u0639\u0645\u064A\u0644 \u0627\u0644\u0627\u0646\u062A\u0638\u0627\u0631 \u0645\u062F\u0629 \u0623\u0637\u0648\u0644.',
    guidanceDomainYoung: '\u062A\u0645 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u0646\u0637\u0627\u0642 \u0645\u0624\u062E\u0631\u064B\u0627 (\u062E\u0644\u0627\u0644 {days} \u064A\u0648\u0645\u064B\u0627). \u0627\u0637\u0644\u0628 \u0645\u0646 \u0627\u0644\u0639\u0645\u064A\u0644 \u0627\u0644\u0627\u0646\u062A\u0638\u0627\u0631 \u0645\u062F\u0629 \u0623\u0637\u0648\u0644\u061B \u062A\u0633\u062A\u062E\u062F\u0645 Microsoft \u0647\u0630\u0647 \u0627\u0644\u0625\u0634\u0627\u0631\u0629 \u0644\u0644\u0645\u0633\u0627\u0639\u062F\u0629 \u0641\u064A \u0645\u0646\u0639 \u0645\u0631\u0633\u0644\u064A \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0639\u0634\u0648\u0627\u0626\u064A \u0645\u0646 \u0625\u0639\u062F\u0627\u062F \u0639\u0646\u0627\u0648\u064A\u0646 \u0648\u064A\u0628 \u062C\u062F\u064A\u062F\u0629.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  }
};

Object.keys(REMAINING_TRANSLATION_OVERRIDES).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, REMAINING_TRANSLATION_OVERRIDES[code]);
});

const UI_TRANSLATION_OVERRIDES = {
  en: {
    removeLabel: 'Remove',
    reportIssueTitle: 'Report an issue (includes the domain name)',
    noRecordOnDomain: 'No record on {domain}',
    parentDomainAcsTxtInfo: 'Parent domain {lookupDomain} ACS TXT (informational only):',
    noTxtRecordsOnDomain: 'No TXT records on {domain}',
    parentDomainTxtRecordsInfo: 'Parent domain {lookupDomain} TXT records (informational only):',
    listedOnZone: 'IP {ip} listed on {zone}{suffix}',
    spfOutlookRequirementPresent: 'Required Outlook SPF include detected for ACS.',
    spfOutlookRequirementMissing: 'Required Outlook SPF include was not detected for ACS.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  es: {
    removeLabel: 'Quitar',
    reportIssueTitle: 'Reportar un problema (incluye el nombre de dominio)',
    noRecordOnDomain: 'No hay registro en {domain}',
    parentDomainAcsTxtInfo: 'TXT ACS del dominio primario {lookupDomain} (solo informativo):',
    noTxtRecordsOnDomain: 'No hay registros TXT en {domain}',
    parentDomainTxtRecordsInfo: 'Registros TXT del dominio primario {lookupDomain} (solo informativo):',
    listedOnZone: 'La IP {ip} figura en {zone}{suffix}',
    spfOutlookRequirementPresent: 'Se detect\u00F3 el include SPF de Outlook requerido para ACS.',
    spfOutlookRequirementMissing: 'No se detect\u00F3 el include SPF de Outlook requerido para ACS.',
    unitYearOne: 'a\u00F1o',
    unitYearMany: 'a\u00F1os',
    unitMonthOne: 'mes',
    unitMonthMany: 'meses',
    unitDayOne: 'd\u00EDa',
    unitDayMany: 'd\u00EDas',
    wordExpired: 'Vencido',
    mxPriorityLabel: 'Prioridad',
    providerHintMicrosoft365: 'El MX apunta a Exchange Online Protection (EOP).',
    providerHintGoogleWorkspace: 'El MX apunta a los servidores de correo de Google.',
    providerHintCloudflare: 'El MX apunta a Cloudflare (mx.cloudflare.net).',
    providerHintProofpoint: 'El MX apunta a correo alojado en Proofpoint.',
    providerHintMimecast: 'El MX apunta a Mimecast.',
    providerHintZoho: 'El MX apunta a Zoho Mail.',
    providerHintUnknown: 'No se reconoci\u00F3 el proveedor a partir del nombre de host MX.',
    riskClean: 'Limpio',
    riskWarning: 'Aviso',
    riskElevated: 'Riesgo elevado',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  fr: {
    removeLabel: 'Supprimer',
    reportIssueTitle: 'Signaler un probl\u00E8me (inclut le nom de domaine)',
    noRecordOnDomain: 'Aucun enregistrement sur {domain}',
    parentDomainAcsTxtInfo: 'TXT ACS du domaine parent {lookupDomain} (informatif uniquement) :',
    noTxtRecordsOnDomain: 'Aucun enregistrement TXT sur {domain}',
    parentDomainTxtRecordsInfo: 'Enregistrements TXT du domaine parent {lookupDomain} (informatif uniquement) :',
    listedOnZone: 'IP {ip} list\u00E9e sur {zone}{suffix}',
    spfOutlookRequirementPresent: 'L\u2019inclusion SPF Outlook requise pour ACS a \u00E9t\u00E9 d\u00E9tect\u00E9e.',
    spfOutlookRequirementMissing: 'L\u2019inclusion SPF Outlook requise pour ACS n\u2019a pas \u00E9t\u00E9 d\u00E9tect\u00E9e.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  de: {
    removeLabel: 'Entfernen',
    reportIssueTitle: 'Problem melden (einschlie\u00DFlich Domainname)',
    noRecordOnDomain: 'Kein Eintrag auf {domain}',
    parentDomainAcsTxtInfo: 'ACS-TXT der \u00FCbergeordneten Domain {lookupDomain} (nur informativ):',
    noTxtRecordsOnDomain: 'Keine TXT-Eintr\u00E4ge auf {domain}',
    parentDomainTxtRecordsInfo: 'TXT-Eintr\u00E4ge der \u00FCbergeordneten Domain {lookupDomain} (nur informativ):',
    listedOnZone: 'IP {ip} ist auf {zone} gelistet{suffix}',
    spfOutlookRequirementPresent: 'Der f\u00FCr ACS erforderliche Outlook-SPF-Include wurde erkannt.',
    spfOutlookRequirementMissing: 'Der f\u00FCr ACS erforderliche Outlook-SPF-Include wurde nicht erkannt.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  'pt-BR': {
    removeLabel: 'Remover',
    reportIssueTitle: 'Relatar um problema (inclui o nome do dom\u00EDnio)',
    noRecordOnDomain: 'Nenhum registro em {domain}',
    parentDomainAcsTxtInfo: 'TXT ACS do dom\u00EDnio pai {lookupDomain} (somente informativo):',
    noTxtRecordsOnDomain: 'Nenhum registro TXT em {domain}',
    parentDomainTxtRecordsInfo: 'Registros TXT do dom\u00EDnio pai {lookupDomain} (somente informativo):',
    listedOnZone: 'IP {ip} listada em {zone}{suffix}',
    spfOutlookRequirementPresent: 'O include SPF do Outlook exigido para ACS foi detectado.',
    spfOutlookRequirementMissing: 'O include SPF do Outlook exigido para ACS n\u00E3o foi detectado.',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2'
  },
  ar: {
    removeLabel: '\u0625\u0632\u0627\u0644\u0629',
    reportIssueTitle: '\u0627\u0644\u0625\u0628\u0644\u0627\u063A \u0639\u0646 \u0645\u0634\u0643\u0644\u0629 (\u064A\u062A\u0636\u0645\u0646 \u0627\u0633\u0645 \u0627\u0644\u0646\u0637\u0627\u0642)',
    noRecordOnDomain: '\u0644\u0627 \u064A\u0648\u062C\u062F \u0633\u062C\u0644 \u0639\u0644\u0649 {domain}',
    parentDomainAcsTxtInfo: 'TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain} (\u0644\u0644\u0645\u0639\u0644\u0648\u0645\u0629 \u0641\u0642\u0637):',
    noTxtRecordsOnDomain: '\u0644\u0627 \u062A\u0648\u062C\u062F \u0633\u062C\u0644\u0627\u062A TXT \u0639\u0644\u0649 {domain}',
    parentDomainTxtRecordsInfo: '\u0633\u062C\u0644\u0627\u062A TXT \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain} (\u0644\u0644\u0645\u0639\u0644\u0648\u0645\u0629 \u0641\u0642\u0637):',
    listedOnZone: '\u062A\u0645 \u0625\u062F\u0631\u0627\u062C IP \u200F{ip} \u0641\u064A {zone}{suffix}',
    spfOutlookRequirementPresent: '\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u062A\u0636\u0645\u064A\u0646 Outlook SPF \u0627\u0644\u0645\u0637\u0644\u0648\u0628 \u0644\u0640 ACS.',
    spfOutlookRequirementMissing: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u062A\u0636\u0645\u064A\u0646 Outlook SPF \u0627\u0644\u0645\u0637\u0644\u0648\u0628 \u0644\u0640 ACS.',
    unitYearOne: '\u0633\u0646\u0629',
    unitYearMany: '\u0633\u0646\u0648\u0627\u062A',
    unitMonthOne: '\u0634\u0647\u0631',
    unitMonthMany: '\u0623\u0634\u0647\u0631',
    unitDayOne: '\u064A\u0648\u0645',
    unitDayMany: '\u0623\u064A\u0627\u0645',
    wordExpired: '\u0645\u0646\u062A\u0647\u064A \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629',
    mxPriorityLabel: '\u0627\u0644\u0623\u0648\u0644\u0648\u064A\u0629',
    providerHintMicrosoft365: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Exchange Online Protection \u200F(EOP).',
    providerHintGoogleWorkspace: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 \u062E\u0648\u0627\u062F\u0645 \u0628\u0631\u064A\u062F Google.',
    providerHintCloudflare: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Cloudflare \u200F(mx.cloudflare.net).',
    providerHintProofpoint: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 \u0628\u0631\u064A\u062F \u0645\u0633\u062A\u0636\u0627\u0641 \u0644\u062F\u0649 Proofpoint.',
    providerHintMimecast: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Mimecast.',
    providerHintZoho: '\u064A\u0634\u064A\u0631 MX \u0625\u0644\u0649 Zoho Mail.',
    providerHintUnknown: '\u062A\u0639\u0630\u0631 \u0627\u0644\u062A\u0639\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0645\u0648\u0641\u0631 \u0645\u0646 \u0627\u0633\u0645 \u0645\u0636\u064A\u0641 MX.',
    riskClean: '\u0646\u0638\u064A\u0641',
    riskWarning: '\u062A\u062D\u0630\u064A\u0631',
    riskElevated: '\u0645\u062E\u0627\u0637\u0631 \u0645\u0631\u062A\u0641\u0639\u0629'
  },
  'zh-CN': {
    removeLabel: '\u79FB\u9664',
    reportIssueTitle: '\u62A5\u544A\u95EE\u9898\uFF08\u5305\u542B\u57DF\u540D\uFF09',
    noRecordOnDomain: '{domain} \u4E0A\u6CA1\u6709\u8BB0\u5F55',
    parentDomainAcsTxtInfo: '\u7236\u57DF {lookupDomain} \u7684 ACS TXT\uFF08\u4EC5\u4F9B\u53C2\u8003\uFF09\uFF1A',
    noTxtRecordsOnDomain: '{domain} \u4E0A\u6CA1\u6709 TXT \u8BB0\u5F55',
    parentDomainTxtRecordsInfo: '\u7236\u57DF {lookupDomain} \u7684 TXT \u8BB0\u5F55\uFF08\u4EC5\u4F9B\u53C2\u8003\uFF09\uFF1A',
    listedOnZone: 'IP {ip} \u5DF2\u5728 {zone} \u4E2D\u5217\u51FA{suffix}',
    spfOutlookRequirementPresent: '\u5DF2\u68C0\u6D4B\u5230 ACS \u6240\u9700\u7684 Outlook SPF include\u3002',
    spfOutlookRequirementMissing: '\u672A\u68C0\u6D4B\u5230 ACS \u6240\u9700\u7684 Outlook SPF include\u3002'
  },
  'hi-IN': {
    removeLabel: '\u0939\u091F\u093E\u090F\u0901',
    reportIssueTitle: '\u0938\u092E\u0938\u094D\u092F\u093E \u0930\u093F\u092A\u094B\u0930\u094D\u091F \u0915\u0930\u0947\u0902 (\u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E \u0936\u093E\u092E\u093F\u0932 \u0939\u0948)',
    noRecordOnDomain: '{domain} \u092A\u0930 \u0915\u094B\u0908 \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u0939\u0948',
    parentDomainAcsTxtInfo: '\u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0915\u093E ACS TXT (\u0915\u0947\u0935\u0932 \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u0915\u0947 \u0932\u093F\u090F):',
    noTxtRecordsOnDomain: '{domain} \u092A\u0930 \u0915\u094B\u0908 TXT \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u0939\u0948',
    parentDomainTxtRecordsInfo: '\u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0915\u0947 TXT \u0930\u093F\u0915\u0949\u0930\u094D\u0921 (\u0915\u0947\u0935\u0932 \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u0915\u0947 \u0932\u093F\u090F):',
    listedOnZone: 'IP {ip} {zone} \u092A\u0930 \u0938\u0942\u091A\u0940\u092C\u0926\u094D\u0927 \u0939\u0948{suffix}',
    spfOutlookRequirementPresent: 'ACS \u0915\u0947 \u0932\u093F\u090F \u0906\u0935\u0936\u094D\u092F\u0915 Outlook SPF include \u092E\u093F\u0932 \u0917\u092F\u093E\u0964',
    spfOutlookRequirementMissing: 'ACS \u0915\u0947 \u0932\u093F\u090F \u0906\u0935\u0936\u094D\u092F\u0915 Outlook SPF include \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964'
  },
  'ja-JP': {
    removeLabel: '\u524A\u9664',
    reportIssueTitle: '\u554F\u984C\u3092\u5831\u544A\uFF08\u30C9\u30E1\u30A4\u30F3\u540D\u3092\u542B\u307F\u307E\u3059\uFF09',
    noRecordOnDomain: '{domain} \u306B\u30EC\u30B3\u30FC\u30C9\u306F\u3042\u308A\u307E\u305B\u3093',
    parentDomainAcsTxtInfo: '\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E ACS TXT\uFF08\u53C2\u8003\u60C5\u5831\u306E\u307F\uFF09:',
    noTxtRecordsOnDomain: '{domain} \u306B TXT \u30EC\u30B3\u30FC\u30C9\u306F\u3042\u308A\u307E\u305B\u3093',
    parentDomainTxtRecordsInfo: '\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E TXT \u30EC\u30B3\u30FC\u30C9\uFF08\u53C2\u8003\u60C5\u5831\u306E\u307F\uFF09:',
    listedOnZone: 'IP {ip} \u306F {zone} \u306B\u63B2\u8F09\u3055\u308C\u3066\u3044\u307E\u3059{suffix}',
    spfOutlookRequirementPresent: 'ACS \u306B\u5FC5\u8981\u306A Outlook SPF include \u304C\u691C\u51FA\u3055\u308C\u307E\u3057\u305F\u3002',
    spfOutlookRequirementMissing: 'ACS \u306B\u5FC5\u8981\u306A Outlook SPF include \u304C\u691C\u51FA\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002'
  },
  'ru-RU': {
    removeLabel: '\u0423\u0434\u0430\u043B\u0438\u0442\u044C',
    reportIssueTitle: '\u0421\u043E\u043E\u0431\u0449\u0438\u0442\u044C \u043E \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0435 (\u0432\u043A\u043B\u044E\u0447\u0430\u044F \u0438\u043C\u044F \u0434\u043E\u043C\u0435\u043D\u0430)',
    noRecordOnDomain: '\u041D\u0430 {domain} \u0437\u0430\u043F\u0438\u0441\u044C \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442',
    parentDomainAcsTxtInfo: 'ACS TXT \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain} (\u0442\u043E\u043B\u044C\u043A\u043E \u0434\u043B\u044F \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u0438):',
    noTxtRecordsOnDomain: '\u041D\u0430 {domain} \u043D\u0435\u0442 TXT-\u0437\u0430\u043F\u0438\u0441\u0435\u0439',
    parentDomainTxtRecordsInfo: 'TXT-\u0437\u0430\u043F\u0438\u0441\u0438 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain} (\u0442\u043E\u043B\u044C\u043A\u043E \u0434\u043B\u044F \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u0438):',
    listedOnZone: 'IP {ip} \u0432\u043D\u0435\u0441\u0451\u043D \u0432 \u0441\u043F\u0438\u0441\u043E\u043A {zone}{suffix}',
    spfOutlookRequirementPresent: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D \u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u0439 Outlook SPF include \u0434\u043B\u044F ACS.',
    spfOutlookRequirementMissing: '\u041E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u0439 Outlook SPF include \u0434\u043B\u044F ACS \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D.'
  }
};

Object.keys(UI_TRANSLATION_OVERRIDES).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, UI_TRANSLATION_OVERRIDES[code]);
});

const BADGE_TRANSLATION_OVERRIDES = {
  es: {
    checklist: 'LISTA',
    verificationTag: 'VERIFICACI\u00D3N',
    docs: 'DOCS',
    tools: 'HERRAMIENTAS',
    readinessTips: 'CONSEJOS',
    lookedUp: 'CONSULTADO',
    loading: 'CARGANDO',
    missing: 'FALTA',
    optional: 'OPCIONAL',
    info: 'INFO',
    error: 'ERROR',
    pass: 'OK',
    fail: 'FALLO',
    warn: 'AVISO',
    pending: 'PENDIENTE',
    dnsError: 'ERROR DNS',
    newDomain: 'DOMINIO NUEVO',
    expired: 'VENCIDO'
  },
  fr: {
    checklist: 'CHECKLIST',
    verificationTag: 'V\u00C9RIFICATION',
    docs: 'DOCS',
    tools: 'OUTILS',
    readinessTips: 'CONSEILS',
    lookedUp: 'CONSULT\u00C9',
    loading: 'CHARGEMENT',
    missing: 'MANQUANT',
    optional: 'OPTIONNEL',
    info: 'INFO',
    error: 'ERREUR',
    pass: 'OK',
    fail: '\u00C9CHEC',
    warn: 'AVERT.',
    pending: 'EN ATTENTE',
    dnsError: 'ERREUR DNS',
    newDomain: 'NOUVEAU DOMAINE',
    expired: 'EXPIR\u00C9'
  },
  de: {
    checklist: 'CHECKLISTE',
    verificationTag: 'VERIFIZIERUNG',
    docs: 'DOKS',
    tools: 'TOOLS',
    readinessTips: 'TIPPS',
    lookedUp: 'ABGEFRAGT',
    loading: 'LADEN',
    missing: 'FEHLT',
    optional: 'OPTIONAL',
    info: 'INFO',
    error: 'FEHLER',
    pass: 'OK',
    fail: 'FEHLER',
    warn: 'WARNUNG',
    pending: 'AUSSTEHEND',
    dnsError: 'DNS-FEHLER',
    newDomain: 'NEUE DOMAIN',
    expired: 'ABGELAUFEN'
  },
  'pt-BR': {
    checklist: 'CHECKLIST',
    verificationTag: 'VERIFICA\u00C7\u00C3O',
    docs: 'DOCS',
    tools: 'FERRAMENTAS',
    readinessTips: 'DICAS',
    lookedUp: 'CONSULTADO',
    loading: 'CARREGANDO',
    missing: 'AUSENTE',
    optional: 'OPCIONAL',
    info: 'INFO',
    error: 'ERRO',
    pass: 'OK',
    fail: 'FALHA',
    warn: 'AVISO',
    pending: 'PENDENTE',
    dnsError: 'ERRO DNS',
    newDomain: 'DOM\u00CDNIO NOVO',
    expired: 'EXPIRADO'
  },
  ar: {
    checklist: '\u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u062A\u062D\u0642\u0642',
    verificationTag: '\u0627\u0644\u062A\u062D\u0642\u0642',
    docs: '\u0627\u0644\u0645\u0633\u062A\u0646\u062F\u0627\u062A',
    tools: '\u0627\u0644\u0623\u062F\u0648\u0627\u062A',
    readinessTips: '\u0646\u0635\u0627\u0626\u062D \u0627\u0644\u062C\u0627\u0647\u0632\u064A\u0629',
    lookedUp: '\u062A\u0645 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645',
    loading: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0645\u064A\u0644',
    missing: '\u0645\u0641\u0642\u0648\u062F',
    optional: '\u0627\u062E\u062A\u064A\u0627\u0631\u064A',
    info: '\u0645\u0639\u0644\u0648\u0645\u0629',
    error: '\u062E\u0637\u0623',
    pass: '\u0646\u0627\u062C\u062D',
    fail: '\u0641\u0634\u0644',
    warn: '\u062A\u062D\u0630\u064A\u0631',
    pending: '\u0642\u064A\u062F \u0627\u0644\u0627\u0646\u062A\u0638\u0627\u0631',
    dnsError: '\u062E\u0637\u0623 DNS',
    newDomain: '\u0646\u0637\u0627\u0642 \u062C\u062F\u064A\u062F',
    expired: '\u0645\u0646\u062A\u0647\u064A \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629'
  },
  'zh-CN': {
    checklist: '\u68C0\u67E5\u6E05\u5355',
    verificationTag: '\u9A8C\u8BC1',
    docs: '\u6587\u6863',
    tools: '\u5DE5\u5177',
    readinessTips: '\u5C31\u7EEA\u5EFA\u8BAE',
    lookedUp: '\u5DF2\u67E5\u8BE2',
    loading: '\u52A0\u8F7D\u4E2D',
    missing: '\u7F3A\u5931',
    optional: '\u53EF\u9009',
    info: '\u4FE1\u606F',
    error: '\u9519\u8BEF',
    pass: '\u901A\u8FC7',
    fail: '\u5931\u8D25',
    warn: '\u8B66\u544A',
    pending: '\u7B49\u5F85\u4E2D',
    dnsError: 'DNS \u9519\u8BEF',
    newDomain: '\u65B0\u57DF\u540D',
    expired: '\u5DF2\u8FC7\u671F'
  },
  'hi-IN': {
    checklist: '\u091A\u0947\u0915\u0932\u093F\u0938\u094D\u091F',
    verificationTag: '\u0938\u0924\u094D\u092F\u093E\u092A\u0928',
    docs: '\u0926\u0938\u094D\u0924\u093E\u0935\u0947\u091C\u093C',
    tools: '\u0909\u092A\u0915\u0930\u0923',
    readinessTips: '\u0924\u0924\u094D\u092A\u0930\u0924\u093E \u0938\u0941\u091D\u093E\u0935',
    lookedUp: '\u091C\u093E\u0901\u091A\u093E \u0917\u092F\u093E',
    loading: '\u0932\u094B\u0921 \u0939\u094B \u0930\u0939\u093E \u0939\u0948',
    missing: '\u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924',
    optional: '\u0935\u0948\u0915\u0932\u094D\u092A\u093F\u0915',
    info: '\u091C\u093E\u0928\u0915\u093E\u0930\u0940',
    error: '\u0924\u094D\u0930\u0941\u091F\u093F',
    pass: '\u0938\u092B\u0932',
    fail: '\u0935\u093F\u092B\u0932',
    warn: '\u091A\u0947\u0924\u093E\u0935\u0928\u0940',
    pending: '\u0932\u0902\u092C\u093F\u0924',
    dnsError: 'DNS \u0924\u094D\u0930\u0941\u091F\u093F',
    newDomain: '\u0928\u092F\u093E \u0921\u094B\u092E\u0947\u0928',
    expired: '\u0938\u092E\u093E\u092A\u094D\u0924'
  },
  'ja-JP': {
    checklist: '\u30C1\u30A7\u30C3\u30AF\u30EA\u30B9\u30C8',
    verificationTag: '\u691C\u8A3C',
    docs: '\u30C9\u30AD\u30E5\u30E1\u30F3\u30C8',
    tools: '\u30C4\u30FC\u30EB',
    readinessTips: '\u6E96\u5099\u306E\u30D2\u30F3\u30C8',
    lookedUp: '\u78BA\u8A8D\u6E08\u307F',
    loading: '\u8AAD\u307F\u8FBC\u307F\u4E2D',
    missing: '\u4E0D\u8DB3',
    optional: '\u4EFB\u610F',
    info: '\u60C5\u5831',
    error: '\u30A8\u30E9\u30FC',
    pass: '\u6210\u529F',
    fail: '\u5931\u6557',
    warn: '\u8B66\u544A',
    pending: '\u4FDD\u7559\u4E2D',
    dnsError: 'DNS \u30A8\u30E9\u30FC',
    newDomain: '\u65B0\u3057\u3044\u30C9\u30E1\u30A4\u30F3',
    expired: '\u671F\u9650\u5207\u308C'
  },
  'ru-RU': {
    checklist: '\u041A\u041E\u041D\u0422\u0420\u041E\u041B\u042C\u041D\u042B\u0419 \u0421\u041F\u0418\u0421\u041E\u041A',
    verificationTag: '\u041F\u0420\u041E\u0412\u0415\u0420\u041A\u0410',
    docs: '\u0414\u041E\u041A\u0423\u041C\u0415\u041D\u0422\u0410\u0426\u0418\u042F',
    tools: '\u0418\u041D\u0421\u0422\u0420\u0423\u041C\u0415\u041D\u0422\u042B',
    readinessTips: '\u0421\u041E\u0412\u0415\u0422\u042B \u041F\u041E \u0413\u041E\u0422\u041E\u0412\u041D\u041E\u0421\u0422\u0418',
    lookedUp: '\u041F\u0420\u041E\u0412\u0415\u0420\u0415\u041D\u041E',
    loading: '\u0417\u0410\u0413\u0420\u0423\u0417\u041A\u0410',
    missing: '\u041E\u0422\u0421\u0423\u0422\u0421\u0422\u0412\u0423\u0415\u0422',
    optional: '\u041D\u0415\u041E\u0411\u042F\u0417\u0410\u0422\u0415\u041B\u042C\u041D\u041E',
    info: '\u0418\u041D\u0424\u041E',
    error: '\u041E\u0428\u0418\u0411\u041A\u0410',
    pass: '\u0423\u0421\u041F\u0415\u0425',
    fail: '\u041E\u0428\u0418\u0411\u041A\u0410',
    warn: '\u041F\u0420\u0415\u0414\u0423\u041F\u0420\u0415\u0416\u0414\u0415\u041D\u0418\u0415',
    pending: '\u041E\u0416\u0418\u0414\u0410\u041D\u0418\u0415',
    dnsError: '\u041E\u0428\u0418\u0411\u041A\u0410 DNS',
    newDomain: '\u041D\u041E\u0412\u042B\u0419 \u0414\u041E\u041C\u0415\u041D',
    expired: '\u0418\u0421\u0422\u0401\u041A'
  }
};

Object.keys(BADGE_TRANSLATION_OVERRIDES).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, BADGE_TRANSLATION_OVERRIDES[code]);
});

const RUNTIME_TRANSLATION_OVERRIDES = {
  es: {
    authInitFailed: 'No se pudo inicializar el inicio de sesi\u00F3n con Microsoft. Consulte la consola del navegador para m\u00E1s detalles.',
    authInitFailedWithReason: 'No se pudo inicializar el inicio de sesi\u00F3n con Microsoft: {reason}',
    authLibraryLoadFailed: 'No se pudo cargar la biblioteca de inicio de sesi\u00F3n de Microsoft. Verifique el acceso a la CDN de MSAL o proporcione un archivo local msal-browser.min.js.',
    authMicrosoftLabel: 'Microsoft',
    authSetClientIdAndRestart: 'El inicio de sesi\u00F3n con Microsoft no est\u00E1 configurado. Establezca la variable de entorno ACS_ENTRA_CLIENT_ID y reinicie.',
    authSignInCancelled: 'Se cancel\u00F3 el inicio de sesi\u00F3n.',
    authSignInFailed: 'Error al iniciar sesi\u00F3n: {reason}',
    authSignInNotConfigured: 'El inicio de sesi\u00F3n con Microsoft no est\u00E1 configurado. Confirme que ACS_ENTRA_CLIENT_ID se haya insertado en la p\u00E1gina y actualice.',
    authSigningIn: 'Iniciando sesi\u00F3n...',
    authUnknownError: 'Error desconocido',
    copiedToClipboard: 'Copiado al portapapeles.',
    copiedFieldToClipboard: 'Se copi\u00F3 {field} al portapapeles.',
    failedCopyFieldToClipboard: 'No se pudo copiar {field} al portapapeles.',
    failedCopyLink: 'No se pudo copiar el v\u00EDnculo al portapapeles.',
    failedCopyScreenshot: 'No se pudo copiar la captura al portapapeles.',
    failedCopyToClipboard: 'No se pudo copiar al portapapeles.',
    issueReportConfirm: 'Esto abrir\u00E1 el sistema de seguimiento de problemas e incluir\u00E1 {detail}. \u00BFDesea continuar?',
    issueReportDetailDomain: 'el nombre de dominio "{domain}"',
    issueReportDetailInput: 'el nombre de dominio del cuadro de entrada',
    issueReportingNotConfigured: 'La notificaci\u00F3n de problemas no est\u00E1 configurada.',
    linkCopiedToClipboard: 'V\u00EDnculo copiado al portapapeles.',
    nothingToCopyFor: 'No hay nada para copiar para {field}.',
    screenshotCaptureFailed: 'No se pudo capturar la captura de pantalla.',
    screenshotClipboardUnsupported: 'La compatibilidad para copiar capturas al portapapeles no est\u00E1 disponible en este navegador.',
    screenshotContainerNotFound: 'No se encontr\u00F3 el contenedor para la captura.',
    screenshotCopiedToClipboard: 'Captura de pantalla copiada al portapapeles.',
    screenshotRenderFailed: 'Error al capturar la captura de pantalla.',
    dkim1StatusLabel: 'Estado de DKIM1',
    dkim2StatusLabel: 'Estado de DKIM2',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dmarcStatusLabel: 'Estado de DMARC',
    domainNameLabel: 'Nombre de dominio',
    domainStatusLabel: 'Estado del dominio',
    expiredOn: 'Vencido el {date}',
    mxRecordsLabel: 'Registros MX',
    mxUsingParentNote: '(usando MX del dominio primario {lookupDomain})',
    newDomainUnder180Days: 'Dominio nuevo de menos de 180 d\u00EDas.',
    newDomainUnder90Days: 'Dominio nuevo de menos de 90 d\u00EDas.',
    parentCheckedNoMx: 'Se comprob\u00F3 el dominio primario {parentDomain} (sin MX).',
    registrationAppearsExpired: 'El registro del dominio parece expirado.',
    spfStatusLabel: 'Estado de SPF'
  },
  fr: {
    acsReadyMessage: 'Ce domaine semble pr\u00EAt pour la v\u00E9rification de domaine Azure Communication Services.',
    checkingDnsblReputation: 'V\u00E9rification de la r\u00E9putation DNSBL...',
    checkingMxRecords: 'V\u00E9rification des enregistrements MX...',
    checkingValue: 'V\u00E9rification...',
    checklist: 'CHECKLIST',
    cname: 'CNAME',
    dkim1StatusLabel: '\u00C9tat DKIM1',
    dkim2StatusLabel: '\u00C9tat DKIM2',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: 'L\u2019alignement DKIM pour {domain} utilise le mode rel\u00E2ch\u00E9 (adkim=r). Envisagez un alignement strict (adkim=s) si votre infrastructure d\u2019envoi le permet pour une meilleure protection du domaine.',
    dmarcAspfRelaxed: 'L\u2019alignement SPF pour {domain} utilise le mode rel\u00E2ch\u00E9 (aspf=r). Envisagez un alignement strict (aspf=s) si vos exp\u00E9diteurs utilisent syst\u00E9matiquement le domaine exact.',
    dmarcMissingRua: 'DMARC pour {domain} ne publie pas de rapports agr\u00E9g\u00E9s (rua=). L\u2019ajout d\u2019une bo\u00EEte aux lettres de rapport am\u00E9liore la visibilit\u00E9 sur les tentatives d\u2019usurpation et l\u2019impact de l\u2019application.',
    dmarcMissingRuf: 'DMARC pour {domain} ne publie pas de rapports forensiques (ruf=). Si votre processus le permet, ces rapports peuvent fournir plus de d\u00E9tails pour les investigations.',
    dmarcMissingSp: 'DMARC pour les sous-domaines de {lookupDomain} ne d\u00E9finit pas de politique explicite pour les sous-domaines (sp=). Si vous envoyez depuis des sous-domaines comme {domain}, envisagez d\u2019ajouter sp=quarantine ou sp=reject pour une protection plus claire.',
    dmarcMonitorOnly: 'DMARC pour {domain} est en mode surveillance uniquement (p=none). Pour une protection plus forte contre l\u2019usurpation, passez \u00E0 l\u2019application avec p=quarantine ou p=reject apr\u00E8s validation des sources l\u00E9gitimes.',
    dmarcPct: 'L\u2019application de DMARC pour {domain} ne s\u2019applique qu\u2019\u00E0 {pct}% des messages (pct={pct}). Utilisez pct=100 pour une protection compl\u00E8te une fois le d\u00E9ploiement valid\u00E9.',
    dmarcQuarantine: 'DMARC pour {domain} est d\u00E9fini sur p=quarantine. Pour la meilleure protection contre l\u2019usurpation, envisagez p=reject une fois que tout le courrier l\u00E9gitime est enti\u00E8rement align\u00E9.',
    dmarcStatusLabel: '\u00C9tat DMARC',
    domainDossier: 'Dossier de domaine (CentralOps)',
    domainNameLabel: 'Nom de domaine',
    domainStatusLabel: 'Statut du domaine',
    expiredOn: 'Expir\u00E9 le {date}',
    guidanceAcsMissing: 'Le TXT ACS ms-domain-verification est manquant. Ajoutez la valeur depuis le portail Azure.',
    guidanceAcsMissingParent: 'Le TXT ACS ms-domain-verification est manquant sur {domain}. Le domaine parent {lookupDomain} poss\u00E8de un TXT ACS, mais il ne v\u00E9rifie pas le sous-domaine interrog\u00E9.',
    guidanceCnameMissing: 'Le CNAME n\u2019est pas configur\u00E9 sur l\u2019h\u00F4te interrog\u00E9. V\u00E9rifiez que cela correspond bien \u00E0 votre sc\u00E9nario.',
    guidanceDkim1Missing: 'Le s\u00E9lecteur DKIM1 (selector1-azurecomm-prod-net) est manquant.',
    guidanceDkim2Missing: 'Le s\u00E9lecteur DKIM2 (selector2-azurecomm-prod-net) est manquant.',
    guidanceDmarcInherited: 'La politique DMARC effective est h\u00E9rit\u00E9e du domaine parent {lookupDomain}.',
    guidanceDmarcMissing: 'DMARC est manquant. Ajoutez un enregistrement TXT _dmarc.{domain} pour r\u00E9duire le risque d\u2019usurpation.',
    guidanceDmarcMoreInfo: 'Pour plus d\u2019informations sur la syntaxe de l\u2019enregistrement TXT DMARC, consultez : {url}',
    guidanceDnsTxtFailed: 'La recherche DNS TXT a \u00E9chou\u00E9 ou a expir\u00E9. Les autres enregistrements DNS peuvent encore r\u00E9pondre.',
    guidanceDomainExpired: 'L\u2019enregistrement du domaine semble expir\u00E9. Renouvelez le domaine avant de continuer.',
    guidanceDomainVeryYoung: 'Le domaine a \u00E9t\u00E9 enregistr\u00E9 tr\u00E8s r\u00E9cemment (dans les {days} derniers jours). Cela est trait\u00E9 comme un signal d\u2019erreur pour la v\u00E9rification ; demandez au client d\u2019attendre davantage.',
    guidanceDomainYoung: 'Le domaine a \u00E9t\u00E9 enregistr\u00E9 r\u00E9cemment (dans les {days} derniers jours). Demandez au client d\u2019attendre davantage ; Microsoft utilise ce signal pour aider \u00E0 emp\u00EAcher les spammeurs de cr\u00E9er de nouvelles adresses web.',
    guidanceMxGoogleSpf: 'Votre MX indique Google Workspace, mais SPF n\u2019inclut pas _spf.google.com. V\u00E9rifiez que votre SPF inclut bien l\u2019include correct du fournisseur.',
    guidanceMxMicrosoftSpf: 'Votre MX indique Microsoft 365, mais SPF n\u2019inclut pas spf.protection.outlook.com. V\u00E9rifiez que votre SPF inclut bien l\u2019include correct du fournisseur.',
    guidanceMxMissing: 'Aucun enregistrement MX d\u00E9tect\u00E9. Le flux de messagerie ne fonctionnera pas tant que les enregistrements MX ne seront pas configur\u00E9s.',
    guidanceMxMissingCheckedParent: 'Aucun enregistrement MX d\u00E9tect\u00E9 pour {domain} ni pour son domaine parent {parentDomain}. Le flux de messagerie ne fonctionnera pas tant que les enregistrements MX ne seront pas configur\u00E9s.',
    guidanceMxMissingParentFallback: 'Aucun enregistrement MX trouv\u00E9 sur {domain} ; utilisation des MX du domaine parent {lookupDomain} en secours.',
    guidanceMxParentShown: 'Aucun enregistrement MX trouv\u00E9 sur {domain} ; les r\u00E9sultats affich\u00E9s proviennent du domaine parent {lookupDomain}.',
    guidanceMxProviderDetected: 'Fournisseur MX d\u00E9tect\u00E9 : {provider}',
    guidanceMxZohoSpf: 'Votre MX indique Zoho, mais SPF n\u2019inclut pas include:zoho.com. V\u00E9rifiez que votre SPF inclut bien l\u2019include correct du fournisseur.',
    guidanceSpfMissing: 'SPF est manquant. Ajoutez v=spf1 include:spf.protection.outlook.com -all (ou l\u2019\u00E9quivalent de votre fournisseur).',
    guidanceSpfMissingParent: 'SPF est manquant sur {domain}. Le domaine parent {lookupDomain} publie SPF, mais SPF ne s\u2019applique pas automatiquement au sous-domaine interrog\u00E9.',
    listingsLabel: 'Inscriptions',
    missingRequiredAcsTxt: 'Le TXT ACS requis est manquant.',
    mxRecordsLabel: 'Enregistrements MX',
    mxUsingParentNote: '(utilise le MX du domaine parent {lookupDomain})',
    newDomainUnder180Days: 'Nouveau domaine de moins de 180 jours.',
    newDomainUnder90Days: 'Nouveau domaine de moins de 90 jours.',
    newDomainUnderDays: 'Nouveau domaine (moins de {days} jours){suffix}',
    noMxRecordsDetected: 'Aucun enregistrement MX d\u00E9tect\u00E9.',
    noSpfRecordDetected: 'Aucun enregistrement SPF d\u00E9tect\u00E9.',
    noSuccessfulQueries: 'Inconnu (aucune requ\u00EAte r\u00E9ussie)',
    notStarted: 'NON D\u00C9MARR\u00C9',
    notVerified: 'NON V\u00C9RIFI\u00C9',
    noteDomainLessThanDays: 'Le domaine a moins de {days} jours.',
    pageTitle: 'Azure Communication Services - V\u00E9rificateur de domaine e-mail',
    parentCheckedNoMx: 'Le domaine parent {parentDomain} a \u00E9t\u00E9 v\u00E9rifi\u00E9 (aucun MX).',
    registrationAppearsExpired: 'L\u2019enregistrement du domaine semble expir\u00E9.',
    rawWhoisLabel: 'whois',
    source: 'Source',
    spfStatusLabel: '\u00C9tat SPF',
    statusLabel: 'Statut',
    txtLookupFailedOrTimedOut: 'La recherche TXT a \u00E9chou\u00E9 ou a expir\u00E9.',
    type: 'Type',
    unableDetermineAcsTxtValue: 'Impossible de d\u00E9terminer la valeur TXT ACS.',
    unknown: 'INCONNU',
    verified: 'V\u00C9RIFI\u00C9',
    waitingForBaseTxtLookup: 'En attente de la recherche TXT de base...',
    waitingForTxtLookup: 'En attente de la recherche TXT...'
  },
  de: {
    acsReadyMessage: 'Diese Domain scheint f\u00FCr die Dom\u00E4nen\u00FCberpr\u00FCfung von Azure Communication Services bereit zu sein.',
    checkingDnsblReputation: 'DNSBL-Reputation wird gepr\u00FCft...',
    checkingMxRecords: 'MX-Eintr\u00E4ge werden gepr\u00FCft...',
    checkingValue: 'Wird gepr\u00FCft...',
    cname: 'CNAME',
    dkim1StatusLabel: 'DKIM1-Status',
    dkim2StatusLabel: 'DKIM2-Status',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: 'Die DKIM-Ausrichtung f\u00FCr {domain} verwendet den lockeren Modus (adkim=r). Erw\u00E4gen Sie eine strikte Ausrichtung (adkim=s), wenn Ihre Sendeinfrastruktur dies zur besseren Domainabsicherung unterst\u00FCtzt.',
    dmarcAspfRelaxed: 'Die SPF-Ausrichtung f\u00FCr {domain} verwendet den lockeren Modus (aspf=r). Erw\u00E4gen Sie eine strikte Ausrichtung (aspf=s), wenn Ihre Absender konsequent die exakte Domain verwenden.',
    dmarcMissingRua: 'DMARC f\u00FCr {domain} ver\u00F6ffentlicht keine aggregierten Berichte (rua=). Das Hinzuf\u00FCgen eines Berichtspostfachs verbessert die Sichtbarkeit von Spoofing-Versuchen und deren Auswirkungen.',
    dmarcMissingRuf: 'DMARC f\u00FCr {domain} ver\u00F6ffentlicht keine forensischen Berichte (ruf=). Falls Ihr Prozess dies zul\u00E4sst, k\u00F6nnen forensische Berichte zus\u00E4tzliche Details f\u00FCr Untersuchungen liefern.',
    dmarcMissingSp: 'DMARC f\u00FCr Subdomains von {lookupDomain} definiert keine explizite Subdomain-Richtlinie (sp=). Wenn Sie von Subdomains wie {domain} senden, sollten Sie sp=quarantine oder sp=reject f\u00FCr klareren Schutz hinzuf\u00FCgen.',
    dmarcMonitorOnly: 'DMARC f\u00FCr {domain} ist nur auf \u00DCberwachung eingestellt (p=none). F\u00FCr st\u00E4rkeren Schutz vor Spoofing wechseln Sie nach der Validierung legitimer Quellen zu p=quarantine oder p=reject.',
    dmarcPct: 'Die DMARC-Durchsetzung f\u00FCr {domain} gilt nur f\u00FCr {pct}% der Nachrichten (pct={pct}). Verwenden Sie pct=100 f\u00FCr vollst\u00E4ndigen Schutz, sobald die Einf\u00FChrung validiert ist.',
    dmarcQuarantine: 'DMARC f\u00FCr {domain} ist auf p=quarantine gesetzt. F\u00FCr den st\u00E4rksten Schutz vor Spoofing sollten Sie p=reject in Betracht ziehen, sobald legitime E-Mails vollst\u00E4ndig ausgerichtet sind.',
    dmarcStatusLabel: 'DMARC-Status',
    domain: 'Domain',
    domainDossier: 'Domain-Dossier (CentralOps)',
    domainNameLabel: 'Domainname',
    domainStatusLabel: 'Domainstatus',
    expiredOn: 'Abgelaufen am {date}',
    guidanceAcsMissing: 'ACS ms-domain-verification TXT fehlt. F\u00FCgen Sie den Wert aus dem Azure-Portal hinzu.',
    guidanceAcsMissingParent: 'ACS ms-domain-verification TXT fehlt auf {domain}. Die \u00FCbergeordnete Domain {lookupDomain} enth\u00E4lt zwar einen ACS-TXT-Eintrag, \u00FCberpr\u00FCft aber nicht die abgefragte Subdomain.',
    guidanceCnameMissing: 'CNAME ist auf dem abgefragten Host nicht konfiguriert. Pr\u00FCfen Sie, ob dies f\u00FCr Ihr Szenario erwartet wird.',
    guidanceDkim1Missing: 'DKIM selector1 (selector1-azurecomm-prod-net) fehlt.',
    guidanceDkim2Missing: 'DKIM selector2 (selector2-azurecomm-prod-net) fehlt.',
    guidanceDmarcInherited: 'Die effektive DMARC-Richtlinie wird von der \u00FCbergeordneten Domain {lookupDomain} geerbt.',
    guidanceDmarcMissing: 'DMARC fehlt. F\u00FCgen Sie einen _dmarc.{domain}-TXT-Eintrag hinzu, um das Spoofing-Risiko zu verringern.',
    guidanceDmarcMoreInfo: 'Weitere Informationen zur Syntax von DMARC-TXT-Eintr\u00E4gen finden Sie unter: {url}',
    guidanceDnsTxtFailed: 'Die DNS-TXT-Abfrage ist fehlgeschlagen oder hat das Zeitlimit \u00FCberschritten. Andere DNS-Eintr\u00E4ge k\u00F6nnen dennoch aufgel\u00F6st werden.',
    guidanceDomainExpired: 'Die Domainregistrierung scheint abgelaufen zu sein. Verl\u00E4ngern Sie die Domain, bevor Sie fortfahren.',
    guidanceDomainVeryYoung: 'Die Domain wurde erst vor sehr kurzer Zeit registriert (innerhalb von {days} Tagen). Dies wird als Fehlersignal f\u00FCr die \u00DCberpr\u00FCfung gewertet; bitten Sie den Kunden, noch etwas l\u00E4nger zu warten.',
    guidanceDomainYoung: 'Die Domain wurde vor Kurzem registriert (innerhalb von {days} Tagen). Bitten Sie den Kunden, noch etwas l\u00E4nger zu warten; Microsoft nutzt dieses Signal, um Spammer am Einrichten neuer Webadressen zu hindern.',
    guidanceMxGoogleSpf: 'Ihr MX weist auf Google Workspace hin, aber SPF enth\u00E4lt nicht _spf.google.com. Pr\u00FCfen Sie, ob SPF den korrekten Provider-Include enth\u00E4lt.',
    guidanceMxMicrosoftSpf: 'Ihr MX weist auf Microsoft 365 hin, aber SPF enth\u00E4lt nicht spf.protection.outlook.com. Pr\u00FCfen Sie, ob SPF den korrekten Provider-Include enth\u00E4lt.',
    guidanceMxMissing: 'Es wurden keine MX-Eintr\u00E4ge erkannt. Der E-Mail-Fluss funktioniert erst, wenn MX-Eintr\u00E4ge konfiguriert sind.',
    guidanceMxMissingCheckedParent: 'Es wurden keine MX-Eintr\u00E4ge f\u00FCr {domain} oder die \u00FCbergeordnete Domain {parentDomain} erkannt. Der E-Mail-Fluss funktioniert erst, wenn MX-Eintr\u00E4ge konfiguriert sind.',
    guidanceMxMissingParentFallback: 'Keine MX-Eintr\u00E4ge auf {domain} gefunden; MX-Eintr\u00E4ge der \u00FCbergeordneten Domain {lookupDomain} werden als Fallback verwendet.',
    guidanceMxParentShown: 'Keine MX-Eintr\u00E4ge auf {domain} gefunden; die angezeigten Ergebnisse stammen von der \u00FCbergeordneten Domain {lookupDomain}.',
    guidanceMxProviderDetected: 'Erkannter MX-Anbieter: {provider}',
    guidanceMxZohoSpf: 'Ihr MX weist auf Zoho hin, aber SPF enth\u00E4lt nicht include:zoho.com. Pr\u00FCfen Sie, ob SPF den korrekten Provider-Include enth\u00E4lt.',
    guidanceSpfMissing: 'SPF fehlt. F\u00FCgen Sie v=spf1 include:spf.protection.outlook.com -all hinzu (oder das entsprechende \u00C4quivalent Ihres Anbieters).',
    guidanceSpfMissingParent: 'SPF fehlt auf {domain}. Die \u00FCbergeordnete Domain {lookupDomain} ver\u00F6ffentlicht SPF, aber SPF gilt nicht automatisch f\u00FCr die abgefragte Subdomain.',
    hostname: 'Hostname',
    info: 'INFO',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    listingsLabel: 'Listungen',
    missingRequiredAcsTxt: 'Erforderlicher ACS-TXT-Eintrag fehlt.',
    mxRecordsLabel: 'MX-Eintr\u00E4ge',
    mxUsingParentNote: '(MX der \u00FCbergeordneten Domain {lookupDomain} wird verwendet)',
    newDomainUnder180Days: 'Neue Domain, j\u00FCnger als 180 Tage.',
    newDomainUnder90Days: 'Neue Domain, j\u00FCnger als 90 Tage.',
    newDomainUnderDays: 'Neue Domain (unter {days} Tagen){suffix}',
    noMxRecordsDetected: 'Keine MX-Eintr\u00E4ge erkannt.',
    noSpfRecordDetected: 'Kein SPF-Eintrag erkannt.',
    noSuccessfulQueries: 'Unbekannt (keine erfolgreichen Abfragen)',
    notStarted: 'NICHT GESTARTET',
    notVerified: 'NICHT VERIFIZIERT',
    noteDomainLessThanDays: 'Die Domain ist j\u00FCnger als {days} Tage.',
    pageTitle: 'Azure Communication Services - E-Mail-Domain-Pr\u00FCfer',
    parentCheckedNoMx: '\u00DCbergeordnete Domain {parentDomain} wurde gepr\u00FCft (kein MX).',
    rawWhoisLabel: 'whois',
    registrarLabel: 'Registrar',
    registrationAppearsExpired: 'Die Domainregistrierung scheint abgelaufen zu sein.',
    reputationDnsbl: 'Reputation (DNSBL)',
    reputationWord: 'Reputation',
    spfStatusLabel: 'SPF-Status',
    status: 'Status',
    statusLabel: 'Status',
    tools: 'TOOLS',
    txtLookupFailedOrTimedOut: 'TXT-Abfrage fehlgeschlagen oder Zeit\u00FCberschreitung.',
    unableDetermineAcsTxtValue: 'ACS-TXT-Wert konnte nicht ermittelt werden.',
    unknown: 'UNBEKANNT',
    verified: 'VERIFIZIERT',
    waitingForBaseTxtLookup: 'Warten auf Basis-TXT-Abfrage...',
    waitingForTxtLookup: 'Warten auf TXT-Abfrage...'
  },
  'pt-BR': {
    acsReadyMessage: 'Este dom\u00EDnio parece pronto para a verifica\u00E7\u00E3o de dom\u00EDnio do Azure Communication Services.',
    checkingDnsblReputation: 'Verificando a reputa\u00E7\u00E3o DNSBL...',
    checkingMxRecords: 'Verificando os registros MX...',
    checkingValue: 'Verificando...',
    checklist: 'CHECKLIST',
    cname: 'CNAME',
    dkim1StatusLabel: 'Status do DKIM1',
    dkim2StatusLabel: 'Status do DKIM2',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: 'O alinhamento DKIM para {domain} usa modo relaxado (adkim=r). Considere alinhamento estrito (adkim=s) se a sua infraestrutura de envio permitir, para maior prote\u00E7\u00E3o do dom\u00EDnio.',
    dmarcAspfRelaxed: 'O alinhamento SPF para {domain} usa modo relaxado (aspf=r). Considere alinhamento estrito (aspf=s) se os remetentes usarem consistentemente o dom\u00EDnio exato.',
    dmarcMissingRua: 'O DMARC para {domain} n\u00E3o publica relat\u00F3rios agregados (rua=). Adicionar uma caixa de correio de relat\u00F3rio melhora a visibilidade sobre tentativas de spoofing e o impacto da aplica\u00E7\u00E3o.',
    dmarcMissingRuf: 'O DMARC para {domain} n\u00E3o publica relat\u00F3rios forenses (ruf=). Se o seu processo permitir, esses relat\u00F3rios podem fornecer mais detalhes para investiga\u00E7\u00F5es.',
    dmarcMissingSp: 'O DMARC para subdom\u00EDnios de {lookupDomain} n\u00E3o define uma pol\u00EDtica expl\u00EDcita para subdom\u00EDnios (sp=). Se voc\u00EA envia de subdom\u00EDnios como {domain}, considere adicionar sp=quarantine ou sp=reject para uma prote\u00E7\u00E3o mais clara.',
    dmarcMonitorOnly: 'O DMARC para {domain} est\u00E1 somente em monitoramento (p=none). Para uma prote\u00E7\u00E3o mais forte contra spoofing, avance para enforcement com p=quarantine ou p=reject ap\u00F3s validar as fontes leg\u00EDtimas de e-mail.',
    dmarcPct: 'A aplica\u00E7\u00E3o do DMARC para {domain} vale apenas para {pct}% das mensagens (pct={pct}). Use pct=100 para prote\u00E7\u00E3o total quando a implanta\u00E7\u00E3o estiver validada.',
    dmarcQuarantine: 'O DMARC para {domain} est\u00E1 definido como p=quarantine. Para a postura mais forte contra spoofing, considere p=reject quando confirmar que o e-mail leg\u00EDtimo est\u00E1 totalmente alinhado.',
    dmarcStatusLabel: 'Status do DMARC',
    docs: 'DOCS',
    domainDossier: 'Dossi\u00EA do dom\u00EDnio (CentralOps)',
    domainNameLabel: 'Nome do dom\u00EDnio',
    domainStatusLabel: 'Status do dom\u00EDnio',
    expiredOn: 'Expirado em {date}',
    guidanceAcsMissing: 'O TXT ACS ms-domain-verification est\u00E1 ausente. Adicione o valor do portal do Azure.',
    guidanceAcsMissingParent: 'O TXT ACS ms-domain-verification est\u00E1 ausente em {domain}. O dom\u00EDnio pai {lookupDomain} tem um TXT ACS, mas ele n\u00E3o verifica o subdom\u00EDnio consultado.',
    guidanceCnameMissing: 'O CNAME n\u00E3o est\u00E1 configurado no host consultado. Valide se isso \u00E9 esperado para o seu cen\u00E1rio.',
    guidanceDkim1Missing: 'O seletor DKIM1 (selector1-azurecomm-prod-net) est\u00E1 ausente.',
    guidanceDkim2Missing: 'O seletor DKIM2 (selector2-azurecomm-prod-net) est\u00E1 ausente.',
    guidanceDmarcInherited: 'A pol\u00EDtica DMARC efetiva \u00E9 herdada do dom\u00EDnio pai {lookupDomain}.',
    guidanceDmarcMissing: 'O DMARC est\u00E1 ausente. Adicione um registro TXT _dmarc.{domain} para reduzir o risco de falsifica\u00E7\u00E3o.',
    guidanceDmarcMoreInfo: 'Para mais informa\u00E7\u00F5es sobre a sintaxe do registro TXT DMARC, consulte: {url}',
    guidanceDnsTxtFailed: 'A consulta DNS TXT falhou ou excedeu o tempo limite. Outros registros DNS ainda podem resolver.',
    guidanceDomainExpired: 'O registro do dom\u00EDnio parece expirado. Renove o dom\u00EDnio antes de continuar.',
    guidanceDomainVeryYoung: 'O dom\u00EDnio foi registrado muito recentemente (dentro de {days} dias). Isso \u00E9 tratado como um sinal de erro para verifica\u00E7\u00E3o; pe\u00E7a ao cliente para aguardar mais tempo.',
    guidanceDomainYoung: 'O dom\u00EDnio foi registrado recentemente (dentro de {days} dias). Pe\u00E7a ao cliente para aguardar mais tempo; a Microsoft usa esse sinal para ajudar a impedir que remetentes mal-intencionados configurem novos endere\u00E7os da web.',
    guidanceMxGoogleSpf: 'Seu MX indica Google Workspace, mas o SPF n\u00E3o inclui _spf.google.com. Verifique se o SPF inclui o include correto do provedor.',
    guidanceMxMicrosoftSpf: 'Seu MX indica Microsoft 365, mas o SPF n\u00E3o inclui spf.protection.outlook.com. Verifique se o SPF inclui o include correto do provedor.',
    guidanceMxMissing: 'Nenhum registro MX detectado. O fluxo de e-mail n\u00E3o funcionar\u00E1 at\u00E9 que os registros MX sejam configurados.',
    guidanceMxMissingCheckedParent: 'Nenhum registro MX detectado para {domain} nem para o dom\u00EDnio pai {parentDomain}. O fluxo de e-mail n\u00E3o funcionar\u00E1 at\u00E9 que os registros MX sejam configurados.',
    guidanceMxMissingParentFallback: 'Nenhum registro MX encontrado em {domain}; usando os registros MX do dom\u00EDnio pai {lookupDomain} como alternativa.',
    guidanceMxParentShown: 'Nenhum registro MX encontrado em {domain}; os resultados exibidos s\u00E3o do dom\u00EDnio pai {lookupDomain}.',
    guidanceMxProviderDetected: 'Provedor MX detectado: {provider}',
    guidanceMxZohoSpf: 'Seu MX indica Zoho, mas o SPF n\u00E3o inclui include:zoho.com. Verifique se o SPF inclui o include correto do provedor.',
    guidanceSpfMissing: 'O SPF est\u00E1 ausente. Adicione v=spf1 include:spf.protection.outlook.com -all (ou o equivalente do seu provedor).',
    guidanceSpfMissingParent: 'O SPF est\u00E1 ausente em {domain}. O dom\u00EDnio pai {lookupDomain} publica SPF, mas o SPF n\u00E3o se aplica automaticamente ao subdom\u00EDnio consultado.',
    hostname: 'Hostname',
    info: 'INFO',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    listingsLabel: 'Listagens',
    missingRequiredAcsTxt: 'O TXT ACS obrigat\u00F3rio est\u00E1 ausente.',
    mxRecordsLabel: 'Registros MX',
    mxUsingParentNote: '(usando MX do dom\u00EDnio pai {lookupDomain})',
    newDomainUnder180Days: 'Dom\u00EDnio novo com menos de 180 dias.',
    newDomainUnder90Days: 'Dom\u00EDnio novo com menos de 90 dias.',
    newDomainUnderDays: 'Dom\u00EDnio novo (menos de {days} dias){suffix}',
    noMxRecordsDetected: 'Nenhum registro MX detectado.',
    noSpfRecordDetected: 'Nenhum registro SPF detectado.',
    noSuccessfulQueries: 'Desconhecida (nenhuma consulta bem-sucedida)',
    notStarted: 'N\u00C3O INICIADO',
    notVerified: 'N\u00C3O VERIFICADO',
    noteDomainLessThanDays: 'O dom\u00EDnio tem menos de {days} dias.',
    pageTitle: 'Azure Communication Services - Verificador de dom\u00EDnio de e-mail',
    parentCheckedNoMx: 'O dom\u00EDnio pai {parentDomain} foi verificado (sem MX).',
    rawWhoisLabel: 'whois',
    registrationAppearsExpired: 'O registro do dom\u00EDnio parece expirado.',
    spfStatusLabel: 'Status do SPF',
    status: 'Status',
    statusLabel: 'Status',
    txtLookupFailedOrTimedOut: 'A consulta TXT falhou ou excedeu o tempo limite.',
    unableDetermineAcsTxtValue: 'N\u00E3o foi poss\u00EDvel determinar o valor do TXT ACS.',
    unknown: 'DESCONHECIDO',
    verified: 'VERIFICADO',
    waitingForBaseTxtLookup: 'Aguardando a consulta TXT base...',
    waitingForTxtLookup: 'Aguardando a consulta TXT...'
  },
  ar: {
    acsEmailDomainVerification: '\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0646\u0637\u0627\u0642 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0644\u0640 ACS',
    acsEmailQuotaLimitIncrease: '\u0632\u064A\u0627\u062F\u0629 \u062D\u062F \u062D\u0635\u0629 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0644\u0640 ACS',
    acsReadiness: '\u062C\u0627\u0647\u0632\u064A\u0629 ACS',
    acsTxtMsDomainVerification: 'TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u200F(ms-domain-verification)',
    addAcsTxtFromPortal: '\u0623\u0636\u0641 TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u0645\u0646 \u0645\u062F\u062E\u0644 Azure.',
    additionalDetailsMinus: '\u062A\u0641\u0627\u0635\u064A\u0644 \u0625\u0636\u0627\u0641\u064A\u0629 -',
    additionalDetailsPlus: '\u062A\u0641\u0627\u0635\u064A\u0644 \u0625\u0636\u0627\u0641\u064A\u0629 +',
    addresses: '\u0627\u0644\u0639\u0646\u0627\u0648\u064A\u0646',
    ageLabel: '\u0627\u0644\u0639\u0645\u0631',
    authMicrosoftLabel: 'Microsoft',
    checkingDnsblReputation: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0633\u0645\u0639\u0629 DNSBL...',
    checkingMxRecords: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0633\u062C\u0644\u0627\u062A MX...',
    checkingValue: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642...',
    checklist: '\u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u062A\u062D\u0642\u0642',
    clean: '\u0646\u0638\u064A\u0641',
    cname: 'CNAME',
    copied: '\u062A\u0645 \u0627\u0644\u0646\u0633\u062E! \u2714',
    copy: '\u0646\u0633\u062E',
    copyEmailQuota: '\u0646\u0633\u062E \u062D\u0635\u0629 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A',
    creationDate: '\u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
    daysUntilExpiry: '\u0639\u062F\u062F \u0627\u0644\u0623\u064A\u0627\u0645 \u062D\u062A\u0649 \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621',
    detectedProvider: '\u0645\u0648\u0641\u0631 \u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641\u0647',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dkimRecordBasics: '\u0623\u0633\u0627\u0633\u064A\u0627\u062A DKIM',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: '\u064A\u0633\u062A\u062E\u062F\u0645 \u062A\u0648\u0627\u0641\u0642 DKIM \u0644\u0640 {domain} \u0627\u0644\u0648\u0636\u0639 \u0627\u0644\u0645\u0631\u0646 (adkim=r). \u0641\u0643\u0651\u0631 \u0641\u064A \u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0627\u0644\u0635\u0627\u0631\u0645 (adkim=s) \u0625\u0630\u0627 \u0643\u0627\u0646\u062A \u0628\u0646\u064A\u0629 \u0627\u0644\u0625\u0631\u0633\u0627\u0644 \u0644\u062F\u064A\u0643 \u062A\u062F\u0639\u0645\u0647 \u0644\u062D\u0645\u0627\u064A\u0629 \u0623\u0643\u062B\u0631 \u0625\u062D\u0643\u0627\u0645\u064B\u0627 \u0644\u0644\u0646\u0637\u0627\u0642.',
    dmarcAspfRelaxed: '\u064A\u0633\u062A\u062E\u062F\u0645 \u062A\u0648\u0627\u0641\u0642 SPF \u0644\u0640 {domain} \u0627\u0644\u0648\u0636\u0639 \u0627\u0644\u0645\u0631\u0646 (aspf=r). \u0641\u0643\u0651\u0631 \u0641\u064A \u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0627\u0644\u0635\u0627\u0631\u0645 (aspf=s) \u0625\u0630\u0627 \u0643\u0627\u0646 \u0627\u0644\u0645\u0631\u0633\u0644\u0648\u0646 \u0644\u062F\u064A\u0643 \u064A\u0633\u062A\u062E\u062F\u0645\u0648\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0646\u0641\u0633\u0647 \u0628\u0627\u0633\u062A\u0645\u0631\u0627\u0631.',
    dmarcMissingRua: '\u0644\u0627 \u064A\u0646\u0634\u0631 DMARC \u0644\u0640 {domain} \u062A\u0642\u0627\u0631\u064A\u0631 \u0645\u062C\u0645\u0639\u0629 (rua=). \u062A\u0624\u062F\u064A \u0625\u0636\u0627\u0641\u0629 \u0635\u0646\u062F\u0648\u0642 \u0628\u0631\u064A\u062F \u0644\u0644\u062A\u0642\u0627\u0631\u064A\u0631 \u0625\u0644\u0649 \u062A\u062D\u0633\u064A\u0646 \u0627\u0644\u0631\u0624\u064A\u0629 \u0644\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0627\u0644\u0627\u0646\u062A\u062D\u0627\u0644 \u0648\u062A\u0623\u062B\u064A\u0631\u0627\u062A \u0627\u0644\u062A\u0637\u0628\u064A\u0642.',
    dmarcMissingRuf: '\u0644\u0627 \u064A\u0646\u0634\u0631 DMARC \u0644\u0640 {domain} \u062A\u0642\u0627\u0631\u064A\u0631 \u062A\u062D\u0644\u064A\u0644\u064A\u0629/\u062C\u0646\u0627\u0626\u064A\u0629 (ruf=). \u0625\u0630\u0627 \u0643\u0627\u0646\u062A \u0625\u062C\u0631\u0627\u0621\u0627\u062A\u0643 \u062A\u0633\u0645\u062D \u0628\u0630\u0644\u0643\u060C \u0641\u0642\u062F \u062A\u0648\u0641\u0631 \u0647\u0630\u0647 \u0627\u0644\u062A\u0642\u0627\u0631\u064A\u0631 \u062A\u0641\u0627\u0635\u064A\u0644 \u0625\u0636\u0627\u0641\u064A\u0629 \u0644\u0644\u062A\u062D\u0642\u064A\u0642\u0627\u062A.',
    dmarcMissingSp: '\u0644\u0627 \u064A\u062D\u062F\u062F DMARC \u0644\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629 \u0627\u0644\u062A\u0627\u0628\u0639\u0629 \u0644\u0640 {lookupDomain} \u0633\u064A\u0627\u0633\u0629 \u0635\u0631\u064A\u062D\u0629 \u0644\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629 (sp=). \u0625\u0630\u0627 \u0643\u0646\u062A \u062A\u0631\u0633\u0644 \u0645\u0646 \u0646\u0637\u0627\u0642\u0627\u062A \u0641\u0631\u0639\u064A\u0629 \u0645\u062B\u0644 {domain}\u060C \u0641\u0641\u0643\u0651\u0631 \u0641\u064A \u0625\u0636\u0627\u0641\u0629 sp=quarantine \u0623\u0648 sp=reject \u0644\u062D\u0645\u0627\u064A\u0629 \u0623\u0648\u0636\u062D.',
    dmarcMonitorOnly: '\u0625\u0646 DMARC \u0644\u0640 {domain} \u0641\u064A \u0648\u0636\u0639 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0641\u0642\u0637 (p=none). \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u062D\u0645\u0627\u064A\u0629 \u0623\u0642\u0648\u0649 \u0645\u0646 \u0627\u0644\u0627\u0646\u062A\u062D\u0627\u0644\u060C \u0627\u0646\u062A\u0642\u0644 \u0625\u0644\u0649 \u0627\u0644\u062A\u0637\u0628\u064A\u0642 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 p=quarantine \u0623\u0648 p=reject \u0628\u0639\u062F \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0645\u0635\u0627\u062F\u0631 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0634\u0631\u0639\u064A\u0629.',
    dmarcPct: '\u064A\u062A\u0645 \u062A\u0637\u0628\u064A\u0642 DMARC \u0644\u0640 {domain} \u0639\u0644\u0649 {pct}% \u0641\u0642\u0637 \u0645\u0646 \u0627\u0644\u0631\u0633\u0627\u0626\u0644 (pct={pct}). \u0627\u0633\u062A\u062E\u062F\u0645 pct=100 \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u062D\u0645\u0627\u064A\u0629 \u0643\u0627\u0645\u0644\u0629 \u0628\u0645\u062C\u0631\u062F \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0634\u0631.',
    dmarcQuarantine: '\u062A\u0645 \u062A\u0639\u064A\u064A\u0646 DMARC \u0644\u0640 {domain} \u0625\u0644\u0649 p=quarantine. \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0623\u0642\u0648\u0649 \u062D\u0645\u0627\u064A\u0629 \u0645\u0646 \u0627\u0644\u0627\u0646\u062A\u062D\u0627\u0644\u060C \u0641\u0643\u0651\u0631 \u0641\u064A p=reject \u0628\u0639\u062F \u0627\u0644\u062A\u0623\u0643\u062F \u0645\u0646 \u0623\u0646 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0634\u0631\u0639\u064A \u0645\u062A\u0648\u0627\u0641\u0642 \u0628\u0627\u0644\u0643\u0627\u0645\u0644.',
    dmarcRecordBasics: '\u0623\u0633\u0627\u0633\u064A\u0627\u062A DMARC',
    dnsTxtLookup: '\u0627\u0633\u062A\u0639\u0644\u0627\u0645 DNS TXT',
    docs: '\u0627\u0644\u0645\u0633\u062A\u0646\u062F\u0627\u062A',
    domain: '\u0627\u0644\u0646\u0637\u0627\u0642',
    domainAgeLabel: '\u0639\u0645\u0631 \u0627\u0644\u0646\u0637\u0627\u0642',
    domainDossier: '\u0645\u0644\u0641 \u0627\u0644\u0646\u0637\u0627\u0642 (CentralOps)',
    domainExpiringIn: '\u064A\u0646\u062A\u0647\u064A \u0627\u0644\u0646\u0637\u0627\u0642 \u062E\u0644\u0627\u0644',
    effectivePolicyInherited: '\u064A\u062A\u0645 \u062A\u0648\u0631\u064A\u062B \u0627\u0644\u0633\u064A\u0627\u0633\u0629 \u0627\u0644\u0641\u0639\u0627\u0644\u0629 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain}.',
    error: '\u062E\u0637\u0623',
    errorsCount: '\u0627\u0644\u0623\u062E\u0637\u0627\u0621',
    excellent: '\u0645\u0645\u062A\u0627\u0632',
    expired: '\u0645\u0646\u062A\u0647\u064A \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629',
    expiresInLabel: '\u064A\u0646\u062A\u0647\u064A \u062E\u0644\u0627\u0644',
    failed: '\u0641\u0634\u0644',
    fair: '\u0645\u0642\u0628\u0648\u0644',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u0645\u0646 \u0625\u0639\u062F\u0627\u062F: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 \u062A\u0645 \u0625\u0646\u0634\u0627\u0624\u0647 \u0628\u0648\u0627\u0633\u0637\u0629 PowerShell \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">\u0627\u0644\u0639\u0648\u062F\u0629 \u0625\u0644\u0649 \u0627\u0644\u0623\u0639\u0644\u0649</a>',
    good: '\u062C\u064A\u062F',
    great: '\u0631\u0627\u0626\u0639',
    guidanceAcsMissing: 'TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS ms-domain-verification \u0645\u0641\u0642\u0648\u062F. \u0623\u0636\u0641 \u0627\u0644\u0642\u064A\u0645\u0629 \u0645\u0646 \u0645\u062F\u062E\u0644 Azure.',
    guidanceAcsMissingParent: 'TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS ms-domain-verification \u0645\u0641\u0642\u0648\u062F \u0639\u0644\u0649 {domain}. \u064A\u062D\u062A\u0648\u064A \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain} \u0639\u0644\u0649 \u0633\u062C\u0644 ACS TXT\u060C \u0644\u0643\u0646\u0647 \u0644\u0627 \u064A\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0641\u0631\u0639\u064A \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647.',
    guidanceCnameMissing: '\u0644\u0645 \u062A\u062A\u0645 \u062A\u0647\u064A\u0626\u0629 CNAME \u0639\u0644\u0649 \u0627\u0644\u0645\u0636\u064A\u0641 \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647. \u062A\u062D\u0642\u0651\u0642 \u0645\u0645\u0627 \u0625\u0630\u0627 \u0643\u0627\u0646 \u0647\u0630\u0627 \u0645\u062A\u0648\u0642\u0639\u064B\u0627 \u0644\u0633\u064A\u0646\u0627\u0631\u064A\u0648\u0643.',
    guidanceDkim1Missing: '\u0645\u062D\u062F\u062F DKIM1 \u200F(selector1-azurecomm-prod-net) \u0645\u0641\u0642\u0648\u062F.',
    guidanceDkim2Missing: '\u0645\u062D\u062F\u062F DKIM2 \u200F(selector2-azurecomm-prod-net) \u0645\u0641\u0642\u0648\u062F.',
    guidanceDmarcInherited: '\u064A\u062A\u0645 \u062A\u0648\u0631\u064A\u062B \u0633\u064A\u0627\u0633\u0629 DMARC \u0627\u0644\u0641\u0639\u0627\u0644\u0629 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain}.',
    guidanceDmarcMissing: 'DMARC \u0645\u0641\u0642\u0648\u062F. \u0623\u0636\u0641 \u0633\u062C\u0644 TXT \u0628\u0627\u0633\u0645 _dmarc.{domain} \u0644\u062A\u0642\u0644\u064A\u0644 \u0645\u062E\u0627\u0637\u0631 \u0627\u0644\u0627\u0646\u062A\u062D\u0627\u0644.',
    guidanceDmarcMoreInfo: '\u0644\u0645\u0632\u064A\u062F \u0645\u0646 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062A \u062D\u0648\u0644 \u0628\u0646\u064A\u0629 \u0633\u062C\u0644 DMARC TXT\u060C \u0631\u0627\u062C\u0639: {url}',
    guidanceDnsTxtFailed: '\u0641\u0634\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 DNS TXT \u0623\u0648 \u0627\u0646\u062A\u0647\u062A \u0645\u0647\u0644\u062A\u0647. \u0642\u062F \u062A\u0638\u0644 \u0633\u062C\u0644\u0627\u062A DNS \u0627\u0644\u0623\u062E\u0631\u0649 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062D\u0644.',
    guidanceMxGoogleSpf: '\u064A\u0634\u064A\u0631 MX \u0644\u062F\u064A\u0643 \u0625\u0644\u0649 Google Workspace\u060C \u0644\u0643\u0646 SPF \u0644\u0627 \u064A\u062A\u0636\u0645\u0646 _spf.google.com. \u062A\u062D\u0642\u0651\u0642 \u0645\u0646 \u0623\u0646 SPF \u064A\u062A\u0636\u0645\u0646 include \u0627\u0644\u0635\u062D\u064A\u062D \u0644\u0644\u0645\u0648\u0641\u0631.',
    guidanceMxMicrosoftSpf: '\u064A\u0634\u064A\u0631 MX \u0644\u062F\u064A\u0643 \u0625\u0644\u0649 Microsoft 365\u060C \u0644\u0643\u0646 SPF \u0644\u0627 \u064A\u062A\u0636\u0645\u0646 spf.protection.outlook.com. \u062A\u062D\u0642\u0651\u0642 \u0645\u0646 \u0623\u0646 SPF \u064A\u062A\u0636\u0645\u0646 include \u0627\u0644\u0635\u062D\u064A\u062D \u0644\u0644\u0645\u0648\u0641\u0631.',
    guidanceMxMissing: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u0633\u062C\u0644\u0627\u062A MX. \u0644\u0646 \u064A\u0639\u0645\u0644 \u062A\u062F\u0641\u0642 \u0627\u0644\u0628\u0631\u064A\u062F \u062D\u062A\u0649 \u062A\u062A\u0645 \u062A\u0647\u064A\u0626\u0629 \u0633\u062C\u0644\u0627\u062A MX.',
    guidanceMxMissingCheckedParent: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u0633\u062C\u0644\u0627\u062A MX \u0644\u0640 {domain} \u0623\u0648 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {parentDomain}. \u0644\u0646 \u064A\u0639\u0645\u0644 \u062A\u062F\u0641\u0642 \u0627\u0644\u0628\u0631\u064A\u062F \u062D\u062A\u0649 \u062A\u062A\u0645 \u062A\u0647\u064A\u0626\u0629 \u0633\u062C\u0644\u0627\u062A MX.',
    guidanceMxMissingParentFallback: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0633\u062C\u0644\u0627\u062A MX \u0639\u0644\u0649 {domain}\u061B \u0633\u064A\u062A\u0645 \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0633\u062C\u0644\u0627\u062A MX \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain} \u0643\u062E\u064A\u0627\u0631 \u0627\u062D\u062A\u064A\u0627\u0637\u064A.',
    guidanceMxParentShown: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0633\u062C\u0644\u0627\u062A MX \u0639\u0644\u0649 {domain}\u061B \u0627\u0644\u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0645\u0639\u0631\u0648\u0636\u0629 \u0645\u0623\u062E\u0648\u0630\u0629 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain}.',
    guidanceMxZohoSpf: '\u064A\u0634\u064A\u0631 MX \u0644\u062F\u064A\u0643 \u0625\u0644\u0649 Zoho\u060C \u0644\u0643\u0646 SPF \u0644\u0627 \u064A\u062A\u0636\u0645\u0646 include:zoho.com. \u062A\u062D\u0642\u0651\u0642 \u0645\u0646 \u0623\u0646 SPF \u064A\u062A\u0636\u0645\u0646 include \u0627\u0644\u0635\u062D\u064A\u062D \u0644\u0644\u0645\u0648\u0641\u0631.',
    guidanceSpfMissing: '\u0633\u062C\u0644 SPF \u0645\u0641\u0642\u0648\u062F. \u0623\u0636\u0641 v=spf1 include:spf.protection.outlook.com -all (\u0623\u0648 \u0645\u0627 \u064A\u0639\u0627\u062F\u0644\u0647 \u0644\u062F\u0649 \u0645\u0648\u0641\u0631 \u0627\u0644\u062E\u062F\u0645\u0629).',
    guidanceSpfMissingParent: '\u0633\u062C\u0644 SPF \u0645\u0641\u0642\u0648\u062F \u0639\u0644\u0649 {domain}. \u064A\u0646\u0634\u0631 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain} \u0633\u062C\u0644 SPF\u060C \u0644\u0643\u0646 SPF \u0644\u0627 \u064A\u0646\u0637\u0628\u0642 \u062A\u0644\u0642\u0627\u0626\u064A\u064B\u0627 \u0639\u0644\u0649 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0641\u0631\u0639\u064A \u0627\u0644\u0645\u0633\u062A\u0639\u0644\u0645 \u0639\u0646\u0647.',
    hostname: '\u0627\u0633\u0645 \u0627\u0644\u0645\u0636\u064A\u0641',
    info: '\u0645\u0639\u0644\u0648\u0645\u0629',
    ipAddress: '\u0639\u0646\u0648\u0627\u0646 IP',
    ipv4: 'IPv4',
    ipv4Addresses: '\u0639\u0646\u0627\u0648\u064A\u0646 IPv4',
    ipv6: 'IPv6',
    ipv6Addresses: '\u0639\u0646\u0627\u0648\u064A\u0646 IPv6',
    listed: '\u0645\u062F\u0631\u062C',
    listingsLabel: '\u0627\u0644\u0625\u062F\u0631\u0627\u062C\u0627\u062A',
    loadingValue: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0645\u064A\u0644...',
    missingRequiredAcsTxt: 'TXT \u0627\u0644\u0645\u0637\u0644\u0648\u0628 \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ACS \u0645\u0641\u0642\u0648\u062F.',
    msDomainVerificationFound: '\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 TXT \u0627\u0644\u062E\u0627\u0635 \u0628\u0640 ms-domain-verification.',
    multiRblLookup: '\u0628\u062D\u062B DNSBL \u0639\u0628\u0631 MultiRBL',
    mxRecordBasics: '\u0623\u0633\u0627\u0633\u064A\u0627\u062A MX',
    newDomainUnderDays: '\u0646\u0637\u0627\u0642 \u062C\u062F\u064A\u062F (\u0623\u0642\u0644 \u0645\u0646 {days} \u064A\u0648\u0645\u064B\u0627){suffix}',
    no: '\u0644\u0627',
    noAdditionalGuidance: '\u0644\u0627 \u062A\u0648\u062C\u062F \u0625\u0631\u0634\u0627\u062F\u0627\u062A \u0625\u0636\u0627\u0641\u064A\u0629.',
    noAdditionalMxDetails: '\u0644\u0627 \u062A\u0648\u062C\u062F \u062A\u0641\u0627\u0635\u064A\u0644 MX \u0625\u0636\u0627\u0641\u064A\u0629 \u0645\u062A\u0648\u0641\u0631\u0629.',
    noIpAddressesFound: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0639\u0646\u0627\u0648\u064A\u0646 IP',
    noMxParentChecked: '\u062A\u0645 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {parentDomain} (\u0644\u0627 \u064A\u0648\u062C\u062F MX).',
    noMxParentShowing: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0633\u062C\u0644\u0627\u062A MX \u0639\u0644\u0649 {domain}\u061B \u064A\u062A\u0645 \u0639\u0631\u0636 \u0633\u062C\u0644\u0627\u062A MX \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {lookupDomain}.',
    noMxRecordsDetected: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u0633\u062C\u0644\u0627\u062A MX.',
    noRecordsAvailable: '\u0644\u0627 \u062A\u0648\u062C\u062F \u0633\u062C\u0644\u0627\u062A \u0645\u062A\u0648\u0641\u0631\u0629.',
    noRegistrationInformation: '\u0644\u0627 \u062A\u062A\u0648\u0641\u0631 \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u062A\u0633\u062C\u064A\u0644.',
    noSpfRecordDetected: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u0633\u062C\u0644 SPF.',
    noSuccessfulQueries: '\u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641 (\u0644\u0627 \u062A\u0648\u062C\u062F \u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A \u0646\u0627\u062C\u062D\u0629)',
    none: '\u0644\u0627 \u064A\u0648\u062C\u062F',
    notListed: '\u063A\u064A\u0631 \u0645\u062F\u0631\u062C',
    notStarted: '\u0644\u0645 \u064A\u0628\u062F\u0623',
    notVerified: '\u063A\u064A\u0631 \u0645\u062A\u062D\u0642\u0642',
    noteDomainLessThanDays: '\u0639\u0645\u0631 \u0627\u0644\u0646\u0637\u0627\u0642 \u0623\u0642\u0644 \u0645\u0646 {days} \u064A\u0648\u0645\u064B\u0627.',
    passing: '\u0646\u0627\u062C\u062D',
    pending: '\u0642\u064A\u062F \u0627\u0644\u0627\u0646\u062A\u0638\u0627\u0631',
    poor: '\u0636\u0639\u064A\u0641',
    priority: '\u0627\u0644\u0623\u0648\u0644\u0648\u064A\u0629',
    rawLabel: '\u062E\u0627\u0645',
    rawWhoisLabel: 'whois',
    readinessTips: '\u0646\u0635\u0627\u0626\u062D \u0627\u0644\u062C\u0627\u0647\u0632\u064A\u0629',
    registrantLabel: '\u0635\u0627\u062D\u0628 \u0627\u0644\u062A\u0633\u062C\u064A\u0644',
    registrarLabel: '\u0627\u0644\u0645\u0633\u062C\u0644',
    registrationDetailsUnavailable: '\u062A\u0641\u0627\u0635\u064A\u0644 \u0627\u0644\u062A\u0633\u062C\u064A\u0644 \u063A\u064A\u0631 \u0645\u062A\u0648\u0641\u0631\u0629.',
    registryExpiryDate: '\u062A\u0627\u0631\u064A\u062E \u0627\u0646\u062A\u0647\u0627\u0621 \u0627\u0644\u062A\u0633\u062C\u064A\u0644',
    reputationDnsbl: '\u0627\u0644\u0633\u0645\u0639\u0629 (DNSBL)',
    reputationWord: '\u0627\u0644\u0633\u0645\u0639\u0629',
    resolvedSuccessfully: '\u062A\u0645 \u0627\u0644\u062D\u0644 \u0628\u0646\u062C\u0627\u062D.',
    resolvedUsingGuidance: '\u062A\u0645 \u0627\u0644\u062D\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 {lookupDomain} \u0643\u0645\u0631\u062C\u0639.',
    riskLabel: '\u0627\u0644\u0645\u062E\u0627\u0637\u0631',
    source: '\u0627\u0644\u0645\u0635\u062F\u0631',
    spfRecordBasics: '\u0623\u0633\u0627\u0633\u064A\u0627\u062A SPF',
    status: '\u0627\u0644\u062D\u0627\u0644\u0629',
    statusChecking: '\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 {domain} \u23F3',
    statusCollectedOn: '\u062A\u0645 \u0627\u0644\u062C\u0645\u0639 \u0641\u064A: {value}',
    statusLabel: '\u0627\u0644\u062D\u0627\u0644\u0629',
    statusSomeChecksFailed: '\u0641\u0634\u0644\u062A \u0628\u0639\u0636 \u0639\u0645\u0644\u064A\u0627\u062A \u0627\u0644\u062A\u062D\u0642\u0642 \u274C',
    statusTxtFailed: '\u0641\u0634\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 TXT \u274C \u2014 \u0642\u062F \u062A\u0638\u0644 \u0633\u062C\u0644\u0627\u062A DNS \u0627\u0644\u0623\u062E\u0631\u0649 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062D\u0644.',
    tools: '\u0627\u0644\u0623\u062F\u0648\u0627\u062A',
    totalQueries: '\u0625\u062C\u0645\u0627\u0644\u064A \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A',
    txtLookupFailedOrTimedOut: '\u0641\u0634\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 TXT \u0623\u0648 \u0627\u0646\u062A\u0647\u062A \u0645\u0647\u0644\u062A\u0647.',
    type: '\u0627\u0644\u0646\u0648\u0639',
    unableDetermineAcsTxtValue: '\u062A\u0639\u0630\u0631 \u062A\u062D\u062F\u064A\u062F \u0642\u064A\u0645\u0629 ACS TXT.',
    unknown: '\u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641',
    usingIpParent: '\u062C\u0627\u0631\u064D \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0639\u0646\u0627\u0648\u064A\u0646 IP \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644 {domain} (\u0644\u0627 \u062A\u0648\u062C\u062F \u0633\u062C\u0644\u0627\u062A A/AAAA \u0639\u0644\u0649 {queryDomain}).',
    verificationTag: '\u0627\u0644\u062A\u062D\u0642\u0642',
    verified: '\u062A\u0645 \u0627\u0644\u062A\u062D\u0642\u0642',
    view: '\u0639\u0631\u0636',
    waitingForBaseTxtLookup: '\u0641\u064A \u0627\u0646\u062A\u0638\u0627\u0631 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 TXT \u0627\u0644\u0623\u0633\u0627\u0633\u064A...',
    waitingForTxtLookup: '\u0641\u064A \u0627\u0646\u062A\u0638\u0627\u0631 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 TXT...',
    warningState: '\u062A\u062D\u0630\u064A\u0631',
    yes: '\u0646\u0639\u0645',
    zonesQueried: '\u0627\u0644\u0645\u0646\u0627\u0637\u0642 \u0627\u0644\u062A\u064A \u062A\u0645 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0639\u0646\u0647\u0627'
  },
  'zh-CN': {
    acsEmailDomainVerification: 'ACS \u7535\u5B50\u90AE\u4EF6\u57DF\u9A8C\u8BC1',
    acsEmailQuotaLimitIncrease: 'ACS \u7535\u5B50\u90AE\u4EF6\u914D\u989D\u9650\u5236\u63D0\u5347',
    additionalDetailsMinus: '\u66F4\u591A\u8BE6\u7EC6\u4FE1\u606F -',
    additionalDetailsPlus: '\u66F4\u591A\u8BE6\u7EC6\u4FE1\u606F +',
    addresses: '\u5730\u5740',
    authMicrosoftLabel: 'Microsoft',
    checkingDnsblReputation: '\u6B63\u5728\u68C0\u67E5 DNSBL \u4FE1\u8A89...',
    checkingMxRecords: '\u6B63\u5728\u68C0\u67E5 MX \u8BB0\u5F55...',
    checkingValue: '\u68C0\u67E5\u4E2D...',
    checklist: '\u68C0\u67E5\u6E05\u5355',
    cname: 'CNAME',
    copied: '\u5DF2\u590D\u5236\uFF01\u2714',
    copy: '\u590D\u5236',
    copyEmailQuota: '\u590D\u5236\u7535\u5B50\u90AE\u4EF6\u914D\u989D',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dkimRecordBasics: 'DKIM \u57FA\u7840\u77E5\u8BC6',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: '{domain} \u7684 DKIM \u5BF9\u9F50\u4F7F\u7528\u5BBD\u677E\u6A21\u5F0F (adkim=r)\u3002\u5982\u679C\u60A8\u7684\u53D1\u9001\u57FA\u7840\u7ED3\u6784\u652F\u6301\uFF0C\u4E3A\u4E86\u66F4\u4E25\u683C\u7684\u57DF\u4FDD\u62A4\uFF0C\u53EF\u8003\u8651\u4F7F\u7528\u4E25\u683C\u5BF9\u9F50 (adkim=s)\u3002',
    dmarcAspfRelaxed: '{domain} \u7684 SPF \u5BF9\u9F50\u4F7F\u7528\u5BBD\u677E\u6A21\u5F0F (aspf=r)\u3002\u5982\u679C\u60A8\u7684\u53D1\u4EF6\u65B9\u59CB\u7EC8\u4F7F\u7528\u5B8C\u5168\u76F8\u540C\u7684\u57DF\uFF0C\u53EF\u8003\u8651\u4F7F\u7528\u4E25\u683C\u5BF9\u9F50 (aspf=s)\u3002',
    dmarcMissingRua: '{domain} \u7684 DMARC \u672A\u53D1\u5E03\u805A\u5408\u62A5\u544A (rua=)\u3002\u6DFB\u52A0\u62A5\u544A\u90AE\u7BB1\u6709\u52A9\u4E8E\u63D0\u9AD8\u5BF9\u4F2A\u9020\u5C1D\u8BD5\u548C\u5B9E\u65BD\u5F71\u54CD\u7684\u53EF\u89C1\u6027\u3002',
    dmarcMissingRuf: '{domain} \u7684 DMARC \u672A\u53D1\u5E03\u53D6\u8BC1\u62A5\u544A (ruf=)\u3002\u5982\u679C\u60A8\u7684\u6D41\u7A0B\u5141\u8BB8\uFF0C\u8FD9\u4E9B\u62A5\u544A\u53EF\u4E3A\u8C03\u67E5\u63D0\u4F9B\u989D\u5916\u7684\u5931\u8D25\u7EC6\u8282\u3002',
    dmarcMissingSp: '{lookupDomain} \u7684\u5B50\u57DF DMARC \u672A\u5B9A\u4E49\u663E\u5F0F\u5B50\u57DF\u7B56\u7565 (sp=)\u3002\u5982\u679C\u60A8\u4ECE {domain} \u8FD9\u6837\u7684\u5B50\u57DF\u53D1\u9001\u90AE\u4EF6\uFF0C\u8BF7\u8003\u8651\u6DFB\u52A0 sp=quarantine \u6216 sp=reject \u4EE5\u83B7\u5F97\u66F4\u660E\u786E\u7684\u4FDD\u62A4\u3002',
    dmarcMonitorOnly: '{domain} \u7684 DMARC \u4EC5\u5904\u4E8E\u76D1\u89C6\u6A21\u5F0F (p=none)\u3002\u82E5\u8981\u83B7\u5F97\u66F4\u5F3A\u7684\u53CD\u4F2A\u9020\u4FDD\u62A4\uFF0C\u8BF7\u5728\u9A8C\u8BC1\u5408\u6CD5\u90AE\u4EF6\u6E90\u540E\u8FC1\u79FB\u5230 p=quarantine \u6216 p=reject\u3002',
    dmarcPct: '{domain} \u7684 DMARC \u4EC5\u5E94\u7528\u4E8E {pct}% \u7684\u90AE\u4EF6 (pct={pct})\u3002\u5728\u786E\u8BA4\u90E8\u7F72\u540E\uFF0C\u8BF7\u4F7F\u7528 pct=100 \u4EE5\u83B7\u5F97\u5B8C\u6574\u4FDD\u62A4\u3002',
    dmarcQuarantine: '{domain} \u7684 DMARC \u8BBE\u7F6E\u4E3A p=quarantine\u3002\u82E5\u8981\u83B7\u5F97\u6700\u5F3A\u7684\u53CD\u4F2A\u9020\u9632\u62A4\uFF0C\u5728\u786E\u8BA4\u5408\u6CD5\u90AE\u4EF6\u5DF2\u5B8C\u5168\u5BF9\u9F50\u540E\uFF0C\u53EF\u8003\u8651\u4F7F\u7528 p=reject\u3002',
    dmarcRecordBasics: 'DMARC \u57FA\u7840\u77E5\u8BC6',
    docs: '\u6587\u6863',
    domain: '\u57DF\u540D',
    domainDossier: '\u57DF\u540D\u6863\u6848 (CentralOps)',
    effectivePolicyInherited: '\u6709\u6548\u7B56\u7565\u7EE7\u627F\u81EA\u7236\u57DF {lookupDomain}\u3002',
    error: '\u9519\u8BEF',
    expired: '\u5DF2\u8FC7\u671F',
    footer: 'ACS Email Domain Checker v{version} \u2022 \u4F5C\u8005\uFF1A<a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> \u2022 \u7531 PowerShell \u751F\u6210 \u2022 <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">\u8FD4\u56DE\u9876\u90E8</a>',
    guidanceAcsMissing: '\u7F3A\u5C11 ACS ms-domain-verification TXT\u3002\u8BF7\u4ECE Azure \u95E8\u6237\u6DFB\u52A0\u8BE5\u503C\u3002',
    guidanceAcsMissingParent: '{domain} \u4E0A\u7F3A\u5C11 ACS ms-domain-verification TXT\u3002\u7236\u57DF {lookupDomain} \u5177\u6709 ACS TXT\uFF0C\u4F46\u5B83\u4E0D\u4F1A\u9A8C\u8BC1\u6240\u67E5\u8BE2\u7684\u5B50\u57DF\u3002',
    guidanceCnameMissing: '\u67E5\u8BE2\u7684\u4E3B\u673A\u4E0A\u672A\u914D\u7F6E CNAME\u3002\u8BF7\u786E\u8BA4\u8FD9\u662F\u5426\u7B26\u5408\u60A8\u7684\u573A\u666F\u9884\u671F\u3002',
    guidanceDkim1Missing: '\u7F3A\u5C11 DKIM selector1 (selector1-azurecomm-prod-net)\u3002',
    guidanceDkim2Missing: '\u7F3A\u5C11 DKIM selector2 (selector2-azurecomm-prod-net)\u3002',
    guidanceDmarcInherited: '\u6709\u6548 DMARC \u7B56\u7565\u7EE7\u627F\u81EA\u7236\u57DF {lookupDomain}\u3002',
    guidanceDmarcMissing: '\u7F3A\u5C11 DMARC\u3002\u8BF7\u6DFB\u52A0 _dmarc.{domain} TXT \u8BB0\u5F55\u4EE5\u964D\u4F4E\u4F2A\u9020\u98CE\u9669\u3002',
    guidanceDmarcMoreInfo: '\u6709\u5173 DMARC TXT \u8BB0\u5F55\u8BED\u6CD5\u7684\u8BE6\u7EC6\u4FE1\u606F\uFF0C\u8BF7\u53C2\u9605\uFF1A{url}',
    guidanceDnsTxtFailed: 'DNS TXT \u67E5\u8BE2\u5931\u8D25\u6216\u8D85\u65F6\u3002\u5176\u4ED6 DNS \u8BB0\u5F55\u4ECD\u53EF\u80FD\u53EF\u4EE5\u89E3\u6790\u3002',
    guidanceMxGoogleSpf: '\u60A8\u7684 MX \u6307\u5411 Google Workspace\uFF0C\u4F46 SPF \u4E0D\u5305\u542B _spf.google.com\u3002\u8BF7\u9A8C\u8BC1 SPF \u662F\u5426\u5305\u542B\u6B63\u786E\u7684\u63D0\u4F9B\u5546 include\u3002',
    guidanceMxMicrosoftSpf: '\u60A8\u7684 MX \u6307\u5411 Microsoft 365\uFF0C\u4F46 SPF \u4E0D\u5305\u542B spf.protection.outlook.com\u3002\u8BF7\u9A8C\u8BC1 SPF \u662F\u5426\u5305\u542B\u6B63\u786E\u7684\u63D0\u4F9B\u5546 include\u3002',
    guidanceMxMissing: '\u672A\u68C0\u6D4B\u5230 MX \u8BB0\u5F55\u3002\u5728\u914D\u7F6E MX \u8BB0\u5F55\u4E4B\u524D\uFF0C\u90AE\u4EF6\u6D41\u5C06\u65E0\u6CD5\u6B63\u5E38\u5DE5\u4F5C\u3002',
    guidanceMxMissingCheckedParent: '\u672A\u68C0\u6D4B\u5230 {domain} \u6216\u5176\u7236\u57DF {parentDomain} \u7684 MX \u8BB0\u5F55\u3002\u5728\u914D\u7F6E MX \u8BB0\u5F55\u4E4B\u524D\uFF0C\u90AE\u4EF6\u6D41\u5C06\u65E0\u6CD5\u6B63\u5E38\u5DE5\u4F5C\u3002',
    guidanceMxMissingParentFallback: '{domain} \u4E0A\u672A\u627E\u5230 MX \u8BB0\u5F55\uFF1B\u6B63\u5728\u4F7F\u7528\u7236\u57DF {lookupDomain} \u7684 MX \u8BB0\u5F55\u4F5C\u4E3A\u56DE\u9000\u3002',
    guidanceMxParentShown: '{domain} \u4E0A\u672A\u627E\u5230 MX \u8BB0\u5F55\uFF1B\u663E\u793A\u7684\u7ED3\u679C\u6765\u81EA\u7236\u57DF {lookupDomain}\u3002',
    guidanceMxZohoSpf: '\u60A8\u7684 MX \u6307\u5411 Zoho\uFF0C\u4F46 SPF \u4E0D\u5305\u542B include:zoho.com\u3002\u8BF7\u9A8C\u8BC1 SPF \u662F\u5426\u5305\u542B\u6B63\u786E\u7684\u63D0\u4F9B\u5546 include\u3002',
    guidanceSpfMissing: '\u7F3A\u5C11 SPF\u3002\u8BF7\u6DFB\u52A0 v=spf1 include:spf.protection.outlook.com -all\uFF08\u6216\u60A8\u63D0\u4F9B\u5546\u7684\u7B49\u6548\u503C\uFF09\u3002',
    guidanceSpfMissingParent: '{domain} \u4E0A\u7F3A\u5C11 SPF\u3002\u7236\u57DF {lookupDomain} \u53D1\u5E03\u4E86 SPF\uFF0C\u4F46 SPF \u4E0D\u4F1A\u81EA\u52A8\u5E94\u7528\u5230\u67E5\u8BE2\u7684\u5B50\u57DF\u3002',
    hostname: '\u4E3B\u673A\u540D',
    info: '\u4FE1\u606F',
    ipAddress: 'IP \u5730\u5740',
    ipv4: 'IPv4',
    ipv4Addresses: 'IPv4 \u5730\u5740',
    ipv6: 'IPv6',
    ipv6Addresses: 'IPv6 \u5730\u5740',
    listingsLabel: '\u5217\u5165\u60C5\u51B5',
    loadingValue: '\u52A0\u8F7D\u4E2D...',
    missingRequiredAcsTxt: '\u7F3A\u5C11\u6240\u9700\u7684 ACS TXT\u3002',
    multiRblLookup: 'MultiRBL DNSBL \u67E5\u8BE2',
    mxRecordBasics: 'MX \u57FA\u7840\u77E5\u8BC6',
    newDomainUnderDays: '\u65B0\u57DF\u540D\uFF08\u5C11\u4E8E {days} \u5929\uFF09{suffix}',
    noAdditionalGuidance: '\u65E0\u5176\u4ED6\u6307\u5BFC\u3002',
    noAdditionalMxDetails: '\u6CA1\u6709\u5176\u4ED6 MX \u8BE6\u7EC6\u4FE1\u606F\u3002',
    noIpAddressesFound: '\u672A\u627E\u5230 IP \u5730\u5740',
    noMxParentChecked: '\u5DF2\u68C0\u67E5\u7236\u57DF {parentDomain}\uFF08\u65E0 MX\uFF09\u3002',
    noMxParentShowing: '{domain} \u4E0A\u672A\u627E\u5230 MX \u8BB0\u5F55\uFF1B\u6B63\u5728\u663E\u793A\u7236\u57DF {lookupDomain} \u7684 MX\u3002',
    noMxRecordsDetected: '\u672A\u68C0\u6D4B\u5230 MX \u8BB0\u5F55\u3002',
    noRecordsAvailable: '\u6CA1\u6709\u53EF\u7528\u8BB0\u5F55\u3002',
    noSpfRecordDetected: '\u672A\u68C0\u6D4B\u5230 SPF \u8BB0\u5F55\u3002',
    noSuccessfulQueries: '\u672A\u77E5\uFF08\u65E0\u6210\u529F\u67E5\u8BE2\uFF09',
    notStarted: '\u672A\u5F00\u59CB',
    notVerified: '\u672A\u9A8C\u8BC1',
    noteDomainLessThanDays: '\u57DF\u540D\u5E74\u9F84\u5C11\u4E8E {days} \u5929\u3002',
    pending: '\u7B49\u5F85\u4E2D',
    rawWhoisLabel: 'whois',
    readinessTips: '\u5C31\u7EEA\u5EFA\u8BAE',
    reputationDnsbl: '\u4FE1\u8A89 (DNSBL)',
    resolvedUsingGuidance: '\u4F7F\u7528 {lookupDomain} \u8FDB\u884C\u53C2\u8003\u89E3\u6790\u3002',
    spfRecordBasics: 'SPF \u57FA\u7840\u77E5\u8BC6',
    status: '\u72B6\u6001',
    statusChecking: '\u6B63\u5728\u68C0\u67E5 {domain} \u23F3',
    statusCollectedOn: '\u6536\u96C6\u65F6\u95F4\uFF1A{value}',
    statusLabel: '\u72B6\u6001',
    statusSomeChecksFailed: '\u90E8\u5206\u68C0\u67E5\u5931\u8D25 \u274C',
    statusTxtFailed: 'TXT \u67E5\u8BE2\u5931\u8D25 \u274C \u2014 \u5176\u4ED6 DNS \u8BB0\u5F55\u4ECD\u53EF\u80FD\u53EF\u4EE5\u89E3\u6790\u3002',
    tools: '\u5DE5\u5177',
    txtLookupFailedOrTimedOut: 'TXT \u67E5\u8BE2\u5931\u8D25\u6216\u8D85\u65F6\u3002',
    type: '\u7C7B\u578B',
    unableDetermineAcsTxtValue: '\u65E0\u6CD5\u786E\u5B9A ACS TXT \u503C\u3002',
    unknown: '\u672A\u77E5',
    usingIpParent: '\u6B63\u5728\u4F7F\u7528\u7236\u57DF {domain} \u7684 IP \u5730\u5740\uFF08{queryDomain} \u4E0A\u6CA1\u6709 A/AAAA\uFF09\u3002',
    verificationTag: '\u9A8C\u8BC1',
    verified: '\u5DF2\u9A8C\u8BC1',
    view: '\u67E5\u770B',
    waitingForBaseTxtLookup: '\u6B63\u5728\u7B49\u5F85\u57FA\u7840 TXT \u67E5\u8BE2...',
    waitingForTxtLookup: '\u6B63\u5728\u7B49\u5F85 TXT \u67E5\u8BE2...'
  },
  'hi-IN': {
    acsEmailDomainVerification: 'ACS \u0908\u092E\u0947\u0932 \u0921\u094B\u092E\u0947\u0928 \u0938\u0924\u094D\u092F\u093E\u092A\u0928',
    acsEmailQuotaLimitIncrease: 'ACS \u0908\u092E\u0947\u0932 \u0915\u094B\u091F\u093E \u0938\u0940\u092E\u093E \u0935\u0943\u0926\u094D\u0927\u093F',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    additionalDetailsMinus: '\u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 \u0935\u093F\u0935\u0930\u0923 -',
    additionalDetailsPlus: '\u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 \u0935\u093F\u0935\u0930\u0923 +',
    addresses: '\u092A\u0924\u0947',
    authMicrosoftLabel: 'Microsoft',
    checkingDnsblReputation: 'DNSBL \u092A\u094D\u0930\u0924\u093F\u0937\u094D\u0920\u093E \u091C\u093E\u0901\u091A\u0940 \u091C\u093E \u0930\u0939\u0940 \u0939\u0948...',
    checkingMxRecords: 'MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u091C\u093E\u0901\u091A\u0947 \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902...',
    checkingValue: '\u091C\u093E\u0901\u091A \u0939\u094B \u0930\u0939\u0940 \u0939\u0948...',
    checklist: '\u091A\u0947\u0915\u0932\u093F\u0938\u094D\u091F',
    cname: 'CNAME',
    copied: '\u0915\u0949\u092A\u0940 \u0939\u094B \u0917\u092F\u093E! \u2714',
    copy: '\u0915\u0949\u092A\u0940 \u0915\u0930\u0947\u0902',
    copyEmailQuota: '\u0908\u092E\u0947\u0932 \u0915\u094B\u091F\u093E \u0915\u0949\u092A\u0940 \u0915\u0930\u0947\u0902',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dkimRecordBasics: 'DKIM \u0915\u0940 \u092E\u0942\u0932 \u092C\u093E\u0924\u0947\u0902',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: '{domain} \u0915\u0947 \u0932\u093F\u090F DKIM \u0938\u0902\u0930\u0947\u0916\u0923 relaxed mode (adkim=r) \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0924\u093E \u0939\u0948\u0964 \u092F\u0926\u093F \u0906\u092A\u0915\u0940 sending infrastructure \u0938\u092E\u0930\u094D\u0925\u0928 \u0915\u0930\u0924\u0940 \u0939\u0948, \u0924\u094B \u0905\u0927\u093F\u0915 \u0915\u0921\u093C\u0947 \u0921\u094B\u092E\u0947\u0928 \u0938\u0941\u0930\u0915\u094D\u0937\u093E \u0915\u0947 \u0932\u093F\u090F strict alignment (adkim=s) \u092A\u0930 \u0935\u093F\u091A\u093E\u0930 \u0915\u0930\u0947\u0902\u0964',
    dmarcAspfRelaxed: '{domain} \u0915\u0947 \u0932\u093F\u090F SPF \u0938\u0902\u0930\u0947\u0916\u0923 relaxed mode (aspf=r) \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0924\u093E \u0939\u0948\u0964 \u092F\u0926\u093F \u0906\u092A\u0915\u0947 \u092A\u094D\u0930\u0947\u0937\u0915 \u0932\u0917\u093E\u0924\u093E\u0930 \u0938\u091F\u0940\u0915 \u0921\u094B\u092E\u0947\u0928 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0924\u0947 \u0939\u0948\u0902, \u0924\u094B strict alignment (aspf=s) \u092A\u0930 \u0935\u093F\u091A\u093E\u0930 \u0915\u0930\u0947\u0902\u0964',
    dmarcMissingRua: '{domain} \u0915\u0947 \u0932\u093F\u090F DMARC aggregate reporting (rua=) \u092A\u094D\u0930\u0915\u093E\u0936\u093F\u0924 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964 \u090F\u0915 reporting mailbox \u091C\u094B\u0921\u093C\u0928\u0947 \u0938\u0947 spoofing \u092A\u094D\u0930\u092F\u093E\u0938\u094B\u0902 \u0914\u0930 enforcement \u092A\u094D\u0930\u092D\u093E\u0935 \u0915\u0940 \u0926\u0943\u0936\u094D\u092F\u0924\u093E \u092C\u0922\u093C\u0924\u0940 \u0939\u0948\u0964',
    dmarcMissingRuf: '{domain} \u0915\u0947 \u0932\u093F\u090F DMARC forensic reporting (ruf=) \u092A\u094D\u0930\u0915\u093E\u0936\u093F\u0924 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964 \u092F\u0926\u093F \u0906\u092A\u0915\u0940 \u092A\u094D\u0930\u0915\u094D\u0930\u093F\u092F\u093E \u0905\u0928\u0941\u092E\u0924\u093F \u0926\u0947\u0924\u0940 \u0939\u0948, \u0924\u094B forensic reports \u091C\u093E\u0902\u091A \u0915\u0947 \u0932\u093F\u090F \u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 \u0935\u093F\u092B\u0932\u0924\u093E \u0935\u093F\u0935\u0930\u0923 \u0926\u0947 \u0938\u0915\u0924\u0940 \u0939\u0948\u0902\u0964',
    dmarcMissingSp: '{lookupDomain} \u0915\u0947 \u0909\u092A\u0921\u094B\u092E\u0947\u0928\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F DMARC \u0938\u094D\u092A\u0937\u094D\u091F subdomain policy (sp=) \u092A\u0930\u093F\u092D\u093E\u0937\u093F\u0924 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964 \u092F\u0926\u093F \u0906\u092A {domain} \u091C\u0948\u0938\u0947 \u0909\u092A\u0921\u094B\u092E\u0947\u0928\u094B\u0902 \u0938\u0947 \u092D\u0947\u091C\u0924\u0947 \u0939\u0948\u0902, \u0924\u094B \u0905\u0927\u093F\u0915 \u0938\u094D\u092A\u0937\u094D\u091F \u0938\u0941\u0930\u0915\u094D\u0937\u093E \u0915\u0947 \u0932\u093F\u090F sp=quarantine \u092F\u093E sp=reject \u091C\u094B\u0921\u093C\u0928\u0947 \u092A\u0930 \u0935\u093F\u091A\u093E\u0930 \u0915\u0930\u0947\u0902\u0964',
    dmarcMonitorOnly: '{domain} \u0915\u0947 \u0932\u093F\u090F DMARC monitor-only (p=none) \u0939\u0948\u0964 spoofing \u0915\u0947 \u0935\u093F\u0930\u0941\u0926\u094D\u0927 \u0905\u0927\u093F\u0915 \u092E\u091C\u092C\u0942\u0924 \u0938\u0941\u0930\u0915\u094D\u0937\u093E \u0915\u0947 \u0932\u093F\u090F, \u0935\u0948\u0927 \u092E\u0947\u0932 \u0938\u094D\u0930\u094B\u0924\u094B\u0902 \u0915\u094B \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0915\u0930\u0928\u0947 \u0915\u0947 \u092C\u093E\u0926 p=quarantine \u092F\u093E p=reject \u092A\u0930 \u091C\u093E\u090F\u0901\u0964',
    dmarcPct: '{domain} \u0915\u0947 \u0932\u093F\u090F DMARC enforcement \u0915\u0947\u0935\u0932 {pct}% \u0938\u0902\u0926\u0947\u0936\u094B\u0902 \u092A\u0930 \u0932\u093E\u0917\u0942 \u0939\u0948 (pct={pct})\u0964 rollout \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0939\u094B\u0928\u0947 \u0915\u0947 \u092C\u093E\u0926 \u092A\u0942\u0930\u094D\u0923 \u0938\u0941\u0930\u0915\u094D\u0937\u093E \u0915\u0947 \u0932\u093F\u090F pct=100 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0947\u0902\u0964',
    dmarcQuarantine: '{domain} \u0915\u0947 \u0932\u093F\u090F DMARC p=quarantine \u092A\u0930 \u0938\u0947\u091F \u0939\u0948\u0964 spoofing \u0915\u0947 \u0935\u093F\u0930\u0941\u0926\u094D\u0927 \u0938\u092C\u0938\u0947 \u092E\u091C\u092C\u0942\u0924 \u0938\u0941\u0930\u0915\u094D\u0937\u093E \u0915\u0947 \u0932\u093F\u090F, \u0935\u0948\u0927 \u092E\u0947\u0932 \u0915\u0947 \u092A\u0942\u0930\u0940 \u0924\u0930\u0939 aligned \u0939\u094B\u0928\u0947 \u0915\u0940 \u092A\u0941\u0937\u094D\u091F\u093F \u0915\u0947 \u092C\u093E\u0926 p=reject \u092A\u0930 \u0935\u093F\u091A\u093E\u0930 \u0915\u0930\u0947\u0902\u0964',
    dmarcRecordBasics: 'DMARC \u0915\u0940 \u092E\u0942\u0932 \u092C\u093E\u0924\u0947\u0902',
    docs: '\u0926\u0938\u094D\u0924\u093E\u0935\u0947\u091C\u093C',
    domain: '\u0921\u094B\u092E\u0947\u0928',
    domainDossier: '\u0921\u094B\u092E\u0947\u0928 \u0921\u0949\u0938\u093F\u092F\u0930 (CentralOps)',
    effectivePolicyInherited: '\u092A\u094D\u0930\u092D\u093E\u0935\u0940 \u0928\u0940\u0924\u093F \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0938\u0947 \u0935\u093F\u0930\u093E\u0938\u0924 \u092E\u0947\u0902 \u092E\u093F\u0932\u0940 \u0939\u0948\u0964',
    error: '\u0924\u094D\u0930\u0941\u091F\u093F',
    expired: '\u0938\u092E\u093E\u092A\u094D\u0924',
    guidanceAcsMissing: 'ACS ms-domain-verification TXT \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964 Azure portal \u0938\u0947 \u092E\u093E\u0928 \u091C\u094B\u0921\u093C\u0947\u0902\u0964',
    guidanceAcsMissingParent: '{domain} \u092A\u0930 ACS ms-domain-verification TXT \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964 \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u092A\u0930 ACS TXT \u0939\u0948, \u0932\u0947\u0915\u093F\u0928 \u092F\u0939 \u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u090F \u0917\u090F \u0909\u092A\u0921\u094B\u092E\u0947\u0928 \u0915\u094B \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964',
    guidanceCnameMissing: '\u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u090F \u0917\u090F \u0939\u094B\u0938\u094D\u091F \u092A\u0930 CNAME \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0915\u0930\u0947\u0902 \u0915\u093F \u092F\u0939 \u0906\u092A\u0915\u0947 \u092A\u0930\u093F\u0926\u0943\u0936\u094D\u092F \u0915\u0947 \u0932\u093F\u090F \u0905\u092A\u0947\u0915\u094D\u0937\u093F\u0924 \u0939\u0948\u0964',
    guidanceDkim1Missing: 'DKIM selector1 (selector1-azurecomm-prod-net) \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964',
    guidanceDkim2Missing: 'DKIM selector2 (selector2-azurecomm-prod-net) \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964',
    guidanceDmarcInherited: '\u092A\u094D\u0930\u092D\u093E\u0935\u0940 DMARC \u0928\u0940\u0924\u093F \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0938\u0947 \u0935\u093F\u0930\u093E\u0938\u0924 \u092E\u0947\u0902 \u092E\u093F\u0932\u0940 \u0939\u0948\u0964',
    guidanceDmarcMissing: 'DMARC \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964 spoofing \u091C\u094B\u0916\u093F\u092E \u0915\u092E \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F _dmarc.{domain} TXT \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u091C\u094B\u0921\u093C\u0947\u0902\u0964',
    guidanceDmarcMoreInfo: 'DMARC TXT \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0938\u093F\u0902\u091F\u0948\u0915\u094D\u0938 \u0915\u0947 \u092C\u093E\u0930\u0947 \u092E\u0947\u0902 \u0905\u0927\u093F\u0915 \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u0915\u0947 \u0932\u093F\u090F \u0926\u0947\u0916\u0947\u0902: {url}',
    guidanceDnsTxtFailed: 'DNS TXT \u0932\u0941\u0915\u0905\u092A \u0935\u093F\u092B\u0932 \u0939\u0941\u0906 \u092F\u093E \u0938\u092E\u092F \u0938\u092E\u093E\u092A\u094D\u0924 \u0939\u094B \u0917\u092F\u093E\u0964 \u0905\u0928\u094D\u092F DNS \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0905\u092D\u0940 \u092D\u0940 resolve \u0939\u094B \u0938\u0915\u0924\u0947 \u0939\u0948\u0902\u0964',
    guidanceMxGoogleSpf: '\u0906\u092A\u0915\u093E MX Google Workspace \u0926\u0930\u094D\u0936\u093E\u0924\u093E \u0939\u0948, \u0932\u0947\u0915\u093F\u0928 SPF \u092E\u0947\u0902 _spf.google.com \u0936\u093E\u092E\u093F\u0932 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0915\u0930\u0947\u0902 \u0915\u093F SPF \u092E\u0947\u0902 \u0938\u0939\u0940 provider include \u0939\u0948\u0964',
    guidanceMxMicrosoftSpf: '\u0906\u092A\u0915\u093E MX Microsoft 365 \u0926\u0930\u094D\u0936\u093E\u0924\u093E \u0939\u0948, \u0932\u0947\u0915\u093F\u0928 SPF \u092E\u0947\u0902 spf.protection.outlook.com \u0936\u093E\u092E\u093F\u0932 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0915\u0930\u0947\u0902 \u0915\u093F SPF \u092E\u0947\u0902 \u0938\u0939\u0940 provider include \u0939\u0948\u0964',
    guidanceMxMissing: '\u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964 \u091C\u092C \u0924\u0915 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u094B\u0924\u0947, \u092E\u0947\u0932 \u092A\u094D\u0930\u0935\u093E\u0939 \u0915\u093E\u092E \u0928\u0939\u0940\u0902 \u0915\u0930\u0947\u0917\u093E\u0964',
    guidanceMxMissingCheckedParent: '{domain} \u092F\u093E \u0909\u0938\u0915\u0947 \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {parentDomain} \u0915\u0947 \u0932\u093F\u090F \u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964 \u091C\u092C \u0924\u0915 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0915\u0949\u0928\u094D\u092B\u093C\u093F\u0917\u0930 \u0928\u0939\u0940\u0902 \u0939\u094B\u0924\u0947, \u092E\u0947\u0932 \u092A\u094D\u0930\u0935\u093E\u0939 \u0915\u093E\u092E \u0928\u0939\u0940\u0902 \u0915\u0930\u0947\u0917\u093E\u0964',
    guidanceMxMissingParentFallback: '{domain} \u092A\u0930 \u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E; \u092C\u0948\u0915\u0905\u092A \u0915\u0947 \u0930\u0942\u092A \u092E\u0947\u0902 \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0915\u0947 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0909\u092A\u092F\u094B\u0917 \u0915\u093F\u090F \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902\u0964',
    guidanceMxParentShown: '{domain} \u092A\u0930 \u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E; \u0926\u093F\u0916\u093E\u090F \u0917\u090F \u092A\u0930\u093F\u0923\u093E\u092E \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0938\u0947 \u0939\u0948\u0902\u0964',
    guidanceMxZohoSpf: '\u0906\u092A\u0915\u093E MX Zoho \u0926\u0930\u094D\u0936\u093E\u0924\u093E \u0939\u0948, \u0932\u0947\u0915\u093F\u0928 SPF \u092E\u0947\u0902 include:zoho.com \u0936\u093E\u092E\u093F\u0932 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 \u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0915\u0930\u0947\u0902 \u0915\u093F SPF \u092E\u0947\u0902 \u0938\u0939\u0940 provider include \u0939\u0948\u0964',
    guidanceSpfMissing: 'SPF \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964 v=spf1 include:spf.protection.outlook.com -all \u091C\u094B\u0921\u093C\u0947\u0902 (\u092F\u093E \u0905\u092A\u0928\u0947 provider \u0915\u0947 \u0938\u092E\u0915\u0915\u094D\u0937)\u0964',
    guidanceSpfMissingParent: '{domain} \u092A\u0930 SPF \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964 \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} SPF \u092A\u094D\u0930\u0915\u093E\u0936\u093F\u0924 \u0915\u0930\u0924\u093E \u0939\u0948, \u0932\u0947\u0915\u093F\u0928 SPF \u0938\u094D\u0935\u091A\u093E\u0932\u093F\u0924 \u0930\u0942\u092A \u0938\u0947 \u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u093F\u090F \u0917\u090F \u0909\u092A\u0921\u094B\u092E\u0947\u0928 \u092A\u0930 \u0932\u093E\u0917\u0942 \u0928\u0939\u0940\u0902 \u0939\u094B\u0924\u093E\u0964',
    hostname: '\u0939\u094B\u0938\u094D\u091F\u0928\u093E\u092E',
    info: '\u091C\u093E\u0928\u0915\u093E\u0930\u0940',
    ipAddress: 'IP \u092A\u0924\u093E',
    ipv4: 'IPv4',
    ipv4Addresses: 'IPv4 \u092A\u0924\u0947',
    ipv6: 'IPv6',
    ipv6Addresses: 'IPv6 \u092A\u0924\u0947',
    listingsLabel: '\u0938\u0942\u091A\u093F\u092F\u093E\u0901',
    loadingValue: '\u0932\u094B\u0921 \u0939\u094B \u0930\u0939\u093E \u0939\u0948...',
    missingRequiredAcsTxt: '\u0906\u0935\u0936\u094D\u092F\u0915 ACS TXT \u0905\u0928\u0941\u092A\u0938\u094D\u0925\u093F\u0924 \u0939\u0948\u0964',
    multiRblLookup: 'MultiRBL DNSBL \u0932\u0941\u0915\u0905\u092A',
    mxRecordBasics: 'MX \u0915\u0940 \u092E\u0942\u0932 \u092C\u093E\u0924\u0947\u0902',
    newDomainUnderDays: '\u0928\u092F\u093E \u0921\u094B\u092E\u0947\u0928 ({days} \u0926\u093F\u0928\u094B\u0902 \u0938\u0947 \u0915\u092E){suffix}',
    noAdditionalGuidance: '\u0915\u094B\u0908 \u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 \u092E\u093E\u0930\u094D\u0917\u0926\u0930\u094D\u0936\u0928 \u0928\u0939\u0940\u0902\u0964',
    noAdditionalMxDetails: '\u0915\u094B\u0908 \u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 MX \u0935\u093F\u0935\u0930\u0923 \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964',
    noIpAddressesFound: '\u0915\u094B\u0908 IP \u092A\u0924\u093E \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E',
    noMxParentChecked: '\u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {parentDomain} \u091C\u093E\u0901\u091A\u093E \u0917\u092F\u093E (\u0915\u094B\u0908 MX \u0928\u0939\u0940\u0902)\u0964',
    noMxParentShowing: '{domain} \u092A\u0930 \u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E; \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {lookupDomain} \u0915\u0947 MX \u0926\u093F\u0916\u093E\u090F \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902\u0964',
    noMxRecordsDetected: '\u0915\u094B\u0908 MX \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964',
    noRecordsAvailable: '\u0915\u094B\u0908 \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0909\u092A\u0932\u092C\u094D\u0927 \u0928\u0939\u0940\u0902\u0964',
    noSpfRecordDetected: '\u0915\u094B\u0908 SPF \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964',
    noSuccessfulQueries: '\u0905\u091C\u094D\u091E\u093E\u0924 (\u0915\u094B\u0908 \u0938\u092B\u0932 \u0915\u094D\u0935\u0947\u0930\u0940 \u0928\u0939\u0940\u0902)',
    notStarted: '\u0936\u0941\u0930\u0942 \u0928\u0939\u0940\u0902 \u0939\u0941\u0906',
    notVerified: '\u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924 \u0928\u0939\u0940\u0902',
    noteDomainLessThanDays: '\u0921\u094B\u092E\u0947\u0928 {days} \u0926\u093F\u0928\u094B\u0902 \u0938\u0947 \u0915\u092E \u092A\u0941\u0930\u093E\u0928\u093E \u0939\u0948\u0964',
    pending: '\u0932\u0902\u092C\u093F\u0924',
    rawWhoisLabel: 'whois',
    readinessTips: '\u0924\u0924\u094D\u092A\u0930\u0924\u093E \u0938\u0941\u091D\u093E\u0935',
    reputationDnsbl: '\u092A\u094D\u0930\u0924\u093F\u0937\u094D\u0920\u093E (DNSBL)',
    resolvedUsingGuidance: '{lookupDomain} \u0915\u094B \u092E\u093E\u0930\u094D\u0917\u0926\u0930\u094D\u0936\u0928 \u0915\u0947 \u0932\u093F\u090F \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0915\u0947 resolve \u0915\u093F\u092F\u093E \u0917\u092F\u093E\u0964',
    spfRecordBasics: 'SPF \u0915\u0940 \u092E\u0942\u0932 \u092C\u093E\u0924\u0947\u0902',
    status: '\u0938\u094D\u0925\u093F\u0924\u093F',
    statusChecking: '{domain} \u091C\u093E\u0901\u091A\u093E \u091C\u093E \u0930\u0939\u093E \u0939\u0948 \u23F3',
    statusCollectedOn: '\u0938\u0902\u0917\u094D\u0930\u0939\u093F\u0924 \u0938\u092E\u092F: {value}',
    statusLabel: '\u0938\u094D\u0925\u093F\u0924\u093F',
    statusSomeChecksFailed: '\u0915\u0941\u091B \u091C\u093E\u0901\u091A\u0947\u0902 \u0935\u093F\u092B\u0932 \u0939\u0941\u0908\u0902 \u274C',
    statusTxtFailed: 'TXT \u0932\u0941\u0915\u0905\u092A \u0935\u093F\u092B\u0932 \u0939\u0941\u0906 \u274C \u2014 \u0905\u0928\u094D\u092F DNS \u0930\u093F\u0915\u0949\u0930\u094D\u0921 \u0905\u092D\u0940 \u092D\u0940 resolve \u0939\u094B \u0938\u0915\u0924\u0947 \u0939\u0948\u0902\u0964',
    tools: '\u0909\u092A\u0915\u0930\u0923',
    txtLookupFailedOrTimedOut: 'TXT \u0932\u0941\u0915\u0905\u092A \u0935\u093F\u092B\u0932 \u0939\u0941\u0906 \u092F\u093E \u0938\u092E\u092F \u0938\u092E\u093E\u092A\u094D\u0924 \u0939\u094B \u0917\u092F\u093E\u0964',
    type: '\u092A\u094D\u0930\u0915\u093E\u0930',
    unableDetermineAcsTxtValue: 'ACS TXT \u092E\u093E\u0928 \u0928\u093F\u0930\u094D\u0927\u093E\u0930\u093F\u0924 \u0928\u0939\u0940\u0902 \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u093E\u0964',
    unknown: '\u0905\u091C\u094D\u091E\u093E\u0924',
    usingIpParent: '\u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 {domain} \u0915\u0947 IP \u092A\u0924\u0947 \u0909\u092A\u092F\u094B\u0917 \u0915\u093F\u090F \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902 ({queryDomain} \u092A\u0930 A/AAAA \u0928\u0939\u0940\u0902 \u0939\u0948)\u0964',
    verificationTag: '\u0938\u0924\u094D\u092F\u093E\u092A\u0928',
    verified: '\u0938\u0924\u094D\u092F\u093E\u092A\u093F\u0924',
    view: '\u0926\u0947\u0916\u0947\u0902',
    waitingForBaseTxtLookup: '\u092E\u0942\u0932 TXT \u0932\u0941\u0915\u0905\u092A \u0915\u0940 \u092A\u094D\u0930\u0924\u0940\u0915\u094D\u0937\u093E \u0915\u0940 \u091C\u093E \u0930\u0939\u0940 \u0939\u0948...',
    waitingForTxtLookup: 'TXT \u0932\u0941\u0915\u0905\u092A \u0915\u0940 \u092A\u094D\u0930\u0924\u0940\u0915\u094D\u0937\u093E \u0915\u0940 \u091C\u093E \u0930\u0939\u0940 \u0939\u0948...'
  },
  'ja-JP': {
    acsEmailDomainVerification: 'ACS \u30E1\u30FC\u30EB \u30C9\u30E1\u30A4\u30F3\u691C\u8A3C',
    acsEmailQuotaLimitIncrease: 'ACS \u30E1\u30FC\u30EB \u30AF\u30A9\u30FC\u30BF\u4E0A\u9650\u306E\u5F15\u304D\u4E0A\u3052',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    additionalDetailsMinus: '\u8FFD\u52A0\u306E\u8A73\u7D30 -',
    additionalDetailsPlus: '\u8FFD\u52A0\u306E\u8A73\u7D30 +',
    addresses: '\u30A2\u30C9\u30EC\u30B9',
    authMicrosoftLabel: 'Microsoft',
    checkingDnsblReputation: 'DNSBL \u8A55\u4FA1\u3092\u78BA\u8A8D\u3057\u3066\u3044\u307E\u3059...',
    checkingMxRecords: 'MX \u30EC\u30B3\u30FC\u30C9\u3092\u78BA\u8A8D\u3057\u3066\u3044\u307E\u3059...',
    checkingValue: '\u78BA\u8A8D\u4E2D...',
    checklist: '\u30C1\u30A7\u30C3\u30AF\u30EA\u30B9\u30C8',
    cname: 'CNAME',
    copied: '\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F\uFF01\u2714',
    copy: '\u30B3\u30D4\u30FC',
    copyEmailQuota: '\u30E1\u30FC\u30EB \u30AF\u30A9\u30FC\u30BF\u3092\u30B3\u30D4\u30FC',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dkimRecordBasics: 'DKIM \u306E\u57FA\u790E',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: '{domain} \u306E DKIM \u30A2\u30E9\u30A4\u30F3\u30E1\u30F3\u30C8\u306F\u7DE9\u548C\u30E2\u30FC\u30C9 (adkim=r) \u3092\u4F7F\u7528\u3057\u3066\u3044\u307E\u3059\u3002\u9001\u4FE1\u30A4\u30F3\u30D5\u30E9\u304C\u5BFE\u5FDC\u3057\u3066\u3044\u308B\u5834\u5408\u306F\u3001\u3088\u308A\u53B3\u5BC6\u306A\u30C9\u30E1\u30A4\u30F3\u4FDD\u8B77\u306E\u305F\u3081 strict alignment (adkim=s) \u3092\u691C\u8A0E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcAspfRelaxed: '{domain} \u306E SPF \u30A2\u30E9\u30A4\u30F3\u30E1\u30F3\u30C8\u306F\u7DE9\u548C\u30E2\u30FC\u30C9 (aspf=r) \u3092\u4F7F\u7528\u3057\u3066\u3044\u307E\u3059\u3002\u9001\u4FE1\u5143\u304C\u5E38\u306B\u6B63\u78BA\u306A\u30C9\u30E1\u30A4\u30F3\u3092\u4F7F\u7528\u3059\u308B\u5834\u5408\u306F\u3001strict alignment (aspf=s) \u3092\u691C\u8A0E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcMissingRua: '{domain} \u306E DMARC \u306F\u96C6\u8A08\u30EC\u30DD\u30FC\u30C8 (rua=) \u3092\u516C\u958B\u3057\u3066\u3044\u307E\u305B\u3093\u3002\u30EC\u30DD\u30FC\u30C8\u7528\u30E1\u30FC\u30EB\u30DC\u30C3\u30AF\u30B9\u3092\u8FFD\u52A0\u3059\u308B\u3068\u3001\u306A\u308A\u3059\u307E\u3057\u8A66\u884C\u3084\u9069\u7528\u72B6\u6CC1\u306E\u53EF\u8996\u6027\u304C\u5411\u4E0A\u3057\u307E\u3059\u3002',
    dmarcMissingRuf: '{domain} \u306E DMARC \u306F\u30D5\u30A9\u30EC\u30F3\u30B8\u30C3\u30AF \u30EC\u30DD\u30FC\u30C8 (ruf=) \u3092\u516C\u958B\u3057\u3066\u3044\u307E\u305B\u3093\u3002\u30D7\u30ED\u30BB\u30B9\u4E0A\u554F\u984C\u304C\u306A\u3051\u308C\u3070\u3001\u8ABF\u67FB\u306E\u305F\u3081\u306E\u8FFD\u52A0\u306E\u5931\u6557\u8A73\u7D30\u3092\u5F97\u3089\u308C\u308B\u53EF\u80FD\u6027\u304C\u3042\u308A\u307E\u3059\u3002',
    dmarcMissingSp: '{lookupDomain} \u306E\u30B5\u30D6\u30C9\u30E1\u30A4\u30F3\u5411\u3051 DMARC \u306B\u306F\u660E\u793A\u7684\u306A\u30B5\u30D6\u30C9\u30E1\u30A4\u30F3 \u30DD\u30EA\u30B7\u30FC (sp=) \u304C\u5B9A\u7FA9\u3055\u308C\u3066\u3044\u307E\u305B\u3093\u3002{domain} \u306E\u3088\u3046\u306A\u30B5\u30D6\u30C9\u30E1\u30A4\u30F3\u304B\u3089\u9001\u4FE1\u3059\u308B\u5834\u5408\u306F\u3001\u3088\u308A\u660E\u78BA\u306A\u4FDD\u8B77\u306E\u305F\u3081\u306B sp=quarantine \u307E\u305F\u306F sp=reject \u306E\u8FFD\u52A0\u3092\u691C\u8A0E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcMonitorOnly: '{domain} \u306E DMARC \u306F\u76E3\u8996\u5C02\u7528 (p=none) \u3067\u3059\u3002\u306A\u308A\u3059\u307E\u3057\u5BFE\u7B56\u3092\u5F37\u5316\u3059\u308B\u306B\u306F\u3001\u6B63\u5F53\u306A\u9001\u4FE1\u5143\u3092\u78BA\u8A8D\u3057\u305F\u5F8C\u3067 p=quarantine \u307E\u305F\u306F p=reject \u3078\u79FB\u884C\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcPct: '{domain} \u306E DMARC \u9069\u7528\u306F\u30E1\u30C3\u30BB\u30FC\u30B8\u306E {pct}% \u306E\u307F\u306B\u9069\u7528\u3055\u308C\u3066\u3044\u307E\u3059 (pct={pct})\u3002\u5C55\u958B\u304C\u78BA\u8A8D\u3067\u304D\u305F\u3089\u3001\u5B8C\u5168\u4FDD\u8B77\u306E\u305F\u3081 pct=100 \u3092\u4F7F\u7528\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcQuarantine: '{domain} \u306E DMARC \u306F p=quarantine \u306B\u8A2D\u5B9A\u3055\u308C\u3066\u3044\u307E\u3059\u3002\u6700\u3082\u5F37\u529B\u306A\u306A\u308A\u3059\u307E\u3057\u5BFE\u7B56\u306E\u305F\u3081\u3001\u6B63\u5F53\u306A\u30E1\u30FC\u30EB\u304C\u5B8C\u5168\u306B\u6574\u5408\u3057\u3066\u3044\u308B\u3053\u3068\u3092\u78BA\u8A8D\u5F8C\u306B p=reject \u3092\u691C\u8A0E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    dmarcRecordBasics: 'DMARC \u306E\u57FA\u790E',
    docs: '\u30C9\u30AD\u30E5\u30E1\u30F3\u30C8',
    domain: '\u30C9\u30E1\u30A4\u30F3',
    domainDossier: '\u30C9\u30E1\u30A4\u30F3 \u30C9\u30B7\u30A8 (CentralOps)',
    effectivePolicyInherited: '\u6709\u52B9\u306A\u30DD\u30EA\u30B7\u30FC\u306F\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u304B\u3089\u7D99\u627F\u3055\u308C\u3066\u3044\u307E\u3059\u3002',
    error: '\u30A8\u30E9\u30FC',
    expired: '\u671F\u9650\u5207\u308C',
    guidanceAcsMissing: 'ACS ms-domain-verification TXT \u304C\u3042\u308A\u307E\u305B\u3093\u3002Azure portal \u304B\u3089\u5024\u3092\u8FFD\u52A0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceAcsMissingParent: '{domain} \u306B ACS ms-domain-verification TXT \u304C\u3042\u308A\u307E\u305B\u3093\u3002\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306B\u306F ACS TXT \u304C\u3042\u308A\u307E\u3059\u304C\u3001\u7167\u4F1A\u5BFE\u8C61\u306E\u30B5\u30D6\u30C9\u30E1\u30A4\u30F3\u306F\u691C\u8A3C\u3057\u307E\u305B\u3093\u3002',
    guidanceCnameMissing: '\u7167\u4F1A\u5BFE\u8C61\u30DB\u30B9\u30C8\u3067 CNAME \u304C\u69CB\u6210\u3055\u308C\u3066\u3044\u307E\u305B\u3093\u3002\u3053\u308C\u306F\u30B7\u30CA\u30EA\u30AA\u4E0A\u60F3\u5B9A\u3069\u304A\u308A\u304B\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceDkim1Missing: 'DKIM selector1 (selector1-azurecomm-prod-net) \u304C\u3042\u308A\u307E\u305B\u3093\u3002',
    guidanceDkim2Missing: 'DKIM selector2 (selector2-azurecomm-prod-net) \u304C\u3042\u308A\u307E\u305B\u3093\u3002',
    guidanceDmarcInherited: '\u6709\u52B9\u306A DMARC \u30DD\u30EA\u30B7\u30FC\u306F\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u304B\u3089\u7D99\u627F\u3055\u308C\u3066\u3044\u307E\u3059\u3002',
    guidanceDmarcMissing: 'DMARC \u304C\u3042\u308A\u307E\u305B\u3093\u3002\u306A\u308A\u3059\u307E\u3057\u30EA\u30B9\u30AF\u3092\u6E1B\u3089\u3059\u305F\u3081\u306B _dmarc.{domain} TXT \u30EC\u30B3\u30FC\u30C9\u3092\u8FFD\u52A0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceDmarcMoreInfo: 'DMARC TXT \u30EC\u30B3\u30FC\u30C9\u69CB\u6587\u306E\u8A73\u7D30\u306B\u3064\u3044\u3066\u306F\u3001\u6B21\u3092\u53C2\u7167\u3057\u3066\u304F\u3060\u3055\u3044: {url}',
    guidanceDnsTxtFailed: 'DNS TXT \u53C2\u7167\u304C\u5931\u6557\u3057\u305F\u304B\u3001\u30BF\u30A4\u30E0\u30A2\u30A6\u30C8\u3057\u307E\u3057\u305F\u3002\u4ED6\u306E DNS \u30EC\u30B3\u30FC\u30C9\u306F\u89E3\u6C7A\u3067\u304D\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002',
    guidanceMxGoogleSpf: 'MX \u306F Google Workspace \u3092\u793A\u3057\u3066\u3044\u307E\u3059\u304C\u3001SPF \u306B _spf.google.com \u304C\u542B\u307E\u308C\u3066\u3044\u307E\u305B\u3093\u3002SPF \u306B\u6B63\u3057\u3044 provider include \u304C\u542B\u307E\u308C\u3066\u3044\u308B\u3053\u3068\u3092\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceMxMicrosoftSpf: 'MX \u306F Microsoft 365 \u3092\u793A\u3057\u3066\u3044\u307E\u3059\u304C\u3001SPF \u306B spf.protection.outlook.com \u304C\u542B\u307E\u308C\u3066\u3044\u307E\u305B\u3093\u3002SPF \u306B\u6B63\u3057\u3044 provider include \u304C\u542B\u307E\u308C\u3066\u3044\u308B\u3053\u3068\u3092\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceMxMissing: 'MX \u30EC\u30B3\u30FC\u30C9\u304C\u691C\u51FA\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002MX \u30EC\u30B3\u30FC\u30C9\u3092\u69CB\u6210\u3059\u308B\u307E\u3067\u30E1\u30FC\u30EB \u30D5\u30ED\u30FC\u306F\u6A5F\u80FD\u3057\u307E\u305B\u3093\u3002',
    guidanceMxMissingCheckedParent: '{domain} \u307E\u305F\u306F\u89AA\u30C9\u30E1\u30A4\u30F3 {parentDomain} \u306E MX \u30EC\u30B3\u30FC\u30C9\u304C\u691C\u51FA\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002MX \u30EC\u30B3\u30FC\u30C9\u3092\u69CB\u6210\u3059\u308B\u307E\u3067\u30E1\u30FC\u30EB \u30D5\u30ED\u30FC\u306F\u6A5F\u80FD\u3057\u307E\u305B\u3093\u3002',
    guidanceMxMissingParentFallback: '{domain} \u306B MX \u30EC\u30B3\u30FC\u30C9\u304C\u898B\u3064\u304B\u3089\u306A\u3044\u305F\u3081\u3001\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E MX \u30EC\u30B3\u30FC\u30C9\u3092\u30D5\u30A9\u30FC\u30EB\u30D0\u30C3\u30AF\u3068\u3057\u3066\u4F7F\u7528\u3057\u3066\u3044\u307E\u3059\u3002',
    guidanceMxParentShown: '{domain} \u306B MX \u30EC\u30B3\u30FC\u30C9\u304C\u898B\u3064\u304B\u3089\u306A\u3044\u305F\u3081\u3001\u8868\u793A\u4E2D\u306E\u7D50\u679C\u306F\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E\u3082\u306E\u3067\u3059\u3002',
    guidanceMxZohoSpf: 'MX \u306F Zoho \u3092\u793A\u3057\u3066\u3044\u307E\u3059\u304C\u3001SPF \u306B include:zoho.com \u304C\u542B\u307E\u308C\u3066\u3044\u307E\u305B\u3093\u3002SPF \u306B\u6B63\u3057\u3044 provider include \u304C\u542B\u307E\u308C\u3066\u3044\u308B\u3053\u3068\u3092\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceSpfMissing: 'SPF \u304C\u3042\u308A\u307E\u305B\u3093\u3002v=spf1 include:spf.protection.outlook.com -all (\u307E\u305F\u306F\u30D7\u30ED\u30D0\u30A4\u30C0\u30FC\u76F8\u5F53\u306E\u5024) \u3092\u8FFD\u52A0\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    guidanceSpfMissingParent: '{domain} \u306B SPF \u304C\u3042\u308A\u307E\u305B\u3093\u3002\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306F SPF \u3092\u516C\u958B\u3057\u3066\u3044\u307E\u3059\u304C\u3001\u7167\u4F1A\u5BFE\u8C61\u306E\u30B5\u30D6\u30C9\u30E1\u30A4\u30F3\u306B\u306F\u81EA\u52D5\u9069\u7528\u3055\u308C\u307E\u305B\u3093\u3002',
    hostname: '\u30DB\u30B9\u30C8\u540D',
    info: '\u60C5\u5831',
    ipAddress: 'IP \u30A2\u30C9\u30EC\u30B9',
    ipv4: 'IPv4',
    ipv4Addresses: 'IPv4 \u30A2\u30C9\u30EC\u30B9',
    ipv6: 'IPv6',
    ipv6Addresses: 'IPv6 \u30A2\u30C9\u30EC\u30B9',
    listingsLabel: '\u63B2\u8F09',
    loadingValue: '\u8AAD\u307F\u8FBC\u307F\u4E2D...',
    missingRequiredAcsTxt: '\u5FC5\u8981\u306A ACS TXT \u304C\u3042\u308A\u307E\u305B\u3093\u3002',
    multiRblLookup: 'MultiRBL DNSBL \u53C2\u7167',
    mxRecordBasics: 'MX \u306E\u57FA\u790E',
    newDomainUnderDays: '\u65B0\u3057\u3044\u30C9\u30E1\u30A4\u30F3 ({days} \u65E5\u672A\u6E80){suffix}',
    noAdditionalGuidance: '\u8FFD\u52A0\u306E\u30AC\u30A4\u30C0\u30F3\u30B9\u306F\u3042\u308A\u307E\u305B\u3093\u3002',
    noAdditionalMxDetails: '\u8FFD\u52A0\u306E MX \u8A73\u7D30\u306F\u3042\u308A\u307E\u305B\u3093\u3002',
    noIpAddressesFound: 'IP \u30A2\u30C9\u30EC\u30B9\u304C\u898B\u3064\u304B\u308A\u307E\u305B\u3093',
    noMxParentChecked: '\u89AA\u30C9\u30E1\u30A4\u30F3 {parentDomain} \u3092\u78BA\u8A8D\u3057\u307E\u3057\u305F (MX \u306A\u3057)\u3002',
    noMxParentShowing: '{domain} \u306B MX \u30EC\u30B3\u30FC\u30C9\u304C\u898B\u3064\u304B\u3089\u306A\u3044\u305F\u3081\u3001\u89AA\u30C9\u30E1\u30A4\u30F3 {lookupDomain} \u306E MX \u3092\u8868\u793A\u3057\u3066\u3044\u307E\u3059\u3002',
    noMxRecordsDetected: 'MX \u30EC\u30B3\u30FC\u30C9\u304C\u691C\u51FA\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    noRecordsAvailable: '\u5229\u7528\u53EF\u80FD\u306A\u30EC\u30B3\u30FC\u30C9\u306F\u3042\u308A\u307E\u305B\u3093\u3002',
    noSpfRecordDetected: 'SPF \u30EC\u30B3\u30FC\u30C9\u304C\u691C\u51FA\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    noSuccessfulQueries: '\u4E0D\u660E (\u6210\u529F\u3057\u305F\u30AF\u30A8\u30EA\u306A\u3057)',
    notStarted: '\u672A\u958B\u59CB',
    notVerified: '\u672A\u691C\u8A3C',
    noteDomainLessThanDays: '\u30C9\u30E1\u30A4\u30F3\u306F {days} \u65E5\u672A\u6E80\u3067\u3059\u3002',
    pending: '\u4FDD\u7559\u4E2D',
    rawWhoisLabel: 'whois',
    readinessTips: '\u6E96\u5099\u306E\u30D2\u30F3\u30C8',
    reputationDnsbl: '\u8A55\u4FA1 (DNSBL)',
    resolvedUsingGuidance: '\u30AC\u30A4\u30C0\u30F3\u30B9\u306E\u305F\u3081 {lookupDomain} \u3092\u4F7F\u7528\u3057\u3066\u89E3\u6C7A\u3057\u307E\u3057\u305F\u3002',
    spfRecordBasics: 'SPF \u306E\u57FA\u790E',
    status: '\u72B6\u614B',
    statusChecking: '{domain} \u3092\u78BA\u8A8D\u3057\u3066\u3044\u307E\u3059 \u23F3',
    statusCollectedOn: '\u53CE\u96C6\u65E5\u6642: {value}',
    statusLabel: '\u72B6\u614B',
    statusSomeChecksFailed: '\u4E00\u90E8\u306E\u78BA\u8A8D\u306B\u5931\u6557\u3057\u307E\u3057\u305F \u274C',
    statusTxtFailed: 'TXT \u53C2\u7167\u306B\u5931\u6557\u3057\u307E\u3057\u305F \u274C \u2014 \u4ED6\u306E DNS \u30EC\u30B3\u30FC\u30C9\u306F\u5F15\u304D\u7D9A\u304D\u89E3\u6C7A\u3067\u304D\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002',
    tools: '\u30C4\u30FC\u30EB',
    txtLookupFailedOrTimedOut: 'TXT \u53C2\u7167\u304C\u5931\u6557\u3057\u305F\u304B\u3001\u30BF\u30A4\u30E0\u30A2\u30A6\u30C8\u3057\u307E\u3057\u305F\u3002',
    type: '\u7A2E\u985E',
    unableDetermineAcsTxtValue: 'ACS TXT \u5024\u3092\u5224\u5B9A\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    unknown: '\u4E0D\u660E',
    usingIpParent: '\u89AA\u30C9\u30E1\u30A4\u30F3 {domain} \u306E IP \u30A2\u30C9\u30EC\u30B9\u3092\u4F7F\u7528\u3057\u3066\u3044\u307E\u3059 ({queryDomain} \u306B A/AAAA \u304C\u3042\u308A\u307E\u305B\u3093)\u3002',
    verificationTag: '\u691C\u8A3C',
    verified: '\u691C\u8A3C\u6E08\u307F',
    view: '\u8868\u793A',
    waitingForBaseTxtLookup: '\u30D9\u30FC\u30B9 TXT \u53C2\u7167\u3092\u5F85\u6A5F\u3057\u3066\u3044\u307E\u3059...',
    waitingForTxtLookup: 'TXT \u53C2\u7167\u3092\u5F85\u6A5F\u3057\u3066\u3044\u307E\u3059...'
  },
  'ru-RU': {
    acsEmailDomainVerification: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u043F\u043E\u0447\u0442\u043E\u0432\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 ACS',
    acsEmailQuotaLimitIncrease: '\u0423\u0432\u0435\u043B\u0438\u0447\u0435\u043D\u0438\u0435 \u043B\u0438\u043C\u0438\u0442\u0430 \u043F\u043E\u0447\u0442\u043E\u0432\u043E\u0439 \u043A\u0432\u043E\u0442\u044B ACS',
    acsTxtMsDomainVerification: 'ACS TXT (ms-domain-verification)',
    additionalDetailsMinus: '\u0414\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0441\u0432\u0435\u0434\u0435\u043D\u0438\u044F -',
    additionalDetailsPlus: '\u0414\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0441\u0432\u0435\u0434\u0435\u043D\u0438\u044F +',
    addresses: '\u0410\u0434\u0440\u0435\u0441\u0430',
    authMicrosoftLabel: 'Microsoft',
    checkingDnsblReputation: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u0440\u0435\u043F\u0443\u0442\u0430\u0446\u0438\u0438 DNSBL...',
    checkingMxRecords: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 MX-\u0437\u0430\u043F\u0438\u0441\u0435\u0439...',
    checkingValue: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430...',
    checklist: '\u041A\u041E\u041D\u0422\u0420\u041E\u041B\u042C\u041D\u042B\u0419 \u0421\u041F\u0418\u0421\u041E\u041A',
    cname: 'CNAME',
    copied: '\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u043E! \u2714',
    copy: '\u041A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C',
    copyEmailQuota: '\u041A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0432\u043E\u0442\u0443 \u044D\u043B\u0435\u043A\u0442\u0440\u043E\u043D\u043D\u043E\u0439 \u043F\u043E\u0447\u0442\u044B',
    dkim1Title: 'DKIM1',
    dkim2Title: 'DKIM2',
    dkimRecordBasics: '\u041E\u0441\u043D\u043E\u0432\u044B DKIM',
    dmarc: 'DMARC',
    dmarcAdkimRelaxed: '\u0412\u044B\u0440\u0430\u0432\u043D\u0438\u0432\u0430\u043D\u0438\u0435 DKIM \u0434\u043B\u044F {domain} \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 \u0440\u0430\u0441\u0441\u043B\u0430\u0431\u043B\u0435\u043D\u043D\u044B\u0439 \u0440\u0435\u0436\u0438\u043C (adkim=r). \u0420\u0430\u0441\u0441\u043C\u043E\u0442\u0440\u0438\u0442\u0435 \u0441\u0442\u0440\u043E\u0433\u0438\u0439 \u0440\u0435\u0436\u0438\u043C (adkim=s), \u0435\u0441\u043B\u0438 \u0432\u0430\u0448\u0430 \u0438\u043D\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u0430 \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0438 \u044D\u0442\u043E \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442, \u0434\u043B\u044F \u0431\u043E\u043B\u0435\u0435 \u0441\u0442\u0440\u043E\u0433\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u044B \u0434\u043E\u043C\u0435\u043D\u0430.',
    dmarcAspfRelaxed: '\u0412\u044B\u0440\u0430\u0432\u043D\u0438\u0432\u0430\u043D\u0438\u0435 SPF \u0434\u043B\u044F {domain} \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 \u0440\u0430\u0441\u0441\u043B\u0430\u0431\u043B\u0435\u043D\u043D\u044B\u0439 \u0440\u0435\u0436\u0438\u043C (aspf=r). \u0420\u0430\u0441\u0441\u043C\u043E\u0442\u0440\u0438\u0442\u0435 \u0441\u0442\u0440\u043E\u0433\u0438\u0439 \u0440\u0435\u0436\u0438\u043C (aspf=s), \u0435\u0441\u043B\u0438 \u0432\u0430\u0448\u0438 \u043E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u0438 \u0441\u0442\u0430\u0431\u0438\u043B\u044C\u043D\u043E \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044E\u0442 \u0442\u043E\u0447\u043D\u044B\u0439 \u0434\u043E\u043C\u0435\u043D.',
    dmarcMissingRua: 'DMARC \u0434\u043B\u044F {domain} \u043D\u0435 \u043F\u0443\u0431\u043B\u0438\u043A\u0443\u0435\u0442 \u0430\u0433\u0440\u0435\u0433\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u043E\u0442\u0447\u0451\u0442\u044B (rua=). \u0414\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u043F\u043E\u0447\u0442\u043E\u0432\u043E\u0433\u043E \u044F\u0449\u0438\u043A\u0430 \u0434\u043B\u044F \u043E\u0442\u0447\u0451\u0442\u043E\u0432 \u043F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0432\u0438\u0434\u0438\u043C\u043E\u0441\u0442\u044C \u043F\u043E\u043F\u044B\u0442\u043E\u043A \u043F\u043E\u0434\u0434\u0435\u043B\u043A\u0438 \u0438 \u043F\u043E\u0441\u043B\u0435\u0434\u0441\u0442\u0432\u0438\u0439 \u043F\u0440\u0438\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0438.',
    dmarcMissingRuf: 'DMARC \u0434\u043B\u044F {domain} \u043D\u0435 \u043F\u0443\u0431\u043B\u0438\u043A\u0443\u0435\u0442 forensic-\u043E\u0442\u0447\u0451\u0442\u044B (ruf=). \u0415\u0441\u043B\u0438 \u0432\u0430\u0448\u0438 \u043F\u0440\u043E\u0446\u0435\u0441\u0441\u044B \u044D\u0442\u043E \u0434\u043E\u043F\u0443\u0441\u043A\u0430\u044E\u0442, \u0442\u0430\u043A\u0438\u0435 \u043E\u0442\u0447\u0451\u0442\u044B \u043C\u043E\u0433\u0443\u0442 \u0434\u0430\u0442\u044C \u0434\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0441\u0432\u0435\u0434\u0435\u043D\u0438\u044F \u0434\u043B\u044F \u0440\u0430\u0441\u0441\u043B\u0435\u0434\u043E\u0432\u0430\u043D\u0438\u0439.',
    dmarcMissingSp: 'DMARC \u0434\u043B\u044F \u043F\u043E\u0434\u0434\u043E\u043C\u0435\u043D\u043E\u0432 {lookupDomain} \u043D\u0435 \u043E\u043F\u0440\u0435\u0434\u0435\u043B\u044F\u0435\u0442 \u044F\u0432\u043D\u0443\u044E \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0443 \u0434\u043B\u044F \u043F\u043E\u0434\u0434\u043E\u043C\u0435\u043D\u043E\u0432 (sp=). \u0415\u0441\u043B\u0438 \u0432\u044B \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u0442\u0435 \u043F\u043E\u0447\u0442\u0443 \u0441 \u043F\u043E\u0434\u0434\u043E\u043C\u0435\u043D\u043E\u0432, \u0442\u0430\u043A\u0438\u0445 \u043A\u0430\u043A {domain}, \u0440\u0430\u0441\u0441\u043C\u043E\u0442\u0440\u0438\u0442\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u0438\u0435 sp=quarantine \u0438\u043B\u0438 sp=reject \u0434\u043B\u044F \u0431\u043E\u043B\u0435\u0435 \u043F\u043E\u043D\u044F\u0442\u043D\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u044B.',
    dmarcMonitorOnly: 'DMARC \u0434\u043B\u044F {domain} \u0440\u0430\u0431\u043E\u0442\u0430\u0435\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u0432 \u0440\u0435\u0436\u0438\u043C\u0435 \u043C\u043E\u043D\u0438\u0442\u043E\u0440\u0438\u043D\u0433\u0430 (p=none). \u0414\u043B\u044F \u0431\u043E\u043B\u0435\u0435 \u0441\u0438\u043B\u044C\u043D\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u044B \u043E\u0442 \u043F\u043E\u0434\u0434\u0435\u043B\u043A\u0438 \u043F\u0435\u0440\u0435\u0439\u0434\u0438\u0442\u0435 \u043A \u043F\u0440\u0438\u043C\u0435\u043D\u0435\u043D\u0438\u044E \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0438 \u0441 p=quarantine \u0438\u043B\u0438 p=reject \u043F\u043E\u0441\u043B\u0435 \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u043B\u0435\u0433\u0438\u0442\u0438\u043C\u043D\u044B\u0445 \u0438\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u043E\u0432 \u043F\u043E\u0447\u0442\u044B.',
    dmarcPct: '\u041F\u0440\u0438\u043C\u0435\u043D\u0435\u043D\u0438\u0435 DMARC \u0434\u043B\u044F {domain} \u0440\u0430\u0441\u043F\u0440\u043E\u0441\u0442\u0440\u0430\u043D\u044F\u0435\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043D\u0430 {pct}% \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0439 (pct={pct}). \u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 pct=100 \u0434\u043B\u044F \u043F\u043E\u043B\u043D\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u044B \u043F\u043E\u0441\u043B\u0435 \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u0432\u043D\u0435\u0434\u0440\u0435\u043D\u0438\u044F.',
    dmarcQuarantine: 'DMARC \u0434\u043B\u044F {domain} \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D \u0432 p=quarantine. \u0414\u043B\u044F \u043C\u0430\u043A\u0441\u0438\u043C\u0430\u043B\u044C\u043D\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u044B \u043E\u0442 \u043F\u043E\u0434\u0434\u0435\u043B\u043A\u0438 \u0440\u0430\u0441\u0441\u043C\u043E\u0442\u0440\u0438\u0442\u0435 p=reject \u043F\u043E\u0441\u043B\u0435 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043D\u0438\u044F \u043F\u043E\u043B\u043D\u043E\u0439 \u0432\u044B\u0440\u043E\u0432\u043D\u0435\u043D\u043D\u043E\u0441\u0442\u0438 \u043B\u0435\u0433\u0438\u0442\u0438\u043C\u043D\u043E\u0439 \u043F\u043E\u0447\u0442\u044B.',
    dmarcRecordBasics: '\u041E\u0441\u043D\u043E\u0432\u044B DMARC',
    docs: '\u0414\u041E\u041A\u0423\u041C\u0415\u041D\u0422\u0410\u0426\u0418\u042F',
    domain: '\u0414\u043E\u043C\u0435\u043D',
    domainDossier: '\u0414\u043E\u0441\u044C\u0435 \u0434\u043E\u043C\u0435\u043D\u0430 (CentralOps)',
    effectivePolicyInherited: '\u0414\u0435\u0439\u0441\u0442\u0432\u0443\u044E\u0449\u0430\u044F \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0430 \u0443\u043D\u0430\u0441\u043B\u0435\u0434\u043E\u0432\u0430\u043D\u0430 \u043E\u0442 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain}.',
    error: '\u041E\u0428\u0418\u0411\u041A\u0410',
    expired: '\u0418\u0421\u0422\u0401\u041A',
    guidanceAcsMissing: 'TXT ACS ms-domain-verification \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442. \u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435 \u0438\u0437 \u043F\u043E\u0440\u0442\u0430\u043B\u0430 Azure.',
    guidanceAcsMissingParent: 'TXT ACS ms-domain-verification \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043D\u0430 {domain}. \u0423 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain} \u0435\u0441\u0442\u044C ACS TXT, \u043D\u043E \u043E\u043D \u043D\u0435 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0430\u0435\u0442 \u0437\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u044B\u0439 \u043F\u043E\u0434\u0434\u043E\u043C\u0435\u043D.',
    guidanceCnameMissing: 'CNAME \u043D\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D \u043D\u0430 \u0437\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u043E\u043C \u0445\u043E\u0441\u0442\u0435. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435, \u043E\u0436\u0438\u0434\u0430\u0435\u0442\u0441\u044F \u043B\u0438 \u044D\u0442\u043E \u0432 \u0432\u0430\u0448\u0435\u043C \u0441\u0446\u0435\u043D\u0430\u0440\u0438\u0438.',
    guidanceDkim1Missing: '\u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 DKIM selector1 (selector1-azurecomm-prod-net).',
    guidanceDkim2Missing: '\u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 DKIM selector2 (selector2-azurecomm-prod-net).',
    guidanceDmarcInherited: '\u042D\u0444\u0444\u0435\u043A\u0442\u0438\u0432\u043D\u0430\u044F \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0430 DMARC \u0443\u043D\u0430\u0441\u043B\u0435\u0434\u043E\u0432\u0430\u043D\u0430 \u043E\u0442 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain}.',
    guidanceDmarcMissing: 'DMARC \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442. \u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 TXT-\u0437\u0430\u043F\u0438\u0441\u044C _dmarc.{domain}, \u0447\u0442\u043E\u0431\u044B \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0440\u0438\u0441\u043A \u043F\u043E\u0434\u0434\u0435\u043B\u043A\u0438.',
    guidanceDmarcMoreInfo: '\u0414\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0441\u0432\u0435\u0434\u0435\u043D\u0438\u044F \u043E \u0441\u0438\u043D\u0442\u0430\u043A\u0441\u0438\u0441\u0435 TXT-\u0437\u0430\u043F\u0438\u0441\u0438 DMARC \u0441\u043C. \u0437\u0434\u0435\u0441\u044C: {url}',
    guidanceDnsTxtFailed: '\u041F\u043E\u0438\u0441\u043A DNS TXT \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043B\u0441\u044F \u043E\u0448\u0438\u0431\u043A\u043E\u0439 \u0438\u043B\u0438 \u043F\u043E \u0442\u0430\u0439\u043C-\u0430\u0443\u0442\u0443. \u0414\u0440\u0443\u0433\u0438\u0435 DNS-\u0437\u0430\u043F\u0438\u0441\u0438 \u0432\u0441\u0451 \u0435\u0449\u0451 \u043C\u043E\u0433\u0443\u0442 \u0440\u0430\u0437\u0440\u0435\u0448\u0430\u0442\u044C\u0441\u044F.',
    guidanceMxGoogleSpf: '\u0412\u0430\u0448 MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Google Workspace, \u043D\u043E SPF \u043D\u0435 \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u0442 _spf.google.com. \u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044C, \u0447\u0442\u043E SPF \u0432\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u043F\u0440\u0430\u0432\u0438\u043B\u044C\u043D\u044B\u0439 include \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430.',
    guidanceMxMicrosoftSpf: '\u0412\u0430\u0448 MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Microsoft 365, \u043D\u043E SPF \u043D\u0435 \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u0442 spf.protection.outlook.com. \u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044C, \u0447\u0442\u043E SPF \u0432\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u043F\u0440\u0430\u0432\u0438\u043B\u044C\u043D\u044B\u0439 include \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430.',
    guidanceMxMissing: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u044B. \u041F\u043E\u0447\u0442\u043E\u0432\u044B\u0439 \u043F\u043E\u0442\u043E\u043A \u043D\u0435 \u0431\u0443\u0434\u0435\u0442 \u0440\u0430\u0431\u043E\u0442\u0430\u0442\u044C, \u043F\u043E\u043A\u0430 MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u0431\u0443\u0434\u0443\u0442 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u044B.',
    guidanceMxMissingCheckedParent: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u044B \u0434\u043B\u044F {domain} \u0438\u043B\u0438 \u0435\u0433\u043E \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {parentDomain}. \u041F\u043E\u0447\u0442\u043E\u0432\u044B\u0439 \u043F\u043E\u0442\u043E\u043A \u043D\u0435 \u0431\u0443\u0434\u0435\u0442 \u0440\u0430\u0431\u043E\u0442\u0430\u0442\u044C, \u043F\u043E\u043A\u0430 MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u0431\u0443\u0434\u0443\u0442 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u044B.',
    guidanceMxMissingParentFallback: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B \u043D\u0430 {domain}; \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044E\u0442\u0441\u044F MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain} \u043A\u0430\u043A \u0440\u0435\u0437\u0435\u0440\u0432\u043D\u044B\u0439 \u0432\u0430\u0440\u0438\u0430\u043D\u0442.',
    guidanceMxParentShown: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B \u043D\u0430 {domain}; \u043F\u043E\u043A\u0430\u0437\u0430\u043D\u043D\u044B\u0435 \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442\u044B \u0432\u0437\u044F\u0442\u044B \u0438\u0437 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain}.',
    guidanceMxZohoSpf: '\u0412\u0430\u0448 MX \u0443\u043A\u0430\u0437\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 Zoho, \u043D\u043E SPF \u043D\u0435 \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u0442 include:zoho.com. \u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044C, \u0447\u0442\u043E SPF \u0432\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u043F\u0440\u0430\u0432\u0438\u043B\u044C\u043D\u044B\u0439 include \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430.',
    guidanceSpfMissing: 'SPF \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442. \u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 v=spf1 include:spf.protection.outlook.com -all (\u0438\u043B\u0438 \u044D\u043A\u0432\u0438\u0432\u0430\u043B\u0435\u043D\u0442 \u0432\u0430\u0448\u0435\u0433\u043E \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430).',
    guidanceSpfMissingParent: 'SPF \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043D\u0430 {domain}. \u0420\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u0438\u0439 \u0434\u043E\u043C\u0435\u043D {lookupDomain} \u043F\u0443\u0431\u043B\u0438\u043A\u0443\u0435\u0442 SPF, \u043D\u043E SPF \u043D\u0435 \u043F\u0440\u0438\u043C\u0435\u043D\u044F\u0435\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438 \u043A \u0437\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u043E\u043C\u0443 \u043F\u043E\u0434\u0434\u043E\u043C\u0435\u043D\u0443.',
    hostname: '\u0418\u043C\u044F \u0443\u0437\u043B\u0430',
    info: '\u0418\u041D\u0424\u041E',
    ipAddress: 'IP-\u0430\u0434\u0440\u0435\u0441',
    ipv4: 'IPv4',
    ipv4Addresses: 'IPv4-\u0430\u0434\u0440\u0435\u0441\u0430',
    ipv6: 'IPv6',
    ipv6Addresses: 'IPv6-\u0430\u0434\u0440\u0435\u0441\u0430',
    listingsLabel: '\u0421\u043F\u0438\u0441\u043A\u0438',
    loadingValue: '\u0417\u0430\u0433\u0440\u0443\u0437\u043A\u0430...',
    missingRequiredAcsTxt: '\u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u0439 ACS TXT.',
    multiRblLookup: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 DNSBL \u0447\u0435\u0440\u0435\u0437 MultiRBL',
    mxRecordBasics: '\u041E\u0441\u043D\u043E\u0432\u044B MX',
    newDomainUnderDays: '\u041D\u043E\u0432\u044B\u0439 \u0434\u043E\u043C\u0435\u043D (\u043C\u0435\u043D\u044C\u0448\u0435 {days} \u0434\u043D\u0435\u0439){suffix}',
    noAdditionalGuidance: '\u0414\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0445 \u0440\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0439 \u043D\u0435\u0442.',
    noAdditionalMxDetails: '\u0414\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0441\u0432\u0435\u0434\u0435\u043D\u0438\u044F \u043E MX \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B.',
    noIpAddressesFound: 'IP-\u0430\u0434\u0440\u0435\u0441\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B',
    noMxParentChecked: '\u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u0438\u0439 \u0434\u043E\u043C\u0435\u043D {parentDomain} (MX \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D).',
    noMxParentShowing: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B \u043D\u0430 {domain}; \u043E\u0442\u043E\u0431\u0440\u0430\u0436\u0430\u044E\u0442\u0441\u044F MX \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {lookupDomain}.',
    noMxRecordsDetected: 'MX-\u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u044B.',
    noRecordsAvailable: '\u041D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 \u0437\u0430\u043F\u0438\u0441\u0435\u0439.',
    noSpfRecordDetected: 'SPF-\u0437\u0430\u043F\u0438\u0441\u044C \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0430.',
    noSuccessfulQueries: '\u041D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u043E (\u043D\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u044B\u0445 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432)',
    notStarted: '\u041D\u0415 \u041D\u0410\u0427\u0410\u0422\u041E',
    notVerified: '\u041D\u0415 \u041F\u0420\u041E\u0412\u0415\u0420\u0415\u041D\u041E',
    noteDomainLessThanDays: '\u0412\u043E\u0437\u0440\u0430\u0441\u0442 \u0434\u043E\u043C\u0435\u043D\u0430 \u043C\u0435\u043D\u044C\u0448\u0435 {days} \u0434\u043D\u0435\u0439.',
    pending: '\u041E\u0416\u0418\u0414\u0410\u041D\u0418\u0415',
    rawWhoisLabel: 'whois',
    readinessTips: '\u0421\u041E\u0412\u0415\u0422\u042B \u041F\u041E \u0413\u041E\u0422\u041E\u0412\u041D\u041E\u0421\u0422\u0418',
    reputationDnsbl: '\u0420\u0435\u043F\u0443\u0442\u0430\u0446\u0438\u044F (DNSBL)',
    resolvedUsingGuidance: '\u0420\u0430\u0437\u0440\u0435\u0448\u0435\u043D\u043E \u0441 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435\u043C {lookupDomain} \u0434\u043B\u044F \u0441\u043F\u0440\u0430\u0432\u043A\u0438.',
    spfRecordBasics: '\u041E\u0441\u043D\u043E\u0432\u044B SPF',
    status: '\u0421\u0442\u0430\u0442\u0443\u0441',
    statusChecking: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 {domain} \u23F3',
    statusCollectedOn: '\u0421\u043E\u0431\u0440\u0430\u043D\u043E: {value}',
    statusLabel: '\u0421\u0442\u0430\u0442\u0443\u0441',
    statusSomeChecksFailed: '\u041D\u0435\u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043B\u0438\u0441\u044C \u043E\u0448\u0438\u0431\u043A\u043E\u0439 \u274C',
    statusTxtFailed: '\u041F\u043E\u0438\u0441\u043A TXT \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043B\u0441\u044F \u043E\u0448\u0438\u0431\u043A\u043E\u0439 \u274C \u2014 \u0434\u0440\u0443\u0433\u0438\u0435 DNS-\u0437\u0430\u043F\u0438\u0441\u0438 \u0432\u0441\u0451 \u0435\u0449\u0451 \u043C\u043E\u0433\u0443\u0442 \u0440\u0430\u0437\u0440\u0435\u0448\u0430\u0442\u044C\u0441\u044F.',
    tools: '\u0418\u041D\u0421\u0422\u0420\u0423\u041C\u0415\u041D\u0422\u042B',
    txtLookupFailedOrTimedOut: '\u041F\u043E\u0438\u0441\u043A TXT \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043B\u0441\u044F \u043E\u0448\u0438\u0431\u043A\u043E\u0439 \u0438\u043B\u0438 \u043F\u043E \u0442\u0430\u0439\u043C-\u0430\u0443\u0442\u0443.',
    type: '\u0422\u0438\u043F',
    unableDetermineAcsTxtValue: '\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u043F\u0440\u0435\u0434\u0435\u043B\u0438\u0442\u044C \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435 ACS TXT.',
    unknown: '\u041D\u0415\u0418\u0417\u0412\u0415\u0421\u0422\u041D\u041E',
    usingIpParent: '\u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044E\u0442\u0441\u044F IP-\u0430\u0434\u0440\u0435\u0441\u0430 \u0440\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u043E\u0433\u043E \u0434\u043E\u043C\u0435\u043D\u0430 {domain} (\u043D\u0430 {queryDomain} \u043D\u0435\u0442 A/AAAA).',
    verificationTag: '\u041F\u0420\u041E\u0412\u0415\u0420\u041A\u0410',
    verified: '\u041F\u0420\u041E\u0412\u0415\u0420\u0415\u041D\u041E',
    view: '\u041E\u0442\u043A\u0440\u044B\u0442\u044C',
    waitingForBaseTxtLookup: '\u041E\u0436\u0438\u0434\u0430\u043D\u0438\u0435 \u0431\u0430\u0437\u043E\u0432\u043E\u0433\u043E \u043F\u043E\u0438\u0441\u043A\u0430 TXT...',
    waitingForTxtLookup: '\u041E\u0436\u0438\u0434\u0430\u043D\u0438\u0435 \u043F\u043E\u0438\u0441\u043A\u0430 TXT...'
  }
};

Object.keys(RUNTIME_TRANSLATION_OVERRIDES).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, RUNTIME_TRANSLATION_OVERRIDES[code]);
});

const GUIDANCE_AND_AZURE_OVERRIDES = {
  es: {
    guidanceIconInformational: 'Informativo',
    guidanceIconError: 'Error',
    guidanceIconAttention: 'Requiere atenci\u00F3n',
    guidanceIconSuccess: 'Correcto',
    guidanceLegendAttention: 'Atenci\u00F3n',
    guidanceLegendInformational: 'Informativo',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Diagn\u00F3sticos del \u00E1rea de trabajo de Azure',
    azureDiagnosticsHint: 'Inicie sesi\u00F3n para consultar suscripciones de Azure y \u00E1reas de trabajo de Log Analytics directamente desde su sesi\u00F3n del navegador. No se env\u00EDan datos de consulta del cliente al servidor local.',
    azureSubscription: 'Suscripci\u00F3n',
    azureAcsResource: 'Recurso de ACS',
    azureWorkspace: '\u00C1rea de trabajo',
    azureLoadSubscriptions: 'Cargar suscripciones',
    azureDiscoverResources: 'Detectar recursos de ACS',
    azureDiscoverWorkspaces: 'Detectar \u00E1reas de trabajo',
    azureRunInventory: 'Ejecutar inventario del \u00E1rea de trabajo',
    azureRunDomainSearch: 'Ejecutar b\u00FAsqueda de dominio',
    azureRunAcsSearch: 'Ejecutar b\u00FAsqueda de ACS',
    azureSignInRequired: 'Inicie sesi\u00F3n con Microsoft para consultar suscripciones de Azure y Log Analytics desde el navegador.',
    azureLoadingSubscriptions: 'Cargando suscripciones...',
    azureLoadingTenants: 'Detectando inquilinos...',
    azureLoadingTenantSubscriptions: 'Cargando suscripciones del inquilino {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'Comprobando {current}/{total} suscripciones en busca de recursos de ACS...',
    azureLoadingResources: 'Detectando recursos de ACS...',
    azureLoadingWorkspaces: 'Detectando \u00E1reas de trabajo conectadas...',
    azureRunningQuery: 'Ejecutando consulta: {name}',
    azureNoSubscriptions: 'No se devolvieron suscripciones de Azure para este usuario.',
    azureNoResources: 'No se encontraron recursos de ACS en la suscripci\u00F3n seleccionada.',
    azureSubscriptionNotEnabled: 'La suscripci\u00F3n seleccionada est\u00E1 {state}. La detecci\u00F3n de recursos requiere una suscripci\u00F3n habilitada.',
    azureNoWorkspaces: 'No se encontraron \u00E1reas de trabajo de Log Analytics conectadas. Compruebe la configuraci\u00F3n de diagn\u00F3stico en los recursos de ACS seleccionados.',
    azureSelectSubscriptionFirst: 'Seleccione primero una suscripci\u00F3n.',
    azureSelectWorkspaceFirst: 'Seleccione primero un \u00E1rea de trabajo.',
    azureDomainRequired: 'Escriba un dominio antes de ejecutar la consulta de b\u00FAsqueda de dominio.',
    azureWorkspaceInventory: 'Inventario del \u00E1rea de trabajo',
    azureDomainSearch: 'B\u00FAsqueda de dominio',
    azureAcsSearch: 'B\u00FAsqueda de ACS',
    azureResultsSummary: 'Inquilino: {tenant} \u2022 Suscripci\u00F3n: {subscription} \u2022 \u00C1rea de trabajo: {workspace}',
    azureQueryReturnedNoTables: 'La consulta se complet\u00F3 pero no devolvi\u00F3 tablas.',
    azureQueryFailed: 'Error en la consulta de Azure: {reason}',
    azureDiscoverSuccess: 'Detecci\u00F3n completada. Seleccione un \u00E1rea de trabajo y ejecute una consulta.',
    azureSignedInAs: 'Sesi\u00F3n iniciada como {user}',
    azureConsentRequired: 'Se requieren permisos adicionales de Azure. Apruebe la solicitud de consentimiento para continuar.',
    azureQueryTextLabel: 'Consulta ejecutada',
    azureSwitchDirectory: 'Cambiar directorio (id. de inquilino o dominio)',
    azureSwitchBtn: 'Cambiar'
  },
  fr: {
    guidanceIconInformational: 'Informatif',
    guidanceIconError: 'Erreur',
    guidanceIconAttention: 'Attention requise',
    guidanceIconSuccess: 'R\u00E9ussite',
    guidanceLegendAttention: 'Attention',
    guidanceLegendInformational: 'Informatif',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Diagnostics de l\u2019espace de travail Azure',
    azureDiagnosticsHint: 'Connectez-vous pour interroger les abonnements Azure et les espaces de travail Log Analytics directement depuis votre session de navigateur. Aucune donn\u00E9e de requ\u00EAte client n\u2019est envoy\u00E9e au serveur local.',
    azureSubscription: 'Abonnement',
    azureAcsResource: 'Ressource ACS',
    azureWorkspace: 'Espace de travail',
    azureLoadSubscriptions: 'Charger les abonnements',
    azureDiscoverResources: 'D\u00E9couvrir les ressources ACS',
    azureDiscoverWorkspaces: 'D\u00E9couvrir les espaces de travail',
    azureRunInventory: 'Ex\u00E9cuter l\u2019inventaire de l\u2019espace de travail',
    azureRunDomainSearch: 'Ex\u00E9cuter la recherche de domaine',
    azureRunAcsSearch: 'Ex\u00E9cuter la recherche ACS',
    azureSignInRequired: 'Connectez-vous avec Microsoft pour interroger les abonnements Azure et Log Analytics depuis le navigateur.',
    azureLoadingSubscriptions: 'Chargement des abonnements...',
    azureLoadingTenants: 'D\u00E9couverte des locataires...',
    azureLoadingTenantSubscriptions: 'Chargement des abonnements du locataire {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'V\u00E9rification de {current}/{total} abonnements pour les ressources ACS...',
    azureLoadingResources: 'D\u00E9couverte des ressources ACS...',
    azureLoadingWorkspaces: 'D\u00E9couverte des espaces de travail connect\u00E9s...',
    azureRunningQuery: 'Ex\u00E9cution de la requ\u00EAte : {name}',
    azureNoSubscriptions: 'Aucun abonnement Azure n\u2019a \u00E9t\u00E9 retourn\u00E9 pour cet utilisateur.',
    azureNoResources: 'Aucune ressource ACS n\u2019a \u00E9t\u00E9 trouv\u00E9e dans l\u2019abonnement s\u00E9lectionn\u00E9.',
    azureSubscriptionNotEnabled: 'L\u2019abonnement s\u00E9lectionn\u00E9 est {state}. La d\u00E9couverte de ressources n\u00E9cessite un abonnement activ\u00E9.',
    azureNoWorkspaces: 'Aucun espace de travail Log Analytics connect\u00E9 n\u2019a \u00E9t\u00E9 trouv\u00E9. V\u00E9rifiez les param\u00E8tres de diagnostic sur les ressources ACS s\u00E9lectionn\u00E9es.',
    azureSelectSubscriptionFirst: 'S\u00E9lectionnez d\u2019abord un abonnement.',
    azureSelectWorkspaceFirst: 'S\u00E9lectionnez d\u2019abord un espace de travail.',
    azureDomainRequired: 'Saisissez un domaine avant d\u2019ex\u00E9cuter la requ\u00EAte de recherche de domaine.',
    azureWorkspaceInventory: 'Inventaire de l\u2019espace de travail',
    azureDomainSearch: 'Recherche de domaine',
    azureAcsSearch: 'Recherche ACS',
    azureResultsSummary: 'Locataire : {tenant} \u2022 Abonnement : {subscription} \u2022 Espace de travail : {workspace}',
    azureQueryReturnedNoTables: 'La requ\u00EAte s\u2019est termin\u00E9e mais n\u2019a retourn\u00E9 aucune table.',
    azureQueryFailed: '\u00C9chec de la requ\u00EAte Azure : {reason}',
    azureDiscoverSuccess: 'D\u00E9couverte termin\u00E9e. S\u00E9lectionnez un espace de travail et ex\u00E9cutez une requ\u00EAte.',
    azureSignedInAs: 'Connect\u00E9 en tant que {user}',
    azureConsentRequired: 'Des autorisations Azure suppl\u00E9mentaires sont requises. Approuvez l\u2019invite de consentement pour continuer.',
    azureQueryTextLabel: 'Requ\u00EAte ex\u00E9cut\u00E9e',
    azureSwitchDirectory: 'Changer d\u2019annuaire (ID de locataire ou domaine)',
    azureSwitchBtn: 'Changer'
  },
  de: {
    guidanceIconInformational: 'Informativ',
    guidanceIconError: 'Fehler',
    guidanceIconAttention: 'Beachten',
    guidanceIconSuccess: 'Erfolg',
    guidanceLegendAttention: 'Beachten',
    guidanceLegendInformational: 'Informativ',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Azure-Arbeitsbereichsdiagnose',
    azureDiagnosticsHint: 'Melden Sie sich an, um Azure-Abonnements und Log Analytics-Arbeitsbereiche direkt von Ihrer Browsersitzung abzufragen. Es werden keine Kundenabfragedaten an den lokalen Server gesendet.',
    azureSubscription: 'Abonnement',
    azureAcsResource: 'ACS-Ressource',
    azureWorkspace: 'Arbeitsbereich',
    azureLoadSubscriptions: 'Abonnements laden',
    azureDiscoverResources: 'ACS-Ressourcen ermitteln',
    azureDiscoverWorkspaces: 'Arbeitsbereiche ermitteln',
    azureRunInventory: 'Arbeitsbereichsinventar ausf\u00FChren',
    azureRunDomainSearch: 'Domainsuche ausf\u00FChren',
    azureRunAcsSearch: 'ACS-Suche ausf\u00FChren',
    azureSignInRequired: 'Melden Sie sich mit Microsoft an, um Azure-Abonnements und Log Analytics vom Browser aus abzufragen.',
    azureLoadingSubscriptions: 'Abonnements werden geladen...',
    azureLoadingTenants: 'Mandanten werden ermittelt...',
    azureLoadingTenantSubscriptions: 'Abonnements f\u00FCr Mandant {tenant} werden geladen ({current}/{total})...',
    azureFilteringAcsSubscriptions: '{current}/{total} Abonnements werden auf ACS-Ressourcen gepr\u00FCft...',
    azureLoadingResources: 'ACS-Ressourcen werden ermittelt...',
    azureLoadingWorkspaces: 'Verbundene Arbeitsbereiche werden ermittelt...',
    azureRunningQuery: 'Abfrage wird ausgef\u00FChrt: {name}',
    azureNoSubscriptions: 'Es wurden keine Azure-Abonnements f\u00FCr diesen Benutzer zur\u00FCckgegeben.',
    azureNoResources: 'Im ausgew\u00E4hlten Abonnement wurden keine ACS-Ressourcen gefunden.',
    azureSubscriptionNotEnabled: 'Das ausgew\u00E4hlte Abonnement ist {state}. Die Ressourcenermittlung erfordert ein aktiviertes Abonnement.',
    azureNoWorkspaces: 'Es wurden keine verbundenen Log Analytics-Arbeitsbereiche gefunden. Pr\u00FCfen Sie die Diagnoseeinstellungen der ausgew\u00E4hlten ACS-Ressourcen.',
    azureSelectSubscriptionFirst: 'W\u00E4hlen Sie zuerst ein Abonnement aus.',
    azureSelectWorkspaceFirst: 'W\u00E4hlen Sie zuerst einen Arbeitsbereich aus.',
    azureDomainRequired: 'Geben Sie eine Domain ein, bevor Sie die Domainsuche ausf\u00FChren.',
    azureWorkspaceInventory: 'Arbeitsbereichsinventar',
    azureDomainSearch: 'Domainsuche',
    azureAcsSearch: 'ACS-Suche',
    azureResultsSummary: 'Mandant: {tenant} \u2022 Abonnement: {subscription} \u2022 Arbeitsbereich: {workspace}',
    azureQueryReturnedNoTables: 'Die Abfrage wurde abgeschlossen, hat aber keine Tabellen zur\u00FCckgegeben.',
    azureQueryFailed: 'Azure-Abfrage fehlgeschlagen: {reason}',
    azureDiscoverSuccess: 'Ermittlung abgeschlossen. W\u00E4hlen Sie einen Arbeitsbereich und f\u00FChren Sie eine Abfrage aus.',
    azureSignedInAs: 'Angemeldet als {user}',
    azureConsentRequired: 'Zus\u00E4tzliche Azure-Berechtigungen sind erforderlich. Genehmigen Sie die Zustimmungsaufforderung, um fortzufahren.',
    azureQueryTextLabel: 'Ausgef\u00FChrte Abfrage',
    azureSwitchDirectory: 'Verzeichnis wechseln (Mandanten-ID oder Dom\u00E4ne)',
    azureSwitchBtn: 'Wechseln'
  },
  'pt-BR': {
    guidanceIconInformational: 'Informativo',
    guidanceIconError: 'Erro',
    guidanceIconAttention: 'Requer aten\u00E7\u00E3o',
    guidanceIconSuccess: 'Sucesso',
    guidanceLegendAttention: 'Aten\u00E7\u00E3o',
    guidanceLegendInformational: 'Informativo',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Diagn\u00F3stico do workspace do Azure',
    azureDiagnosticsHint: 'Entre para consultar assinaturas do Azure e workspaces do Log Analytics diretamente do navegador. Nenhum dado de consulta do cliente \u00E9 enviado ao servidor local.',
    azureSubscription: 'Assinatura',
    azureAcsResource: 'Recurso do ACS',
    azureWorkspace: 'Workspace',
    azureLoadSubscriptions: 'Carregar assinaturas',
    azureDiscoverResources: 'Descobrir recursos do ACS',
    azureDiscoverWorkspaces: 'Descobrir workspaces',
    azureRunInventory: 'Executar invent\u00E1rio do workspace',
    azureRunDomainSearch: 'Executar pesquisa de dom\u00EDnio',
    azureRunAcsSearch: 'Executar pesquisa do ACS',
    azureSignInRequired: 'Entre com a Microsoft para consultar assinaturas do Azure e Log Analytics pelo navegador.',
    azureLoadingSubscriptions: 'Carregando assinaturas...',
    azureLoadingTenants: 'Descobrindo locat\u00E1rios...',
    azureLoadingTenantSubscriptions: 'Carregando assinaturas do locat\u00E1rio {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'Verificando {current}/{total} assinaturas em busca de recursos do ACS...',
    azureLoadingResources: 'Descobrindo recursos do ACS...',
    azureLoadingWorkspaces: 'Descobrindo workspaces conectados...',
    azureRunningQuery: 'Executando consulta: {name}',
    azureNoSubscriptions: 'Nenhuma assinatura do Azure foi retornada para este usu\u00E1rio.',
    azureNoResources: 'Nenhum recurso do ACS foi encontrado na assinatura selecionada.',
    azureSubscriptionNotEnabled: 'A assinatura selecionada est\u00E1 {state}. A descoberta de recursos requer uma assinatura habilitada.',
    azureNoWorkspaces: 'Nenhum workspace do Log Analytics conectado foi encontrado. Verifique as configura\u00E7\u00F5es de diagn\u00F3stico nos recursos do ACS selecionados.',
    azureSelectSubscriptionFirst: 'Selecione uma assinatura primeiro.',
    azureSelectWorkspaceFirst: 'Selecione um workspace primeiro.',
    azureDomainRequired: 'Insira um dom\u00EDnio antes de executar a consulta de pesquisa de dom\u00EDnio.',
    azureWorkspaceInventory: 'Invent\u00E1rio do workspace',
    azureDomainSearch: 'Pesquisa de dom\u00EDnio',
    azureAcsSearch: 'Pesquisa do ACS',
    azureResultsSummary: 'Locat\u00E1rio: {tenant} \u2022 Assinatura: {subscription} \u2022 Workspace: {workspace}',
    azureQueryReturnedNoTables: 'A consulta foi conclu\u00EDda, mas n\u00E3o retornou tabelas.',
    azureQueryFailed: 'Falha na consulta do Azure: {reason}',
    azureDiscoverSuccess: 'Descoberta conclu\u00EDda. Selecione um workspace e execute uma consulta.',
    azureSignedInAs: 'Conectado como {user}',
    azureConsentRequired: 'S\u00E3o necess\u00E1rias permiss\u00F5es adicionais do Azure. Aprove a solicita\u00E7\u00E3o de consentimento para continuar.',
    azureQueryTextLabel: 'Consulta executada',
    azureSwitchDirectory: 'Alternar diret\u00F3rio (ID do locat\u00E1rio ou dom\u00EDnio)',
    azureSwitchBtn: 'Alternar'
  },
  ar: {
    guidanceIconInformational: '\u0645\u0639\u0644\u0648\u0645\u0627\u062A\u064A',
    guidanceIconError: '\u062E\u0637\u0623',
    guidanceIconAttention: '\u064A\u062A\u0637\u0644\u0628 \u0627\u0646\u062A\u0628\u0627\u0647\u064B\u0627',
    guidanceIconSuccess: '\u0646\u062C\u0627\u062D',
    guidanceLegendAttention: '\u0627\u0646\u062A\u0628\u0627\u0647',
    guidanceLegendInformational: '\u0645\u0639\u0644\u0648\u0645\u0627\u062A\u064A',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: '\u062A\u0634\u062E\u064A\u0635\u0627\u062A \u0645\u0633\u0627\u062D\u0629 \u0639\u0645\u0644 Azure',
    azureDiagnosticsHint: '\u0633\u062C\u0651\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0644\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0639\u0646 \u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A Azure \u0648\u0645\u0633\u0627\u062D\u0627\u062A \u0639\u0645\u0644 Log Analytics \u0645\u0628\u0627\u0634\u0631\u0629 \u0645\u0646 \u062C\u0644\u0633\u0629 \u0627\u0644\u0645\u062A\u0635\u0641\u062D. \u0644\u0627 \u064A\u062A\u0645 \u0625\u0631\u0633\u0627\u0644 \u0623\u064A \u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0639\u0645\u064A\u0644 \u0625\u0644\u0649 \u0627\u0644\u062E\u0627\u062F\u0645 \u0627\u0644\u0645\u062D\u0644\u064A.',
    azureSubscription: '\u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643',
    azureAcsResource: '\u0645\u0648\u0631\u062F ACS',
    azureWorkspace: '\u0645\u0633\u0627\u062D\u0629 \u0627\u0644\u0639\u0645\u0644',
    azureLoadSubscriptions: '\u062A\u062D\u0645\u064A\u0644 \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A',
    azureDiscoverResources: '\u0627\u0643\u062A\u0634\u0627\u0641 \u0645\u0648\u0627\u0631\u062F ACS',
    azureDiscoverWorkspaces: '\u0627\u0643\u062A\u0634\u0627\u0641 \u0645\u0633\u0627\u062D\u0627\u062A \u0627\u0644\u0639\u0645\u0644',
    azureRunInventory: '\u062A\u0634\u063A\u064A\u0644 \u062C\u0631\u062F \u0645\u0633\u0627\u062D\u0629 \u0627\u0644\u0639\u0645\u0644',
    azureRunDomainSearch: '\u062A\u0634\u063A\u064A\u0644 \u0628\u062D\u062B \u0627\u0644\u0646\u0637\u0627\u0642',
    azureRunAcsSearch: '\u062A\u0634\u063A\u064A\u0644 \u0628\u062D\u062B ACS',
    azureSignInRequired: '\u0633\u062C\u0651\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft \u0644\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0639\u0646 \u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A Azure \u0648Log Analytics \u0645\u0646 \u0627\u0644\u0645\u062A\u0635\u0641\u062D.',
    azureLoadingSubscriptions: '\u062C\u0627\u0631\u064D \u062A\u062D\u0645\u064A\u0644 \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A...',
    azureLoadingTenants: '\u062C\u0627\u0631\u064D \u0627\u0643\u062A\u0634\u0627\u0641 \u0627\u0644\u0645\u0633\u062A\u0623\u062C\u0631\u064A\u0646...',
    azureLoadingTenantSubscriptions: '\u062C\u0627\u0631\u064D \u062A\u062D\u0645\u064A\u0644 \u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A \u0627\u0644\u0645\u0633\u062A\u0623\u062C\u0631 {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: '\u062C\u0627\u0631\u064D \u0641\u062D\u0635 {current}/{total} \u0627\u0634\u062A\u0631\u0627\u0643\u064B\u0627 \u0628\u062D\u062B\u064B\u0627 \u0639\u0646 \u0645\u0648\u0627\u0631\u062F ACS...',
    azureLoadingResources: '\u062C\u0627\u0631\u064D \u0627\u0643\u062A\u0634\u0627\u0641 \u0645\u0648\u0627\u0631\u062F ACS...',
    azureLoadingWorkspaces: '\u062C\u0627\u0631\u064D \u0627\u0643\u062A\u0634\u0627\u0641 \u0645\u0633\u0627\u062D\u0627\u062A \u0627\u0644\u0639\u0645\u0644 \u0627\u0644\u0645\u062A\u0635\u0644\u0629...',
    azureRunningQuery: '\u062C\u0627\u0631\u064D \u062A\u0646\u0641\u064A\u0630 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645: {name}',
    azureNoSubscriptions: '\u0644\u0645 \u064A\u062A\u0645 \u0625\u0631\u062C\u0627\u0639 \u0623\u064A \u0627\u0634\u062A\u0631\u0627\u0643\u0627\u062A Azure \u0644\u0647\u0630\u0627 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645.',
    azureNoResources: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0645\u0648\u0627\u0631\u062F ACS \u0641\u064A \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643 \u0627\u0644\u0645\u062D\u062F\u062F.',
    azureSubscriptionNotEnabled: '\u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643 \u0627\u0644\u0645\u062D\u062F\u062F \u0641\u064A \u062D\u0627\u0644\u0629 {state}. \u064A\u062A\u0637\u0644\u0628 \u0627\u0643\u062A\u0634\u0627\u0641 \u0627\u0644\u0645\u0648\u0627\u0631\u062F \u0627\u0634\u062A\u0631\u0627\u0643\u064B\u0627 \u0645\u064F\u0645\u0643\u0651\u0646\u064B\u0627.',
    azureNoWorkspaces: '\u0644\u0645 \u064A\u062A\u0645 \u0627\u0644\u0639\u062B\u0648\u0631 \u0639\u0644\u0649 \u0645\u0633\u0627\u062D\u0627\u062A \u0639\u0645\u0644 Log Analytics \u0645\u062A\u0635\u0644\u0629. \u062A\u062D\u0642\u0651\u0642 \u0645\u0646 \u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u062A\u0634\u062E\u064A\u0635 \u0639\u0644\u0649 \u0645\u0648\u0627\u0631\u062F ACS \u0627\u0644\u0645\u062D\u062F\u062F\u0629.',
    azureSelectSubscriptionFirst: '\u062D\u062F\u062F \u0627\u0634\u062A\u0631\u0627\u0643\u064B\u0627 \u0623\u0648\u0644\u0627\u064B.',
    azureSelectWorkspaceFirst: '\u062D\u062F\u062F \u0645\u0633\u0627\u062D\u0629 \u0639\u0645\u0644 \u0623\u0648\u0644\u0627\u064B.',
    azureDomainRequired: '\u0623\u062F\u062E\u0644 \u0646\u0637\u0627\u0642\u064B\u0627 \u0642\u0628\u0644 \u062A\u0634\u063A\u064A\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0628\u062D\u062B \u0627\u0644\u0646\u0637\u0627\u0642.',
    azureWorkspaceInventory: '\u062C\u0631\u062F \u0645\u0633\u0627\u062D\u0629 \u0627\u0644\u0639\u0645\u0644',
    azureDomainSearch: '\u0628\u062D\u062B \u0627\u0644\u0646\u0637\u0627\u0642',
    azureAcsSearch: '\u0628\u062D\u062B ACS',
    azureResultsSummary: '\u0627\u0644\u0645\u0633\u062A\u0623\u062C\u0631: {tenant} \u2022 \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643: {subscription} \u2022 \u0645\u0633\u0627\u062D\u0629 \u0627\u0644\u0639\u0645\u0644: {workspace}',
    azureQueryReturnedNoTables: '\u0627\u0643\u062A\u0645\u0644 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0648\u0644\u0643\u0646\u0647 \u0644\u0645 \u064A\u064F\u0631\u062C\u0639 \u0623\u064A \u062C\u062F\u0627\u0648\u0644.',
    azureQueryFailed: '\u0641\u0634\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645 Azure: {reason}',
    azureDiscoverSuccess: '\u0627\u0643\u062A\u0645\u0644 \u0627\u0644\u0627\u0643\u062A\u0634\u0627\u0641. \u062D\u062F\u062F \u0645\u0633\u0627\u062D\u0629 \u0639\u0645\u0644 \u0648\u0634\u063A\u0651\u0644 \u0627\u0633\u062A\u0639\u0644\u0627\u0645\u064B\u0627.',
    azureSignedInAs: '\u0645\u0633\u062C\u0651\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u0645 {user}',
    azureConsentRequired: '\u0645\u0637\u0644\u0648\u0628 \u0623\u0630\u0648\u0646\u0627\u062A Azure \u0625\u0636\u0627\u0641\u064A\u0629. \u0648\u0627\u0641\u0642 \u0639\u0644\u0649 \u0637\u0644\u0628 \u0627\u0644\u0645\u0648\u0627\u0641\u0642\u0629 \u0644\u0644\u0645\u062A\u0627\u0628\u0639\u0629.',
    azureQueryTextLabel: '\u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0627\u0644\u0645\u0646\u0641\u0630',
    azureSwitchDirectory: '\u062A\u0628\u062F\u064A\u0644 \u0627\u0644\u062F\u0644\u064A\u0644 (\u0645\u0639\u0631\u0641 \u0627\u0644\u0645\u0633\u062A\u0623\u062C\u0631 \u0623\u0648 \u0627\u0644\u0646\u0637\u0627\u0642)',
    azureSwitchBtn: '\u062A\u0628\u062F\u064A\u0644'
  },
  'zh-CN': {
    guidanceIconInformational: '\u53C2\u8003\u4FE1\u606F',
    guidanceIconError: '\u9519\u8BEF',
    guidanceIconAttention: '\u9700\u8981\u6CE8\u610F',
    guidanceIconSuccess: '\u6210\u529F',
    guidanceLegendAttention: '\u6CE8\u610F',
    guidanceLegendInformational: '\u53C2\u8003\u4FE1\u606F',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Azure \u5DE5\u4F5C\u533A\u8BCA\u65AD',
    azureDiagnosticsHint: '\u767B\u5F55\u4EE5\u76F4\u63A5\u4ECE\u6D4F\u89C8\u5668\u4F1A\u8BDD\u67E5\u8BE2\u5BA2\u6237 Azure \u8BA2\u9605\u548C Log Analytics \u5DE5\u4F5C\u533A\u3002\u4E0D\u4F1A\u5C06\u4EFB\u4F55\u5BA2\u6237\u67E5\u8BE2\u6570\u636E\u53D1\u9001\u5230\u672C\u5730\u670D\u52A1\u5668\u3002',
    azureSubscription: '\u8BA2\u9605',
    azureAcsResource: 'ACS \u8D44\u6E90',
    azureWorkspace: '\u5DE5\u4F5C\u533A',
    azureLoadSubscriptions: '\u52A0\u8F7D\u8BA2\u9605',
    azureDiscoverResources: '\u53D1\u73B0 ACS \u8D44\u6E90',
    azureDiscoverWorkspaces: '\u53D1\u73B0\u5DE5\u4F5C\u533A',
    azureRunInventory: '\u8FD0\u884C\u5DE5\u4F5C\u533A\u6E05\u5355',
    azureRunDomainSearch: '\u8FD0\u884C\u57DF\u641C\u7D22',
    azureRunAcsSearch: '\u8FD0\u884C ACS \u641C\u7D22',
    azureSignInRequired: '\u4F7F\u7528 Microsoft \u767B\u5F55\u4EE5\u4ECE\u6D4F\u89C8\u5668\u67E5\u8BE2 Azure \u8BA2\u9605\u548C Log Analytics\u3002',
    azureLoadingSubscriptions: '\u6B63\u5728\u52A0\u8F7D\u8BA2\u9605...',
    azureLoadingTenants: '\u6B63\u5728\u53D1\u73B0\u79DF\u6237...',
    azureLoadingTenantSubscriptions: '\u6B63\u5728\u52A0\u8F7D\u79DF\u6237 {tenant} \u7684\u8BA2\u9605 ({current}/{total})...',
    azureFilteringAcsSubscriptions: '\u6B63\u5728\u68C0\u67E5 {current}/{total} \u4E2A\u8BA2\u9605\u7684 ACS \u8D44\u6E90...',
    azureLoadingResources: '\u6B63\u5728\u53D1\u73B0 ACS \u8D44\u6E90...',
    azureLoadingWorkspaces: '\u6B63\u5728\u53D1\u73B0\u5DF2\u8FDE\u63A5\u7684\u5DE5\u4F5C\u533A...',
    azureRunningQuery: '\u6B63\u5728\u8FD0\u884C\u67E5\u8BE2\uFF1A{name}',
    azureNoSubscriptions: '\u672A\u8FD4\u56DE\u6B64\u7528\u6237\u7684\u4EFB\u4F55 Azure \u8BA2\u9605\u3002',
    azureNoResources: '\u5728\u6240\u9009\u8BA2\u9605\u4E2D\u672A\u627E\u5230 ACS \u8D44\u6E90\u3002',
    azureSubscriptionNotEnabled: '\u6240\u9009\u8BA2\u9605\u5904\u4E8E {state} \u72B6\u6001\u3002\u8D44\u6E90\u53D1\u73B0\u9700\u8981\u5DF2\u542F\u7528\u7684\u8BA2\u9605\u3002',
    azureNoWorkspaces: '\u672A\u627E\u5230\u5DF2\u8FDE\u63A5\u7684 Log Analytics \u5DE5\u4F5C\u533A\u3002\u8BF7\u68C0\u67E5\u6240\u9009 ACS \u8D44\u6E90\u4E0A\u7684\u8BCA\u65AD\u8BBE\u7F6E\u3002',
    azureSelectSubscriptionFirst: '\u8BF7\u5148\u9009\u62E9\u4E00\u4E2A\u8BA2\u9605\u3002',
    azureSelectWorkspaceFirst: '\u8BF7\u5148\u9009\u62E9\u4E00\u4E2A\u5DE5\u4F5C\u533A\u3002',
    azureDomainRequired: '\u5728\u8FD0\u884C\u57DF\u641C\u7D22\u67E5\u8BE2\u4E4B\u524D\uFF0C\u8BF7\u8F93\u5165\u57DF\u540D\u3002',
    azureWorkspaceInventory: '\u5DE5\u4F5C\u533A\u6E05\u5355',
    azureDomainSearch: '\u57DF\u641C\u7D22',
    azureAcsSearch: 'ACS \u641C\u7D22',
    azureResultsSummary: '\u79DF\u6237\uFF1A{tenant} \u2022 \u8BA2\u9605\uFF1A{subscription} \u2022 \u5DE5\u4F5C\u533A\uFF1A{workspace}',
    azureQueryReturnedNoTables: '\u67E5\u8BE2\u5DF2\u5B8C\u6210\uFF0C\u4F46\u672A\u8FD4\u56DE\u4EFB\u4F55\u8868\u3002',
    azureQueryFailed: 'Azure \u67E5\u8BE2\u5931\u8D25\uFF1A{reason}',
    azureDiscoverSuccess: '\u53D1\u73B0\u5B8C\u6210\u3002\u8BF7\u9009\u62E9\u4E00\u4E2A\u5DE5\u4F5C\u533A\u5E76\u8FD0\u884C\u67E5\u8BE2\u3002',
    azureSignedInAs: '\u5DF2\u4EE5 {user} \u8EAB\u4EFD\u767B\u5F55',
    azureConsentRequired: '\u9700\u8981\u989D\u5916\u7684 Azure \u6743\u9650\u3002\u8BF7\u6279\u51C6\u540C\u610F\u63D0\u793A\u4EE5\u7EE7\u7EED\u3002',
    azureQueryTextLabel: '\u5DF2\u6267\u884C\u7684\u67E5\u8BE2',
    azureSwitchDirectory: '\u5207\u6362\u76EE\u5F55\uFF08\u79DF\u6237 ID \u6216\u57DF\uFF09',
    azureSwitchBtn: '\u5207\u6362'
  },
  'hi-IN': {
    guidanceIconInformational: '\u0938\u0942\u091A\u0928\u093E\u0924\u094D\u092E\u0915',
    guidanceIconError: '\u0924\u094D\u0930\u0941\u091F\u093F',
    guidanceIconAttention: '\u0927\u094D\u092F\u093E\u0928 \u0906\u0935\u0936\u094D\u092F\u0915',
    guidanceIconSuccess: '\u0938\u092B\u0932',
    guidanceLegendAttention: '\u0927\u094D\u092F\u093E\u0928 \u0926\u0947\u0902',
    guidanceLegendInformational: '\u0938\u0942\u091A\u0928\u093E\u0924\u094D\u092E\u0915',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Azure \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0928\u093F\u0926\u093E\u0928',
    azureDiagnosticsHint: '\u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0938\u0924\u094D\u0930 \u0938\u0947 \u0938\u0940\u0927\u0947 \u0917\u094D\u0930\u093E\u0939\u0915 Azure \u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u0914\u0930 Log Analytics \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F \u0938\u093E\u0907\u0928 \u0907\u0928 \u0915\u0930\u0947\u0902\u0964 \u0938\u094D\u0925\u093E\u0928\u0940\u092F \u0938\u0930\u094D\u0935\u0930 \u0915\u094B \u0915\u094B\u0908 \u0917\u094D\u0930\u093E\u0939\u0915 \u0915\u094D\u0935\u0947\u0930\u0940 \u0921\u0947\u091F\u093E \u0928\u0939\u0940\u0902 \u092D\u0947\u091C\u093E \u091C\u093E\u0924\u093E \u0939\u0948\u0964',
    azureSubscription: '\u0938\u0926\u0938\u094D\u092F\u0924\u093E',
    azureAcsResource: 'ACS \u0938\u0902\u0938\u093E\u0927\u0928',
    azureWorkspace: '\u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930',
    azureLoadSubscriptions: '\u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u0932\u094B\u0921 \u0915\u0930\u0947\u0902',
    azureDiscoverResources: 'ACS \u0938\u0902\u0938\u093E\u0927\u0928 \u0916\u094B\u091C\u0947\u0902',
    azureDiscoverWorkspaces: '\u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0916\u094B\u091C\u0947\u0902',
    azureRunInventory: '\u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0938\u0942\u091A\u0940 \u091A\u0932\u093E\u090F\u0901',
    azureRunDomainSearch: '\u0921\u094B\u092E\u0947\u0928 \u0916\u094B\u091C \u091A\u0932\u093E\u090F\u0901',
    azureRunAcsSearch: 'ACS \u0916\u094B\u091C \u091A\u0932\u093E\u090F\u0901',
    azureSignInRequired: '\u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0938\u0947 Azure \u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u0914\u0930 Log Analytics \u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F Microsoft \u0938\u0947 \u0938\u093E\u0907\u0928 \u0907\u0928 \u0915\u0930\u0947\u0902\u0964',
    azureLoadingSubscriptions: '\u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u0932\u094B\u0921 \u0939\u094B \u0930\u0939\u0940 \u0939\u0948\u0902...',
    azureLoadingTenants: '\u091F\u0948\u0928\u0947\u0902\u091F \u0916\u094B\u091C\u0947 \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902...',
    azureLoadingTenantSubscriptions: '\u091F\u0948\u0928\u0947\u0902\u091F {tenant} \u0915\u0940 \u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u0932\u094B\u0921 \u0939\u094B \u0930\u0939\u0940 \u0939\u0948\u0902 ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'ACS \u0938\u0902\u0938\u093E\u0927\u0928\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F {current}/{total} \u0938\u0926\u0938\u094D\u092F\u0924\u093E\u090F\u0901 \u091C\u093E\u0901\u091A\u0940 \u091C\u093E \u0930\u0939\u0940 \u0939\u0948\u0902...',
    azureLoadingResources: 'ACS \u0938\u0902\u0938\u093E\u0927\u0928 \u0916\u094B\u091C\u0947 \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902...',
    azureLoadingWorkspaces: '\u0915\u0928\u0947\u0915\u094D\u091F\u0947\u0921 \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0916\u094B\u091C\u0947 \u091C\u093E \u0930\u0939\u0947 \u0939\u0948\u0902...',
    azureRunningQuery: '\u0915\u094D\u0935\u0947\u0930\u0940 \u091A\u0932 \u0930\u0939\u0940 \u0939\u0948: {name}',
    azureNoSubscriptions: '\u0907\u0938 \u0909\u092A\u092F\u094B\u0917\u0915\u0930\u094D\u0924\u093E \u0915\u0947 \u0932\u093F\u090F \u0915\u094B\u0908 Azure \u0938\u0926\u0938\u094D\u092F\u0924\u093E \u0928\u0939\u0940\u0902 \u0932\u094C\u091F\u0940\u0964',
    azureNoResources: '\u091A\u092F\u0928\u093F\u0924 \u0938\u0926\u0938\u094D\u092F\u0924\u093E \u092E\u0947\u0902 \u0915\u094B\u0908 ACS \u0938\u0902\u0938\u093E\u0927\u0928 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964',
    azureSubscriptionNotEnabled: '\u091A\u092F\u0928\u093F\u0924 \u0938\u0926\u0938\u094D\u092F\u0924\u093E {state} \u0939\u0948\u0964 \u0938\u0902\u0938\u093E\u0927\u0928 \u0916\u094B\u091C \u0915\u0947 \u0932\u093F\u090F \u090F\u0915 \u0938\u0915\u094D\u0937\u092E \u0938\u0926\u0938\u094D\u092F\u0924\u093E \u0906\u0935\u0936\u094D\u092F\u0915 \u0939\u0948\u0964',
    azureNoWorkspaces: '\u0915\u094B\u0908 \u0915\u0928\u0947\u0915\u094D\u091F\u0947\u0921 Log Analytics \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0928\u0939\u0940\u0902 \u092E\u093F\u0932\u093E\u0964 \u091A\u092F\u0928\u093F\u0924 ACS \u0938\u0902\u0938\u093E\u0927\u0928\u094B\u0902 \u092A\u0930 \u0928\u0948\u0926\u093E\u0928\u093F\u0915 \u0938\u0947\u091F\u093F\u0902\u0917\u094D\u0938 \u091C\u093E\u0901\u091A\u0947\u0902\u0964',
    azureSelectSubscriptionFirst: '\u092A\u0939\u0932\u0947 \u090F\u0915 \u0938\u0926\u0938\u094D\u092F\u0924\u093E \u091A\u0941\u0928\u0947\u0902\u0964',
    azureSelectWorkspaceFirst: '\u092A\u0939\u0932\u0947 \u090F\u0915 \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u091A\u0941\u0928\u0947\u0902\u0964',
    azureDomainRequired: '\u0921\u094B\u092E\u0947\u0928 \u0916\u094B\u091C \u0915\u094D\u0935\u0947\u0930\u0940 \u091A\u0932\u093E\u0928\u0947 \u0938\u0947 \u092A\u0939\u0932\u0947 \u0921\u094B\u092E\u0947\u0928 \u0926\u0930\u094D\u091C \u0915\u0930\u0947\u0902\u0964',
    azureWorkspaceInventory: '\u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u0938\u0942\u091A\u0940',
    azureDomainSearch: '\u0921\u094B\u092E\u0947\u0928 \u0916\u094B\u091C',
    azureAcsSearch: 'ACS \u0916\u094B\u091C',
    azureResultsSummary: '\u091F\u0948\u0928\u0947\u0902\u091F: {tenant} \u2022 \u0938\u0926\u0938\u094D\u092F\u0924\u093E: {subscription} \u2022 \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930: {workspace}',
    azureQueryReturnedNoTables: '\u0915\u094D\u0935\u0947\u0930\u0940 \u092A\u0942\u0930\u094D\u0923 \u0939\u0941\u0908 \u0932\u0947\u0915\u093F\u0928 \u0915\u094B\u0908 \u0924\u093E\u0932\u093F\u0915\u093E \u0928\u0939\u0940\u0902 \u0932\u094C\u091F\u0940\u0964',
    azureQueryFailed: 'Azure \u0915\u094D\u0935\u0947\u0930\u0940 \u0935\u093F\u092B\u0932: {reason}',
    azureDiscoverSuccess: '\u0916\u094B\u091C \u092A\u0942\u0930\u094D\u0923\u0964 \u090F\u0915 \u0915\u093E\u0930\u094D\u092F\u0915\u094D\u0937\u0947\u0924\u094D\u0930 \u091A\u0941\u0928\u0947\u0902 \u0914\u0930 \u0915\u094D\u0935\u0947\u0930\u0940 \u091A\u0932\u093E\u090F\u0901\u0964',
    azureSignedInAs: '{user} \u0915\u0947 \u0930\u0942\u092A \u092E\u0947\u0902 \u0938\u093E\u0907\u0928 \u0907\u0928 \u0915\u093F\u092F\u093E',
    azureConsentRequired: '\u0905\u0924\u093F\u0930\u093F\u0915\u094D\u0924 Azure \u0905\u0928\u0941\u092E\u0924\u093F\u092F\u093E\u0901 \u0906\u0935\u0936\u094D\u092F\u0915 \u0939\u0948\u0902\u0964 \u091C\u093E\u0930\u0940 \u0930\u0916\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F \u0938\u0939\u092E\u0924\u093F \u092A\u094D\u0930\u0949\u092E\u094D\u092A\u094D\u091F \u0938\u094D\u0935\u0940\u0915\u093E\u0930 \u0915\u0930\u0947\u0902\u0964',
    azureQueryTextLabel: '\u0928\u093F\u0937\u094D\u092A\u093E\u0926\u093F\u0924 \u0915\u094D\u0935\u0947\u0930\u0940',
    azureSwitchDirectory: '\u0928\u093F\u0930\u094D\u0926\u0947\u0936\u093F\u0915\u093E \u092C\u0926\u0932\u0947\u0902 (\u091F\u0948\u0928\u0947\u0902\u091F ID \u092F\u093E \u0921\u094B\u092E\u0947\u0928)',
    azureSwitchBtn: '\u092C\u0926\u0932\u0947\u0902'
  },
  'ja-JP': {
    guidanceIconInformational: '\u60C5\u5831',
    guidanceIconError: '\u30A8\u30E9\u30FC',
    guidanceIconAttention: '\u5BFE\u5FDC\u304C\u5FC5\u8981',
    guidanceIconSuccess: '\u6210\u529F',
    guidanceLegendAttention: '\u6CE8\u610F',
    guidanceLegendInformational: '\u60C5\u5831',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: 'Azure \u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u8A3A\u65AD',
    azureDiagnosticsHint: '\u30D6\u30E9\u30A6\u30B6\u30FC \u30BB\u30C3\u30B7\u30E7\u30F3\u304B\u3089\u76F4\u63A5 Azure \u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3068 Log Analytics \u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u3092\u7167\u4F1A\u3059\u308B\u306B\u306F\u3001\u30B5\u30A4\u30F3\u30A4\u30F3\u3057\u3066\u304F\u3060\u3055\u3044\u3002\u9867\u5BA2\u306E\u30AF\u30A8\u30EA \u30C7\u30FC\u30BF\u306F\u30ED\u30FC\u30AB\u30EB \u30B5\u30FC\u30D0\u30FC\u306B\u9001\u4FE1\u3055\u308C\u307E\u305B\u3093\u3002',
    azureSubscription: '\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3',
    azureAcsResource: 'ACS \u30EA\u30BD\u30FC\u30B9',
    azureWorkspace: '\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9',
    azureLoadSubscriptions: '\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3092\u8AAD\u307F\u8FBC\u3080',
    azureDiscoverResources: 'ACS \u30EA\u30BD\u30FC\u30B9\u3092\u691C\u51FA',
    azureDiscoverWorkspaces: '\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u3092\u691C\u51FA',
    azureRunInventory: '\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9 \u30A4\u30F3\u30D9\u30F3\u30C8\u30EA\u3092\u5B9F\u884C',
    azureRunDomainSearch: '\u30C9\u30E1\u30A4\u30F3\u691C\u7D22\u3092\u5B9F\u884C',
    azureRunAcsSearch: 'ACS \u691C\u7D22\u3092\u5B9F\u884C',
    azureSignInRequired: '\u30D6\u30E9\u30A6\u30B6\u30FC\u304B\u3089 Azure \u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3068 Log Analytics \u3092\u7167\u4F1A\u3059\u308B\u306B\u306F\u3001Microsoft \u3067\u30B5\u30A4\u30F3\u30A4\u30F3\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureLoadingSubscriptions: '\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3092\u8AAD\u307F\u8FBC\u3093\u3067\u3044\u307E\u3059...',
    azureLoadingTenants: '\u30C6\u30CA\u30F3\u30C8\u3092\u691C\u51FA\u3057\u3066\u3044\u307E\u3059...',
    azureLoadingTenantSubscriptions: '\u30C6\u30CA\u30F3\u30C8 {tenant} \u306E\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3092\u8AAD\u307F\u8FBC\u3093\u3067\u3044\u307E\u3059 ({current}/{total})...',
    azureFilteringAcsSubscriptions: 'ACS \u30EA\u30BD\u30FC\u30B9\u306E {current}/{total} \u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3092\u78BA\u8A8D\u3057\u3066\u3044\u307E\u3059...',
    azureLoadingResources: 'ACS \u30EA\u30BD\u30FC\u30B9\u3092\u691C\u51FA\u3057\u3066\u3044\u307E\u3059...',
    azureLoadingWorkspaces: '\u63A5\u7D9A\u3055\u308C\u305F\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u3092\u691C\u51FA\u3057\u3066\u3044\u307E\u3059...',
    azureRunningQuery: '\u30AF\u30A8\u30EA\u3092\u5B9F\u884C\u3057\u3066\u3044\u307E\u3059: {name}',
    azureNoSubscriptions: '\u3053\u306E\u30E6\u30FC\u30B6\u30FC\u306E Azure \u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u306F\u8FD4\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    azureNoResources: '\u9078\u629E\u3057\u305F\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u306B ACS \u30EA\u30BD\u30FC\u30B9\u304C\u898B\u3064\u304B\u308A\u307E\u305B\u3093\u3002',
    azureSubscriptionNotEnabled: '\u9078\u629E\u3057\u305F\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u306F {state} \u3067\u3059\u3002\u30EA\u30BD\u30FC\u30B9\u306E\u691C\u51FA\u306B\u306F\u6709\u52B9\u306A\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u304C\u5FC5\u8981\u3067\u3059\u3002',
    azureNoWorkspaces: '\u63A5\u7D9A\u3055\u308C\u305F Log Analytics \u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u304C\u898B\u3064\u304B\u308A\u307E\u305B\u3093\u3002\u9078\u629E\u3057\u305F ACS \u30EA\u30BD\u30FC\u30B9\u306E\u8A3A\u65AD\u8A2D\u5B9A\u3092\u78BA\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureSelectSubscriptionFirst: '\u6700\u521D\u306B\u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3\u3092\u9078\u629E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureSelectWorkspaceFirst: '\u6700\u521D\u306B\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u3092\u9078\u629E\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureDomainRequired: '\u30C9\u30E1\u30A4\u30F3\u691C\u7D22\u30AF\u30A8\u30EA\u3092\u5B9F\u884C\u3059\u308B\u524D\u306B\u30C9\u30E1\u30A4\u30F3\u3092\u5165\u529B\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureWorkspaceInventory: '\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9 \u30A4\u30F3\u30D9\u30F3\u30C8\u30EA',
    azureDomainSearch: '\u30C9\u30E1\u30A4\u30F3\u691C\u7D22',
    azureAcsSearch: 'ACS \u691C\u7D22',
    azureResultsSummary: '\u30C6\u30CA\u30F3\u30C8: {tenant} \u2022 \u30B5\u30D6\u30B9\u30AF\u30EA\u30D7\u30B7\u30E7\u30F3: {subscription} \u2022 \u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9: {workspace}',
    azureQueryReturnedNoTables: '\u30AF\u30A8\u30EA\u306F\u5B8C\u4E86\u3057\u307E\u3057\u305F\u304C\u3001\u30C6\u30FC\u30D6\u30EB\u306F\u8FD4\u3055\u308C\u307E\u305B\u3093\u3067\u3057\u305F\u3002',
    azureQueryFailed: 'Azure \u30AF\u30A8\u30EA\u304C\u5931\u6557\u3057\u307E\u3057\u305F: {reason}',
    azureDiscoverSuccess: '\u691C\u51FA\u304C\u5B8C\u4E86\u3057\u307E\u3057\u305F\u3002\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u3092\u9078\u629E\u3057\u3066\u30AF\u30A8\u30EA\u3092\u5B9F\u884C\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureSignedInAs: '{user} \u3068\u3057\u3066\u30B5\u30A4\u30F3\u30A4\u30F3\u4E2D',
    azureConsentRequired: '\u8FFD\u52A0\u306E Azure \u30A2\u30AF\u30BB\u30B9\u8A31\u53EF\u304C\u5FC5\u8981\u3067\u3059\u3002\u7D9A\u884C\u3059\u308B\u306B\u306F\u540C\u610F\u30D7\u30ED\u30F3\u30D7\u30C8\u3092\u627F\u8A8D\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
    azureQueryTextLabel: '\u5B9F\u884C\u3055\u308C\u305F\u30AF\u30A8\u30EA',
    azureSwitchDirectory: '\u30C7\u30A3\u30EC\u30AF\u30C8\u30EA\u306E\u5207\u308A\u66FF\u3048 (\u30C6\u30CA\u30F3\u30C8 ID \u307E\u305F\u306F\u30C9\u30E1\u30A4\u30F3)',
    azureSwitchBtn: '\u5207\u308A\u66FF\u3048'
  },
  'ru-RU': {
    guidanceIconInformational: '\u0418\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u044F',
    guidanceIconError: '\u041E\u0448\u0438\u0431\u043A\u0430',
    guidanceIconAttention: '\u0422\u0440\u0435\u0431\u0443\u0435\u0442 \u0432\u043D\u0438\u043C\u0430\u043D\u0438\u044F',
    guidanceIconSuccess: '\u0423\u0441\u043F\u0435\u0445',
    guidanceLegendAttention: '\u0412\u043D\u0438\u043C\u0430\u043D\u0438\u0435',
    guidanceLegendInformational: '\u0418\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u044F',
    azureTag: 'AZURE',
    azureDiagnosticsTitle: '\u0414\u0438\u0430\u0433\u043D\u043E\u0441\u0442\u0438\u043A\u0430 \u0440\u0430\u0431\u043E\u0447\u0435\u0439 \u043E\u0431\u043B\u0430\u0441\u0442\u0438 Azure',
    azureDiagnosticsHint: '\u0412\u043E\u0439\u0434\u0438\u0442\u0435, \u0447\u0442\u043E\u0431\u044B \u0437\u0430\u043F\u0440\u0430\u0448\u0438\u0432\u0430\u0442\u044C \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438 Azure \u0438 \u0440\u0430\u0431\u043E\u0447\u0438\u0435 \u043E\u0431\u043B\u0430\u0441\u0442\u0438 Log Analytics \u043F\u0440\u044F\u043C\u043E \u0438\u0437 \u0441\u0435\u0430\u043D\u0441\u0430 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430. \u0414\u0430\u043D\u043D\u044B\u0435 \u043A\u043B\u0438\u0435\u043D\u0442\u0441\u043A\u0438\u0445 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432 \u043D\u0435 \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u044F\u044E\u0442\u0441\u044F \u043D\u0430 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0439 \u0441\u0435\u0440\u0432\u0435\u0440.',
    azureSubscription: '\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430',
    azureAcsResource: '\u0420\u0435\u0441\u0443\u0440\u0441 ACS',
    azureWorkspace: '\u0420\u0430\u0431\u043E\u0447\u0430\u044F \u043E\u0431\u043B\u0430\u0441\u0442\u044C',
    azureLoadSubscriptions: '\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438',
    azureDiscoverResources: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0438\u0442\u044C \u0440\u0435\u0441\u0443\u0440\u0441\u044B ACS',
    azureDiscoverWorkspaces: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0438\u0442\u044C \u0440\u0430\u0431\u043E\u0447\u0438\u0435 \u043E\u0431\u043B\u0430\u0441\u0442\u0438',
    azureRunInventory: '\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0438\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u044E \u0440\u0430\u0431\u043E\u0447\u0435\u0439 \u043E\u0431\u043B\u0430\u0441\u0442\u0438',
    azureRunDomainSearch: '\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u043F\u043E\u0438\u0441\u043A \u0434\u043E\u043C\u0435\u043D\u0430',
    azureRunAcsSearch: '\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u043F\u043E\u0438\u0441\u043A ACS',
    azureSignInRequired: '\u0412\u043E\u0439\u0434\u0438\u0442\u0435 \u0447\u0435\u0440\u0435\u0437 Microsoft, \u0447\u0442\u043E\u0431\u044B \u0437\u0430\u043F\u0440\u0430\u0448\u0438\u0432\u0430\u0442\u044C \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438 Azure \u0438 Log Analytics \u0438\u0437 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430.',
    azureLoadingSubscriptions: '\u0417\u0430\u0433\u0440\u0443\u0437\u043A\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043E\u043A...',
    azureLoadingTenants: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435 \u0430\u0440\u0435\u043D\u0434\u0430\u0442\u043E\u0440\u043E\u0432...',
    azureLoadingTenantSubscriptions: '\u0417\u0430\u0433\u0440\u0443\u0437\u043A\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043E\u043A \u0430\u0440\u0435\u043D\u0434\u0430\u0442\u043E\u0440\u0430 {tenant} ({current}/{total})...',
    azureFilteringAcsSubscriptions: '\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 {current}/{total} \u043F\u043E\u0434\u043F\u0438\u0441\u043E\u043A \u043D\u0430 \u043D\u0430\u043B\u0438\u0447\u0438\u0435 \u0440\u0435\u0441\u0443\u0440\u0441\u043E\u0432 ACS...',
    azureLoadingResources: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435 \u0440\u0435\u0441\u0443\u0440\u0441\u043E\u0432 ACS...',
    azureLoadingWorkspaces: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D\u043D\u044B\u0445 \u0440\u0430\u0431\u043E\u0447\u0438\u0445 \u043E\u0431\u043B\u0430\u0441\u0442\u0435\u0439...',
    azureRunningQuery: '\u0412\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0438\u0435 \u0437\u0430\u043F\u0440\u043E\u0441\u0430: {name}',
    azureNoSubscriptions: '\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0438 Azure \u0434\u043B\u044F \u044D\u0442\u043E\u0433\u043E \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B.',
    azureNoResources: '\u0420\u0435\u0441\u0443\u0440\u0441\u044B ACS \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B \u0432 \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u043E\u0439 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0435.',
    azureSubscriptionNotEnabled: '\u0412\u044B\u0431\u0440\u0430\u043D\u043D\u0430\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u043D\u0430\u0445\u043E\u0434\u0438\u0442\u0441\u044F \u0432 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0438 {state}. \u0414\u043B\u044F \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u044F \u0440\u0435\u0441\u0443\u0440\u0441\u043E\u0432 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0430\u043A\u0442\u0438\u0432\u043D\u0430\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0430.',
    azureNoWorkspaces: '\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D\u043D\u044B\u0435 \u0440\u0430\u0431\u043E\u0447\u0438\u0435 \u043E\u0431\u043B\u0430\u0441\u0442\u0438 Log Analytics \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u043F\u0430\u0440\u0430\u043C\u0435\u0442\u0440\u044B \u0434\u0438\u0430\u0433\u043D\u043E\u0441\u0442\u0438\u043A\u0438 \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0445 \u0440\u0435\u0441\u0443\u0440\u0441\u043E\u0432 ACS.',
    azureSelectSubscriptionFirst: '\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443.',
    azureSelectWorkspaceFirst: '\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0440\u0430\u0431\u043E\u0447\u0443\u044E \u043E\u0431\u043B\u0430\u0441\u0442\u044C.',
    azureDomainRequired: '\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0434\u043E\u043C\u0435\u043D \u043F\u0435\u0440\u0435\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0438\u0435\u043C \u0437\u0430\u043F\u0440\u043E\u0441\u0430 \u043F\u043E\u0438\u0441\u043A\u0430 \u0434\u043E\u043C\u0435\u043D\u0430.',
    azureWorkspaceInventory: '\u0418\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u044F \u0440\u0430\u0431\u043E\u0447\u0435\u0439 \u043E\u0431\u043B\u0430\u0441\u0442\u0438',
    azureDomainSearch: '\u041F\u043E\u0438\u0441\u043A \u0434\u043E\u043C\u0435\u043D\u0430',
    azureAcsSearch: '\u041F\u043E\u0438\u0441\u043A ACS',
    azureResultsSummary: '\u0410\u0440\u0435\u043D\u0434\u0430\u0442\u043E\u0440: {tenant} \u2022 \u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430: {subscription} \u2022 \u0420\u0430\u0431\u043E\u0447\u0430\u044F \u043E\u0431\u043B\u0430\u0441\u0442\u044C: {workspace}',
    azureQueryReturnedNoTables: '\u0417\u0430\u043F\u0440\u043E\u0441 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D, \u043D\u043E \u043D\u0435 \u0432\u0435\u0440\u043D\u0443\u043B \u0442\u0430\u0431\u043B\u0438\u0446.',
    azureQueryFailed: '\u041E\u0448\u0438\u0431\u043A\u0430 \u0437\u0430\u043F\u0440\u043E\u0441\u0430 Azure: {reason}',
    azureDiscoverSuccess: '\u041E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u043E. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0440\u0430\u0431\u043E\u0447\u0443\u044E \u043E\u0431\u043B\u0430\u0441\u0442\u044C \u0438 \u0432\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 \u0437\u0430\u043F\u0440\u043E\u0441.',
    azureSignedInAs: '\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D \u043A\u0430\u043A {user}',
    azureConsentRequired: '\u0422\u0440\u0435\u0431\u0443\u044E\u0442\u0441\u044F \u0434\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043D\u0438\u044F Azure. \u041E\u0434\u043E\u0431\u0440\u0438\u0442\u0435 \u0437\u0430\u043F\u0440\u043E\u0441 \u0441\u043E\u0433\u043B\u0430\u0441\u0438\u044F \u0434\u043B\u044F \u043F\u0440\u043E\u0434\u043E\u043B\u0436\u0435\u043D\u0438\u044F.',
    azureQueryTextLabel: '\u0412\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u043D\u044B\u0439 \u0437\u0430\u043F\u0440\u043E\u0441',
    azureSwitchDirectory: '\u0421\u043C\u0435\u043D\u0438\u0442\u044C \u043A\u0430\u0442\u0430\u043B\u043E\u0433 (\u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u043E\u0440 \u0430\u0440\u0435\u043D\u0434\u0430\u0442\u043E\u0440\u0430 \u0438\u043B\u0438 \u0434\u043E\u043C\u0435\u043D)',
    azureSwitchBtn: '\u0421\u043C\u0435\u043D\u0438\u0442\u044C'
  }
};

Object.keys(GUIDANCE_AND_AZURE_OVERRIDES).forEach(code => {
  TRANSLATIONS[code] = Object.assign({}, TRANSLATIONS[code] || TRANSLATIONS.en, GUIDANCE_AND_AZURE_OVERRIDES[code]);
});

const LANG_PARAM = 'lang';
const LANGUAGE_OPTIONS = ['en', 'es', 'fr', 'de', 'pt-BR', 'ar', 'zh-CN', 'hi-IN', 'ja-JP', 'ru-RU'];
const RTL_LANGUAGES = new Set(['ar']);
const LANGUAGE_FLAG_URLS = {
  en: 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/us.svg',
  es: 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/es.svg',
  fr: 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/fr.svg',
  de: 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/de.svg',
  'pt-BR': 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/br.svg',
  ar: 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/sa.svg',
  'zh-CN': 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/cn.svg',
  'hi-IN': 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/in.svg',
  'ja-JP': 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/jp.svg',
  'ru-RU': 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3/ru.svg'
};

const LANGUAGE_DISPLAY_NAMES = {
  en: 'English',
  es: 'Espa\u00f1ol',
  fr: 'Fran\u00e7ais',
  de: 'Deutsch',
  'pt-BR': 'Portugu\u00eas (Brasil)',
  ar: '\u0627\u0644\u0639\u0631\u0628\u064a\u0629',
  'zh-CN': '\u4e2d\u6587\uff08\u7b80\u4f53\uff09',
  'hi-IN': '\u0939\u093f\u0928\u094d\u0926\u0940 (\u092d\u093e\u0930\u0924)',
  'ja-JP': '\u65e5\u672c\u8a9e\uff08\u65e5\u672c\uff09',
  'ru-RU': '\u0420\u0443\u0441\u0441\u043a\u0438\u0439 (\u0420\u043e\u0441\u0441\u0438\u044f)'
};

let currentLanguage = 'en';

let screenshotStatusToken = 0;
let lookupInProgress = false;
let lastAuthData = null;

let activeLookup = { runId: 0, controllers: [] };

'@
# ===== JavaScript Utility Functions =====
$htmlPage += @'
function normalizeLanguageCode(lang) {
  const value = String(lang || '').trim().toLowerCase();
  if (!value) return 'en';
  if (value === 'ptbr' || value.startsWith('pt-br') || value.startsWith('pt_br') || value.startsWith('pt')) return 'pt-BR';
  if (value.startsWith('es')) return 'es';
  if (value.startsWith('fr')) return 'fr';
  if (value.startsWith('de')) return 'de';
  if (value.startsWith('ar')) return 'ar';
  if (value === 'zh' || value.startsWith('zh-cn') || value.startsWith('zh_cn') || value.startsWith('zh-hans')) return 'zh-CN';
  if (value === 'hi' || value.startsWith('hi-in') || value.startsWith('hi_in')) return 'hi-IN';
  if (value === 'ja' || value.startsWith('ja-jp') || value.startsWith('ja_jp')) return 'ja-JP';
  if (value === 'ru' || value.startsWith('ru-ru') || value.startsWith('ru_ru')) return 'ru-RU';
  return 'en';
}

function isRtlLanguage(language) {
  return RTL_LANGUAGES.has(normalizeLanguageCode(language));
}

function getLanguageFromUrl() {
  try {
    const params = new URLSearchParams(window.location.search);
    const lang = params.get(LANG_PARAM) || params.get('language');
    return lang ? normalizeLanguageCode(lang) : null;
  } catch {
    return null;
  }
}

function updateLanguageUrlParameter() {
  try {
    const url = new URL(window.location.href);
    url.searchParams.set(LANG_PARAM, currentLanguage);
    window.history.replaceState({}, '', url);
  } catch {}
}

function getSavedLanguage() {
  try {
    return localStorage.getItem(LANG_KEY);
  } catch {
    return null;
  }
}

function detectLanguage() {
  const urlLanguage = getLanguageFromUrl();
  if (urlLanguage) return urlLanguage;
  const saved = getSavedLanguage();
  if (saved) return normalizeLanguageCode(saved);
  return normalizeLanguageCode(navigator.language || navigator.userLanguage || 'en');
}

function t(key, params = {}) {
  const langTable = TRANSLATIONS[currentLanguage] || TRANSLATIONS.en;
  let text = langTable[key] || TRANSLATIONS.en[key] || key;
  const resolved = String(text).replace(/\{(\w+)\}/g, (_, token) => {
    const value = Object.prototype.hasOwnProperty.call(params, token) ? params[token] : `{${token}}`;
    return value === null || value === undefined ? '' : String(value);
  });

  return stripUiEmoji(repairMojibake(resolved));
}

function looksLikeMojibake(text) {
  // Detect double-encoded UTF-8 misinterpreted as Latin-1/Windows-1252.
  // Lead-byte chars must be followed by continuation-byte chars (\u0080-\u00BF),
  // NOT arbitrary characters, to avoid false-positives on valid Portuguese/French
  // text like \u00E3o (\u00E3 + o) or \u00C3O (\u00C3 + O).
  return /(?:[\u00C2-\u00DF][\u0080-\u00BF]|[\u00E0-\u00EF][\u0080-\u00BF]{2}|[\u00F0-\u00F4][\u0080-\u00BF]{3})/.test(String(text || ''));
}

function repairMojibake(text) {
  const value = String(text || '');
  if (!looksLikeMojibake(value)) return value;

  try {
    const bytes = new Uint8Array(Array.from(value, ch => ch.charCodeAt(0) & 0xFF));
    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    if (decoded && !looksLikeMojibake(decoded)) return decoded;
  } catch {}

  try {
    const decoded = decodeURIComponent(escape(value));
    if (decoded && !looksLikeMojibake(decoded)) return decoded;
  } catch {}

  return value;
}

function repairObjectStrings(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return repairMojibake(value);
  if (Array.isArray(value)) return value.map(repairObjectStrings);
  if (typeof value === 'object') {
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = repairObjectStrings(entry);
    }
    return result;
  }
  return value;
}

function stripUiEmoji(text) {
  return String(text || '')
    .replace(/\uD83C\uDF19|\u2600\uFE0F?|\uD83D\uDD17|\uD83D\uDCF8|\uD83D\uDCE5|\uD83D\uDC1B|\uD83D\uDD12|\u23F3|\u274C|\uD83D\uDCA1/g, '')
    .replace(/\uFE0F/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

const UI_LABEL_ICONS = {
  themeDark: { icon: 'moon-star', className: 'icon-info' },
  themeLight: { icon: 'sun', className: 'icon-warning' },
  copyLink: { icon: 'link', className: 'icon-info' },
  copyScreenshot: { icon: 'camera', className: 'icon-info' },
  downloadJson: { icon: 'download', className: 'icon-success' },
  reportIssue: { icon: 'bug', className: 'icon-warning' },
  signInMicrosoft: { icon: 'lock-keyhole', className: 'icon-info' },
  guidance: { icon: 'lightbulb', className: 'icon-warning guidance-title-icon' }
};

function getLucideIconUrl(iconName) {
  return `https://cdn.jsdelivr.net/npm/lucide-static/icons/${iconName}.svg`;
}

function renderLabelWithIcon(key) {
  const config = UI_LABEL_ICONS[key];
  const text = escapeHtml(t(key));
  if (!config) return text;

  const iconHtml = `<img src="${getLucideIconUrl(config.icon)}" class="toolbar-icon ${config.className}" alt="" aria-hidden="true" />`;
  return `<span class="inline-label">${text}${iconHtml}</span>`;
}

function getLanguageDisplayName(code) {
  return repairMojibake(LANGUAGE_DISPLAY_NAMES[code] || ((TRANSLATIONS[code] && TRANSLATIONS[code].languageName) ? TRANSLATIONS[code].languageName : code));
}

function translateBadge(label) {
  const normalized = String(label || '').trim().toUpperCase();
  const map = {
    'CHECKLIST': 'checklist',
    'VERIFICATION': 'verificationTag',
    'DOCS': 'docs',
    'TOOLS': 'tools',
    'READINESS TIPS': 'readinessTips',
    'LOOKED UP': 'lookedUp',
    'LOADING': 'loading',
    'MISSING': 'missing',
    'OPTIONAL': 'optional',
    'INFO': 'info',
    'ERROR': 'error',
    'PASS': 'pass',
    'FAIL': 'fail',
    'WARN': 'warn',
    'PENDING': 'pending',
    'DNS ERROR': 'dnsError',
    'NEW DOMAIN': 'newDomain',
    'EXPIRED': 'expired'
  };
  return map[normalized] ? t(map[normalized]) : label;
}

function getLanguageButtonHtml(code) {
  const flagUrl = LANGUAGE_FLAG_URLS[code] || '';
  const name = getLanguageDisplayName(code);
  const safeName = escapeHtml(name);
  const flagHtml = flagUrl ? `<img class="language-flag" src="${escapeHtml(flagUrl)}" alt="" loading="lazy" />` : '';
  return `${flagHtml}<span>${safeName}</span><span class="caret">&#x25BE;</span>`;
}

function closeLanguageMenu() {
  const menu = document.getElementById('languageSelectMenu');
  const button = document.getElementById('languageSelectBtn');
  if (menu) menu.classList.remove('open');
  if (button) button.setAttribute('aria-expanded', 'false');
}

function toggleLanguageMenu() {
  const menu = document.getElementById('languageSelectMenu');
  const button = document.getElementById('languageSelectBtn');
  if (!menu || !button) return;
  const willOpen = !menu.classList.contains('open');
  menu.classList.toggle('open', willOpen);
  button.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
}

function populateLanguageSelect() {
  const button = document.getElementById('languageSelectBtn');
  const menu = document.getElementById('languageSelectMenu');
  if (!button || !menu) return;

  button.innerHTML = getLanguageButtonHtml(currentLanguage);
  button.setAttribute('aria-label', `${t('languageLabel')}: ${getLanguageDisplayName(currentLanguage)}`);

  menu.innerHTML = LANGUAGE_OPTIONS.map(code => {
    const selected = code === currentLanguage ? ' active' : '';
    return `<button type="button" class="language-option${selected}" role="option" aria-selected="${code === currentLanguage ? 'true' : 'false'}" onclick="changeLanguage('${code}')">${getLanguageButtonHtml(code).replace('<span class="caret">&#x25BE;</span>', '')}</button>`;
  }).join('');
}

function applyLanguageToStaticUi() {
  document.documentElement.lang = currentLanguage;
  document.documentElement.dir = isRtlLanguage(currentLanguage) ? 'rtl' : 'ltr';
  document.title = t('pageTitle');

  const heading = document.getElementById('appHeading');
  if (heading) heading.innerHTML = t('appHeading');

  const input = document.getElementById('domainInput');
  if (input) input.placeholder = t('placeholderDomain');

  const lookupBtn = document.getElementById('lookupBtn');
  if (lookupBtn) {
    lookupBtn.innerHTML = lookupInProgress
      ? `${escapeHtml(t('checkingShort'))} <span class="spinner"></span>`
      : t('lookup');
  }

  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn) {
    themeBtn.innerHTML = document.documentElement.classList.contains('dark') ? renderLabelWithIcon('themeLight') : renderLabelWithIcon('themeDark');
  }

  const copyLinkBtn = document.getElementById('copyLinkBtn');
  if (copyLinkBtn) copyLinkBtn.innerHTML = renderLabelWithIcon('copyLink');

  const screenshotBtn = document.getElementById('screenshotBtn');
  if (screenshotBtn) screenshotBtn.innerHTML = renderLabelWithIcon('copyScreenshot');

  const downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) downloadBtn.innerHTML = renderLabelWithIcon('downloadJson');

  const reportBtn = document.getElementById('reportIssueBtn');
  if (reportBtn) reportBtn.innerHTML = renderLabelWithIcon('reportIssue');
  if (reportBtn) reportBtn.title = t('reportIssueTitle');

  const signInBtn = document.getElementById('msSignInBtn');
  if (signInBtn && signInBtn.style.display !== 'none') signInBtn.innerHTML = renderLabelWithIcon('signInMicrosoft');

  const signOutBtn = document.getElementById('msSignOutBtn');
  if (signOutBtn) signOutBtn.innerHTML = t('signOut');

  const azureTag = document.getElementById('azureDiagnosticsTag');
  if (azureTag) azureTag.textContent = t('azureTag');

  const azureTitle = document.getElementById('azureDiagnosticsTitle');
  if (azureTitle) azureTitle.textContent = t('azureDiagnosticsTitle');

  const azureHint = document.getElementById('azureDiagnosticsHint');
  if (azureHint) azureHint.textContent = t('azureDiagnosticsHint');

  const azureSubscriptionLabel = document.getElementById('azureSubscriptionLabel');
  if (azureSubscriptionLabel) azureSubscriptionLabel.textContent = t('azureSubscription');

  const azureSwitchDirectoryLabel = document.getElementById('azureSwitchDirectoryLabel');
  if (azureSwitchDirectoryLabel) azureSwitchDirectoryLabel.textContent = t('azureSwitchDirectory');
  const azureSwitchDirectoryBtn = document.getElementById('azureSwitchDirectoryBtn');
  if (azureSwitchDirectoryBtn) azureSwitchDirectoryBtn.textContent = t('azureSwitchBtn');

  const azureResourceLabel = document.getElementById('azureResourceLabel');
  if (azureResourceLabel) azureResourceLabel.textContent = t('azureAcsResource');

  const azureWorkspaceLabel = document.getElementById('azureWorkspaceLabel');
  if (azureWorkspaceLabel) azureWorkspaceLabel.textContent = t('azureWorkspace');

  const azureRunInventoryBtn = document.getElementById('azureRunInventoryBtn');
  if (azureRunInventoryBtn) azureRunInventoryBtn.textContent = t('azureRunInventory');

  const azureRunDomainSearchBtn = document.getElementById('azureRunDomainSearchBtn');
  if (azureRunDomainSearchBtn) azureRunDomainSearchBtn.textContent = t('azureRunDomainSearch');

  const azureRunAcsSearchBtn = document.getElementById('azureRunAcsSearchBtn');
  if (azureRunAcsSearchBtn) azureRunAcsSearchBtn.textContent = t('azureRunAcsSearch');

  const footer = document.getElementById('footerText');
  if (footer) {
    let footerHtml = t('footer', { version: appVersion });
    const langSuffix = currentLanguage ? '?lang=' + encodeURIComponent(currentLanguage) : '';
    footerHtml += ' &bull; <a href="/terms' + langSuffix + '" target="_blank" rel="noopener" style="color:inherit;">' + escapeHtml(t('termsOfService')) + '</a>';
    footerHtml += ' &bull; <a href="/privacy' + langSuffix + '" target="_blank" rel="noopener" style="color:inherit;">' + escapeHtml(t('privacyStatement')) + '</a>';
    footer.innerHTML = footerHtml;
  }

  populateLanguageSelect();
  loadHistory();
  renderAzureDiagnosticsUi();

  if (typeof updateAuthUI === 'function') {
    updateAuthUI(lastAuthData);
  }
}

function applyLanguage(language, persist = true) {
  currentLanguage = normalizeLanguageCode(language);
  if (persist) {
    try { localStorage.setItem(LANG_KEY, currentLanguage); } catch {}
  }
  updateLanguageUrlParameter();
  applyLanguageToStaticUi();
  closeLanguageMenu();
  if (lastResult) {
    // Rebuild derived, language-sensitive strings before rendering cached results again.
    recomputeDerived(lastResult);
    render(lastResult);
  }
}

function changeLanguage(language) {
  applyLanguage(language, true);
}

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
    const removeLabel = escapeHtml(t('removeLabel'));
    return `<span class="history-chip" data-domain="${key}">
      <span class="history-item" onclick='runHistory(${arg})'>${safe}</span>
      <button type="button" class="history-remove" title="${removeLabel}" aria-label="${removeLabel}" onclick='event.stopPropagation(); removeHistory(${arg})'>&#x2715;</button>
    </span>`;
  }).join(" ");
  container.innerHTML = escapeHtml(t('recent')) + ": " + chips;
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
        const buttonText = (b.textContent || "").trim();
        if (buttonText === t('additionalDetailsPlus') || buttonText === t('additionalDetailsMinus') || buttonText.startsWith('Additional Details')) {
          b.textContent = t('additionalDetailsPlus');
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

function linkifyText(text) {
  const escaped = escapeHtml(text);
  return escaped.replace(/(https?:\/\/[^\s<]+)/gi, function(url) {
    return `<a href="${url}" target="_blank" rel="noopener">${url}</a>`;
  });
}

function escapeRegex(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function applyCheckedDomainEmphasis(html, checkedDomain) {
  const domain = String(checkedDomain || '').trim();
  if (!domain) return String(html || '');

  const escapedDomain = escapeHtml(domain);
  if (!escapedDomain) return String(html || '');

  return String(html || '').replace(new RegExp(escapeRegex(escapedDomain), 'gi'), '<em class="checked-domain">$&</em>');
}

function formatGuidanceText(text, checkedDomain) {
  let value = String(text || '');
  const protectedTokens = [];

  const protect = (pattern) => {
    value = value.replace(pattern, (match) => {
      const token = `__GUIDANCE_CODE_${protectedTokens.length}__`;
      protectedTokens.push(match);
      return token;
    });
  };

  protect(/v=spf1\s+include:spf\.protection\.outlook\.com\s+-all/gi);
  protect(/\b(?:p|sp)=(?:none|quarantine|reject)\b/gi);
  protect(/\bpct=\d+\b/gi);
  protect(/\b(?:adkim|aspf)=[rs]\b/gi);
  protect(/\b(?:rua|ruf)=\b/gi);
  protect(/_dmarc\.[a-z0-9.-]+/gi);
  protect(/\binclude:spf\.protection\.outlook\.com\b/gi);
  protect(/\bspf\.protection\.outlook\.com\b/gi);
  protect(/\b_spf\.google\.com\b/gi);
  protect(/\binclude:zoho\.com\b/gi);
  protect(/\bms-domain-verification\b/gi);
  protect(/\bselector[12]-azurecomm-prod-net\b/gi);

  let formatted = linkifyText(value);
  formatted = formatted.replace(/`([^`]+)`/g, '<code class="guidance-code">$1</code>');
  formatted = applyCheckedDomainEmphasis(formatted, checkedDomain);
  formatted = formatted.replace(/__GUIDANCE_CODE_(\d+)__/g, (_, index) => {
    const token = protectedTokens[Number(index)] || '';
    return `<code class="guidance-code">${escapeHtml(token)}</code>`;
  });

  return formatted;
}

function formatLocalDateTime(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return null;

  try {
    return new Intl.DateTimeFormat(currentLanguage, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short'
    }).format(d);
  } catch {
    return d.toLocaleString();
  }
}

function formatLocalizedCount(count, singularKey, pluralKey) {
  const value = Number.parseInt(count, 10);
  if (!Number.isFinite(value)) return String(count || '');
  return `${value} ${t(value === 1 ? singularKey : pluralKey)}`;
}

function localizeDurationText(text) {
  const source = String(text || '').trim();
  if (!source) return source;
  if (/^expired$/i.test(source)) return t('wordExpired');

  const parts = [];
  const regex = /(\d+)\s+(year|years|month|months|day|days)/gi;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const count = Number.parseInt(match[1], 10);
    const unit = match[2].toLowerCase();
    if (unit.startsWith('year')) parts.push(formatLocalizedCount(count, 'unitYearOne', 'unitYearMany'));
    else if (unit.startsWith('month')) parts.push(formatLocalizedCount(count, 'unitMonthOne', 'unitMonthMany'));
    else if (unit.startsWith('day')) parts.push(formatLocalizedCount(count, 'unitDayOne', 'unitDayMany'));
  }

  return parts.length > 0 ? parts.join(', ') : source;
}

function localizeMxRecordText(text) {
  return String(text || '').replace(/\(Priority\s+(\d+)\)/gi, `(${t('mxPriorityLabel')} $1)`);
}

function localizeRiskSummary(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'clean') return t('riskClean');
  if (normalized === 'warning') return t('riskWarning');
  if (normalized === 'elevatedrisk') return t('riskElevated');
  return value || t('unknown');
}

function localizeWhoisStatus(status) {
  const normalized = String(status || '').trim().toLowerCase();
  if (!normalized) return '';
  if (normalized === 'expired') return t('expired');
  return status;
}

function getLocalizedSpfRequirementSummary(result) {
  if (!result || !result.spfPresent) return null;
  if (result.spfHasRequiredInclude === false) return t('spfOutlookRequirementMissing');
  if (result.spfHasRequiredInclude === true) return t('spfOutlookRequirementPresent');
  return null;
}

function stripSpfRequirementSection(text) {
  const source = String(text || '');
  if (!source) return '';
  return source.replace(/\r?\n\r?\nACS Outlook SPF requirement:\r?\n[\s\S]*$/i, '').trim();
}

function getLocalizedMxProviderHint(provider, fallbackHint) {
  switch (String(provider || '')) {
    case 'Microsoft 365 / Exchange Online': return t('providerHintMicrosoft365');
    case 'Google Workspace / Gmail': return t('providerHintGoogleWorkspace');
    case 'Cloudflare Email Routing': return t('providerHintCloudflare');
    case 'Proofpoint': return t('providerHintProofpoint');
    case 'Mimecast': return t('providerHintMimecast');
    case 'Zoho Mail': return t('providerHintZoho');
    case 'Unknown': return t('providerHintUnknown');
    default: return fallbackHint || '';
  }
}

function getDmarcSecurityGuidance(dmarcRecord, domain, lookupDomain, inherited) {
  const guidance = [];
  if (!dmarcRecord) return guidance;

  const tags = {};
  String(dmarcRecord).split(';').forEach(part => {
    const text = String(part || '').trim();
    if (!text) return;
    const idx = text.indexOf('=');
    if (idx < 1) return;
    const name = text.slice(0, idx).trim().toLowerCase();
    const value = text.slice(idx + 1).trim();
    if (name) tags[name] = value;
  });

  const targetDomain = domain || lookupDomain || 'the domain';
  const policy = (tags.p || '').trim().toLowerCase();
  const subdomainPolicy = (tags.sp || '').trim().toLowerCase();
  const pct = Number.parseInt((tags.pct || '').trim(), 10);
  const adkim = (tags.adkim || '').trim().toLowerCase();
  const aspf = (tags.aspf || '').trim().toLowerCase();
  const rua = (tags.rua || '').trim();
  const ruf = (tags.ruf || '').trim();

  if (policy === 'none') {
    guidance.push({ type: 'attention', text: t('dmarcMonitorOnly', { domain: targetDomain }) });
  } else if (policy === 'quarantine') {
    guidance.push({ type: 'attention', text: t('dmarcQuarantine', { domain: targetDomain }) });
  }

  if (Number.isFinite(pct) && pct >= 0 && pct < 100) {
    guidance.push({ type: 'attention', text: t('dmarcPct', { domain: targetDomain, pct }) });
  }

  if (adkim === 'r') {
    guidance.push({ type: 'info', text: t('dmarcAdkimRelaxed', { domain: targetDomain }) });
  }

  if (aspf === 'r') {
    guidance.push({ type: 'info', text: t('dmarcAspfRelaxed', { domain: targetDomain }) });
  }

  if (domain && lookupDomain && inherited === true && lookupDomain !== domain && !Object.prototype.hasOwnProperty.call(tags, 'sp')) {
    guidance.push({ type: 'attention', text: t('dmarcMissingSp', { lookupDomain, domain }) });
  }

  if (!rua) {
    guidance.push({ type: 'attention', text: t('dmarcMissingRua', { domain: targetDomain }) });
  }

  if (!ruf) {
    guidance.push({ type: 'info', text: t('dmarcMissingRuf', { domain: targetDomain }) });
  }

  return guidance;
}

function buildGuidance(r) {
  const guidance = [];
  const loaded = r && r._loaded ? r._loaded : {};
  const dmarcHelpUrl = 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records';

  if (loaded.base && r.dnsFailed) {
    guidance.push({ type: 'error', text: t('guidanceDnsTxtFailed') });
    return guidance;
  }

  if (loaded.base) {
    if (!r.spfPresent) {
      if (r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceSpfMissingParent', { domain: r.domain || '', lookupDomain: r.txtLookupDomain }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceSpfMissing') });
      }
    }
    if (r.spfPresent && r.spfHasRequiredInclude !== true) {
      guidance.push({ type: 'attention', text: t('spfOutlookRequirementMissing') });
    }
    if (!r.acsPresent) {
      if (r.parentAcsPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceAcsMissingParent', { domain: r.domain || '', lookupDomain: r.txtLookupDomain }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceAcsMissing') });
      }
    }
  }

  if (loaded.mx) {
    const mxList = r.mxRecords || [];
    const hasMx = Array.isArray(mxList) && mxList.length > 0;
    if (!hasMx) {
      if (r.mxFallbackDomainChecked && r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
        guidance.push({ type: 'attention', text: t('guidanceMxMissingParentFallback', { domain: r.domain || '', lookupDomain: r.mxLookupDomain }) });
      } else if (r.mxFallbackDomainChecked && !r.mxFallbackUsed) {
        guidance.push({ type: 'attention', text: t('guidanceMxMissingCheckedParent', { domain: r.domain || '', parentDomain: r.mxFallbackDomainChecked }) });
      } else {
        guidance.push({ type: 'attention', text: t('guidanceMxMissing') });
      }
    } else if (r.mxFallbackUsed && r.mxLookupDomain && r.mxLookupDomain !== r.domain) {
      guidance.push({ type: 'info', text: t('guidanceMxParentShown', { domain: r.domain || '', lookupDomain: r.mxLookupDomain }) });
    }
    if (r.mxProvider && r.mxProvider !== 'Unknown') {
      guidance.push({ type: 'info', text: t('guidanceMxProviderDetected', { provider: r.mxProvider }) });
    }
  }

  if (loaded.whois) {
    if (r.whoisIsExpired === true) {
      guidance.push({ type: 'attention', text: t('guidanceDomainExpired') });
    } else if (r.whoisIsVeryYoungDomain === true) {
      const d = r.whoisNewDomainErrorThresholdDays || 90;
      guidance.push({ type: 'attention', text: t('guidanceDomainVeryYoung', { days: String(d) }) });
    } else if (r.whoisIsYoungDomain === true) {
      const d = r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180;
      guidance.push({ type: 'attention', text: t('guidanceDomainYoung', { days: String(d) }) });
    }
  }

  if (loaded.dmarc && !r.dmarc) {
    guidance.push({ type: 'attention', text: t('guidanceDmarcMissing', { domain: r.domain || '' }) });
  } else if (loaded.dmarc && r.dmarc && r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain) {
    guidance.push({ type: 'info', text: t('guidanceDmarcInherited', { lookupDomain: r.dmarcLookupDomain }) });
  }

  let dmarcActionable = false;
  if (loaded.dmarc && r.dmarc) {
    const dmarcSecurityGuidance = getDmarcSecurityGuidance(r.dmarc, r.domain, r.dmarcLookupDomain, r.dmarcInherited === true);
    if (dmarcSecurityGuidance.length > 0) dmarcActionable = true;
    guidance.push(...dmarcSecurityGuidance);
  }

  if ((loaded.dmarc && !r.dmarc) || dmarcActionable) {
    guidance.push({ type: 'info', text: t('guidanceDmarcMoreInfo', { url: dmarcHelpUrl }) });
  }

  if (loaded.dkim) {
    if (!r.dkim1) guidance.push({ type: 'attention', text: t('guidanceDkim1Missing') });
    if (!r.dkim2) guidance.push({ type: 'attention', text: t('guidanceDkim2Missing') });
  }

  if (loaded.cname && !r.cname) {
    guidance.push({ type: 'attention', text: t('guidanceCnameMissing') });
  }

  if (loaded.base && loaded.mx && r.mxProvider === 'Microsoft 365 / Exchange Online' && r.spfPresent && r.spfHasRequiredInclude === false) {
    guidance.push({ type: 'attention', text: t('guidanceMxMicrosoftSpf') });
  }
  if (loaded.base && loaded.mx && r.mxProvider === 'Google Workspace / Gmail' && r.spfPresent && r.spfValue && !/_spf\.google\.com/i.test(r.spfValue)) {
    guidance.push({ type: 'attention', text: t('guidanceMxGoogleSpf') });
  }
  if (loaded.base && loaded.mx && r.mxProvider === 'Zoho Mail' && r.spfPresent && r.spfValue && !/include:zoho\.com/i.test(r.spfValue)) {
    guidance.push({ type: 'attention', text: t('guidanceMxZohoSpf') });
  }

  if (loaded.base && r.acsReady) {
    guidance.push({ type: 'success', text: t('acsReadyMessage') });
  }

  return guidance;
}

function recomputeDerived(r) {
  const loaded = r && r._loaded ? r._loaded : {};
  if (loaded.base) {
    r.acsReady = (!r.dnsFailed) && !!r.acsPresent;
  } else {
    r.acsReady = false;
  }
  r.guidance = buildGuidance(r);
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
    add("SPF (queried domain TXT)", "pending");
    add("ACS TXT", "pending");
    add("TXT Records", "pending");
  } else if (errors.base) {
    add("SPF (queried domain TXT)", "error");
    add("ACS TXT", "error");
    add("TXT Records", "error");
  } else if (r.dnsFailed) {
    add("SPF (queried domain TXT)", "unavailable", true);
    add("ACS TXT", "fail");
    add("TXT Records", "unavailable", true);
  } else {
    add("SPF (queried domain TXT)", (r.spfPresent && r.spfHasRequiredInclude === true) ? "pass" : "fail", true);
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
    if (btn) btn.innerHTML = renderLabelWithIcon('themeLight');
  } else {
    root.classList.remove("dark");
    if (btn) btn.innerHTML = renderLabelWithIcon('themeDark');
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

document.addEventListener('click', (e) => {
  const dropdown = document.getElementById('languageDropdown');
  if (!dropdown) return;
  if (!dropdown.contains(e.target)) {
    closeLanguageMenu();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeLanguageMenu();
  }
});

function copyShareLink() {
  const btn = document.getElementById("copyLinkBtn");
  if (!navigator.clipboard) {
    setStatus(t('clipboardUnavailable'));
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
  url.searchParams.set(LANG_PARAM, currentLanguage);

  navigator.clipboard.writeText(url.toString())
    .then(() => {
      if (btn) {
        const original = btn.innerHTML;
        btn.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { btn.innerHTML = original; }, 2000);
      } else {
        setStatus(t('linkCopiedToClipboard'));
      }
    })
    .catch(() => setStatus(t('failedCopyLink')));
}

function copyText(text, btn) {
  const payload = text;
  const plain = (payload && typeof payload === 'object' && payload !== null)
    ? (payload.plain ?? payload.text ?? '')
    : ((payload === null || payload === undefined) ? "" : String(payload));
  const html = (payload && typeof payload === 'object' && payload !== null) ? payload.html : null;

  if (!navigator.clipboard) {
    setStatus(t('clipboardUnavailable'));
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
        btn.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      } else {
        setStatus(t('copiedToClipboard'));
      }
    })
    .catch(() => setStatus(t('failedCopyToClipboard')));
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
    setStatus(t('nothingToCopyFor', { field: fieldKey }));
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
    setStatus(t('clipboardUnavailable'));
    return;
  }
  navigator.clipboard.writeText(text)
    .then(() => {
      if (button && button.tagName === "BUTTON") {
        const originalText = button.innerHTML;
        button.innerHTML = escapeHtml(t('copied'));
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
      } else {
        setStatus(t('copiedFieldToClipboard', { field: fieldKey }));
      }
    })
    .catch(() => setStatus(t('failedCopyFieldToClipboard', { field: fieldKey })));
}

function screenshotPage() {
  if (!window.html2canvas || !navigator.clipboard || typeof ClipboardItem === "undefined") {
    setStatus(t('screenshotClipboardUnsupported'));
    return;
  }

  const statusEl = document.getElementById("status");
  const previousStatusHtml = statusEl ? statusEl.innerHTML : "";
  const myToken = ++screenshotStatusToken;

  // Capture only the container div instead of the entire body
  const container = document.querySelector(".container");
  if (!container) {
    setStatus(t('screenshotContainerNotFound'));
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
        setStatus(t('screenshotCaptureFailed'));
        return;
      }
      const item = new ClipboardItem({ "image/png": blob });
      navigator.clipboard.write([item])
        .then(() => {
          setStatus(t('screenshotCopiedToClipboard'));
          setTimeout(() => {
            if (myToken !== screenshotStatusToken) return;
            const el = document.getElementById("status");
            if (el && el.innerHTML === t('screenshotCopiedToClipboard')) {
              el.innerHTML = previousStatusHtml;
            }
          }, 2500);
        })
        .catch(() => setStatus(t('failedCopyScreenshot')));
    });
  }).catch(() => {
    setStatus(t('screenshotRenderFailed'));
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
    if (appVersion && !appVersion.startsWith('__')) {
      url.searchParams.set('environment-version', appVersion);
    }
    return url.toString();
  } catch {
    return null;
  }
}

function reportIssue() {
  const domain = normalizeDomain((document.getElementById("domainInput") || {}).value || "");
  const targetUrl = buildIssueUrl(domain);
  if (!targetUrl) {
    setStatus(t('issueReportingNotConfigured'));
    return;
  }

  const detail = domain ? t('issueReportDetailDomain', { domain }) : t('issueReportDetailInput');
  const ok = window.confirm(t('issueReportConfirm', { detail }));
  if (!ok) return;

  window.open(targetUrl, '_blank', 'noopener');
}

'@
# ===== JavaScript Core UI (Lookup, Render, Events) =====
$htmlPage += @'
function lookup() {
  const input = document.getElementById("domainInput");
  const btn   = document.getElementById("lookupBtn");
  const screenshotBtn = document.getElementById("screenshotBtn");
  const dlBtn = document.getElementById("downloadBtn");
  const domain = normalizeDomain(input.value);
  input.value = domain;
  toggleClearBtn();

  if (!domain) {
    setStatus(t('promptEnterDomain'));
    return;
  }

  if (!isValidDomain(domain)) {
    setStatus(t('promptEnterValidDomain'));
    return;
  }

  // Cancel any previous lookup's requests and start a new run
  const runId = ++activeLookup.runId;
  cancelInflightLookup();

  // Clear previous results and hide download button
  document.getElementById("results").innerHTML = "";
  setStatus("");
  if (dlBtn) dlBtn.style.display = "none";
  lookupInProgress = true;

  const url = new URL(window.location.href);
  url.searchParams.set("domain", domain);
  url.searchParams.set(LANG_PARAM, currentLanguage);
  window.history.replaceState({}, "", url);

  // Keep Lookup clickable so another click can cancel/restart
  btn.disabled = false;
  if (screenshotBtn) screenshotBtn.disabled = true;
  btn.innerHTML = `${escapeHtml(t('checkingShort'))} <span class="spinner"></span>`;
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
      const raw = await r.arrayBuffer();
      const text = new TextDecoder('utf-8', { fatal: false }).decode(raw);
      return repairObjectStrings(JSON.parse(text));
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
      lastResult._loaded = { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false };
    }
    if (!lastResult._errors) {
      lastResult._errors = {};
    }
  }

  ensureResultObject();
  lastResult = {
    domain,
    _loaded: { base: false, mx: false, whois: false, dmarc: false, dkim: false, cname: false, reputation: false },
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
        lastResult.whoisLookupDomain = data.lookupDomain;
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
      lookupInProgress = false;
      btn.disabled = false;
      if (screenshotBtn) screenshotBtn.disabled = false;
      btn.innerHTML = t('lookup');
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
  const checkedDomain = (lastResult && lastResult.domain) ? String(lastResult.domain) : '';
  // Always escape the title text to prevent XSS via crafted DNS responses.
  // Use titleSuffixHtml for trusted HTML additions (e.g., info-dot buttons, links).
  const safeTitle = applyCheckedDomainEmphasis(escapeHtml(title), checkedDomain);
  const safeValue = applyCheckedDomainEmphasis(escapeHtml(value || t('noRecordsAvailable')), checkedDomain);
  const translatedLabel = label ? escapeHtml(translateBadge(label)) : "";
  return `
  <div class="card"${cardId ? ` id="${cardId}"` : ''}>
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      ${label ? `<span class="tag ${cls}">${translatedLabel}</span>` : ""}
      <strong>${safeTitle}</strong>${titleSuffixHtml ? ' ' + titleSuffixHtml : ''}
      ${showCopy ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, '${key}')">${escapeHtml(t('copy'))}</button>` : ""}
    </div>
    <div id="field-${key}" class="code card-content">${safeValue}</div>
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
    element.textContent = t('additionalDetailsMinus');
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === "none");
  if (isOpen) {
    element.textContent = t('additionalDetailsMinus');
  } else {
    element.textContent = t('additionalDetailsPlus');
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
    statusText = escapeHtml(t('statusChecking', { domain: r.domain || '' }));
  } else if (anyError) {
    statusText = escapeHtml(t('statusSomeChecksFailed'));
  } else if (loaded.base && r.dnsFailed) {
    statusText = escapeHtml(t('statusTxtFailed'));
  } else {
    // Determine overall status for Email Quota and Domain Verification

    // Domain Verification: strictly based on ACS readiness (ms-domain-verification TXT)
    let domainVerStatus = `${escapeHtml(t('failed'))} &#x274C;`;
    if (r.acsReady) {
      domainVerStatus = `${escapeHtml(t('passing'))} &#x2705;`;
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
    if (!r.spfPresent || r.spfHasRequiredInclude !== true) { quotaFail = true; }

    let emailQuotaStatus = `${escapeHtml(t('passing'))} &#x2705;`;
    if (quotaFail) {
        emailQuotaStatus = `${escapeHtml(t('failed'))} &#x274C;`;
    } else if (quotaWarn) {
        emailQuotaStatus = `${escapeHtml(t('warningState'))} &#x26A0;&#xFE0F;`;
    }

    statusText = `${escapeHtml(t('emailQuota'))}: ${emailQuotaStatus} | ${escapeHtml(t('domainVerification'))}: ${domainVerStatus}`;
  }

  const statusWithTime = gatheredAtLocal
    ? `${statusText}<div style="font-size:12px;color:var(--status);margin-top:2px;">${escapeHtml(t('statusCollectedOn', { value: gatheredAtLocal }))}</div>`
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
    const stateKeyMap = { pass: 'pass', fail: 'fail', error: 'error', warn: 'warn', pending: 'pending' };
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(t(stateKeyMap[state] || String(state || '').toLowerCase()))}</span>`;
    const nameHtml = escapeHtml(name)
      + (infoTitle ? ` <button type="button" class="info-dot" aria-label="${escapeHtml(infoTitle)}" data-info="${escapeHtml(infoTitle)}">i</button>` : "")
      + (extraHtml ? ` ${extraHtml}` : '');
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">${escapeHtml(t('view'))}</button>` : '';
    return `<div class="status-row"><span class="status-name">${nameHtml}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  let mxCopyDetail = '';
  let repCopyDetail = '';
  let repStats = null;
  const localizedWhoisAgeHuman = localizeDurationText(r.whoisAgeHuman);
  const localizedWhoisExpiryHuman = r.whoisIsExpired === true ? t('wordExpired') : localizeDurationText(r.whoisExpiryHuman);

  const domainForCopy = r.domain || '';
  quotaLines.push(`**${t('emailQuota')} (${t('domainNameLabel')}):** ${domainForCopy}`.trim());
  quotaLinesHtml.push(`<strong>${escapeHtml(t('emailQuota'))} (${escapeHtml(t('domainNameLabel'))}):</strong> ${escapeHtml(domainForCopy)}`.trim());
  quotaCopyPlainLines.push(`${t('domainNameLabel')}: ${domainForCopy}`);
  quotaCopyPlainLines.push('----------------------------------');
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainNameLabel'))}:</strong> ${escapeHtml(domainForCopy)}</div>`);
  quotaCopyHtmlLines.push('<div>----------------------------------</div>');


  // 1) MX Records
  let mxStatusText = '';
    if (!loaded.mx && !errors.mx) {
    mxCopyDetail = t('checkingMxRecords');
    quotaItems.push(quotaRow(t('mxRecords'), 'pending', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** PENDING${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> PENDING${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = t('checkingValue');
  } else if (errors.mx) {
    mxCopyDetail = errors.mx;
    quotaItems.push(quotaRow(t('mxRecords'), 'error', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ERROR${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ERROR${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = t('error');
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    const mxRecordsText = (r.mxRecords || []).join(', ');
    if (hasMx) {
      let note = '';
      if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
        note = ` ${t('mxUsingParentNote', { lookupDomain: mxLookupDomain })}`;
      }
      mxCopyDetail = localizeMxRecordText(mxRecordsText || t('mxRecords')) + note;
    } else {
      mxCopyDetail = t('noMxRecordsDetected');
      if (mxFallbackChecked && mxFallbackChecked !== r.domain) {
        mxCopyDetail += ` ${t('parentCheckedNoMx', { parentDomain: mxFallbackChecked })}`;
      }
    }
    const mxState = hasMx ? 'PASS' : 'FAIL';
    quotaItems.push(quotaRow(t('mxRecords'), hasMx ? 'pass' : 'fail', mxCopyDetail, null, 'mx'));
    quotaLines.push(`**MX Records:** ${mxState}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>MX Records:</strong> ${escapeHtml(mxState)}${mxCopyDetail ? ' - ' + escapeHtml(mxCopyDetail) : ''}`);
    mxStatusText = hasMx ? t('yes') : t('no');
  }

  quotaCopyPlainLines.push(`${t('mxRecordsLabel')}:   ${mxStatusText || t('unknown')}`);
  if (mxCopyDetail) { quotaCopyPlainLines.push(`  ${mxCopyDetail}`); }
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('mxRecordsLabel'))}:</strong> ${escapeHtml(mxStatusText || t('unknown'))}</div>` + (mxCopyDetail ? `<div style="margin-left:12px;">${escapeHtml(mxCopyDetail)}</div>` : ''));

  const multiRblLink = `https://multirbl.valli.org/dnsbl-lookup/${encodeURIComponent(r.domain || "")}.html`;
  const multiRblHtml = `<a href="${multiRblLink}" target="_blank" rel="noopener" style="font-size:11px; color:#2f80ed; text-decoration:none;">(MultiRBL &#x2197;)</a>`;

  // 2) Reputation
  const reputationInfo = "Default DNSBL checks use a safer free/no-budget set: Spamcop, Barracuda, PSBL, DroneBL, and 0spam. Optional user-supplied zones may also be queried. Reputation = percent of not-listed over successful DNSBL queries. Ratings: Excellent \u226599%, Great \u226590%, Good \u226575%, Fair \u226550%, Poor otherwise. Risk summary: 0 hits = Clean, 1 hit = Warning, 2+ hits = ElevatedRisk. Listed entries are shown when present; errors reduce confidence.";
  let repStateForCopy = '';
  if (!loaded.reputation && !errors.reputation) {
    repCopyDetail = t('checkingDnsblReputation');
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

    quotaItems.push(quotaRow(t('reputationDnsbl'), 'pending', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** PENDING${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> PENDING${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}`);
    repStateForCopy = 'PENDING';
  } else if (errors.reputation) {
    repCopyDetail = errors.reputation;
    quotaItems.push(quotaRow(t('reputationDnsbl'), 'error', repCopyDetail, reputationInfo, 'reputation', multiRblHtml));
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
      const ratingMap = { excellent: t('excellent'), great: t('great'), good: t('good'), fair: t('fair'), poor: t('poor'), unknown: t('unknown') };
      const ratingLabel = ratingMap[rating] || rating;
    const state = listed > 0 ? 'warn' : (percent === null ? 'warn' : (percent >= 75 ? 'pass' : 'warn'));
      const riskSummary = (summary.riskSummary || 'Clean') === 'Clean' ? t('clean') : (summary.riskSummary || 'Clean');
    const baseDetail = percent === null
      ? `${t('riskLabel')}: ${riskSummary} | ${t('totalQueries')}: ${total}, ${t('notListed')}: ${notListed}`
      : `${t('riskLabel')}: ${riskSummary} | ${t('reputationWord')}: ${ratingLabel} (${percent}%) | ${t('listed')}: ${listed}, ${t('notListed')}: ${notListed}`;
      const parentNote = repUsedParent ? t('usingIpParent', { domain: rep.lookupDomain, queryDomain: r.domain || '' }) : '';
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
    quotaItems.push(quotaRow(t('reputationDnsbl'), state, detail, reputationInfo, 'reputation', multiRblHtml));
    quotaLines.push(`**Reputation (DNSBL):** ${state.toUpperCase()}${detail ? ' - ' + detail : ''}`);
    quotaLinesHtml.push(`<strong>Reputation (DNSBL):</strong> ${escapeHtml(state.toUpperCase())}${detail ? ' - ' + escapeHtml(detail) : ''}`);
    repStateForCopy = state.toUpperCase();
  }

  // 3) Domain Registration
  let regState = 'PENDING';
  const whoisErrorText = errors.whois || r.whoisError || '';
  const whoisHasData = !!(r.whoisSource || r.whoisCreationDateUtc || r.whoisExpiryDateUtc || r.whoisRegistrar || r.whoisRegistrant || r.whoisAgeHuman || r.whoisExpiryHuman);

  if (!loaded.whois && !errors.whois) {
    quotaItems.push(quotaRow(t('domainRegistration'), 'pending', t('loadingValue'), null, 'whois'));
    regState = 'PENDING';
  } else if (whoisErrorText) {
    quotaItems.push(quotaRow(t('domainRegistration'), 'error', whoisErrorText, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState}${whoisErrorText ? ' - ' + whoisErrorText : ''}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${whoisErrorText ? ' - ' + escapeHtml(whoisErrorText) : ''}`);
  } else if (!whoisHasData) {
    const msg = t('registrationDetailsUnavailable');
    quotaItems.push(quotaRow(t('domainRegistration'), 'error', msg, null, 'whois'));
    regState = 'ERROR';
    quotaLines.push(`**Domain Registration:** ${regState} - ${msg}`);
    quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)} - ${escapeHtml(msg)}`);
  } else {
    if (r.whoisIsExpired === true) {
      const expText = r.whoisExpiryDateUtc ? t('expiredOn', { date: r.whoisExpiryDateUtc }) : t('registrationAppearsExpired');
      quotaItems.push(quotaRow(t('domainRegistration'), 'fail', expText, null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${expText ? ' - ' + expText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${expText ? ' - ' + escapeHtml(expText) : ''}`);
    } else if (r.whoisIsVeryYoungDomain === true) {
      const suffix = localizedWhoisAgeHuman ? ': ' + localizedWhoisAgeHuman : '';
      const text = t('newDomainUnderDays', { days: String(r.whoisNewDomainErrorThresholdDays || 90), suffix }).trim();
      quotaItems.push(quotaRow(t('domainRegistration'), 'fail', text || t('newDomainUnder90Days'), null, 'whois'));
      regState = 'FAIL';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else if (r.whoisIsYoungDomain === true) {
      const suffix = localizedWhoisAgeHuman ? ': ' + localizedWhoisAgeHuman : '';
      const text = t('newDomainUnderDays', { days: String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180), suffix }).trim();
      quotaItems.push(quotaRow(t('domainRegistration'), 'warn', text || t('newDomainUnder180Days'), null, 'whois'));
      regState = 'WARN';
      quotaLines.push(`**Domain Registration:** ${regState}${text ? ' - ' + text : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${text ? ' - ' + escapeHtml(text) : ''}`);
    } else {
      const parts = [];
      if (localizedWhoisAgeHuman) { parts.push(`${t('ageLabel')}: ${localizedWhoisAgeHuman}`); }
      if (localizedWhoisExpiryHuman) { parts.push(`${t('expiresInLabel')}: ${localizedWhoisExpiryHuman}`); }
      const ageText = parts.join(' | ') || t('resolvedSuccessfully');
      quotaItems.push(quotaRow(t('domainRegistration'), 'pass', ageText, null, 'whois'));
      regState = 'PASS';
      quotaLines.push(`**Domain Registration:** ${regState}${ageText ? ' - ' + ageText : ''}`);
      quotaLinesHtml.push(`<strong>Domain Registration:</strong> ${escapeHtml(regState)}${ageText ? ' - ' + escapeHtml(ageText) : ''}`);
    }
  }

  // 4) SPF
  if (!loaded.base && !errors.base) {
    quotaItems.push(quotaRow(t('spfQueried'), 'pending', t('waitingForTxtLookup'), null, 'spf'));
    quotaLines.push('**SPF (queried domain TXT):** PENDING - Waiting for TXT lookup...');
    quotaLinesHtml.push('<strong>SPF (queried domain TXT):</strong> PENDING - Waiting for TXT lookup...');
  } else if (errors.base) {
    quotaItems.push(quotaRow(t('spfQueried'), 'error', errors.base, null, 'spf'));
    quotaLines.push(`**SPF (queried domain TXT):** ERROR${errors.base ? ' - ' + errors.base : ''}`);
    quotaLinesHtml.push(`<strong>SPF (queried domain TXT):</strong> ERROR${errors.base ? ' - ' + escapeHtml(errors.base) : ''}`);
  } else if (r.dnsFailed) {
    quotaItems.push(quotaRow(t('spfQueried'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), null, 'spf'));
    quotaLines.push(`**${t('spfQueried')}:** FAIL${r.dnsError ? ' - ' + r.dnsError : ' - ' + t('txtLookupFailedOrTimedOut')}`);
    quotaLinesHtml.push(`<strong>${escapeHtml(t('spfQueried'))}:</strong> FAIL${r.dnsError ? ' - ' + escapeHtml(r.dnsError) : ' - ' + escapeHtml(t('txtLookupFailedOrTimedOut'))}`);
  } else {
    const spfPassesRequirement = !!(r.spfPresent && r.spfHasRequiredInclude === true);
    const spfDetail = r.spfPresent
      ? ([r.spfValue, getLocalizedSpfRequirementSummary(r)].filter(Boolean).join("\n\n"))
      : t('noSpfRecordDetected');
    quotaItems.push(quotaRow(t('spfQueried'), spfPassesRequirement ? 'pass' : 'fail', spfDetail, null, 'spf'));
    const spfState = spfPassesRequirement ? 'PASS' : 'FAIL';
    quotaLines.push(`**${t('spfQueried')}:** ${spfState}${spfDetail ? ' - ' + spfDetail.replace(/\r?\n/g, ' | ') : ''}`);
    quotaLinesHtml.push(`<strong>${escapeHtml(t('spfQueried'))}:</strong> ${escapeHtml(spfState)}${spfDetail ? ' - ' + escapeHtml(spfDetail).replace(/\r?\n/g, '<br>') : ''}`);
  }

  // Domain age / expiry for copy block
  const ageText = localizedWhoisAgeHuman || t('unknown');
  const expiryText = localizedWhoisExpiryHuman || t('unknown');
  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`${t('domainAgeLabel')}:  ${ageText}`);
  quotaCopyPlainLines.push(`${t('domainExpiringIn')}: ${expiryText}`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainAgeLabel'))}:</strong> ${escapeHtml(ageText)}</div>`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('domainExpiringIn'))}:</strong> ${escapeHtml(expiryText)}</div>`);

  quotaCopyPlainLines.push('');
  quotaCopyPlainLines.push(`${t('reputationDnsbl')} [MultiRBL: ${multiRblLink}] - ${repStateForCopy || t('unknown')}${repCopyDetail ? ' - ' + repCopyDetail : ''}`);
  quotaCopyHtmlLines.push(`<div><strong>${escapeHtml(t('reputationDnsbl'))} - ${escapeHtml(repStateForCopy || t('unknown'))}</strong>&nbsp;${multiRblHtml}${repCopyDetail ? ' - ' + escapeHtml(repCopyDetail) : ''}</div>`);

  if (repStats) {
    const repLines = [
      `${t('zonesQueried')}: ${repStats.zones}`,
      `${t('totalQueries')}: ${repStats.total}`,
      `${t('errorsCount')}: ${repStats.errors}`,
      `${t('reputationWord')}: ${repStats.rating}${repStats.percent !== null ? ` (${repStats.percent}%)` : ''}`,
      `${t('listed')}: ${repStats.listed}`,
      `${t('notListed')}: ${repStats.notListed}`
    ];
    quotaCopyPlainLines.push(...repLines);
    quotaCopyHtmlLines.push('<div>' + repLines.map(l => escapeHtml(l)).join('<br>') + '</div>');
  }

  const repSummaryText = `${(repStateForCopy || t('unknown'))}${repCopyDetail ? ' - ' + repCopyDetail : ''}` + (repStats
    ? ` | ${t('zonesQueried')}: ${repStats.zones} | ${t('totalQueries')}: ${repStats.total} | ${t('listed')}: ${repStats.listed} | ${t('notListed')}: ${repStats.notListed}`
    : '');

  const domainStatusText = (!loaded.base && !errors.base)
    ? t('pending')
    : (errors.base
      ? t('error')
      : (r.acsPresent ? t('verified') : t('notVerified')));

  const spfStatusText = (!loaded.base && !errors.base)
    ? t('pending')
    : (errors.base
      ? t('error')
      : ((r.spfPresent && r.spfHasRequiredInclude !== false) ? t('verified') : t('notStarted')));

  const dkim1StatusText = (!loaded.dkim && !errors.dkim)
    ? t('pending')
    : (errors.dkim
      ? t('error')
      : (r.dkim1 ? t('verified') : t('notStarted')));

  const dkim2StatusText = (!loaded.dkim && !errors.dkim)
    ? t('pending')
    : (errors.dkim
      ? t('error')
      : (r.dkim2 ? t('verified') : t('notStarted')));

  const dmarcStatusText = (!loaded.dmarc && !errors.dmarc)
    ? t('pending')
    : (errors.dmarc
      ? t('error')
      : (r.dmarc ? t('verified') : t('notStarted')));

  const plainTable = [];
  plainTable.push('| Field | Value |');
  plainTable.push('| --- | --- |');
  plainTable.push(`| ${t('domainNameLabel')} | ${domainForCopy || t('unknown')} |`);
  plainTable.push(`| ${t('domainStatusLabel')} | ${domainStatusText} |`);
  plainTable.push(`| ${t('mxRecordsLabel')} | ${mxStatusText || t('unknown')}${mxCopyDetail ? ` - ${mxCopyDetail}` : ''} |`);
  plainTable.push(`| ${t('domainAgeLabel')} | ${ageText} |`);
  plainTable.push(`| ${t('domainExpiringIn')} | ${expiryText} |`);
  plainTable.push(`| ${t('spfStatusLabel')} | ${spfStatusText} |`);
  plainTable.push(`| ${t('dkim1StatusLabel')} | ${dkim1StatusText} |`);
  plainTable.push(`| ${t('dkim2StatusLabel')} | ${dkim2StatusText} |`);
  plainTable.push(`| ${t('dmarcStatusLabel')} | ${dmarcStatusText} |`);
  plainTable.push(`| ${t('reputationDnsbl')} | ${repSummaryText} [MultiRBL: ${multiRblLink}] |`);

  const htmlTableRows = [];
  const addRow = (name, value) => { htmlTableRows.push(`<tr><th>${escapeHtml(name)}</th><td>${escapeHtml(value)}</td></tr>`); };
  addRow(t('domainNameLabel'), domainForCopy || t('unknown'));
  addRow(t('domainStatusLabel'), domainStatusText);
  addRow(t('mxRecordsLabel'), `${mxStatusText || t('unknown')}${mxCopyDetail ? ' - ' + mxCopyDetail : ''}`);
  addRow(t('domainAgeLabel'), ageText);
  addRow(t('domainExpiringIn'), expiryText);
  addRow(t('spfStatusLabel'), spfStatusText);
  addRow(t('dkim1StatusLabel'), dkim1StatusText);
  addRow(t('dkim2StatusLabel'), dkim2StatusText);
  addRow(t('dmarcStatusLabel'), dmarcStatusText);
  // Manual push for Reputation to include parsed HTML link (multiRblHtml)
  htmlTableRows.push(`<tr><th>${escapeHtml(t('reputationDnsbl'))}</th><td>${escapeHtml(repSummaryText)}<br>${multiRblHtml}</td></tr>`);

  const quotaCopyTextPlain = plainTable.join('\n');
  const quotaCopyTextHtml = `<table style="border-collapse:collapse;min-width:260px;">${htmlTableRows.map(r => r.replace('<th>', '<th style="text-align:left;padding:4px 8px;border:1px solid #ddd;">').replace('<td>', '<td style="padding:4px 8px;border:1px solid #ddd;">')).join('')}</table>`;
  quotaCopyText = quotaCopyTextPlain;
  // Expose for inline copy handler with rich + plain variants
  window.quotaCopyText = { plain: quotaCopyTextPlain, html: quotaCopyTextHtml };

  cards.push(`
  <div class="card" id="card-email-quota">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('checklist'))}</span>
      <strong>${escapeHtml(t('emailQuota'))}</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left:auto;" onclick="event.stopPropagation(); copyText(window.quotaCopyText, this)">${escapeHtml(t('copyEmailQuota'))}</button>
    </div>
    <div class="card-content">
      <div class="status-summary">${quotaItems.join('')}</div>
    </div>
  </div>
  `);

  // Domain Verification box (ACS requirements)
  const verificationItems = [];
  const verifyRow = (name, state, detail, targetId = null) => {
    const stateKeyMap = { pass: 'pass', fail: 'fail', error: 'error', warn: 'warn', pending: 'pending' };
    const badge = `<span class="tag ${quotaStateClass(state)} status-pill">${escapeHtml(t(stateKeyMap[state] || String(state || '').toLowerCase()))}</span>`;
    const link = targetId ? `<button type="button" class="copy-btn hide-on-screenshot" onclick="event.stopPropagation(); scrollToSection('${targetId}')">${escapeHtml(t('view'))}</button>` : '';
    return `<div class="status-row"><span class="status-name">${escapeHtml(name)}</span><span class="status-pills">${link}${badge}</span></div>` + (detail ? `<div class="code" style="margin:6px 0 10px 0;">${escapeHtml(detail)}</div>` : '');
  };

  if (!loaded.base && !errors.base) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'pending', t('waitingForBaseTxtLookup'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'pending', t('waitingForBaseTxtLookup'), 'acsTxt'));
  } else if (errors.base) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'error', errors.base, 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'error', t('unableDetermineAcsTxtValue'), 'acsTxt'));
  } else if (r.dnsFailed) {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'fail', r.dnsError || t('txtLookupFailedOrTimedOut'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), 'fail', t('missingRequiredAcsTxt'), 'acsTxt'));
  } else {
    verificationItems.push(verifyRow(t('dnsTxtLookup'), 'pass', t('resolvedSuccessfully'), 'txtRecords'));
    verificationItems.push(verifyRow(t('acsTxtMsDomainVerification'), r.acsPresent ? 'pass' : 'fail', r.acsPresent ? t('msDomainVerificationFound') : t('addAcsTxtFromPortal'), 'acsTxt'));
  }

  // Overall ACS readiness
  verificationItems.push(verifyRow(t('acsReadiness'), (loaded.base && !errors.base && !r.dnsFailed && r.acsPresent) ? 'pass' : (loaded.base && !errors.base ? 'fail' : 'pending'), r.acsReady ? t('acsReadyMessage') : t('missingRequiredAcsTxt'), 'verification'));

  cards.push(`
  <div class="card" id="card-verification">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('verificationTag'))}</span>
      <strong>${escapeHtml(t('domainVerification'))}</strong>
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
      t('domainRegistration'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "whois",
      true
    ));
  } else if (errors.whois) {
    cards.push(card(
      t('domainRegistration'),
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
    const whoisRows = [];
    const addWhoisRow = (label, value, options = {}) => {
      if (value === null || value === undefined || value === '') return;
      const valueHtml = options.italic
        ? `<em>${escapeHtml(value)}</em>`
        : escapeHtml(value);
      whoisRows.push(`<div class="kv-label">${escapeHtml(label)}:</div><div class="kv-value">${valueHtml}</div>`);
    };

    addWhoisRow(t('lookupDomainLabel'), r.whoisLookupDomain);
    if (r.whoisLookupDomain && r.whoisSource) {
      whoisRows.push('<div class="kv-spacer"></div>');
    }
    addWhoisRow(t('source'), r.whoisSource, { italic: true });
    addWhoisRow(t('creationDate'), r.whoisCreationDateUtc);
    addWhoisRow(t('registryExpiryDate'), r.whoisExpiryDateUtc);
    addWhoisRow(t('registrarLabel'), r.whoisRegistrar);
    addWhoisRow(t('registrantLabel'), r.whoisRegistrant);
    if (r.whoisAgeHuman) {
      addWhoisRow(t('domainAgeLabel'), localizeDurationText(r.whoisAgeHuman));
    } else if (r.whoisAgeDays !== null && r.whoisAgeDays !== undefined) {
      addWhoisRow(t('domainAgeLabel') + ' (days)', String(r.whoisAgeDays));
    }
    if (r.whoisExpiryHuman) {
      addWhoisRow(t('domainExpiringIn'), r.whoisIsExpired === true ? t('wordExpired') : localizeDurationText(r.whoisExpiryHuman));
    }
    if (r.whoisExpiryDays !== null && r.whoisExpiryDays !== undefined) {
      addWhoisRow(t('daysUntilExpiry'), String(r.whoisExpiryDays));
    }
    if (isExpired) {
      addWhoisRow(t('statusLabel'), localizeWhoisStatus(t('expired')));
    } else if (isVeryYoung) {
      addWhoisRow(t('statusLabel'), t('noteDomainLessThanDays', { days: String(r.whoisNewDomainErrorThresholdDays || 90) }));
    } else if (isYoung) {
      addWhoisRow(t('statusLabel'), t('noteDomainLessThanDays', { days: String(r.whoisNewDomainWarnThresholdDays || r.whoisNewDomainThresholdDays || 180) }));
    }

    const rawWhoisHtml = (r.whoisRawText && !r.whoisCreationDateUtc && !r.whoisExpiryDateUtc && !r.whoisRegistrar && !r.whoisRegistrant)
      ? `<div class="code" style="margin-top:10px;">${escapeHtml(t('rawLabel'))} (${escapeHtml(r.whoisSource || t('rawWhoisLabel'))}):\n${escapeHtml(r.whoisRawText)}</div>`
      : '';
    const whoisErrorHtml = r.whoisError
      ? `<div class="code" style="margin-top:10px;">${escapeHtml(t('error'))}: ${escapeHtml(r.whoisError)}</div>`
      : '';

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

    cards.push(`
  <div class="card" id="card-whois">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag ${whoisTagClass}">${escapeHtml(translateBadge(whoisLabel))}</span>
      <strong>${escapeHtml(t('domainRegistration'))}</strong>
      <button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, 'whois')">${escapeHtml(t('copy'))}</button>
    </div>
    <div id="field-whois" class="card-content">
      ${whoisRows.length > 0 ? `<div class="kv-grid">${whoisRows.join('')}</div>` : `<div class="code">${escapeHtml(t('noRegistrationInformation'))}</div>`}
      ${rawWhoisHtml}
      ${whoisErrorHtml}
    </div>
  </div>
    `);
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
      ? `<div class="code code-lite" style="margin-top:6px;">${escapeHtml(t('usingIpParent', { domain: ipLookupDomain, queryDomain: r.domain || '' }))}</div>`
      : '';

    const ipvTable = baseLoaded ? `
      <div class="code code-lite" style="margin-top:6px;">
        <table class="mx-table">
          <thead>
            <tr>
              <th style="width: 120px;">${escapeHtml(t('type'))}</th>
              <th>${escapeHtml(t('addresses'))}</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>${escapeHtml(t('ipv4'))}</td><td>${ipv4List.length ? ipv4List.map(escapeHtml).join(', ') : escapeHtml(t('none'))}</td></tr>
            <tr><td>${escapeHtml(t('ipv6'))}</td><td>${ipv6List.length ? ipv6List.map(escapeHtml).join(', ') : escapeHtml(t('none'))}</td></tr>
          </tbody>
        </table>
      </div>
    ` : '';

    cards.push(`
      <div class="card" id="card-domain">
        <div class="card-header" onclick="toggleCard(this)">
          <span class="chevron">&#x25BC;</span>
          <span class="tag ${domainClass}">${escapeHtml(translateBadge(domainLabel))}</span>
          <strong>${escapeHtml(t('domain'))}</strong>
        </div>
        <div class="card-content">
      <div id="field-domain" class="code code-lite">${escapeHtml(r.domain || t('noRecordsAvailable'))}</div>
          ${ipNote}${ipvTable}
        </div>
      </div>
    `);
  }

  // MX (placed directly below Domain per UI request)
  if (!loaded.mx && !errors.mx) {
    cards.push(card(
      t('mxRecords'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "mx",
      false
    ));
  } else if (errors.mx) {
    cards.push(card(
      t('mxRecords'),
      errors.mx,
      "ERROR",
      "tag-fail",
      "mx",
      false
    ));
  } else {
    let mxFallbackNote = '';
    if (mxFallbackUsed && mxLookupDomain && mxLookupDomain !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('noMxParentShowing', { domain: r.domain || '', lookupDomain: mxLookupDomain }))}</div>`;
    } else if ((!r.mxRecords || r.mxRecords.length === 0) && mxFallbackChecked && mxFallbackChecked !== r.domain) {
      mxFallbackNote = `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('noMxParentChecked', { domain: r.domain || '', parentDomain: mxFallbackChecked }))}</div>`;
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
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('ipv4Addresses'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('ipAddress'))}</th>
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
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('ipv6Addresses'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('ipAddress'))}</th>
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
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">${escapeHtml(t('noIpAddressesFound'))}</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>${escapeHtml(t('hostname'))}</th>
              <th>${escapeHtml(t('priority'))}</th>
              <th>${escapeHtml(t('status'))}</th>
            </tr>
          </thead>
          <tbody>${noIpRows}</tbody>
        </table>
      </div>`;
    }

    if (!mxDetailsContent) {
      mxDetailsContent = `<div class="code">${escapeHtml(t('noAdditionalMxDetails'))}</div>`;
    }

    cards.push(`
  <div class="card" id="card-mx">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">${escapeHtml(t('info'))}</span>
      <strong>${escapeHtml(t('mxRecords'))}</strong>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              style="margin-left: auto;"
              onclick="event.stopPropagation(); toggleMxDetails(this)">
        ${escapeHtml(t('additionalDetailsPlus'))}
      </button>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              onclick="event.stopPropagation(); copyField(this, 'mx')">
        ${escapeHtml(t('copy'))}
      </button>
    </div>
    <div class="card-content">
      ${mxFallbackNote}
      ${r.mxProvider ? `<div class="code" style="margin-bottom:6px;">${escapeHtml(t('detectedProvider'))}: ${escapeHtml(r.mxProvider)}${getLocalizedMxProviderHint(r.mxProvider, r.mxProviderHint) ? " \u2014 " + escapeHtml(getLocalizedMxProviderHint(r.mxProvider, r.mxProviderHint)) : ""}</div>` : ""}
      <div id="field-mx" class="code">${escapeHtml((r.mxRecords || []).join("\n") || t('noRecordsAvailable'))}</div>
      <div id="mxDetails" style="margin-top:6px; display:none;">${mxDetailsContent}</div>
    </div>
  </div>
    `);
  }

  // Match card order to the Check Summary.
  const spfCardBaseValue = loaded.base
    ? (r.spfValue || ((r.parentSpfPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('none')}: ${r.domain}\n\n${t('resolvedUsingGuidance', { lookupDomain: r.txtLookupDomain })}\n${r.parentSpfValue || ''}`) : null))
    : (baseError ? (errors.base || t('error')) : t('loadingValue'));
  const spfCardValue = [spfCardBaseValue, getLocalizedSpfRequirementSummary(r)].filter(Boolean).join("\n\n");
  // The expanded SPF analysis is server-generated in English, and it is only meaningful once the
  // base TXT payload has loaded, so only render it for English after the base check completes.
  const spfExpandedSection = currentLanguage === 'en' && loaded.base && r.spfExpandedText
    ? `\n\n--- ${t('spfRecordBasics')} ---\n${stripSpfRequirementSection(r.spfExpandedText)}`
    : '';
  cards.push(card(
    t('spfQueried'),
    (spfCardValue || t('noRecordsAvailable')) + spfExpandedSection,
    basePending ? "LOADING" : (baseError ? "ERROR" : ((r.spfPresent && r.spfHasRequiredInclude === true) ? "PASS" : "FAIL")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : ((r.spfPresent && r.spfHasRequiredInclude === true) ? "tag-pass" : "tag-fail")),
    "spf"
  ));

  cards.push(card(
    t('acsDomainVerificationTxt'),
    loaded.base ? (r.acsValue || ((r.parentAcsPresent && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noRecordOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainAcsTxtInfo', { lookupDomain: r.txtLookupDomain })}\n${r.parentAcsValue || ''}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.acsPresent ? "PASS" : "MISSING")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.acsPresent ? "tag-pass" : "tag-fail")),
    "acsTxt"
  ));

  cards.push(card(
    t('txtRecordsQueried'),
    loaded.base ? (((r.txtRecords || []).join("\n")) || ((r.parentTxtRecords && r.parentTxtRecords.length > 0 && r.txtUsedParent && r.txtLookupDomain && r.txtLookupDomain !== r.domain) ? (`${t('noTxtRecordsOnDomain', { domain: r.domain || '' })}\n\n${t('parentDomainTxtRecordsInfo', { lookupDomain: r.txtLookupDomain })}\n${(r.parentTxtRecords || []).join("\n")}`) : null)) : (baseError ? (errors.base || t('error')) : t('loadingValue')),
    basePending ? "LOADING" : (baseError ? "ERROR" : "INFO"),
    basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info"),
    "txtRecords",
    false
  ));

  cards.push(card(
    t('dmarc'),
    loaded.dmarc ? (r.dmarc ? (r.dmarcInherited && r.dmarcLookupDomain && r.dmarcLookupDomain !== r.domain ? (`${r.dmarc}\n\n${t('effectivePolicyInherited', { lookupDomain: r.dmarcLookupDomain })}`) : r.dmarc) : null) : (errors.dmarc ? errors.dmarc : t('loadingValue')),
    (!loaded.dmarc && !errors.dmarc) ? "LOADING" : (errors.dmarc ? "ERROR" : (r.dmarc ? "PASS" : "OPTIONAL")),
    (!loaded.dmarc && !errors.dmarc) ? "tag-info" : (errors.dmarc ? "tag-fail" : (r.dmarc ? "tag-pass" : "tag-info")),
    "dmarc"
  ));

  // include full selector host with domain in title
  cards.push(card(
    `${t('dkim1Title')} (selector1-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim1 : (errors.dkim ? errors.dkim : t('loadingValue')),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim1 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim1 ? "tag-pass" : "tag-info")),
    "dkim1"
  ));

  cards.push(card(
    `${t('dkim2Title')} (selector2-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim2 : (errors.dkim ? errors.dkim : t('loadingValue')),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim2 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim2 ? "tag-pass" : "tag-info")),
    "dkim2"
  ));

  // Reputation / DNSBL
  if (!loaded.reputation && !errors.reputation) {
    cards.push(card(
      t('reputationDnsbl'),
      t('loadingValue'),
      "LOADING",
      "tag-info",
      "reputation",
      false,
      multiRblHtml
    ));
  } else if (errors.reputation) {
    cards.push(card(
      t('reputationDnsbl'),
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

    let rating = t('unknown');
    if (percent !== null) {
      if (percent >= 99) rating = t('excellent');
      else if (percent >= 90) rating = t('great');
      else if (percent >= 75) rating = t('good');
      else if (percent >= 50) rating = t('fair');
      else rating = t('poor');
    }

    const statusLabel = percent === null ? t('unknown') : `${rating.toUpperCase()} (${percent}%)`;
    const statusClass = percent === null ? "tag-info"
      : (percent >= 90 ? "tag-pass"
      : (percent >= 75 ? "tag-info" : "tag-fail"));

    // Show only listed entries to avoid noise
    const listedItems = (rep.results || []).filter(x => x && x.listed === true);
    let body = `${t('zonesQueried')}: ${rep.rblZones ? rep.rblZones.length : 0}\n` +
               `${t('totalQueries')}: ${total}\n` +
               `${t('errorsCount')}: ${errorCount}`;
    if (percent !== null) {
    const riskSummary = localizeRiskSummary(summary.riskSummary || 'Clean');
      body += `\n${t('riskLabel')}: ${riskSummary}`;
      body += `\n${t('reputationWord')}: ${rating} (${percent}%)`;
      body += `\n${t('listed')}: ${listed}\n${t('notListed')}: ${notListed}`;
    } else {
      const riskSummary = localizeRiskSummary(summary.riskSummary || 'Clean');
      body += `\n${t('riskLabel')}: ${riskSummary}`;
      body += `\n${t('reputationWord')}: ${t('noSuccessfulQueries')}`;
    }
    if (listedItems.length > 0) {
      const lines = listedItems.map(x => t('listedOnZone', {
        ip: x.ip,
        zone: x.queriedZone,
        suffix: x.listedAddress ? ` (${x.listedAddress})` : ''
      }));
      body += `\n\n${t('listingsLabel')}:\n` + lines.join("\n");
    }

    cards.push(card(
      t('reputationDnsbl'),
      body,
      statusLabel,
      statusClass,
      "reputation",
      false,
      `<button type="button" class="info-dot" aria-label="${escapeHtml(reputationInfo)}" data-info="${escapeHtml(reputationInfo)}">i</button> ${multiRblHtml}`
    ));
  }

  cards.push(card(
    t('cname'),
    loaded.cname ? (r.cname ? (r.cnameUsedWwwFallback && r.cnameLookupDomain && r.cnameLookupDomain !== r.domain ? (`${r.cname}\n\n${t('resolvedUsingGuidance', { lookupDomain: r.cnameLookupDomain })}`) : r.cname) : null) : (errors.cname ? errors.cname : t('loadingValue')),
    (!loaded.cname && !errors.cname) ? "LOADING" : (errors.cname ? "ERROR" : (r.cname ? "PASS" : "FAIL")),
    (!loaded.cname && !errors.cname) ? "tag-info" : (errors.cname ? "tag-fail" : (r.cname ? "tag-pass" : "tag-fail")),
    "cname"
  ));

  const guidanceItems = (r.guidance || []).map(g => {
    let iconHtml = '';
    let text = g;
    let type = 'info';

    if (typeof g === 'object' && g !== null) {
      text = g.text;
      type = g.type || 'info';
    }

    let iconClass = 'icon-info';
    let iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/info.svg';
    let iconTitle = t('guidanceIconInformational');

    if (type === 'error') {
      iconClass = 'icon-error';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/alert-circle.svg';
      iconTitle = t('guidanceIconError');
    } else if (type === 'attention') {
      iconClass = 'icon-warning';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/triangle-alert.svg';
      iconTitle = t('guidanceIconAttention');
    } else if (type === 'success') {
      iconClass = 'icon-success';
      iconSrc = 'https://cdn.jsdelivr.net/npm/lucide-static/icons/check-circle.svg';
      iconTitle = t('guidanceIconSuccess');
    }

    iconHtml = `<img src="${iconSrc}" class="status-icon ${iconClass}" alt="${iconTitle}" title="${iconTitle}" />`;

    return '<li style="display:flex; align-items:flex-start; gap:8px; margin-bottom:8px;">' + iconHtml + '<span style="padding-top:2px;">' + formatGuidanceText(text, r.domain || '') + '</span></li>';
  }).join("");
  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('readinessTips'))}</span>
        <strong>${renderLabelWithIcon('guidance')}</strong>
        <div class="card-icons" style="margin-left: auto; font-size: 0.8em; display: flex; align-items: center; gap: 6px;">
           <img src="https://cdn.jsdelivr.net/npm/lucide-static/icons/triangle-alert.svg" class="status-icon icon-warning" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendAttention'))}"/> <span style="margin-right: 8px;">${escapeHtml(t('guidanceLegendAttention'))}</span>
           <img src="https://cdn.jsdelivr.net/npm/lucide-static/icons/info.svg" class="status-icon icon-info" style="width: 14px; height: 14px; margin-right: 0;" alt="${escapeHtml(t('guidanceLegendInformational'))}"/> <span>${escapeHtml(t('guidanceLegendInformational'))}</span>
        </div>
      </div>
      <div id="field-guidance" class="card-content">
        <ul class="guidance">
          ${guidanceItems || `<li>${escapeHtml(t('noAdditionalGuidance'))}</li>`}
        </ul>
      </div>
    </div>
  `);

  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">${escapeHtml(t('docs'))}</span>
        <strong>${escapeHtml(t('helpfulLinks'))}</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="https://learn.microsoft.com/azure/communication-services/quickstarts/email/add-custom-verified-domains" target="_blank" rel="noopener">${escapeHtml(t('acsEmailDomainVerification'))}</a></li>
          <li><a href="https://learn.microsoft.com/azure/communication-services/concepts/email/email-quota-increase" target="_blank" rel="noopener">${escapeHtml(t('acsEmailQuotaLimitIncrease'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure" target="_blank" rel="noopener">${escapeHtml(t('spfRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records" target="_blank" rel="noopener">${escapeHtml(t('dmarcRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure" target="_blank" rel="noopener">${escapeHtml(t('dkimRecordBasics'))}</a></li>
          <li><a href="https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider?view=o365-worldwide" target="_blank" rel="noopener">${escapeHtml(t('mxRecordBasics'))}</a></li>
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
        <span class="tag tag-info">${escapeHtml(t('tools'))}</span>
        <strong>${escapeHtml(t('externalTools'))}</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="${centralOps}" target="_blank" rel="noopener">${escapeHtml(t('domainDossier'))}</a></li>
          <li><a href="${multiRbl}" target="_blank" rel="noopener">${escapeHtml(t('multiRblLookup'))}</a></li>
        </ul>
      </div>
    </div>
  `);

  document.getElementById("results").innerHTML = cards.join("");
  startLoadingDotAnimations();
}

let _loadingDotsTimer = null;
function startLoadingDotAnimations() {
  if (_loadingDotsTimer) { clearInterval(_loadingDotsTimer); _loadingDotsTimer = null; }
  const codeEls = document.querySelectorAll('#results .code');
  const targets = [];
  codeEls.forEach(el => {
    const txt = el.textContent || '';
    if (txt.length > 3 && txt.endsWith('...') && !el.querySelector('.loading-dot')) {
      const base = txt.slice(0, -3);
      el.innerHTML = escapeHtml(base)
        + '<span class="loading-dot">.</span>'
        + '<span class="loading-dot">.</span>'
        + '<span class="loading-dot">.</span>';
      el.classList.add('loading-dots');
      targets.push(el);
    }
  });
  if (targets.length === 0) return;
  let step = 0;
  _loadingDotsTimer = setInterval(() => {
    const active = document.querySelectorAll('#results .loading-dots');
    if (active.length === 0) { clearInterval(_loadingDotsTimer); _loadingDotsTimer = null; return; }
    active.forEach(el => {
      const dots = el.querySelectorAll('.loading-dot');
      dots.forEach((d, i) => {
        d.classList.toggle('active', i === step % 3);
      });
    });
    step++;
  }, 400);
}

document.getElementById("domainInput").addEventListener("keyup", function (e) {
  if (e.key === "Enter") {
    lookup();
  }
});

document.getElementById('azureSubscriptionSelect').addEventListener('change', function () {
  azureDiagnosticsState.resources = [];
  azureDiagnosticsState.workspaces = [];
  renderAzureDiagnosticsUi();
  discoverAzureResources();
});

document.getElementById('azureResourceSelect').addEventListener('change', function () {
  azureDiagnosticsState.workspaces = [];
  renderAzureDiagnosticsUi();
  discoverAzureWorkspaces();
});

// Theme + query-domain initialization
window.addEventListener("load", function () {
  currentLanguage = detectLanguage();

  // 1. Check for saved theme
  // 2. If none, check system preference (Dark vs Light)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = systemPrefersDark ? "dark" : "light";

  const savedTheme = localStorage.getItem("acsTheme") || defaultTheme;

  applyTheme(savedTheme);
  applyLanguage(currentLanguage, false);
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
const ARM_SCOPES = ['https://management.azure.com/user_impersonation'];
const LOG_ANALYTICS_SCOPES = ['https://api.loganalytics.io/Data.Read'];
const GRAPH_SCOPES = ['User.Read'];
let azureDiagnosticsState = {
  subscriptions: [],
  resources: [],
  workspaces: [],
  lastQueryText: '',
  lastQueryName: '',
  lastResult: null,
  isBusy: false
};

'@
# ===== JavaScript Azure / MSAL Integration =====
$htmlPage += @'
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
      knownAuthorities: ['login.microsoftonline.com'],
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
      btn.innerHTML = t('signInMicrosoft');
    }
    msalInitError = 'Missing ACS_ENTRA_CLIENT_ID in the served HTML.';
    setStatus(t('authSignInNotConfigured'));
    return;
  }

  try {
    await ensureMsalLoaded();
  } catch (e) {
    msalInitError = e?.message || 'MSAL library not loaded.';
    setStatus(t('authLibraryLoadFailed'));
    return;
  }

  if (typeof msal === 'undefined') {
    msalInitError = 'MSAL library not loaded.';
    setStatus(t('authLibraryLoadFailed'));
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
    setStatus(t('authInitFailed'));
  }
}

async function msSignIn() {
  if (!msalInstance) {
    if (msalInitError) {
      setStatus(t('authInitFailedWithReason', { reason: msalInitError }));
    } else {
      setStatus(t('authSetClientIdAndRestart'));
    }
    return;
  }

  try {
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = true; btn.textContent = t('authSigningIn'); }

    // Use redirect flow for best compatibility with browser / popup blockers.
    // Request Graph scopes for the token, plus pre-consent ARM and Log Analytics
    // via extraScopesToConsent so acquireTokenSilent works later without popups.
    await msalInstance.loginRedirect({
      scopes: GRAPH_SCOPES,
      extraScopesToConsent: [...ARM_SCOPES, ...LOG_ANALYTICS_SCOPES],
      prompt: 'select_account'
    });
  } catch (e) {
    console.error('Sign-in error:', e);
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = false; btn.innerHTML = t('signInMicrosoft'); }

    if (e && e.errorCode === 'user_cancelled') {
      setStatus(t('authSignInCancelled'));
    } else {
      setStatus(t('authSignInFailed', { reason: e?.errorMessage || e?.message || t('authUnknownError') }));
    }
  }
}

async function msSignOut() {
  if (!msalInstance) return;

  try {
    // Clear the MSAL token cache locally without redirecting to the Microsoft
    // logout page.  This avoids the account-picker screen and keeps the user
    // on the current page.  The next sign-in still uses prompt:'select_account'
    // so the user can choose a different account if needed.
    const accounts = msalInstance.getAllAccounts() || [];
    for (const acct of accounts) {
      // MSAL v2 removeAccount is synchronous in the browser cache but returns void.
      // It only removes the local cache entry, it does not call Microsoft's logout endpoint.
      try { msalInstance.setActiveAccount(null); } catch {}
    }
    // Clear all MSAL-related entries from session storage
    const keysToRemove = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && (key.startsWith('msal.') || key.includes('login.microsoftonline.com') || key.includes('msal'))) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => sessionStorage.removeItem(k));

    msAuthAccount = null;
    isMsEmployee = false;
    azureDiagnosticsState.subscriptions = [];
    azureDiagnosticsState.resources = [];
    azureDiagnosticsState.workspaces = [];
    azureDiagnosticsState.lastResult = null;
    azureDiagnosticsState.lastQueryText = '';
    azureDiagnosticsState.lastQueryName = '';
    setAzureDiagnosticsResultsHtml('');
    updateAuthUI(null);
  } catch (e) {
    console.error('Sign-out error:', e);
  }
}

async function verifyMsAccount(accessToken) {
  try {
    let profile = null;
    try {
      const resp = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: {
          'Authorization': 'Bearer ' + accessToken
        }
      });
      if (resp.ok) {
        profile = await resp.json();
      }
    } catch {}

    const claims = (msAuthAccount && msAuthAccount.idTokenClaims) ? msAuthAccount.idTokenClaims : {};
    const userPrincipalName = String((profile && (profile.userPrincipalName || profile.mail)) || msAuthAccount?.username || claims.preferred_username || '').trim();
    const displayName = String((profile && profile.displayName) || msAuthAccount?.name || claims.name || userPrincipalName || '').trim();
    const tenantId = String(claims.tid || '').trim();

    const data = {
      displayName,
      userPrincipalName,
      tenantId,
      isMicrosoftEmployee: /@(microsoft\.com|microsoftsupport\.com)$/i.test(userPrincipalName)
    };

    isMsEmployee = data.isMicrosoftEmployee === true;
    updateAuthUI(data);
  } catch (e) {
    console.error('Auth verify error:', e);
    updateAuthUI(null);
  }
}

function updateAuthUI(authData) {
  lastAuthData = authData || null;
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
        statusEl.innerHTML = '&#x2705; ' + name + ' (' + escapeHtml(t('authMicrosoftLabel')) + ')';
      } else {
        statusEl.className = 'ms-auth-status ms-external hide-on-screenshot';
        statusEl.innerHTML = '&#x1F464; ' + name;
      }
    }
  } else {
    if (signInBtn) {
      signInBtn.style.display = '';
      signInBtn.disabled = false;
      signInBtn.innerHTML = t('signInMicrosoft');
    }
    if (signOutBtn) signOutBtn.style.display = 'none';
    if (statusEl) statusEl.style.display = 'none';
    isMsEmployee = false;
  }

  renderAzureDiagnosticsUi();

  if (authData && msAuthAccount) {
    loadAzureSubscriptions();
  }
}

function setAzureDiagnosticsStatus(message, isError = false) {
  const el = document.getElementById('azureDiagnosticsStatus');
  if (!el) return;
  el.textContent = message || '';
  el.className = isError ? 'azure-status error' : 'azure-status';
}

function setAzureDiagnosticsResultsHtml(html) {
  const el = document.getElementById('azureDiagnosticsResults');
  if (!el) return;
  el.innerHTML = html || '';
}

function getSelectedAzureSubscriptionId() {
  const el = document.getElementById('azureSubscriptionSelect');
  return el ? String(el.value || '') : '';
}

function getSelectedAzureResourceId() {
  const el = document.getElementById('azureResourceSelect');
  return el ? String(el.value || '') : '';
}

function getSelectedAzureWorkspaceId() {
  const el = document.getElementById('azureWorkspaceSelect');
  return el ? String(el.value || '') : '';
}

function renderAzureSelectOptions(selectId, items, getValue, getLabel, emptyText) {
  const el = document.getElementById(selectId);
  if (!el) return;
  const currentValue = el.value;
  const options = (items || []).map(item => {
    const value = String(getValue(item) || '');
    const label = String(getLabel(item) || value);
    return `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;
  });
  if (options.length === 0) {
    el.innerHTML = `<option value="">${escapeHtml(emptyText)}</option>`;
    return;
  }
  el.innerHTML = options.join('');
  if (currentValue && items.some(item => String(getValue(item) || '') === currentValue)) {
    el.value = currentValue;
  }
}

function getAzureAuthDisplayName() {
  return (lastAuthData && (lastAuthData.displayName || lastAuthData.userPrincipalName))
    ? String(lastAuthData.displayName || lastAuthData.userPrincipalName)
    : '';
}

function renderAzureDiagnosticsUi() {
  const card = document.getElementById('azureDiagnosticsCard');
  if (!card) return;

  const signedIn = !!(msAuthAccount && msalInstance);
  card.style.display = (getMsalConfig() && signedIn) ? '' : 'none';

  const switchRow = document.getElementById('azureSwitchDirectoryRow');
  if (switchRow) switchRow.style.display = signedIn ? '' : 'none';

  renderAzureSelectOptions(
    'azureSubscriptionSelect',
    azureDiagnosticsState.subscriptions,
    item => item.subscriptionId,
    item => `${item.displayName || item.subscriptionId}${item.tenantId ? ` (${item.tenantId})` : ''}`,
    t('azureNoSubscriptions')
  );

  renderAzureSelectOptions(
    'azureResourceSelect',
    azureDiagnosticsState.resources,
    item => item.id,
    item => `${item.name} [${item.type}]`,
    t('azureNoResources')
  );

  renderAzureSelectOptions(
    'azureWorkspaceSelect',
    azureDiagnosticsState.workspaces,
    item => item.id,
    item => `${item.name}${item.customerId ? ` (${item.customerId})` : ''}`,
    t('azureNoWorkspaces')
  );

  const hint = document.getElementById('azureDiagnosticsHint');
  if (hint) {
    hint.textContent = signedIn
      ? t('azureSignedInAs', { user: getAzureAuthDisplayName() || t('authMicrosoftLabel') })
      : t('azureDiagnosticsHint');
  }

  ['azureRunInventoryBtn','azureRunDomainSearchBtn','azureRunAcsSearchBtn']
    .forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = !signedIn || azureDiagnosticsState.isBusy;
    });

  if (!signedIn) {
    setAzureDiagnosticsStatus(t('azureSignInRequired'), false);
  }
}

function escapeKqlString(text) {
  return String(text || '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function getMsAuthLoginHint() {
  if (msAuthAccount) {
    return msAuthAccount.username || (msAuthAccount.idTokenClaims && msAuthAccount.idTokenClaims.preferred_username) || '';
  }
  if (lastAuthData && lastAuthData.userPrincipalName) {
    return lastAuthData.userPrincipalName;
  }
  return '';
}

async function acquireAzureAccessToken(scopes, tenantId, silentOnly) {
  const scopeLabel = (scopes || []).map(s => String(s).split('/').pop()).join(',');
  const tenantLabel = tenantId ? tenantId.substring(0, 8) + '...' : 'default';
  console.log(`[AzureDiag] acquireToken: scope=${scopeLabel}, tenant=${tenantLabel}, silentOnly=${!!silentOnly}`);

  if (!msalInstance || !msAuthAccount) {
    console.warn('[AzureDiag] acquireToken: FAILED \u2014 msalInstance or msAuthAccount is null');
    throw new Error(t('azureSignInRequired'));
  }

  const loginHint = getMsAuthLoginHint();
  const homeTenantId = msAuthAccount.tenantId || '';
  const isCrossTenant = tenantId && tenantId !== homeTenantId;

  const request = {
    scopes,
    account: msAuthAccount
  };
  if (tenantId) {
    request.authority = `https://login.microsoftonline.com/${tenantId}`;
  }
  // For cross-tenant requests, always force a fresh token from the target
  // tenant's authority.  MSAL v2 cache keys do not always differentiate by
  // tenant for the same resource, so without forceRefresh the cached home-
  // tenant token is returned and ARM sees subscriptions as "Disabled".
  if (isCrossTenant) {
    request.forceRefresh = true;
    console.log(`[AzureDiag] acquireToken: cross-tenant detected (home=${homeTenantId.substring(0, 8)}...), forcing refresh`);
  }

  try {
    const silent = await msalInstance.acquireTokenSilent(request);
    const tokenTenant = silent.tenantId || silent.account?.tenantId || 'n/a';
    const tokenTenantLabel = tokenTenant !== 'n/a' ? tokenTenant.substring(0, 8) + '...' : 'n/a';
    console.log(`[AzureDiag] acquireToken: silent OK for tenant=${tenantLabel}, tokenTenant=${tokenTenantLabel}, tokenLength=${silent.accessToken ? silent.accessToken.length : 0}, fromCache=${!!silent.fromCache}`);
    return silent.accessToken;
  } catch (e) {
    const errorCode = String(e?.errorCode || e?.name || 'unknown');
    console.warn(`[AzureDiag] acquireToken: silent FAILED for tenant=${tenantLabel}, errorCode=${errorCode}`);
    const requiresInteraction = e instanceof msal.InteractionRequiredAuthError ||
      ['interaction_required', 'consent_required', 'login_required'].includes(String(e?.errorCode || '').toLowerCase());
    if (!requiresInteraction) throw e;

    // Try once more with forceRefresh before falling back to redirect
    try {
      console.log(`[AzureDiag] acquireToken: retrying with forceRefresh for tenant=${tenantLabel}`);
      const retry = await msalInstance.acquireTokenSilent({ ...request, forceRefresh: true });
      console.log(`[AzureDiag] acquireToken: forceRefresh OK for tenant=${tenantLabel}`);
      return retry.accessToken;
    } catch (_retryErr) {
      const retryCode = String(_retryErr?.errorCode || _retryErr?.name || 'unknown');
      console.warn(`[AzureDiag] acquireToken: forceRefresh FAILED for tenant=${tenantLabel}, errorCode=${retryCode}`);
      // In silentOnly mode, do not redirect; just throw so callers can skip this tenant.
      if (silentOnly) throw _retryErr;

      // Silent retry also failed; use redirect to get consent.
      // This avoids opening a popup that shows a mini copy of the website.
      console.log('[AzureDiag] acquireToken: falling back to redirect for consent');
      setAzureDiagnosticsStatus(t('azureConsentRequired'));
      const redirectRequest = {
        scopes,
        account: msAuthAccount
      };
      if (tenantId) {
        redirectRequest.authority = `https://login.microsoftonline.com/${tenantId}`;
      }
      if (loginHint) {
        redirectRequest.loginHint = loginHint;
      }
      await msalInstance.acquireTokenRedirect(redirectRequest);
      // Page will redirect; code below this line will not execute.
      // After redirect, handleRedirectPromise in initMsAuth will resume the session.
      return '';
    }
  }
}

async function armFetchJson(url, options = {}, tenantId) {
  const token = await acquireAzureAccessToken(ARM_SCOPES, tenantId);
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`ARM ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

async function armFetchJsonSilent(url, options = {}, tenantId) {
  const urlPath = url.replace('https://management.azure.com', '');
  console.log(`[AzureDiag] armFetchSilent: ${urlPath.substring(0, 120)}${urlPath.length > 120 ? '...' : ''}`);
  const token = await acquireAzureAccessToken(ARM_SCOPES, tenantId, true);
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  console.log(`[AzureDiag] armFetchSilent: HTTP ${response.status} for ${urlPath.substring(0, 80)}`);
  if (!response.ok) {
    const text = await response.text();
    console.warn(`[AzureDiag] armFetchSilent: FAILED HTTP ${response.status} \u2014 ${(text || '').substring(0, 200)}`);
    throw new Error(`ARM ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

async function armFetchAll(url, tenantId) {
  const items = [];
  let next = url;
  const maxPages = 50;
  let page = 0;
  while (next && page < maxPages) {
    page++;
    const data = await armFetchJson(next, {}, tenantId);
    if (Array.isArray(data.value)) items.push(...data.value);
    // ARM uses '@odata.nextLink' (or sometimes 'nextLink') for pagination
    next = data['@odata.nextLink'] || data.nextLink || null;
  }
  return items;
}

async function armFetchAllSilent(url, tenantId) {
  const items = [];
  let next = url;
  const maxPages = 50;
  let page = 0;
  while (next && page < maxPages) {
    page++;
    const data = await armFetchJsonSilent(next, {}, tenantId);
    const pageCount = Array.isArray(data.value) ? data.value.length : 0;
    if (Array.isArray(data.value)) items.push(...data.value);
    const hasNext = !!(data['@odata.nextLink'] || data.nextLink);
    console.log(`[AzureDiag] armFetchAllSilent: page=${page}, itemsOnPage=${pageCount}, totalSoFar=${items.length}, hasNextPage=${hasNext}`);
    next = data['@odata.nextLink'] || data.nextLink || null;
  }
  console.log(`[AzureDiag] armFetchAllSilent: DONE pages=${page}, totalItems=${items.length}`);
  return items;
}

async function switchAzureDirectory() {
  const input = document.getElementById('azureTenantInput');
  const tenantValue = (input ? input.value : '').trim();
  if (!tenantValue) {
    setAzureDiagnosticsStatus('Enter a tenant ID or domain name (e.g. contoso.onmicrosoft.com).', true);
    return;
  }
  if (!msalInstance) {
    setAzureDiagnosticsStatus(t('azureSignInRequired'), true);
    return;
  }
  console.log(`[AzureDiag] switchAzureDirectory: re-authenticating against tenant "${tenantValue}"`);
  try {
    await msalInstance.loginRedirect({
      scopes: GRAPH_SCOPES,
      extraScopesToConsent: [...ARM_SCOPES, ...LOG_ANALYTICS_SCOPES],
      authority: `https://login.microsoftonline.com/${encodeURIComponent(tenantValue)}`,
      prompt: 'login'
    });
  } catch (e) {
    console.error('[AzureDiag] switchAzureDirectory failed:', e);
    setAzureDiagnosticsStatus(t('authSignInFailed', { reason: e?.message || t('authUnknownError') }), true);
  }
}

async function loadAzureSubscriptions() {
  console.log('[AzureDiag] ===== loadAzureSubscriptions START =====');
  console.log('[AzureDiag] msalInstance exists:', !!msalInstance);
  console.log('[AzureDiag] msAuthAccount exists:', !!msAuthAccount);
  if (msAuthAccount) {
    console.log('[AzureDiag] account homeAccountId length:', (msAuthAccount.homeAccountId || '').length);
    console.log('[AzureDiag] account environment:', msAuthAccount.environment || 'n/a');
    console.log('[AzureDiag] account tenantId:', msAuthAccount.tenantId ? msAuthAccount.tenantId.substring(0, 8) + '...' : 'n/a');
  }
  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingSubscriptions'));

    // Step 1: Enumerate all tenants the user has access to.
    // The home-tenant token can list tenants even if it cannot get tokens for them.
    console.log('[AzureDiag] Step 1: Enumerating tenants via GET /tenants...');
    let tenants = [];
    try {
      tenants = await armFetchAll('https://management.azure.com/tenants?api-version=2020-01-01');
      console.log(`[AzureDiag] Step 1 result: ${tenants.length} tenant(s) returned`);
    } catch (tenantErr) {
      const errCode = String(tenantErr?.errorCode || tenantErr?.name || tenantErr?.message || 'unknown').substring(0, 100);
      console.warn(`[AzureDiag] Step 1 FAILED: ${errCode} \u2014 falling back to default tenant`);
      tenants = [];
    }
    const tenantIds = tenants.length > 0
      ? tenants.map(tn => String(tn.tenantId || '')).filter(Boolean)
      : [null]; // null = use default (home) tenant
    console.log(`[AzureDiag] Step 1 final: ${tenantIds.length} tenant ID(s) to query: [${tenantIds.map(t => t ? t.substring(0, 8) + '...' : 'default').join(', ')}]`);

    // Step 2: For each tenant, silently acquire an ARM token and list subscriptions.
    // Cross-tenant token acquisition will fail for tenants where the app has no
    // consent (AADSTS65001) or where conditional access blocks it (AADSTS53003).
    // Those failures are expected and silently skipped.
    console.log('[AzureDiag] Step 2: Loading subscriptions per tenant...');
    const allSubscriptions = [];
    const seenSubscriptionIds = new Set();
    for (let i = 0; i < tenantIds.length; i++) {
      const tid = tenantIds[i];
      const tenantLabel = tid ? tid.substring(0, 8) + '...' : 'default';
      console.log(`[AzureDiag] Step 2.${i + 1}: Loading subscriptions for tenant=${tenantLabel}`);
      setAzureDiagnosticsStatus(t('azureLoadingTenantSubscriptions', {
        tenant: tenantLabel.length > 12 ? tenantLabel.substring(0, 12) + '...' : tenantLabel,
        current: String(i + 1),
        total: String(tenantIds.length)
      }));
      try {
        const subs = await armFetchAllSilent('https://management.azure.com/subscriptions?api-version=2020-01-01', tid);
        console.log(`[AzureDiag] Step 2.${i + 1}: ARM returned ${(subs || []).length} raw subscription(s) for tenant=${tenantLabel}`);
        let added = 0;
        let skippedDupe = 0;
        for (const item of (subs || [])) {
          if (seenSubscriptionIds.has(item.subscriptionId)) { skippedDupe++; continue; }
          seenSubscriptionIds.add(item.subscriptionId);
          allSubscriptions.push({
            subscriptionId: item.subscriptionId,
            displayName: item.displayName || item.subscriptionId,
            tenantId: item.tenantId || tid || ''
          });
          added++;
        }
        console.log(`[AzureDiag] Step 2.${i + 1}: added=${added}, skippedDupe=${skippedDupe}`);
      } catch (subErr) {
        const errCode = String(subErr?.errorCode || subErr?.name || 'unknown');
        const errMsg = String(subErr?.message || '').substring(0, 150);
        console.warn(`[AzureDiag] Step 2.${i + 1}: FAILED for tenant=${tenantLabel}, errorCode=${errCode}, message=${errMsg}`);
      }
    }
    console.log(`[AzureDiag] Step 2 complete: ${allSubscriptions.length} total subscription(s) across all tenants`);

    azureDiagnosticsState.subscriptions = allSubscriptions;
    azureDiagnosticsState.resources = [];
    azureDiagnosticsState.workspaces = [];
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(
      allSubscriptions.length > 0
        ? `${allSubscriptions.length} ${t('azureSubscription').toLowerCase()}(s) loaded.`
        : t('azureNoSubscriptions')
    );

    if (allSubscriptions.length > 0) {
      const subSelect = document.getElementById('azureSubscriptionSelect');
      if (subSelect && subSelect.options.length > 0) subSelect.selectedIndex = 0;
      // Release busy before chaining so that discoverAzureResources can set it again cleanly
      azureDiagnosticsState.isBusy = false;
      renderAzureDiagnosticsUi();
      try {
        await discoverAzureResources();
      } catch (chainErr) {
        console.error('Azure resource discovery chain failed:', chainErr);
        setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: chainErr?.message || t('authUnknownError') }), true);
      }
      return;
    }
    console.log('[AzureDiag] ===== loadAzureSubscriptions END (no subscriptions) =====');
  } catch (e) {
    const errCode = String(e?.errorCode || e?.name || 'unknown');
    const errMsg = String(e?.message || '').substring(0, 200);
    console.error(`[AzureDiag] loadAzureSubscriptions OUTER ERROR: errorCode=${errCode}, message=${errMsg}`);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

function getSelectedSubscriptionTenantId() {
  const subId = getSelectedAzureSubscriptionId();
  if (!subId) return null;
  const sub = azureDiagnosticsState.subscriptions.find(s => s.subscriptionId === subId);
  return (sub && sub.tenantId) ? sub.tenantId : null;
}

async function discoverAzureResources() {
  const subscriptionId = getSelectedAzureSubscriptionId();
  if (!subscriptionId) {
    setAzureDiagnosticsStatus(t('azureSelectSubscriptionFirst'), true);
    return;
  }
  const tenantId = getSelectedSubscriptionTenantId();

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingResources'));

    const resources = await armFetchAll(`https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resources?api-version=2021-04-01`, tenantId);
    azureDiagnosticsState.resources = (resources || [])
      .filter(item => /^microsoft\.communication\//i.test(String(item.type || '')))
      .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));

    azureDiagnosticsState.workspaces = [];
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(
      azureDiagnosticsState.resources.length > 0
        ? `${azureDiagnosticsState.resources.length} ACS resource(s) discovered.`
        : t('azureNoResources')
    );

    if (azureDiagnosticsState.resources.length > 0) {
      const resSelect = document.getElementById('azureResourceSelect');
      if (resSelect && resSelect.options.length > 0) resSelect.selectedIndex = 0;
      // Release busy before chaining so that discoverAzureWorkspaces can set it again cleanly
      azureDiagnosticsState.isBusy = false;
      renderAzureDiagnosticsUi();
      try {
        await discoverAzureWorkspaces();
      } catch (chainErr) {
        console.error('Azure workspace discovery chain failed:', chainErr);
        setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: chainErr?.message || t('authUnknownError') }), true);
      }
      return;
    }
  } catch (e) {
    console.error('Azure resource discovery failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

async function getWorkspaceMetadata(workspaceResourceId) {
  // Ensure the resource ID starts with '/' for a valid ARM URL
  const normalizedId = workspaceResourceId.startsWith('/') ? workspaceResourceId : '/' + workspaceResourceId;
  const tenantId = getSelectedSubscriptionTenantId();
  const data = await armFetchJson(`https://management.azure.com${normalizedId}?api-version=2022-10-01`, {}, tenantId);
  return {
    id: data.id,
    name: data.name,
    location: data.location,
    customerId: data.properties && data.properties.customerId ? data.properties.customerId : '',
    resourceGroup: data.id ? (data.id.split('/')[4] || '') : ''
  };
}

async function discoverAzureWorkspaces() {
  const subscriptionId = getSelectedAzureSubscriptionId();
  if (!subscriptionId) {
    setAzureDiagnosticsStatus(t('azureSelectSubscriptionFirst'), true);
    return;
  }
  const tenantId = getSelectedSubscriptionTenantId();

  const selectedResourceId = getSelectedAzureResourceId();
  const resourcesToCheck = selectedResourceId
    ? azureDiagnosticsState.resources.filter(item => item.id === selectedResourceId)
    : azureDiagnosticsState.resources;

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingWorkspaces'));

    const workspaceMap = new Map();

    for (const resource of resourcesToCheck) {
      try {
        const diagnostics = await armFetchJson(`https://management.azure.com${resource.id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview`, {}, tenantId);
        for (const setting of (diagnostics.value || [])) {
          // The workspaceId lives under setting.properties, not at the top level
          const wsId = (setting.properties && setting.properties.workspaceId) || setting.workspaceId || '';
          if (wsId) {
            workspaceMap.set(wsId.toLowerCase(), wsId);
          }
        }
      } catch (diagErr) {
        console.warn('Diagnostic settings read failed for', resource.id, diagErr);
      }
    }

    if (workspaceMap.size === 0) {
      const resources = await armFetchAll(`https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resources?api-version=2021-04-01`, tenantId);
      for (const resource of resources) {
        if (String(resource.type || '').toLowerCase() === 'microsoft.operationalinsights/workspaces') {
          workspaceMap.set(String(resource.id).toLowerCase(), resource.id);
        }
      }
    }

    const workspaces = [];
    for (const workspaceId of workspaceMap.values()) {
      try {
        workspaces.push(await getWorkspaceMetadata(workspaceId));
      } catch (e) {
        console.warn('Workspace metadata load failed for', workspaceId, e);
      }
    }

    azureDiagnosticsState.workspaces = workspaces.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
    renderAzureDiagnosticsUi();

    if (azureDiagnosticsState.workspaces.length > 0) {
      const wsSelect = document.getElementById('azureWorkspaceSelect');
      if (wsSelect && wsSelect.options.length > 0) wsSelect.selectedIndex = 0;
    }

    setAzureDiagnosticsStatus(
      azureDiagnosticsState.workspaces.length > 0
        ? t('azureDiscoverSuccess')
        : t('azureNoWorkspaces')
    );
  } catch (e) {
    console.error('Azure workspace discovery failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

function buildAzureQueryTemplate(templateName) {
  const domain = String((document.getElementById('domainInput')?.value || '').trim());
  switch (templateName) {
    case 'workspaceInventory':
      return {
        name: t('azureWorkspaceInventory'),
        query: 'union withsource=SourceTable * | summarize Rows=count() by SourceTable | top 25 by Rows desc'
      };
    case 'domainSearch':
      if (!domain) throw new Error(t('azureDomainRequired'));
      return {
        name: t('azureDomainSearch'),
        query: `search in (*) "${escapeKqlString(domain)}" | take 100`
      };
    case 'acsSearch':
      return {
        name: t('azureAcsSearch'),
        query: 'search in (*) "Microsoft.Communication" | take 100'
      };
    default:
      throw new Error('Unknown Azure query template: ' + templateName);
  }
}

function renderLogAnalyticsResult(result) {
  if (!result || !Array.isArray(result.tables) || result.tables.length === 0) {
    return `<div>${escapeHtml(t('azureQueryReturnedNoTables'))}</div>`;
  }

  const workspace = azureDiagnosticsState.workspaces.find(item => item.id === getSelectedAzureWorkspaceId());
  const subscription = azureDiagnosticsState.subscriptions.find(item => item.subscriptionId === getSelectedAzureSubscriptionId());
  const meta = `<div class="azure-result-meta">${escapeHtml(t('azureResultsSummary', {
    tenant: lastAuthData?.tenantId || 'n/a',
    subscription: subscription?.displayName || subscription?.subscriptionId || 'n/a',
    workspace: workspace?.name || workspace?.customerId || 'n/a'
  }))}</div>`;
  const queryText = azureDiagnosticsState.lastQueryText
    ? `<div class="azure-result-meta"><strong>${escapeHtml(t('azureQueryTextLabel'))}:</strong> <code class="guidance-code">${escapeHtml(azureDiagnosticsState.lastQueryText)}</code></div>`
    : '';

  const tablesHtml = result.tables.map(table => {
    const columns = Array.isArray(table.columns) ? table.columns : [];
    const rows = Array.isArray(table.rows) ? table.rows.slice(0, 100) : [];
    const totalRows = Array.isArray(table.rows) ? table.rows.length : 0;
    const truncatedNote = totalRows > 100 ? ` (showing 100 of ${totalRows})` : '';
    return `
      <div>
        <div class="azure-result-meta"><strong>${escapeHtml(table.name || 'Table')}</strong> \u2014 ${rows.length} row(s)${truncatedNote}</div>
        <div class="azure-result-table-wrap">
          <table class="azure-result-table">
            <thead><tr>${columns.map(col => `<th>${escapeHtml(col.name || '')}</th>`).join('')}</tr></thead>
            <tbody>
              ${rows.map(row => `<tr>${columns.map((col, index) => {
                const val = row[index] === null || row[index] === undefined ? '' : String(row[index]);
                return `<td title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
              }).join('')}</tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  }).join('');

  return meta + queryText + tablesHtml;
}

async function runAzureQueryTemplate(templateName) {
  const workspaceId = getSelectedAzureWorkspaceId();
  if (!workspaceId) {
    setAzureDiagnosticsStatus(t('azureSelectWorkspaceFirst'), true);
    return;
  }

  const workspace = azureDiagnosticsState.workspaces.find(item => item.id === workspaceId);
  if (!workspace || !workspace.customerId) {
    setAzureDiagnosticsStatus(t('azureSelectWorkspaceFirst'), true);
    return;
  }

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();

    const template = buildAzureQueryTemplate(templateName);
    azureDiagnosticsState.lastQueryText = template.query;
    azureDiagnosticsState.lastQueryName = template.name;
    setAzureDiagnosticsStatus(t('azureRunningQuery', { name: template.name }));

    const token = await acquireAzureAccessToken(LOG_ANALYTICS_SCOPES);
    const response = await fetch(`https://api.loganalytics.io/v1/workspaces/${encodeURIComponent(workspace.customerId)}/query`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: template.query,
        timespan: 'P1D'
      })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${response.status}: ${text || response.statusText}`);
    }

    const result = await response.json();
    azureDiagnosticsState.lastResult = result;
    setAzureDiagnosticsResultsHtml(renderLogAnalyticsResult(result));
    setAzureDiagnosticsStatus(`${template.name} completed.`);
  } catch (e) {
    console.error('Azure Log Analytics query failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}
</script>

</body>
</html>
'@
# ===== HTML Post-Processing (Template Replacements) =====
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

# ===== Static Pages (Terms of Service, Privacy) & MSAL Setup =====
# ------------------- Embedded Terms of Service page -------------------
$script:TosPageHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Terms of Service - ACS Email Domain Checker</title>
<style nonce="__CSP_NONCE__">
  :root { --bg: #f4f6fb; --fg: #111827; --card-bg: #ffffff; --border: #e0e3ee; --link: #2f80ed; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #1e1e1e; --fg: #d4d4d4; --card-bg: #2d2d2d; --border: #444; --link: #5ba8f5; }
  }
  body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--fg); max-width: 800px; margin: 40px auto; padding: 0 24px; line-height: 1.7; }
  h1 { border-bottom: 2px solid var(--border); padding-bottom: 12px; }
  h2 { margin-top: 1.6em; }
  a { color: var(--link); }
  .back { display: inline-block; margin-bottom: 16px; text-decoration: none; }
</style>
</head>
<body>
<a id="backLink" class="back" href="/">&larr; Back to ACS Email Domain Checker</a>
<h1 id="tosTitle">Terms of Service</h1>
<p><strong id="updatedLabel">Last updated:</strong> <span id="updatedValue">March 2026</span></p>

<h2 id="tosSection1Title">1. Acceptance of Terms</h2>
<p id="tosSection1Body">By accessing or using the ACS Email Domain Checker (&ldquo;the Tool&rdquo;), you agree to be bound by these Terms of Service. If you do not agree, do not use the Tool.</p>

<h2 id="tosSection2Title">2. Description of the Tool</h2>
<p id="tosSection2Body">The Tool performs DNS lookups and provides guidance related to Azure Communication Services email domain verification. It is intended for informational and troubleshooting purposes only.</p>

<h2 id="tosSection3Title">3. No Warranty</h2>
<p id="tosSection3Body">The Tool is provided <strong>&ldquo;as is&rdquo;</strong> and <strong>&ldquo;as available&rdquo;</strong> without warranties of any kind, either express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement. DNS results may be cached, incomplete, or affected by network conditions.</p>

<h2 id="tosSection4Title">4. Limitation of Liability</h2>
<p id="tosSection4Body">In no event shall the authors or contributors be liable for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with your use of the Tool.</p>

<h2 id="tosSection5Title">5. Acceptable Use</h2>
<p id="tosSection5Intro">You agree not to use the Tool to:</p>
<ul>
  <li id="tosSection5Item1">Perform unauthorized or abusive DNS queries.</li>
  <li id="tosSection5Item2">Attempt to disrupt or overload the service.</li>
  <li id="tosSection5Item3">Violate any applicable laws or regulations.</li>
</ul>

<h2 id="tosSection6Title">6. Data &amp; Privacy</h2>
<p id="tosSection6Body">The Tool does not collect personally identifiable information. Optional anonymous usage metrics (when enabled) contain only HMAC-hashed domain names and aggregate counters. See the <a id="privacyLink" href="/privacy">Privacy Statement</a> for details.</p>

<h2 id="tosSection7Title">7. Third-Party Services</h2>
<p id="tosSection7Body">The Tool may interact with third-party DNS resolvers, WHOIS providers, and Azure APIs. Your use of those services is subject to their respective terms.</p>

<h2 id="tosSection8Title">8. Changes to These Terms</h2>
<p id="tosSection8Body">These terms may be updated from time to time. Continued use of the Tool after changes constitutes acceptance of the revised terms.</p>

<h2 id="tosSection9Title">9. Contact</h2>
<p id="tosSection9Body">For questions about these terms, visit <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.</p>
<script nonce="__CSP_NONCE__">
(() => {
  const TRANSLATIONS = {
    en: {
      pageTitle: 'Terms of Service - ACS Email Domain Checker',
      back: '\u2190 Back to ACS Email Domain Checker',
      title: 'Terms of Service',
      updatedLabel: 'Last updated:',
      updatedValue: 'March 2026',
      privacyStatement: 'Privacy Statement',
      s1t: '1. Acceptance of Terms',
      s1b: 'By accessing or using the ACS Email Domain Checker (\u201Cthe Tool\u201D), you agree to be bound by these Terms of Service. If you do not agree, do not use the Tool.',
      s2t: '2. Description of the Tool',
      s2b: 'The Tool performs DNS lookups and provides guidance related to Azure Communication Services email domain verification. It is intended for informational and troubleshooting purposes only.',
      s3t: '3. No Warranty',
      s3b: 'The Tool is provided <strong>\u201Cas is\u201D</strong> and <strong>\u201Cas available\u201D</strong> without warranties of any kind, either express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement. DNS results may be cached, incomplete, or affected by network conditions.',
      s4t: '4. Limitation of Liability',
      s4b: 'In no event shall the authors or contributors be liable for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with your use of the Tool.',
      s5t: '5. Acceptable Use',
      s5i: 'You agree not to use the Tool to:',
      s5l1: 'Perform unauthorized or abusive DNS queries.',
      s5l2: 'Attempt to disrupt or overload the service.',
      s5l3: 'Violate any applicable laws or regulations.',
      s6t: '6. Data & Privacy',
      s6b: 'The Tool does not collect personally identifiable information. Optional anonymous usage metrics (when enabled) contain only HMAC-hashed domain names and aggregate counters. See the <a id="privacyLink" href="/privacy">Privacy Statement</a> for details.',
      s7t: '7. Third-Party Services',
      s7b: 'The Tool may interact with third-party DNS resolvers, WHOIS providers, and Azure APIs. Your use of those services is subject to their respective terms.',
      s8t: '8. Changes to These Terms',
      s8b: 'These terms may be updated from time to time. Continued use of the Tool after changes constitutes acceptance of the revised terms.',
      s9t: '9. Contact',
      s9b: 'For questions about these terms, visit <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    es: {
      pageTitle: 'T\u00E9rminos de servicio - ACS Email Domain Checker', back: '\u2190 Volver a ACS Email Domain Checker', title: 'T\u00E9rminos de servicio', updatedLabel: '\u00DAltima actualizaci\u00F3n:', updatedValue: 'Marzo de 2026', privacyStatement: 'Declaraci\u00F3n de privacidad',
      s1t: '1. Aceptaci\u00F3n de los t\u00E9rminos', s1b: 'Al acceder o usar ACS Email Domain Checker (\u201Cla Herramienta\u201D), acepta quedar sujeto a estos T\u00E9rminos de servicio. Si no est\u00E1 de acuerdo, no use la Herramienta.',
      s2t: '2. Descripci\u00F3n de la herramienta', s2b: 'La Herramienta realiza b\u00FAsquedas DNS y proporciona orientaci\u00F3n relacionada con la verificaci\u00F3n de dominios de correo de Azure Communication Services. Est\u00E1 destinada \u00FAnicamente a fines informativos y de soluci\u00F3n de problemas.',
      s3t: '3. Sin garant\u00EDa', s3b: 'La Herramienta se proporciona <strong>\u201Ctal cual\u201D</strong> y <strong>\u201Cseg\u00FAn disponibilidad\u201D</strong>, sin garant\u00EDas de ning\u00FAn tipo, expresas o impl\u00EDcitas, incluidas, entre otras, las garant\u00EDas de comerciabilidad, idoneidad para un prop\u00F3sito determinado o no infracci\u00F3n. Los resultados DNS pueden estar almacenados en cach\u00E9, incompletos o verse afectados por las condiciones de red.',
      s4t: '4. Limitaci\u00F3n de responsabilidad', s4b: 'En ning\u00FAn caso los autores o colaboradores ser\u00E1n responsables de da\u00F1os directos, indirectos, incidentales, especiales o consecuentes derivados de o relacionados con el uso de la Herramienta.',
      s5t: '5. Uso aceptable', s5i: 'Acepta no usar la Herramienta para:', s5l1: 'Realizar consultas DNS no autorizadas o abusivas.', s5l2: 'Intentar interrumpir o sobrecargar el servicio.', s5l3: 'Infringir cualquier ley o normativa aplicable.',
      s6t: '6. Datos y privacidad', s6b: 'La Herramienta no recopila informaci\u00F3n personal identificable. Las m\u00E9tricas opcionales de uso an\u00F3nimo (cuando est\u00E1n habilitadas) contienen solo nombres de dominio con hash HMAC y contadores agregados. Consulte la <a id="privacyLink" href="/privacy">Declaraci\u00F3n de privacidad</a> para obtener m\u00E1s informaci\u00F3n.',
      s7t: '7. Servicios de terceros', s7b: 'La Herramienta puede interactuar con solucionadores DNS de terceros, proveedores de WHOIS y API de Azure. El uso de esos servicios est\u00E1 sujeto a sus respectivos t\u00E9rminos.',
      s8t: '8. Cambios en estos t\u00E9rminos', s8b: 'Estos t\u00E9rminos pueden actualizarse peri\u00F3dicamente. El uso continuado de la Herramienta despu\u00E9s de los cambios constituye la aceptaci\u00F3n de los t\u00E9rminos revisados.',
      s9t: '9. Contacto', s9b: 'Si tiene preguntas sobre estos t\u00E9rminos, visite <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    fr: {
      pageTitle: 'Conditions d\u2019utilisation - ACS Email Domain Checker', back: '\u2190 Retour \u00E0 ACS Email Domain Checker', title: 'Conditions d\u2019utilisation', updatedLabel: 'Derni\u00E8re mise \u00E0 jour :', updatedValue: 'Mars 2026', privacyStatement: 'D\u00E9claration de confidentialit\u00E9',
      s1t: '1. Acceptation des conditions', s1b: 'En acc\u00E9dant \u00E0 ACS Email Domain Checker (\u00AB l\u2019Outil \u00BB) ou en l\u2019utilisant, vous acceptez d\u2019\u00EAtre li\u00E9 par les pr\u00E9sentes Conditions d\u2019utilisation. Si vous n\u2019\u00EAtes pas d\u2019accord, n\u2019utilisez pas l\u2019Outil.',
      s2t: '2. Description de l\u2019outil', s2b: 'L\u2019Outil effectue des recherches DNS et fournit des conseils li\u00E9s \u00E0 la v\u00E9rification de domaines de messagerie Azure Communication Services. Il est destin\u00E9 uniquement \u00E0 des fins d\u2019information et de d\u00E9pannage.',
      s3t: '3. Absence de garantie', s3b: 'L\u2019Outil est fourni <strong>\u00AB tel quel \u00BB</strong> et <strong>\u00AB selon disponibilit\u00E9 \u00BB</strong>, sans garantie d\u2019aucune sorte, expresse ou implicite, y compris notamment les garanties de qualit\u00E9 marchande, d\u2019ad\u00E9quation \u00E0 un usage particulier ou d\u2019absence de contrefa\u00E7on. Les r\u00E9sultats DNS peuvent \u00EAtre mis en cache, incomplets ou affect\u00E9s par les conditions r\u00E9seau.',
      s4t: '4. Limitation de responsabilit\u00E9', s4b: 'En aucun cas les auteurs ou contributeurs ne pourront \u00EAtre tenus responsables de dommages directs, indirects, accessoires, sp\u00E9ciaux ou cons\u00E9cutifs r\u00E9sultant de l\u2019utilisation de l\u2019Outil ou en lien avec celle-ci.',
      s5t: '5. Utilisation acceptable', s5i: 'Vous acceptez de ne pas utiliser l\u2019Outil pour :', s5l1: 'Effectuer des requ\u00EAtes DNS non autoris\u00E9es ou abusives.', s5l2: 'Tenter de perturber ou de surcharger le service.', s5l3: 'Enfreindre toute loi ou r\u00E9glementation applicable.',
      s6t: '6. Donn\u00E9es et confidentialit\u00E9', s6b: 'L\u2019Outil ne collecte aucune information personnelle identifiable. Les m\u00E9triques facultatives d\u2019utilisation anonyme (lorsqu\u2019elles sont activ\u00E9es) contiennent uniquement des noms de domaine hach\u00E9s par HMAC et des compteurs agr\u00E9g\u00E9s. Consultez la <a id="privacyLink" href="/privacy">D\u00E9claration de confidentialit\u00E9</a> pour plus de d\u00E9tails.',
      s7t: '7. Services tiers', s7b: 'L\u2019Outil peut interagir avec des r\u00E9solveurs DNS tiers, des fournisseurs WHOIS et des API Azure. Votre utilisation de ces services est soumise \u00E0 leurs conditions respectives.',
      s8t: '8. Modifications de ces conditions', s8b: 'Ces conditions peuvent \u00EAtre mises \u00E0 jour de temps \u00E0 autre. L\u2019utilisation continue de l\u2019Outil apr\u00E8s les modifications constitue l\u2019acceptation des conditions r\u00E9vis\u00E9es.',
      s9t: '9. Contact', s9b: 'Pour toute question concernant ces conditions, consultez <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    de: {
      pageTitle: 'Nutzungsbedingungen - ACS Email Domain Checker', back: '\u2190 Zur\u00FCck zu ACS Email Domain Checker', title: 'Nutzungsbedingungen', updatedLabel: 'Zuletzt aktualisiert:', updatedValue: 'M\u00E4rz 2026', privacyStatement: 'Datenschutzerkl\u00E4rung',
      s1t: '1. Annahme der Bedingungen', s1b: 'Durch den Zugriff auf oder die Nutzung von ACS Email Domain Checker (\u201Edas Tool\u201C) erkl\u00E4ren Sie sich mit diesen Nutzungsbedingungen einverstanden. Wenn Sie nicht einverstanden sind, verwenden Sie das Tool nicht.',
      s2t: '2. Beschreibung des Tools', s2b: 'Das Tool f\u00FChrt DNS-Abfragen durch und bietet Hinweise zur E-Mail-Dom\u00E4nen\u00FCberpr\u00FCfung f\u00FCr Azure Communication Services. Es ist ausschlie\u00DFlich f\u00FCr Informations- und Fehlerbehebungszwecke bestimmt.',
      s3t: '3. Keine Gew\u00E4hrleistung', s3b: 'Das Tool wird <strong>\u201Ewie besehen\u201C</strong> und <strong>\u201Ewie verf\u00FCgbar\u201C</strong> ohne jegliche ausdr\u00FCckliche oder stillschweigende Gew\u00E4hrleistung bereitgestellt, einschlie\u00DFlich, aber nicht beschr\u00E4nkt auf Marktg\u00E4ngigkeit, Eignung f\u00FCr einen bestimmten Zweck oder Nichtverletzung von Rechten. DNS-Ergebnisse k\u00F6nnen zwischengespeichert, unvollst\u00E4ndig oder durch Netzwerkbedingungen beeinflusst sein.',
      s4t: '4. Haftungsbeschr\u00E4nkung', s4b: 'In keinem Fall haften die Autoren oder Mitwirkenden f\u00FCr direkte, indirekte, zuf\u00E4llige, besondere oder Folgesch\u00E4den, die aus der Nutzung des Tools entstehen oder damit zusammenh\u00E4ngen.',
      s5t: '5. Zul\u00E4ssige Nutzung', s5i: 'Sie erkl\u00E4ren sich damit einverstanden, das Tool nicht zu verwenden, um:', s5l1: 'Nicht autorisierte oder missbr\u00E4uchliche DNS-Abfragen durchzuf\u00FChren.', s5l2: 'Zu versuchen, den Dienst zu st\u00F6ren oder zu \u00FCberlasten.', s5l3: 'Geltende Gesetze oder Vorschriften zu verletzen.',
      s6t: '6. Daten und Datenschutz', s6b: 'Das Tool erfasst keine personenbezogenen Daten. Optionale anonyme Nutzungsmetriken (falls aktiviert) enthalten nur HMAC-gehashte Dom\u00E4nennamen und aggregierte Z\u00E4hler. Weitere Informationen finden Sie in der <a id="privacyLink" href="/privacy">Datenschutzerkl\u00E4rung</a>.',
      s7t: '7. Dienste von Drittanbietern', s7b: 'Das Tool kann mit DNS-Resolvern von Drittanbietern, WHOIS-Anbietern und Azure-APIs interagieren. Ihre Nutzung dieser Dienste unterliegt deren jeweiligen Bedingungen.',
      s8t: '8. \u00C4nderungen dieser Bedingungen', s8b: 'Diese Bedingungen k\u00F6nnen von Zeit zu Zeit aktualisiert werden. Die fortgesetzte Nutzung des Tools nach \u00C4nderungen gilt als Zustimmung zu den \u00FCberarbeiteten Bedingungen.',
      s9t: '9. Kontakt', s9b: 'Bei Fragen zu diesen Bedingungen besuchen Sie <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    'pt-BR': {
      pageTitle: 'Termos de Servi\u00E7o - ACS Email Domain Checker', back: '\u2190 Voltar para ACS Email Domain Checker', title: 'Termos de Servi\u00E7o', updatedLabel: '\u00DAltima atualiza\u00E7\u00E3o:', updatedValue: 'Mar\u00E7o de 2026', privacyStatement: 'Declara\u00E7\u00E3o de Privacidade',
      s1t: '1. Aceita\u00E7\u00E3o dos Termos', s1b: 'Ao acessar ou usar o ACS Email Domain Checker (\u201Ca Ferramenta\u201D), voc\u00EA concorda em estar vinculado a estes Termos de Servi\u00E7o. Se n\u00E3o concordar, n\u00E3o use a Ferramenta.',
      s2t: '2. Descri\u00E7\u00E3o da Ferramenta', s2b: 'A Ferramenta realiza pesquisas de DNS e fornece orienta\u00E7\u00F5es relacionadas \u00E0 verifica\u00E7\u00E3o de dom\u00EDnios de e-mail do Azure Communication Services. Ela se destina apenas a fins informativos e de solu\u00E7\u00E3o de problemas.',
      s3t: '3. Sem Garantia', s3b: 'A Ferramenta \u00E9 fornecida <strong>\u201Cno estado em que se encontra\u201D</strong> e <strong>\u201Cconforme dispon\u00EDvel\u201D</strong>, sem garantias de qualquer tipo, expressas ou impl\u00EDcitas, incluindo, entre outras, garantias de comercializa\u00E7\u00E3o, adequa\u00E7\u00E3o a uma finalidade espec\u00EDfica ou n\u00E3o viola\u00E7\u00E3o. Os resultados de DNS podem estar em cache, incompletos ou ser afetados pelas condi\u00E7\u00F5es da rede.',
      s4t: '4. Limita\u00E7\u00E3o de Responsabilidade', s4b: 'Em nenhuma hip\u00F3tese os autores ou colaboradores ser\u00E3o respons\u00E1veis por quaisquer danos diretos, indiretos, incidentais, especiais ou consequenciais decorrentes do uso da Ferramenta ou relacionados a ele.',
      s5t: '5. Uso Aceit\u00E1vel', s5i: 'Voc\u00EA concorda em n\u00E3o usar a Ferramenta para:', s5l1: 'Executar consultas de DNS n\u00E3o autorizadas ou abusivas.', s5l2: 'Tentar interromper ou sobrecarregar o servi\u00E7o.', s5l3: 'Violar quaisquer leis ou regulamentos aplic\u00E1veis.',
      s6t: '6. Dados e Privacidade', s6b: 'A Ferramenta n\u00E3o coleta informa\u00E7\u00F5es pessoalmente identific\u00E1veis. As m\u00E9tricas opcionais de uso an\u00F4nimo (quando habilitadas) cont\u00EAm apenas nomes de dom\u00EDnio com hash HMAC e contadores agregados. Consulte a <a id="privacyLink" href="/privacy">Declara\u00E7\u00E3o de Privacidade</a> para obter detalhes.',
      s7t: '7. Servi\u00E7os de Terceiros', s7b: 'A Ferramenta pode interagir com resolvedores DNS de terceiros, provedores de WHOIS e APIs do Azure. Seu uso desses servi\u00E7os est\u00E1 sujeito aos respectivos termos.',
      s8t: '8. Altera\u00E7\u00F5es Nestes Termos', s8b: 'Estes termos podem ser atualizados periodicamente. O uso continuado da Ferramenta ap\u00F3s as altera\u00E7\u00F5es constitui aceita\u00E7\u00E3o dos termos revisados.',
      s9t: '9. Contato', s9b: 'Para d\u00FAvidas sobre estes termos, visite <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    ar: {
      pageTitle: '\u0634\u0631\u0648\u0637 \u0627\u0644\u062E\u062F\u0645\u0629 - ACS Email Domain Checker', back: '\u2190 \u0627\u0644\u0639\u0648\u062F\u0629 \u0625\u0644\u0649 ACS Email Domain Checker', title: '\u0634\u0631\u0648\u0637 \u0627\u0644\u062E\u062F\u0645\u0629', updatedLabel: '\u0622\u062E\u0631 \u062A\u062D\u062F\u064A\u062B:', updatedValue: '\u0645\u0627\u0631\u0633 2026', privacyStatement: '\u0628\u064A\u0627\u0646 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629',
      s1t: '1. \u0642\u0628\u0648\u0644 \u0627\u0644\u0634\u0631\u0648\u0637', s1b: '\u0645\u0646 \u062E\u0644\u0627\u0644 \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 ACS Email Domain Checker (\u00AB\u0627\u0644\u0623\u062F\u0627\u0629\u00BB) \u0623\u0648 \u0627\u0633\u062A\u062E\u062F\u0627\u0645\u0647\u060C \u0641\u0625\u0646\u0643 \u062A\u0648\u0627\u0641\u0642 \u0639\u0644\u0649 \u0627\u0644\u0627\u0644\u062A\u0632\u0627\u0645 \u0628\u0634\u0631\u0648\u0637 \u0627\u0644\u062E\u062F\u0645\u0629 \u0647\u0630\u0647. \u0625\u0630\u0627 \u0643\u0646\u062A \u0644\u0627 \u062A\u0648\u0627\u0641\u0642\u060C \u0641\u0644\u0627 \u062A\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629.',
      s2t: '2. \u0648\u0635\u0641 \u0627\u0644\u0623\u062F\u0627\u0629', s2b: '\u062A\u064F\u062C\u0631\u064A \u0627\u0644\u0623\u062F\u0627\u0629 \u0639\u0645\u0644\u064A\u0627\u062A \u0628\u062D\u062B DNS \u0648\u062A\u0648\u0641\u0631 \u0625\u0631\u0634\u0627\u062F\u0627\u062A \u062A\u062A\u0639\u0644\u0642 \u0628\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0641\u064A Azure Communication Services. \u0648\u0647\u064A \u0645\u062E\u0635\u0635\u0629 \u0644\u0644\u0623\u063A\u0631\u0627\u0636 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062A\u064A\u0629 \u0648\u0627\u0633\u062A\u0643\u0634\u0627\u0641 \u0627\u0644\u0623\u062E\u0637\u0627\u0621 \u0641\u0642\u0637.',
      s3t: '3. \u0639\u062F\u0645 \u0648\u062C\u0648\u062F \u0636\u0645\u0627\u0646', s3b: '\u064A\u062A\u0645 \u062A\u0648\u0641\u064A\u0631 \u0627\u0644\u0623\u062F\u0627\u0629 <strong>\u00AB\u0643\u0645\u0627 \u0647\u064A\u00BB</strong> \u0648<strong>\u00AB\u062D\u0633\u0628 \u0627\u0644\u062A\u0648\u0641\u0631\u00BB</strong> \u0645\u0646 \u062F\u0648\u0646 \u0623\u064A \u0636\u0645\u0627\u0646\u0627\u062A \u0645\u0646 \u0623\u064A \u0646\u0648\u0639\u060C \u0633\u0648\u0627\u0621 \u0643\u0627\u0646\u062A \u0635\u0631\u064A\u062D\u0629 \u0623\u0648 \u0636\u0645\u0646\u064A\u0629\u060C \u0628\u0645\u0627 \u0641\u064A \u0630\u0644\u0643 \u0639\u0644\u0649 \u0633\u0628\u064A\u0644 \u0627\u0644\u0645\u062B\u0627\u0644 \u0644\u0627 \u0627\u0644\u062D\u0635\u0631 \u0636\u0645\u0627\u0646\u0627\u062A \u0627\u0644\u0642\u0627\u0628\u0644\u064A\u0629 \u0644\u0644\u062A\u0633\u0648\u064A\u0642 \u0623\u0648 \u0627\u0644\u0645\u0644\u0627\u0621\u0645\u0629 \u0644\u063A\u0631\u0636 \u0645\u0639\u064A\u0646 \u0623\u0648 \u0639\u062F\u0645 \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0643. \u0642\u062F \u062A\u0643\u0648\u0646 \u0646\u062A\u0627\u0626\u062C DNS \u0645\u062E\u0632\u0646\u0629 \u0645\u0624\u0642\u062A\u064B\u0627 \u0623\u0648 \u063A\u064A\u0631 \u0645\u0643\u062A\u0645\u0644\u0629 \u0623\u0648 \u0645\u062A\u0623\u062B\u0631\u0629 \u0628\u0638\u0631\u0648\u0641 \u0627\u0644\u0634\u0628\u0643\u0629.',
      s4t: '4. \u062A\u062D\u062F\u064A\u062F \u0627\u0644\u0645\u0633\u0624\u0648\u0644\u064A\u0629', s4b: '\u0644\u0627 \u064A\u062A\u062D\u0645\u0644 \u0627\u0644\u0645\u0624\u0644\u0641\u0648\u0646 \u0623\u0648 \u0627\u0644\u0645\u0633\u0627\u0647\u0645\u0648\u0646 \u0628\u0623\u064A \u062D\u0627\u0644 \u0645\u0646 \u0627\u0644\u0623\u062D\u0648\u0627\u0644 \u0627\u0644\u0645\u0633\u0624\u0648\u0644\u064A\u0629 \u0639\u0646 \u0623\u064A \u0623\u0636\u0631\u0627\u0631 \u0645\u0628\u0627\u0634\u0631\u0629 \u0623\u0648 \u063A\u064A\u0631 \u0645\u0628\u0627\u0634\u0631\u0629 \u0623\u0648 \u0639\u0631\u0636\u064A\u0629 \u0623\u0648 \u062E\u0627\u0635\u0629 \u0623\u0648 \u062A\u0628\u0639\u064A\u0629 \u062A\u0646\u0634\u0623 \u0639\u0646 \u0627\u0633\u062A\u062E\u062F\u0627\u0645\u0643 \u0644\u0644\u0623\u062F\u0627\u0629 \u0623\u0648 \u0641\u064A\u0645\u0627 \u064A\u062A\u0639\u0644\u0642 \u0628\u0647.',
      s5t: '5. \u0627\u0644\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0645\u0642\u0628\u0648\u0644', s5i: '\u0623\u0646\u062A \u062A\u0648\u0627\u0641\u0642 \u0639\u0644\u0649 \u0639\u062F\u0645 \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 \u0645\u0646 \u0623\u062C\u0644:', s5l1: '\u0625\u062C\u0631\u0627\u0621 \u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A DNS \u063A\u064A\u0631 \u0645\u0635\u0631\u062D \u0628\u0647\u0627 \u0623\u0648 \u0645\u0633\u064A\u0626\u0629.', s5l2: '\u0645\u062D\u0627\u0648\u0644\u0629 \u062A\u0639\u0637\u064A\u0644 \u0627\u0644\u062E\u062F\u0645\u0629 \u0623\u0648 \u062A\u062D\u0645\u064A\u0644\u0647\u0627 \u0641\u0648\u0642 \u0637\u0627\u0642\u062A\u0647\u0627.', s5l3: '\u0627\u0646\u062A\u0647\u0627\u0643 \u0623\u064A \u0642\u0648\u0627\u0646\u064A\u0646 \u0623\u0648 \u0644\u0648\u0627\u0626\u062D \u0645\u0639\u0645\u0648\u0644 \u0628\u0647\u0627.',
      s6t: '6. \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0648\u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629', s6b: '\u0644\u0627 \u062A\u062C\u0645\u0639 \u0627\u0644\u0623\u062F\u0627\u0629 \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u062A\u0639\u0631\u064A\u0641 \u0634\u062E\u0635\u064A\u0629. \u062A\u062D\u062A\u0648\u064A \u0645\u0642\u0627\u064A\u064A\u0633 \u0627\u0644\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0645\u062C\u0647\u0648\u0644\u0629 \u0627\u0644\u0627\u062E\u062A\u064A\u0627\u0631\u064A\u0629 (\u0639\u0646\u062F \u062A\u0645\u0643\u064A\u0646\u0647\u0627) \u0641\u0642\u0637 \u0639\u0644\u0649 \u0623\u0633\u0645\u0627\u0621 \u0646\u0637\u0627\u0642\u0627\u062A \u0645\u062C\u0632\u0623\u0629 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 HMAC \u0648\u0639\u062F\u0627\u062F\u0627\u062A \u0645\u062C\u0645\u0639\u0629. \u0631\u0627\u062C\u0639 <a id="privacyLink" href="/privacy">\u0628\u064A\u0627\u0646 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629</a> \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0627\u0644\u062A\u0641\u0627\u0635\u064A\u0644.',
      s7t: '7. \u062E\u062F\u0645\u0627\u062A \u0627\u0644\u062C\u0647\u0627\u062A \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629', s7b: '\u0642\u062F \u062A\u062A\u0641\u0627\u0639\u0644 \u0627\u0644\u0623\u062F\u0627\u0629 \u0645\u0639 \u0645\u062D\u0644\u0644\u0627\u062A DNS \u062A\u0627\u0628\u0639\u0629 \u0644\u062C\u0647\u0627\u062A \u062E\u0627\u0631\u062C\u064A\u0629\u060C \u0648\u0645\u0632\u0648\u062F\u064A WHOIS\u060C \u0648\u0648\u0627\u062C\u0647\u0627\u062A Azure \u0627\u0644\u0628\u0631\u0645\u062C\u064A\u0629. \u064A\u062E\u0636\u0639 \u0627\u0633\u062A\u062E\u062F\u0627\u0645\u0643 \u0644\u0647\u0630\u0647 \u0627\u0644\u062E\u062F\u0645\u0627\u062A \u0644\u0634\u0631\u0648\u0637\u0647\u0627 \u0627\u0644\u062E\u0627\u0635\u0629.',
      s8t: '8. \u0627\u0644\u062A\u063A\u064A\u064A\u0631\u0627\u062A \u0639\u0644\u0649 \u0647\u0630\u0647 \u0627\u0644\u0634\u0631\u0648\u0637', s8b: '\u0642\u062F \u064A\u062A\u0645 \u062A\u062D\u062F\u064A\u062B \u0647\u0630\u0647 \u0627\u0644\u0634\u0631\u0648\u0637 \u0645\u0646 \u0648\u0642\u062A \u0644\u0622\u062E\u0631. \u0648\u064A\u064F\u0639\u062F \u0627\u0633\u062A\u0645\u0631\u0627\u0631 \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 \u0628\u0639\u062F \u0627\u0644\u062A\u063A\u064A\u064A\u0631\u0627\u062A \u0642\u0628\u0648\u0644\u064B\u0627 \u0644\u0644\u0634\u0631\u0648\u0637 \u0627\u0644\u0645\u0639\u062F\u0644\u0629.',
      s9t: '9. \u0627\u0644\u0627\u062A\u0635\u0627\u0644', s9b: '\u0625\u0630\u0627 \u0643\u0627\u0646\u062A \u0644\u062F\u064A\u0643 \u0623\u0633\u0626\u0644\u0629 \u062D\u0648\u0644 \u0647\u0630\u0647 \u0627\u0644\u0634\u0631\u0648\u0637\u060C \u0641\u0632\u0631 <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    'zh-CN': {
      pageTitle: '\u670D\u52A1\u6761\u6B3E - ACS Email Domain Checker', back: '\u2190 \u8FD4\u56DE ACS Email Domain Checker', title: '\u670D\u52A1\u6761\u6B3E', updatedLabel: '\u4E0A\u6B21\u66F4\u65B0\uFF1A', updatedValue: '2026\u5E743\u6708', privacyStatement: '\u9690\u79C1\u58F0\u660E',
      s1t: '1. \u6761\u6B3E\u63A5\u53D7', s1b: '\u8BBF\u95EE\u6216\u4F7F\u7528 ACS Email Domain Checker\uFF08\u201C\u672C\u5DE5\u5177\u201D\uFF09\u5373\u8868\u793A\u60A8\u540C\u610F\u53D7\u8FD9\u4E9B\u670D\u52A1\u6761\u6B3E\u7684\u7EA6\u675F\u3002\u5982\u679C\u60A8\u4E0D\u540C\u610F\uFF0C\u8BF7\u4E0D\u8981\u4F7F\u7528\u672C\u5DE5\u5177\u3002',
      s2t: '2. \u5DE5\u5177\u8BF4\u660E', s2b: '\u672C\u5DE5\u5177\u6267\u884C DNS \u67E5\u8BE2\uFF0C\u5E76\u63D0\u4F9B\u4E0E Azure Communication Services \u7535\u5B50\u90AE\u4EF6\u57DF\u9A8C\u8BC1\u76F8\u5173\u7684\u6307\u5BFC\u3002\u5176\u4EC5\u7528\u4E8E\u4FE1\u606F\u53C2\u8003\u548C\u6545\u969C\u6392\u67E5\u3002',
      s3t: '3. \u65E0\u62C5\u4FDD', s3b: '\u672C\u5DE5\u5177\u6309<strong>\u201C\u539F\u6837\u201D</strong>\u548C<strong>\u201C\u73B0\u72B6\u201D</strong>\u63D0\u4F9B\uFF0C\u4E0D\u9644\u5E26\u4EFB\u4F55\u660E\u793A\u6216\u6697\u793A\u4FDD\u8BC1\uFF0C\u5305\u62EC\u4F46\u4E0D\u9650\u4E8E\u9002\u9500\u6027\u3001\u7279\u5B9A\u7528\u9014\u9002\u7528\u6027\u6216\u4E0D\u4FB5\u6743\u4FDD\u8BC1\u3002DNS \u7ED3\u679C\u53EF\u80FD\u88AB\u7F13\u5B58\u3001\u4E0D\u5B8C\u6574\u6216\u53D7\u7F51\u7EDC\u72B6\u51B5\u5F71\u54CD\u3002',
      s4t: '4. \u8D23\u4EFB\u9650\u5236', s4b: '\u5728\u4EFB\u4F55\u60C5\u51B5\u4E0B\uFF0C\u4F5C\u8005\u6216\u8D21\u732E\u8005\u5747\u4E0D\u5BF9\u56E0\u60A8\u4F7F\u7528\u672C\u5DE5\u5177\u800C\u4EA7\u751F\u7684\u6216\u4E0E\u4E4B\u76F8\u5173\u7684\u4EFB\u4F55\u76F4\u63A5\u3001\u95F4\u63A5\u3001\u9644\u5E26\u3001\u7279\u6B8A\u6216\u540E\u679C\u6027\u635F\u5BB3\u627F\u62C5\u8D23\u4EFB\u3002',
      s5t: '5. \u53EF\u63A5\u53D7\u7684\u4F7F\u7528', s5i: '\u60A8\u540C\u610F\u4E0D\u5C06\u672C\u5DE5\u5177\u7528\u4E8E\uFF1A', s5l1: '\u6267\u884C\u672A\u7ECF\u6388\u6743\u6216\u6EE5\u7528\u7684 DNS \u67E5\u8BE2\u3002', s5l2: '\u5C1D\u8BD5\u4E2D\u65AD\u6216\u4F7F\u670D\u52A1\u8FC7\u8F7D\u3002', s5l3: '\u8FDD\u53CD\u4EFB\u4F55\u9002\u7528\u6CD5\u5F8B\u6216\u6CD5\u89C4\u3002',
      s6t: '6. \u6570\u636E\u548C\u9690\u79C1', s6b: '\u672C\u5DE5\u5177\u4E0D\u6536\u96C6\u53EF\u8BC6\u522B\u4E2A\u4EBA\u8EAB\u4EFD\u7684\u4FE1\u606F\u3002\u53EF\u9009\u7684\u533F\u540D\u4F7F\u7528\u6307\u6807\uFF08\u542F\u7528\u65F6\uFF09\u4EC5\u5305\u542B\u7ECF\u8FC7 HMAC \u54C8\u5E0C\u7684\u57DF\u540D\u548C\u805A\u5408\u8BA1\u6570\u5668\u3002\u6709\u5173\u8BE6\u7EC6\u4FE1\u606F\uFF0C\u8BF7\u53C2\u9605<a id="privacyLink" href="/privacy">\u9690\u79C1\u58F0\u660E</a>\u3002',
      s7t: '7. \u7B2C\u4E09\u65B9\u670D\u52A1', s7b: '\u672C\u5DE5\u5177\u53EF\u80FD\u4F1A\u4E0E\u7B2C\u4E09\u65B9 DNS \u89E3\u6790\u5668\u3001WHOIS \u63D0\u4F9B\u5546\u548C Azure API \u4EA4\u4E92\u3002\u60A8\u5BF9\u8FD9\u4E9B\u670D\u52A1\u7684\u4F7F\u7528\u53D7\u5176\u5404\u81EA\u6761\u6B3E\u7EA6\u675F\u3002',
      s8t: '8. \u6761\u6B3E\u53D8\u66F4', s8b: '\u8FD9\u4E9B\u6761\u6B3E\u53EF\u80FD\u4F1A\u4E0D\u65F6\u66F4\u65B0\u3002\u60A8\u5728\u66F4\u6539\u540E\u7EE7\u7EED\u4F7F\u7528\u672C\u5DE5\u5177\u5373\u8868\u793A\u63A5\u53D7\u4FEE\u8BA2\u540E\u7684\u6761\u6B3E\u3002',
      s9t: '9. \u8054\u7CFB\u65B9\u5F0F', s9b: '\u5982\u5BF9\u8FD9\u4E9B\u6761\u6B3E\u6709\u7591\u95EE\uFF0C\u8BF7\u8BBF\u95EE <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>\u3002'
    },
    'hi-IN': {
      pageTitle: '\u0938\u0947\u0935\u093E \u0915\u0940 \u0936\u0930\u094D\u0924\u0947\u0902 - ACS Email Domain Checker', back: '\u2190 ACS Email Domain Checker \u092A\u0930 \u0935\u093E\u092A\u0938 \u091C\u093E\u090F\u0901', title: '\u0938\u0947\u0935\u093E \u0915\u0940 \u0936\u0930\u094D\u0924\u0947\u0902', updatedLabel: '\u0905\u0902\u0924\u093F\u092E \u0905\u092A\u0921\u0947\u091F:', updatedValue: '\u092E\u093E\u0930\u094D\u091A 2026', privacyStatement: '\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0935\u0915\u094D\u0924\u0935\u094D\u092F',
      s1t: '1. \u0936\u0930\u094D\u0924\u094B\u0902 \u0915\u0940 \u0938\u094D\u0935\u0940\u0915\u0943\u0924\u093F', s1b: 'ACS Email Domain Checker (\u201C\u091F\u0942\u0932\u201D) \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u092F\u093E \u0909\u0938 \u0924\u0915 \u092A\u0939\u0941\u0901\u091A \u0915\u0930\u0915\u0947, \u0906\u092A \u0907\u0928 \u0938\u0947\u0935\u093E \u0915\u0940 \u0936\u0930\u094D\u0924\u094B\u0902 \u0938\u0947 \u092C\u0902\u0927\u0947 \u0930\u0939\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F \u0938\u0939\u092E\u0924 \u0939\u094B\u0924\u0947 \u0939\u0948\u0902\u0964 \u092F\u0926\u093F \u0906\u092A \u0938\u0939\u092E\u0924 \u0928\u0939\u0940\u0902 \u0939\u0948\u0902, \u0924\u094B \u091F\u0942\u0932 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0928 \u0915\u0930\u0947\u0902\u0964',
      s2t: '2. \u091F\u0942\u0932 \u0915\u093E \u0935\u093F\u0935\u0930\u0923', s2b: '\u091F\u0942\u0932 DNS \u0932\u0941\u0915\u0905\u092A \u0915\u0930\u0924\u093E \u0939\u0948 \u0914\u0930 Azure Communication Services \u0908\u092E\u0947\u0932 \u0921\u094B\u092E\u0947\u0928 \u0938\u0924\u094D\u092F\u093E\u092A\u0928 \u0938\u0947 \u0938\u0902\u092C\u0902\u0927\u093F\u0924 \u092E\u093E\u0930\u094D\u0917\u0926\u0930\u094D\u0936\u0928 \u092A\u094D\u0930\u0926\u093E\u0928 \u0915\u0930\u0924\u093E \u0939\u0948\u0964 \u092F\u0939 \u0915\u0947\u0935\u0932 \u0938\u0942\u091A\u0928\u093E\u0924\u094D\u092E\u0915 \u0914\u0930 \u0938\u092E\u0938\u094D\u092F\u093E \u0928\u093F\u0935\u093E\u0930\u0923 \u0909\u0926\u094D\u0926\u0947\u0936\u094D\u092F\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F \u0939\u0948\u0964',
      s3t: '3. \u0915\u094B\u0908 \u0935\u093E\u0930\u0902\u091F\u0940 \u0928\u0939\u0940\u0902', s3b: '\u091F\u0942\u0932 <strong>\u201C\u091C\u0948\u0938\u093E \u0939\u0948\u201D</strong> \u0914\u0930 <strong>\u201C\u091C\u0948\u0938\u093E \u0909\u092A\u0932\u092C\u094D\u0927 \u0939\u0948\u201D</strong> \u0906\u0927\u093E\u0930 \u092A\u0930 \u092A\u094D\u0930\u0926\u093E\u0928 \u0915\u093F\u092F\u093E \u091C\u093E\u0924\u093E \u0939\u0948, \u092C\u093F\u0928\u093E \u0915\u093F\u0938\u0940 \u092A\u094D\u0930\u0915\u093E\u0930 \u0915\u0940 \u0935\u093E\u0930\u0902\u091F\u0940 \u0915\u0947, \u091A\u093E\u0939\u0947 \u0935\u0939 \u0938\u094D\u092A\u0937\u094D\u091F \u0939\u094B \u092F\u093E \u0928\u093F\u0939\u093F\u0924, \u091C\u093F\u0938\u092E\u0947\u0902 \u0935\u094D\u092F\u093E\u092A\u093E\u0930\u0940\u0915\u0930\u0923, \u0915\u093F\u0938\u0940 \u0935\u093F\u0936\u0947\u0937 \u0909\u0926\u094D\u0926\u0947\u0936\u094D\u092F \u0915\u0947 \u0932\u093F\u090F \u0909\u092A\u092F\u0941\u0915\u094D\u0924\u0924\u093E, \u092F\u093E \u0909\u0932\u094D\u0932\u0902\u0918\u0928 \u0928 \u0939\u094B\u0928\u0947 \u0915\u0940 \u0935\u093E\u0930\u0902\u091F\u0940 \u0936\u093E\u092E\u093F\u0932 \u0939\u0948 \u0932\u0947\u0915\u093F\u0928 \u0907\u0928\u094D\u0939\u0940\u0902 \u0924\u0915 \u0938\u0940\u092E\u093F\u0924 \u0928\u0939\u0940\u0902 \u0939\u0948\u0964 DNS \u092A\u0930\u093F\u0923\u093E\u092E \u0915\u0948\u0936 \u0915\u093F\u090F \u091C\u093E \u0938\u0915\u0924\u0947 \u0939\u0948\u0902, \u0905\u092A\u0942\u0930\u094D\u0923 \u0939\u094B \u0938\u0915\u0924\u0947 \u0939\u0948\u0902, \u092F\u093E \u0928\u0947\u091F\u0935\u0930\u094D\u0915 \u0938\u094D\u0925\u093F\u0924\u093F\u092F\u094B\u0902 \u0938\u0947 \u092A\u094D\u0930\u092D\u093E\u0935\u093F\u0924 \u0939\u094B \u0938\u0915\u0924\u0947 \u0939\u0948\u0902\u0964',
      s4t: '4. \u0926\u093E\u092F\u093F\u0924\u094D\u0935 \u0915\u0940 \u0938\u0940\u092E\u093E', s4b: '\u0915\u093F\u0938\u0940 \u092D\u0940 \u0938\u094D\u0925\u093F\u0924\u093F \u092E\u0947\u0902 \u0932\u0947\u0916\u0915 \u092F\u093E \u092F\u094B\u0917\u0926\u093E\u0928\u0915\u0930\u094D\u0924\u093E \u091F\u0942\u0932 \u0915\u0947 \u0906\u092A\u0915\u0947 \u0909\u092A\u092F\u094B\u0917 \u0938\u0947 \u0909\u0924\u094D\u092A\u0928\u094D\u0928 \u092F\u093E \u0909\u0938\u0938\u0947 \u0938\u0902\u092C\u0902\u0927\u093F\u0924 \u0915\u093F\u0938\u0940 \u092D\u0940 \u092A\u094D\u0930\u0924\u094D\u092F\u0915\u094D\u0937, \u0905\u092A\u094D\u0930\u0924\u094D\u092F\u0915\u094D\u0937, \u0906\u0915\u0938\u094D\u092E\u093F\u0915, \u0935\u093F\u0936\u0947\u0937 \u092F\u093E \u092A\u0930\u093F\u0923\u093E\u092E\u0940 \u0915\u094D\u0937\u0924\u093F \u0915\u0947 \u0932\u093F\u090F \u0909\u0924\u094D\u0924\u0930\u0926\u093E\u092F\u0940 \u0928\u0939\u0940\u0902 \u0939\u094B\u0902\u0917\u0947\u0964',
      s5t: '5. \u0938\u094D\u0935\u0940\u0915\u093E\u0930\u094D\u092F \u0909\u092A\u092F\u094B\u0917', s5i: '\u0906\u092A \u0938\u0939\u092E\u0924 \u0939\u0948\u0902 \u0915\u093F \u091F\u0942\u0932 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0907\u0928 \u0909\u0926\u094D\u0926\u0947\u0936\u094D\u092F\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F \u0928\u0939\u0940\u0902 \u0915\u0930\u0947\u0902\u0917\u0947:', s5l1: '\u0905\u0928\u0927\u093F\u0915\u0943\u0924 \u092F\u093E \u0926\u0941\u0930\u0941\u092A\u092F\u094B\u0917\u092A\u0942\u0930\u094D\u0923 DNS \u0915\u094D\u0935\u0947\u0930\u0940 \u0915\u0930\u0928\u093E\u0964', s5l2: '\u0938\u0947\u0935\u093E \u0915\u094B \u092C\u093E\u0927\u093F\u0924 \u0915\u0930\u0928\u0947 \u092F\u093E \u0909\u0938 \u092A\u0930 \u0905\u0924\u094D\u092F\u0927\u093F\u0915 \u092D\u093E\u0930 \u0921\u093E\u0932\u0928\u0947 \u0915\u093E \u092A\u094D\u0930\u092F\u093E\u0938 \u0915\u0930\u0928\u093E\u0964', s5l3: '\u0915\u093F\u0938\u0940 \u0932\u093E\u0917\u0942 \u0915\u093E\u0928\u0942\u0928 \u092F\u093E \u0935\u093F\u0928\u093F\u092F\u092E \u0915\u093E \u0909\u0932\u094D\u0932\u0902\u0918\u0928 \u0915\u0930\u0928\u093E\u0964',
      s6t: '6. \u0921\u0947\u091F\u093E \u0914\u0930 \u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E', s6b: '\u091F\u0942\u0932 \u0935\u094D\u092F\u0915\u094D\u0924\u093F\u0917\u0924 \u092A\u0939\u091A\u093E\u0928 \u092F\u094B\u0917\u094D\u092F \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u090F\u0915\u0924\u094D\u0930 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964 \u0935\u0948\u0915\u0932\u094D\u092A\u093F\u0915 \u0905\u0928\u093E\u092E \u0909\u092A\u092F\u094B\u0917 \u092E\u0940\u091F\u094D\u0930\u093F\u0915 (\u0938\u0915\u094D\u0937\u092E \u0939\u094B\u0928\u0947 \u092A\u0930) \u0915\u0947\u0935\u0932 HMAC-\u0939\u0948\u0936 \u0915\u093F\u090F \u0917\u090F \u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E \u0914\u0930 \u0938\u092E\u0917\u094D\u0930 \u0915\u093E\u0909\u0902\u091F\u0930 \u0930\u0916\u0924\u0947 \u0939\u0948\u0902\u0964 \u0935\u093F\u0935\u0930\u0923 \u0915\u0947 \u0932\u093F\u090F <a id="privacyLink" href="/privacy">\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0935\u0915\u094D\u0924\u0935\u094D\u092F</a> \u0926\u0947\u0916\u0947\u0902\u0964',
      s7t: '7. \u0924\u0943\u0924\u0940\u092F-\u092A\u0915\u094D\u0937 \u0938\u0947\u0935\u093E\u090F\u0901', s7b: '\u091F\u0942\u0932 \u0924\u0943\u0924\u0940\u092F-\u092A\u0915\u094D\u0937 DNS resolvers, WHOIS providers \u0914\u0930 Azure APIs \u0915\u0947 \u0938\u093E\u0925 \u0907\u0902\u091F\u0930\u0948\u0915\u094D\u091F \u0915\u0930 \u0938\u0915\u0924\u093E \u0939\u0948\u0964 \u0909\u0928 \u0938\u0947\u0935\u093E\u0913\u0902 \u0915\u093E \u0906\u092A\u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0909\u0928\u0915\u0947 \u0938\u0902\u092C\u0902\u0927\u093F\u0924 \u0928\u093F\u092F\u092E\u094B\u0902 \u0915\u0947 \u0905\u0927\u0940\u0928 \u0939\u0948\u0964',
      s8t: '8. \u0907\u0928 \u0936\u0930\u094D\u0924\u094B\u0902 \u092E\u0947\u0902 \u092A\u0930\u093F\u0935\u0930\u094D\u0924\u0928', s8b: '\u0907\u0928 \u0936\u0930\u094D\u0924\u094B\u0902 \u0915\u094B \u0938\u092E\u092F-\u0938\u092E\u092F \u092A\u0930 \u0905\u0926\u094D\u092F\u0924\u0928 \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u0924\u093E \u0939\u0948\u0964 \u092A\u0930\u093F\u0935\u0930\u094D\u0924\u0928\u094B\u0902 \u0915\u0947 \u092C\u093E\u0926 \u091F\u0942\u0932 \u0915\u093E \u0928\u093F\u0930\u0902\u0924\u0930 \u0909\u092A\u092F\u094B\u0917 \u0938\u0902\u0936\u094B\u0927\u093F\u0924 \u0936\u0930\u094D\u0924\u094B\u0902 \u0915\u0940 \u0938\u094D\u0935\u0940\u0915\u0943\u0924\u093F \u092E\u093E\u0928\u093E \u091C\u093E\u090F\u0917\u093E\u0964',
      s9t: '9. \u0938\u0902\u092A\u0930\u094D\u0915', s9b: '\u0907\u0928 \u0936\u0930\u094D\u0924\u094B\u0902 \u0915\u0947 \u092C\u093E\u0930\u0947 \u092E\u0947\u0902 \u092A\u094D\u0930\u0936\u094D\u0928\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a> \u092A\u0930 \u091C\u093E\u090F\u0901\u0964'
    },
    'ja-JP': {
      pageTitle: '\u5229\u7528\u898F\u7D04 - ACS Email Domain Checker', back: '\u2190 ACS Email Domain Checker \u306B\u623B\u308B', title: '\u5229\u7528\u898F\u7D04', updatedLabel: '\u6700\u7D42\u66F4\u65B0:', updatedValue: '2026\u5E743\u6708', privacyStatement: '\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8',
      s1t: '1. \u898F\u7D04\u3078\u306E\u540C\u610F', s1b: 'ACS Email Domain Checker\uFF08\u300C\u672C\u30C4\u30FC\u30EB\u300D\uFF09\u306B\u30A2\u30AF\u30BB\u30B9\u307E\u305F\u306F\u4F7F\u7528\u3059\u308B\u3053\u3068\u306B\u3088\u308A\u3001\u3053\u308C\u3089\u306E\u5229\u7528\u898F\u7D04\u306B\u62D8\u675F\u3055\u308C\u308B\u3053\u3068\u306B\u540C\u610F\u3057\u305F\u3082\u306E\u3068\u307F\u306A\u3055\u308C\u307E\u3059\u3002\u540C\u610F\u3057\u306A\u3044\u5834\u5408\u306F\u3001\u672C\u30C4\u30FC\u30EB\u3092\u4F7F\u7528\u3057\u306A\u3044\u3067\u304F\u3060\u3055\u3044\u3002',
      s2t: '2. \u30C4\u30FC\u30EB\u306E\u8AAC\u660E', s2b: '\u672C\u30C4\u30FC\u30EB\u306F DNS \u53C2\u7167\u3092\u5B9F\u884C\u3057\u3001Azure Communication Services \u306E\u30E1\u30FC\u30EB \u30C9\u30E1\u30A4\u30F3\u691C\u8A3C\u306B\u95A2\u3059\u308B\u30AC\u30A4\u30C0\u30F3\u30B9\u3092\u63D0\u4F9B\u3057\u307E\u3059\u3002\u3053\u308C\u306F\u60C5\u5831\u63D0\u4F9B\u304A\u3088\u3073\u30C8\u30E9\u30D6\u30EB\u30B7\u30E5\u30FC\u30C6\u30A3\u30F3\u30B0\u306E\u307F\u3092\u76EE\u7684\u3068\u3057\u3066\u3044\u307E\u3059\u3002',
      s3t: '3. \u7121\u4FDD\u8A3C', s3b: '\u672C\u30C4\u30FC\u30EB\u306F <strong>\u300C\u73FE\u72B6\u6709\u59FF\u300D</strong> \u304B\u3064 <strong>\u300C\u63D0\u4F9B\u53EF\u80FD\u306A\u7BC4\u56F2\u300D</strong> \u3067\u63D0\u4F9B\u3055\u308C\u3001\u660E\u793A\u307E\u305F\u306F\u9ED9\u793A\u3092\u554F\u308F\u305A\u3001\u5546\u54C1\u6027\u3001\u7279\u5B9A\u76EE\u7684\u9069\u5408\u6027\u3001\u975E\u4FB5\u5BB3\u6027\u3092\u542B\u3080\u304C\u3053\u308C\u3089\u306B\u9650\u5B9A\u3055\u308C\u306A\u3044\u3001\u3044\u304B\u306A\u308B\u4FDD\u8A3C\u3082\u884C\u3044\u307E\u305B\u3093\u3002DNS \u306E\u7D50\u679C\u306F\u30AD\u30E3\u30C3\u30B7\u30E5\u3055\u308C\u3066\u3044\u308B\u5834\u5408\u3084\u4E0D\u5B8C\u5168\u306A\u5834\u5408\u304C\u3042\u308A\u3001\u30CD\u30C3\u30C8\u30EF\u30FC\u30AF\u72B6\u6CC1\u306E\u5F71\u97FF\u3092\u53D7\u3051\u308B\u3053\u3068\u304C\u3042\u308A\u307E\u3059\u3002',
      s4t: '4. \u8CAC\u4EFB\u306E\u5236\u9650', s4b: '\u8457\u8005\u307E\u305F\u306F\u8CA2\u732E\u8005\u306F\u3001\u3044\u304B\u306A\u308B\u5834\u5408\u3082\u3001\u672C\u30C4\u30FC\u30EB\u306E\u4F7F\u7528\u306B\u8D77\u56E0\u307E\u305F\u306F\u95A2\u9023\u3057\u3066\u751F\u3058\u308B\u76F4\u63A5\u7684\u3001\u9593\u63A5\u7684\u3001\u5076\u767A\u7684\u3001\u7279\u5225\u3001\u7D50\u679C\u7684\u640D\u5BB3\u306B\u3064\u3044\u3066\u8CAC\u4EFB\u3092\u8CA0\u3044\u307E\u305B\u3093\u3002',
      s5t: '5. \u8A31\u5BB9\u3055\u308C\u308B\u4F7F\u7528', s5i: '\u304A\u5BA2\u69D8\u306F\u3001\u672C\u30C4\u30FC\u30EB\u3092\u6B21\u306E\u76EE\u7684\u306B\u4F7F\u7528\u3057\u306A\u3044\u3053\u3068\u306B\u540C\u610F\u3057\u307E\u3059\u3002', s5l1: '\u8A31\u53EF\u3055\u308C\u3066\u3044\u306A\u3044\u3001\u307E\u305F\u306F\u6FEB\u7528\u7684\u306A DNS \u30AF\u30A8\u30EA\u306E\u5B9F\u884C\u3002', s5l2: '\u30B5\u30FC\u30D3\u30B9\u306E\u59A8\u5BB3\u3084\u904E\u8CA0\u8377\u306E\u8A66\u307F\u3002', s5l3: '\u9069\u7528\u3055\u308C\u308B\u6CD5\u4EE4\u307E\u305F\u306F\u898F\u5236\u3078\u306E\u9055\u53CD\u3002',
      s6t: '6. \u30C7\u30FC\u30BF\u3068\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC', s6b: '\u672C\u30C4\u30FC\u30EB\u306F\u500B\u4EBA\u3092\u7279\u5B9A\u3067\u304D\u308B\u60C5\u5831\u3092\u53CE\u96C6\u3057\u307E\u305B\u3093\u3002\u30AA\u30D7\u30B7\u30E7\u30F3\u306E\u533F\u540D\u5229\u7528\u30E1\u30C8\u30EA\u30C3\u30AF\uFF08\u6709\u52B9\u6642\uFF09\u306B\u306F\u3001HMAC \u30CF\u30C3\u30B7\u30E5\u5316\u3055\u308C\u305F\u30C9\u30E1\u30A4\u30F3\u540D\u3068\u96C6\u8A08\u30AB\u30A6\u30F3\u30BF\u30FC\u306E\u307F\u304C\u542B\u307E\u308C\u307E\u3059\u3002\u8A73\u7D30\u306B\u3064\u3044\u3066\u306F <a id="privacyLink" href="/privacy">\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8</a> \u3092\u53C2\u7167\u3057\u3066\u304F\u3060\u3055\u3044\u3002',
      s7t: '7. \u30B5\u30FC\u30C9\u30D1\u30FC\u30C6\u30A3 \u30B5\u30FC\u30D3\u30B9', s7b: '\u672C\u30C4\u30FC\u30EB\u306F\u3001\u30B5\u30FC\u30C9\u30D1\u30FC\u30C6\u30A3\u306E DNS \u30EA\u30BE\u30EB\u30D0\u30FC\u3001WHOIS \u30D7\u30ED\u30D0\u30A4\u30C0\u30FC\u3001\u304A\u3088\u3073 Azure API \u3068\u3084\u308A\u53D6\u308A\u3059\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002\u3053\u308C\u3089\u306E\u30B5\u30FC\u30D3\u30B9\u306E\u4F7F\u7528\u306B\u306F\u3001\u305D\u308C\u305E\u308C\u306E\u898F\u7D04\u304C\u9069\u7528\u3055\u308C\u307E\u3059\u3002',
      s8t: '8. \u672C\u898F\u7D04\u306E\u5909\u66F4', s8b: '\u3053\u308C\u3089\u306E\u898F\u7D04\u306F\u968F\u6642\u66F4\u65B0\u3055\u308C\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002\u5909\u66F4\u5F8C\u3082\u672C\u30C4\u30FC\u30EB\u306E\u4F7F\u7528\u3092\u7D99\u7D9A\u3057\u305F\u5834\u5408\u3001\u6539\u8A02\u5F8C\u306E\u898F\u7D04\u306B\u540C\u610F\u3057\u305F\u3082\u306E\u3068\u307F\u306A\u3055\u308C\u307E\u3059\u3002',
      s9t: '9. \u304A\u554F\u3044\u5408\u308F\u305B', s9b: '\u672C\u898F\u7D04\u306B\u95A2\u3059\u308B\u3054\u8CEA\u554F\u306F\u3001<a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a> \u3092\u3054\u89A7\u304F\u3060\u3055\u3044\u3002'
    },
    'ru-RU': {
      pageTitle: '\u0423\u0441\u043B\u043E\u0432\u0438\u044F \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F - ACS Email Domain Checker', back: '\u2190 \u041D\u0430\u0437\u0430\u0434 \u043A ACS Email Domain Checker', title: '\u0423\u0441\u043B\u043E\u0432\u0438\u044F \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F', updatedLabel: '\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u0435 \u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435:', updatedValue: '\u041C\u0430\u0440\u0442 2026', privacyStatement: '\u0417\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0435 \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438',
      s1t: '1. \u041F\u0440\u0438\u043D\u044F\u0442\u0438\u0435 \u0443\u0441\u043B\u043E\u0432\u0438\u0439', s1b: '\u041F\u043E\u043B\u0443\u0447\u0430\u044F \u0434\u043E\u0441\u0442\u0443\u043F \u043A ACS Email Domain Checker (\u00AB\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u00BB) \u0438\u043B\u0438 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044F \u0435\u0433\u043E, \u0432\u044B \u0441\u043E\u0433\u043B\u0430\u0448\u0430\u0435\u0442\u0435\u0441\u044C \u0441\u043E\u0431\u043B\u044E\u0434\u0430\u0442\u044C \u043D\u0430\u0441\u0442\u043E\u044F\u0449\u0438\u0435 \u0423\u0441\u043B\u043E\u0432\u0438\u044F \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F. \u0415\u0441\u043B\u0438 \u0432\u044B \u043D\u0435 \u0441\u043E\u0433\u043B\u0430\u0441\u043D\u044B, \u043D\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442.',
      s2t: '2. \u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0430', s2b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0432\u044B\u043F\u043E\u043B\u043D\u044F\u0435\u0442 DNS-\u0437\u0430\u043F\u0440\u043E\u0441\u044B \u0438 \u043F\u0440\u0435\u0434\u043E\u0441\u0442\u0430\u0432\u043B\u044F\u0435\u0442 \u0440\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438, \u0441\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0435 \u0441 \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u043E\u0439 \u043F\u043E\u0447\u0442\u043E\u0432\u044B\u0445 \u0434\u043E\u043C\u0435\u043D\u043E\u0432 Azure Communication Services. \u041E\u043D \u043F\u0440\u0435\u0434\u043D\u0430\u0437\u043D\u0430\u0447\u0435\u043D \u0442\u043E\u043B\u044C\u043A\u043E \u0434\u043B\u044F \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u043E\u043D\u043D\u044B\u0445 \u0446\u0435\u043B\u0435\u0439 \u0438 \u0443\u0441\u0442\u0440\u0430\u043D\u0435\u043D\u0438\u044F \u043D\u0435\u043F\u043E\u043B\u0430\u0434\u043E\u043A.',
      s3t: '3. \u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0438\u0435 \u0433\u0430\u0440\u0430\u043D\u0442\u0438\u0439', s3b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043F\u0440\u0435\u0434\u043E\u0441\u0442\u0430\u0432\u043B\u044F\u0435\u0442\u0441\u044F <strong>\u00AB\u043A\u0430\u043A \u0435\u0441\u0442\u044C\u00BB</strong> \u0438 <strong>\u00AB\u043F\u043E \u043C\u0435\u0440\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0441\u0442\u0438\u00BB</strong> \u0431\u0435\u0437 \u043A\u0430\u043A\u0438\u0445-\u043B\u0438\u0431\u043E \u0433\u0430\u0440\u0430\u043D\u0442\u0438\u0439, \u044F\u0432\u043D\u044B\u0445 \u0438\u043B\u0438 \u043F\u043E\u0434\u0440\u0430\u0437\u0443\u043C\u0435\u0432\u0430\u0435\u043C\u044B\u0445, \u0432\u043A\u043B\u044E\u0447\u0430\u044F, \u043F\u043E\u043C\u0438\u043C\u043E \u043F\u0440\u043E\u0447\u0435\u0433\u043E, \u0433\u0430\u0440\u0430\u043D\u0442\u0438\u0438 \u0442\u043E\u0432\u0430\u0440\u043D\u043E\u0439 \u043F\u0440\u0438\u0433\u043E\u0434\u043D\u043E\u0441\u0442\u0438, \u043F\u0440\u0438\u0433\u043E\u0434\u043D\u043E\u0441\u0442\u0438 \u0434\u043B\u044F \u043E\u043F\u0440\u0435\u0434\u0435\u043B\u0435\u043D\u043D\u043E\u0439 \u0446\u0435\u043B\u0438 \u0438\u043B\u0438 \u043D\u0435\u043D\u0430\u0440\u0443\u0448\u0435\u043D\u0438\u044F \u043F\u0440\u0430\u0432. \u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442\u044B DNS \u043C\u043E\u0433\u0443\u0442 \u043A\u044D\u0448\u0438\u0440\u043E\u0432\u0430\u0442\u044C\u0441\u044F, \u0431\u044B\u0442\u044C \u043D\u0435\u043F\u043E\u043B\u043D\u044B\u043C\u0438 \u0438\u043B\u0438 \u0437\u0430\u0432\u0438\u0441\u0435\u0442\u044C \u043E\u0442 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F \u0441\u0435\u0442\u0438.',
      s4t: '4. \u041E\u0433\u0440\u0430\u043D\u0438\u0447\u0435\u043D\u0438\u0435 \u043E\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0435\u043D\u043D\u043E\u0441\u0442\u0438', s4b: '\u041D\u0438 \u043F\u0440\u0438 \u043A\u0430\u043A\u0438\u0445 \u043E\u0431\u0441\u0442\u043E\u044F\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0430\u0445 \u0430\u0432\u0442\u043E\u0440\u044B \u0438\u043B\u0438 \u0443\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043D\u0435 \u043D\u0435\u0441\u0443\u0442 \u043E\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0435\u043D\u043D\u043E\u0441\u0442\u0438 \u0437\u0430 \u043B\u044E\u0431\u044B\u0435 \u043F\u0440\u044F\u043C\u044B\u0435, \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u044B\u0435, \u0441\u043B\u0443\u0447\u0430\u0439\u043D\u044B\u0435, \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u044B\u0435 \u0438\u043B\u0438 \u043F\u043E\u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0438\u0435 \u0443\u0431\u044B\u0442\u043A\u0438, \u0432\u043E\u0437\u043D\u0438\u043A\u0430\u044E\u0449\u0438\u0435 \u0432 \u0441\u0432\u044F\u0437\u0438 \u0441 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435\u043C \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0430.',
      s5t: '5. \u0414\u043E\u043F\u0443\u0441\u0442\u0438\u043C\u043E\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435', s5i: '\u0412\u044B \u0441\u043E\u0433\u043B\u0430\u0448\u0430\u0435\u0442\u0435\u0441\u044C \u043D\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u044C \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0434\u043B\u044F \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u0433\u043E:', s5l1: '\u0412\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0438\u044F \u043D\u0435\u0441\u0430\u043D\u043A\u0446\u0438\u043E\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0445 \u0438\u043B\u0438 \u0437\u043B\u043E\u0443\u043F\u043E\u0442\u0440\u0435\u0431\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0445 DNS-\u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432.', s5l2: '\u041F\u043E\u043F\u044B\u0442\u043E\u043A \u043D\u0430\u0440\u0443\u0448\u0438\u0442\u044C \u0440\u0430\u0431\u043E\u0442\u0443 \u0438\u043B\u0438 \u043F\u0435\u0440\u0435\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441.', s5l3: '\u041D\u0430\u0440\u0443\u0448\u0435\u043D\u0438\u044F \u043F\u0440\u0438\u043C\u0435\u043D\u0438\u043C\u044B\u0445 \u0437\u0430\u043A\u043E\u043D\u043E\u0432 \u0438\u043B\u0438 \u043D\u043E\u0440\u043C\u0430\u0442\u0438\u0432\u043D\u044B\u0445 \u0442\u0440\u0435\u0431\u043E\u0432\u0430\u043D\u0438\u0439.',
      s6t: '6. \u0414\u0430\u043D\u043D\u044B\u0435 \u0438 \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u044C', s6b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043D\u0435 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442 \u043F\u0435\u0440\u0441\u043E\u043D\u0430\u043B\u044C\u043D\u043E \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u0446\u0438\u0440\u0443\u0435\u043C\u0443\u044E \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u044E. \u041D\u0435\u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u0430\u043D\u043E\u043D\u0438\u043C\u043D\u044B\u0435 \u043C\u0435\u0442\u0440\u0438\u043A\u0438 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F (\u0435\u0441\u043B\u0438 \u0432\u043A\u043B\u044E\u0447\u0435\u043D\u044B) \u0441\u043E\u0434\u0435\u0440\u0436\u0430\u0442 \u0442\u043E\u043B\u044C\u043A\u043E HMAC-\u0445\u044D\u0448\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u0434\u043E\u043C\u0435\u043D\u043D\u044B\u0435 \u0438\u043C\u0435\u043D\u0430 \u0438 \u0430\u0433\u0440\u0435\u0433\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u0441\u0447\u0435\u0442\u0447\u0438\u043A\u0438. \u041F\u043E\u0434\u0440\u043E\u0431\u043D\u043E\u0441\u0442\u0438 \u0441\u043C. \u0432 <a id="privacyLink" href="/privacy">\u0417\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0438 \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438</a>.',
      s7t: '7. \u0421\u0442\u043E\u0440\u043E\u043D\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044B', s7b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043C\u043E\u0436\u0435\u0442 \u0432\u0437\u0430\u0438\u043C\u043E\u0434\u0435\u0439\u0441\u0442\u0432\u043E\u0432\u0430\u0442\u044C \u0441\u043E \u0441\u0442\u043E\u0440\u043E\u043D\u043D\u0438\u043C\u0438 DNS-\u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440\u0430\u043C\u0438, \u043F\u043E\u0441\u0442\u0430\u0432\u0449\u0438\u043A\u0430\u043C\u0438 WHOIS \u0438 API Azure. \u0418\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435 \u044D\u0442\u0438\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432 \u0440\u0435\u0433\u0443\u043B\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u0438\u0445 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u043C\u0438 \u0443\u0441\u043B\u043E\u0432\u0438\u044F\u043C\u0438.',
      s8t: '8. \u0418\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u044D\u0442\u0438\u0445 \u0443\u0441\u043B\u043E\u0432\u0438\u0439', s8b: '\u042D\u0442\u0438 \u0443\u0441\u043B\u043E\u0432\u0438\u044F \u043C\u043E\u0433\u0443\u0442 \u0432\u0440\u0435\u043C\u044F \u043E\u0442 \u0432\u0440\u0435\u043C\u0435\u043D\u0438 \u043E\u0431\u043D\u043E\u0432\u043B\u044F\u0442\u044C\u0441\u044F. \u041F\u0440\u043E\u0434\u043E\u043B\u0436\u0435\u043D\u0438\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0430 \u043F\u043E\u0441\u043B\u0435 \u0438\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u0439 \u043E\u0437\u043D\u0430\u0447\u0430\u0435\u0442 \u043F\u0440\u0438\u043D\u044F\u0442\u0438\u0435 \u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u044B\u0445 \u0443\u0441\u043B\u043E\u0432\u0438\u0439.',
      s9t: '9. \u041A\u043E\u043D\u0442\u0430\u043A\u0442\u044B', s9b: '\u0415\u0441\u043B\u0438 \u0443 \u0432\u0430\u0441 \u0435\u0441\u0442\u044C \u0432\u043E\u043F\u0440\u043E\u0441\u044B \u043F\u043E \u044D\u0442\u0438\u043C \u0443\u0441\u043B\u043E\u0432\u0438\u044F\u043C, \u043F\u043E\u0441\u0435\u0442\u0438\u0442\u0435 <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    }
  };

  function normalizeLanguageCode(lang) {
    const value = String(lang || '').trim().toLowerCase();
    if (!value) return 'en';
    if (value === 'ptbr' || value.startsWith('pt-br') || value.startsWith('pt_br') || value.startsWith('pt')) return 'pt-BR';
    if (value.startsWith('es')) return 'es';
    if (value.startsWith('fr')) return 'fr';
    if (value.startsWith('de')) return 'de';
    if (value.startsWith('ar')) return 'ar';
    if (value === 'zh' || value.startsWith('zh-cn') || value.startsWith('zh_cn') || value.startsWith('zh-hans')) return 'zh-CN';
    if (value === 'hi' || value.startsWith('hi-in') || value.startsWith('hi_in')) return 'hi-IN';
    if (value === 'ja' || value.startsWith('ja-jp') || value.startsWith('ja_jp')) return 'ja-JP';
    if (value === 'ru' || value.startsWith('ru-ru') || value.startsWith('ru_ru')) return 'ru-RU';
    return 'en';
  }

  const params = new URLSearchParams(window.location.search);
  const lang = normalizeLanguageCode(params.get('lang') || navigator.language || 'en');
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.title = t.pageTitle;

  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  const setHtml = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = value;
  };

  setText('backLink', t.back);
  document.getElementById('backLink').href = '/?lang=' + encodeURIComponent(lang);
  setText('tosTitle', t.title);
  setText('updatedLabel', t.updatedLabel);
  setText('updatedValue', t.updatedValue);
  setText('tosSection1Title', t.s1t); setText('tosSection1Body', t.s1b);
  setText('tosSection2Title', t.s2t); setText('tosSection2Body', t.s2b);
  setText('tosSection3Title', t.s3t); setHtml('tosSection3Body', t.s3b);
  setText('tosSection4Title', t.s4t); setText('tosSection4Body', t.s4b);
  setText('tosSection5Title', t.s5t); setText('tosSection5Intro', t.s5i);
  setText('tosSection5Item1', t.s5l1); setText('tosSection5Item2', t.s5l2); setText('tosSection5Item3', t.s5l3);
  setText('tosSection6Title', t.s6t); setHtml('tosSection6Body', t.s6b);
  setText('tosSection7Title', t.s7t); setText('tosSection7Body', t.s7b);
  setText('tosSection8Title', t.s8t); setText('tosSection8Body', t.s8b);
  setText('tosSection9Title', t.s9t); setHtml('tosSection9Body', t.s9b);

  const privacyLink = document.getElementById('privacyLink');
  if (privacyLink) privacyLink.href = '/privacy?lang=' + encodeURIComponent(lang);
})();
</script>
</body>
</html>
'@

# ------------------- Embedded Privacy Statement page -------------------
$script:PrivacyPageHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Privacy Statement - ACS Email Domain Checker</title>
<style nonce="__CSP_NONCE__">
  :root { --bg: #f4f6fb; --fg: #111827; --card-bg: #ffffff; --border: #e0e3ee; --link: #2f80ed; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #1e1e1e; --fg: #d4d4d4; --card-bg: #2d2d2d; --border: #444; --link: #5ba8f5; }
  }
  body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--fg); max-width: 800px; margin: 40px auto; padding: 0 24px; line-height: 1.7; }
  h1 { border-bottom: 2px solid var(--border); padding-bottom: 12px; }
  h2 { margin-top: 1.6em; }
  a { color: var(--link); }
  .back { display: inline-block; margin-bottom: 16px; text-decoration: none; }
</style>
</head>
<body>
<a id="privacyBackLink" class="back" href="/">&larr; Back to ACS Email Domain Checker</a>
<h1 id="privacyTitle">Privacy Statement</h1>
<p><strong id="privacyUpdatedLabel">Last updated:</strong> <span id="privacyUpdatedValue">March 2026</span></p>

<h2 id="privacySection1Title">1. Overview</h2>
<p id="privacySection1Body">The ACS Email Domain Checker (&ldquo;the Tool&rdquo;) is designed with privacy in mind. This statement explains what data the Tool does and does not collect.</p>

<h2 id="privacySection2Title">2. Data We Do Not Collect</h2>
<ul>
  <li id="privacySection2Item1"><strong>No personal information</strong> &mdash; the Tool does not collect names, email addresses, IP addresses, or hardware identifiers.</li>
  <li id="privacySection2Item2"><strong>No tracking cookies</strong> &mdash; the Tool does not use advertising or analytics tracking cookies.</li>
  <li id="privacySection2Item3"><strong>No query logging</strong> &mdash; domain names you look up are not stored on the server.</li>
</ul>

<h2 id="privacySection3Title">3. Anonymous Usage Metrics (Optional)</h2>
<p id="privacySection3Intro">When anonymous metrics are enabled, the Tool collects:</p>
<ul>
  <li id="privacySection3Item1">HMAC-hashed domain names (irreversible; the original domain cannot be recovered).</li>
  <li id="privacySection3Item2">Aggregate lookup counters and first-seen timestamps.</li>
  <li id="privacySection3Item3">A random session identifier (not persisted across restarts).</li>
</ul>
<p id="privacySection3Body">Anonymous metrics can be disabled entirely with the <code>-DisableAnonymousMetrics</code> flag.</p>

<h2 id="privacySection4Title">4. Microsoft Entra ID Authentication</h2>
<p id="privacySection4Body">If you choose to sign in with Microsoft, the Tool uses MSAL.js with the Authorization Code + PKCE flow. Tokens are stored in your browser&rsquo;s session storage and are never sent to the Tool&rsquo;s server. The Tool reads only your display name and email address from Microsoft Graph to show your identity in the UI.</p>

<h2 id="privacySection5Title">5. Azure Resource Queries</h2>
<p id="privacySection5Body">When using Azure Workspace Diagnostics, all API calls go directly from your browser to Azure Resource Manager and Log Analytics using your own access token. The Tool&rsquo;s server does not proxy, log, or store any Azure data.</p>

<h2 id="privacySection6Title">6. DNS Lookups</h2>
<p id="privacySection6Body">DNS queries are performed server-side using the configured resolver (system DNS or DNS-over-HTTPS). Query results are returned to your browser and are not stored.</p>

<h2 id="privacySection7Title">7. Local Storage</h2>
<p id="privacySection7Body">The Tool uses your browser&rsquo;s <code>localStorage</code> to persist your theme preference and recent domain history. This data never leaves your browser.</p>

<h2 id="privacySection8Title">8. Third-Party Services</h2>
<p id="privacySection8Body">The Tool may use third-party services for DNS resolution (e.g., DNS-over-HTTPS providers), WHOIS lookups, and DNSBL reputation checks. These services have their own privacy policies.</p>

<h2 id="privacySection9Title">9. Changes to This Statement</h2>
<p id="privacySection9Body">This privacy statement may be updated from time to time. Changes take effect when published in the Tool.</p>

<h2 id="privacySection10Title">10. Contact</h2>
<p id="privacySection10Body">For privacy-related questions, visit <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.</p>
<script nonce="__CSP_NONCE__">
(() => {
  const TRANSLATIONS = {
    en: {
      pageTitle: 'Privacy Statement - ACS Email Domain Checker', back: '\u2190 Back to ACS Email Domain Checker', title: 'Privacy Statement', updatedLabel: 'Last updated:', updatedValue: 'March 2026',
      s1t: '1. Overview', s1b: 'The ACS Email Domain Checker (\u201Cthe Tool\u201D) is designed with privacy in mind. This statement explains what data the Tool does and does not collect.',
      s2t: '2. Data We Do Not Collect', s2l1: '<strong>No personal information</strong> \u2014 the Tool does not collect names, email addresses, IP addresses, or hardware identifiers.', s2l2: '<strong>No tracking cookies</strong> \u2014 the Tool does not use advertising or analytics tracking cookies.', s2l3: '<strong>No query logging</strong> \u2014 domain names you look up are not stored on the server.',
      s3t: '3. Anonymous Usage Metrics (Optional)', s3i: 'When anonymous metrics are enabled, the Tool collects:', s3l1: 'HMAC-hashed domain names (irreversible; the original domain cannot be recovered).', s3l2: 'Aggregate lookup counters and first-seen timestamps.', s3l3: 'A random session identifier (not persisted across restarts).', s3b: 'Anonymous metrics can be disabled entirely with the <code>-DisableAnonymousMetrics</code> flag.',
      s4t: '4. Microsoft Entra ID Authentication', s4b: 'If you choose to sign in with Microsoft, the Tool uses MSAL.js with the Authorization Code + PKCE flow. Tokens are stored in your browser\u2019s session storage and are never sent to the Tool\u2019s server. The Tool reads only your display name and email address from Microsoft Graph to show your identity in the UI.',
      s5t: '5. Azure Resource Queries', s5b: 'When using Azure Workspace Diagnostics, all API calls go directly from your browser to Azure Resource Manager and Log Analytics using your own access token. The Tool\u2019s server does not proxy, log, or store any Azure data.',
      s6t: '6. DNS Lookups', s6b: 'DNS queries are performed server-side using the configured resolver (system DNS or DNS-over-HTTPS). Query results are returned to your browser and are not stored.',
      s7t: '7. Local Storage', s7b: 'The Tool uses your browser\u2019s <code>localStorage</code> to persist your theme preference and recent domain history. This data never leaves your browser.',
      s8t: '8. Third-Party Services', s8b: 'The Tool may use third-party services for DNS resolution (e.g., DNS-over-HTTPS providers), WHOIS lookups, and DNSBL reputation checks. These services have their own privacy policies.',
      s9t: '9. Changes to This Statement', s9b: 'This privacy statement may be updated from time to time. Changes take effect when published in the Tool.',
      s10t: '10. Contact', s10b: 'For privacy-related questions, visit <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.'
    },
    es: { pageTitle: 'Declaraci\u00F3n de privacidad - ACS Email Domain Checker', back: '\u2190 Volver a ACS Email Domain Checker', title: 'Declaraci\u00F3n de privacidad', updatedLabel: '\u00DAltima actualizaci\u00F3n:', updatedValue: 'Marzo de 2026', s1t: '1. Informaci\u00F3n general', s1b: 'ACS Email Domain Checker (\u201Cla Herramienta\u201D) est\u00E1 dise\u00F1ado teniendo en cuenta la privacidad. Esta declaraci\u00F3n explica qu\u00E9 datos recopila y no recopila la Herramienta.', s2t: '2. Datos que no recopilamos', s2l1: '<strong>Sin informaci\u00F3n personal</strong> \u2014 la Herramienta no recopila nombres, direcciones de correo electr\u00F3nico, direcciones IP ni identificadores de hardware.', s2l2: '<strong>Sin cookies de seguimiento</strong> \u2014 la Herramienta no usa cookies de seguimiento publicitario ni anal\u00EDtico.', s2l3: '<strong>Sin registro de consultas</strong> \u2014 los nombres de dominio que consulta no se almacenan en el servidor.', s3t: '3. M\u00E9tricas de uso an\u00F3nimo (opcional)', s3i: 'Cuando las m\u00E9tricas an\u00F3nimas est\u00E1n habilitadas, la Herramienta recopila:', s3l1: 'Nombres de dominio con hash HMAC (irreversibles; no se puede recuperar el dominio original).', s3l2: 'Contadores agregados de b\u00FAsqueda y marcas de tiempo de primer uso.', s3l3: 'Un identificador de sesi\u00F3n aleatorio (no se conserva tras reinicios).', s3b: 'Las m\u00E9tricas an\u00F3nimas pueden deshabilitarse por completo con la marca <code>-DisableAnonymousMetrics</code>.', s4t: '4. Autenticaci\u00F3n de Microsoft Entra ID', s4b: 'Si elige iniciar sesi\u00F3n con Microsoft, la Herramienta usa MSAL.js con el flujo Authorization Code + PKCE. Los tokens se almacenan en el almacenamiento de sesi\u00F3n del navegador y nunca se env\u00EDan al servidor de la Herramienta. La Herramienta solo lee su nombre para mostrar y su direcci\u00F3n de correo desde Microsoft Graph para mostrar su identidad en la interfaz.', s5t: '5. Consultas de recursos de Azure', s5b: 'Al usar Azure Workspace Diagnostics, todas las llamadas API van directamente desde el navegador a Azure Resource Manager y Log Analytics con su propio token de acceso. El servidor de la Herramienta no act\u00FAa como proxy, ni registra ni almacena datos de Azure.', s6t: '6. B\u00FAsquedas DNS', s6b: 'Las consultas DNS se realizan en el servidor usando el resolvedor configurado (DNS del sistema o DNS sobre HTTPS). Los resultados se devuelven al navegador y no se almacenan.', s7t: '7. Almacenamiento local', s7b: 'La Herramienta usa <code>localStorage</code> del navegador para conservar la preferencia de tema y el historial reciente de dominios. Estos datos nunca salen del navegador.', s8t: '8. Servicios de terceros', s8b: 'La Herramienta puede usar servicios de terceros para la resoluci\u00F3n DNS (por ejemplo, proveedores de DNS sobre HTTPS), b\u00FAsquedas WHOIS y comprobaciones de reputaci\u00F3n DNSBL. Estos servicios tienen sus propias pol\u00EDticas de privacidad.', s9t: '9. Cambios en esta declaraci\u00F3n', s9b: 'Esta declaraci\u00F3n de privacidad puede actualizarse peri\u00F3dicamente. Los cambios entran en vigor cuando se publican en la Herramienta.', s10t: '10. Contacto', s10b: 'Para preguntas relacionadas con la privacidad, visite <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' },
    fr: { pageTitle: 'D\u00E9claration de confidentialit\u00E9 - ACS Email Domain Checker', back: '\u2190 Retour \u00E0 ACS Email Domain Checker', title: 'D\u00E9claration de confidentialit\u00E9', updatedLabel: 'Derni\u00E8re mise \u00E0 jour :', updatedValue: 'Mars 2026', s1t: '1. Pr\u00E9sentation', s1b: 'ACS Email Domain Checker (\u00AB l\u2019Outil \u00BB) est con\u00E7u dans le respect de la confidentialit\u00E9. Cette d\u00E9claration explique quelles donn\u00E9es l\u2019Outil collecte et ne collecte pas.', s2t: '2. Donn\u00E9es que nous ne collectons pas', s2l1: '<strong>Aucune information personnelle</strong> \u2014 l\u2019Outil ne collecte ni noms, ni adresses e-mail, ni adresses IP, ni identifiants mat\u00E9riels.', s2l2: '<strong>Aucun cookie de suivi</strong> \u2014 l\u2019Outil n\u2019utilise pas de cookies publicitaires ou analytiques de suivi.', s2l3: '<strong>Aucune journalisation des requ\u00EAtes</strong> \u2014 les noms de domaine que vous recherchez ne sont pas stock\u00E9s sur le serveur.', s3t: '3. M\u00E9triques d\u2019utilisation anonymes (facultatif)', s3i: 'Lorsque les m\u00E9triques anonymes sont activ\u00E9es, l\u2019Outil collecte :', s3l1: 'Des noms de domaine hach\u00E9s par HMAC (irr\u00E9versibles ; le domaine d\u2019origine ne peut pas \u00EAtre r\u00E9cup\u00E9r\u00E9).', s3l2: 'Des compteurs agr\u00E9g\u00E9s de recherche et des horodatages de premi\u00E8re apparition.', s3l3: 'Un identifiant de session al\u00E9atoire (non conserv\u00E9 apr\u00E8s red\u00E9marrage).', s3b: 'Les m\u00E9triques anonymes peuvent \u00EAtre enti\u00E8rement d\u00E9sactiv\u00E9es avec l\u2019option <code>-DisableAnonymousMetrics</code>.', s4t: '4. Authentification Microsoft Entra ID', s4b: 'Si vous choisissez de vous connecter avec Microsoft, l\u2019Outil utilise MSAL.js avec le flux Authorization Code + PKCE. Les jetons sont stock\u00E9s dans le stockage de session du navigateur et ne sont jamais envoy\u00E9s au serveur de l\u2019Outil. L\u2019Outil lit uniquement votre nom d\u2019affichage et votre adresse e-mail via Microsoft Graph pour afficher votre identit\u00E9 dans l\u2019interface.', s5t: '5. Requ\u00EAtes sur les ressources Azure', s5b: 'Lors de l\u2019utilisation d\u2019Azure Workspace Diagnostics, tous les appels API vont directement de votre navigateur vers Azure Resource Manager et Log Analytics \u00E0 l\u2019aide de votre propre jeton d\u2019acc\u00E8s. Le serveur de l\u2019Outil ne sert pas de proxy et n\u2019enregistre ni ne stocke aucune donn\u00E9e Azure.', s6t: '6. Recherches DNS', s6b: 'Les requ\u00EAtes DNS sont effectu\u00E9es c\u00F4t\u00E9 serveur \u00E0 l\u2019aide du r\u00E9solveur configur\u00E9 (DNS syst\u00E8me ou DNS-over-HTTPS). Les r\u00E9sultats sont renvoy\u00E9s \u00E0 votre navigateur et ne sont pas stock\u00E9s.', s7t: '7. Stockage local', s7b: 'L\u2019Outil utilise le <code>localStorage</code> de votre navigateur pour conserver votre pr\u00E9f\u00E9rence de th\u00E8me et l\u2019historique r\u00E9cent des domaines. Ces donn\u00E9es ne quittent jamais votre navigateur.', s8t: '8. Services tiers', s8b: 'L\u2019Outil peut utiliser des services tiers pour la r\u00E9solution DNS (par exemple des fournisseurs DNS-over-HTTPS), les recherches WHOIS et les v\u00E9rifications de r\u00E9putation DNSBL. Ces services ont leurs propres politiques de confidentialit\u00E9.', s9t: '9. Modifications de cette d\u00E9claration', s9b: 'Cette d\u00E9claration de confidentialit\u00E9 peut \u00EAtre mise \u00E0 jour de temps \u00E0 autre. Les modifications prennent effet d\u00E8s leur publication dans l\u2019Outil.', s10t: '10. Contact', s10b: 'Pour toute question relative \u00E0 la confidentialit\u00E9, consultez <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' },
    de: { pageTitle: 'Datenschutzerkl\u00E4rung - ACS Email Domain Checker', back: '\u2190 Zur\u00FCck zu ACS Email Domain Checker', title: 'Datenschutzerkl\u00E4rung', updatedLabel: 'Zuletzt aktualisiert:', updatedValue: 'M\u00E4rz 2026', s1t: '1. \u00DCberblick', s1b: 'ACS Email Domain Checker (\u201Edas Tool\u201C) wurde unter Ber\u00FCcksichtigung des Datenschutzes entwickelt. Diese Erkl\u00E4rung erl\u00E4utert, welche Daten das Tool erfasst und nicht erfasst.', s2t: '2. Daten, die wir nicht erfassen', s2l1: '<strong>Keine personenbezogenen Informationen</strong> \u2014 das Tool erfasst keine Namen, E-Mail-Adressen, IP-Adressen oder Hardwarekennungen.', s2l2: '<strong>Keine Tracking-Cookies</strong> \u2014 das Tool verwendet keine Werbe- oder Analyse-Tracking-Cookies.', s2l3: '<strong>Keine Protokollierung von Abfragen</strong> \u2014 die von Ihnen abgefragten Dom\u00E4nennamen werden nicht auf dem Server gespeichert.', s3t: '3. Anonyme Nutzungsmetriken (optional)', s3i: 'Wenn anonyme Metriken aktiviert sind, erfasst das Tool:', s3l1: 'HMAC-gehashte Dom\u00E4nennamen (irreversibel; die urspr\u00FCngliche Dom\u00E4ne kann nicht wiederhergestellt werden).', s3l2: 'Aggregierte Lookup-Z\u00E4hler und Zeitstempel des ersten Auftretens.', s3l3: 'Eine zuf\u00E4llige Sitzungskennung (wird nicht \u00FCber Neustarts hinweg gespeichert).', s3b: 'Anonyme Metriken k\u00F6nnen mit dem Schalter <code>-DisableAnonymousMetrics</code> vollst\u00E4ndig deaktiviert werden.', s4t: '4. Microsoft Entra ID-Authentifizierung', s4b: 'Wenn Sie sich mit Microsoft anmelden, verwendet das Tool MSAL.js mit dem Authorization Code + PKCE-Flow. Token werden im Sitzungsspeicher Ihres Browsers gespeichert und niemals an den Server des Tools gesendet. Das Tool liest nur Ihren Anzeigenamen und Ihre E-Mail-Adresse aus Microsoft Graph, um Ihre Identit\u00E4t in der Benutzeroberfl\u00E4che anzuzeigen.', s5t: '5. Azure-Ressourcenabfragen', s5b: 'Bei Verwendung von Azure Workspace Diagnostics gehen alle API-Aufrufe direkt von Ihrem Browser an Azure Resource Manager und Log Analytics unter Verwendung Ihres eigenen Zugriffstokens. Der Server des Tools fungiert nicht als Proxy und protokolliert oder speichert keine Azure-Daten.', s6t: '6. DNS-Abfragen', s6b: 'DNS-Abfragen werden serverseitig mit dem konfigurierten Resolver durchgef\u00FChrt (System-DNS oder DNS-over-HTTPS). Die Ergebnisse werden an Ihren Browser zur\u00FCckgegeben und nicht gespeichert.', s7t: '7. Lokaler Speicher', s7b: 'Das Tool verwendet den <code>localStorage</code> Ihres Browsers, um Ihre Designpr\u00E4ferenz und den zuletzt verwendeten Dom\u00E4nenverlauf zu speichern. Diese Daten verlassen Ihren Browser nie.', s8t: '8. Dienste von Drittanbietern', s8b: 'Das Tool kann Drittanbieterdienste f\u00FCr DNS-Aufl\u00F6sung (z. B. DNS-over-HTTPS-Anbieter), WHOIS-Abfragen und DNSBL-Reputationspr\u00FCfungen verwenden. Diese Dienste haben eigene Datenschutzrichtlinien.', s9t: '9. \u00C4nderungen dieser Erkl\u00E4rung', s9b: 'Diese Datenschutzerkl\u00E4rung kann von Zeit zu Zeit aktualisiert werden. \u00C4nderungen treten mit ihrer Ver\u00F6ffentlichung im Tool in Kraft.', s10t: '10. Kontakt', s10b: 'Bei datenschutzbezogenen Fragen besuchen Sie <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' },
    'pt-BR': { pageTitle: 'Declara\u00E7\u00E3o de Privacidade - ACS Email Domain Checker', back: '\u2190 Voltar para ACS Email Domain Checker', title: 'Declara\u00E7\u00E3o de Privacidade', updatedLabel: '\u00DAltima atualiza\u00E7\u00E3o:', updatedValue: 'Mar\u00E7o de 2026', s1t: '1. Vis\u00E3o geral', s1b: 'O ACS Email Domain Checker (\u201Ca Ferramenta\u201D) foi desenvolvido com foco em privacidade. Esta declara\u00E7\u00E3o explica quais dados a Ferramenta coleta e quais n\u00E3o coleta.', s2t: '2. Dados que n\u00E3o coletamos', s2l1: '<strong>Nenhuma informa\u00E7\u00E3o pessoal</strong> \u2014 a Ferramenta n\u00E3o coleta nomes, endere\u00E7os de e-mail, endere\u00E7os IP ou identificadores de hardware.', s2l2: '<strong>Nenhum cookie de rastreamento</strong> \u2014 a Ferramenta n\u00E3o usa cookies de rastreamento de publicidade ou an\u00E1lise.', s2l3: '<strong>Nenhum registro de consulta</strong> \u2014 os nomes de dom\u00EDnio que voc\u00EA pesquisa n\u00E3o s\u00E3o armazenados no servidor.', s3t: '3. M\u00E9tricas de uso an\u00F4nimas (opcional)', s3i: 'Quando as m\u00E9tricas an\u00F4nimas est\u00E3o habilitadas, a Ferramenta coleta:', s3l1: 'Nomes de dom\u00EDnio com hash HMAC (irrevers\u00EDveis; o dom\u00EDnio original n\u00E3o pode ser recuperado).', s3l2: 'Contadores agregados de consultas e carimbos de data/hora do primeiro uso.', s3l3: 'Um identificador de sess\u00E3o aleat\u00F3rio (n\u00E3o persistido entre reinicializa\u00E7\u00F5es).', s3b: 'As m\u00E9tricas an\u00F4nimas podem ser totalmente desabilitadas com a op\u00E7\u00E3o <code>-DisableAnonymousMetrics</code>.', s4t: '4. Autentica\u00E7\u00E3o do Microsoft Entra ID', s4b: 'Se voc\u00EA optar por entrar com a Microsoft, a Ferramenta usar\u00E1 o MSAL.js com o fluxo Authorization Code + PKCE. Os tokens s\u00E3o armazenados no armazenamento de sess\u00E3o do navegador e nunca s\u00E3o enviados ao servidor da Ferramenta. A Ferramenta l\u00EA apenas seu nome de exibi\u00E7\u00E3o e endere\u00E7o de e-mail do Microsoft Graph para mostrar sua identidade na interface.', s5t: '5. Consultas de recursos do Azure', s5b: 'Ao usar o Azure Workspace Diagnostics, todas as chamadas de API v\u00E3o diretamente do navegador para o Azure Resource Manager e o Log Analytics usando seu pr\u00F3prio token de acesso. O servidor da Ferramenta n\u00E3o atua como proxy, n\u00E3o registra e n\u00E3o armazena dados do Azure.', s6t: '6. Consultas DNS', s6b: 'As consultas DNS s\u00E3o realizadas no servidor usando o resolvedor configurado (DNS do sistema ou DNS sobre HTTPS). Os resultados s\u00E3o retornados ao seu navegador e n\u00E3o s\u00E3o armazenados.', s7t: '7. Armazenamento local', s7b: 'A Ferramenta usa o <code>localStorage</code> do navegador para persistir sua prefer\u00EAncia de tema e o hist\u00F3rico recente de dom\u00EDnios. Esses dados nunca saem do seu navegador.', s8t: '8. Servi\u00E7os de terceiros', s8b: 'A Ferramenta pode usar servi\u00E7os de terceiros para resolu\u00E7\u00E3o DNS (por exemplo, provedores de DNS sobre HTTPS), consultas WHOIS e verifica\u00E7\u00F5es de reputa\u00E7\u00E3o DNSBL. Esses servi\u00E7os t\u00EAm suas pr\u00F3prias pol\u00EDticas de privacidade.', s9t: '9. Altera\u00E7\u00F5es nesta declara\u00E7\u00E3o', s9b: 'Esta declara\u00E7\u00E3o de privacidade pode ser atualizada periodicamente. As altera\u00E7\u00F5es entram em vigor quando s\u00E3o publicadas na Ferramenta.', s10t: '10. Contato', s10b: 'Para quest\u00F5es relacionadas \u00E0 privacidade, visite <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' },
    ar: { pageTitle: '\u0628\u064A\u0627\u0646 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629 - ACS Email Domain Checker', back: '\u2190 \u0627\u0644\u0639\u0648\u062F\u0629 \u0625\u0644\u0649 ACS Email Domain Checker', title: '\u0628\u064A\u0627\u0646 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629', updatedLabel: '\u0622\u062E\u0631 \u062A\u062D\u062F\u064A\u062B:', updatedValue: '\u0645\u0627\u0631\u0633 2026', s1t: '1. \u0646\u0638\u0631\u0629 \u0639\u0627\u0645\u0629', s1b: '\u062A\u0645 \u062A\u0635\u0645\u064A\u0645 ACS Email Domain Checker (\u00AB\u0627\u0644\u0623\u062F\u0627\u0629\u00BB) \u0645\u0639 \u0645\u0631\u0627\u0639\u0627\u0629 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629. \u064A\u0648\u0636\u062D \u0647\u0630\u0627 \u0627\u0644\u0628\u064A\u0627\u0646 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u062A\u064A \u062A\u062C\u0645\u0639\u0647\u0627 \u0627\u0644\u0623\u062F\u0627\u0629 \u0648\u0627\u0644\u062A\u064A \u0644\u0627 \u062A\u062C\u0645\u0639\u0647\u0627.', s2t: '2. \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u062A\u064A \u0644\u0627 \u0646\u062C\u0645\u0639\u0647\u0627', s2l1: '<strong>\u0644\u0627 \u062A\u0648\u062C\u062F \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u0634\u062E\u0635\u064A\u0629</strong> \u2014 \u0644\u0627 \u062A\u062C\u0645\u0639 \u0627\u0644\u0623\u062F\u0627\u0629 \u0627\u0644\u0623\u0633\u0645\u0627\u0621 \u0623\u0648 \u0639\u0646\u0627\u0648\u064A\u0646 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0623\u0648 \u0639\u0646\u0627\u0648\u064A\u0646 IP \u0623\u0648 \u0645\u0639\u0631\u0641\u0627\u062A \u0627\u0644\u0623\u062C\u0647\u0632\u0629.', s2l2: '<strong>\u0644\u0627 \u062A\u0648\u062C\u062F \u0645\u0644\u0641\u0627\u062A \u062A\u0639\u0631\u064A\u0641 \u0627\u0631\u062A\u0628\u0627\u0637 \u0644\u0644\u062A\u062A\u0628\u0639</strong> \u2014 \u0644\u0627 \u062A\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 \u0645\u0644\u0641\u0627\u062A \u062A\u0639\u0631\u064A\u0641 \u0627\u0631\u062A\u0628\u0627\u0637 \u062A\u062A\u0639\u0644\u0642 \u0628\u0627\u0644\u0625\u0639\u0644\u0627\u0646\u0627\u062A \u0623\u0648 \u0627\u0644\u062A\u062D\u0644\u064A\u0644\u0627\u062A.', s2l3: '<strong>\u0644\u0627 \u064A\u0648\u062C\u062F \u062A\u0633\u062C\u064A\u0644 \u0644\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A</strong> \u2014 \u0644\u0627 \u064A\u062A\u0645 \u062A\u062E\u0632\u064A\u0646 \u0623\u0633\u0645\u0627\u0621 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u062A\u064A \u062A\u0628\u062D\u062B \u0639\u0646\u0647\u0627 \u0639\u0644\u0649 \u0627\u0644\u062E\u0627\u062F\u0645.', s3t: '3. \u0645\u0642\u0627\u064A\u064A\u0633 \u0627\u0644\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0645\u062C\u0647\u0648\u0644\u0629 (\u0627\u062E\u062A\u064A\u0627\u0631\u064A)', s3i: '\u0639\u0646\u062F \u062A\u0645\u0643\u064A\u0646 \u0627\u0644\u0645\u0642\u0627\u064A\u064A\u0633 \u0627\u0644\u0645\u062C\u0647\u0648\u0644\u0629\u060C \u062A\u062C\u0645\u0639 \u0627\u0644\u0623\u062F\u0627\u0629:', s3l1: '\u0623\u0633\u0645\u0627\u0621 \u0646\u0637\u0627\u0642\u0627\u062A \u0645\u062C\u0632\u0623\u0629 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 HMAC (\u063A\u064A\u0631 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u0639\u0643\u0633\u061B \u0644\u0627 \u064A\u0645\u0643\u0646 \u0627\u0633\u062A\u0639\u0627\u062F\u0629 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0623\u0635\u0644\u064A).', s3l2: '\u0639\u062F\u0627\u062F\u0627\u062A \u0628\u062D\u062B \u0645\u062C\u0645\u0639\u0629 \u0648\u0637\u0648\u0627\u0628\u0639 \u0632\u0645\u0646\u064A\u0629 \u0644\u0623\u0648\u0644 \u0638\u0647\u0648\u0631.', s3l3: '\u0645\u0639\u0631\u0641 \u062C\u0644\u0633\u0629 \u0639\u0634\u0648\u0627\u0626\u064A (\u0644\u0627 \u064A\u062A\u0645 \u0627\u0644\u0627\u062D\u062A\u0641\u0627\u0638 \u0628\u0647 \u0639\u0628\u0631 \u0639\u0645\u0644\u064A\u0627\u062A \u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0634\u063A\u064A\u0644).', s3b: '\u064A\u0645\u0643\u0646 \u062A\u0639\u0637\u064A\u0644 \u0627\u0644\u0645\u0642\u0627\u064A\u064A\u0633 \u0627\u0644\u0645\u062C\u0647\u0648\u0644\u0629 \u0628\u0627\u0644\u0643\u0627\u0645\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0648\u0633\u064A\u0637 <code>-DisableAnonymousMetrics</code>.', s4t: '4. \u0645\u0635\u0627\u062F\u0642\u0629 Microsoft Entra ID', s4b: '\u0625\u0630\u0627 \u0627\u062E\u062A\u0631\u062A \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 Microsoft\u060C \u062A\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 MSAL.js \u0645\u0639 \u062A\u062F\u0641\u0642 Authorization Code + PKCE. \u064A\u062A\u0645 \u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u0631\u0645\u0648\u0632 \u0641\u064A \u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u062C\u0644\u0633\u0629 \u0628\u0627\u0644\u0645\u062A\u0635\u0641\u062D \u0648\u0644\u0627 \u064A\u062A\u0645 \u0625\u0631\u0633\u0627\u0644\u0647\u0627 \u0645\u0637\u0644\u0642\u064B\u0627 \u0625\u0644\u0649 \u062E\u0627\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629. \u062A\u0642\u0631\u0623 \u0627\u0644\u0623\u062F\u0627\u0629 \u0641\u0642\u0637 \u0627\u0633\u0645 \u0627\u0644\u0639\u0631\u0636 \u0648\u0639\u0646\u0648\u0627\u0646 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0645\u0646 Microsoft Graph \u0644\u0625\u0638\u0647\u0627\u0631 \u0647\u0648\u064A\u062A\u0643 \u0641\u064A \u0627\u0644\u0648\u0627\u062C\u0647\u0629.', s5t: '5. \u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A \u0645\u0648\u0627\u0631\u062F Azure', s5b: '\u0639\u0646\u062F \u0627\u0633\u062A\u062E\u062F\u0627\u0645 Azure Workspace Diagnostics\u060C \u062A\u0646\u062A\u0642\u0644 \u062C\u0645\u064A\u0639 \u0627\u0633\u062A\u062F\u0639\u0627\u0621\u0627\u062A API \u0645\u0628\u0627\u0634\u0631\u0629\u064B \u0645\u0646 \u0645\u062A\u0635\u0641\u062D\u0643 \u0625\u0644\u0649 Azure Resource Manager \u0648Log Analytics \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0631\u0645\u0632 \u0627\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u062E\u0627\u0635 \u0628\u0643. \u0644\u0627 \u064A\u0639\u0645\u0644 \u062E\u0627\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 \u0643\u0648\u0643\u064A\u0644 \u0648\u0644\u0627 \u064A\u0633\u062C\u0644 \u0623\u0648 \u064A\u062E\u0632\u0646 \u0623\u064A \u0628\u064A\u0627\u0646\u0627\u062A Azure.', s6t: '6. \u0639\u0645\u0644\u064A\u0627\u062A \u0628\u062D\u062B DNS', s6b: '\u064A\u062A\u0645 \u062A\u0646\u0641\u064A\u0630 \u0627\u0633\u062A\u0639\u0644\u0627\u0645\u0627\u062A DNS \u0639\u0644\u0649 \u062C\u0627\u0646\u0628 \u0627\u0644\u062E\u0627\u062F\u0645 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0645\u062D\u0644\u0644 \u0627\u0644\u0645\u0643\u0648\u0651\u064E\u0646 (DNS \u0627\u0644\u0646\u0638\u0627\u0645 \u0623\u0648 DNS-over-HTTPS). \u064A\u062A\u0645 \u0625\u0631\u062C\u0627\u0639 \u0627\u0644\u0646\u062A\u0627\u0626\u062C \u0625\u0644\u0649 \u0645\u062A\u0635\u0641\u062D\u0643 \u0648\u0644\u0627 \u064A\u062A\u0645 \u062A\u062E\u0632\u064A\u0646\u0647\u0627.', s7t: '7. \u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u0645\u062D\u0644\u064A', s7b: '\u062A\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 <code>localStorage</code> \u0641\u064A \u0645\u062A\u0635\u0641\u062D\u0643 \u0644\u0644\u0627\u062D\u062A\u0641\u0627\u0638 \u0628\u062A\u0641\u0636\u064A\u0644 \u0627\u0644\u0646\u0633\u0642 \u0648\u0633\u062C\u0644 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u062D\u062F\u064A\u062B. \u0647\u0630\u0647 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0644\u0627 \u062A\u063A\u0627\u062F\u0631 \u0645\u062A\u0635\u0641\u062D\u0643 \u0645\u0637\u0644\u0642\u064B\u0627.', s8t: '8. \u062E\u062F\u0645\u0627\u062A \u0627\u0644\u062C\u0647\u0627\u062A \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629', s8b: '\u0642\u062F \u062A\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0623\u062F\u0627\u0629 \u062E\u062F\u0645\u0627\u062A \u062A\u0627\u0628\u0639\u0629 \u0644\u062C\u0647\u0627\u062A \u062E\u0627\u0631\u062C\u064A\u0629 \u0644\u062D\u0644 DNS (\u0645\u062B\u0644 \u0645\u0648\u0641\u0631\u064A DNS-over-HTTPS) \u0648\u0639\u0645\u0644\u064A\u0627\u062A \u0628\u062D\u062B WHOIS \u0648\u0641\u062D\u0648\u0635\u0627\u062A \u0633\u0645\u0639\u0629 DNSBL. \u0644\u0647\u0630\u0647 \u0627\u0644\u062E\u062F\u0645\u0627\u062A \u0633\u064A\u0627\u0633\u0627\u062A \u062E\u0635\u0648\u0635\u064A\u0629 \u062E\u0627\u0635\u0629 \u0628\u0647\u0627.', s9t: '9. \u0627\u0644\u062A\u063A\u064A\u064A\u0631\u0627\u062A \u0639\u0644\u0649 \u0647\u0630\u0627 \u0627\u0644\u0628\u064A\u0627\u0646', s9b: '\u0642\u062F \u064A\u062A\u0645 \u062A\u062D\u062F\u064A\u062B \u0628\u064A\u0627\u0646 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629 \u0647\u0630\u0627 \u0645\u0646 \u0648\u0642\u062A \u0644\u0622\u062E\u0631. \u062A\u0633\u0631\u064A \u0627\u0644\u062A\u063A\u064A\u064A\u0631\u0627\u062A \u0639\u0646\u062F \u0646\u0634\u0631\u0647\u0627 \u0641\u064A \u0627\u0644\u0623\u062F\u0627\u0629.', s10t: '10. \u0627\u0644\u0627\u062A\u0635\u0627\u0644', s10b: '\u0644\u0644\u0623\u0633\u0626\u0644\u0629 \u0627\u0644\u0645\u062A\u0639\u0644\u0642\u0629 \u0628\u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629\u060C \u062A\u0641\u0636\u0644 \u0628\u0632\u064A\u0627\u0631\u0629 <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' },
    'zh-CN': { pageTitle: '\u9690\u79C1\u58F0\u660E - ACS Email Domain Checker', back: '\u2190 \u8FD4\u56DE ACS Email Domain Checker', title: '\u9690\u79C1\u58F0\u660E', updatedLabel: '\u4E0A\u6B21\u66F4\u65B0\uFF1A', updatedValue: '2026\u5E743\u6708', s1t: '1. \u6982\u8FF0', s1b: 'ACS Email Domain Checker\uFF08\u201C\u672C\u5DE5\u5177\u201D\uFF09\u5728\u8BBE\u8BA1\u65F6\u5DF2\u8003\u8651\u9690\u79C1\u4FDD\u62A4\u3002\u672C\u58F0\u660E\u8BF4\u660E\u672C\u5DE5\u5177\u4F1A\u6536\u96C6\u548C\u4E0D\u4F1A\u6536\u96C6\u54EA\u4E9B\u6570\u636E\u3002', s2t: '2. \u6211\u4EEC\u4E0D\u4F1A\u6536\u96C6\u7684\u6570\u636E', s2l1: '<strong>\u65E0\u4E2A\u4EBA\u4FE1\u606F</strong> \u2014 \u672C\u5DE5\u5177\u4E0D\u4F1A\u6536\u96C6\u59D3\u540D\u3001\u7535\u5B50\u90AE\u4EF6\u5730\u5740\u3001IP \u5730\u5740\u6216\u786C\u4EF6\u6807\u8BC6\u7B26\u3002', s2l2: '<strong>\u65E0\u8DDF\u8E2A Cookie</strong> \u2014 \u672C\u5DE5\u5177\u4E0D\u4F7F\u7528\u5E7F\u544A\u6216\u5206\u6790\u8DDF\u8E2A Cookie\u3002', s2l3: '<strong>\u65E0\u67E5\u8BE2\u65E5\u5FD7</strong> \u2014 \u60A8\u67E5\u8BE2\u7684\u57DF\u540D\u4E0D\u4F1A\u5B58\u50A8\u5728\u670D\u52A1\u5668\u4E0A\u3002', s3t: '3. \u533F\u540D\u4F7F\u7528\u6307\u6807\uFF08\u53EF\u9009\uFF09', s3i: '\u542F\u7528\u533F\u540D\u6307\u6807\u65F6\uFF0C\u672C\u5DE5\u5177\u4F1A\u6536\u96C6\uFF1A', s3l1: '\u7ECF\u8FC7 HMAC \u54C8\u5E0C\u5904\u7406\u7684\u57DF\u540D\uFF08\u4E0D\u53EF\u9006\uFF1B\u65E0\u6CD5\u6062\u590D\u539F\u59CB\u57DF\u540D\uFF09\u3002', s3l2: '\u805A\u5408\u67E5\u8BE2\u8BA1\u6570\u5668\u548C\u9996\u6B21\u51FA\u73B0\u65F6\u95F4\u6233\u3002', s3l3: '\u968F\u673A\u4F1A\u8BDD\u6807\u8BC6\u7B26\uFF08\u4E0D\u4F1A\u5728\u91CD\u542F\u540E\u4FDD\u7559\uFF09\u3002', s3b: '\u53EF\u4F7F\u7528 <code>-DisableAnonymousMetrics</code> \u53C2\u6570\u5B8C\u5168\u7981\u7528\u533F\u540D\u6307\u6807\u3002', s4t: '4. Microsoft Entra ID \u8EAB\u4EFD\u9A8C\u8BC1', s4b: '\u5982\u679C\u60A8\u9009\u62E9\u4F7F\u7528 Microsoft \u767B\u5F55\uFF0C\u672C\u5DE5\u5177\u5C06\u4F7F\u7528\u5E26 Authorization Code + PKCE \u6D41\u7A0B\u7684 MSAL.js\u3002\u4EE4\u724C\u5B58\u50A8\u5728\u6D4F\u89C8\u5668\u4F1A\u8BDD\u5B58\u50A8\u4E2D\uFF0C\u7EDD\u4E0D\u4F1A\u53D1\u9001\u5230\u672C\u5DE5\u5177\u670D\u52A1\u5668\u3002\u672C\u5DE5\u5177\u4EC5\u4ECE Microsoft Graph \u8BFB\u53D6\u60A8\u7684\u663E\u793A\u540D\u79F0\u548C\u7535\u5B50\u90AE\u4EF6\u5730\u5740\uFF0C\u4EE5\u5728 UI \u4E2D\u663E\u793A\u60A8\u7684\u8EAB\u4EFD\u3002', s5t: '5. Azure \u8D44\u6E90\u67E5\u8BE2', s5b: '\u4F7F\u7528 Azure Workspace Diagnostics \u65F6\uFF0C\u6240\u6709 API \u8C03\u7528\u90FD\u4F1A\u4F7F\u7528\u60A8\u81EA\u5DF1\u7684\u8BBF\u95EE\u4EE4\u724C\uFF0C\u76F4\u63A5\u4ECE\u6D4F\u89C8\u5668\u53D1\u9001\u5230 Azure Resource Manager \u548C Log Analytics\u3002\u672C\u5DE5\u5177\u670D\u52A1\u5668\u4E0D\u4F1A\u4EE3\u7406\u3001\u8BB0\u5F55\u6216\u5B58\u50A8\u4EFB\u4F55 Azure \u6570\u636E\u3002', s6t: '6. DNS \u67E5\u8BE2', s6b: 'DNS \u67E5\u8BE2\u5728\u670D\u52A1\u5668\u7AEF\u4F7F\u7528\u914D\u7F6E\u7684\u89E3\u6790\u5668\u6267\u884C\uFF08\u7CFB\u7EDF DNS \u6216 DNS-over-HTTPS\uFF09\u3002\u67E5\u8BE2\u7ED3\u679C\u5C06\u8FD4\u56DE\u5230\u60A8\u7684\u6D4F\u89C8\u5668\u4E14\u4E0D\u4F1A\u88AB\u5B58\u50A8\u3002', s7t: '7. \u672C\u5730\u5B58\u50A8', s7b: '\u672C\u5DE5\u5177\u4F7F\u7528\u6D4F\u89C8\u5668\u7684 <code>localStorage</code> \u4FDD\u5B58\u60A8\u7684\u4E3B\u9898\u504F\u597D\u548C\u6700\u8FD1\u57DF\u5386\u53F2\u8BB0\u5F55\u3002\u8FD9\u4E9B\u6570\u636E\u4E0D\u4F1A\u79BB\u5F00\u60A8\u7684\u6D4F\u89C8\u5668\u3002', s8t: '8. \u7B2C\u4E09\u65B9\u670D\u52A1', s8b: '\u672C\u5DE5\u5177\u53EF\u80FD\u4F7F\u7528\u7B2C\u4E09\u65B9\u670D\u52A1\u8FDB\u884C DNS \u89E3\u6790\uFF08\u4F8B\u5982 DNS-over-HTTPS \u63D0\u4F9B\u5546\uFF09\u3001WHOIS \u67E5\u8BE2\u548C DNSBL \u4FE1\u8A89\u68C0\u67E5\u3002\u8FD9\u4E9B\u670D\u52A1\u6709\u5176\u81EA\u5DF1\u7684\u9690\u79C1\u653F\u7B56\u3002', s9t: '9. \u672C\u58F0\u660E\u7684\u53D8\u66F4', s9b: '\u672C\u9690\u79C1\u58F0\u660E\u53EF\u80FD\u4F1A\u4E0D\u65F6\u66F4\u65B0\u3002\u66F4\u6539\u5728\u672C\u5DE5\u5177\u4E2D\u53D1\u5E03\u65F6\u751F\u6548\u3002', s10t: '10. \u8054\u7CFB\u65B9\u5F0F', s10b: '\u5982\u6709\u9690\u79C1\u76F8\u5173\u95EE\u9898\uFF0C\u8BF7\u8BBF\u95EE <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>\u3002' },
    'hi-IN': { pageTitle: '\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0935\u0915\u094D\u0924\u0935\u094D\u092F - ACS Email Domain Checker', back: '\u2190 ACS Email Domain Checker \u092A\u0930 \u0935\u093E\u092A\u0938 \u091C\u093E\u090F\u0901', title: '\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0935\u0915\u094D\u0924\u0935\u094D\u092F', updatedLabel: '\u0905\u0902\u0924\u093F\u092E \u0905\u092A\u0921\u0947\u091F:', updatedValue: '\u092E\u093E\u0930\u094D\u091A 2026', s1t: '1. \u0905\u0935\u0932\u094B\u0915\u0928', s1b: 'ACS Email Domain Checker (\u201C\u091F\u0942\u0932\u201D) \u0915\u094B \u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0915\u094B \u0927\u094D\u092F\u093E\u0928 \u092E\u0947\u0902 \u0930\u0916\u0915\u0930 \u0921\u093F\u091C\u093C\u093E\u0907\u0928 \u0915\u093F\u092F\u093E \u0917\u092F\u093E \u0939\u0948\u0964 \u092F\u0939 \u0935\u0915\u094D\u0924\u0935\u094D\u092F \u092C\u0924\u093E\u0924\u093E \u0939\u0948 \u0915\u093F \u091F\u0942\u0932 \u0915\u094C\u0928-\u0938\u093E \u0921\u0947\u091F\u093E \u090F\u0915\u0924\u094D\u0930 \u0915\u0930\u0924\u093E \u0939\u0948 \u0914\u0930 \u0915\u094C\u0928-\u0938\u093E \u0928\u0939\u0940\u0902\u0964', s2t: '2. \u0935\u0939 \u0921\u0947\u091F\u093E \u091C\u093F\u0938\u0947 \u0939\u092E \u090F\u0915\u0924\u094D\u0930 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u0947', s2l1: '<strong>\u0915\u094B\u0908 \u0935\u094D\u092F\u0915\u094D\u0924\u093F\u0917\u0924 \u091C\u093E\u0928\u0915\u093E\u0930\u0940 \u0928\u0939\u0940\u0902</strong> \u2014 \u091F\u0942\u0932 \u0928\u093E\u092E, \u0908\u092E\u0947\u0932 \u092A\u0924\u0947, IP \u092A\u0924\u0947 \u092F\u093E \u0939\u093E\u0930\u094D\u0921\u0935\u0947\u092F\u0930 \u092A\u0939\u091A\u093E\u0928\u0915\u0930\u094D\u0924\u093E \u090F\u0915\u0924\u094D\u0930 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964', s2l2: '<strong>\u0915\u094B\u0908 \u091F\u094D\u0930\u0948\u0915\u093F\u0902\u0917 \u0915\u0941\u0915\u0940 \u0928\u0939\u0940\u0902</strong> \u2014 \u091F\u0942\u0932 \u0935\u093F\u091C\u094D\u091E\u093E\u092A\u0928 \u092F\u093E \u0935\u093F\u0936\u094D\u0932\u0947\u0937\u0923 \u091F\u094D\u0930\u0948\u0915\u093F\u0902\u0917 \u0915\u0941\u0915\u0940 \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964', s2l3: '<strong>\u0915\u094B\u0908 \u0915\u094D\u0935\u0947\u0930\u0940 \u0932\u0949\u0917\u093F\u0902\u0917 \u0928\u0939\u0940\u0902</strong> \u2014 \u091C\u093F\u0928 \u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E\u094B\u0902 \u0915\u094B \u0906\u092A \u0916\u094B\u091C\u0924\u0947 \u0939\u0948\u0902 \u0935\u0947 \u0938\u0930\u094D\u0935\u0930 \u092A\u0930 \u0938\u0902\u0917\u094D\u0930\u0939\u0940\u0924 \u0928\u0939\u0940\u0902 \u0915\u093F\u090F \u091C\u093E\u0924\u0947\u0964', s3t: '3. \u0905\u0928\u093E\u092E \u0909\u092A\u092F\u094B\u0917 \u092E\u0940\u091F\u094D\u0930\u093F\u0915\u094D\u0938 (\u0935\u0948\u0915\u0932\u094D\u092A\u093F\u0915)', s3i: '\u091C\u092C \u0905\u0928\u093E\u092E \u092E\u0940\u091F\u094D\u0930\u093F\u0915\u094D\u0938 \u0938\u0915\u094D\u0937\u092E \u0939\u094B\u0924\u0947 \u0939\u0948\u0902, \u0924\u094B \u091F\u0942\u0932 \u092F\u0939 \u090F\u0915\u0924\u094D\u0930 \u0915\u0930\u0924\u093E \u0939\u0948:', s3l1: 'HMAC-\u0939\u0948\u0936 \u0915\u093F\u090F \u0917\u090F \u0921\u094B\u092E\u0947\u0928 \u0928\u093E\u092E (\u0905\u092A\u0930\u093F\u0935\u0930\u094D\u0924\u0928\u0940\u092F; \u092E\u0942\u0932 \u0921\u094B\u092E\u0947\u0928 \u092A\u0941\u0928\u0930\u094D\u092A\u094D\u0930\u093E\u092A\u094D\u0924 \u0928\u0939\u0940\u0902 \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u0924\u093E)\u0964', s3l2: '\u0938\u092E\u0917\u094D\u0930 \u0932\u0941\u0915\u0905\u092A \u0915\u093E\u0909\u0902\u091F\u0930 \u0914\u0930 \u092A\u0939\u0932\u0940 \u092C\u093E\u0930 \u0926\u0947\u0916\u0947 \u091C\u093E\u0928\u0947 \u0915\u0947 \u091F\u093E\u0907\u092E\u0938\u094D\u091F\u0948\u092E\u094D\u092A\u0964', s3l3: '\u090F\u0915 \u092F\u093E\u0926\u0943\u091A\u094D\u091B\u093F\u0915 \u0938\u0924\u094D\u0930 \u092A\u0939\u091A\u093E\u0928\u0915\u0930\u094D\u0924\u093E (\u0930\u0940\u0938\u094D\u091F\u093E\u0930\u094D\u091F \u0915\u0947 \u092C\u093E\u0926 \u0938\u0902\u0930\u0915\u094D\u0937\u093F\u0924 \u0928\u0939\u0940\u0902 \u0930\u0939\u0924\u093E)\u0964', s3b: '\u0905\u0928\u093E\u092E \u092E\u0940\u091F\u094D\u0930\u093F\u0915\u094D\u0938 \u0915\u094B <code>-DisableAnonymousMetrics</code> \u092B\u093C\u094D\u0932\u0948\u0917 \u0938\u0947 \u092A\u0942\u0930\u0940 \u0924\u0930\u0939 \u0905\u0915\u094D\u0937\u092E \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u0924\u093E \u0939\u0948\u0964', s4t: '4. Microsoft Entra ID \u092A\u094D\u0930\u092E\u093E\u0923\u0940\u0915\u0930\u0923', s4b: '\u092F\u0926\u093F \u0906\u092A Microsoft \u0915\u0947 \u0938\u093E\u0925 \u0938\u093E\u0907\u0928 \u0907\u0928 \u0915\u0930\u0928\u093E \u091A\u0941\u0928\u0924\u0947 \u0939\u0948\u0902, \u0924\u094B \u091F\u0942\u0932 Authorization Code + PKCE \u092B\u094D\u0932\u094B \u0915\u0947 \u0938\u093E\u0925 MSAL.js \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0924\u093E \u0939\u0948\u0964 \u091F\u094B\u0915\u0928 \u0906\u092A\u0915\u0947 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0915\u0947 \u0938\u0924\u094D\u0930 \u0938\u0902\u0917\u094D\u0930\u0939\u0923 \u092E\u0947\u0902 \u0938\u0902\u0917\u094D\u0930\u0939\u0940\u0924 \u0939\u094B\u0924\u0947 \u0939\u0948\u0902 \u0914\u0930 \u0915\u092D\u0940 \u092D\u0940 \u091F\u0942\u0932 \u0915\u0947 \u0938\u0930\u094D\u0935\u0930 \u092A\u0930 \u0928\u0939\u0940\u0902 \u092D\u0947\u091C\u0947 \u091C\u093E\u0924\u0947\u0964 UI \u092E\u0947\u0902 \u0906\u092A\u0915\u0940 \u092A\u0939\u091A\u093E\u0928 \u0926\u093F\u0916\u093E\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F \u091F\u0942\u0932 Microsoft Graph \u0938\u0947 \u0915\u0947\u0935\u0932 \u0906\u092A\u0915\u093E display name \u0914\u0930 email address \u092A\u0922\u093C\u0924\u093E \u0939\u0948\u0964', s5t: '5. Azure \u0938\u0902\u0938\u093E\u0927\u0928 \u0915\u094D\u0935\u0947\u0930\u0940', s5b: 'Azure Workspace Diagnostics \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0924\u0947 \u0938\u092E\u092F, \u0938\u092D\u0940 API \u0915\u0949\u0932 \u0906\u092A\u0915\u0947 \u0905\u092A\u0928\u0947 access token \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0915\u0947 \u0938\u0940\u0927\u0947 \u0906\u092A\u0915\u0947 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0938\u0947 Azure Resource Manager \u0914\u0930 Log Analytics \u0924\u0915 \u091C\u093E\u0924\u0940 \u0939\u0948\u0902\u0964 \u091F\u0942\u0932 \u0915\u093E \u0938\u0930\u094D\u0935\u0930 \u0915\u093F\u0938\u0940 Azure \u0921\u0947\u091F\u093E \u0915\u093E proxy, log \u092F\u093E store \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093E\u0964', s6t: '6. DNS \u0932\u0941\u0915\u0905\u092A', s6b: 'DNS \u0915\u094D\u0935\u0947\u0930\u0940 server-side configured resolver (system DNS \u092F\u093E DNS-over-HTTPS) \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930\u0915\u0947 \u0915\u0940 \u091C\u093E\u0924\u0940 \u0939\u0948\u0902\u0964 \u092A\u0930\u093F\u0923\u093E\u092E \u0906\u092A\u0915\u0947 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0915\u094B \u0932\u094C\u091F\u093E\u090F \u091C\u093E\u0924\u0947 \u0939\u0948\u0902 \u0914\u0930 \u0938\u0902\u0917\u094D\u0930\u0939\u0940\u0924 \u0928\u0939\u0940\u0902 \u0915\u093F\u090F \u091C\u093E\u0924\u0947\u0964', s7t: '7. \u0938\u094D\u0925\u093E\u0928\u0940\u092F \u0938\u0902\u0917\u094D\u0930\u0939\u0923', s7b: '\u091F\u0942\u0932 \u0906\u092A\u0915\u0947 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0915\u0947 <code>localStorage</code> \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0906\u092A\u0915\u0940 theme preference \u0914\u0930 recent domain history \u0915\u094B \u092C\u0928\u093E\u090F \u0930\u0916\u0928\u0947 \u0915\u0947 \u0932\u093F\u090F \u0915\u0930\u0924\u093E \u0939\u0948\u0964 \u092F\u0939 \u0921\u0947\u091F\u093E \u0915\u092D\u0940 \u0906\u092A\u0915\u0947 \u092C\u094D\u0930\u093E\u0909\u091C\u093C\u0930 \u0938\u0947 \u092C\u093E\u0939\u0930 \u0928\u0939\u0940\u0902 \u091C\u093E\u0924\u093E\u0964', s8t: '8. \u0924\u0943\u0924\u0940\u092F-\u092A\u0915\u094D\u0937 \u0938\u0947\u0935\u093E\u090F\u0901', s8b: '\u091F\u0942\u0932 DNS resolution (\u091C\u0948\u0938\u0947 DNS-over-HTTPS providers), WHOIS lookups, \u0914\u0930 DNSBL reputation checks \u0915\u0947 \u0932\u093F\u090F third-party services \u0915\u093E \u0909\u092A\u092F\u094B\u0917 \u0915\u0930 \u0938\u0915\u0924\u093E \u0939\u0948\u0964 \u0907\u0928 \u0938\u0947\u0935\u093E\u0913\u0902 \u0915\u0940 \u0905\u092A\u0928\u0940 privacy policies \u0939\u094B\u0924\u0940 \u0939\u0948\u0902\u0964', s9t: '9. \u0907\u0938 \u0935\u0915\u094D\u0924\u0935\u094D\u092F \u092E\u0947\u0902 \u092A\u0930\u093F\u0935\u0930\u094D\u0924\u0928', s9b: '\u0907\u0938 \u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0935\u0915\u094D\u0924\u0935\u094D\u092F \u0915\u094B \u0938\u092E\u092F-\u0938\u092E\u092F \u092A\u0930 \u0905\u092A\u0921\u0947\u091F \u0915\u093F\u092F\u093E \u091C\u093E \u0938\u0915\u0924\u093E \u0939\u0948\u0964 \u092A\u0930\u093F\u0935\u0930\u094D\u0924\u0928 \u091F\u0942\u0932 \u092E\u0947\u0902 \u092A\u094D\u0930\u0915\u093E\u0936\u093F\u0924 \u0939\u094B\u0928\u0947 \u092A\u0930 \u092A\u094D\u0930\u092D\u093E\u0935\u0940 \u0939\u094B \u091C\u093E\u0924\u0947 \u0939\u0948\u0902\u0964', s10t: '10. \u0938\u0902\u092A\u0930\u094D\u0915', s10b: '\u0917\u094B\u092A\u0928\u0940\u092F\u0924\u093E \u0938\u0947 \u0938\u0902\u092C\u0902\u0927\u093F\u0924 \u092A\u094D\u0930\u0936\u094D\u0928\u094B\u0902 \u0915\u0947 \u0932\u093F\u090F <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a> \u092A\u0930 \u091C\u093E\u090F\u0901\u0964' },
    'ja-JP': { pageTitle: '\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8 - ACS Email Domain Checker', back: '\u2190 ACS Email Domain Checker \u306B\u623B\u308B', title: '\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8', updatedLabel: '\u6700\u7D42\u66F4\u65B0:', updatedValue: '2026\u5E743\u6708', s1t: '1. \u6982\u8981', s1b: 'ACS Email Domain Checker\uFF08\u300C\u672C\u30C4\u30FC\u30EB\u300D\uFF09\u306F\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC\u3092\u8003\u616E\u3057\u3066\u8A2D\u8A08\u3055\u308C\u3066\u3044\u307E\u3059\u3002\u3053\u306E\u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8\u3067\u306F\u3001\u672C\u30C4\u30FC\u30EB\u304C\u53CE\u96C6\u3059\u308B\u30C7\u30FC\u30BF\u3068\u53CE\u96C6\u3057\u306A\u3044\u30C7\u30FC\u30BF\u306B\u3064\u3044\u3066\u8AAC\u660E\u3057\u307E\u3059\u3002', s2t: '2. \u53CE\u96C6\u3057\u306A\u3044\u30C7\u30FC\u30BF', s2l1: '<strong>\u500B\u4EBA\u60C5\u5831\u306A\u3057</strong> \u2014 \u672C\u30C4\u30FC\u30EB\u306F\u3001\u6C0F\u540D\u3001\u30E1\u30FC\u30EB \u30A2\u30C9\u30EC\u30B9\u3001IP \u30A2\u30C9\u30EC\u30B9\u3001\u30CF\u30FC\u30C9\u30A6\u30A7\u30A2\u8B58\u5225\u5B50\u3092\u53CE\u96C6\u3057\u307E\u305B\u3093\u3002', s2l2: '<strong>\u30C8\u30E9\u30C3\u30AD\u30F3\u30B0 Cookie \u306A\u3057</strong> \u2014 \u672C\u30C4\u30FC\u30EB\u306F\u5E83\u544A\u307E\u305F\u306F\u5206\u6790\u7528\u306E\u30C8\u30E9\u30C3\u30AD\u30F3\u30B0 Cookie \u3092\u4F7F\u7528\u3057\u307E\u305B\u3093\u3002', s2l3: '<strong>\u30AF\u30A8\u30EA \u30ED\u30B0\u306A\u3057</strong> \u2014 \u691C\u7D22\u3057\u305F\u30C9\u30E1\u30A4\u30F3\u540D\u306F\u30B5\u30FC\u30D0\u30FC\u306B\u4FDD\u5B58\u3055\u308C\u307E\u305B\u3093\u3002', s3t: '3. \u533F\u540D\u5229\u7528\u30E1\u30C8\u30EA\u30C3\u30AF\uFF08\u4EFB\u610F\uFF09', s3i: '\u533F\u540D\u30E1\u30C8\u30EA\u30C3\u30AF\u304C\u6709\u52B9\u306A\u5834\u5408\u3001\u672C\u30C4\u30FC\u30EB\u306F\u6B21\u3092\u53CE\u96C6\u3057\u307E\u3059\u3002', s3l1: 'HMAC \u30CF\u30C3\u30B7\u30E5\u5316\u3055\u308C\u305F\u30C9\u30E1\u30A4\u30F3\u540D\uFF08\u4E0D\u53EF\u9006\u3067\u3042\u308A\u3001\u5143\u306E\u30C9\u30E1\u30A4\u30F3\u306F\u5FA9\u5143\u3067\u304D\u307E\u305B\u3093\uFF09\u3002', s3l2: '\u96C6\u8A08\u3055\u308C\u305F\u53C2\u7167\u30AB\u30A6\u30F3\u30BF\u30FC\u3068\u521D\u56DE\u691C\u51FA\u30BF\u30A4\u30E0\u30B9\u30BF\u30F3\u30D7\u3002', s3l3: '\u30E9\u30F3\u30C0\u30E0\u306A\u30BB\u30C3\u30B7\u30E7\u30F3\u8B58\u5225\u5B50\uFF08\u518D\u8D77\u52D5\u5F8C\u306B\u4FDD\u6301\u3055\u308C\u307E\u305B\u3093\uFF09\u3002', s3b: '\u533F\u540D\u30E1\u30C8\u30EA\u30C3\u30AF\u306F <code>-DisableAnonymousMetrics</code> \u30D5\u30E9\u30B0\u3067\u5B8C\u5168\u306B\u7121\u52B9\u306B\u3067\u304D\u307E\u3059\u3002', s4t: '4. Microsoft Entra ID \u8A8D\u8A3C', s4b: 'Microsoft \u3067\u30B5\u30A4\u30F3\u30A4\u30F3\u3059\u308B\u5834\u5408\u3001\u672C\u30C4\u30FC\u30EB\u306F Authorization Code + PKCE \u30D5\u30ED\u30FC\u3067 MSAL.js \u3092\u4F7F\u7528\u3057\u307E\u3059\u3002\u30C8\u30FC\u30AF\u30F3\u306F\u30D6\u30E9\u30A6\u30B6\u30FC\u306E\u30BB\u30C3\u30B7\u30E7\u30F3 \u30B9\u30C8\u30EC\u30FC\u30B8\u306B\u4FDD\u5B58\u3055\u308C\u3001\u672C\u30C4\u30FC\u30EB\u306E\u30B5\u30FC\u30D0\u30FC\u306B\u9001\u4FE1\u3055\u308C\u308B\u3053\u3068\u306F\u3042\u308A\u307E\u305B\u3093\u3002\u672C\u30C4\u30FC\u30EB\u306F UI \u306B\u672C\u4EBA\u78BA\u8A8D\u60C5\u5831\u3092\u8868\u793A\u3059\u308B\u305F\u3081\u306B\u3001Microsoft Graph \u304B\u3089\u8868\u793A\u540D\u3068\u30E1\u30FC\u30EB \u30A2\u30C9\u30EC\u30B9\u306E\u307F\u3092\u8AAD\u307F\u53D6\u308A\u307E\u3059\u3002', s5t: '5. Azure \u30EA\u30BD\u30FC\u30B9 \u30AF\u30A8\u30EA', s5b: 'Azure Workspace Diagnostics \u3092\u4F7F\u7528\u3059\u308B\u5834\u5408\u3001\u3059\u3079\u3066\u306E API \u547C\u3073\u51FA\u3057\u306F\u304A\u5BA2\u69D8\u81EA\u8EAB\u306E\u30A2\u30AF\u30BB\u30B9 \u30C8\u30FC\u30AF\u30F3\u3092\u4F7F\u7528\u3057\u3066\u30D6\u30E9\u30A6\u30B6\u30FC\u304B\u3089 Azure Resource Manager \u3068 Log Analytics \u306B\u76F4\u63A5\u9001\u4FE1\u3055\u308C\u307E\u3059\u3002\u672C\u30C4\u30FC\u30EB\u306E\u30B5\u30FC\u30D0\u30FC\u306F Azure \u30C7\u30FC\u30BF\u3092\u30D7\u30ED\u30AD\u30B7\u3001\u8A18\u9332\u3001\u4FDD\u5B58\u3057\u307E\u305B\u3093\u3002', s6t: '6. DNS \u53C2\u7167', s6b: 'DNS \u30AF\u30A8\u30EA\u306F\u3001\u69CB\u6210\u3055\u308C\u305F\u30EA\u30BE\u30EB\u30D0\u30FC\uFF08\u30B7\u30B9\u30C6\u30E0 DNS \u307E\u305F\u306F DNS-over-HTTPS\uFF09\u3092\u4F7F\u7528\u3057\u3066\u30B5\u30FC\u30D0\u30FC\u5074\u3067\u5B9F\u884C\u3055\u308C\u307E\u3059\u3002\u7D50\u679C\u306F\u30D6\u30E9\u30A6\u30B6\u30FC\u306B\u8FD4\u3055\u308C\u3001\u4FDD\u5B58\u3055\u308C\u307E\u305B\u3093\u3002', s7t: '7. \u30ED\u30FC\u30AB\u30EB \u30B9\u30C8\u30EC\u30FC\u30B8', s7b: '\u672C\u30C4\u30FC\u30EB\u306F\u3001\u30C6\u30FC\u30DE\u8A2D\u5B9A\u3068\u6700\u8FD1\u306E\u30C9\u30E1\u30A4\u30F3\u5C65\u6B74\u3092\u4FDD\u6301\u3059\u308B\u305F\u3081\u306B\u3001\u30D6\u30E9\u30A6\u30B6\u30FC\u306E <code>localStorage</code> \u3092\u4F7F\u7528\u3057\u307E\u3059\u3002\u3053\u306E\u30C7\u30FC\u30BF\u304C\u30D6\u30E9\u30A6\u30B6\u30FC\u5916\u306B\u9001\u4FE1\u3055\u308C\u308B\u3053\u3068\u306F\u3042\u308A\u307E\u305B\u3093\u3002', s8t: '8. \u30B5\u30FC\u30C9\u30D1\u30FC\u30C6\u30A3 \u30B5\u30FC\u30D3\u30B9', s8b: '\u672C\u30C4\u30FC\u30EB\u306F DNS \u89E3\u6C7A\uFF08DNS-over-HTTPS \u30D7\u30ED\u30D0\u30A4\u30C0\u30FC\u306A\u3069\uFF09\u3001WHOIS \u53C2\u7167\u3001\u304A\u3088\u3073 DNSBL \u8A55\u5224\u30C1\u30A7\u30C3\u30AF\u306B\u30B5\u30FC\u30C9\u30D1\u30FC\u30C6\u30A3 \u30B5\u30FC\u30D3\u30B9\u3092\u4F7F\u7528\u3059\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002\u3053\u308C\u3089\u306E\u30B5\u30FC\u30D3\u30B9\u306B\u306F\u72EC\u81EA\u306E\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30DD\u30EA\u30B7\u30FC\u304C\u3042\u308A\u307E\u3059\u3002', s9t: '9. \u672C\u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8\u306E\u5909\u66F4', s9b: '\u3053\u306E\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \u30B9\u30C6\u30FC\u30C8\u30E1\u30F3\u30C8\u306F\u968F\u6642\u66F4\u65B0\u3055\u308C\u308B\u5834\u5408\u304C\u3042\u308A\u307E\u3059\u3002\u5909\u66F4\u306F\u672C\u30C4\u30FC\u30EB\u3067\u516C\u958B\u3055\u308C\u305F\u6642\u70B9\u3067\u6709\u52B9\u306B\u306A\u308A\u307E\u3059\u3002', s10t: '10. \u304A\u554F\u3044\u5408\u308F\u305B', s10b: '\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC\u306B\u95A2\u3059\u308B\u3054\u8CEA\u554F\u306F\u3001<a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a> \u3092\u3054\u89A7\u304F\u3060\u3055\u3044\u3002' },
    'ru-RU': { pageTitle: '\u0417\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0435 \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438 - ACS Email Domain Checker', back: '\u2190 \u041D\u0430\u0437\u0430\u0434 \u043A ACS Email Domain Checker', title: '\u0417\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0435 \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438', updatedLabel: '\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u0435 \u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435:', updatedValue: '\u041C\u0430\u0440\u0442 2026', s1t: '1. \u041E\u0431\u0437\u043E\u0440', s1b: 'ACS Email Domain Checker (\u00AB\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u00BB) \u0440\u0430\u0437\u0440\u0430\u0431\u043E\u0442\u0430\u043D \u0441 \u0443\u0447\u0435\u0442\u043E\u043C \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438. \u0412 \u044D\u0442\u043E\u043C \u0437\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0438 \u043E\u0431\u044A\u044F\u0441\u043D\u044F\u0435\u0442\u0441\u044F, \u043A\u0430\u043A\u0438\u0435 \u0434\u0430\u043D\u043D\u044B\u0435 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442, \u0430 \u043A\u0430\u043A\u0438\u0435 \u2014 \u043D\u0435\u0442.', s2t: '2. \u0414\u0430\u043D\u043D\u044B\u0435, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043C\u044B \u043D\u0435 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u043C', s2l1: '<strong>\u041D\u0435\u0442 \u043B\u0438\u0447\u043D\u043E\u0439 \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u0438</strong> \u2014 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043D\u0435 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442 \u0438\u043C\u0435\u043D\u0430, \u0430\u0434\u0440\u0435\u0441\u0430 \u044D\u043B\u0435\u043A\u0442\u0440\u043E\u043D\u043D\u043E\u0439 \u043F\u043E\u0447\u0442\u044B, IP-\u0430\u0434\u0440\u0435\u0441\u0430 \u0438\u043B\u0438 \u0430\u043F\u043F\u0430\u0440\u0430\u0442\u043D\u044B\u0435 \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u043E\u0440\u044B.', s2l2: '<strong>\u041D\u0435\u0442 \u0444\u0430\u0439\u043B\u043E\u0432 cookie \u043E\u0442\u0441\u043B\u0435\u0436\u0438\u0432\u0430\u043D\u0438\u044F</strong> \u2014 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043D\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 \u0440\u0435\u043A\u043B\u0430\u043C\u043D\u044B\u0435 \u0438\u043B\u0438 \u0430\u043D\u0430\u043B\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0435 cookie \u043E\u0442\u0441\u043B\u0435\u0436\u0438\u0432\u0430\u043D\u0438\u044F.', s2l3: '<strong>\u041D\u0435\u0442 \u0436\u0443\u0440\u043D\u0430\u043B\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432</strong> \u2014 \u0434\u043E\u043C\u0435\u043D\u043D\u044B\u0435 \u0438\u043C\u0435\u043D\u0430, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0432\u044B \u0438\u0449\u0435\u0442\u0435, \u043D\u0435 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u044E\u0442\u0441\u044F \u043D\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0435.', s3t: '3. \u0410\u043D\u043E\u043D\u0438\u043C\u043D\u044B\u0435 \u043C\u0435\u0442\u0440\u0438\u043A\u0438 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u044F (\u043D\u0435\u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u043E)', s3i: '\u0415\u0441\u043B\u0438 \u0432\u043A\u043B\u044E\u0447\u0435\u043D\u044B \u0430\u043D\u043E\u043D\u0438\u043C\u043D\u044B\u0435 \u043C\u0435\u0442\u0440\u0438\u043A\u0438, \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442:', s3l1: '\u0414\u043E\u043C\u0435\u043D\u043D\u044B\u0435 \u0438\u043C\u0435\u043D\u0430, \u0445\u044D\u0448\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u0441 \u043F\u043E\u043C\u043E\u0449\u044C\u044E HMAC (\u043D\u0435\u043E\u0431\u0440\u0430\u0442\u0438\u043C\u043E; \u0438\u0441\u0445\u043E\u0434\u043D\u044B\u0439 \u0434\u043E\u043C\u0435\u043D \u043D\u0435\u0432\u043E\u0437\u043C\u043E\u0436\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u044C).', s3l2: '\u0410\u0433\u0440\u0435\u0433\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u0441\u0447\u0435\u0442\u0447\u0438\u043A\u0438 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432 \u0438 \u043E\u0442\u043C\u0435\u0442\u043A\u0438 \u0432\u0440\u0435\u043C\u0435\u043D\u0438 \u043F\u0435\u0440\u0432\u043E\u0433\u043E \u043F\u043E\u044F\u0432\u043B\u0435\u043D\u0438\u044F.', s3l3: '\u0421\u043B\u0443\u0447\u0430\u0439\u043D\u044B\u0439 \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u043E\u0440 \u0441\u0435\u0430\u043D\u0441\u0430 (\u043D\u0435 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0435\u0442\u0441\u044F \u043F\u043E\u0441\u043B\u0435 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u043A\u0430).', s3b: '\u0410\u043D\u043E\u043D\u0438\u043C\u043D\u044B\u0435 \u043C\u0435\u0442\u0440\u0438\u043A\u0438 \u043C\u043E\u0436\u043D\u043E \u043F\u043E\u043B\u043D\u043E\u0441\u0442\u044C\u044E \u043E\u0442\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u0441 \u043F\u043E\u043C\u043E\u0449\u044C\u044E \u043F\u0430\u0440\u0430\u043C\u0435\u0442\u0440\u0430 <code>-DisableAnonymousMetrics</code>.', s4t: '4. \u0410\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F Microsoft Entra ID', s4b: '\u0415\u0441\u043B\u0438 \u0432\u044B \u0440\u0435\u0448\u0438\u0442\u0435 \u0432\u043E\u0439\u0442\u0438 \u0441 \u043F\u043E\u043C\u043E\u0449\u044C\u044E Microsoft, \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 MSAL.js \u0441 \u043F\u043E\u0442\u043E\u043A\u043E\u043C Authorization Code + PKCE. \u0422\u043E\u043A\u0435\u043D\u044B \u0445\u0440\u0430\u043D\u044F\u0442\u0441\u044F \u0432 \u0445\u0440\u0430\u043D\u0438\u043B\u0438\u0449\u0435 \u0441\u0435\u0430\u043D\u0441\u0430 \u0432\u0430\u0448\u0435\u0433\u043E \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430 \u0438 \u043D\u0438\u043A\u043E\u0433\u0434\u0430 \u043D\u0435 \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u044F\u044E\u0442\u0441\u044F \u043D\u0430 \u0441\u0435\u0440\u0432\u0435\u0440 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0430. \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0441\u0447\u0438\u0442\u044B\u0432\u0430\u0435\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u0432\u0430\u0448\u0435 \u043E\u0442\u043E\u0431\u0440\u0430\u0436\u0430\u0435\u043C\u043E\u0435 \u0438\u043C\u044F \u0438 \u0430\u0434\u0440\u0435\u0441 \u044D\u043B\u0435\u043A\u0442\u0440\u043E\u043D\u043D\u043E\u0439 \u043F\u043E\u0447\u0442\u044B \u0438\u0437 Microsoft Graph, \u0447\u0442\u043E\u0431\u044B \u043F\u043E\u043A\u0430\u0437\u0430\u0442\u044C \u0432\u0430\u0448\u0443 \u043B\u0438\u0447\u043D\u043E\u0441\u0442\u044C \u0432 \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0435.', s5t: '5. \u0417\u0430\u043F\u0440\u043E\u0441\u044B \u0440\u0435\u0441\u0443\u0440\u0441\u043E\u0432 Azure', s5b: '\u041F\u0440\u0438 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0438 Azure Workspace Diagnostics \u0432\u0441\u0435 \u0432\u044B\u0437\u043E\u0432\u044B API \u0432\u044B\u043F\u043E\u043B\u043D\u044F\u044E\u0442\u0441\u044F \u043D\u0430\u043F\u0440\u044F\u043C\u0443\u044E \u0438\u0437 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430 \u0432 Azure Resource Manager \u0438 Log Analytics \u0441 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435\u043C \u0432\u0430\u0448\u0435\u0433\u043E \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0442\u043E\u043A\u0435\u043D\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u0430. \u0421\u0435\u0440\u0432\u0435\u0440 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0430 \u043D\u0435 \u0432\u044B\u0441\u0442\u0443\u043F\u0430\u0435\u0442 \u0432 \u0440\u043E\u043B\u0438 \u043F\u0440\u043E\u043A\u0441\u0438, \u043D\u0435 \u0436\u0443\u0440\u043D\u0430\u043B\u0438\u0440\u0443\u0435\u0442 \u0438 \u043D\u0435 \u0445\u0440\u0430\u043D\u0438\u0442 \u0434\u0430\u043D\u043D\u044B\u0435 Azure.', s6t: '6. DNS-\u0437\u0430\u043F\u0440\u043E\u0441\u044B', s6b: 'DNS-\u0437\u0430\u043F\u0440\u043E\u0441\u044B \u0432\u044B\u043F\u043E\u043B\u043D\u044F\u044E\u0442\u0441\u044F \u043D\u0430 \u0441\u0442\u043E\u0440\u043E\u043D\u0435 \u0441\u0435\u0440\u0432\u0435\u0440\u0430 \u0441 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u043D\u0438\u0435\u043C \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u043D\u043E\u0433\u043E \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440\u0430 (\u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 DNS \u0438\u043B\u0438 DNS-over-HTTPS). \u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442\u044B \u0432\u043E\u0437\u0432\u0440\u0430\u0449\u0430\u044E\u0442\u0441\u044F \u0432 \u0432\u0430\u0448 \u0431\u0440\u0430\u0443\u0437\u0435\u0440 \u0438 \u043D\u0435 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u044E\u0442\u0441\u044F.', s7t: '7. \u041B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u0435 \u0445\u0440\u0430\u043D\u0438\u043B\u0438\u0449\u0435', s7b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 <code>localStorage</code> \u0432\u0430\u0448\u0435\u0433\u043E \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430 \u0434\u043B\u044F \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u0438\u044F \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043A \u0442\u0435\u043C\u044B \u0438 \u0438\u0441\u0442\u043E\u0440\u0438\u0438 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0445 \u0434\u043E\u043C\u0435\u043D\u043E\u0432. \u042D\u0442\u0438 \u0434\u0430\u043D\u043D\u044B\u0435 \u043D\u0438\u043A\u043E\u0433\u0434\u0430 \u043D\u0435 \u043F\u043E\u043A\u0438\u0434\u0430\u044E\u0442 \u0432\u0430\u0448 \u0431\u0440\u0430\u0443\u0437\u0435\u0440.', s8t: '8. \u0421\u0442\u043E\u0440\u043E\u043D\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044B', s8b: '\u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442 \u043C\u043E\u0436\u0435\u0442 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u044C \u0441\u0442\u043E\u0440\u043E\u043D\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044B \u0434\u043B\u044F \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043D\u0438\u044F DNS (\u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440, \u043F\u043E\u0441\u0442\u0430\u0432\u0449\u0438\u043A\u043E\u0432 DNS-over-HTTPS), WHOIS-\u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432 \u0438 \u043F\u0440\u043E\u0432\u0435\u0440\u043E\u043A \u0440\u0435\u043F\u0443\u0442\u0430\u0446\u0438\u0438 DNSBL. \u0423 \u044D\u0442\u0438\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432 \u0435\u0441\u0442\u044C \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0435 \u043F\u043E\u043B\u0438\u0442\u0438\u043A\u0438 \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438.', s9t: '9. \u0418\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u0432 \u044D\u0442\u043E\u043C \u0437\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0438', s9b: '\u042D\u0442\u043E \u0437\u0430\u044F\u0432\u043B\u0435\u043D\u0438\u0435 \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u0440\u0435\u043C\u044F \u043E\u0442 \u0432\u0440\u0435\u043C\u0435\u043D\u0438 \u043E\u0431\u043D\u043E\u0432\u043B\u044F\u0442\u044C\u0441\u044F. \u0418\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u0432\u0441\u0442\u0443\u043F\u0430\u044E\u0442 \u0432 \u0441\u0438\u043B\u0443 \u043F\u043E\u0441\u043B\u0435 \u043F\u0443\u0431\u043B\u0438\u043A\u0430\u0446\u0438\u0438 \u0432 \u0418\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u0435.', s10t: '10. \u041A\u043E\u043D\u0442\u0430\u043A\u0442\u044B', s10b: '\u041F\u043E \u0432\u043E\u043F\u0440\u043E\u0441\u0430\u043C, \u0441\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u043C \u0441 \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u044C\u044E, \u043F\u043E\u0441\u0435\u0442\u0438\u0442\u0435 <a href="https://blakedrumm.com/" target="_blank" rel="noopener">blakedrumm.com</a>.' }
  };

  function normalizeLanguageCode(lang) {
    const value = String(lang || '').trim().toLowerCase();
    if (!value) return 'en';
    if (value === 'ptbr' || value.startsWith('pt-br') || value.startsWith('pt_br') || value.startsWith('pt')) return 'pt-BR';
    if (value.startsWith('es')) return 'es';
    if (value.startsWith('fr')) return 'fr';
    if (value.startsWith('de')) return 'de';
    if (value.startsWith('ar')) return 'ar';
    if (value === 'zh' || value.startsWith('zh-cn') || value.startsWith('zh_cn') || value.startsWith('zh-hans')) return 'zh-CN';
    if (value === 'hi' || value.startsWith('hi-in') || value.startsWith('hi_in')) return 'hi-IN';
    if (value === 'ja' || value.startsWith('ja-jp') || value.startsWith('ja_jp')) return 'ja-JP';
    if (value === 'ru' || value.startsWith('ru-ru') || value.startsWith('ru_ru')) return 'ru-RU';
    return 'en';
  }

  const params = new URLSearchParams(window.location.search);
  const lang = normalizeLanguageCode(params.get('lang') || navigator.language || 'en');
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.title = t.pageTitle;

  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  const setHtml = (id, value) => { const el = document.getElementById(id); if (el) el.innerHTML = value; };

  setText('privacyBackLink', t.back);
  document.getElementById('privacyBackLink').href = '/?lang=' + encodeURIComponent(lang);
  setText('privacyTitle', t.title);
  setText('privacyUpdatedLabel', t.updatedLabel);
  setText('privacyUpdatedValue', t.updatedValue);
  setText('privacySection1Title', t.s1t); setText('privacySection1Body', t.s1b);
  setText('privacySection2Title', t.s2t); setHtml('privacySection2Item1', t.s2l1); setHtml('privacySection2Item2', t.s2l2); setHtml('privacySection2Item3', t.s2l3);
  setText('privacySection3Title', t.s3t); setText('privacySection3Intro', t.s3i); setText('privacySection3Item1', t.s3l1); setText('privacySection3Item2', t.s3l2); setText('privacySection3Item3', t.s3l3); setHtml('privacySection3Body', t.s3b);
  setText('privacySection4Title', t.s4t); setText('privacySection4Body', t.s4b);
  setText('privacySection5Title', t.s5t); setText('privacySection5Body', t.s5b);
  setText('privacySection6Title', t.s6t); setText('privacySection6Body', t.s6b);
  setText('privacySection7Title', t.s7t); setHtml('privacySection7Body', t.s7b);
  setText('privacySection8Title', t.s8t); setText('privacySection8Body', t.s8b);
  setText('privacySection9Title', t.s9t); setText('privacySection9Body', t.s9b);
  setText('privacySection10Title', t.s10t); setHtml('privacySection10Body', t.s10b);
})();
</script>
</body>
</html>
'@

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

# ===== Runspace Pool Initialization =====
# ------------------- MAIN LOOP -------------------
# Request handling uses a RunspacePool to process multiple HTTP requests concurrently.
# This keeps the UI responsive while DNS lookups are in flight.
# Each incoming request is dispatched to a PowerShell runspace from the pool, which
# executes the $handlerScript (defined below). The main thread only accepts connections
# and dispatches; all DNS work happens in runspace workers.

# Maximum number of concurrent request-handling runspaces.
$maxConcurrentRequests = 64

# Per-domain throttling: only one lookup per domain at a time.
# This prevents a single browser from hammering DNS (e.g., repeated refreshes) for the same domain.

$domainLocks = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Threading.SemaphoreSlim]]::new([System.StringComparer]::OrdinalIgnoreCase)

# List all functions that need to be available inside the runspace workers.
# These are injected into the InitialSessionState so each runspace can call them.
$functionNames = @(
  'Set-SecurityHeaders','Write-Json','Write-Html','Write-FileResponse',
  'New-AnonSessionId','Get-RequestCookies','Get-OrCreate-AnonymousSessionId',
  'Get-HashedDomain',
  'Get-AnonymousMetricsPersistPath','Load-AnonymousMetricsPersisted','Save-AnonymousMetricsPersisted',
  'Update-AnonymousMetrics','Get-AnonymousMetricsSnapshot',
  'Get-RegistrableDomain','Get-ParentDomains','Test-WhoisRawTextHasUsableData',
  'Resolve-DohName','ResolveSafely','Get-DnsIpString','Get-MxRecordObjects','ConvertTo-NormalizedDomain','Test-DomainName','Write-RequestLog',
  'Get-SpfTokens','Test-SpfOutlookIncludeToken','Find-SpfOutlookRequirementMatch','Get-SpfOutlookRequirementStatus','Get-SpfNestedAnalysis','Format-SpfNestedAnalysisText','Get-SpfGuidance',
  'Get-ClientIp','Get-ApiKeyFromRequest','Test-ApiKey','Test-RateLimit',
  'Get-DnsBaseStatus','Get-DnsMxStatus','Get-DnsDmarcStatus','Get-DnsDkimStatus','Get-CnameTargetFromRecords','Get-DnsCnameStatus','Invoke-RblLookup','ConvertTo-ReversedIpv4','Get-DnsReputationStatus',
  'Get-RblCacheEntry','Set-RblCacheEntry','Clear-ExpiredRblCacheEntries',
  'Get-RdapBootstrapData','Get-RdapBaseUrlForDomain','Invoke-RdapLookup','Invoke-WhoisXmlLookup','Invoke-GoDaddyWhoisLookup','ConvertTo-NullableUtcIso8601','Get-DomainAgeDays','Get-DomainRegistrationStatus',
  'Get-DmarcSecurityGuidance',
  'Invoke-SysinternalsWhoisLookup','Invoke-LinuxWhoisLookup','Invoke-TcpWhoisLookup','Get-DomainAgeParts','Format-DomainAge','Get-TimeUntilParts','Format-ExpiryRemaining',
  'Get-AcsDnsStatus'
)

# Create an InitialSessionState that will be shared by all runspace workers.
# This seeds each runspace with the function definitions, shared variables, and config.
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

# Create and open the RunspacePool. Workers will be allocated from this pool on demand.
$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxConcurrentRequests, $iss, $Host)
$pool.Open()

# Track in-flight async invocations so we can dispose them promptly from the main runspace.
$inflight = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Complete-InflightInvocation {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InvocationId,

    [switch]$Force
  )

  $item = $null
  if (-not $inflight.TryGetValue($InvocationId, [ref]$item)) { return }
  if (-not $Force -and -not $item.Async.IsCompleted) { return }

  if ($inflight.TryRemove($InvocationId, [ref]$item)) {
    $completed = $false
    try { $completed = ($item.Async -and $item.Async.IsCompleted) } catch { $completed = $false }

    if ($completed) {
      try { $item.Ps.EndInvoke($item.Async) } catch { $null = $_ }
    }
    elseif ($Force) {
      try { $item.Ps.Stop() } catch { $null = $_ }
    }

    try {
      if ($item.Async -and $item.Async.AsyncWaitHandle) {
        $item.Async.AsyncWaitHandle.Close()
      }
    } catch { $null = $_ }
    try { $item.Ps.Dispose() } catch { $null = $_ }
  }
}

function Register-InflightInvocation {
  param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PowerShell]$PowerShellInstance,

    [Parameter(Mandatory = $true)]
    [object]$AsyncResult
  )

  $invocationId = [Guid]::NewGuid().ToString('N')
  $item = [pscustomobject]@{
    Ps = $PowerShellInstance
    Async = $AsyncResult
  }

  $null = $inflight.TryAdd($invocationId, $item)

  return $invocationId
}

# Reap any completed async PowerShell invocations from the main runspace.
function Invoke-InflightCleanup {
  foreach ($invocationId in @($inflight.Keys)) {
    Complete-InflightInvocation -InvocationId $invocationId
  }
}

# ===== Per-Request Handler Script =====
# ------------------- PER-REQUEST HANDLER SCRIPT -------------------
# This here-string is the script block that runs inside each RunspacePool worker
# for every incoming HTTP request. It receives the request context, routes by URL path,
# and dispatches to the appropriate DNS check function or serves the HTML UI.
$handlerScript = @'
param($ctx, $htmlPage, $domainLocks, $msalLocalPath, $tosPageHtml, $privacyPageHtml)

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

  # 1-tos) Serve Terms of Service page
  if ($path -eq "/terms" -and -not [string]::IsNullOrWhiteSpace($tosPageHtml)) {
    $tosNonceBytes = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tosNonceBytes)
    $tosNonce = [Convert]::ToBase64String($tosNonceBytes)
    Write-Html -Context $ctx -Html $tosPageHtml -Nonce $tosNonce
    return
  }

  # 1-privacy) Serve Privacy Statement page
  if ($path -eq "/privacy" -and -not [string]::IsNullOrWhiteSpace($privacyPageHtml)) {
    $privNonceBytes = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($privNonceBytes)
    $privNonce = [Convert]::ToBase64String($privNonceBytes)
    Write-Html -Context $ctx -Html $privacyPageHtml -Nonce $privNonce
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
      if ($metricsEnabled) { Update-AnonymousMetrics -Domain $domain -Started }
      $result = Get-AcsDnsStatus -Domain $domain
      Write-Json -Context $ctx -Object $result
      if ($metricsEnabled) { Update-AnonymousMetrics -Domain $domain -Completed }
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
# ===== HTTP Accept Loop & TcpListener Shim =====

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

  # ------------------- TcpListener HTTP Shim -------------------
  # When HttpListener is unavailable, these helper functions provide a minimal HTTP/1.1
  # implementation over raw TCP sockets. They parse request lines + headers and build
  # response objects that mimic the HttpListenerResponse API surface.
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

  # Read and parse an HTTP/1.1 request from a raw TCP stream (request line + headers).
  # Only GET and POST are supported by the TcpListener server mode.
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
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath).AddArgument($script:TosPageHtml).AddArgument($script:PrivacyPageHtml)

        $async = $ps.BeginInvoke()
        $null = Register-InflightInvocation -PowerShellInstance $ps -AsyncResult $async

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
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath).AddArgument($script:TosPageHtml).AddArgument($script:PrivacyPageHtml)

        $async = $ps.BeginInvoke()
        $null = Register-InflightInvocation -PowerShellInstance $ps -AsyncResult $async

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
# ===== Graceful Shutdown =====
finally {
# ------------------- GRACEFUL SHUTDOWN -------------------
# Stop listeners, persist final metrics, drain in-flight requests, and dispose the pool.
try { if ($listener -and $listener.IsListening) { $listener.Stop() } } catch { $null = $_ }
try { if ($tcpListener) { $tcpListener.Stop() } } catch { $null = $_ }

  # Persist metrics one last time.
  try { Save-AnonymousMetricsPersisted -Force } catch { $null = $_ }

  Invoke-InflightCleanup
  foreach ($invocationId in @($inflight.Keys)) {
    Complete-InflightInvocation -InvocationId $invocationId -Force
  }
  try { $pool.Close(); $pool.Dispose() } catch { $null = $_ }
  Write-Information -InformationAction Continue -MessageData "Server stopped."
}
