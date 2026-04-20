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

# Built-in TLD -> RDAP base URL map used as a safety net when the IANA bootstrap
# fetch is unavailable (offline / proxy / first-run) or when a registry has not
# yet been added to the published bootstrap file. Keeping these inline preserves
# the project's "no third-party data providers required" goal: the URLs below
# are the registries' own RDAP endpoints, not third-party WHOIS aggregators.
function Get-RdapBuiltInTldMap {
  # Returned as a fresh hashtable so callers in any runspace can use it without
  # depending on script-scoped state (worker runspaces only inherit function
  # definitions, not script-scope variables, so a $script: hashtable is invisible
  # to them).
  return @{
    'ch'  = 'https://rdap.nic.ch/'
    'li'  = 'https://rdap.nic.ch/'
    'de'  = 'https://rdap.denic.de/'
    'nl'  = 'https://rdap.dns.nl/'
    'eu'  = 'https://rdap.eu.org/'
    'fr'  = 'https://rdap.nic.fr/'
    're'  = 'https://rdap.nic.fr/'
    'pm'  = 'https://rdap.nic.fr/'
    'tf'  = 'https://rdap.nic.fr/'
    'wf'  = 'https://rdap.nic.fr/'
    'yt'  = 'https://rdap.nic.fr/'
    'be'  = 'https://rdap.dnsbelgium.be/'
    'cz'  = 'https://rdap.nic.cz/'
    'se'  = 'https://rdap.iis.se/'
    'nu'  = 'https://rdap.iis.se/'
    'br'  = 'https://rdap.registro.br/'
    'pt'  = 'https://rdap.dns.pt/'
    'fi'  = 'https://rdap.traficom.fi/'
    'au'  = 'https://rdap.auda.org.au/'
    'us'  = 'https://rdap.nic.us/'
    'co'  = 'https://rdap.nic.co/'
    'io'  = 'https://rdap.nic.io/'
    'ai'  = 'https://rdap.nic.ai/'
    'app' = 'https://rdap.nic.google/'
    'dev' = 'https://rdap.nic.google/'
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

  # 1) Prefer the IANA bootstrap mapping when available.
  $bootstrap = $null
  try { $bootstrap = Get-RdapBootstrapData } catch { $bootstrap = $null }
  if ($bootstrap -and $bootstrap.services) {
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

        break
      }
    }
  }

  # 2) Fall back to the built-in map for restrictive registries that refuse
  # port-43 WHOIS but operate their own RDAP service. This keeps lookups
  # working even when the bootstrap file cannot be downloaded or when the
  # function is being invoked from a worker runspace that does not inherit
  # script-scoped variables from the parent process.
  $builtIn = Get-RdapBuiltInTldMap
  if ($builtIn -and $builtIn.ContainsKey($tld)) {
    return $builtIn[$tld]
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
