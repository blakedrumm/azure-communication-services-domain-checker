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
