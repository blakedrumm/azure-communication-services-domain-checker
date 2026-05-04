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

# Extract the client's IP address from the request.
#
# By default we use the immediate TCP peer (RemoteEndPoint). If the
# `ACS_TRUSTED_PROXIES` env var lists the immediate peer (as an IP or CIDR),
# we additionally honor `X-Forwarded-For` / `X-Real-IP` so reverse-proxy
# deployments can still rate-limit / log on the originating client IP.
#
# This is intentionally strict: arbitrary clients can set X-Forwarded-For,
# so trusting it unconditionally lets any caller spoof their identity for
# `Test-RateLimit`. Operators who terminate TLS at a known proxy must
# opt in by listing that proxy's IP/CIDR in ACS_TRUSTED_PROXIES.
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

  # Resolve the immediate socket peer first; this is the trust anchor.
  $peerIp = $null
  try {
    if ($Context.Request -is [System.Net.HttpListenerRequest]) {
      $peerIp = [string]$Context.Request.RemoteEndPoint.Address
    }
    elseif ($Context.Request.RemoteEndPoint) {
      $peerIp = [string]$Context.Request.RemoteEndPoint.Address
    }
  } catch { $peerIp = $null }

  # Honor forwarded headers only when the immediate peer is a configured
  # trusted proxy. This avoids client-spoofable rate-limit bypass.
  if ($headers -and -not [string]::IsNullOrWhiteSpace($peerIp) -and (Test-IsTrustedProxy -PeerIp $peerIp)) {
    $forwardedRaw = $null
    foreach ($h in @('X-Forwarded-For','x-forwarded-for')) {
      try { $forwardedRaw = [string]$headers[$h] } catch { $forwardedRaw = $null }
      if (-not [string]::IsNullOrWhiteSpace($forwardedRaw)) { break }
    }
    if (-not [string]::IsNullOrWhiteSpace($forwardedRaw)) {
      # Per RFC 7239 / de-facto standard, the original client IP is the leftmost
      # value in a comma-separated list. Normalize whitespace and surrounding brackets.
      $first = ($forwardedRaw -split ',')[0]
      $first = ([string]$first).Trim().Trim('"').Trim('[').Trim(']')
      if (-not [string]::IsNullOrWhiteSpace($first)) { return $first }
    }

    $realIp = $null
    foreach ($h in @('X-Real-IP','x-real-ip')) {
      try { $realIp = [string]$headers[$h] } catch { $realIp = $null }
      if (-not [string]::IsNullOrWhiteSpace($realIp)) { break }
    }
    if (-not [string]::IsNullOrWhiteSpace($realIp)) {
      return $realIp.Trim()
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($peerIp)) { return $peerIp }
  return $null
}

# Return $true when the immediate peer IP is listed in ACS_TRUSTED_PROXIES
# (comma/semicolon/newline-delimited list of IPs and/or CIDRs). Parsing is
# best-effort: malformed entries are silently ignored so a typo never causes
# the listener to crash mid-request.
function Test-IsTrustedProxy {
  param([string]$PeerIp)

  if ([string]::IsNullOrWhiteSpace($PeerIp)) { return $false }
  $raw = [string]$env:ACS_TRUSTED_PROXIES
  if ([string]::IsNullOrWhiteSpace($raw)) { return $false }

  $peerAddr = $null
  try { $peerAddr = [System.Net.IPAddress]::Parse($PeerIp) } catch { return $false }

  $entries = @()
  foreach ($chunk in ($raw -split '[,;\r\n]')) {
    $t = ([string]$chunk).Trim()
    if (-not [string]::IsNullOrWhiteSpace($t)) { $entries += $t }
  }
  if ($entries.Count -eq 0) { return $false }

  foreach ($entry in $entries) {
    # CIDR form: address/prefix
    if ($entry.Contains('/')) {
      $parts = $entry.Split('/', 2)
      if ($parts.Count -ne 2) { continue }
      $network = $null
      try { $network = [System.Net.IPAddress]::Parse($parts[0]) } catch { continue }
      $prefix = 0
      if (-not [int]::TryParse($parts[1], [ref]$prefix)) { continue }
      if ($network.AddressFamily -ne $peerAddr.AddressFamily) { continue }
      $netBytes = $network.GetAddressBytes()
      $peerBytes = $peerAddr.GetAddressBytes()
      $maxBits = $netBytes.Length * 8
      if ($prefix -lt 0 -or $prefix -gt $maxBits) { continue }
      $bitsRemaining = $prefix
      $matched = $true
      for ($i = 0; $i -lt $netBytes.Length; $i++) {
        if ($bitsRemaining -ge 8) {
          if ($netBytes[$i] -ne $peerBytes[$i]) { $matched = $false; break }
          $bitsRemaining -= 8
        }
        elseif ($bitsRemaining -gt 0) {
          $mask = [byte](0xFF -shl (8 - $bitsRemaining)) -band 0xFF
          if (($netBytes[$i] -band $mask) -ne ($peerBytes[$i] -band $mask)) { $matched = $false }
          break
        }
        else { break }
      }
      if ($matched) { return $true }
    }
    else {
      # Plain address form
      $candidate = $null
      try { $candidate = [System.Net.IPAddress]::Parse($entry) } catch { continue }
      if ($candidate.Equals($peerAddr)) { return $true }
    }
  }

  return $false
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

# Constant-time string comparison.
# Avoids the small timing side channel of [string]::Equals which short-circuits
# on the first mismatching byte. The remote-attacker exploitability of that
# side channel over the network is low (PowerShell + jitter dominate any
# nanosecond-scale leak), but a fixed-time compare costs essentially nothing
# and removes the side channel entirely. The XOR-accumulator pattern walks
# every byte of the longer string so the elapsed time depends only on the
# combined length, not on where the first byte differs.
function Test-StringEqualsConstantTime {
  param(
    [string]$A,
    [string]$B
  )

  if ($null -eq $A) { $A = '' }
  if ($null -eq $B) { $B = '' }

  $bytesA = [Text.Encoding]::UTF8.GetBytes($A)
  $bytesB = [Text.Encoding]::UTF8.GetBytes($B)

  # Walk the longer of the two so length differences cannot short-circuit.
  $maxLen = [Math]::Max($bytesA.Length, $bytesB.Length)
  $diff = $bytesA.Length -bxor $bytesB.Length
  for ($i = 0; $i -lt $maxLen; $i++) {
    $bA = if ($i -lt $bytesA.Length) { $bytesA[$i] } else { 0 }
    $bB = if ($i -lt $bytesB.Length) { $bytesB[$i] } else { 0 }
    $diff = $diff -bor ($bA -bxor $bB)
  }
  return ($diff -eq 0)
}

# Validate the API key from the request against ACS_API_KEY env var.
# Returns $true if no API key is configured (open access) or if the provided key matches.
function Test-ApiKey {
  param($Context)

  $expected = [string]$env:ACS_API_KEY
  if ([string]::IsNullOrWhiteSpace($expected)) { return $true }

  $provided = Get-ApiKeyFromRequest -Context $Context
  if ([string]::IsNullOrWhiteSpace($provided)) { return $false }

  # Constant-time compare so a remote caller cannot infer the API key one byte
  # at a time by measuring response timing. See Test-StringEqualsConstantTime.
  return Test-StringEqualsConstantTime -A $provided -B $expected
}

# Enforce per-client-IP rate limiting using a sliding 60-second window.
# Returns an object with allowed (bool), remaining count, and retry-after seconds.
#
# -Multiplier raises the per-window limit for cheap, high-frequency endpoints
# (such as /api/metrics, which is polled by the SPA dashboard). The default
# multiplier of 1 keeps the original behavior for DNS/WHOIS endpoints. The
# bucket is shared across multipliers so a single noisy client cannot escape
# rate limiting by spreading calls across endpoints.
function Test-RateLimit {
  param(
    $Context,
    [int]$Multiplier = 1
  )

  $limit = 0
  if ($env:ACS_RATE_LIMIT_PER_MIN -and $env:ACS_RATE_LIMIT_PER_MIN -match '^\d+$') {
    $limit = [int]$env:ACS_RATE_LIMIT_PER_MIN
  }
  if ($limit -le 0) {
    return [pscustomobject]@{ allowed = $true; remaining = $null; retryAfterSec = $null; limit = $limit }
  }
  if ($Multiplier -lt 1) { $Multiplier = 1 }
  $effectiveLimit = $limit * $Multiplier

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

    if ($entry.count -ge $effectiveLimit) {
      $retryAfter = [int][Math]::Ceiling(($entry.windowStart.AddSeconds($windowSeconds) - $now).TotalSeconds)
      if ($retryAfter -lt 1) { $retryAfter = 1 }
      return [pscustomobject]@{ allowed = $false; remaining = 0; retryAfterSec = $retryAfter; limit = $effectiveLimit }
    }

    $entry.count++
    $remaining = [Math]::Max(0, $effectiveLimit - $entry.count)
    return [pscustomobject]@{ allowed = $true; remaining = $remaining; retryAfterSec = $null; limit = $effectiveLimit }
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
