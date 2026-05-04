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

# Read a specific request header from either HttpListener or the TcpListener shim.
function Get-RequestHeaderValue {
  param(
    $Context,
    [string]$Name
  )

  if (-not $Context -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
  try {
    $headers = $null
    try { $headers = $Context.Request.Headers } catch { $headers = $null }
    if ($null -eq $headers) { return $null }

    # Branch on the *headers* type, not the request type. The TcpListener shim
    # stores headers as a [hashtable] (lowercased keys, supports ContainsKey),
    # while HttpListenerRequest exposes a WebHeaderCollection (no ContainsKey
    # method, but case-insensitive indexer). Picking the right access pattern
    # by type avoids a silent throw-and-swallow that previously caused this
    # function to always return $null for HttpListener requests, which in turn
    # broke consent-gated analytics increments (see /api/base path).
    if ($headers -is [System.Collections.IDictionary]) {
      if ($headers.Contains($Name)) { return [string]$headers[$Name] }
      $lower = $Name.ToLowerInvariant()
      if ($headers.Contains($lower)) { return [string]$headers[$lower] }
      return $null
    }

    # WebHeaderCollection / NameValueCollection — case-insensitive indexer
    # returns $null for missing keys instead of throwing.
    $value = $null
    try { $value = $headers[$Name] } catch { $value = $null }
    if ($null -ne $value) { return [string]$value }
  } catch { }
  return $null
}

# Parse the consent header sent by the browser UI. Returns $true, $false, or $null
# when the request did not explicitly include an analytics consent state.
function Get-AnonymousAnalyticsConsentState {
  param($Context)

  $raw = Get-RequestHeaderValue -Context $Context -Name 'X-ACS-Cookie-Consent'
  if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

  try {
    foreach ($part in ($raw -split ';')) {
      $segment = [string]$part
      if ([string]::IsNullOrWhiteSpace($segment)) { continue }
      $kv = $segment.Trim() -split '=', 2
      if ($kv.Count -ne 2) { continue }
      $name = ([string]$kv[0]).Trim().ToLowerInvariant()
      $value = ([string]$kv[1]).Trim().ToLowerInvariant()
      if ($name -ne 'analytics') { continue }
      if ($value -in @('1', 'true', 'yes', 'on')) { return $true }
      if ($value -in @('0', 'false', 'no', 'off')) { return $false }
    }
  } catch { }

  return $null
}

# Remove the analytics session cookie when the user explicitly rejects analytics.
function Clear-AnonymousSessionCookie {
  param($Context)

  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $Context.Response.Headers.Add('Set-Cookie', 'acs_session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; HttpOnly')
    }
  } catch { }
}

# Read the acs_session cookie from the request, or create a new one and set it on the response.
# Also registers the session in the in-memory metrics session tracker.
function Get-OrCreate-AnonymousSessionId {
  param($Context)

  try {
    $cookieHeader = $null
    $headers = $null
    try { $headers = $Context.Request.Headers } catch { $headers = $null }
    if ($null -ne $headers) {
      # Branch on the *headers* type so we use the correct access pattern. See
      # the comment in Get-RequestHeaderValue for the full rationale: the
      # TcpListener shim uses a [hashtable] with ContainsKey/Contains, while
      # HttpListenerRequest exposes a WebHeaderCollection whose ContainsKey
      # call would throw and silently zero out the cookie header.
      if ($headers -is [System.Collections.IDictionary]) {
        if ($headers.Contains('cookie')) { $cookieHeader = [string]$headers['cookie'] }
        elseif ($headers.Contains('Cookie')) { $cookieHeader = [string]$headers['Cookie'] }
      } else {
        try { $cookieHeader = [string]$headers['Cookie'] } catch { $cookieHeader = $null }
      }
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

# Anonymous Microsoft Entra ID auth metrics. Called from the consent-gated
# `/api/auth/event` route after the SPA has finished verifying the user
# against Microsoft Graph entirely client-side. The server never sees the
# user's access token, UPN, oid, or tenant ID directly:
#
# - $AccountKey is an opaque, client-side SHA-256 hex digest of
#   `tenantId + ':' + oid`. The browser computes it via SubtleCrypto and
#   posts only the hex digest. We then HMAC-rehash it with the server-only
#   `MetricsHashKey` so that even if both the persisted metrics file and the
#   client-side digest leak, an attacker cannot precompute the stored hash
#   without also stealing the per-install hash key.
# - $IsMicrosoftEmployee is a boolean flag the SPA derives from the user's
#   UPN domain (microsoft.com / microsoftsupport.com). We trust it for
#   anonymous bucket counting only; nothing security-sensitive depends on
#   the value being honest. Worst case a tampered request inflates a usage
#   counter by 1, which is acceptable for an opt-in analytics signal.
#
# Both per-call counters (totalMsAuthVerifications, lifetimeMsAuthVerifications)
# are incremented unconditionally so we can see overall sign-in volume; the
# unique employee hash set only grows when IsMicrosoftEmployee is true.
function Update-AnonymousAuthMetrics {
  param(
    [Parameter(Mandatory = $false)]
    [string]$AccountKey,

    [Parameter(Mandatory = $false)]
    [bool]$IsMicrosoftEmployee
  )

  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  try {
    # Per-verification counters are bumped for every authenticated request so
    # the lifetime counter reflects total sign-in volume (employees + guests).
    [System.Threading.Interlocked]::Increment($script:AcsMetrics['totalMsAuthVerifications']) | Out-Null
    [System.Threading.Interlocked]::Increment($script:AcsMetrics['lifetimeMsAuthVerifications']) | Out-Null

    if ($IsMicrosoftEmployee -and -not [string]::IsNullOrWhiteSpace($AccountKey)) {
      # Rehash the SPA-supplied SHA-256 with the server-side HMAC key. The
      # existing Get-HashedDomain helper already wraps HMAC-SHA256 with
      # `MetricsHashKey`, so we reuse it for consistency rather than
      # duplicating the crypto. The trim+lowercase it does is a no-op on a
      # hex digest but keeps behavior uniform with domain hashing.
      $hashed = Get-HashedDomain $AccountKey
      if (-not [string]::IsNullOrWhiteSpace($hashed)) {
        $null = $script:AcsMetrics['lifetimeMsEmployeeIdHashes'].TryAdd($hashed, 0)
      }
    }

    # Persist immediately so the new event survives a quick restart. Save is
    # internally throttled / mutex-protected, so calling it here is safe even
    # under bursty consent toggles.
    Save-AnonymousMetricsPersisted
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
