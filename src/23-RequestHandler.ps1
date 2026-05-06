# ===== Per-Request Handler Script =====
# ------------------- PER-REQUEST HANDLER SCRIPT -------------------
# This here-string is the script block that runs inside each RunspacePool worker
# for every incoming HTTP request. It receives the request context, routes by URL path,
# and dispatches to the appropriate DNS check function or serves the HTML UI.
$handlerScript = @'
param($ctx, $htmlPage, $domainLocks, $msalLocalPath, $tosPageHtml, $privacyPageHtml, $assetsRoot)

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

# SECURITY: Cap POST/PUT/PATCH request bodies before any handler runs. The
# only POST today is /api/consent which is header-driven and ignores the
# body, so any oversized body is wasted bandwidth and a tying-up vector for
# worker runspaces. The cap is configurable via ACS_MAX_REQUEST_BODY_BYTES
# (default 64 KB, set in 00-Header.ps1). Returning 413 early avoids reading
# the body at all.
try {
  $reqMethod = $null
  try { $reqMethod = [string]$ctx.Request.HttpMethod } catch { $reqMethod = $null }
  if ([string]::IsNullOrWhiteSpace($reqMethod)) {
    try { $reqMethod = [string]$ctx.Request.Method } catch { $reqMethod = $null }
  }
  if (-not [string]::IsNullOrWhiteSpace($reqMethod)) {
    $reqMethodUpper = $reqMethod.ToUpperInvariant()
    if ($reqMethodUpper -eq 'POST' -or $reqMethodUpper -eq 'PUT' -or $reqMethodUpper -eq 'PATCH') {
      $bodyCap = 65536
      if ($env:ACS_MAX_REQUEST_BODY_BYTES -and $env:ACS_MAX_REQUEST_BODY_BYTES -match '^\d+$') {
        $bodyCap = [int]$env:ACS_MAX_REQUEST_BODY_BYTES
      }
      $contentLength = -1
      try {
        if ($ctx.Request -is [System.Net.HttpListenerRequest]) {
          $contentLength = [int64]$ctx.Request.ContentLength64
        } else {
          $clHeader = $null
          try {
            if ($ctx.Request.Headers -and $ctx.Request.Headers.ContainsKey('content-length')) {
              $clHeader = [string]$ctx.Request.Headers['content-length']
            }
          } catch { $clHeader = $null }
          if (-not [string]::IsNullOrWhiteSpace($clHeader)) {
            $parsed = 0
            if ([int64]::TryParse($clHeader, [ref]$parsed)) { $contentLength = $parsed }
          }
        }
      } catch { $contentLength = -1 }
      if ($contentLength -gt $bodyCap) {
        Write-Json -Context $ctx -Object @{ error = 'Request body too large.'; maxBytes = $bodyCap } -StatusCode 413
        return
      }
    }
  }
} catch { }

# This script block runs inside the RunspacePool for each incoming request.
# Inputs:
# - $ctx         : the request/response context (HttpListenerContext or TcpListener shim)
# - $htmlPage    : the embedded SPA HTML (string)
# - $domainLocks : shared dictionary of per-domain semaphores

function Get-DomainSemaphore([string]$domain, [string]$scope) {
  # Get/create a per-domain+scope semaphore so duplicate work serializes, while
  # different lookup stages for the same domain can still run concurrently.
  $scopeKey = if ([string]::IsNullOrWhiteSpace($scope)) { 'default' } else { $scope.Trim() }
  $lockKey = if ([string]::IsNullOrWhiteSpace($domain)) { $scopeKey } else { "$scopeKey|$domain" }

  # SECURITY/MEMORY: prune idle semaphores when the dictionary grows large so a
  # long-running container that processes many distinct domains cannot leak
  # memory indefinitely. We only remove entries whose semaphore is currently
  # idle (CurrentCount == 1, meaning no holder, no waiters), so an in-flight
  # lookup is never disturbed. The threshold was lowered from 10k to 1k so a
  # request burst against many distinct domains cannot balloon the dictionary
  # before the next prune fires; the prune walk itself is bounded so a very
  # large dictionary cannot pin the request thread either.
  try {
    if ($domainLocks.Count -gt 1000) {
      $pruneBudget = 2000
      foreach ($existingKey in @($domainLocks.Keys)) {
        if ($pruneBudget -le 0) { break }
        $pruneBudget--
        $existingSem = $null
        if ($domainLocks.TryGetValue($existingKey, [ref]$existingSem)) {
          if ($existingSem -and $existingSem.CurrentCount -eq 1) {
            $removed = $null
            if ($domainLocks.TryRemove($existingKey, [ref]$removed)) {
              try { $removed.Dispose() } catch { }
            }
          }
        }
      }
    }
  } catch { }

  $sem = $null
  if (-not $domainLocks.TryGetValue($lockKey, [ref]$sem)) {
    $newSem = [System.Threading.SemaphoreSlim]::new(1, 1)
    if ($domainLocks.TryAdd($lockKey, $newSem)) {
      $sem = $newSem
    } else {
      $null = $domainLocks.TryGetValue($lockKey, [ref]$sem)
    }
  }
  return $sem
}

try {
# Anonymous metrics are only allowed after the browser explicitly sends
# analytics consent in the consent header. This prevents non-essential
# analytics cookies from being issued before the user opts in.
$metricsEnabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled)
$analyticsConsentState = $null
if ($metricsEnabled) {
  $analyticsConsentState = Get-AnonymousAnalyticsConsentState -Context $ctx
  if ($false -eq $analyticsConsentState) {
    Clear-AnonymousSessionCookie -Context $ctx
  }
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

  # 1a-assets) Serve local static assets from the repository assets folder.
  # Restrict responses to files beneath the configured assets root to prevent
  # path traversal from exposing arbitrary content on disk.
  if ($path.StartsWith('/assets/', [System.StringComparison]::OrdinalIgnoreCase) -and -not [string]::IsNullOrWhiteSpace($assetsRoot)) {
    try {
      $relativeAssetPath = $path.Substring(8) -replace '/', [System.IO.Path]::DirectorySeparatorChar
      $rootFullPath = [System.IO.Path]::GetFullPath($assetsRoot)
      $assetFullPath = [System.IO.Path]::GetFullPath((Join-Path -Path $rootFullPath -ChildPath $relativeAssetPath))

      # SECURITY: Append a directory separator before the prefix check so a
      # sibling directory whose name starts with the same prefix (for example
      # `C:\repo\assetsX\` vs `C:\repo\assets\`) cannot satisfy `StartsWith`.
      # On Windows the comparison stays case-insensitive; on case-sensitive
      # file systems we use ordinal comparison so an "/Assets/..." request
      # path will not slip through pointing at a different directory.
      $sep = [string][System.IO.Path]::DirectorySeparatorChar
      $rootFullPathWithSep = if ($rootFullPath.EndsWith($sep)) { $rootFullPath } else { $rootFullPath + $sep }
      # `$IsWindows` is only defined in PowerShell 7+. On Windows PowerShell
      # 5.1 (Desktop edition) the variable is unset, so we treat the
      # Desktop edition as Windows by definition.
      $isWindowsRuntime = $false
      try { if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $isWindowsRuntime = [bool]$IsWindows } } catch { }
      if (-not $isWindowsRuntime -and $PSVersionTable.PSEdition -eq 'Desktop') { $isWindowsRuntime = $true }
      $comparisonMode = if ($isWindowsRuntime) {
        [System.StringComparison]::OrdinalIgnoreCase
      } else {
        [System.StringComparison]::Ordinal
      }
      if (-not $assetFullPath.StartsWith($rootFullPathWithSep, $comparisonMode) -and ($assetFullPath -ne $rootFullPath)) {
        Write-Json -Context $ctx -Object @{ error = 'Invalid asset path.' } -StatusCode 400
        return
      }

      $contentType = 'application/octet-stream'
      switch ([System.IO.Path]::GetExtension($assetFullPath).ToLowerInvariant()) {
        '.svg' { $contentType = 'image/svg+xml; charset=utf-8' }
        '.png' { $contentType = 'image/png' }
        '.jpg' { $contentType = 'image/jpeg' }
        '.jpeg' { $contentType = 'image/jpeg' }
        '.gif' { $contentType = 'image/gif' }
        '.webp' { $contentType = 'image/webp' }
        '.ico' { $contentType = 'image/x-icon' }
        '.js' { $contentType = 'application/javascript; charset=utf-8' }
        '.css' { $contentType = 'text/css; charset=utf-8' }
      }

      Write-FileResponse -Context $ctx -Path $assetFullPath -ContentType $contentType
      return
    } catch {
      Write-Json -Context $ctx -Object @{ error = 'Failed to load requested asset.' } -StatusCode 500
      return
    }
  }

  # 1b) Metrics endpoint handled by caller (fast-path in main loop). Keep here as safety net only.
  if ($path -eq "/api/metrics") {
    Handle-MetricsRequest -Context $ctx -MetricsEnabled $metricsEnabled
    return
  }

  # 1c) Consent sync endpoint. This is called by the SPA after the user saves
  # cookie preferences so the server can immediately clear any existing
  # analytics session cookie when analytics consent is rejected.
  # Rate-limited so a noisy client cannot pin a worker runspace by spamming
  # consent toggles. Uses a generous multiplier because the SPA may legitimately
  # call this several times during a single page load (load + save + theme).
  if ($path -eq '/api/consent') {
    $rate = Test-RateLimit -Context $ctx -Multiplier 4
    if (-not $rate.allowed) {
      try {
        if ($ctx.Response -is [System.Net.HttpListenerResponse] -and $rate.retryAfterSec) {
          $ctx.Response.Headers['Retry-After'] = [string]$rate.retryAfterSec
        }
      } catch { }
      Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $rate.retryAfterSec } -StatusCode 429
      return
    }
    if ($false -eq $analyticsConsentState) {
      Clear-AnonymousSessionCookie -Context $ctx
    }
    Write-Json -Context $ctx -Object @{
      ok = $true
      analyticsConsent = $(if ($null -eq $analyticsConsentState) { $null } else { [bool]$analyticsConsentState })
    }
    return
  }

  # 2) Serve individual API endpoints (/api/*)
  if ($path -in @("/api/base","/api/mx","/api/records","/api/whois","/api/dmarc","/api/dkim","/api/cname","/api/reputation")) {
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

    # Serialize duplicate work for this domain + endpoint, but allow other endpoints
    # for the same domain to execute in parallel.
    $sem = Get-DomainSemaphore -domain $domain -scope $path
    $null = $sem.Wait()
    try {
      switch ($path) {
        "/api/base"  {
          if ($metricsEnabled -and ($true -eq $analyticsConsentState)) {
            $null = Get-OrCreate-AnonymousSessionId -Context $ctx
            Update-AnonymousMetrics -Domain $domain -Started
          }
          Write-Json -Context $ctx -Object (Get-DnsBaseStatus  -Domain $domain)
          if ($metricsEnabled -and ($true -eq $analyticsConsentState)) { Update-AnonymousMetrics -Domain $domain -Completed }
        }
        "/api/mx"    { Write-Json -Context $ctx -Object (Get-DnsMxStatus    -Domain $domain) }
        "/api/records" { Write-Json -Context $ctx -Object (Get-DnsRecordsStatus -Domain $domain) }
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

  # 2b) Microsoft Entra ID auth: handled entirely client-side in the SPA.
  # The browser uses MSAL to acquire a Microsoft Graph token and calls
  # Graph /me directly (see verifyMsAccount in 20e-HtmlAzureIntegration.ps1).
  # The previous /api/auth/verify route forwarded user bearer tokens to
  # Microsoft Graph from the server, which expanded the trust boundary
  # without adding security. It was removed so the server never handles
  # raw Entra access tokens.
  #
  # The /api/auth/event route below is the consent-gated, header-only
  # successor: after the SPA finishes its own Graph verification it POSTs
  # a single notification with two non-PII headers so we can keep counting
  # anonymous sign-in volume and unique Microsoft-employee bucket counts:
  #
  #   X-ACS-Auth-Account-Key  - SHA-256 hex of (tenantId + ':' + oid),
  #                             computed in the browser via SubtleCrypto.
  #                             Optional; only sent when both claims are
  #                             present. Server HMAC-rehashes it with the
  #                             per-install MetricsHashKey before storing.
  #   X-ACS-Auth-Is-Microsoft - '1' if the SPA classified the user as a
  #                             Microsoft employee (UPN matches
  #                             microsoft.com/microsoftsupport.com),
  #                             otherwise '0'. Worst case a tampered
  #                             value off-by-ones a usage counter, which
  #                             is acceptable for an opt-in analytics
  #                             signal.
  #
  # The route requires analytics consent and applies the standard rate
  # limiter so a noisy client cannot pin a worker.
  if ($path -eq '/api/auth/event') {
    if (-not $metricsEnabled) {
      Write-Json -Context $ctx -Object @{ ok = $true; recorded = $false; reason = 'metrics-disabled' }
      return
    }
    if ($true -ne $analyticsConsentState) {
      # Honor the user's consent choice: do nothing, but acknowledge with 200
      # so the SPA does not retry. Mirrors the /api/consent shape.
      Write-Json -Context $ctx -Object @{ ok = $true; recorded = $false; reason = 'analytics-consent-required' }
      return
    }

    $rate = Test-RateLimit -Context $ctx -Multiplier 4
    if (-not $rate.allowed) {
      try {
        if ($ctx.Response -is [System.Net.HttpListenerResponse] -and $rate.retryAfterSec) {
          $ctx.Response.Headers['Retry-After'] = [string]$rate.retryAfterSec
        }
      } catch { }
      Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $rate.retryAfterSec } -StatusCode 429
      return
    }

    # Read the two opt-in headers via Get-RequestHeaderValue, which already
    # handles both the WebHeaderCollection (HttpListener) and hashtable
    # (TcpListener shim) header shapes.
    $accountKey = Get-RequestHeaderValue -Context $ctx -Name 'X-ACS-Auth-Account-Key'
    $isMsRaw    = Get-RequestHeaderValue -Context $ctx -Name 'X-ACS-Auth-Is-Microsoft'

    # Defensive validation: the account key must look like a SHA-256 hex
    # digest (64 chars, [0-9a-f]). Anything else gets ignored so we never
    # store junk in the unique-employee hash set.
    $accountKeyValid = $false
    if (-not [string]::IsNullOrWhiteSpace($accountKey)) {
      $accountKeyTrimmed = $accountKey.Trim().ToLowerInvariant()
      if ($accountKeyTrimmed -match '^[0-9a-f]{64}$') {
        $accountKey = $accountKeyTrimmed
        $accountKeyValid = $true
      } else {
        $accountKey = $null
      }
    } else {
      $accountKey = $null
    }

    $isMsEmployee = $false
    if (-not [string]::IsNullOrWhiteSpace($isMsRaw)) {
      $isMsTrim = $isMsRaw.Trim().ToLowerInvariant()
      if ($isMsTrim -in @('1', 'true', 'yes', 'on')) { $isMsEmployee = $true }
    }

    try {
      Update-AnonymousAuthMetrics -AccountKey $accountKey -IsMicrosoftEmployee $isMsEmployee
    } catch { $null = $_ }

    Write-Json -Context $ctx -Object @{
      ok = $true
      recorded = $true
      accountKeyAccepted = $accountKeyValid
      isMicrosoftEmployee = $isMsEmployee
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

    # Serialize duplicate work for this domain + endpoint, but allow other endpoints
    # for the same domain to execute in parallel.
    $sem = Get-DomainSemaphore -domain $domain -scope $path
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
  # SECURITY: Do NOT echo $_.Exception.Message back to the client. PowerShell
  # exception messages frequently include file paths, stack hints, env var
  # values, or third-party library internals (e.g. "The remote name could
  # not be resolved: 'rdap.nic.example' (proxy=10.1.2.3)"). Returning a
  # generic error keeps the failure observable for the SPA without leaking
  # those details to anonymous callers.
  #
  # The original message is still emitted to the server console via
  # Write-Information so operators can correlate the request log line with
  # the underlying exception when triaging.
  try {
    $errMsg = $null
    try { $errMsg = [string]$_.Exception.Message } catch { $errMsg = '<unavailable>' }
    Write-Information -InformationAction Continue -MessageData "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] handler error for path '$path': $errMsg"
  } catch { }
  try { Write-Json -Context $ctx -Object @{ error = 'Internal server error.' } -StatusCode 500 } catch {}
  try { if ($ctx -and $ctx.Response) { $ctx.Response.Close() } } catch {}
}
'@
