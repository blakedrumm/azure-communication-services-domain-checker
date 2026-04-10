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

      if (-not $assetFullPath.StartsWith($rootFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
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
  if ($path -eq '/api/consent') {
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
  # Last-resort error handler: attempt to return a JSON error payload.
  try { Write-Json -Context $ctx -Object @{ error = $_.Exception.Message } -StatusCode 500 } catch {}
  try { if ($ctx -and $ctx.Response) { $ctx.Response.Close() } } catch {}
}
'@
