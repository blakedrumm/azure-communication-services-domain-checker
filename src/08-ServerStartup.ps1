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
