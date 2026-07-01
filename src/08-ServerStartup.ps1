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
$script:ShutdownRequested = $false
$script:AcsServerHttpListener = $null
$script:AcsServerTcpListener = $null
$script:ConsoleCancelHandler = $null
$script:PreviousTreatControlCAsInput = $null

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
      Write-AcsLogException -Level 'Error' -Component 'ServerStartup' -Operation 'http-listener-start' -EventId 'HTTP-LISTENER-START-FAILED' -ErrorCode 'ACS-HTTP-LISTENER-START' -Exception $_ -Fields @{ listenerMode = 'HttpListener'; port = $Port }
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
    # In some integrated terminals, a normal Ctrl+C interrupt can terminate the
    # hosting pwsh process (exit code 2) instead of unwinding back to the prompt.
    # While the server is running, treat Ctrl+C as regular console input and let
    # the request loop poll for char 0x03. The shutdown file restores the prior
    # console setting so Ctrl+C behaves normally after the server stops.
    try {
      $script:PreviousTreatControlCAsInput = [Console]::TreatControlCAsInput
      [Console]::TreatControlCAsInput = $true
    } catch {
      $script:PreviousTreatControlCAsInput = $null
      Write-AcsLogException -Level 'Warning' -Component 'ServerStartup' -Operation 'console-ctrlc-mode' -EventId 'CONSOLE-CTRLC-MODE-WARN' -ErrorCode 'ACS-CONSOLE-CTRLC' -Exception $_
    }

    # Ctrl+C must stop the underlying listener so the blocking GetContext() /
    # AcceptTcpClient() call in the request loop wakes up and can enter the
    # normal finally{} shutdown path. We cancel the default process abort so
    # metrics/in-flight cleanup still runs and the terminal can be reused.
    $script:AcsServerHttpListener = $listener
    $script:AcsServerTcpListener = $tcpListener
    try {
      if ($null -eq $script:ConsoleCancelHandler) {
        $script:ConsoleCancelHandler = [System.ConsoleCancelEventHandler]{
          param($sender, $eventArgs)
          $eventArgs.Cancel = $true
          $script:ShutdownRequested = $true
          try { if ($script:AcsServerHttpListener -and $script:AcsServerHttpListener.IsListening) { $script:AcsServerHttpListener.Stop() } } catch { }
          try { if ($script:AcsServerTcpListener) { $script:AcsServerTcpListener.Stop() } } catch { }
        }
        [Console]::add_CancelKeyPress($script:ConsoleCancelHandler)
      }
    } catch {
      Write-AcsLogException -Level 'Warning' -Component 'ServerStartup' -Operation 'register-shutdown-handler' -EventId 'SERVER-SHUTDOWN-HANDLER-WARN' -ErrorCode 'ACS-SERVER-SHUTDOWN-HANDLER' -Exception $_
    }

    Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'server-start' -EventId 'SERVER-STARTED' -Message 'Server started.' -Fields @{ listenerMode = $serverMode; port = $Port }
    Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'shutdown-instructions' -EventId 'SERVER-SHUTDOWN-INSTRUCTIONS' -Message 'Press Ctrl+C or Q to stop the server.'

    if ($env:ACS_ENABLE_ANON_METRICS -eq '1') {
      Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'metrics-config' -EventId 'METRICS-ENABLED' -Message 'Anonymous metrics enabled.'
    } else {
      Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'metrics-config' -EventId 'METRICS-DISABLED' -Message 'Anonymous metrics disabled.'
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ACS_API_KEY)) {
      Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'api-auth-config' -EventId 'API-AUTH-ENABLED' -Message 'API key authentication enabled.'
    } else {
      Write-AcsLogEvent -Level 'Warning' -Component 'ServerStartup' -Operation 'api-auth-config' -EventId 'API-AUTH-DISABLED' -Message 'API key authentication disabled.'
    }

    if ($rateLimitPerMinute -gt 0) {
      Write-AcsLogEvent -Level 'Information' -Component 'ServerStartup' -Operation 'rate-limit-config' -EventId 'RATE-LIMIT-ENABLED' -Message 'Rate limiting enabled.' -Fields @{ limit = $rateLimitPerMinute }
    } else {
      Write-AcsLogEvent -Level 'Warning' -Component 'ServerStartup' -Operation 'rate-limit-config' -EventId 'RATE-LIMIT-DISABLED' -Message 'Rate limiting disabled.'
    }
  } else {
    if (-not [string]::IsNullOrWhiteSpace($startupErrorMessage)) {
      Write-AcsLogEvent -Level 'Error' -Component 'ServerStartup' -Operation 'server-start' -EventId 'SERVER-START-FAILED' -Message 'Server failed to start.' -ErrorCode 'ACS-SERVER-START' -Fields @{ port = $Port }
    } else {
      Write-AcsLogEvent -Level 'Error' -Component 'ServerStartup' -Operation 'server-start' -EventId 'SERVER-START-FAILED' -Message 'Server failed to start.' -ErrorCode 'ACS-SERVER-START' -Fields @{ port = $Port }
    }
    return
  }
}
