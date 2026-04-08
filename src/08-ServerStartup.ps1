# ===== Web Server Startup =====
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
