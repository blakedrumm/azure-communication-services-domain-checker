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
    # `_extraHeaders` is populated by Set-SecurityHeaders / Set-NoCacheHeaders so
    # the fallback path emits the same CSP, X-Frame-Options, X-Content-Type-Options,
    # Referrer-Policy, CORS, and cache-control headers as the HttpListener path.
    # Without this slot the fallback server mode would silently strip every
    # browser-side defense.
    $resp = [pscustomobject]@{
      StatusCode = 200
      StatusDescription = 'OK'
      ContentType = 'text/plain; charset=utf-8'
      ContentLength64 = [int64]0
      _client = $Client
      _stream = $networkStream
      _sent = $false
      _extraHeaders = [ordered]@{}
    }

    $resp | Add-Member -MemberType ScriptMethod -Name SendBody -Value {
      param([byte[]]$Bytes)
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }

      $statusText = if ([string]::IsNullOrWhiteSpace($this.StatusDescription)) { 'OK' } else { $this.StatusDescription }
      # SECURITY/CORRECTNESS: HTTP/1.1 requires CRLF (0x0D 0x0A) between headers
      # and after the final blank line. The previous implementation used the
      # double-quoted PowerShell literal "\r\n" which is the four characters
      # `\`, `r`, `\`, `n` and produces a single-line malformed response that
      # browsers reject. Build the header block with explicit `r`n sequences.
      $crlf = "`r`n"
      $headerBuilder = New-Object System.Text.StringBuilder
      [void]$headerBuilder.Append("HTTP/1.1 $($this.StatusCode) $statusText$crlf")
      [void]$headerBuilder.Append("Content-Type: $($this.ContentType)$crlf")
      [void]$headerBuilder.Append("Content-Length: $($Bytes.Length)$crlf")
      [void]$headerBuilder.Append("Connection: close$crlf")
      # Emit any security / cache-control headers the request handler attached
      # via Set-SecurityHeaders / Set-NoCacheHeaders. We strip CR/LF from values
      # defensively so a buggy caller cannot inject extra headers (HTTP response
      # splitting). Skip duplicates of the headers we already wrote above.
      $reserved = @('content-type','content-length','connection')
      if ($null -ne $this._extraHeaders) {
        foreach ($k in @($this._extraHeaders.Keys)) {
          $kn = ([string]$k).Trim()
          if ([string]::IsNullOrWhiteSpace($kn)) { continue }
          if ($reserved -contains $kn.ToLowerInvariant()) { continue }
          $v = [string]$this._extraHeaders[$k]
          if ($null -eq $v) { continue }
          $v = $v -replace "[`r`n]", ' '
          [void]$headerBuilder.Append("$kn`: $v$crlf")
        }
      }
      [void]$headerBuilder.Append($crlf)
      $headerBytes = [Text.Encoding]::ASCII.GetBytes($headerBuilder.ToString())

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

    # Extremely small HTTP/1.1 request reader (GET/POST).
    # We only need the request line + headers to route requests and read query strings.
    # SECURITY: cap the request line length, individual header line length, and
    # the total number of headers so a peer that opens a TCP connection and
    # streams an unbounded line cannot tie up a worker indefinitely or exhaust
    # memory. These limits are deliberately generous compared to real browsers
    # (which send sub-kilobyte request lines) but small enough to fail fast on
    # abuse.
    $maxRequestLineBytes = 8192   # 8 KB request line cap
    $maxHeaderLineBytes  = 8192   # 8 KB per header line
    $maxHeaderCount      = 100    # max distinct headers
    # Cap the POST request body we are willing to read/discard. /api/consent is
    # the only POST endpoint today and its payload is a tiny JSON document; a
    # generous cap is plenty and prevents an attacker from streaming unbounded
    # bytes into the worker. Honor the operator's configured cap from
    # ACS_MAX_REQUEST_BODY_BYTES (set in 00-Header.ps1) and clamp to a hard
    # ceiling so the fallback never allocates an unreasonable buffer even if
    # the env var is mis-configured.
    $maxRequestBodyBytes = 65536  # 64 KB request body cap (default)
    try {
      if ($env:ACS_MAX_REQUEST_BODY_BYTES -and $env:ACS_MAX_REQUEST_BODY_BYTES -match '^\d+$') {
        $envCap = [int]$env:ACS_MAX_REQUEST_BODY_BYTES
        if ($envCap -gt 0) {
          # Hard ceiling of 1 MB so the fallback can never allocate gigabyte buffers.
          $maxRequestBodyBytes = [Math]::Min($envCap, 1048576)
        }
      }
    } catch { }

    # SECURITY: Bound how long we are willing to wait for the peer to send
    # bytes. Without these, a slow-loris client could dribble data within
    # the per-line caps and tie up a worker indefinitely. 15 seconds is
    # comfortably above any normal browser/curl latency.
    try { $Client.ReceiveTimeout = 15000 } catch { }
    try { $Client.SendTimeout    = 15000 } catch { }

    $stream = $Client.GetStream()
    try { $stream.ReadTimeout  = 15000 } catch { }
    try { $stream.WriteTimeout = 15000 } catch { }
    # SECURITY/CORRECTNESS: use UTF-8 for the full reader. UTF-8 is ASCII-
    # compatible so the request line + header parsing (which only deals with
    # ASCII per HTTP/1.1) is unaffected, but POST bodies (e.g. JSON for
    # /api/consent if it ever consumes a request body in this fallback path)
    # are decoded correctly instead of being silently mangled by an ASCII
    # decoder when they contain bytes >= 0x80.
    $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $false, 8192, $true)

    try {
      $line1 = $reader.ReadLine()
    } catch {
      # Read timeout / IO error; treat as a malformed request so the caller closes the socket.
      return $null
    }
    if ([string]::IsNullOrWhiteSpace($line1)) { return $null }
    if ($line1.Length -gt $maxRequestLineBytes) { return $null }

    $parts = $line1 -split '\s+'
    if ($parts.Count -lt 2) { return $null }

    $method = $parts[0].Trim().ToUpperInvariant()
    $target = $parts[1].Trim()

    $headers = @{}
    $headerCount = 0
    while ($true) {
      try {
        $line = $reader.ReadLine()
      } catch {
        # Read timeout / IO error mid-headers; treat as malformed.
        return $null
      }
      if ($null -eq $line) { break }
      if ($line -eq '') { break }
      if ($line.Length -gt $maxHeaderLineBytes) { return $null }
      $headerCount++
      if ($headerCount -gt $maxHeaderCount) { return $null }
      $idx = $line.IndexOf(':')
      if ($idx -le 0) { continue }
      $hName = $line.Substring(0, $idx).Trim().ToLowerInvariant()
      $hValue = $line.Substring($idx + 1).Trim()
      $headers[$hName] = $hValue
    }

    # Drain the POST body (if any) so the StreamReader buffer and the
    # underlying network stream are consumed before we hand control to the
    # request handler. Today no handler reads the body (the consent route is
    # driven entirely by the X-ACS-Cookie-Consent header), so we simply
    # discard up to $maxRequestBodyBytes. If a handler ever needs the body in
    # this fallback mode, the captured value is exposed on the returned
    # object as `Body`.
    $body = $null
    if ($method -eq 'POST') {
      $contentLength = 0
      if ($headers.ContainsKey('content-length')) {
        $clRaw = [string]$headers['content-length']
        [void][int]::TryParse($clRaw, [ref]$contentLength)
      }
      if ($contentLength -gt 0) {
        $toRead = [Math]::Min($contentLength, $maxRequestBodyBytes)
        try {
          $buffer = New-Object char[] $toRead
          $totalRead = 0
          while ($totalRead -lt $toRead) {
            $chunk = $reader.Read($buffer, $totalRead, ($toRead - $totalRead))
            if ($chunk -le 0) { break }
            $totalRead += $chunk
          }
          if ($totalRead -gt 0) {
            $body = New-Object string ($buffer, 0, $totalRead)
          }
        } catch { $body = $null }
      }
    }

    return [pscustomobject]@{ Method = $method; Target = $target; Headers = $headers; Body = $body }
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
          # SECURITY: even though /api/metrics is cheap, it can take the metrics
          # file mutex and read+JSON-parse the persistence file, which is a
          # cheap-but-real DoS amplifier under sustained polling. Apply a
          # generous rate limit (10x the per-endpoint limit) so the SPA's
          # auto-refresh keeps working but a tight loop gets throttled.
          $metricsRate = Test-RateLimit -Context $ctx -Multiplier 10
          if (-not $metricsRate.allowed) {
            try {
              if ($ctx.Response -is [System.Net.HttpListenerResponse] -and $metricsRate.retryAfterSec) {
                $ctx.Response.Headers['Retry-After'] = [string]$metricsRate.retryAfterSec
              }
            } catch { }
            Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $metricsRate.retryAfterSec } -StatusCode 429
            continue
          }
          # Respond inline (fast and avoids ThreadPool runspace issues).
          Handle-MetricsRequest -Context $ctx -MetricsEnabled $anonMetricsEnabled
          continue
        }

        # Run the handler in the RunspacePool so multiple requests can be processed concurrently.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath).AddArgument($script:TosPageHtml).AddArgument($script:PrivacyPageHtml).AddArgument($script:AssetsRoot)

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
          # See HttpListener fast-path above for the rationale on rate-limiting
          # the metrics endpoint with a 10x multiplier.
          $metricsRate = Test-RateLimit -Context $ctx -Multiplier 10
          if (-not $metricsRate.allowed) {
            Write-Json -Context $ctx -Object @{ error = 'Rate limit exceeded.'; retryAfterSeconds = $metricsRate.retryAfterSec } -StatusCode 429
            continue
          }
          Handle-MetricsRequest -Context $ctx -MetricsEnabled $anonMetricsEnabled
          continue
        }

        # Run the same handler script used by HttpListener.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks).AddArgument($msalLocalPath).AddArgument($script:TosPageHtml).AddArgument($script:PrivacyPageHtml).AddArgument($script:AssetsRoot)

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
