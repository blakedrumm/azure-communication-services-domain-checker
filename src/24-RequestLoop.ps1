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
    $resp = [pscustomobject]@{
      StatusCode = 200
      StatusDescription = 'OK'
      ContentType = 'text/plain; charset=utf-8'
      ContentLength64 = [int64]0
      _client = $Client
      _stream = $networkStream
      _sent = $false
    }

    $resp | Add-Member -MemberType ScriptMethod -Name SendBody -Value {
      param([byte[]]$Bytes)
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }

      $statusText = if ([string]::IsNullOrWhiteSpace($this.StatusDescription)) { 'OK' } else { $this.StatusDescription }
      $headers = "HTTP/1.1 {0} {1}\r\nContent-Type: {2}\r\nContent-Length: {3}\r\nConnection: close\r\n\r\n" -f $this.StatusCode, $statusText, $this.ContentType, $Bytes.Length
      $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)

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

    # Extremely small HTTP/1.1 request reader (GET only).
    # We only need the request line + headers to route GET requests and read query strings.
    $stream = $Client.GetStream()
    $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 8192, $true)
    $line1 = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line1)) { return $null }

    $parts = $line1 -split '\s+'
    if ($parts.Count -lt 2) { return $null }

    $method = $parts[0].Trim().ToUpperInvariant()
    $target = $parts[1].Trim()

    $headers = @{}
    while ($true) {
      $line = $reader.ReadLine()
      if ($null -eq $line) { break }
      if ($line -eq '') { break }
      $idx = $line.IndexOf(':')
      if ($idx -le 0) { continue }
      $hName = $line.Substring(0, $idx).Trim().ToLowerInvariant()
      $hValue = $line.Substring($idx + 1).Trim()
      $headers[$hName] = $hValue
    }

    return [pscustomobject]@{ Method = $method; Target = $target; Headers = $headers }
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
