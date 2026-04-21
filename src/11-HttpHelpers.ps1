# ===== HTTP Response Helpers =====
function Set-SecurityHeaders {
  param(
    $Context,
    [string]$Nonce
  )
  # Apply security headers to all responses:
  # - CORS: restrict to same-origin only (no cross-origin API access)
  # - CSP: restrict script sources to self and known CDNs
  # - X-Content-Type-Options: prevent MIME-sniffing
  # - X-Frame-Options: prevent clickjacking
  # - Referrer-Policy: minimize referrer leakage
  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $origin = $null
      try { $origin = [string]$Context.Request.Headers['Origin'] } catch { $origin = $null }
      if (-not [string]::IsNullOrWhiteSpace($origin)) {
        # Only reflect the origin if it matches the listener's own origin
        $requestHost = $null
        try { $requestHost = $Context.Request.Url.GetLeftPart([System.UriPartial]::Authority) } catch { $requestHost = $null }
        if ($origin -eq $requestHost) {
          $Context.Response.Headers['Access-Control-Allow-Origin'] = $origin
          $Context.Response.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
          $Context.Response.Headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Api-Key, X-ACS-API-Key'
          $Context.Response.Headers['Access-Control-Max-Age'] = '3600'
          $Context.Response.Headers['Vary'] = 'Origin'
        }
        # If origin does not match, no CORS headers are set (browser blocks the response)
      }
      $Context.Response.Headers['X-Content-Type-Options'] = 'nosniff'
      $Context.Response.Headers['X-Frame-Options'] = 'DENY'
      $Context.Response.Headers['Referrer-Policy'] = 'no-referrer'

      $nonceToken = if ([string]::IsNullOrWhiteSpace($Nonce)) { $null } else { "'nonce-$Nonce'" }
      $scriptSrcParts = @("'self'", $nonceToken, 'https://cdn.jsdelivr.net', 'https://alcdn.msauth.net') | Where-Object { $_ }
      $styleSrcParts = @("'self'", $nonceToken) | Where-Object { $_ }
      $scriptSrc = 'script-src ' + ($scriptSrcParts -join ' ')
      $styleSrc = 'style-src ' + ($styleSrcParts -join ' ')
      $Context.Response.Headers['Content-Security-Policy'] = "default-src 'self'; $scriptSrc; script-src-attr 'unsafe-inline'; $styleSrc; style-src-attr 'unsafe-inline'; img-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com https://management.azure.com https://api.loganalytics.io; frame-ancestors 'none'"
    }
  } catch { }
}

# Serialize an object to JSON and write it as the HTTP response body.
# Works with both HttpListener (native) and TcpListener (shim) server modes.
function Write-Json {
    param(
    $Context,
    [object]$Object,
    [int]$StatusCode = 200
    )

    # Serialize to JSON and write to the current response type.
    # The script can run in 2 server modes:
    # - HttpListener: native `HttpListenerContext`/`HttpListenerResponse` objects
    # - TcpListener : a minimal compatibility layer that mimics a subset of those APIs
    # Depth 16 is needed because nested SPF expansion analysis (Get-SpfNestedAnalysis)
    # can produce trees deeper than the default ConvertTo-Json depth of 2 and the
    # earlier conservative limit of 8 — anything deeper was silently truncated to null.
    $json  = $Object | ConvertTo-Json -Depth 16
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)

  Set-SecurityHeaders -Context $Context

  if ($Context.Response -is [System.Net.HttpListenerResponse]) {
    $Context.Response.ContentType = "application/json; charset=utf-8"
    try { $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8 } catch { }
    $Context.Response.StatusCode  = $StatusCode
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
    return
  }

  # TcpListener fallback response
  $Context.Response.ContentType = "application/json; charset=utf-8"
  $Context.Response.StatusCode  = $StatusCode
  $Context.Response.ContentLength64 = $bytes.Length
  $Context.Response.SendBody($bytes)
}

# Serve a static file from disk as the HTTP response (used for favicon, etc.).
function Write-FileResponse {
    param(
        $Context,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$ContentType = 'application/octet-stream'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($Context.Response -is [System.Net.HttpListenerResponse]) {
            $Context.Response.StatusCode = 404
            $Context.Response.StatusDescription = 'Not Found'
            $Context.Response.Close()
            return
        }
        $Context.Response.StatusCode = 404
        $Context.Response.StatusDescription = 'Not Found'
        $Context.Response.SendBody([byte[]]@())
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    Set-SecurityHeaders -Context $Context

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
        $Context.Response.ContentType = $ContentType
        try {
          if ($ContentType -match '(?i)charset\s*=\s*utf-8') {
            $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8
          }
        } catch { }
        $Context.Response.StatusCode  = 200
        $Context.Response.ContentLength64 = $bytes.Length
        $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Context.Response.OutputStream.Close()
        return
    }

    $Context.Response.ContentType = $ContentType
    $Context.Response.StatusCode  = 200
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.SendBody($bytes)
}

# Serve the embedded single-page HTML UI.
# Replaces the CSP nonce placeholder in the HTML template before sending.
function Write-Html {
    param(
        $Context,
        [string]$Html,
        [string]$Nonce
    )

    # Serve the embedded SPA HTML. (All dynamic data is fetched from JSON endpoints.)
    if ([string]::IsNullOrWhiteSpace($Nonce)) {
      $Html = $Html.Replace('nonce="__CSP_NONCE__"', '')
    } else {
      $Html = $Html.Replace('__CSP_NONCE__', $Nonce)
    }

    $bytes = [Text.Encoding]::UTF8.GetBytes($Html)

    Set-SecurityHeaders -Context $Context -Nonce $Nonce

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      try {
        $Context.Response.Headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        $Context.Response.Headers['Pragma'] = 'no-cache'
        $Context.Response.Headers['Expires'] = '0'
      } catch { }
      $Context.Response.ContentType = "text/html; charset=utf-8"
      try { $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8 } catch { }
      $Context.Response.StatusCode  = 200
      $Context.Response.ContentLength64 = $bytes.Length
      $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
      $Context.Response.OutputStream.Close()
      return
    }

    # TcpListener fallback response
    $Context.Response.ContentType = "text/html; charset=utf-8"
    $Context.Response.StatusCode  = 200
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.SendBody($bytes)
}

# ------------------- DNS RESOLUTION LAYER -------------------
# Two DNS backends are supported:
#   1. Resolve-DnsName (Windows DnsClient module) - fast, uses the OS resolver.
#   2. DNS-over-HTTPS (DoH) via Cloudflare (or custom endpoint) - cross-platform fallback.
# The "Auto" mode tries Resolve-DnsName first and falls back to DoH.

# Perform a DNS query using DNS-over-HTTPS (DoH).
# Sends a JSON-format query (RFC 8484) to the configured DoH endpoint (default: Cloudflare).
# Returns objects shaped like Resolve-DnsName output for downstream compatibility.
