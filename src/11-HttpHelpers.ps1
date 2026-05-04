# ===== HTTP Response Helpers =====
function Get-SecurityHeaderMap {
  param(
    $Context,
    [string]$Nonce
  )
  # Compute the security/CORS header map for a given request context. Returned
  # as a hashtable so both the HttpListener path (Set-SecurityHeaders) and the
  # TcpListener fallback (New-TcpContext SendBody) can write the same set of
  # headers. This guarantees the fallback server mode is not silently weaker
  # than the primary one.
  $headers = [ordered]@{}

  $origin = $null
  try { $origin = [string]$Context.Request.Headers['Origin'] } catch { $origin = $null }
  if (-not [string]::IsNullOrWhiteSpace($origin)) {
    $allowOrigin = $false
    $allowList = [string]$env:ACS_ALLOWED_ORIGINS
    if (-not [string]::IsNullOrWhiteSpace($allowList)) {
      foreach ($entry in ($allowList -split '[,;\r\n]')) {
        $e = ([string]$entry).Trim().TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($e)) { continue }
        if ([string]::Equals($origin.TrimEnd('/'), $e, [System.StringComparison]::OrdinalIgnoreCase)) {
          $allowOrigin = $true
          break
        }
        try {
          $oUri = [uri]$origin
          if ([string]::Equals($oUri.Host, $e, [System.StringComparison]::OrdinalIgnoreCase)) {
            $allowOrigin = $true
            break
          }
        } catch { }
      }
    }
    else {
      $requestHost = $null
      try { $requestHost = $Context.Request.Url.GetLeftPart([System.UriPartial]::Authority) } catch { $requestHost = $null }
      if ($origin -eq $requestHost) {
        try {
          $oHost = ([uri]$origin).Host
          if ($oHost -eq '127.0.0.1' -or $oHost -eq '::1' -or $oHost -eq '[::1]' -or
              [string]::Equals($oHost, 'localhost', [System.StringComparison]::OrdinalIgnoreCase)) {
            $allowOrigin = $true
          }
        } catch { $allowOrigin = $false }
      }
    }

    if ($allowOrigin) {
      $headers['Access-Control-Allow-Origin']  = $origin
      $headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
      $headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Api-Key, X-ACS-API-Key'
      $headers['Access-Control-Max-Age']       = '3600'
      $headers['Vary']                         = 'Origin'
    }
  }

  $headers['X-Content-Type-Options'] = 'nosniff'
  $headers['X-Frame-Options']        = 'DENY'
  $headers['Referrer-Policy']        = 'no-referrer'

  $nonceToken = if ([string]::IsNullOrWhiteSpace($Nonce)) { $null } else { "'nonce-$Nonce'" }
  $scriptSrcParts = @("'self'", $nonceToken, 'https://cdn.jsdelivr.net', 'https://alcdn.msauth.net') | Where-Object { $_ }
  $styleSrcParts  = @("'self'", $nonceToken) | Where-Object { $_ }
  $scriptSrc = 'script-src ' + ($scriptSrcParts -join ' ')
  $styleSrc  = 'style-src '  + ($styleSrcParts  -join ' ')
  $headers['Content-Security-Policy'] = "default-src 'self'; $scriptSrc; script-src-attr 'unsafe-inline'; $styleSrc; style-src-attr 'unsafe-inline'; img-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com https://management.azure.com https://api.loganalytics.io; frame-ancestors 'none'"

  return $headers
}

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
    $headers = Get-SecurityHeaderMap -Context $Context -Nonce $Nonce
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      foreach ($k in $headers.Keys) {
        try { $Context.Response.Headers[$k] = [string]$headers[$k] } catch { }
      }
    }
    else {
      # TcpListener fallback: stash the headers on the response object so
      # SendBody emits them alongside Content-Type / Content-Length. Without
      # this branch the fallback server mode would serve every response
      # without CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
      # or any CORS gating, which is materially weaker than the primary
      # HttpListener path.
      try {
        if ($null -ne $Context.Response.PSObject.Properties['_extraHeaders']) {
          $existing = $Context.Response._extraHeaders
          if ($null -eq $existing) {
            $Context.Response._extraHeaders = $headers
          } else {
            foreach ($k in $headers.Keys) { $existing[$k] = $headers[$k] }
          }
        }
      } catch { }
    }
  } catch { }
}

function Set-NoCacheHeaders {
  param($Context)
  # Apply no-cache headers in a way that works for both the HttpListener path
  # and the TcpListener fallback. Centralizing this avoids the previous bug
  # where the fallback path silently dropped Cache-Control/Pragma/Expires.
  $noCache = [ordered]@{
    'Cache-Control' = 'no-store, no-cache, must-revalidate, max-age=0'
    'Pragma'        = 'no-cache'
    'Expires'       = '0'
  }
  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      foreach ($k in $noCache.Keys) {
        try { $Context.Response.Headers[$k] = [string]$noCache[$k] } catch { }
      }
    } else {
      if ($null -ne $Context.Response.PSObject.Properties['_extraHeaders']) {
        $existing = $Context.Response._extraHeaders
        if ($null -eq $existing) {
          $Context.Response._extraHeaders = $noCache
        } else {
          foreach ($k in $noCache.Keys) { $existing[$k] = $noCache[$k] }
        }
      }
    }
  } catch { }
}

# Centralized outbound HTTP helper for user-driven lookups (DoH, RDAP, WHOIS,
# RBL, etc.). Goals:
# - Enforce HTTPS-only (refuses cleartext) so a typo in a custom endpoint
#   cannot leak a domain query in plaintext.
# - Hard-cap timeout per request and the number of redirects we will follow.
# - Centralize the outbound surface so future hardening (proxy, per-request
#   call counter, IP allow-list) only has to land in one place.
# Returns the deserialized body when -ReturnRaw is omitted; throws on failure
# so callers' existing try/catch flow keeps working.
function Invoke-OutboundHttp {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Uri,

    [string]$Method = 'GET',

    [hashtable]$Headers,

    [int]$TimeoutSec = 15,

    [int]$MaximumRedirection = 3,

    [switch]$ReturnRaw
  )

  if ([string]::IsNullOrWhiteSpace($Uri)) {
    throw "Invoke-OutboundHttp: Uri is required."
  }

  $parsed = $null
  try { $parsed = [uri]$Uri } catch { throw "Invoke-OutboundHttp: malformed Uri '$Uri'." }
  if (-not $parsed.IsAbsoluteUri) {
    throw "Invoke-OutboundHttp: Uri must be absolute ('$Uri')."
  }
  if ($parsed.Scheme -ne 'https') {
    throw "Invoke-OutboundHttp: only https is allowed (got '$($parsed.Scheme)' for '$Uri')."
  }

  if ($TimeoutSec -le 0) { $TimeoutSec = 15 }
  if ($MaximumRedirection -lt 0) { $MaximumRedirection = 0 }

  $params = @{
    Uri                 = $Uri
    Method              = $Method
    TimeoutSec          = $TimeoutSec
    MaximumRedirection  = $MaximumRedirection
    ErrorAction         = 'Stop'
  }
  if ($Headers -and $Headers.Count -gt 0) { $params.Headers = $Headers }

  if ($ReturnRaw) {
    $params.UseBasicParsing = $true
    return Invoke-WebRequest @params
  }
  return Invoke-RestMethod @params
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
  # Disable browser/proxy caching for all JSON API responses so users always
  # see fresh DNS/WHOIS data without needing a forced refresh (CTRL+SHIFT+R).
  # Routed through Set-NoCacheHeaders so the TcpListener fallback also emits
  # these headers (the previous inline writes only worked for HttpListener).
  Set-NoCacheHeaders -Context $Context

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
    Set-NoCacheHeaders -Context $Context

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
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
