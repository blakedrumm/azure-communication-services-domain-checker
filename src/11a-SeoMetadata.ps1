# ===== SEO / AI Discovery Metadata =====
#
# The SPA HTML is assembled once at startup, so anything that depends on WHERE
# the instance is actually deployed (public scheme + hostname) cannot be baked
# in at build time. The HTML template therefore carries an __ACS_SITE_URL__
# token that Write-Html resolves per request from Get-AcsPublicBaseUrl.
#
# This file also serves the machine-readable discovery documents:
#   /robots.txt   - crawler policy (explicitly welcomes AI agents)
#   /sitemap.xml  - page list + hreflang alternates for all 10 locales
#   /llms.txt     - llmstxt.org summary so an LLM can learn the API in one fetch
#   /openapi.json - OpenAPI 3.1 contract so an agent can call the API correctly

# Language codes the SPA ships translations for. Drives the hreflang alternates
# and the sitemap so ?lang= variants are understood as translations of one page
# instead of duplicate content.
function Get-AcsSeoLanguages {
  return @('en', 'es', 'fr', 'de', 'pt-BR', 'ar', 'zh-CN', 'hi-IN', 'ja-JP', 'ru-RU')
}

# Operators running a private/internal instance set ACS_SEO_NOINDEX=1 to stay out
# of search indexes entirely (robots.txt Disallow + noindex on every page).
function Test-AcsSeoIndexingAllowed {
  $raw = ([string]$env:ACS_SEO_NOINDEX).Trim().ToLowerInvariant()
  return -not ($raw -in @('1', 'true', 'yes', 'on'))
}

# Operators who do not want their instance used as an AI/LLM data source set
# ACS_AI_DISALLOW=1. Default is to welcome AI agents: this tool answers factual
# DNS questions, which is exactly the kind of lookup an assistant benefits from.
function Test-AcsAiCrawlingAllowed {
  $raw = ([string]$env:ACS_AI_DISALLOW).Trim().ToLowerInvariant()
  if ($raw -in @('1', 'true', 'yes', 'on')) { return $false }
  return (Test-AcsSeoIndexingAllowed)
}

# Named AI crawlers / assistant fetchers that get an explicit Allow block in
# robots.txt. Several of these (Google-Extended, Applebot-Extended) are
# training-opt-out tokens rather than crawlers, so naming them is the only way
# to signal "yes, this content may be used".
function Get-AcsAiUserAgents {
  return @(
    'GPTBot', 'OAI-SearchBot', 'ChatGPT-User',
    'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'anthropic-ai',
    'Google-Extended', 'Applebot-Extended',
    'PerplexityBot', 'Perplexity-User',
    'meta-externalagent', 'FacebookBot',
    'Amazonbot', 'Bytespider', 'CCBot',
    'MistralAI-User', 'DuckAssistBot', 'YouBot',
    'cohere-ai', 'cohere-training-data-crawler'
  )
}

# Accept only characters that may legally appear in an authority we are willing
# to echo back into a canonical URL. Rejecting anything else stops a spoofed
# Host header from pointing canonical/og:url at an attacker-controlled domain.
function Test-AcsSafeUrlAuthority {
  param([string]$Authority)
  if ([string]::IsNullOrWhiteSpace($Authority)) { return $false }
  if ($Authority.Length -gt 255) { return $false }
  return [bool]($Authority -match '^(?:\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9](?:[A-Za-z0-9\-.]*[A-Za-z0-9])?)(?::[0-9]{1,5})?$')
}

# Absolute origin (no trailing slash) used for canonical/og:url/sitemap entries.
# Returns '' when no trustworthy value exists, in which case callers fall back to
# root-relative URLs (valid for <link rel=canonical>, omitted for og:url).
function Get-AcsPublicBaseUrl {
  param($Context)

  # 1) Explicit operator configuration wins. This is the only form that is
  #    reliable behind a proxy/CDN that rewrites Host, and the only one that
  #    cannot be influenced by the requesting client.
  $configured = ([string]$env:ACS_PUBLIC_BASE_URL).Trim()
  if (-not [string]::IsNullOrWhiteSpace($configured)) {
    try {
      $u = [uri]$configured
      if ($u.IsAbsoluteUri -and ($u.Scheme -eq 'http' -or $u.Scheme -eq 'https')) {
        return $u.GetLeftPart([System.UriPartial]::Path).TrimEnd('/')
      }
    } catch { }
  }

  if ($null -eq $Context) { return '' }

  # 2) Derive from the live request. X-Forwarded-* is honored ONLY when the
  #    immediate TCP peer is in ACS_TRUSTED_PROXIES -- the same trust model
  #    Get-ClientIp and the session cookie's Secure flag already use.
  $scheme = 'http'
  $authority = ''
  try { $scheme = [string]$Context.Request.Url.Scheme } catch { $scheme = 'http' }
  try { $authority = [string]$Context.Request.Url.Authority } catch { $authority = '' }

  try {
    $peerIp = $null
    try { $peerIp = [string]$Context.Request.RemoteEndPoint.Address } catch { $peerIp = $null }
    if (-not [string]::IsNullOrWhiteSpace($peerIp) -and (Test-IsTrustedProxy -PeerIp $peerIp)) {
      $fwdProto = ([string]$Context.Request.Headers['X-Forwarded-Proto']).Trim().ToLowerInvariant()
      if (-not [string]::IsNullOrWhiteSpace($fwdProto)) { $fwdProto = ($fwdProto -split ',')[0].Trim() }
      if ($fwdProto -eq 'https' -or $fwdProto -eq 'http') { $scheme = $fwdProto }

      $fwdHost = ([string]$Context.Request.Headers['X-Forwarded-Host']).Trim()
      if (-not [string]::IsNullOrWhiteSpace($fwdHost)) { $fwdHost = ($fwdHost -split ',')[0].Trim() }
      if (Test-AcsSafeUrlAuthority -Authority $fwdHost) { $authority = $fwdHost }
    }
  } catch { }

  if ($scheme -ne 'http' -and $scheme -ne 'https') { return '' }
  if (-not (Test-AcsSafeUrlAuthority -Authority $authority)) { return '' }
  return ('{0}://{1}' -f $scheme, $authority)
}

# True only when the operator pinned the origin via ACS_PUBLIC_BASE_URL. When it
# is false the origin is derived from the request's Host header, which a client
# controls -- so any document that embeds it must not be stored by a shared
# cache, or one spoofed request could poison /robots.txt or /sitemap.xml for
# everyone behind that cache.
function Test-AcsPublicBaseUrlIsConfigured {
  $configured = ([string]$env:ACS_PUBLIC_BASE_URL).Trim()
  if ([string]::IsNullOrWhiteSpace($configured)) { return $false }
  try {
    $u = [uri]$configured
    return ($u.IsAbsoluteUri -and ($u.Scheme -eq 'http' -or $u.Scheme -eq 'https'))
  } catch { return $false }
}

function ConvertTo-AcsXmlText {
  param([string]$Value)
  if ([string]::IsNullOrEmpty($Value)) { return '' }
  return $Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&apos;')
}

# Brand artwork served from memory so the single-file distribution stays intact.
# 'icon'  -> /favicon.svg  (browser tab, 64x64 viewBox, scales to any size)
# 'share' -> /og-image.svg (1200x630 social/link-preview card)
function Get-AcsBrandSvg {
  param([ValidateSet('icon', 'share')][string]$Variant = 'icon')

  if ($Variant -eq 'icon') {
    return @'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="ACS Email Domain Checker">
  <defs>
    <linearGradient id="acsShield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#54b3ff"/>
      <stop offset="1" stop-color="#0b5cd5"/>
    </linearGradient>
  </defs>
  <path fill="url(#acsShield)" d="M32 3 8 11.5v18.9C8 44.6 17.9 56.9 32 61c14.1-4.1 24-16.4 24-30.6V11.5z"/>
  <path fill="none" stroke="#ffffff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round" d="m19.5 32.5 8.8 8.8L45 24.5"/>
</svg>
'@
  }

  return @'
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="Azure Communication Services Email Domain Checker">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1220"/>
      <stop offset="1" stop-color="#132b52"/>
    </linearGradient>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#54b3ff"/>
      <stop offset="1" stop-color="#0b5cd5"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <g transform="translate(92 175) scale(4.1)">
    <path fill="url(#shield)" d="M32 3 8 11.5v18.9C8 44.6 17.9 56.9 32 61c14.1-4.1 24-16.4 24-30.6V11.5z"/>
    <path fill="none" stroke="#ffffff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round" d="m19.5 32.5 8.8 8.8L45 24.5"/>
  </g>
  <g font-family="Segoe UI, Helvetica Neue, Arial, sans-serif">
    <text x="400" y="242" fill="#9fc6ff" font-size="30" font-weight="600" letter-spacing="3">AZURE COMMUNICATION SERVICES</text>
    <text x="400" y="330" fill="#ffffff" font-size="72" font-weight="700">Email Domain Checker</text>
    <text x="400" y="395" fill="#c9d8f2" font-size="31">SPF &#183; DKIM &#183; DMARC &#183; MX &#183; TXT &#183; CNAME</text>
    <text x="400" y="447" fill="#c9d8f2" font-size="31">Global DNS propagation &#183; Blocklists &#183; WHOIS</text>
  </g>
</svg>
'@
}

function Get-AcsRobotsTxt {
  param([string]$BaseUrl)

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine('# robots.txt - Azure Communication Services Email Domain Checker')

  if (-not (Test-AcsSeoIndexingAllowed)) {
    # Private deployment: keep everything out of every index.
    [void]$sb.AppendLine('# Indexing disabled by operator (ACS_SEO_NOINDEX).')
    [void]$sb.AppendLine('User-agent: *')
    [void]$sb.AppendLine('Disallow: /')
    return $sb.ToString()
  }

  # General crawlers: index the human-facing pages, skip the JSON endpoints
  # (thin, per-domain, and infinite in cardinality). /assets/ is deliberately
  # NOT blocked -- search engines need the CSS/JS/images to render the page.
  [void]$sb.AppendLine('User-agent: *')
  [void]$sb.AppendLine('Allow: /')
  [void]$sb.AppendLine('Disallow: /api/')
  [void]$sb.AppendLine('Disallow: /dns')
  [void]$sb.AppendLine()

  if (Test-AcsAiCrawlingAllowed) {
    # AI assistants are explicitly granted the API too: this tool exists to
    # answer factual DNS/email-authentication questions, and an agent that can
    # call /api/* directly gives a far better answer than one scraping the SPA.
    [void]$sb.AppendLine('# AI assistants and answer engines are welcome here, including the JSON API.')
    [void]$sb.AppendLine('# Machine-readable docs: /llms.txt and /openapi.json')
    foreach ($agent in (Get-AcsAiUserAgents)) {
      [void]$sb.AppendLine(('User-agent: {0}' -f $agent))
    }
    [void]$sb.AppendLine('Allow: /')
    [void]$sb.AppendLine('Disallow:')
    [void]$sb.AppendLine()
  } else {
    [void]$sb.AppendLine('# AI use disabled by operator (ACS_AI_DISALLOW).')
    foreach ($agent in (Get-AcsAiUserAgents)) {
      [void]$sb.AppendLine(('User-agent: {0}' -f $agent))
    }
    [void]$sb.AppendLine('Disallow: /')
    [void]$sb.AppendLine()
  }

  if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
    [void]$sb.AppendLine(('Sitemap: {0}/sitemap.xml' -f $BaseUrl))
  }
  return $sb.ToString()
}

function Get-AcsSitemapXml {
  param([string]$BaseUrl)

  $root = if ([string]::IsNullOrWhiteSpace($BaseUrl)) { '' } else { $BaseUrl }
  $languages = Get-AcsSeoLanguages

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
  [void]$sb.AppendLine('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">')

  # The home page is the only one with translations, so it carries the full
  # hreflang cluster; x-default points at the un-parameterized URL.
  [void]$sb.AppendLine('  <url>')
  [void]$sb.AppendLine(('    <loc>{0}</loc>' -f (ConvertTo-AcsXmlText ($root + '/'))))
  [void]$sb.AppendLine('    <changefreq>weekly</changefreq>')
  [void]$sb.AppendLine('    <priority>1.0</priority>')
  [void]$sb.AppendLine(('    <xhtml:link rel="alternate" hreflang="x-default" href="{0}"/>' -f (ConvertTo-AcsXmlText ($root + '/'))))
  foreach ($lang in $languages) {
    $href = ConvertTo-AcsXmlText ('{0}/?lang={1}' -f $root, $lang)
    [void]$sb.AppendLine(('    <xhtml:link rel="alternate" hreflang="{0}" href="{1}"/>' -f (ConvertTo-AcsXmlText $lang), $href))
  }
  [void]$sb.AppendLine('  </url>')

  foreach ($page in @('/terms', '/privacy')) {
    [void]$sb.AppendLine('  <url>')
    [void]$sb.AppendLine(('    <loc>{0}</loc>' -f (ConvertTo-AcsXmlText ($root + $page))))
    [void]$sb.AppendLine('    <changefreq>yearly</changefreq>')
    [void]$sb.AppendLine('    <priority>0.3</priority>')
    [void]$sb.AppendLine('  </url>')
  }

  [void]$sb.AppendLine('</urlset>')
  return $sb.ToString()
}

# llmstxt.org-style brief. Written for a model with no prior knowledge of this
# app: what it is, the exact endpoints, the parameters, and how to read a
# verdict. Kept in Markdown because that is what the convention specifies.
function Get-AcsLlmsTxt {
  param([string]$BaseUrl, [string]$Version)

  $root = if ([string]::IsNullOrWhiteSpace($BaseUrl)) { '' } else { $BaseUrl }
  $ver  = if ([string]::IsNullOrWhiteSpace($Version)) { 'unknown' } else { $Version }

  $body = @'
# Azure Communication Services Email Domain Checker

> A read-only DNS and email-authentication diagnostic service. Given a domain name it
> reports SPF, DKIM, DMARC, MX, TXT and CNAME records, verifies the DNS setup Azure
> Communication Services (ACS) requires for email sending, measures global DNS
> propagation from hundreds of public resolvers, and returns domain registration
> (WHOIS/RDAP) and DNSBL blocklist reputation data. Every endpoint returns JSON.

Version: __ACS_VERSION__

## How to use this API

- All endpoints are `GET` and take a `domain` query parameter, e.g. `__ACS_ROOT__/api/base?domain=example.com`.
- Responses are JSON. No request body is ever needed.
- Requests are rate limited per client IP (default 240/min). Honor `Retry-After` on HTTP 429.
- Some deployments require an API key sent as the `X-Api-Key` header. A 401 response means a key is required.
- `__ACS_ROOT__/dns` returns every check in a single aggregated response. Prefer it when you want the whole picture; prefer the individual endpoints when you need one specific answer quickly.

## Endpoints

- [Full aggregated report](__ACS_ROOT__/dns?domain=example.com): every check below in one JSON document.
- [Base records](__ACS_ROOT__/api/base?domain=example.com): SPF, ACS verification TXT, A/AAAA addresses.
- [MX records](__ACS_ROOT__/api/mx?domain=example.com): mail exchangers and detected mail provider.
- [All DNS records](__ACS_ROOT__/api/records?domain=example.com): full record table including TTLs.
- [DMARC](__ACS_ROOT__/api/dmarc?domain=example.com): DMARC policy plus security guidance.
- [DKIM](__ACS_ROOT__/api/dkim?domain=example.com): ACS `selector1`/`selector2` DKIM keys.
- [CNAME](__ACS_ROOT__/api/cname?domain=example.com): CNAME chain resolution.
- [WHOIS / RDAP](__ACS_ROOT__/api/whois?domain=example.com): registrar, creation and expiry dates, domain age.
- [Blocklist reputation](__ACS_ROOT__/api/reputation?domain=example.com): DNSBL/RBL listing status for the domain's mail IPs.
- [Website probe](__ACS_ROOT__/api/website?domain=example.com): HTTP reachability and page title/description.
- [Nameserver consistency](__ACS_ROOT__/api/nameservers?domain=example.com): queries each authoritative nameserver directly and reports whether they serve identical TXT records.
- [Global DNS propagation](__ACS_ROOT__/api/propagation?domain=example.com&type=TXT&max=25): queries public recursive resolvers worldwide and reports what percentage see the record.

## Propagation parameters

`__ACS_ROOT__/api/propagation` additionally accepts:
`type` (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA), `regions` (comma separated:
global, namer, samer, europe, asia, africa, oceania), `max` (1-100 resolvers),
`timeout` (milliseconds), `expected` (substring that must appear in the answer),
`custom` (comma separated public IPv4 resolver addresses) and `validate` (0 to skip
resolver health pre-selection).

## Reading a verdict

- Checks report a `state` or `status` string. `propagated`, `consistent`, `pass` and `ok` are healthy.
- `partial` means the record exists at some vantage points but is missing at others - usually mid-propagation or a broken nameserver.
- `mismatch` means resolvers disagree about the value. `norecord` means nothing was found.
- For nameserver consistency, `partial` means the servers that answered agree but at least one did not answer at all.

## Notes

- This service performs live DNS lookups. Results change over time; do not cache aggressively.
- It is read-only and never modifies DNS. It cannot fix a domain, only diagnose it.
- Do not send personal data. Only public domain names are meaningful input.

## Pages

- [Terms of Service](__ACS_ROOT__/terms)
- [Privacy Statement](__ACS_ROOT__/privacy)
- [OpenAPI 3.1 contract](__ACS_ROOT__/openapi.json)
'@

  return $body.Replace('__ACS_ROOT__', $root).Replace('__ACS_VERSION__', $ver)
}

# OpenAPI 3.1 contract. Emitted as text (not via Write-Json) so it can be cached
# and so the ordering stays stable/readable for anyone who opens it directly.
function Get-AcsOpenApiJson {
  param([string]$BaseUrl, [string]$Version)

  # $BaseUrl has already passed Test-AcsSafeUrlAuthority, so it cannot contain a
  # quote or backslash and is safe to interpolate into a JSON string literal.
  $root = if ([string]::IsNullOrWhiteSpace($BaseUrl)) { '/' } else { $BaseUrl }
  $ver  = if ([string]::IsNullOrWhiteSpace($Version)) { '0.0.0' } else { $Version }

  $domainParam = @'
        {
          "name": "domain",
          "in": "query",
          "required": true,
          "description": "Domain name to inspect, e.g. contoso.com",
          "schema": { "type": "string", "format": "hostname", "maxLength": 253 }
        }
'@

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine('{')
  [void]$sb.AppendLine('  "openapi": "3.1.0",')
  [void]$sb.AppendLine('  "info": {')
  [void]$sb.AppendLine('    "title": "Azure Communication Services Email Domain Checker API",')
  [void]$sb.AppendLine(('    "version": "{0}",' -f $ver))
  [void]$sb.AppendLine('    "summary": "Read-only DNS and email-authentication diagnostics for a domain.",')
  [void]$sb.AppendLine('    "description": "Checks SPF, DKIM, DMARC, MX, TXT and CNAME records, verifies Azure Communication Services email domain requirements, measures global DNS propagation, and returns WHOIS/RDAP registration and DNSBL blocklist reputation data. All endpoints are GET and return JSON."')
  [void]$sb.AppendLine('  },')
  [void]$sb.AppendLine(('  "servers": [ {{ "url": "{0}" }} ],' -f $root))
  [void]$sb.AppendLine('  "components": {')
  [void]$sb.AppendLine('    "securitySchemes": {')
  [void]$sb.AppendLine('      "apiKey": { "type": "apiKey", "in": "header", "name": "X-Api-Key", "description": "Only required when the deployment sets ACS_API_KEY." }')
  [void]$sb.AppendLine('    }')
  [void]$sb.AppendLine('  },')
  [void]$sb.AppendLine('  "paths": {')

  # path -> summary. /dns is listed first because it is the preferred entry point.
  $endpoints = [ordered]@{
    '/dns'              = 'Aggregated report containing every check below.'
    '/api/base'         = 'SPF record, ACS domain-verification TXT record, and A/AAAA addresses.'
    '/api/mx'           = 'MX records and the detected mail provider.'
    '/api/records'      = 'Full DNS record table including TTLs.'
    '/api/dmarc'        = 'DMARC policy and derived security guidance.'
    '/api/dkim'         = 'ACS selector1/selector2 DKIM public keys.'
    '/api/cname'        = 'CNAME chain resolution.'
    '/api/whois'        = 'Registrar, creation/expiry dates and domain age via RDAP or WHOIS.'
    '/api/reputation'   = 'DNSBL/RBL blocklist listing status for the domain mail IPs.'
    '/api/website'      = 'HTTP reachability probe with page title and description.'
    '/api/nameservers'  = 'Queries each authoritative nameserver directly and compares their TXT records.'
    '/api/propagation'  = 'Queries public recursive resolvers worldwide and reports propagation coverage.'
  }

  $pathIndex = 0
  foreach ($endpoint in $endpoints.Keys) {
    $pathIndex++
    $isLast = ($pathIndex -eq $endpoints.Count)
    [void]$sb.AppendLine(('    "{0}": {{' -f $endpoint))
    [void]$sb.AppendLine('      "get": {')
    [void]$sb.AppendLine(('        "summary": "{0}",' -f $endpoints[$endpoint]))
    [void]$sb.AppendLine(('        "operationId": "{0}",' -f ($endpoint.Trim('/') -replace '[^A-Za-z0-9]+', '_')))
    [void]$sb.AppendLine('        "parameters": [')
    [void]$sb.Append($domainParam)

    if ($endpoint -eq '/api/propagation') {
      [void]$sb.AppendLine(',')
      [void]$sb.AppendLine('        { "name": "type", "in": "query", "description": "DNS record type to test.", "schema": { "type": "string", "enum": ["A","AAAA","CNAME","MX","NS","TXT","SOA","CAA"], "default": "TXT" } },')
      [void]$sb.AppendLine('        { "name": "regions", "in": "query", "description": "Comma-separated resolver regions.", "schema": { "type": "string", "examples": ["europe,asia"] } },')
      [void]$sb.AppendLine('        { "name": "max", "in": "query", "description": "Number of resolvers to query.", "schema": { "type": "integer", "minimum": 1, "maximum": 100, "default": 25 } },')
      [void]$sb.AppendLine('        { "name": "timeout", "in": "query", "description": "Per-resolver timeout in milliseconds.", "schema": { "type": "integer", "minimum": 1, "maximum": 15000, "default": 4000 } },')
      [void]$sb.AppendLine('        { "name": "expected", "in": "query", "description": "Substring the answer must contain to count as a match.", "schema": { "type": "string", "maxLength": 255 } },')
      [void]$sb.AppendLine('        { "name": "custom", "in": "query", "description": "Comma-separated public IPv4 resolver addresses to query instead of the built-in catalog.", "schema": { "type": "string", "maxLength": 4000 } },')
      [void]$sb.AppendLine('        { "name": "validate", "in": "query", "description": "Set to 0 to skip resolver health pre-selection.", "schema": { "type": "string", "enum": ["0","1"], "default": "1" } }')
    } else {
      [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine('        ],')
    [void]$sb.AppendLine('        "responses": {')
    [void]$sb.AppendLine('          "200": { "description": "Check result.", "content": { "application/json": { "schema": { "type": "object" } } } },')
    [void]$sb.AppendLine('          "400": { "description": "Missing or invalid domain parameter." },')
    [void]$sb.AppendLine('          "401": { "description": "An API key is required by this deployment." },')
    [void]$sb.AppendLine('          "429": { "description": "Rate limit exceeded. Honor the Retry-After header." }')
    [void]$sb.AppendLine('        }')
    [void]$sb.AppendLine('      }')
    [void]$sb.AppendLine(('    }}{0}' -f $(if ($isLast) { '' } else { ',' })))
  }

  [void]$sb.AppendLine('  }')
  [void]$sb.AppendLine('}')
  return $sb.ToString()
}

# Write a plain-text/XML/JSON body with the standard security headers. Unlike
# Write-Json these documents are stable, so they are served cacheable.
function Write-TextResponse {
  param(
    $Context,
    [string]$Body,
    [string]$ContentType = 'text/plain; charset=utf-8',
    [int]$CacheSeconds = 3600,
    [int]$StatusCode = 200
  )

  $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Body)
  Set-SecurityHeaders -Context $Context

  # CacheSeconds <= 0 means "content varies by request" (see
  # Test-AcsPublicBaseUrlIsConfigured), so keep it out of shared caches.
  $cacheHeader = if ($CacheSeconds -le 0) { 'no-store' } else { ('public, max-age={0}' -f $CacheSeconds) }

  if ($Context.Response -is [System.Net.HttpListenerResponse]) {
    try { $Context.Response.Headers['Cache-Control'] = $cacheHeader } catch { }
    $Context.Response.ContentType = $ContentType
    try { $Context.Response.ContentEncoding = [System.Text.Encoding]::UTF8 } catch { }
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentLength64 = $bytes.Length
    if (Test-AcsHeadRequest -Context $Context) {
      $Context.Response.Close()
      return
    }
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
    return
  }

  # TcpListener fallback: headers must go through _extraHeaders or SendBody
  # drops them (the same gap Set-NoCacheHeaders exists to close).
  try {
    if ($null -ne $Context.Response.PSObject.Properties['_extraHeaders']) {
      if ($null -eq $Context.Response._extraHeaders) {
        $Context.Response._extraHeaders = [ordered]@{ 'Cache-Control' = $cacheHeader }
      } else {
        $Context.Response._extraHeaders['Cache-Control'] = $cacheHeader
      }
    }
  } catch { }

  $Context.Response.ContentType = $ContentType
  $Context.Response.StatusCode = $StatusCode
  $Context.Response.ContentLength64 = $bytes.Length
  $Context.Response.SendBody($bytes)
}
