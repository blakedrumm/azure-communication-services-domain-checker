# ===== Website Reachability / Parked-Page Probe =====
# ------------------- WEBSITE PROBE -------------------
# This check performs a security-hardened outbound HTTP(S) request to the queried
# domain so an operator can see, at a glance, whether the domain actually serves a
# real website or is blank / "under construction" / a registrar parking page.
#
# IMPORTANT (presentation): the output is intentionally NEUTRAL and FACTUAL
# (status code, redirect chain, page title, a short text excerpt, and whether
# common placeholder/parked-page markers were detected). It deliberately makes
# NO judgement about the customer's intent. The UI must mirror that neutrality.
#
# SECURITY: probing an arbitrary, attacker-influenced hostname is a classic SSRF
# vector. The following defenses are layered here:
#   * No destination is authorized by default. Only exact origins explicitly
#     approved by the operator may be probed, including every redirect/fallback.
#     Public addressing alone does not authorize use of the server's network.
#   * Only http/https schemes and only ports 80/443 are allowed.
#   * The target host is resolved up-front and EVERY resolved address must be a
#     public, routable IP (v4 + v6). If any address is private/loopback/link-local/
#     unique-local/CGNAT/etc. the request is refused.
#   * Redirects are NOT followed automatically; each hop's Location is re-validated
#     (scheme/port/public-IP) before we connect to it, with a small hop cap.
#   * Connections use ONLY the validated IPs, without a second hostname lookup.
#     The original hostname is retained for Host, TLS SNI, and certificate checks.
#     Ambient proxies are disabled so proxy-side DNS cannot bypass these guards.
#   * The response body is read with a hard byte cap and the whole operation runs
#     under a short cancellation timeout so a slow/huge target cannot pin a worker.

try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {
  Write-AcsLogException -Component 'WebsiteProbe' -Operation 'http-initialization' -EventId 'WEB-HTTP-INIT-FAILED' -Exception $_.Exception -ErrorCode 'ACS-WEB-HTTP-INIT' -Message 'Website HTTP dependency initialization failed.'
}

# ConnectCallback runs on .NET threads without a PowerShell runspace. Keep it in
# C#, and retain the native HTTP stack's multi-address connection fallback.
$websiteSocketsHandlerType = 'System.Net.Http.SocketsHttpHandler' -as [type]
if ($websiteSocketsHandlerType -and $websiteSocketsHandlerType.GetProperty('ConnectCallback') -and -not ('AcsWebsitePinnedHttp' -as [type])) {
  try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

public sealed class AcsWebsitePinnedHttp : DelegatingHandler
{
    private readonly ConcurrentDictionary<string, IPAddress[]> targets =
        new ConcurrentDictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase);

    public AcsWebsitePinnedHttp(Uri target, string[] addresses, CookieContainer cookies)
    {
        var handler = new SocketsHttpHandler();
        handler.AllowAutoRedirect = false;
        handler.UseProxy = false;
        handler.CookieContainer = cookies;
        handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
        handler.ConnectCallback = (context, token) =>
            new ValueTask<Stream>(Connect(context.DnsEndPoint, token));
        InnerHandler = handler;
        SetTarget(target, addresses);
    }

    public static HttpMessageHandler CreateHandler(Uri target, string[] addresses, CookieContainer cookies)
    {
        return new AcsWebsitePinnedHttp(target, addresses, cookies);
    }

    public void SetTarget(Uri target, string[] addresses)
    {
        var pinned = new IPAddress[addresses.Length];
        for (int i = 0; i < addresses.Length; i++) pinned[i] = IPAddress.Parse(addresses[i]);
        targets[Key(target.IdnHost, target.Port)] = pinned;
    }

    private static string Key(string host, int port)
    {
        return host.Trim('[', ']') + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<Stream> Connect(DnsEndPoint endpoint, CancellationToken token)
    {
        IPAddress[] addresses;
        if (!targets.TryGetValue(Key(endpoint.Host, endpoint.Port), out addresses))
            throw new InvalidOperationException("Unexpected website connection destination.");

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        socket.NoDelay = true;
        using (token.Register(() => socket.Dispose()))
        {
            try
            {
                await SocketTaskExtensions.ConnectAsync(socket, addresses, endpoint.Port).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                return new NetworkStream(socket, true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
    }
}
'@ -ErrorAction Stop
  } catch {
    Write-AcsLogException -Component 'WebsiteProbe' -Operation 'pinned-transport-initialization' -EventId 'WEB-PINNED-INIT-FAILED' -Exception $_.Exception -ErrorCode 'ACS-WEB-PINNED-INIT' -Message 'Native website connection pinning unavailable; using literal-IP request pinning.' -Fields @{ fallback = 'literal-ip' }
  }
}

# Return $true only when the supplied IP literal is a public, routable address.
# Handles both IPv4 and IPv6 (including IPv4-mapped IPv6 like ::ffff:10.0.0.1,
# which must be unwrapped and re-checked as IPv4 to avoid a bypass).
function Test-IsPublicIpAddress {
  param([string]$IpAddress)

  $ipObj = $null
  if (-not [System.Net.IPAddress]::TryParse(([string]$IpAddress).Trim(), [ref]$ipObj)) { return $false }

  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
	# ---- IPv4 ----
	$b = $ipObj.GetAddressBytes()
	if ($b[0] -eq 0)   { return $false }                       # 0.0.0.0/8 "this network"
	if ($b[0] -eq 10)  { return $false }                       # 10.0.0.0/8 private
	if ($b[0] -eq 127) { return $false }                       # 127.0.0.0/8 loopback
	if ($b[0] -ge 224) { return $false }                       # 224.0.0.0/4 multicast + 240/4 reserved
	if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }  # 100.64/10 CGNAT
	if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }                    # 169.254/16 link-local
	if ($b[0] -eq 168 -and $b[1] -eq 63 -and $b[2] -eq 129 -and $b[3] -eq 16) { return $false } # Azure host service
	if ($b[0] -eq 172 -and $b[1] -ge 16  -and $b[1] -le 31)  { return $false } # 172.16/12 private
	if ($b[0] -eq 192 -and $b[1] -eq 0   -and $b[2] -eq 0)   { return $false } # 192.0.0/24 IETF
	if ($b[0] -eq 192 -and $b[1] -eq 0   -and $b[2] -eq 2)   { return $false } # 192.0.2/24 TEST-NET-1
	if ($b[0] -eq 192 -and $b[1] -eq 88  -and $b[2] -eq 99)  { return $false } # 192.88.99/24 6to4 relay
	if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }                    # 192.168/16 private
	if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19))  { return $false } # 198.18/15 benchmark
	if ($b[0] -eq 198 -and $b[1] -eq 51  -and $b[2] -eq 100) { return $false } # 198.51.100/24 TEST-NET-2
	if ($b[0] -eq 203 -and $b[1] -eq 0   -and $b[2] -eq 113) { return $false } # 203.0.113/24 TEST-NET-3
	if ($b[0] -eq 255 -and $b[1] -eq 255 -and $b[2] -eq 255 -and $b[3] -eq 255) { return $false } # broadcast
	return $true
  }

  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
	# ---- IPv6 ----
	if ($ipObj.ScopeId -ne 0) { return $false }
	if ($ipObj.IsIPv4MappedToIPv6) {
	  # ::ffff:a.b.c.d - re-validate the embedded IPv4 so a mapped private
	  # address cannot slip past the IPv6 checks below.
	  try { return (Test-IsPublicIpAddress -IpAddress ($ipObj.MapToIPv4().ToString())) } catch { return $false }
	}
	if ([System.Net.IPAddress]::IsLoopback($ipObj)) { return $false }          # ::1
	if ($ipObj.IsIPv6LinkLocal)  { return $false }                             # fe80::/10
	if ($ipObj.IsIPv6SiteLocal)  { return $false }                             # fec0::/10 (deprecated)
	if ($ipObj.IsIPv6Multicast)  { return $false }                             # ff00::/8
	$b6 = $ipObj.GetAddressBytes()
	$allZero = $true
	foreach ($octet in $b6) { if ($octet -ne 0) { $allZero = $false; break } }
	if ($allZero) { return $false }                                            # :: unspecified
	# Only allocated global unicast space is eligible. This also excludes
	# IPv4-compatible, NAT64, discard-only, and unique-local addresses.
	if (($b6[0] -band 0xE0) -ne 0x20) { return $false }                       # outside 2000::/3
	if ($b6[0] -eq 0x20 -and $b6[1] -eq 0x01 -and ($b6[2] -band 0xFE) -eq 0) { return $false } # 2001::/23 special-use
	if ($b6[0] -eq 0x20 -and $b6[1] -eq 0x01 -and $b6[2] -eq 0x0D -and $b6[3] -eq 0xB8) { return $false } # documentation
	if ($b6[0] -eq 0x20 -and $b6[1] -eq 0x02) { return $false }               # 2002::/16 6to4
	if ($b6[0] -eq 0x3F -and $b6[1] -eq 0xFE) { return $false }               # retired 6bone
	if ($b6[0] -eq 0x3F -and $b6[1] -eq 0xFF -and ($b6[2] -band 0xF0) -eq 0) { return $false } # 3fff::/20 documentation
	return $true
  }

  # Unknown address family - refuse.
  return $false
}

# Resolve a hostname and confirm it is safe to connect to. Returns a result object
# with isPublic + the resolved addresses + a reason string. The host is considered
# safe ONLY when it resolves to at least one address AND every resolved address is
# public. Requiring ALL addresses to be public defeats a host that publishes both a
# public and a private/loopback record to trick us into connecting internally.
function Test-WebsiteHostIsPublic {
  param(
	[Parameter(Mandatory = $true)][string]$HostName,
	[int]$DnsTimeoutSec = 5
  )

  $name = ([string]$HostName).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($name)) {
	return [pscustomobject]@{ isPublic = $false; addresses = @(); reason = 'Empty host.' }
  }

  # A bare IP literal as host: validate directly (covers redirects to IPs).
  $literal = $null
  if ([System.Net.IPAddress]::TryParse($name, [ref]$literal)) {
	$ok = Test-IsPublicIpAddress -IpAddress $name
	return [pscustomobject]@{
	  isPublic  = $ok
	  addresses = @($name)
	  reason    = if ($ok) { $null } else { 'Host is a non-public IP literal.' }
	}
  }

  $addresses = @()
  try {
	# GetHostAddressesAsync matches what the OS resolver/HttpClient will use, so
	# the guard reflects the IPs we are actually about to connect to. Bounded by a
	# short wait so a deliberately slow authoritative server cannot stall a worker.
	$task = [System.Net.Dns]::GetHostAddressesAsync($name)
	if (-not $task.Wait([TimeSpan]::FromSeconds([Math]::Max(1, $DnsTimeoutSec)))) {
	  return [pscustomobject]@{ isPublic = $false; addresses = @(); reason = 'DNS resolution timed out.' }
	}
	$addresses = @($task.Result | ForEach-Object { $_.ToString() })
  } catch {
	return [pscustomobject]@{ isPublic = $false; addresses = @(); reason = 'DNS resolution failed.' }
  }

  if (-not $addresses -or $addresses.Count -eq 0) {
	return [pscustomobject]@{ isPublic = $false; addresses = @(); reason = 'Host did not resolve to any address.' }
  }

  foreach ($addr in $addresses) {
	if (-not (Test-IsPublicIpAddress -IpAddress $addr)) {
	  return [pscustomobject]@{ isPublic = $false; addresses = $addresses; reason = 'Host resolves to a non-public IP address.' }
	}
  }

  return [pscustomobject]@{ isPublic = $true; addresses = $addresses; reason = $null }
}

function ConvertTo-WebsiteProbeOrigin {
  param([Parameter(Mandatory = $true)][uri]$TargetUri)

  if (-not $TargetUri.IsAbsoluteUri -or $TargetUri.Scheme -notin @('http','https') -or
	  $TargetUri.Port -notin @(80,443) -or $TargetUri.HostNameType -ne [System.UriHostNameType]::Dns -or
	  -not [string]::IsNullOrEmpty($TargetUri.UserInfo)) { return $null }

  try {
	return '{0}://{1}:{2}' -f $TargetUri.Scheme, $TargetUri.IdnHost.TrimEnd('.').ToLowerInvariant(), $TargetUri.Port
  } catch [System.UriFormatException] { return $null }
}

function Get-WebsiteProbePolicy {
  if (([string]$env:ACS_DISABLE_WEBSITE_PROBE).Trim() -eq '1') {
	return [pscustomobject]@{ enabled = $false; reason = 'Website probe disabled by server configuration.'; origins = $null }
  }

  $raw = [string]$env:ACS_WEBSITE_PROBE_ALLOWED_ORIGINS
  $cached = $ExecutionContext.SessionState.PSVariable.GetValue('script:WebsiteProbePolicyCache')
  if ($cached -and $cached.raw -ceq $raw) { return $cached.policy }

  $origins = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $policy = [pscustomobject]@{
	enabled = $false
	reason = 'Website probe disabled: no server-approved origins are configured.'
	origins = $origins
  }
  if (-not [string]::IsNullOrWhiteSpace($raw)) {
	$valid = $raw.Length -le 16384
	if ($valid) {
	  foreach ($entry in ($raw -split '[,;\r\n]')) {
		$value = $entry.Trim()
		if (-not $value) { continue }
		$uri = $null
		if (-not [uri]::TryCreate($value, [System.UriKind]::Absolute, [ref]$uri) -or
			$uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { $valid = $false; break }
		$origin = ConvertTo-WebsiteProbeOrigin -TargetUri $uri
		if (-not $origin) { $valid = $false; break }
		$null = $origins.Add($origin)
		if ($origins.Count -gt 256) { $valid = $false; break }
	  }
	}
	if (-not $valid) {
	  $origins.Clear()
	  $policy.reason = 'Website probe disabled: server-approved origins configuration is invalid.'
	} elseif ($origins.Count -gt 0) {
	  $policy.enabled = $true
	  $policy.reason = $null
	}
  }
  # Cache only trusted process configuration, never request-selected origins.
  $script:WebsiteProbePolicyCache = [pscustomobject]@{ raw = $raw; policy = $policy }
  return $policy
}

function Test-WebsiteProbeTarget {
  param(
	[Parameter(Mandatory = $true)][uri]$TargetUri,
	[object]$Policy = (Get-WebsiteProbePolicy)
  )

  if (-not $Policy.enabled) { return $false }
  $origin = ConvertTo-WebsiteProbeOrigin -TargetUri $TargetUri
  return ($null -ne $origin -and $Policy.origins.Contains($origin))
}

function New-WebsiteHttpHandler {
  param(
	[Parameter(Mandatory = $true)][uri]$TargetUri,
	[Parameter(Mandatory = $true)][string[]]$Addresses,
	[Parameter(Mandatory = $true)][System.Net.CookieContainer]$Cookies
  )

  $policy = Get-WebsiteProbePolicy
  if (-not (Test-WebsiteProbeTarget -TargetUri $TargetUri -Policy $policy)) {
	throw 'Website destination is not authorized by server policy.'
  }
  foreach ($address in $Addresses) {
	if (-not (Test-IsPublicIpAddress -IpAddress $address)) { throw 'Refused a non-public website connection address.' }
  }

  if ('AcsWebsitePinnedHttp' -as [type]) {
	return [AcsWebsitePinnedHttp]::CreateHandler($TargetUri, $Addresses, $Cookies)
  }

  # .NET Framework has no ConnectCallback. Its requests are instead addressed
  # to a validated IP literal, retaining Host for TLS SNI/certificate validation.
  # Cookies are managed against the original URL, not that transport-only IP.
  $handler = [System.Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $handler.UseProxy = $false
  $handler.UseCookies = $false
  $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
  return $handler
}

# Perform the manual, SSRF-guarded redirect walk for a single starting URL and
# return a neutral snapshot of what was found. This is the workhorse: it creates a
# short-lived HttpClient with auto-redirect DISABLED, validates each hop, reads the
# terminal response body under a hard byte cap, and extracts title/description/
# visible-text plus parked/placeholder markers.
function Get-WebsiteSnapshot {
  param(
	[Parameter(Mandatory = $true)][string]$Url,
	[int]$TimeoutSec = 8,
	[int]$MaxBytes = 262144,
	[int]$MaxRedirects = 5
  )

  if ($TimeoutSec -le 0)  { $TimeoutSec = 8 }
  if ($MaxBytes -le 0)    { $MaxBytes = 262144 }
  if ($MaxRedirects -lt 0) { $MaxRedirects = 0 }

  # Build the base result so every return path has a consistent shape.
  $result = [pscustomobject]@{
	requestedUrl     = $Url
	finalUrl         = $null
	reachable        = $false
	statusCode       = $null
	scheme           = $null
	contentType      = $null
	redirected       = $false
	redirectChain    = @()
	title            = $null
	metaDescription  = $null
	bodyExcerpt      = $null
	visibleTextLength = $null
	nearEmpty        = $null
	placeholderDetected = $false
	placeholderSignals  = @()
	tlsError         = $false
	error            = $null
  }

  $startUri = $null
  try { $startUri = [uri]$Url } catch { $result.error = 'Malformed URL.'; return $result }
  if (-not $startUri.IsAbsoluteUri) { $result.error = 'URL must be absolute.'; return $result }
  $policy = Get-WebsiteProbePolicy
  if (-not $policy.enabled) { $result.error = $policy.reason; return $result }

  $handler = $null
  $client  = $null
  $cts     = $null
  $resp    = $null
  $cookies = [System.Net.CookieContainer]::new()
  $lastAuthority = $null
  try {
	# Prefer TLS 1.2+ for the handshake (older defaults bite Windows PowerShell 5.1).
	try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 } catch { }

	# Whole-operation cancellation budget (covers headers + body streaming, which
	# HttpClient.Timeout alone does not when using ResponseHeadersRead).
	$cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSec))

	$current = $startUri
	$chain = [System.Collections.Generic.List[object]]::new()

	for ($hop = 0; $hop -le $MaxRedirects; $hop++) {
	  # Only http/https and only standard web ports are ever contacted.
	  if ($current.Scheme -ne 'http' -and $current.Scheme -ne 'https') {
		$result.error = 'Refused non-HTTP(S) redirect target.'
		break
	  }
	  if ($current.Port -ne 80 -and $current.Port -ne 443) {
		$result.error = 'Refused redirect to a non-standard port.'
		break
	  }
	  if (-not [string]::IsNullOrEmpty($current.UserInfo)) {
		$result.error = 'Refused URL containing user information.'
		break
	  }

	  # Authorize before DNS, even for public IPs or an existing connection.
	  if (-not (Test-WebsiteProbeTarget -TargetUri $current -Policy $policy)) {
		$result.error = 'Website destination is not authorized by server policy.'
		break
	  }
	  $hostCheck = Test-WebsiteHostIsPublic -HostName $current.IdnHost
	  if (-not $hostCheck.isPublic) {
		$result.error = $hostCheck.reason
		break
	  }

	  $resp = $null
	  try {
		$authority = $current.GetLeftPart([System.UriPartial]::Authority)
		if ($client -and $handler -is [System.Net.Http.HttpClientHandler] -and $lastAuthority -ne $authority) {
		  # Do not reuse an IP-keyed TLS connection for a different hostname.
		  $client.Dispose()
		  $client = $null
		}
		if (-not $client) {
		  $handler = New-WebsiteHttpHandler -TargetUri $current -Addresses $hostCheck.addresses -Cookies $cookies
		  $client = [System.Net.Http.HttpClient]::new($handler)
		  $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
		  $null = $client.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (compatible; ACS-Domain-Checker/1.0; +https://github.com/mcaps-microsoft/azure-communication-services-domain-checker)')
		  $null = $client.DefaultRequestHeaders.Accept.ParseAdd('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
		  $lastAuthority = $authority
		} elseif ($handler.GetType().FullName -eq 'AcsWebsitePinnedHttp') {
		  $handler.SetTarget($current, [string[]]$hostCheck.addresses)
		}

		$literalPinning = $handler -is [System.Net.Http.HttpClientHandler]
		$connectionAddresses = @('')
		if ($literalPinning) { $connectionAddresses = @($hostCheck.addresses) }
		foreach ($address in $connectionAddresses) {
		  $req = $null
		  try {
			$requestUri = $current
			if ($literalPinning) {
			  $transportUri = [System.UriBuilder]::new($current)
			  $transportUri.Host = $address
			  $requestUri = $transportUri.Uri
			}
			$req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $requestUri)
			if ($literalPinning) {
			  $originalAuthority = [System.UriBuilder]::new($current)
			  $originalAuthority.Host = $current.IdnHost
			  $req.Headers.Host = $originalAuthority.Uri.Authority
			  # Match the native pinned socket's TCP_NODELAY without changing
			  # process-wide networking defaults for other lookup providers.
			  $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($requestUri, [System.Net.IWebProxy]$null)
			  $servicePoint.UseNagleAlgorithm = $false
			  $cookieHeader = $cookies.GetCookieHeader($current)
			  if ($cookieHeader) { $null = $req.Headers.TryAddWithoutValidation('Cookie', $cookieHeader) }
			}
			$resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
			break
		  } catch {
			# Match the native stack: try another validated address only for a
			# socket connection failure, not for TLS or HTTP-level failures.
			$connectionError = $_.Exception
			$socketFailure = $false
			while ($connectionError) {
			  if ($connectionError -is [System.Net.Sockets.SocketException]) { $socketFailure = $true; break }
			  $connectionError = $connectionError.InnerException
			}
			if (-not $literalPinning -or -not $socketFailure -or $cts.IsCancellationRequested -or $address -eq $connectionAddresses[-1]) { throw }
		  } finally {
			if ($req) { $req.Dispose() }
		  }
		}

		if ($literalPinning -and $resp.Headers.Contains('Set-Cookie')) {
		  foreach ($setCookie in $resp.Headers.GetValues('Set-Cookie')) {
			try { $cookies.SetCookies($current, $setCookie) } catch [System.Net.CookieException] {
			  Write-AcsLogEvent -Level 'Warning' -Component 'WebsiteProbe' -Operation 'response-cookie' -EventId 'WEB-COOKIE-REJECTED' -Message 'Website response contained an invalid cookie.' -ErrorCode 'ACS-WEB-COOKIE'
			}
		  }
		}
	  } catch {
		# Classify TLS/handshake failures distinctly - an expired/self-signed cert
		# is itself a useful, neutral signal about the site.
		$msg = [string]$_.Exception.Message
		$inner = $_.Exception.InnerException
		$isTls = $false
		$probe = $_.Exception
		while ($probe) {
		  if ($probe -is [System.Security.Authentication.AuthenticationException]) { $isTls = $true; break }
		  $probe = $probe.InnerException
		}
		if ($isTls) {
		  $result.tlsError = $true
		  $result.error = 'TLS/SSL handshake failed (certificate or protocol error).'
		} elseif ($cts.IsCancellationRequested -or $msg -match '(?i)cancel|timed out|timeout') {
		  $result.error = 'Connection timed out.'
		} else {
		  $result.error = 'Connection failed.'
		}
		if ($inner) { } # inner intentionally not surfaced to avoid leaking internals
		break
	  }

	  $status = [int]$resp.StatusCode
	  $result.statusCode = $status
	  $result.finalUrl = $current.AbsoluteUri
	  $result.scheme = $current.Scheme

	  # Redirect handling: follow 3xx with a Location while we still have hops left.
	  $isRedirect = ($status -in @(301, 302, 303, 307, 308))
	  $location = $null
	  try { if ($resp.Headers -and $resp.Headers.Location) { $location = $resp.Headers.Location } } catch { $location = $null }

	  if ($isRedirect -and $location -and $hop -lt $MaxRedirects) {
		$nextUri = $null
		try {
		  # Location may be relative; resolve against the current absolute URL.
		  $nextUri = if ($location.IsAbsoluteUri) { $location } else { [uri]::new($current, $location) }
		} catch { $nextUri = $null }

		try { $resp.Dispose() } catch { }

		if (-not $nextUri) { $result.error = 'Malformed redirect target.'; break }

		$chain.Add([pscustomobject]@{
		  from   = $current.AbsoluteUri
		  to     = $nextUri.AbsoluteUri
		  status = $status
		})
		$result.redirected = $true
		$current = $nextUri
		continue
	  }

	  # ---- Terminal response: this hop is the final page. ----
	  $result.reachable = $true
	  try { $result.contentType = [string]$resp.Content.Headers.ContentType } catch { $result.contentType = $null }

	  # Only parse markup when the content looks like HTML/text. Binary payloads
	  # (images, PDFs, downloads) are still reported as reachable, just without a
	  # body excerpt.
	  $ctLower = ([string]$result.contentType).ToLowerInvariant()
	  $looksHtml = ($ctLower -match 'text/html' -or $ctLower -match 'application/xhtml' -or $ctLower -match 'text/plain' -or [string]::IsNullOrWhiteSpace($ctLower))

	  if ($looksHtml) {
		$bytes = $null
		$stream = $null
		$ms = $null
		$bodyReadFailed = $false
		try {
		  $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
		  $ms = [System.IO.MemoryStream]::new()
		  $buffer = [byte[]]::new(8192)
		  $total = 0
		  while ($true) {
			$readCount = $buffer.Length
			if (($MaxBytes - $total) -lt $readCount) { $readCount = $MaxBytes - $total }
			$read = $stream.ReadAsync($buffer, 0, $readCount, $cts.Token).GetAwaiter().GetResult()
			if ($read -le 0) { break }
			$take = [Math]::Min($read, ($MaxBytes - $total))
			if ($take -gt 0) { $ms.Write($buffer, 0, $take); $total += $take }
			if ($total -ge $MaxBytes) { break }
		  }
		  $bytes = $ms.ToArray()
		} catch {
		  $bodyReadFailed = $true
		  if ($ms) { $bytes = $ms.ToArray() }
		  $result.error = if ($cts.IsCancellationRequested) { 'Response body read timed out.' } else { 'Response body read failed.' }
		  Write-AcsLogEvent -Level 'Warning' -Component 'WebsiteProbe' -Operation 'response-body' -EventId 'WEB-BODY-READ-FAILED' -Message 'Website response body could not be read completely.' -ErrorCode 'ACS-WEB-BODY'
		} finally {
		  if ($ms) { $ms.Dispose() }
		  if ($stream) { $stream.Dispose() }
		}

		if ($bytes -and $bytes.Length -gt 0) {
		  # Decode as UTF-8 (best-effort; sufficient for title/description/markers).
		  $html = [System.Text.Encoding]::UTF8.GetString($bytes)

		  # Title.
		  $titleMatch = [regex]::Match($html, '(?is)<title[^>]*>(.*?)</title>')
		  if ($titleMatch.Success) {
			$result.title = (Format-WebsiteText -Text ([System.Net.WebUtility]::HtmlDecode($titleMatch.Groups[1].Value)) -MaxLength 200)
		  }

		  # Meta description / OpenGraph description (attribute order varies).
		  foreach ($metaMatch in [regex]::Matches($html, '(?is)<meta\b[^>]*>')) {
			$tag = $metaMatch.Value
			if ($tag -match '(?i)(?:name|property)\s*=\s*["''](?:description|og:description)["'']') {
			  $contentMatch = [regex]::Match($tag, '(?i)content\s*=\s*["'']([^"'']*)["'']')
			  if ($contentMatch.Success) {
				$result.metaDescription = (Format-WebsiteText -Text ([System.Net.WebUtility]::HtmlDecode($contentMatch.Groups[1].Value)) -MaxLength 300)
				break
			  }
			}
		  }

		  # Visible text: drop script/style blocks, strip tags, decode entities,
		  # collapse whitespace. Used for the excerpt + near-empty + marker checks.
		  $noScript = [regex]::Replace($html, '(?is)<(script|style|noscript)\b.*?</\1>', ' ')
		  $stripped = [regex]::Replace($noScript, '(?s)<[^>]+>', ' ')
		  $visible = (Format-WebsiteText -Text ([System.Net.WebUtility]::HtmlDecode($stripped)) -MaxLength 100000)
		  $result.visibleTextLength = if ($visible) { $visible.Length } else { 0 }
		  $result.nearEmpty = ($result.visibleTextLength -lt 50)
		  if ($visible) {
			$result.bodyExcerpt = if ($visible.Length -gt 400) { $visible.Substring(0, 400) } else { $visible }
		  }

		  # Parked / placeholder / default-server markers. These are surfaced as
		  # neutral "indicators", never as an accusation. The haystack includes the
		  # title + meta + a bounded slice of the raw HTML (so markers inside links
		  # / scripts-removed content are still caught).
		  $haystack = (("{0} {1} {2}" -f $result.title, $result.metaDescription, $visible)).ToLowerInvariant()
		  $markers = [ordered]@{
			'under construction'   = 'underConstruction'
			'coming soon'          = 'comingSoon'
			'domain is for sale'   = 'domainForSale'
			'buy this domain'      = 'domainForSale'
			'this domain is parked' = 'parked'
			'domain parking'       = 'parked'
			'parked free'          = 'parked'
			'future home of'       = 'placeholder'
			'default web page'     = 'defaultPage'
			'welcome to nginx'     = 'defaultPage'
			'it works!'            = 'defaultPage'
			'apache2 default'      = 'defaultPage'
			'iis windows server'   = 'defaultPage'
			'account suspended'    = 'suspended'
			'site not configured'  = 'notConfigured'
		  }
		  $signals = [System.Collections.Generic.List[string]]::new()
		  foreach ($marker in $markers.GetEnumerator()) {
			if ($haystack.Contains($marker.Key)) {
			  if (-not $signals.Contains($marker.Value)) { $signals.Add($marker.Value) }
			}
		  }
		  $result.placeholderSignals = $signals.ToArray()
		  $result.placeholderDetected = ($signals.Count -gt 0)
		} elseif (-not $bodyReadFailed) {
		  # Reachable but empty body is itself a (neutral) signal.
		  $result.visibleTextLength = 0
		  $result.nearEmpty = $true
		}
	  }

	  try { $resp.Dispose() } catch { }
	  break
	}

	# We consumed all hops without reaching a terminal page.
	if ($result.reachable -eq $false -and [string]::IsNullOrWhiteSpace([string]$result.error) -and $chain.Count -gt 0) {
	  $result.error = 'Too many redirects.'
	}
	$result.redirectChain = $chain.ToArray()
  }
  catch {
	if ([string]::IsNullOrWhiteSpace([string]$result.error)) { $result.error = 'Website probe failed.' }
  }
  finally {
	if ($resp)    { $resp.Dispose() }
	if ($cts)     { try { $cts.Dispose() } catch { } }
	if ($client)  { try { $client.Dispose() } catch { } }
	if ($handler) { try { $handler.Dispose() } catch { } }
  }

  return $result
}

# Small text normalizer: decode-safe trim + whitespace collapse + length cap.
# Kept top-level (not nested) so both Get-WebsiteSnapshot and any future caller
# can reuse it; registered in the runspace pool.
function Format-WebsiteText {
  param(
	[string]$Text,
	[int]$MaxLength = 1000
  )
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $clean = [regex]::Replace($Text, '\s+', ' ').Trim()
  if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
  if ($MaxLength -gt 0 -and $clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) }
  return $clean
}

# Top-level orchestrator called by the /api/website route. Tries a small ordered
# set of candidate URLs (https first, apex + www) and returns the first reachable
# terminal page, plus a per-attempt log. Output is strictly neutral/factual.
function Get-WebsiteProbeStatus {
  param(
	[Parameter(Mandatory = $true)][string]$Domain
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')

  # Result skeleton (kept stable so the SPA can rely on the shape).
  $status = [pscustomobject]@{
	domain          = $d
	generatedAtUtc  = ([DateTime]::UtcNow.ToString('o'))
	checked         = $true
	disabledReason  = $null
	reachable       = $false
	finalUrl        = $null
	statusCode      = $null
	scheme          = $null
	contentType     = $null
	redirected      = $false
	redirectChain   = @()
	title           = $null
	metaDescription = $null
	bodyExcerpt     = $null
	visibleTextLength = $null
	nearEmpty       = $null
	placeholderDetected = $false
	placeholderSignals  = @()
	tlsError        = $false
	attempts        = @()
	summary         = 'Unreachable'
	error           = $null
  }

  if ([string]::IsNullOrWhiteSpace($d)) {
	$status.checked = $false
	$status.summary = 'Unknown'
	$status.error = 'Missing domain.'
	return $status
  }

  $policy = Get-WebsiteProbePolicy
  if (-not $policy.enabled) {
	$status.checked = $false
	$status.summary = 'Disabled'
	$status.disabledReason = $policy.reason
	return $status
  }

  # Tunable, bounded knobs (read inline, mirroring the RBL check's pattern).
  $timeoutSec = 8
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_WEBSITE_PROBE_TIMEOUT_SEC, [ref]$parsed) -and $parsed -gt 0) {
	$timeoutSec = [Math]::Min(30, $parsed)
  }
  $maxBytes = 262144
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_WEBSITE_PROBE_MAX_BYTES, [ref]$parsed) -and $parsed -gt 0) {
	$maxBytes = [Math]::Min(2097152, $parsed)   # hard ceiling 2 MB
  }
  $maxRedirects = 5
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_WEBSITE_PROBE_MAX_REDIRECTS, [ref]$parsed) -and $parsed -ge 0) {
	$maxRedirects = [Math]::Min(10, $parsed)
  }

  # Candidate URLs: https first (apex, then www), then http as a fallback. The www
  # variant is skipped when the queried name already starts with www. so we don't
  # probe www.www.example.com.
  $hasWww = $d.ToLowerInvariant().StartsWith('www.')
  $candidates = [System.Collections.Generic.List[string]]::new()
  $candidates.Add("https://$d/")
  if (-not $hasWww) { $candidates.Add("https://www.$d/") }
  $candidates.Add("http://$d/")
  if (-not $hasWww) { $candidates.Add("http://www.$d/") }

  $approvedCandidate = $false
  foreach ($candidate in $candidates) {
	$candidateUri = $null
	if ([uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$candidateUri) -and
		(Test-WebsiteProbeTarget -TargetUri $candidateUri -Policy $policy)) { $approvedCandidate = $true; break }
  }
  if (-not $approvedCandidate) {
	$status.checked = $false
	$status.summary = 'Disabled'
	$status.disabledReason = 'Website destination is not authorized by server policy.'
	return $status
  }

  $attempts = [System.Collections.Generic.List[object]]::new()
  $picked = $null

  foreach ($candidate in $candidates) {
	$snap = Get-WebsiteSnapshot -Url $candidate -TimeoutSec $timeoutSec -MaxBytes $maxBytes -MaxRedirects $maxRedirects

	$attempts.Add([pscustomobject]@{
	  url        = $candidate
	  reachable  = [bool]$snap.reachable
	  statusCode = $snap.statusCode
	  tlsError   = [bool]$snap.tlsError
	  error      = $snap.error
	})

	# Stop at the first candidate that returned a terminal page.
	if ($snap.reachable) { $picked = $snap; break }
  }

  # Use ToArray() so the strongly-typed List[object] becomes a plain object[]
  # that PowerShell will accept when assigning back onto the [pscustomobject]
  # NoteProperty (which was initialized as an empty array literal). Assigning the
  # List instance directly throws "Argument types do not match".
  $status.attempts = $attempts.ToArray()

  if ($picked) {
	$status.reachable           = $true
	$status.finalUrl            = $picked.finalUrl
	$status.statusCode          = $picked.statusCode
	$status.scheme              = $picked.scheme
	$status.contentType         = $picked.contentType
	$status.redirected          = [bool]$picked.redirected
	$status.redirectChain       = @($picked.redirectChain)
	$status.title               = $picked.title
	$status.metaDescription     = $picked.metaDescription
	$status.bodyExcerpt         = $picked.bodyExcerpt
	$status.visibleTextLength   = $picked.visibleTextLength
	$status.nearEmpty           = $picked.nearEmpty
	$status.placeholderDetected = [bool]$picked.placeholderDetected
	$status.placeholderSignals  = @($picked.placeholderSignals)
	$status.tlsError            = [bool]$picked.tlsError
	$status.error               = $picked.error

	# Neutral summary classification:
	#   * PlaceholderContent - parked/under-construction/default/near-empty page.
	#   * ServerError        - reachable but 5xx.
	#   * ClientError        - reachable but 4xx (e.g. 403/404 landing).
	#   * Reachable          - a normal 2xx page with real content.
	$code = [int]($picked.statusCode | ForEach-Object { $_ })
	if ($picked.placeholderDetected -or ($picked.nearEmpty -eq $true)) {
	  $status.summary = 'PlaceholderContent'
	} elseif ($code -ge 500) {
	  $status.summary = 'ServerError'
	} elseif ($code -ge 400) {
	  $status.summary = 'ClientError'
	} else {
	  $status.summary = 'Reachable'
	}
  } else {
	# Nothing reachable. Surface the most informative attempt error (prefer a TLS
	# error, else the first non-empty error) so the card isn't blank.
	$status.reachable = $false
	$status.summary = 'Unreachable'
	$tlsAttempt = $attempts | Where-Object { $_.tlsError } | Select-Object -First 1
	if ($tlsAttempt) {
	  $status.tlsError = $true
	  $status.error = $tlsAttempt.error
	} else {
	  $firstErr = $attempts | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.error) } | Select-Object -First 1
	  if ($firstErr) { $status.error = $firstErr.error } else { $status.error = 'No HTTP(S) response from the domain.' }
	}
  }

  return $status
}
