# Offline security/output checks and HTTP/TLS tests against owned loopback listeners.
# Optional -BaselineFile compares every output field and timings with an older
# 16b-WebsiteProbe.ps1. No public, corporate, or cloud-metadata service is contacted.
[CmdletBinding()]
param([string]$BaselineFile)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$checks = 0

function Assert-Equal {
  param([string]$Name, $Expected, $Actual)
  if ($Expected -ne $Actual) { throw "$Name expected '$Expected', got '$Actual'." }
  $script:checks++
}

function Assert-Throws {
  param([string]$Name, [scriptblock]$Action)
  $threw = $false
  try { & $Action } catch { $threw = $true }
  Assert-Equal $Name $true $threw
}

function ConvertTo-ComparableJson {
  param($Value)
  $Value | Select-Object -Property * -ExcludeProperty generatedAtUtc | ConvertTo-Json -Depth 12 -Compress
}

$savedEnvironment = @{}
foreach ($name in @('ACS_DISABLE_WEBSITE_PROBE','ACS_WEBSITE_PROBE_TIMEOUT_SEC','ACS_WEBSITE_PROBE_MAX_BYTES','ACS_WEBSITE_PROBE_MAX_REDIRECTS','ACS_LOG_LEVEL','ACS_LOG_FILE')) {
  $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
  [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}
$env:ACS_LOG_LEVEL = 'Critical'

try {
  . (Join-Path $repoRoot 'src\03a-SecureLogging.ps1')
  . (Join-Path $repoRoot 'src\16b-WebsiteProbe.ps1')
  $realHandlerFactory = (Get-Command New-WebsiteHttpHandler).ScriptBlock
  $realIpTest = (Get-Command Test-IsPublicIpAddress).ScriptBlock
  $snapshotSource = (Get-Command Get-WebsiteSnapshot).ScriptBlock.ToString()

  Write-Output '=== Website SSRF and Output Regression Checks ==='
  foreach ($ip in @(
    '', 'invalid', '0.0.0.0', '0.1.2.3', '10.0.0.1', '127.0.0.1', '127.1',
    '2130706433', '0x7f000001', '100.64.0.1', '100.127.255.255', '169.254.169.254',
    '168.63.129.16', '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.1',
    '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.19.255.255', '198.51.100.1',
    '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255',
    '::', '::1', '::127.0.0.1', '::10.0.0.1', '::ffff:127.0.0.1',
    '::ffff:169.254.169.254', '::ffff:168.63.129.16', 'fc00::1', 'fdff::1',
    'fe80::1', 'fec0::1', 'ff02::1', '64:ff9b::7f00:1', '64:ff9b:1::1',
    '100::1', '2001::1', '2001:2::1', '2001:10::1', '2001:db8::1',
    '2002:0a00:0001::1', '3ffe::1', '3fff::1', '3fff:fff::1',
    '4000::1', '2606:4700:4700::1111%1'
  )) {
    Assert-Equal "blocked IP $ip" $false (Test-IsPublicIpAddress $ip)
  }
  foreach ($ip in @(
    '8.8.8.8', '1.1.1.1', '9.9.9.9', '100.63.255.255', '100.128.0.0',
    '172.15.255.255', '172.32.0.0', '168.63.129.15', '168.63.129.17',
    '198.17.255.255', '198.20.0.0', '223.255.255.255',
    '2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450::1',
    '::ffff:8.8.8.8'
  )) {
    Assert-Equal "public IP $ip" $true (Test-IsPublicIpAddress $ip)
  }
  foreach ($ip in @('127.0.0.1','::ffff:127.0.0.1','168.63.129.16','64:ff9b::a00:1')) {
    Assert-Equal "literal host guard $ip" $false (Test-WebsiteHostIsPublic -HostName $ip).isPublic
  }
  Assert-Throws 'handler independently refuses a private address' {
    New-WebsiteHttpHandler -TargetUri 'https://example.com/' -Addresses @('8.8.8.8','127.0.0.1') -Cookies ([System.Net.CookieContainer]::new())
  }
  $safeHandler = & $realHandlerFactory -TargetUri 'https://example.com/' -Addresses @('8.8.8.8') -Cookies ([System.Net.CookieContainer]::new())
  try {
    $innerHandler = if ($safeHandler -is [System.Net.Http.DelegatingHandler]) { $safeHandler.InnerHandler } else { $safeHandler }
    Assert-Equal 'ambient proxies are disabled' $false $innerHandler.UseProxy
    Assert-Equal 'automatic redirects are disabled' $false $innerHandler.AllowAutoRedirect
    $socketsType = 'System.Net.Http.SocketsHttpHandler' -as [type]
    if ($socketsType -and $socketsType.GetProperty('ConnectCallback')) {
      Assert-Equal 'native pinned transport compiled successfully' 'AcsWebsitePinnedHttp' $safeHandler.GetType().Name
      Assert-Equal 'native TLS certificate validation is not overridden' $null $innerHandler.SslOptions.RemoteCertificateValidationCallback
    } else {
      Assert-Equal 'legacy transport remains available' 'HttpClientHandler' $safeHandler.GetType().Name
      Assert-Equal 'legacy TLS certificate validation is not overridden' $null $innerHandler.ServerCertificateCustomValidationCallback
    }
  } finally { $safeHandler.Dispose() }

  $fixtureCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class WebsiteProbeResponseSpec
{
    public int Status = 200;
    public string Body = "";
    public string ContentType = "text/html";
    public string Location;
    public string Cookie;
    public string Failure;
    public int ReadDelay;
    public int FailAfter = -1;
}

public sealed class WebsiteProbeTrackedStream : MemoryStream
{
    private readonly WebsiteProbeResponseSpec spec;
    public WebsiteProbeTrackedStream(WebsiteProbeResponseSpec spec) : base(Encoding.UTF8.GetBytes(spec.Body)) { this.spec = spec; }
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
    {
        if (spec.ReadDelay > 0) await Task.Delay(spec.ReadDelay, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (spec.FailAfter >= 0 && Position >= spec.FailAfter) throw new IOException("Synthetic body read failure.");
        if (spec.FailAfter >= 0) count = Math.Min(count, spec.FailAfter - (int)Position);
        int read = base.Read(buffer, offset, count);
        WebsiteProbeFixtures.BytesRead += read;
        return read;
    }
}

public static class WebsiteProbeFixtures
{
    public static readonly Queue<WebsiteProbeResponseSpec> Responses = new Queue<WebsiteProbeResponseSpec>();
    public static readonly List<string> Uris = new List<string>();
    public static readonly List<string> Hosts = new List<string>();
    public static readonly List<string> Cookies = new List<string>();
    public static int BytesRead;
    public static void Reset()
    {
        Responses.Clear(); Uris.Clear(); Hosts.Clear(); Cookies.Clear(); BytesRead = 0;
    }
    public static Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken token)
    {
        Uris.Add(request.RequestUri.AbsoluteUri);
        Hosts.Add(request.Headers.Host ?? request.RequestUri.Authority);
        IEnumerable<string> values;
        Cookies.Add(request.Headers.TryGetValues("Cookie", out values) ? String.Join("; ", values) : "");
        if (Responses.Count == 0) throw new InvalidOperationException("Unexpected fixture request.");
        var spec = Responses.Dequeue();
        if (spec.Failure == "socket") throw new HttpRequestException("Synthetic connection failure.", new SocketException((int)SocketError.ConnectionRefused));
        if (spec.Failure == "tls") throw new HttpRequestException("Synthetic TLS failure.", new AuthenticationException("Synthetic certificate failure."));
        var response = new HttpResponseMessage((HttpStatusCode)spec.Status);
        response.Content = new StreamContent(new WebsiteProbeTrackedStream(spec));
        if (spec.ContentType != null) response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(spec.ContentType);
        if (spec.Location != null) response.Headers.Location = new Uri(spec.Location, UriKind.RelativeOrAbsolute);
        if (spec.Cookie != null) response.Headers.TryAddWithoutValidation("Set-Cookie", spec.Cookie);
        return Task.FromResult(response);
    }
}

public sealed class WebsiteProbeMemoryHandler : HttpMessageHandler
{
    public bool AllowAutoRedirect { get; set; }
    public DecompressionMethods AutomaticDecompression { get; set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    { return WebsiteProbeFixtures.Send(request, token); }
}

public sealed class WebsiteProbeLiteralMemoryHandler : HttpClientHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    { return WebsiteProbeFixtures.Send(request, token); }
}

public static class WebsiteProbeTlsPolicy
{
    public static string Thumbprint;
    public static HttpClientHandler CreateHandler()
    {
        var handler = new HttpClientHandler();
        handler.UseProxy = false;
        handler.ServerCertificateCustomValidationCallback = ValidateRequest;
        return handler;
    }
    public static bool ValidateRequest(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
    { return Validate(null, certificate, chain, errors); }
    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        return certificate != null && certificate.GetCertHashString() == Thumbprint &&
            (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None;
    }
}
'@
  $typeParameters = @{ TypeDefinition = $fixtureCode; ErrorAction = 'Stop' }
  if ($PSVersionTable.PSVersion.Major -lt 6) { $typeParameters.ReferencedAssemblies = @('System.Net.Http','System','System.Core') }
  Add-Type @typeParameters

  $script:dnsFixtures = @{}
  $script:dnsCalls = [System.Collections.Generic.List[string]]::new()
  $script:factoryCalls = 0
  $script:fixtureMode = 'memory'
  $script:ownedLoopback = $false

  function Test-WebsiteHostIsPublic {
    param([string]$HostName, [int]$DnsTimeoutSec = 5)
    $script:dnsCalls.Add($HostName)
    $addresses = if ($script:dnsFixtures.ContainsKey($HostName)) { @($script:dnsFixtures[$HostName]) } else { @('8.8.8.8') }
    $public = $addresses.Count -gt 0
    foreach ($address in $addresses) {
      if ($script:ownedLoopback -and $address -eq '127.0.0.1') { continue }
      if (-not (& $script:realIpTest $address)) { $public = $false }
    }
    [pscustomobject]@{ isPublic = $public; addresses = $addresses; reason = if ($public) { $null } else { 'Host resolves to a non-public IP address.' } }
  }

  function New-WebsiteHttpHandler {
    param([uri]$TargetUri, [string[]]$Addresses, [System.Net.CookieContainer]$Cookies)
    $script:factoryCalls++
    if ($script:fixtureMode -eq 'memory') { return [WebsiteProbeMemoryHandler]::new() }
    if ($script:fixtureMode -eq 'literal-memory') {
      $handler = [WebsiteProbeLiteralMemoryHandler]::new()
      $handler.UseProxy = $false
      $handler.UseCookies = $false
      return $handler
    }
    if ($script:fixtureMode -ne 'loopback' -or -not $script:ownedLoopback -or $Addresses.Count -ne 1 -or $Addresses[0] -ne '127.0.0.1' -or $TargetUri.Port -notin $script:fixturePorts) {
      throw 'Live test transport is restricted to its owned loopback listeners.'
    }
    if ('AcsWebsitePinnedHttp' -as [type]) {
      $handler = [AcsWebsitePinnedHttp]::CreateHandler($TargetUri, $Addresses, $Cookies)
      $handler.InnerHandler.SslOptions.RemoteCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback][WebsiteProbeTlsPolicy]::Validate
      return $handler
    }
    $handler = [WebsiteProbeTlsPolicy]::CreateHandler()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    return $handler
  }

  function New-ResponseSpec {
    param([string]$Body = '', [int]$Status = 200, [string]$Location, [string]$ContentType = 'text/html', [string]$Cookie, [string]$Failure, [int]$ReadDelay = 0, [int]$FailAfter = -1)
    $spec = [WebsiteProbeResponseSpec]::new()
    $spec.Body = $Body; $spec.Status = $Status; $spec.Location = $Location
    $spec.ContentType = $ContentType; $spec.Cookie = $Cookie; $spec.Failure = $Failure
    $spec.ReadDelay = $ReadDelay; $spec.FailAfter = $FailAfter
    return $spec
  }

  function Reset-WebsiteFixture {
    param([WebsiteProbeResponseSpec[]]$Responses)
    [WebsiteProbeFixtures]::Reset()
    foreach ($response in $Responses) { [WebsiteProbeFixtures]::Responses.Enqueue($response) }
    $script:dnsCalls.Clear()
    $script:factoryCalls = 0
  }

  $baselineSnapshot = $null
  if ($BaselineFile) {
    $tokens = $null; $parseErrors = $null
    $baselineAst = [System.Management.Automation.Language.Parser]::ParseFile($BaselineFile, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Baseline source did not parse.' }
    $definition = $baselineAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-WebsiteSnapshot' }, $true)
    if (-not $definition) { throw 'Baseline website snapshot function was not found.' }
    $baselineSnapshot = $definition.Extent.Text.Replace('function Get-WebsiteSnapshot', 'function Get-BaselineWebsiteSnapshot')
    . ([scriptblock]::Create($baselineSnapshot.Replace('[System.Net.Http.HttpClientHandler]::new()', '[WebsiteProbeMemoryHandler]::new()')))
    $definition = $baselineAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-WebsiteProbeStatus' }, $true)
    . ([scriptblock]::Create($definition.Extent.Text.Replace('function Get-WebsiteProbeStatus', 'function Get-BaselineWebsiteProbeStatus').Replace('Get-WebsiteSnapshot -Url', 'Get-BaselineWebsiteSnapshot -Url')))
  }

  $snapshotFields = @('requestedUrl','finalUrl','reachable','statusCode','scheme','contentType','redirected','redirectChain','title','metaDescription','bodyExcerpt','visibleTextLength','nearEmpty','placeholderDetected','placeholderSignals','tlsError','error')
  $statusFields = @('domain','generatedAtUtc','checked','disabledReason','reachable','finalUrl','statusCode','scheme','contentType','redirected','redirectChain','title','metaDescription','bodyExcerpt','visibleTextLength','nearEmpty','placeholderDetected','placeholderSignals','tlsError','attempts','summary','error')
  $body = '<html><head><title>Example &amp; Co</title><meta content="We &amp; you" name="description"></head><body><script>secret script text</script><style>hidden style</style><p>A working public website with products, contact information, and useful customer guidance.</p></body></html>'

  foreach ($mode in @('memory','literal-memory')) {
    $script:fixtureMode = $mode
    foreach ($case in @(
      @{ name = 'HTML metadata'; responses = @(New-ResponseSpec -Body $body) },
      @{ name = 'empty HTML'; responses = @(New-ResponseSpec) },
      @{ name = 'no-content response'; responses = @(New-ResponseSpec -Status 204) },
      @{ name = 'binary response'; responses = @(New-ResponseSpec -Body 'binary' -ContentType 'application/pdf') },
      @{ name = 'plain text'; responses = @(New-ResponseSpec -Body ('Useful public text. ' * 10) -ContentType 'text/plain') },
      @{ name = 'client error'; responses = @(New-ResponseSpec -Body $body -Status 403) },
      @{ name = 'server error'; responses = @(New-ResponseSpec -Body $body -Status 503) },
      @{ name = 'relative redirect'; responses = @((New-ResponseSpec -Status 302 -Location '/landing?q=1#section'), (New-ResponseSpec -Body $body)) },
      @{ name = 'cross-host redirect'; responses = @((New-ResponseSpec -Status 301 -Location 'https://www.example.com/landing'), (New-ResponseSpec -Body $body)) },
      @{ name = 'title/description/excerpt caps'; responses = @(New-ResponseSpec -Body ('<title>' + ('t' * 250) + '</title><meta name="description" content="' + ('d' * 350) + '"><p>' + ('x' * 150000) + '</p>')) }
    )) {
      Reset-WebsiteFixture $case.responses
      $actual = Get-WebsiteSnapshot -Url 'https://example.com/'
      Assert-Equal "$mode $($case.name) snapshot fields" ($snapshotFields -join ',') ($actual.PSObject.Properties.Name -join ',')
      if ($baselineSnapshot) {
        Reset-WebsiteFixture $case.responses
        $expected = Get-BaselineWebsiteSnapshot -Url 'https://example.com/'
        Assert-Equal "$mode $($case.name) preserves every snapshot value" (ConvertTo-ComparableJson $expected) (ConvertTo-ComparableJson $actual)
      }
      Reset-WebsiteFixture $case.responses
      $actualStatus = Get-WebsiteProbeStatus -Domain 'example.com'
      Assert-Equal "$mode $($case.name) API fields" ($statusFields -join ',') ($actualStatus.PSObject.Properties.Name -join ',')
      Assert-Equal "$mode $($case.name) retains the timestamp" $true ([DateTime]::Parse($actualStatus.generatedAtUtc).ToUniversalTime() -le [DateTime]::UtcNow)
      if ($baselineSnapshot) {
        Reset-WebsiteFixture $case.responses
        $expectedStatus = Get-BaselineWebsiteProbeStatus -Domain 'example.com'
        Assert-Equal "$mode $($case.name) preserves every API value" (ConvertTo-ComparableJson $expectedStatus) (ConvertTo-ComparableJson $actualStatus)
      }
    }

    Reset-WebsiteFixture @(New-ResponseSpec -Body $body)
    $result = Get-WebsiteSnapshot -Url 'https://example.com/'
    Assert-Equal "$mode title decoding" 'Example & Co' $result.title
    Assert-Equal "$mode description decoding and attribute order" 'We & you' $result.metaDescription
    Assert-Equal "$mode script/style text is excluded" $false $result.bodyExcerpt.Contains('secret')
    Assert-Equal "$mode meaningful page remains reachable" $true $result.reachable

    foreach ($status in @(301,302,303,307,308)) {
      Reset-WebsiteFixture @((New-ResponseSpec -Status $status -Location '/final'), (New-ResponseSpec -Body $body))
      $result = Get-WebsiteSnapshot -Url 'http://example.com/'
      Assert-Equal "$mode follows $status manually" 2 ([WebsiteProbeFixtures]::Uris.Count)
      Assert-Equal "$mode rechecks $status destination DNS" 2 $script:dnsCalls.Count
      Assert-Equal "$mode retains $status redirect chain" $status $result.redirectChain[0].status
      Assert-Equal "$mode retains $status final URL" 'http://example.com/final' $result.finalUrl
    }

    foreach ($target in @('http://127.0.0.1/','http://169.254.169.254/','http://168.63.129.16/','http://[::1]/','http://[::ffff:127.0.0.1]/','http://[64:ff9b::a00:1]/')) {
      $hostName = ([uri]$target).IdnHost
      $script:dnsFixtures[$hostName] = @($hostName)
      Reset-WebsiteFixture @(New-ResponseSpec -Status 302 -Location $target)
      $result = Get-WebsiteSnapshot -Url 'http://example.com/'
      Assert-Equal "$mode unsafe redirect refused: $target" $false $result.reachable
      Assert-Equal "$mode unsafe redirect makes no second request: $target" 1 ([WebsiteProbeFixtures]::Uris.Count)
    }
    foreach ($target in @('ftp://example.com/','http://example.com:8080/','https://user:password@example.com/')) {
      Reset-WebsiteFixture @(New-ResponseSpec -Status 302 -Location $target)
      $result = Get-WebsiteSnapshot -Url 'http://example.com/'
      Assert-Equal "$mode disallowed redirect $target" $false $result.reachable
      Assert-Equal "$mode disallowed redirect sends no second request" 1 ([WebsiteProbeFixtures]::Uris.Count)
    }
    $script:dnsFixtures['mixed.example.com'] = @('8.8.8.8','10.0.0.1')
    $script:dnsFixtures['empty.example.com'] = @()
    foreach ($domain in @('mixed.example.com','empty.example.com')) {
      Reset-WebsiteFixture @()
      $result = Get-WebsiteSnapshot -Url "https://$domain/"
      Assert-Equal "$mode mixed/empty DNS answer is refused" $false $result.reachable
      Assert-Equal "$mode no transport created for mixed/empty DNS" 0 $script:factoryCalls
    }
    foreach ($url in @('/relative','ftp://example.com/','http://example.com:1234/','https://user:password@example.com/')) {
      Reset-WebsiteFixture @()
      Assert-Equal "$mode invalid starting URL $url" $false (Get-WebsiteSnapshot -Url $url).reachable
      Assert-Equal "$mode invalid starting URL never sends a request" 0 ([WebsiteProbeFixtures]::Uris.Count)
    }

    foreach ($marker in @{
      'under construction' = 'underConstruction'; 'coming soon' = 'comingSoon'
      'domain is for sale' = 'domainForSale'; 'buy this domain' = 'domainForSale'
      'this domain is parked' = 'parked'; 'domain parking' = 'parked'; 'parked free' = 'parked'
      'future home of' = 'placeholder'; 'default web page' = 'defaultPage'; 'welcome to nginx' = 'defaultPage'
      'it works!' = 'defaultPage'; 'apache2 default' = 'defaultPage'; 'iis windows server' = 'defaultPage'
      'account suspended' = 'suspended'; 'site not configured' = 'notConfigured'
    }.GetEnumerator()) {
      Reset-WebsiteFixture @(New-ResponseSpec -Body ("<title>$($marker.Key)</title><p>" + ('body text ' * 10) + '</p>'))
      $result = Get-WebsiteProbeStatus -Domain 'example.com'
      Assert-Equal "$mode placeholder marker $($marker.Key)" $marker.Value $result.placeholderSignals[0]
      Assert-Equal "$mode placeholder summary $($marker.Key)" 'PlaceholderContent' $result.summary
    }
    foreach ($length in @(49,50)) {
      Reset-WebsiteFixture @(New-ResponseSpec -Body ('x' * $length))
      Assert-Equal "$mode near-empty boundary $length" ($length -lt 50) (Get-WebsiteSnapshot -Url 'http://example.com/').nearEmpty
    }
    Reset-WebsiteFixture @(New-ResponseSpec -Body ('x' * 30000))
    $result = Get-WebsiteSnapshot -Url 'http://example.com/' -MaxBytes 12345
    Assert-Equal "$mode hard cap applies to bytes actually read" 12345 ([WebsiteProbeFixtures]::BytesRead)
    Assert-Equal "$mode body length matches cap" 12345 $result.visibleTextLength
    Assert-Equal "$mode excerpt cap" 400 $result.bodyExcerpt.Length

    Reset-WebsiteFixture @(New-ResponseSpec -Body $body -FailAfter 100)
    $result = Get-WebsiteProbeStatus -Domain 'example.com'
    Assert-Equal "$mode partial body error is explicit in API output" 'Response body read failed.' $result.error
    Assert-Equal "$mode metadata already received is retained" 'Example & Co' $result.title
    Reset-WebsiteFixture @(New-ResponseSpec -Body $body -FailAfter 0)
    $result = Get-WebsiteSnapshot -Url 'http://example.com/'
    Assert-Equal "$mode failed body is not misreported as empty" $null $result.nearEmpty
    Reset-WebsiteFixture @(New-ResponseSpec -Body $body -ReadDelay 2000)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Get-WebsiteSnapshot -Url 'http://example.com/' -TimeoutSec 1
    Assert-Equal "$mode body timeout is explicit" 'Response body read timed out.' $result.error
    Assert-Equal "$mode whole-operation timeout remains bounded" $true ($timer.Elapsed.TotalSeconds -lt 2)

    Reset-WebsiteFixture @((New-ResponseSpec -Failure tls), (New-ResponseSpec -Failure socket), (New-ResponseSpec -Body $body))
    $result = Get-WebsiteProbeStatus -Domain 'example.com'
    Assert-Equal "$mode HTTPS/apex/www/HTTP fallback preserved" 3 $result.attempts.Count
    Assert-Equal "$mode HTTP fallback final URL preserved" 'http://example.com/' $result.finalUrl
    Reset-WebsiteFixture @((New-ResponseSpec -Failure tls), (New-ResponseSpec -Body $body))
    $result = Get-WebsiteProbeStatus -Domain 'www.example.com'
    Assert-Equal "$mode no www.www candidate" 2 $result.attempts.Count
    Assert-Equal "$mode www fallback URL" 'http://www.example.com/' $result.finalUrl

    $script:dnsFixtures['example.com'] = @('8.8.8.8','1.1.1.1')
    if ($mode -eq 'literal-memory') {
      Reset-WebsiteFixture @((New-ResponseSpec -Failure socket), (New-ResponseSpec -Body $body))
      $result = Get-WebsiteSnapshot -Url 'https://example.com/path?q=one'
      Assert-Equal 'legacy tries the second validated IP after connection refusal' $true $result.reachable
      Assert-Equal 'legacy preserves original Host on both addresses' 'example.com,example.com' ([WebsiteProbeFixtures]::Hosts -join ',')
      Assert-Equal 'legacy transport URI contains only pinned IPs' 'https://8.8.8.8/path?q=one,https://1.1.1.1/path?q=one' ([WebsiteProbeFixtures]::Uris -join ',')
      Assert-Equal 'transport-only IP does not replace output URL' 'https://example.com/path?q=one' $result.finalUrl
      Reset-WebsiteFixture @((New-ResponseSpec -Status 302 -Location '/final' -Cookie 'session=fixture; Path=/; HttpOnly'), (New-ResponseSpec -Body $body))
      $null = Get-WebsiteSnapshot -Url 'https://example.com/'
      Assert-Equal 'legacy cookies remain scoped to original hostname' 'session=fixture' ([WebsiteProbeFixtures]::Cookies[1])
      Reset-WebsiteFixture @(New-ResponseSpec -Failure tls)
      $result = Get-WebsiteSnapshot -Url 'https://example.com/'
      Assert-Equal 'legacy TLS errors do not trigger another-address retry' 1 ([WebsiteProbeFixtures]::Uris.Count)
      Assert-Equal 'legacy retains TLS error classification' $true $result.tlsError
    }
    $script:dnsFixtures.Remove('example.com')
  }

  Reset-WebsiteFixture @()
  $env:ACS_DISABLE_WEBSITE_PROBE = '1'
  $disabled = Get-WebsiteProbeStatus -Domain 'example.com'
  Assert-Equal 'existing opt-out keeps the complete API shape' ($statusFields -join ',') ($disabled.PSObject.Properties.Name -join ',')
  Assert-Equal 'existing opt-out is still neutral' 'Disabled' $disabled.summary
  Assert-Equal 'existing opt-out performs no DNS or HTTP work' 0 $script:dnsCalls.Count
  $env:ACS_DISABLE_WEBSITE_PROBE = $null

  $serverCode = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class WebsiteProbeLoopbackServer : IDisposable
{
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new CancellationTokenSource();
    private readonly ConcurrentBag<Task> clients = new ConcurrentBag<Task>();
    private readonly X509Certificate2 certificate;
    private readonly Task accepting;
    public string Body = "<title>Loopback fixture</title><p>A complete public website fixture with enough visible text to be non-empty.</p>";
    public string EncodingName;
    public bool Chunked;
    public int DelayMs;
    public int Connections;
    public readonly ConcurrentQueue<string> Hosts = new ConcurrentQueue<string>();
    public readonly ConcurrentQueue<string> Cookies = new ConcurrentQueue<string>();
    public readonly ConcurrentQueue<string> Errors = new ConcurrentQueue<string>();
    public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
    public WebsiteProbeLoopbackServer(X509Certificate2 certificate) : this(certificate, 0, false) { }
    public WebsiteProbeLoopbackServer(X509Certificate2 certificate, int port, bool ipv6)
    {
        this.certificate = certificate;
        listener = new TcpListener(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, port);
        listener.Start();
        accepting = Accept();
    }
    private async Task Accept()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                Interlocked.Increment(ref Connections);
                clients.Add(Serve(client));
            }
        }
        catch (ObjectDisposedException) { if (!stop.IsCancellationRequested) throw; }
        catch (SocketException) { if (!stop.IsCancellationRequested) throw; }
    }
    private async Task Serve(TcpClient client)
    {
        client.NoDelay = true;
        using (client)
        using (stop.Token.Register(() => client.Close()))
        {
            Stream stream = client.GetStream();
            try
            {
                if (certificate != null)
                {
                    var ssl = new SslStream(stream, false);
                    stream = ssl;
                    await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false).ConfigureAwait(false);
                }
                var reader = new StreamReader(stream, Encoding.ASCII, false, 8192, true);
                while (!stop.IsCancellationRequested)
                {
                    string request = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (request == null) break;
                    string path = request.Split(' ')[1];
                    string host = "", cookie = "", line;
                    while (!String.IsNullOrEmpty(line = await reader.ReadLineAsync().ConfigureAwait(false)))
                    {
                        if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) host = line.Substring(5).Trim();
                        if (line.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase)) cookie = line.Substring(7).Trim();
                    }
                    Hosts.Enqueue(host); Cookies.Enqueue(cookie);
                    if (DelayMs > 0) await Task.Delay(DelayMs, stop.Token).ConfigureAwait(false);
                    bool redirect = path == "/redirect" || path == "/cookie-redirect";
                    byte[] body = redirect ? new byte[0] : Encoding.UTF8.GetBytes(Body);
                    var header = new StringBuilder(redirect ? "HTTP/1.1 302 Found\r\nLocation: /page\r\n" : "HTTP/1.1 200 OK\r\n");
                    if (path == "/cookie-redirect") header.Append("Set-Cookie: session=fixture; Path=/; HttpOnly\r\n");
                    if (!redirect && !String.IsNullOrEmpty(EncodingName))
                    {
                        using (var output = new MemoryStream())
                        {
                            using (Stream compressor = EncodingName == "gzip" ? (Stream)new GZipStream(output, CompressionMode.Compress, true) : new DeflateStream(output, CompressionMode.Compress, true))
                                compressor.Write(body, 0, body.Length);
                            body = output.ToArray();
                        }
                        header.Append("Content-Encoding: ").Append(EncodingName).Append("\r\n");
                    }
                    header.Append("Content-Type: text/html; charset=utf-8\r\n");
                    if (Chunked && !redirect) header.Append("Transfer-Encoding: chunked\r\n");
                    else header.Append("Content-Length: ").Append(body.Length).Append("\r\n");
                    header.Append("\r\n");
                    byte[] bytes = Encoding.ASCII.GetBytes(header.ToString());
                    await stream.WriteAsync(bytes, 0, bytes.Length, stop.Token).ConfigureAwait(false);
                    if (Chunked && !redirect)
                    {
                        bytes = Encoding.ASCII.GetBytes(body.Length.ToString("x") + "\r\n");
                        await stream.WriteAsync(bytes, 0, bytes.Length, stop.Token).ConfigureAwait(false);
                        await stream.WriteAsync(body, 0, body.Length, stop.Token).ConfigureAwait(false);
                        bytes = Encoding.ASCII.GetBytes("\r\n0\r\n\r\n");
                        await stream.WriteAsync(bytes, 0, bytes.Length, stop.Token).ConfigureAwait(false);
                    }
                    else if (body.Length > 0) await stream.WriteAsync(body, 0, body.Length, stop.Token).ConfigureAwait(false);
                    await stream.FlushAsync(stop.Token).ConfigureAwait(false);
                }
            }
            catch (AuthenticationException) { }
            catch (IOException) { }
            catch (OperationCanceledException) { if (!stop.IsCancellationRequested) throw; }
            catch (ObjectDisposedException) { if (!stop.IsCancellationRequested) throw; }
            catch (Exception error) { Errors.Enqueue(error.GetType().Name); }
            finally { stream.Dispose(); }
        }
    }
    public void Dispose()
    {
        stop.Cancel(); listener.Stop();
        accepting.GetAwaiter().GetResult();
        Task.WaitAll(clients.ToArray(), 5000);
        stop.Dispose();
    }
}
'@
  $typeParameters.TypeDefinition = $serverCode
  Add-Type @typeParameters

  $rsa = if ($PSVersionTable.PSVersion.Major -lt 6) {
    $key = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $key.PersistKeyInCsp = $false
    $key
  } else { [System.Security.Cryptography.RSA]::Create(2048) }
  $certificate = $null; $temporaryCertificate = $null; $httpServer = $null; $tlsServer = $null; $ipv6Server = $null
  try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost'); $san.AddDnsName('public-website.test')
    $san.AddIPAddress([System.Net.IPAddress]::Loopback)
    $request.CertificateExtensions.Add($san.Build())
    $temporaryCertificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
    $pfx = $temporaryCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
    if ('System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]) {
      $certificate = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12($pfx, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
    } else {
      $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, [string]$null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
    }
    [WebsiteProbeTlsPolicy]::Thumbprint = $certificate.Thumbprint
    $httpServer = [WebsiteProbeLoopbackServer]::new($null)
    $tlsServer = [WebsiteProbeLoopbackServer]::new($certificate)
    $script:fixturePorts = @($httpServer.Port, $tlsServer.Port)
    $script:ownedLoopback = $true
    $script:fixtureMode = 'loopback'
    $script:dnsFixtures = @{}
    foreach ($hostName in @('127.0.0.1','localhost','public-website.test','does-not-resolve.invalid','wrong-website.test')) { $script:dnsFixtures[$hostName] = @('127.0.0.1') }
    # Permit only the explicitly owned ephemeral ports in an in-memory clone.
    # The production function's standard-port checks were tested above unchanged.
    $testSource = $snapshotSource.Replace('$current.Port -ne 80 -and $current.Port -ne 443', '$current.Port -notin $script:fixturePorts')
    Set-Item -Path Function:\Get-WebsiteSnapshot -Value ([scriptblock]::Create($testSource))
    if ($baselineSnapshot) {
      $liveBaseline = $baselineSnapshot.Replace('[System.Net.Http.HttpClientHandler]::new()', '[WebsiteProbeTlsPolicy]::CreateHandler()').Replace('$current.Port -ne 80 -and $current.Port -ne 443', '$current.Port -notin $script:fixturePorts')
      . ([scriptblock]::Create($liveBaseline))
    }

    Write-Output '=== Owned Loopback HTTP/TLS, Cookies, Compression and Pooling ==='
    foreach ($serverCase in @(
      @{ server = $httpServer; scheme = 'http' },
      @{ server = $tlsServer; scheme = 'https' }
    )) {
      $server = $serverCase.server
      foreach ($encoding in @($null,'gzip','deflate')) {
        foreach ($chunked in @($false,$true)) {
          $server.EncodingName = $encoding; $server.Chunked = $chunked
          $url = "$($serverCase.scheme)://127.0.0.1:$($server.Port)/page"
          $actual = Get-WebsiteSnapshot -Url $url
          Assert-Equal "$($serverCase.scheme) $encoding chunked=$chunked is reachable" $true $actual.reachable
          Assert-Equal "$($serverCase.scheme) $encoding returns no read/TLS error" $null $actual.error
          Assert-Equal "$($serverCase.scheme) $encoding retains decompressed title" 'Loopback fixture' $actual.title
          if ($baselineSnapshot) {
            $expected = Get-BaselineWebsiteSnapshot -Url $url
            Assert-Equal "$($serverCase.scheme) $encoding chunked=$chunked preserves every live value" (ConvertTo-ComparableJson $expected) (ConvertTo-ComparableJson $actual)
          }
        }
      }
      $server.EncodingName = $null; $server.Chunked = $false
      $before = $server.Connections
      $result = Get-WebsiteSnapshot -Url "$($serverCase.scheme)://127.0.0.1:$($server.Port)/cookie-redirect"
      Assert-Equal "$($serverCase.scheme) redirect remains reachable" $true $result.reachable
      Assert-Equal "$($serverCase.scheme) redirect retains a single connection" 1 ($server.Connections - $before)
      Assert-Equal "$($serverCase.scheme) cookies survive redirects" 'session=fixture' ($server.Cookies.ToArray()[-1])
    }
    $result = Get-WebsiteSnapshot -Url "http://does-not-resolve.invalid:$($httpServer.Port)/page"
    Assert-Equal 'connection pinning avoids a second DNS lookup' $true $result.reachable
    $result = Get-WebsiteSnapshot -Url "https://public-website.test:$($tlsServer.Port)/page"
    Assert-Equal 'original hostname remains the TLS validation target' $true $result.reachable
    Assert-Equal 'original hostname remains the HTTP Host header' "public-website.test:$($tlsServer.Port)" ($tlsServer.Hosts.ToArray()[-1])
    $result = Get-WebsiteSnapshot -Url "https://wrong-website.test:$($tlsServer.Port)/page"
    Assert-Equal 'a mismatched TLS certificate is still rejected' $true $result.tlsError
    Assert-Equal 'a mismatched TLS certificate is not reachable' $false $result.reachable

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($name in @('Get-WebsiteSnapshot','Format-WebsiteText','New-WebsiteHttpHandler')) {
      $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, (Get-Command $name).Definition))
    }
    $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Test-WebsiteHostIsPublic', 'param($HostName) [pscustomobject]@{ isPublic = $true; addresses = @("127.0.0.1"); reason = $null }'))
    foreach ($entry in @{
      fixtureMode = 'loopback'; ownedLoopback = $true; fixturePorts = $script:fixturePorts
    }.GetEnumerator()) {
      $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($entry.Key, $entry.Value, 'Owned loopback fixture state'))
    }
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 8, $iss, $Host)
    $pending = [System.Collections.Generic.List[object]]::new()
    try {
      $pool.Open()
      $url = "https://public-website.test:$($tlsServer.Port)/page"
      $expected = Get-WebsiteSnapshot -Url $url
      for ($index = 0; $index -lt 24; $index++) {
        $worker = [System.Management.Automation.PowerShell]::Create()
        $worker.RunspacePool = $pool
        $null = $worker.AddScript('Get-WebsiteSnapshot -Url $args[0]').AddArgument($url)
        $pending.Add([pscustomobject]@{ worker = $worker; handle = $worker.BeginInvoke() })
      }
      foreach ($item in $pending) {
        $output = $item.worker.EndInvoke($item.handle)
        Assert-Equal 'concurrent runspace produces exactly one snapshot' 1 $output.Count
        Assert-Equal 'concurrent runspace retains every snapshot field/value' (ConvertTo-ComparableJson $expected) (ConvertTo-ComparableJson $output[0])
        Assert-Equal 'concurrent runspace has no missing-function/delegate errors' 0 $item.worker.Streams.Error.Count
      }
    } finally {
      foreach ($item in $pending) { $item.worker.Dispose() }
      $pool.Dispose()
    }

    if ($baselineSnapshot) {
      Write-Output '=== Baseline Performance Comparison ==='
      $httpServer.Body = '<title>Performance fixture</title><p>' + ('Useful public website information. ' * 1800) + '</p>'
      if ([System.Net.Sockets.Socket]::OSSupportsIPv6) {
        $ipv6Server = [WebsiteProbeLoopbackServer]::new($null, $httpServer.Port, $true)
        $ipv6Server.Body = $httpServer.Body
      }
      foreach ($address in [System.Net.Dns]::GetHostAddresses('localhost')) {
        if (-not $address.Equals([System.Net.IPAddress]::Loopback) -and -not ($ipv6Server -and $address.Equals([System.Net.IPAddress]::IPv6Loopback))) {
          throw 'The baseline localhost resolver returned an address not owned by this fixture.'
        }
      }
      $url = "http://localhost:$($httpServer.Port)/page"
      $oldSamples = [System.Collections.Generic.List[double]]::new()
      $newSamples = [System.Collections.Generic.List[double]]::new()
      for ($index = 0; $index -lt 220; $index++) {
        foreach ($name in $(if ($index % 2 -eq 0) { @('Get-BaselineWebsiteSnapshot','Get-WebsiteSnapshot') } else { @('Get-WebsiteSnapshot','Get-BaselineWebsiteSnapshot') })) {
          $timer = [System.Diagnostics.Stopwatch]::StartNew()
          $result = & $name -Url $url
          $timer.Stop()
          Assert-Equal 'performance sample retains output data' 'Performance fixture' $result.title
          if ($index -ge 20) {
            if ($name -eq 'Get-WebsiteSnapshot') { $newSamples.Add($timer.Elapsed.TotalMilliseconds) } else { $oldSamples.Add($timer.Elapsed.TotalMilliseconds) }
          }
        }
      }
      $oldSorted = @($oldSamples | Sort-Object); $newSorted = @($newSamples | Sort-Object)
      $oldMedian = $oldSorted[100]; $newMedian = $newSorted[100]
      $oldP95 = $oldSorted[189]; $newP95 = $newSorted[189]
      Write-Output ('  Median: baseline {0:N2} ms; pinned {1:N2} ms ({2:N1}% change)' -f $oldMedian,$newMedian,(100 * ($newMedian / $oldMedian - 1)))
      Write-Output ('  P95:    baseline {0:N2} ms; pinned {1:N2} ms' -f $oldP95,$newP95)
      Assert-Equal 'median stays within 10% plus 1 ms measurement noise' $true ($newMedian -le $oldMedian * 1.10 + 1)
      Assert-Equal 'p95 stays within 20% plus 2 ms scheduler noise' $true ($newP95 -le $oldP95 * 1.20 + 2)
    }
    Assert-Equal 'HTTP fixture had no unexpected server errors' 0 $httpServer.Errors.Count
    Assert-Equal 'TLS fixture had no unexpected server errors' 0 $tlsServer.Errors.Count
  } finally {
    if ($httpServer) { $httpServer.Dispose() }
    if ($ipv6Server) { $ipv6Server.Dispose() }
    if ($tlsServer) { $tlsServer.Dispose() }
    if ($certificate) { $certificate.Dispose() }
    if ($temporaryCertificate) { $temporaryCertificate.Dispose() }
    $rsa.Dispose()
  }
  Write-Output ("PASS: {0} website security, output, transport, and performance checks ({1})." -f $checks,$PSVersionTable.PSVersion)
} finally {
  foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
