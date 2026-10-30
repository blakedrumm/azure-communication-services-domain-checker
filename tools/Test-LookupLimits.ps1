# Offline boundary, authentication, handler, and browser-source regression checks.
# Usage: pwsh -NoProfile -File .\tools\Test-LookupLimits.ps1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$checks = 0

class LookupTestHttpException : System.Exception {
  [object]$Response
  LookupTestHttpException([int]$StatusCode) : base('Synthetic Graph failure') {
    $this.Response = [pscustomobject]@{ StatusCode = $StatusCode }
  }
}

function Assert-Equal {
  param([string]$Name, $Expected, $Actual)
  if ($Expected -ne $Actual) { throw "$Name expected '$Expected', got '$Actual'." }
  $script:checks++
  Write-Host "  PASS  $Name" -ForegroundColor Green
}

function New-TestContext {
  param([string]$Path = '/api/base', [hashtable]$Query = @{}, [hashtable]$Headers = @{}, [string]$Ip = '127.0.0.1', [switch]$HttpHeaders)
  $queryString = [System.Collections.Specialized.NameValueCollection]::new()
  foreach ($key in $Query.Keys) { $queryString[$key] = [string]$Query[$key] }
  $requestHeaders = @{}
  if ($HttpHeaders) { $requestHeaders = [System.Net.WebHeaderCollection]::new() }
  foreach ($key in $Headers.Keys) { $requestHeaders[$key] = [string]$Headers[$key] }
  return [pscustomobject]@{
    Request = [pscustomobject]@{
      Url = [uri]("http://localhost" + $Path)
      HttpMethod = 'GET'
      QueryString = $queryString
      Headers = $requestHeaders
      RemoteEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Ip), 12345)
    }
    Response = [pscustomobject]@{ StatusCode = 0; Json = $null; Headers = @{}; _extraHeaders = @{} }
  }
}

function Invoke-TestHandler {
  param($Context)
  & $script:requestHandler $Context '' $script:domainLocks '' '' '' ''
  return $Context.Response
}

function Write-Json {
  param($Context, $Object, [int]$StatusCode = 200)
  $Context.Response.StatusCode = $StatusCode
  $Context.Response.Json = $Object
}

function Invoke-OutboundHttp {
  param([string]$Uri, [hashtable]$Headers, [int]$TimeoutSec, [switch]$ReturnRaw)
  $script:graphCalls++
  Assert-Equal 'verification uses only the fixed Graph profile endpoint' 'https://graph.microsoft.com/v1.0/me?$select=id' $Uri
  if ($script:graphUnavailable) { throw [System.Net.WebException]::new('Synthetic network failure') }
  if ($Headers.Authorization -ne 'Bearer synthetic-valid-token') { throw [LookupTestHttpException]::new(401) }
  return [pscustomobject]@{ StatusCode = 200 }
}

$savedEnvironment = @{}
foreach ($name in @('ACS_RATE_LIMIT_PER_MIN', 'ACS_API_KEY', 'ACS_API_KEYS', 'ACS_TRUSTED_PROXIES', 'ACS_ENABLE_ANON_METRICS', 'ACS_LOG_LEVEL', 'ACS_LOG_FILE')) {
  $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
  $env:ACS_RATE_LIMIT_PER_MIN = '1'
  $env:ACS_API_KEY = $null
  $env:ACS_API_KEYS = $null
  $env:ACS_TRUSTED_PROXIES = $null
  $env:ACS_ENABLE_ANON_METRICS = '0'
  $env:ACS_LOG_LEVEL = 'Critical'
  $env:ACS_LOG_FILE = $null
  $AcsAnonMetricsEnabled = $false
  $script:AppVersion = 'test'
  . (Join-Path $repoRoot 'src\01-DomainParsing.ps1')
  . (Join-Path $repoRoot 'src\03a-SecureLogging.ps1')
  . (Join-Path $repoRoot 'src\10-SessionCookies.ps1')
  . (Join-Path $repoRoot 'src\13-InputValidation.ps1')
  $TestDomain = 'example.com'
  . (Join-Path $repoRoot 'src\08-ServerStartup.ps1')
  . (Join-Path $repoRoot 'src\15-RequestUtilities.ps1')
  . (Join-Path $repoRoot 'src\23-RequestHandler.ps1')
  $script:requestHandler = [scriptblock]::Create($handlerScript)
  $AcsRateLimitStore = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
  $AcsRateLimitLock = [object]::new()
  $AcsLookupActionStore = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
  $script:domainLocks = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Threading.SemaphoreSlim]]::new()
  $script:graphCalls = 0
  $script:graphUnavailable = $false

  $lookupStub = {
    param($Domain, $SpfRequiredInclude, $AdditionalDkimSelectors, $Dkim1Override, $Dkim2Override, $RecordType, $Regions, $MaxResolvers, $TimeoutMs, $ExpectedValue, $CustomResolvers, $ValidateResolvers, $RequireDmarcEnforcement, $PageLink)
    return @{ domain = $Domain }
  }
  foreach ($name in @('Get-DnsBaseStatus', 'Get-DnsMxStatus', 'Get-DnsRecordsStatus', 'Get-DomainRegistrationStatus', 'Get-DnsDmarcStatus', 'Get-DnsDkimStatus', 'Get-DnsCnameStatus', 'Get-DnsReputationStatus', 'Get-WebsiteProbeStatus', 'Get-NameserverTxtStatus', 'Get-DnsPropagationStatus', 'Get-AcsEmailQuotaStatus', 'Get-AcsDnsStatus')) {
    Set-Item -Path "Function:\$name" -Value $lookupStub
  }

  Write-Host '=== Server Lookup Action Limits ===' -ForegroundColor Cyan
  $plain = New-TestContext
  Assert-Equal 'first unbatched request is allowed' $true (Test-RateLimit -Context $plain).allowed
  Assert-Equal 'configured unbatched abuse guard remains enforced' $false (Test-RateLimit -Context $plain).allowed

  $anonymous = Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 100 })
  Assert-Equal 'anonymous action accepts exactly 100 websites' 200 $anonymous.StatusCode
  Assert-Equal 'anonymous admission reports a 100-website limit' 100 $anonymous.Json.maxDomains
  Assert-Equal 'anonymous admission does not contact Graph' 0 $script:graphCalls
  Assert-Equal 'anonymous action rejects 101 websites' 429 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 101 })).StatusCode
  Assert-Equal 'employee analytics headers cannot grant elevated capacity' 429 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1000 } -Headers @{ 'X-ACS-Auth-Is-Microsoft' = '1' })).StatusCode

  foreach ($count in @('0', '-1', '', 'not-a-number', '2147483648')) {
    Assert-Equal "invalid website count '$count' is rejected" 400 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = $count })).StatusCode
  }

  $signed = Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1000 } -Headers @{ Authorization = 'Bearer synthetic-valid-token' } -HttpHeaders)
  Assert-Equal 'verified Microsoft action accepts exactly 1000 websites' 200 $signed.StatusCode
  Assert-Equal 'verified action reports the 1000-website limit' 1000 $signed.Json.maxDomains
  Assert-Equal 'elevated admission validates the token once' 1 $script:graphCalls
  Assert-Equal 'verified action rejects 1001 websites' 429 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1001 } -Headers @{ Authorization = 'Bearer synthetic-valid-token' })).StatusCode
  Assert-Equal 'invalid Microsoft token cannot grant 1000 websites' 401 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1000 } -Headers @{ Authorization = 'Bearer invalid-token' })).StatusCode
  $script:graphUnavailable = $true
  Assert-Equal 'verification outages are explicit and fail closed' 502 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1000 } -Headers @{ Authorization = 'Bearer synthetic-valid-token' })).StatusCode
  $script:graphUnavailable = $false

  foreach ($batch in @(
    @{ name = 'anonymous'; size = 100; id = $anonymous.Json.actionId },
    @{ name = 'Microsoft'; size = 1000; id = $signed.Json.actionId }
  )) {
    $blocked = 0
    for ($index = 1; $index -le $batch.size; $index++) {
      $context = New-TestContext -Query @{ domain = "site$index.example.com" } -Headers @{ 'X-ACS-Lookup-Action' = $batch.id } -HttpHeaders:($index % 2 -eq 0)
      for ($check = 0; $check -lt 11; $check++) {
        if (-not (Test-RateLimit -Context $context -DomainLookup).allowed) { $blocked++ }
      }
    }
    Assert-Equal "$($batch.name) batch completes all $($batch.size * 11) internal checks despite an exhausted IP bucket" 0 $blocked
    Assert-Equal "$($batch.name) batch counts each website once" $batch.size $AcsLookupActionStore[$batch.id].domains.Count
    $overflow = New-TestContext -Query @{ domain = 'overflow.example.com' } -Headers @{ 'X-ACS-Lookup-Action' = $batch.id }
    Assert-Equal "$($batch.name) action cannot admit one extra website" $false (Test-RateLimit -Context $overflow -DomainLookup).allowed
    $duplicate = New-TestContext -Query @{ domain = 'https://SITE1.example.com/path' } -Headers @{ 'X-ACS-Lookup-Action' = $batch.id }
    Assert-Equal 'a normalized duplicate is allowed even at the boundary' $true (Test-RateLimit -Context $duplicate -DomainLookup).allowed
  }

  $routes = @('/api/base', '/api/mx', '/api/records', '/api/whois', '/api/dmarc', '/api/dkim', '/api/cname', '/api/reputation', '/api/website', '/api/nameservers', '/api/propagation', '/api/email-quota', '/dns')
  foreach ($path in $routes) {
    $context = New-TestContext -Path $path -Query @{ domain = 'site1.example.com' } -Headers @{ 'X-ACS-Lookup-Action' = $anonymous.Json.actionId }
    Assert-Equal "$path honors admitted actions" 200 (Invoke-TestHandler $context).StatusCode
    $context.Request.Headers['X-ACS-Lookup-Action'] = 'not-an-action'
    Assert-Equal "$path reports invalid actions without falling back to IP limits" 410 (Invoke-TestHandler $context).StatusCode
  }

  $wrongIp = New-TestContext -Query @{ domain = 'site1.example.com' } -Headers @{ 'X-ACS-Lookup-Action' = $anonymous.Json.actionId } -Ip '127.0.0.2'
  Assert-Equal 'action identifiers are bound to their originating client' 403 (Invoke-TestHandler $wrongIp).StatusCode
  $fresh = New-AcsLookupAction -Context $plain -DomainCount 100
  $repeat = New-TestContext -Query @{ domain = 'new.example.com' } -Headers @{ 'X-ACS-Lookup-Action' = $fresh.body.actionId }
  Assert-Equal 'a new processing action gets its own fresh website budget' $true (Test-RateLimit -Context $repeat -DomainLookup).allowed
  $repeat.Request.QueryString['domain'] = 'not a domain'
  Assert-Equal 'invalid website input keeps the normal validation response' 400 (Invoke-TestHandler $repeat).StatusCode
  Assert-Equal 'invalid input consumes no website slot' 1 $AcsLookupActionStore[$fresh.body.actionId].domains.Count

  $AcsLookupActionStore[$fresh.body.actionId].lastSeenUtc = [DateTimeOffset]::UtcNow.AddHours(-2)
  $repeat.Request.QueryString['domain'] = 'new.example.com'
  Assert-Equal 'idle actions expire explicitly rather than raising a website limit error' 410 (Invoke-TestHandler $repeat).StatusCode
  Assert-Equal 'expired action state is removed' $false $AcsLookupActionStore.ContainsKey($fresh.body.actionId)
  $env:ACS_RATE_LIMIT_PER_MIN = '0'
  $overflow = New-TestContext -Query @{ domain = 'another.example.com' } -Headers @{ 'X-ACS-Lookup-Action' = $anonymous.Json.actionId }
  Assert-Equal 'disabling the IP guard does not disable per-action website limits' $false (Test-RateLimit -Context $overflow -DomainLookup).allowed
  Assert-Equal 'action records never retain bearer credentials' $false (($AcsLookupActionStore.Values | ConvertTo-Json -Depth 5) -match 'Bearer|synthetic-valid-token|accessToken')

  $env:ACS_API_KEY = 'synthetic-api-key'
  Assert-Equal 'admission still requires the configured API key' 401 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1 })).StatusCode
  Assert-Equal 'API-key-protected admission accepts the configured key' 200 (Invoke-TestHandler (New-TestContext -Path '/api/lookup-action' -Query @{ count = 1 } -Headers @{ 'X-Api-Key' = 'synthetic-api-key' })).StatusCode

  $AcsLookupActionStore.Clear()
  $expired = [pscustomobject]@{ lastSeenUtc = [DateTimeOffset]::UtcNow.AddHours(-2) }
  for ($index = 0; $index -lt 1000; $index++) { $AcsLookupActionStore[[string]$index] = $expired }
  $null = New-AcsLookupAction -Context $plain -DomainCount 1
  Assert-Equal 'admission prunes stale action records' 1 $AcsLookupActionStore.Count
  $AcsLookupActionStore.Clear()
  $active = [pscustomobject]@{ lastSeenUtc = [DateTimeOffset]::UtcNow }
  for ($index = 0; $index -lt 10000; $index++) { $AcsLookupActionStore[[string]$index] = $active }
  Assert-Equal 'action storage is bounded and capacity failure is explicit' 503 (New-AcsLookupAction -Context $plain -DomainCount 1).statusCode
  $AcsLookupActionStore.Clear()

  & node (Join-Path $PSScriptRoot 'Test-LookupLimits.mjs') $repoRoot
  if ($LASTEXITCODE -ne 0) { throw 'Browser-source lookup limit validation failed.' }
  Write-Host "PASS: $checks server lookup limit checks passed." -ForegroundColor Green
} finally {
  foreach ($name in $savedEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
  }
}
