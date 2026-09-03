# Validates mail-IP reputation target selection without contacting external DNS.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-DnsReputationScope.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFile = Join-Path $repoRoot 'src/17-DnsReputation.ps1'
$domainReputationFile = Join-Path $repoRoot 'src/17a-DomainReputation.ps1'
$uiFile = Join-Path $repoRoot 'src/20d-HtmlJsCore.ps1'
$translationsFile = Join-Path $repoRoot 'src/20b-HtmlTranslations.ps1'
$failures = [System.Collections.Generic.List[string]]::new()
$checks = 0

function Assert-Equal {
  param([string]$Name, $Expected, $Actual)

  $script:checks++
  if ($Expected -eq $Actual) {
    Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    return
  }

  Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
  Write-Host ("        expected='{0}' actual='{1}'" -f $Expected, $Actual) -ForegroundColor DarkYellow
  $script:failures.Add($Name)
}

Write-Host '=== DNS Reputation Scope Validation ===' -ForegroundColor Cyan

. $sourceFile
# Load the REAL combiner. It was previously stubbed here, and the stub returned
# 'clean' unconditionally, which is precisely the defect the stub then hid.
. $domainReputationFile

$script:reputationFixture = @{}
$script:reputationQueries = [System.Collections.Generic.List[string]]::new()

function ResolveSafely {
  param([string]$Name, [string]$Type, [switch]$ThrowOnError)

  $key = '{0}|{1}' -f $Name.TrimEnd('.').ToLowerInvariant(), $Type.ToUpperInvariant()
  $script:reputationQueries.Add($key)
  if ($script:reputationFixture.ContainsKey($key)) { return $script:reputationFixture[$key] }
  return $null
}

function Get-MxRecordObjects { param([object[]]$Records) return @($Records) }
function Get-DnsIpString {
  param([Parameter(ValueFromPipeline = $true)][object]$Record)
  process {
    if ($null -ne $Record -and $Record.PSObject.Properties.Match('IPAddress').Count -gt 0) {
      return [string]$Record.IPAddress
    }
  }
}
function Get-CnameTargetFromRecords { param([object]$Records) return $null }
function Get-ParentDomains { param([string]$Domain) return @() }
function Clear-ExpiredRblCacheEntries { param([int]$TtlSec = 180, [int]$MaxRemovalsPerPass = 256) return 0 }
function Invoke-RblLookup {
  param([string]$IPv4, [string]$Zone)
  return [pscustomobject]@{
    ip = $IPv4
    queriedZone = $Zone
    listed = $false
    response = $null
    listedAddress = $null
    listedText = $null
    error = $null
  }
}

function Invoke-ReputationFixture {
  param([string]$NullExchange)

  $script:reputationQueries.Clear()
  $script:reputationFixture = @{
    'ohiodnr.gov|MX' = @([pscustomobject]@{ Preference = 0; NameExchange = $NullExchange })
    'ohiodnr.gov|A' = @(
      [pscustomobject]@{ IPAddress = '108.156.184.65' },
      [pscustomobject]@{ IPAddress = '108.156.184.97' }
    )
  }
  return Get-DnsReputationStatus -Domain 'ohiodnr.gov'
}

function Get-DomainReputationStatus {
  param([string]$Domain)
  return [pscustomobject]@{
    state = 'disabled'
    reasonCode = 'testFixture'
    queryDomain = $Domain
    configuredCount = 0
    results = @()
    summary = [pscustomobject]@{ providerCount=0;validatedCount=0;listedCount=0;notListedCount=0;blockedCount=0;errorCount=0;riskSummary='Unknown' }
  }
}
$resultDot = Invoke-ReputationFixture -NullExchange '.'
Assert-Equal 'reputation function emits exactly one API object' 1 @($resultDot).Count
Assert-Equal 'DoH Null MX is identified' $true $resultDot.nullMx
Assert-Equal 'DoH Null MX has a not-applicable mail-IP state' 'notApplicable' $resultDot.ipCheckState
Assert-Equal 'DoH Null MX reports its reason' 'nullMx' $resultDot.ipCheckReason
Assert-Equal 'DoH Null MX performs no IP blocklist queries' 0 $resultDot.summary.totalQueries
Assert-Equal 'DoH Null MX is never called Clean' 'NotApplicable' $resultDot.summary.riskSummary
Assert-Equal 'DoH Null MX never resolves the website A record' $false $script:reputationQueries.Contains('ohiodnr.gov|A')

$resultEmpty = Invoke-ReputationFixture -NullExchange ''
Assert-Equal 'System-resolver Null MX is identified' $true $resultEmpty.nullMx
Assert-Equal 'System-resolver Null MX has the same state' 'notApplicable' $resultEmpty.ipCheckState
Assert-Equal 'System-resolver Null MX never resolves the website A record' $false $script:reputationQueries.Contains('ohiodnr.gov|A')

$script:reputationQueries.Clear()
$script:reputationFixture = @{
  'nomx.example|MX' = @()
  'nomx.example|A' = @([pscustomobject]@{ IPAddress = '93.184.216.34' })
}
$resultNoMx = Get-DnsReputationStatus -Domain 'nomx.example'
Assert-Equal 'domain without MX uses the apex fallback' 'apex' $resultNoMx.targets[0].source
Assert-Equal 'apex fallback is reported as checked' 'checked' $resultNoMx.ipCheckState
Assert-Equal 'domain without MX resolves its own A record' $true $script:reputationQueries.Contains('nomx.example|A')

$uiSource = Get-Content $uiFile -Raw
$translationSource = Get-Content $translationsFile -Raw
Assert-Equal 'quota UI does not default missing reputation to Clean' $false $uiSource.Contains("summary.riskSummary || 'Clean'")
Assert-Equal 'reputation card does not default missing reputation to Clean' $false $uiSource.Contains("summary.riskSummary || 'Clean'")
Assert-Equal 'aggregate verdicts use the shared reputation view model' $true ([regex]::Matches($uiSource, 'getReputationViewModel\(r\.reputation\)').Count -ge 2)
Assert-Equal 'generic informational rows keep the generic info label' $true $uiSource.Contains("info: 'info', notApplicable: 'reputationNotApplicable'")
Assert-Equal 'Null MX copy output suppresses zero-query statistics' $true $uiSource.Contains('repStats = reputationView.ipNotApplicable ? null : {')
Assert-Equal 'all ten locales define the not-applicable label' 10 ([regex]::Matches($translationSource, 'reputationNotApplicable\s*:').Count)
Assert-Equal 'English Null MX explanation is present' $true $translationSource.Contains("reputationNullMxNote: 'This domain publishes a Null MX record")

# Assemble the same UI fragments used by Build-Release.ps1 and syntax-check all
# executable inline scripts. This catches malformed JavaScript inside the
# PowerShell here-strings without starting the server or contacting the network.
$script:AppVersion = 'test'
$uiSourceNames = @(
  '20-HtmlCss.ps1',
  '20a-HtmlScriptSetup.ps1',
  '20b-HtmlTranslations.ps1',
  '20c-HtmlJsUtilities.ps1',
  '20d-HtmlJsCore.ps1',
  '20e-HtmlAzureIntegration.ps1',
  '20f-HtmlPostProcess.ps1',
  '20g-HtmlAccessibility.ps1'
)
foreach ($uiSourceName in $uiSourceNames) {
  . (Join-Path $repoRoot "src/$uiSourceName")
}

$inlineScripts = [System.Collections.Generic.List[string]]::new()
$scriptPattern = '<script(?<attrs>[^>]*)>(?<body>[\s\S]*?)</script>'
foreach ($match in [regex]::Matches($htmlPage, $scriptPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
  $attributes = [string]$match.Groups['attrs'].Value
  if ($attributes -match '(?i)\bsrc\s*=' -or $attributes -match '(?i)application/ld\+json') { continue }
  $inlineScripts.Add([string]$match.Groups['body'].Value)
}

$tempJsFile = Join-Path ([IO.Path]::GetTempPath()) ("acs-reputation-ui-{0}.js" -f [Guid]::NewGuid().ToString('N'))
try {
  [IO.File]::WriteAllText($tempJsFile, ($inlineScripts -join "`n"), [Text.UTF8Encoding]::new($false))
  $nodeOutput = & node --check $tempJsFile 2>&1
  Assert-Equal 'assembled inline JavaScript passes node syntax check' 0 $LASTEXITCODE
  if ($LASTEXITCODE -ne 0 -and $nodeOutput) { Write-Host ($nodeOutput -join "`n") -ForegroundColor DarkYellow }
} finally {
  Remove-Item $tempJsFile -Force -ErrorAction SilentlyContinue
}

Write-Host '--- combined reputation state ---' -ForegroundColor Cyan

# NOTE: $DomainReputation is a Mandatory parameter, so a literal $null would make
# PowerShell prompt interactively and hang the run. The production caller always
# supplies an object, so 'disabled' is expressed as an object here too.
function New-IpSummaryFixture {
  param([int]$Total, [int]$Errors, [int]$Listed)
  return [pscustomobject]@{ totalQueries = $Total; errorCount = $Errors; listedCount = $Listed }
}
function Invoke-Combined {
  param([int]$Total, [int]$Errors, [int]$Listed, [string]$IpCheckState, [string]$DomainState)
  return Get-CombinedReputationState -IpSummary (New-IpSummaryFixture -Total $Total -Errors $Errors -Listed $Listed) -IpCheckState $IpCheckState -DomainReputation ([pscustomobject]@{ state = $DomainState })
}

Assert-Equal 'clean domain plus fully successful mail-IP scope is clean' 'clean' (Invoke-Combined -Total 25 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'clean')
# REGRESSION GUARD: the same payload's summary.riskSummary reports Warning whenever
# errorCount > 0, so returning 'clean' here would contradict it on the same page.
Assert-Equal 'clean domain with ANY mail-IP query error degrades to partial' 'partial' (Invoke-Combined -Total 25 -Errors 1 -Listed 0 -IpCheckState 'checked' -DomainState 'clean')
Assert-Equal 'clean domain with all mail-IP queries failing is partial' 'partial' (Invoke-Combined -Total 25 -Errors 25 -Listed 0 -IpCheckState 'checked' -DomainState 'clean')
Assert-Equal 'clean domain with not-applicable mail IPs is clean' 'clean' (Invoke-Combined -Total 0 -Errors 0 -Listed 0 -IpCheckState 'notApplicable' -DomainState 'clean')
Assert-Equal 'listed domain outranks a clean mail-IP scope' 'listed' (Invoke-Combined -Total 25 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'listed')
Assert-Equal 'listed mail IP outranks a clean domain scope' 'listed' (Invoke-Combined -Total 25 -Errors 0 -Listed 1 -IpCheckState 'checked' -DomainState 'clean')
Assert-Equal 'partial domain scope stays partial' 'partial' (Invoke-Combined -Total 25 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'partial')
Assert-Equal 'disabled domain scope with a clean mail-IP scope is clean' 'clean' (Invoke-Combined -Total 25 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'disabled')
# REGRESSION GUARD: same contradiction, on the path where domain reputation is off.
Assert-Equal 'disabled domain scope with mail-IP errors is partial' 'partial' (Invoke-Combined -Total 25 -Errors 3 -Listed 0 -IpCheckState 'checked' -DomainState 'disabled')
Assert-Equal 'disabled domain scope with not-applicable mail IPs is not applicable' 'notApplicable' (Invoke-Combined -Total 0 -Errors 0 -Listed 0 -IpCheckState 'notApplicable' -DomainState 'disabled')
Assert-Equal 'unknown domain scope with a clean mail-IP scope is partial' 'partial' (Invoke-Combined -Total 25 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'unknown')
Assert-Equal 'clean domain with zero mail-IP queries attempted is partial' 'partial' (Invoke-Combined -Total 0 -Errors 0 -Listed 0 -IpCheckState 'checked' -DomainState 'clean')
Assert-Equal 'nothing conclusive anywhere is unknown' 'unknown' (Invoke-Combined -Total 0 -Errors 0 -Listed 0 -IpCheckState 'unknown' -DomainState 'unknown')

if ($failures.Count -gt 0) {
  Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("`nPASS: {0} reputation scope checks passed." -f $checks) -ForegroundColor Green
