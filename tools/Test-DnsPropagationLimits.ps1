# Validates propagation resolver limits without contacting external DNS servers.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-DnsPropagationLimits.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$propagationFile = Join-Path $repoRoot 'src/16d-DnsPropagation.ps1'
$handlerFile = Join-Path $repoRoot 'src/23-RequestHandler.ps1'
$utilitiesFile = Join-Path $repoRoot 'src/20c-HtmlJsUtilities.ps1'
$coreFile = Join-Path $repoRoot 'src/20d-HtmlJsCore.ps1'
$seoFile = Join-Path $repoRoot 'src/11a-SeoMetadata.ps1'
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

function Assert-Contains {
  param([string]$Name, [string]$Text, [string]$ExpectedText)

  Assert-Equal -Name $Name -Expected $true -Actual $Text.Contains($ExpectedText)
}

Write-Host '=== DNS Propagation Limit Validation ===' -ForegroundColor Cyan

$propagationSource = Get-Content $propagationFile -Raw
$handlerSource = Get-Content $handlerFile -Raw
$utilitiesSource = Get-Content $utilitiesFile -Raw
$coreSource = Get-Content $coreFile -Raw
$seoSource = Get-Content $seoFile -Raw

Assert-Contains 'server request clamp is 1000' $propagationSource '$defaultMax = [Math]::Min(1000, $parsed)'
Assert-Contains 'server explicit max clamp is 1000' $propagationSource '[Math]::Min(1000, $MaxResolvers)'
Assert-Contains 'validation candidate fan-out is capped at 1000' $propagationSource '$candidateTarget = [Math]::Min(1000,'
Assert-Contains 'request handler clamp is 1000' $handlerSource '$propMax = [Math]::Min(1000,'
Assert-Contains 'stored browser setting clamp is 1000' $utilitiesSource 'Math.min(1000, Math.max(4, Math.round(max)))'
Assert-Contains 'settings input follows the active catalog up to 1000' $coreSource 'Math.min(1000, catalogTotal)'
Assert-Contains 'OpenAPI advertises a 1000 maximum' $seoSource '"maximum": 1000, "default": 25'

# The operator override is the supported source for catalogs larger than the
# built-in 283 entries. Confirm an oversized override is bounded before any
# resolver selection or socket creation can occur.
. $propagationFile
$previousOverride = $env:ACS_PROPAGATION_RESOLVERS
try {
  $entries = [System.Collections.Generic.List[string]]::new()
  for ($index = 0; $index -lt 1001; $index++) {
    $second = [int][Math]::Floor($index / 65025)
    $third = [int][Math]::Floor(($index % 65025) / 255)
    $fourth = ($index % 255) + 1
    $entries.Add(("11.{0}.{1}.{2}||||||global|0" -f $second, $third, $fourth))
  }
  $env:ACS_PROPAGATION_RESOLVERS = $entries -join ';'
  Assert-Equal 'operator catalog is capped at 1000 entries' 1000 @(Get-DnsPropagationResolverCatalog).Count
} finally {
  $env:ACS_PROPAGATION_RESOLVERS = $previousOverride
}

# Replace all network-facing functions with deterministic in-process doubles.
# This exercises Get-DnsPropagationStatus's real clamp and result-building path
# while proving that a request for more than the cap yields exactly 1000 rows.
$script:syntheticResolvers = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt 1001; $index++) {
  $second = [int][Math]::Floor($index / 65025)
  $third = [int][Math]::Floor(($index % 65025) / 255)
  $fourth = ($index % 255) + 1
  $script:syntheticResolvers.Add([pscustomobject]@{
    ip = ("11.{0}.{1}.{2}" -f $second, $third, $fourth)
    provider = 'Synthetic resolver'
    countryCode = 'US'
    city = ''
    latitude = $null
    longitude = $null
    region = 'global'
    anycast = $false
  })
}

function Get-DnsPropagationResolverCatalog { return $script:syntheticResolvers.ToArray() }
function Select-DnsPropagationResolvers {
  param([string[]]$Regions = @(), [int]$MaxResolvers = 25)
  return @($script:syntheticResolvers | Select-Object -First $MaxResolvers)
}
function Invoke-DnsPropagationFanout {
  param([object[]]$Resolvers, [string]$Name, [int]$TypeCode, [int]$TimeoutMs = 4000)
  $outcomes = @{}
  foreach ($resolver in $Resolvers) {
    $outcomes[[string]$resolver.ip] = @{
      answers = @('v=spf1 -all')
      rcode = 0
      rcodeLabel = 'NOERROR'
      transport = 'udp'
      responseMs = 1
      error = $null
      truncated = $false
    }
  }
  return $outcomes
}
function Set-DnsPropagationHealthState { param([string]$Ip, [bool]$Healthy) }

$result = Get-DnsPropagationStatus -Domain 'example.com' -RecordType TXT -MaxResolvers 1001 -ValidateResolvers:$false
Assert-Equal 'requests above the hard cap report 1000 requested resolvers' 1000 $result.requestedCount
Assert-Equal 'orchestration selects at most 1000 resolvers' 1000 $result.resolverCount
Assert-Equal 'API payload contains at most 1000 resolver results' 1000 @($result.results).Count

if ($failures.Count -gt 0) {
  Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("`nPASS: {0} propagation limit checks passed." -f $checks) -ForegroundColor Green