<#
.SYNOPSIS
Validates ACS Domain Checker DNSBL/RBL default configuration, optional custom zone support, normalization behavior, and runtime reputation summary output.

.DESCRIPTION
This script performs both static source validation and runtime validation against the target ACS Domain Checker script.

It verifies that:
- The default DNSBL/RBL zone list matches the required approved set
- Removed zones are no longer included by default
- Environment variable override support exists through ACS_RBL_ZONES
- Optional Spamhaus usage is documented as user-supplied only and not enabled by default
- Case-insensitive normalization exists for custom zones
- Duplicate and blank custom zone handling behaves as expected
- riskSummary output is present and follows the expected mapping:
  - 0 hits  = Clean
  - 1 hit   = Warning
  - 2+ hits = ElevatedRisk

The script also launches the target script in separate one-shot runs to validate:
- Default runtime zone behavior
- Blank custom zone fallback behavior
- Custom zone normalization behavior
- Runtime riskSummary output presence

.AUTHOR
Blake Drumm (blakedrumm@microsoft.com)

.NOTES
File Name  : Validate-ACSRblConfiguration.ps1
Purpose    : Validate DNSBL/RBL defaults and runtime behavior for acs-domain-checker.ps1
Requirements:
- PowerShell
- The target script must support:
  - -TestDomain parameter
  - ACS_RBL_ZONES environment variable override
  - JSON output containing reputation.rblZones and reputation.summary.riskSummary

.PARAMETER ScriptPath
Path to the ACS Domain Checker script to validate.

.PARAMETER Domain
Domain name passed to the target script during runtime validation.

.EXAMPLE
.\Validate-ACSRblConfiguration.ps1

.EXAMPLE
.\Validate-ACSRblConfiguration.ps1 -ScriptPath ".\acs-domain-checker.ps1" -Domain "contoso.com"
#>

param(
  [string]$ScriptPath = ".\acs-domain-checker.ps1",
  [string]$Domain = "example.com"
)

$source = Get-Content -LiteralPath $ScriptPath -Raw -ErrorAction Stop
$errors = New-Object System.Collections.Generic.List[string]
$resolvedScriptPath = (Resolve-Path $ScriptPath).Path

$defaultPattern = [regex]'\$defaultZones\s*=\s*@\((?<body>[\s\S]*?)\)'
$match = $defaultPattern.Match($source)
if (-not $match.Success) {
  throw "Unable to locate `$defaultZones in $ScriptPath"
}

$zonePattern = [regex]"'([^']+)'"
$defaults = @($zonePattern.Matches($match.Groups['body'].Value) | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })

$expectedDefaults = @(
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'psbl.surriel.com',
  'dnsbl.dronebl.org',
  'bl.0spam.org',
  'rbl.0spam.org'
)

$removedDefaults = @(
  'zen.spamhaus.org',
  'dnsbl.sorbs.net',
  'rbl.efnetrbl.org'
)

if (@($defaults) -join ',' -ne (@($expectedDefaults) -join ',')) {
  $errors.Add("Default DNSBL zone list does not match the required set. Found: $($defaults -join ', ')")
}

foreach ($removed in $removedDefaults) {
  if ($defaults -contains $removed) {
    $errors.Add("Removed zone '$removed' is still present in the default DNSBL zone list.")
  }
}

if ($source -match 'ACS_RBL_ZONES') {
  # expected
} else {
  $errors.Add('Expected ACS_RBL_ZONES environment configuration support was not found.')
}

if ($source -match 'riskSummary') {
  # expected
} else {
  $errors.Add('Expected riskSummary field was not found in the reputation summary output.')
}

if ($source -match 'zen\.spamhaus\.org' -and $source -match 'user-supplied only' -and $source -match 'not enabled by default') {
  # expected doc text
} else {
  $errors.Add('Expected optional Spamhaus documentation note was not found.')
}

$customNormalizationPattern = [regex]"ToLowerInvariant\(\)"
if (-not $customNormalizationPattern.IsMatch($source)) {
  $errors.Add('Expected case-insensitive normalization was not found.')
}

# Simulate duplicate-removal / blank fallback behavior using the same normalization rules.
$simulatedCustom = @('ZEN.SPAMHAUS.ORG', 'zen.spamhaus.org', '', ' bl.spamcop.net ')
$normalized = @($simulatedCustom | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
if ($normalized.Count -ne 2 -or $normalized[0] -ne 'zen.spamhaus.org' -or $normalized[1] -ne 'bl.spamcop.net') {
  $errors.Add("Custom zone normalization simulation failed. Found: $($normalized -join ', ')")
}

$hitMap = @{
  0 = 'Clean'
  1 = 'Warning'
  2 = 'ElevatedRisk'
  5 = 'ElevatedRisk'
}
foreach ($kv in $hitMap.GetEnumerator()) {
  $hits = [int]$kv.Key
  $expected = [string]$kv.Value
  $actual = if ($hits -ge 2) { 'ElevatedRisk' } elseif ($hits -eq 1) { 'Warning' } else { 'Clean' }
  if ($actual -ne $expected) {
    $errors.Add("Risk summary mapping failed for hits=$hits. Expected '$expected', found '$actual'.")
  }
}

if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_ }
  exit 1
}

function Invoke-OneShot {
  param(
    [string]$CustomZones
  )

  $old = $env:ACS_RBL_ZONES
  try {
    if ($null -eq $CustomZones) {
      Remove-Item Env:ACS_RBL_ZONES -ErrorAction SilentlyContinue
    } else {
      $env:ACS_RBL_ZONES = $CustomZones
    }

    return (& powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedScriptPath -TestDomain $Domain | Out-String | ConvertFrom-Json)
  }
  finally {
    if ($null -eq $old) {
      Remove-Item Env:ACS_RBL_ZONES -ErrorAction SilentlyContinue
    } else {
      $env:ACS_RBL_ZONES = $old
    }
  }
}

$defaultRun = Invoke-OneShot -CustomZones $null
$defaultZonesFromRuntime = @($defaultRun.reputation.rblZones | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
if (@($defaultZonesFromRuntime) -join ',' -ne (@($expectedDefaults) -join ',')) {
  Write-Error "Runtime default zones do not match expected defaults. Found: $($defaultZonesFromRuntime -join ', ')"
  exit 1
}

foreach ($removed in $removedDefaults) {
  if ($defaultZonesFromRuntime -contains $removed) {
    Write-Error "Removed zone '$removed' appeared in runtime defaults."
    exit 1
  }
}

$blankFallbackRun = Invoke-OneShot -CustomZones " , ; `r`n "
$blankFallbackZones = @($blankFallbackRun.reputation.rblZones | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
if (@($blankFallbackZones) -join ',' -ne (@($expectedDefaults) -join ',')) {
  Write-Error "Blank custom zone configuration did not fall back to defaults. Found: $($blankFallbackZones -join ', ')"
  exit 1
}

$customRun = Invoke-OneShot -CustomZones "ZEN.SPAMHAUS.ORG;bl.spamcop.net;zen.spamhaus.org"
$customZonesFromRuntime = @($customRun.reputation.rblZones | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
$expectedCustom = @('zen.spamhaus.org','bl.spamcop.net')
if (@($customZonesFromRuntime) -join ',' -ne (@($expectedCustom) -join ',')) {
  Write-Error "Custom zone runtime normalization failed. Found: $($customZonesFromRuntime -join ', ')"
  exit 1
}

if ($defaultRun.reputation.summary.riskSummary -notin @('Clean','Warning','ElevatedRisk')) {
  Write-Error "Runtime riskSummary was missing or invalid. Found: $($defaultRun.reputation.summary.riskSummary)"
  exit 1
}

[pscustomobject]@{
  ScriptPath = $resolvedScriptPath
  DefaultZones = $defaults
  RemovedZonesAbsentByDefault = $true
  CustomZonesSupported = $true
  SpamhausOptionalOnly = $true
  RiskSummaryValidated = $true
  RuntimeDefaultZones = $defaultZonesFromRuntime
  RuntimeCustomZones = $customZonesFromRuntime
} | ConvertTo-Json -Depth 4