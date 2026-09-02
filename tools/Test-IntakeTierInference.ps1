# Executes the intake tier JavaScript directly from its source file so these
# checks cannot drift into a separate PowerShell reimplementation of the rules.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-IntakeTierInference.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFile = Join-Path $repoRoot 'src/20d-HtmlJsCore.ps1'
$failures = New-Object System.Collections.Generic.List[string]
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

Write-Host '=== Customer Intake Tier Inference Validation ===' -ForegroundColor Cyan

$source = Get-Content $sourceFile -Raw
$startMarker = 'const INTAKE_TIERS ='
$endMarker = '// ----- Intake option dropdowns'
$start = $source.IndexOf($startMarker, [StringComparison]::Ordinal)
$end = $source.IndexOf($endMarker, $start, [StringComparison]::Ordinal)
if ($start -lt 0 -or $end -le $start) {
    throw 'Could not isolate the intake tier JavaScript from src/20d-HtmlJsCore.ps1.'
}

$tierSource = $source.Substring($start, $end - $start)
$javascript = @"
'use strict';
let extractedIntakeMap = {};
function getExtractedIntakeMap() { return extractedIntakeMap; }

$tierSource

const tierNameAt = (index) => index >= 0 && INTAKE_TIERS[index] ? INTAKE_TIERS[index].name : null;
extractedIntakeMap = {
  expectedVolume: 'Earth \u2014 EarthPremium is the current tier',
  currentTier: 'EarthPremium'
};

process.stdout.write(JSON.stringify({
    reportedIntake: inferExpectedTier('1,000', '10,000', '50,000'),
  sample: inferExpectedTier('2,000', '90,000', '150,000'),
  hourOnly: inferExpectedTier('2,000', '90,000', null),
  dayOnly: inferExpectedTier(null, null, '150,000'),
  minuteOnly: inferExpectedTier('2,000', null, null),
  earthBoundary: inferExpectedTier('5,000', '20,000', '480,000'),
  minuteAboveEarth: inferExpectedTier('5,001', '20,000', '480,000'),
  localizedDigits: inferExpectedTier('\u0662,\u0660\u0660\u0660', '90 000', '\u0661\u0665\u0660,\u0660\u0660\u0660'),
  noRates: inferExpectedTier(null, null, null),
    staleCurrentTextUsesEarth: formatExpectedTierValue('EarthPremium is the current tier', '1,000', '10,000', '50,000') === 'Earth \u2014 EarthPremium is the current tier',
  expectedTierFromMixedText: tierNameAt(getExpectedTierIndexFromIntake())
}));
"@

$tempFile = Join-Path ([IO.Path]::GetTempPath()) ("acs-intake-tier-{0}.js" -f [Guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($tempFile, $javascript, [Text.UTF8Encoding]::new($false))
    $json = & node $tempFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Node.js failed while evaluating the intake tier source: $json"
    }
    $result = $json | ConvertFrom-Json
} finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

Assert-Equal 'all reported rate limits select Earth' 'Earth' $result.reportedIntake
Assert-Equal 'hourly peak remains binding alongside daily total' 'EarthPremium' $result.sample
Assert-Equal 'hour remains binding when no daily total is supplied' 'EarthPremium' $result.hourOnly
Assert-Equal 'daily-only volume selects Earth' 'Earth' $result.dayOnly
Assert-Equal 'minute-only volume preserves the existing tier boundary' 'VenusPremium' $result.minuteOnly
Assert-Equal 'Earth exact boundary remains Earth' 'Earth' $result.earthBoundary
Assert-Equal 'minute burst above Earth advances to EarthStandard' 'EarthStandard' $result.minuteAboveEarth
Assert-Equal 'localized and spaced digits use the same policy' 'EarthPremium' $result.localizedDigits
Assert-Equal 'missing rates do not invent a tier' $null $result.noRates
Assert-Equal 'current-tier text cannot suppress the inferred prefix' $true $result.staleCurrentTextUsesEarth
Assert-Equal 'inferred prefix wins over stale current-tier text downstream' 'Earth' $result.expectedTierFromMixedText

if ($failures.Count -gt 0) {
    Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
    exit 1
}

Write-Host ("`nPASS: {0} intake tier checks passed." -f $checks) -ForegroundColor Green