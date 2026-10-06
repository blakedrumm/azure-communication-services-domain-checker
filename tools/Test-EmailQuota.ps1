# Validates the /api/email-quota verdict and checklist rules without network access.
# ConvertTo-AcsEmailQuotaReport mirrors the SPA's Email Quota card
# (getDomainQuotaStatus / render() in 20d-HtmlJsCore.ps1), so these cases pin
# the server to the same pass/warn/fail decisions the UI makes.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-EmailQuota.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
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

Write-Host '=== Email Quota Report Validation ===' -ForegroundColor Cyan

. (Join-Path $repoRoot 'src/18a-EmailQuota.ps1')

# A healthy domain: every check passes.
function New-HealthyStatus {
  [pscustomobject]@{
    domain = 'contoso.com'
    dnsFailed = $false
    txtRecords = @('v=spf1 include:spf.protection.outlook.com -all', 'ms-domain-verification=abc')
    spfValue = 'v=spf1 include:spf.protection.outlook.com -all'
    spfRecords = @('v=spf1 include:spf.protection.outlook.com -all')
    spfHasRequiredInclude = $true
    spfRequiredInclude = 'spf.protection.outlook.com'
    spfRequiredIncludeCustom = $false
    spfRequiredIncludeMatchType = 'direct-include'
    spfRequiredIncludeDetail = 'Found direct include:spf.protection.outlook.com in the SPF record.'
    spfAnalysis = [pscustomobject]@{ totalLookupTerms = 2 }
    acsValues = @('ms-domain-verification=abc')
    acsReady = $true
    mxRecords = @('contoso-com.mail.protection.outlook.com')
    hasUsableMx = $true
    nullMx = $false
    whoisSource = 'RDAP'
    whoisCreationDateUtc = '2001-01-01T00:00:00Z'
    whoisExpiryDateUtc = '2030-01-01T00:00:00Z'
    whoisRegistrar = 'Example Registrar'
    whoisAgeDays = 9000
    whoisAgeHuman = '25 years'
    whoisExpiryHuman = '3 years'
    whoisIsExpired = $false
    whoisIsYoungDomain = $false
    whoisIsVeryYoungDomain = $false
    whoisNewDomainWarnThresholdDays = 180
    whoisNewDomainErrorThresholdDays = 90
    dmarc = 'v=DMARC1; p=none; rua=mailto:d@contoso.com'
    dmarcLookupDomain = 'contoso.com'
    dmarcInherited = $false
    dmarcMultipleRecords = $false
    dmarcRecordCount = 1
    dkim1 = 'selector1 value'
    dkim2 = 'selector2 value'
  }
}

function New-CleanReputation {
  [pscustomobject]@{
    ipCheckState = 'checked'
    overallReputationState = 'clean'
    overallRiskSummary = 'Clean'
    rblZones = @('zen.example', 'bl.example')
    targets = @([pscustomobject]@{ source = 'mx' })
    summary = [pscustomobject]@{ totalQueries = 4; listedCount = 0; notListedCount = 4; errorCount = 0 }
    domainReputation = [pscustomobject]@{
      state = 'clean'
      summary = [pscustomobject]@{ validatedCount = 3; listedCount = 0 }
      results = @([pscustomobject]@{ providerId = 'uribl'; providerName = 'URIBL Multi'; state = 'notListed' })
    }
  }
}

$website = [pscustomobject]@{ checked = $true; reachable = $true; summary = 'Reachable'; finalUrl = 'https://contoso.com/'; statusCode = 200 }

function Get-Row { param($Report, [string]$Id) return @($Report.checklist | Where-Object { $_.id -eq $Id })[0] }
function Get-Field { param($Report, [string]$Field) return @($Report.report | Where-Object { $_.field -eq $Field })[0].value }

Write-Host "`n[1] Healthy domain"
$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -Reputation (New-CleanReputation) -Website $website -PageLink 'https://example.test/?domain=contoso.com'
Assert-Equal 'verdict is pass' 'pass' $r.emailQuota.status
Assert-Equal 'verdict label' 'Passing' $r.emailQuota.label
Assert-Equal 'domain verification passes' 'pass' $r.domainVerification.status
Assert-Equal 'checklist has 5 rows' 5 @($r.checklist).Count
Assert-Equal 'MX row passes' 'pass' (Get-Row $r 'mx').state
Assert-Equal 'reputation row passes' 'pass' (Get-Row $r 'reputation').state
Assert-Equal 'reputation detail reports 100%' $true ((Get-Row $r 'reputation').detail -like '*Excellent (100%)*')
Assert-Equal 'registration row passes' 'pass' (Get-Row $r 'registration').state
Assert-Equal 'registration detail' 'Age: 25 years | Expires in: 3 years' (Get-Row $r 'registration').detail
Assert-Equal 'SPF row passes' 'pass' (Get-Row $r 'spf').state
Assert-Equal 'DMARC p=none passes by default' 'pass' (Get-Row $r 'dmarc').state
Assert-Equal 'report Email Quota field' 'Passing' (Get-Field $r 'Email Quota')
Assert-Equal 'report SPF lookup count' 'VERIFIED - SPF DNS lookups: 2 (within the RFC 7208 limit of 10)' (Get-Field $r 'SPF Status')
Assert-Equal 'report link row' 'https://example.test/?domain=contoso.com' (Get-Field $r 'Report link')
Assert-Equal 'markdown header' '| Field | Value |' (($r.reportMarkdown -split "`n")[0])
Assert-Equal 'no errors' 0 @($r.errors.PSObject.Properties).Count
Assert-Equal 'report serializes to JSON' $true ([bool]($r | ConvertTo-Json -Depth 16))

Write-Host "`n[2] DMARC enforcement opt-in"
$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -Reputation (New-CleanReputation) -Website $website -RequireDmarcEnforcement $true
Assert-Equal 'p=none warns when enforcement required' 'warn' (Get-Row $r 'dmarc').state
Assert-Equal 'verdict warns' 'warn' $r.emailQuota.status
$s = New-HealthyStatus; $s.dmarc = 'v=DMARC1; p=reject'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website -RequireDmarcEnforcement $true
Assert-Equal 'p=reject passes when enforcement required' 'pass' $r.emailQuota.status

Write-Host "`n[3] Hard failures"
$s = New-HealthyStatus; $s.hasUsableMx = $false; $s.mxRecords = @()
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'missing MX fails' 'fail' $r.emailQuota.status
Assert-Equal 'MX row fails' 'fail' (Get-Row $r 'mx').state

$s = New-HealthyStatus; $s.spfHasRequiredInclude = $false; $s.spfRequiredIncludeMatchType = 'not-found'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'SPF without required include fails' 'fail' $r.emailQuota.status
Assert-Equal 'SPF row fails' 'fail' (Get-Row $r 'spf').state

$s = New-HealthyStatus; $s.spfRecords = @('v=spf1 include:spf.protection.outlook.com -all', 'v=spf1 -all')
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'duplicate SPF records fail' 'fail' $r.emailQuota.status
Assert-Equal 'duplicate SPF row fails' 'fail' (Get-Row $r 'spf').state

$s = New-HealthyStatus; $s.whoisIsVeryYoungDomain = $true; $s.whoisAgeHuman = '10 days'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'very young domain fails' 'fail' $r.emailQuota.status
Assert-Equal 'very young detail' 'New domain (under 90 days): 10 days' (Get-Row $r 'registration').detail

$s = New-HealthyStatus; $s.whoisIsExpired = $true
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'expired domain fails' 'fail' $r.emailQuota.status
Assert-Equal 'expired report expiry' 'Expired' (Get-Field $r 'Domain Expiring in')

Write-Host "`n[4] Warnings"
$s = New-HealthyStatus; $s.whoisIsYoungDomain = $true
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'young domain warns' 'warn' $r.emailQuota.status
Assert-Equal 'young domain row warns' 'warn' (Get-Row $r 'registration').state

$s = New-HealthyStatus; $s.dmarc = $null
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'missing DMARC warns' 'warn' $r.emailQuota.status
Assert-Equal 'missing DMARC row warns' 'warn' (Get-Row $r 'dmarc').state

$s = New-HealthyStatus; $s.spfAnalysis = [pscustomobject]@{ totalLookupTerms = 12 }
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'SPF over 10 lookups warns' 'warn' $r.emailQuota.status
Assert-Equal 'SPF over 10 lookups row warns' 'warn' (Get-Row $r 'spf').state

$s = New-HealthyStatus; $s.spfHasRequiredInclude = $null; $s.spfRequiredIncludeMatchType = 'macro-delegated'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'macro-delegated SPF warns' 'warn' $r.emailQuota.status
Assert-Equal 'macro-delegated SPF row warns' 'warn' (Get-Row $r 'spf').state

$rep = New-CleanReputation; $rep.overallReputationState = 'listed'; $rep.summary.listedCount = 1; $rep.summary.notListedCount = 3
$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -Reputation $rep -Website $website
Assert-Equal 'listed reputation warns' 'warn' $r.emailQuota.status
Assert-Equal 'listed reputation percent rounds like JS' $true ((Get-Row $r 'reputation').detail -like '*Good (75%)*')

$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -ReputationError 'Reputation check failed.' -Website $website
Assert-Equal 'reputation error row' 'error' (Get-Row $r 'reputation').state
Assert-Equal 'reputation error warns' 'warn' $r.emailQuota.status
Assert-Equal 'reputation error reported' 'Reputation check failed.' $r.errors.reputation

$rep = New-CleanReputation; $rep.ipCheckState = 'notApplicable'; $rep.overallReputationState = 'notApplicable'
$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -Reputation $rep -Website $website
Assert-Equal 'Null MX reputation is not applicable' 'notApplicable' (Get-Row $r 'reputation').state

Write-Host "`n[5] Nameserver TXT recovery"
$s = New-HealthyStatus; $s.txtRecords = @(); $s.spfValue = $null; $s.spfRecords = @(); $s.acsValues = @(); $s.acsReady = $false; $s.spfHasRequiredInclude = $false
$ns = [pscustomobject]@{ results = @(
  [pscustomobject]@{ success = $true; txtRecords = @('v=spf1 include:spf.protection.outlook.com -all', 'ms-domain-verification=abc') },
  [pscustomobject]@{ success = $false; txtRecords = @() }
) }
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website -Nameservers $ns
Assert-Equal 'nameserver-recovered SPF warns' 'warn' (Get-Row $r 'spf').state
Assert-Equal 'nameserver-recovered verdict warns' 'warn' $r.emailQuota.status
Assert-Equal 'nameserver-recovered verification warns' 'warn' $r.domainVerification.status

$s = New-HealthyStatus; $s.txtRecords = @(); $s.spfValue = $null; $s.spfRecords = @(); $s.acsValues = @(); $s.acsReady = $false; $s.spfHasRequiredInclude = $false
$s | Add-Member -NotePropertyName txtResolution -NotePropertyValue ([pscustomobject]@{ isServfail = $true })
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'SERVFAIL SPF row warns' 'warn' (Get-Row $r 'spf').state
Assert-Equal 'SERVFAIL without SPF verdict fails like the SPA' 'fail' $r.emailQuota.status
Assert-Equal 'missing ACS TXT fails verification' 'fail' $r.domainVerification.status

Write-Host "`n[6] Registration edge cases"
$s = New-HealthyStatus
foreach ($p in 'whoisSource','whoisCreationDateUtc','whoisExpiryDateUtc','whoisRegistrar','whoisAgeDays','whoisAgeHuman','whoisExpiryHuman') { $s.$p = $null }
$s | Add-Member -NotePropertyName whoisRegistryWebForm -NotePropertyValue 'https://grweb.ics.forth.gr/'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'web-form-only registry is info' 'info' (Get-Row $r 'registration').state
Assert-Equal 'web-form-only registry does not warn' 'pass' $r.emailQuota.status

$s = New-HealthyStatus; $s | Add-Member -NotePropertyName whoisError -NotePropertyValue 'WHOIS lookup failed.'
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'WHOIS error row' 'error' (Get-Row $r 'registration').state
Assert-Equal 'WHOIS error warns' 'warn' $r.emailQuota.status

Write-Host "`n[7] Report table"
$s = New-HealthyStatus; $s.spfRequiredIncludeCustom = $true; $s.spfRequiredInclude = 'spf.protection.office365.us'; $s.spfValue = 'v=spf1 include:spf.protection.office365.us -all'; $s.spfRecords = @($s.spfValue)
$r = ConvertTo-AcsEmailQuotaReport -Status $s -Reputation (New-CleanReputation) -Website $website
Assert-Equal 'custom requirement row' 'SPF include:spf.protection.office365.us' (Get-Field $r 'Custom requirements')
Assert-Equal 'requirements echo custom include' 'spf.protection.office365.us' $r.requirements.spfInclude
$r = ConvertTo-AcsEmailQuotaReport -Status (New-HealthyStatus) -Reputation (New-CleanReputation) -Website $website
$badLines = @(($r.reportMarkdown -split "`n") | Where-Object { ([regex]::Matches($_, '(?<!\\)\|')).Count -ne 3 })
Assert-Equal 'markdown rows keep exactly two columns (pipes in values escaped)' 0 $badLines.Count
Assert-Equal 'markdown reputation row escapes separators' $true ($r.reportMarkdown -like '*\| Zones queried*')

Write-Host ''
if ($failures.Count -eq 0) {
  Write-Host ("PASS: all {0} checks passed." -f $checks) -ForegroundColor Green
  exit 0
}
Write-Host ("FAIL: {0} of {1} checks failed:" -f $failures.Count, $checks) -ForegroundColor Red
$failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
