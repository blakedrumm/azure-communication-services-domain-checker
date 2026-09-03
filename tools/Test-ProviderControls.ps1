# Validates a domain-reputation provider profile against the LIVE service, using
# ONLY the provider's own documented control probes. No customer domain is ever
# sent, no profile constant is ever auto-learned, and no validation rule is relaxed.
#
# Most useful for the opt-in providers (surbl, spamhaus), which require operator
# eligibility and therefore cannot be validated from an unregistered network. Run
# this from a network whose access to the provider is already established.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-ProviderControls.ps1 -ProviderId surbl

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ProviderId,
  [int]$TimeoutMs = 4000
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
foreach ($module in @(
  'src/03a-SecureLogging.ps1',
  'src/11-HttpHelpers.ps1',
  'src/12-DnsResolution.ps1',
  'src/16b-WebsiteProbe.ps1',
  'src/16c-NameserverChecks.ps1',
  'src/16d-DnsPropagation.ps1',
  'src/17a-DomainReputation.ps1'
)) {
  . (Join-Path $repoRoot $module)
}

$provider = @(Get-DomainReputationProviderCatalog | Where-Object { $_.id -eq $ProviderId.Trim().ToLowerInvariant() })[0]
if (-not $provider) {
  $known = (@(Get-DomainReputationProviderCatalog | ForEach-Object id) -join ', ')
  Write-Host ("Unknown provider '{0}'. Known providers: {1}" -f $ProviderId, $known) -ForegroundColor Red
  exit 2
}

Write-Host ("=== Provider control diagnostic: {0} ({1}) ===" -f $provider.displayName, $provider.id) -ForegroundColor Cyan
Write-Host ("  query zone        : {0}" -f $provider.queryZone)
Write-Host ("  authority domain  : {0}" -f $provider.authorityDomain)
Write-Host ("  positive control  : {0}.{1} expecting {2} ({3})" -f $provider.controlDomain, $provider.queryZone, (@($provider.controlExpected) -join ' or '), $provider.controlMatch)
Write-Host ("  negative control  : {0}.{1}" -f $provider.negativeControlDomain, $provider.queryZone)
Write-Host ("  policy            : {0}" -f $provider.policyUrl)
Write-Host ''

Write-Host 'Discovering authoritative nameservers...' -ForegroundColor Cyan
$endpoints = @(Get-DomainReputationProviderEndpoints -Provider $provider -MaxEndpoints 2)
if ($endpoints.Count -eq 0) {
  Write-Host ("  FAIL  No public IPv4 authority could be discovered for '{0}'." -f $provider.authorityDomain) -ForegroundColor Red
  Write-Host '        The profile cannot work until discovery succeeds. Check that the authority' -ForegroundColor DarkYellow
  Write-Host '        domain resolves NS or SOA records from this network.' -ForegroundColor DarkYellow
  exit 1
}
Write-Host ("  Discovered: {0}" -f ($endpoints -join ', ')) -ForegroundColor Green
Write-Host ''

$exitCode = 0
foreach ($endpoint in $endpoints) {
  Write-Host ("--- endpoint {0} ---" -f $endpoint) -ForegroundColor Cyan

  # Only the provider's own documented probe names are ever sent.
  $queries = @(
    [pscustomobject]@{ key = 'control'; ip = $endpoint; name = "$($provider.controlDomain).$($provider.queryZone)"; zone = $provider.queryZone; purpose = 'control' },
    [pscustomobject]@{ key = 'negative'; ip = $endpoint; name = "$($provider.negativeControlDomain).$($provider.queryZone)"; zone = $provider.queryZone; purpose = 'negative' }
  )
  $outcomes = Invoke-DomainReputationDnsFanout -Queries $queries -TimeoutMs $TimeoutMs

  $control = $outcomes['control']
  $negative = $outcomes['negative']

  if ($control -and -not [string]::IsNullOrWhiteSpace([string]$control.error)) {
    Write-Host ("  positive control : ERROR {0}" -f $control.error) -ForegroundColor Red
    Write-Host '                     SERVFAIL, REFUSED, a timeout and a network block are' -ForegroundColor DarkYellow
    Write-Host '                     indistinguishable here. If you are eligible and this still' -ForegroundColor DarkYellow
    Write-Host '                     fails, confirm your access with the provider.' -ForegroundColor DarkYellow
    $exitCode = 1
  } else {
    $state = Test-DomainReputationPositiveControl -Provider $provider -ControlOutcome $control
    $color = if ($state.state -eq 'valid') { 'Green' } else { 'Red' }
    Write-Host ("  positive control : {0} answers=[{1}] rcode={2}" -f $state.state, (@($control.answers) -join ','), $control.rcodeLabel) -ForegroundColor $color
    if ($state.state -ne 'valid') {
      Write-Host ("                     reason={0}; profile expects {1} ({2})" -f $state.reasonCode, (@($provider.controlExpected) -join ' or '), $provider.controlMatch) -ForegroundColor DarkYellow
      $exitCode = 1
    }
  }

  if ($negative -and -not [string]::IsNullOrWhiteSpace([string]$negative.error)) {
    # This is the check that fails for a zone that is not separately delegated: a
    # negative answer must carry an SOA owned by EXACTLY the configured query zone.
    Write-Host ("  negative control : ERROR {0}" -f $negative.error) -ForegroundColor Red
    Write-Host ("                     A 'not listed' verdict requires an authoritative SOA owned by" ) -ForegroundColor DarkYellow
    Write-Host ("                     exactly '{0}'. If this endpoint answers but never proves a" -f $provider.queryZone) -ForegroundColor DarkYellow
    Write-Host  '                     negative, the zone is likely not separately delegated and the' -ForegroundColor DarkYellow
    Write-Host  '                     profile cannot produce a clean verdict as written.' -ForegroundColor DarkYellow
    $exitCode = 1
  } else {
    $proved = [bool]$negative.negativeProof
    $color = if ($proved) { 'Green' } else { 'Red' }
    Write-Host ("  negative control : negativeProof={0} answers=[{1}] rcode={2}" -f $proved, (@($negative.answers) -join ','), $negative.rcodeLabel) -ForegroundColor $color
    if (@($negative.answers).Count -gt 0) {
      Write-Host '                     Zone answered the negative control: it is wildcarded and cannot be trusted.' -ForegroundColor Red
      $exitCode = 1
    }
    if (-not $proved) { $exitCode = 1 }
  }
  Write-Host ''
}

if ($exitCode -eq 0) {
  Write-Host ("PASS: '{0}' validated both controls. The profile works from this network." -f $provider.id) -ForegroundColor Green
} else {
  Write-Host ("FAIL: '{0}' did not validate. It will fail closed and never report a clean verdict." -f $provider.id) -ForegroundColor Red
  Write-Host '      Nothing was changed. Report the output above if you believe the profile constants are wrong.' -ForegroundColor DarkYellow
}
exit $exitCode
