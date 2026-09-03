# Validates literal-domain reputation provider controls and DNS classification.
# No external DNS queries are made.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-DomainReputation.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFile = Join-Path $repoRoot 'src/17a-DomainReputation.ps1'
$dnsWireFile = Join-Path $repoRoot 'src/16d-DnsPropagation.ps1'
$runspaceFile = Join-Path $repoRoot 'src/22-RunspaceSetup.ps1'
$uiFile = Join-Path $repoRoot 'src/20c-HtmlJsUtilities.ps1'
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

function Add-DnsNameBytes {
  param([System.Collections.Generic.List[byte]]$Bytes, [string]$Name)
  foreach ($label in $Name.TrimEnd('.') -split '\.') {
    $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
    $Bytes.Add([byte]$labelBytes.Length)
    $Bytes.AddRange($labelBytes)
  }
  $Bytes.Add([byte]0)
}

function Add-UInt16Bytes {
  param([System.Collections.Generic.List[byte]]$Bytes, [int]$Value)
  $Bytes.Add([byte](($Value -shr 8) -band 0xFF))
  $Bytes.Add([byte]($Value -band 0xFF))
}

function Add-UInt32Bytes {
  param([System.Collections.Generic.List[byte]]$Bytes, [long]$Value)
  $Bytes.Add([byte](($Value -shr 24) -band 0xFF))
  $Bytes.Add([byte](($Value -shr 16) -band 0xFF))
  $Bytes.Add([byte](($Value -shr 8) -band 0xFF))
  $Bytes.Add([byte]($Value -band 0xFF))
}

function New-TestDnsResponse {
  param(
    [int]$TransactionId,
    [string]$Question,
    [string]$AnswerAddress,
    [int]$Rcode = 0,
    [bool]$Authoritative = $true,
    [bool]$IncludeSoa = $false,
    [string]$SoaOwner = 'multi.uribl.com'
  )

  $bytes = [System.Collections.Generic.List[byte]]::new()
  Add-UInt16Bytes $bytes $TransactionId
  $flags1 = 0x80
  if ($Authoritative) { $flags1 = $flags1 -bor 0x04 }
  $bytes.Add([byte]$flags1)
  $bytes.Add([byte]($Rcode -band 0x0F))
  Add-UInt16Bytes $bytes 1
  Add-UInt16Bytes $bytes $(if ($AnswerAddress) { 1 } else { 0 })
  Add-UInt16Bytes $bytes $(if ($IncludeSoa) { 1 } else { 0 })
  Add-UInt16Bytes $bytes 0

  Add-DnsNameBytes $bytes $Question
  Add-UInt16Bytes $bytes 1
  Add-UInt16Bytes $bytes 1

  if ($AnswerAddress) {
    Add-DnsNameBytes $bytes $Question
    Add-UInt16Bytes $bytes 1
    Add-UInt16Bytes $bytes 1
    Add-UInt32Bytes $bytes 60
    Add-UInt16Bytes $bytes 4
    foreach ($part in $AnswerAddress.Split('.')) { $bytes.Add([byte][int]$part) }
  }

  if ($IncludeSoa) {
    $rdata = [System.Collections.Generic.List[byte]]::new()
    Add-DnsNameBytes $rdata "ns.$SoaOwner"
    Add-DnsNameBytes $rdata "hostmaster.$SoaOwner"
    foreach ($value in @(1, 3600, 600, 86400, 60)) { Add-UInt32Bytes $rdata $value }

    Add-DnsNameBytes $bytes $SoaOwner
    Add-UInt16Bytes $bytes 6
    Add-UInt16Bytes $bytes 1
    Add-UInt32Bytes $bytes 60
    Add-UInt16Bytes $bytes $rdata.Count
    $bytes.AddRange($rdata)
  }

  return ,$bytes.ToArray()
}

Write-Host '=== Literal Domain Reputation Validation ===' -ForegroundColor Cyan

if (-not (Test-Path $sourceFile)) {
  throw 'src/17a-DomainReputation.ps1 is missing.'
}
. $dnsWireFile
. $sourceFile

$providers = @(Get-DomainReputationProviderCatalog)
$uribl = @($providers | Where-Object id -eq 'uribl')[0]
$nordspam = @($providers | Where-Object id -eq 'nordspam')[0]
$semUri = @($providers | Where-Object id -eq 'sem-uri')[0]
Assert-Equal 'three independent providers are enabled by default' 'uribl,nordspam,sem-uri' ((@($providers | Where-Object defaultEnabled).id) -join ',')
Assert-Equal 'SURBL is compiled but opt-in' $false ([bool](@($providers | Where-Object id -eq 'surbl')[0].defaultEnabled))
Assert-Equal 'Spamhaus is compiled but opt-in' $false ([bool](@($providers | Where-Object id -eq 'spamhaus')[0].defaultEnabled))
Assert-Equal 'URIBL queries the registrable domain' 'registrableDomain' $uribl.queryNameMode
Assert-Equal 'URIBL discovers the delegated query-zone authority' 'multi.uribl.com' $uribl.authorityDomain
Assert-Equal 'NordSpam publishes an RFC negative control' 'invalid' $nordspam.negativeControlDomain
Assert-Equal 'SEM publishes its documented negative control' '_DNSBLNEG_.test' $semUri.negativeControlDomain

$queryPacket = New-DomainReputationDnsQueryPacket -Name 'ohiodnr.gov.multi.uribl.com' -TransactionId 999
Assert-Equal 'authoritative provider query has recursion disabled' 0 ([int]$queryPacket[2] -band 1)
$underscorePacket = New-DomainReputationDnsQueryPacket -Name '_DNSBL_.test.uribl.spameatingmonkey.net' -TransactionId 998
Assert-Equal 'provider controls may contain underscore labels' $true ($underscorePacket.Length -gt 12)

$controlBytes = New-TestDnsResponse -TransactionId 1001 -Question 'test.uribl.com.multi.uribl.com' -AnswerAddress '127.0.0.14'
$control = Read-DomainReputationDnsResponse -Buffer $controlBytes -TransactionId 1001 -ExpectedName 'test.uribl.com.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'valid control is authoritative' $true $control.authoritative
Assert-Equal 'valid control preserves its address' '127.0.0.14' (@($control.answers) -join ',')
Assert-Equal 'valid control has no parse error' $null $control.error

$negativeBytes = New-TestDnsResponse -TransactionId 1002 -Question 'ohiodnr.gov.multi.uribl.com' -Rcode 3 -IncludeSoa $true
$negative = Read-DomainReputationDnsResponse -Buffer $negativeBytes -TransactionId 1002 -ExpectedName 'ohiodnr.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'authoritative NXDOMAIN carries negative proof' $true $negative.negativeProof
Assert-Equal 'authoritative NXDOMAIN has no parse error' $null $negative.error

$nodataBytes = New-TestDnsResponse -TransactionId 1008 -Question 'invalid.multi.uribl.com' -Rcode 0 -IncludeSoa $true
$nodata = Read-DomainReputationDnsResponse -Buffer $nodataBytes -TransactionId 1008 -ExpectedName 'invalid.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'authoritative NODATA carries negative proof' $true $nodata.negativeProof
Assert-Equal 'authoritative NODATA has no parse error' $null $nodata.error

$nonAuthoritativeBytes = New-TestDnsResponse -TransactionId 1003 -Question 'ohiodnr.gov.multi.uribl.com' -Rcode 3 -IncludeSoa $true -Authoritative $false
$nonAuthoritative = Read-DomainReputationDnsResponse -Buffer $nonAuthoritativeBytes -TransactionId 1003 -ExpectedName 'ohiodnr.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'non-authoritative NXDOMAIN is rejected' $true (-not [string]::IsNullOrWhiteSpace($nonAuthoritative.error))

$foreignSoaBytes = New-TestDnsResponse -TransactionId 1006 -Question 'ohiodnr.gov.multi.uribl.com' -Rcode 3 -IncludeSoa $true -SoaOwner 'com'
$foreignSoa = Read-DomainReputationDnsResponse -Buffer $foreignSoaBytes -TransactionId 1006 -ExpectedName 'ohiodnr.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'NXDOMAIN with an ancestor-zone SOA is rejected' $true (-not [string]::IsNullOrWhiteSpace($foreignSoa.error))

$wrongQuestion = Read-DomainReputationDnsResponse -Buffer $negativeBytes -TransactionId 1002 -ExpectedName 'other.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'mismatched echoed question is rejected' $true (-not [string]::IsNullOrWhiteSpace($wrongQuestion.error))
$wrongTransaction = Read-DomainReputationDnsResponse -Buffer $negativeBytes -TransactionId 9999 -ExpectedName 'ohiodnr.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
Assert-Equal 'transaction mismatch remains identifiable to the receive loop' 'DNS transaction ID mismatch.' $wrongTransaction.error

$clean = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $negative -QueryDomain 'ohiodnr.gov'
Assert-Equal 'validated NXDOMAIN is not listed' 'notListed' $clean.state
Assert-Equal 'validated NXDOMAIN is conclusive' $false $clean.listed

$contradictoryNegative = [pscustomobject]@{ rcode=3; answers=@('127.0.0.2'); negativeProof=$true; error=$null }
$contradictoryResult = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $contradictoryNegative -QueryDomain 'ohiodnr.gov'
Assert-Equal 'NXDOMAIN carrying an A answer is never clean' 'unavailable' $contradictoryResult.state

$blockedBytes = New-TestDnsResponse -TransactionId 1004 -Question 'ohiodnr.gov.multi.uribl.com' -AnswerAddress '127.0.0.1'
$blockedOutcome = Read-DomainReputationDnsResponse -Buffer $blockedBytes -TransactionId 1004 -ExpectedName 'ohiodnr.gov.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
$blocked = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $blockedOutcome -QueryDomain 'ohiodnr.gov'
Assert-Equal 'URIBL bit 1 is blocked, not listed' 'blocked' $blocked.state
Assert-Equal 'blocked response is never a listing' $null $blocked.listed

$listedBytes = New-TestDnsResponse -TransactionId 1005 -Question 'listed.example.multi.uribl.com' -AnswerAddress '127.0.0.2'
$listedOutcome = Read-DomainReputationDnsResponse -Buffer $listedBytes -TransactionId 1005 -ExpectedName 'listed.example.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
$listed = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $listedOutcome -QueryDomain 'listed.example'
Assert-Equal 'URIBL bit 2 is listed' 'listed' $listed.state
Assert-Equal 'URIBL bit 2 decodes black' 'black' (@($listed.categories) -join ',')

$mixedUnknownOutcome = [pscustomobject]@{ rcode=0; answers=@('127.0.0.2', '127.0.0.0'); negativeProof=$false; error=$null }
$mixedUnknown = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $mixedUnknownOutcome -QueryDomain 'listed.example'
Assert-Equal 'one known answer cannot mask an unknown provider code' 'invalid' $mixedUnknown.state

$binaryControlBytes = New-TestDnsResponse -TransactionId 1009 -Question 'test.dbl.nordspam.com' -AnswerAddress '127.0.0.2'
$binaryControl = Read-DomainReputationDnsResponse -Buffer $binaryControlBytes -TransactionId 1009 -ExpectedName 'test.dbl.nordspam.com' -ExpectedZone 'dbl.nordspam.com'
$binaryTargetBytes = New-TestDnsResponse -TransactionId 1010 -Question 'listed.example.dbl.nordspam.com' -AnswerAddress '127.0.0.2'
$binaryTarget = Read-DomainReputationDnsResponse -Buffer $binaryTargetBytes -TransactionId 1010 -ExpectedName 'listed.example.dbl.nordspam.com' -ExpectedZone 'dbl.nordspam.com'
$binaryListed = ConvertFrom-DomainReputationProviderOutcome -Provider $nordspam -ControlOutcome $binaryControl -NegativeControlOutcome $negative -TargetOutcome $binaryTarget -QueryDomain 'listed.example'
Assert-Equal 'binary provider code 127.0.0.2 is listed' 'listed' $binaryListed.state

$foreignAddressBytes = New-TestDnsResponse -TransactionId 1007 -Question 'listed.example.multi.uribl.com' -AnswerAddress '93.184.216.34'
$foreignAddressOutcome = Read-DomainReputationDnsResponse -Buffer $foreignAddressBytes -TransactionId 1007 -ExpectedName 'listed.example.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
$foreignAddress = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $foreignAddressOutcome -QueryDomain 'listed.example'
Assert-Equal 'non-loopback provider answer is invalid' 'invalid' $foreignAddress.state

$failedControl = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $negative -NegativeControlOutcome $negative -TargetOutcome $negative -QueryDomain 'ohiodnr.gov'
Assert-Equal 'failed control cannot authorize a clean target' 'blocked' $failedControl.state
Assert-Equal 'failed control never yields not-listed' $null $failedControl.listed

$wildcardNegativeBytes = New-TestDnsResponse -TransactionId 1011 -Question 'invalid.multi.uribl.com' -AnswerAddress '127.0.0.14'
$wildcardNegative = Read-DomainReputationDnsResponse -Buffer $wildcardNegativeBytes -TransactionId 1011 -ExpectedName 'invalid.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
$wildcardResult = ConvertFrom-DomainReputationProviderOutcome -Provider $uribl -ControlOutcome $control -NegativeControlOutcome $wildcardNegative -TargetOutcome $listedOutcome -QueryDomain 'listed.example'
Assert-Equal 'wildcarded provider cannot accuse a customer domain' 'invalid' $wildcardResult.state
Assert-Equal 'wildcarded provider reports its control failure' 'wildcardDetected' $wildcardResult.reasonCode

# Providers using the binary 127.0.0.2 convention signal an access/policy block with
# 127.0.0.1, 127.0.0.255 or 127.255.255.x. Those must fail closed as 'blocked' so the
# operator is told access was refused, not that the answer was merely unreadable.
$nordspam = @(Get-DomainReputationProviderCatalog | Where-Object { $_.id -eq 'nordspam' })[0]
$nsControlBytes = New-TestDnsResponse -TransactionId 2101 -Question 'test.dbl.nordspam.com' -AnswerAddress '127.0.0.2'
$nsControl = Read-DomainReputationDnsResponse -Buffer $nsControlBytes -TransactionId 2101 -ExpectedName 'test.dbl.nordspam.com' -ExpectedZone 'dbl.nordspam.com'
foreach ($blockCode in @('127.0.0.1', '127.0.0.255', '127.255.255.254')) {
  $nsBlockBytes = New-TestDnsResponse -TransactionId 2102 -Question 'blocked.example.dbl.nordspam.com' -AnswerAddress $blockCode
  $nsBlock = Read-DomainReputationDnsResponse -Buffer $nsBlockBytes -TransactionId 2102 -ExpectedName 'blocked.example.dbl.nordspam.com' -ExpectedZone 'dbl.nordspam.com'
  $nsBlockResult = ConvertFrom-DomainReputationProviderOutcome -Provider $nordspam -ControlOutcome $nsControl -NegativeControlOutcome $negative -TargetOutcome $nsBlock -QueryDomain 'blocked.example'
  Assert-Equal ("binary provider block code {0} is reported as blocked" -f $blockCode) 'blocked' $nsBlockResult.state
  Assert-Equal ("binary provider block code {0} is never a listing" -f $blockCode) $null $nsBlockResult.listed
}
$nsListedBytes = New-TestDnsResponse -TransactionId 2104 -Question 'listed.example.dbl.nordspam.com' -AnswerAddress '127.0.0.2'
$nsListed = Read-DomainReputationDnsResponse -Buffer $nsListedBytes -TransactionId 2104 -ExpectedName 'listed.example.dbl.nordspam.com' -ExpectedZone 'dbl.nordspam.com'
$nsListedResult = ConvertFrom-DomainReputationProviderOutcome -Provider $nordspam -ControlOutcome $nsControl -NegativeControlOutcome $negative -TargetOutcome $nsListed -QueryDomain 'listed.example'
Assert-Equal 'binary provider genuine listing is still reported as listed' 'listed' $nsListedResult.state

# SURBL and Spamhaus DBL are compiled opt-in profiles that had zero classification
# coverage, so a decoder regression could mislabel a listing without any test noticing.
$surbl = @(Get-DomainReputationProviderCatalog | Where-Object { $_.id -eq 'surbl' })[0]
$surblControlBytes = New-TestDnsResponse -TransactionId 3001 -Question 'test.surbl.org.multi.surbl.org' -AnswerAddress '127.0.0.126'
$surblControl = Read-DomainReputationDnsResponse -Buffer $surblControlBytes -TransactionId 3001 -ExpectedName 'test.surbl.org.multi.surbl.org' -ExpectedZone 'multi.surbl.org'
$surblMultiBytes = New-TestDnsResponse -TransactionId 3002 -Question 'listed.example.multi.surbl.org' -AnswerAddress '127.0.0.28'
$surblMulti = Read-DomainReputationDnsResponse -Buffer $surblMultiBytes -TransactionId 3002 -ExpectedName 'listed.example.multi.surbl.org' -ExpectedZone 'multi.surbl.org'
$surblListed = ConvertFrom-DomainReputationProviderOutcome -Provider $surbl -ControlOutcome $surblControl -NegativeControlOutcome $negative -TargetOutcome $surblMulti -QueryDomain 'listed.example'
Assert-Equal 'SURBL multi-bit answer is listed' 'listed' $surblListed.state
Assert-Equal 'SURBL multi-bit decodes every category' 'disposable-mail,malware,phishing' (@($surblListed.categories | Sort-Object) -join ',')
$surblBlockBytes = New-TestDnsResponse -TransactionId 3003 -Question 'blocked.example.multi.surbl.org' -AnswerAddress '127.0.0.1'
$surblBlock = Read-DomainReputationDnsResponse -Buffer $surblBlockBytes -TransactionId 3003 -ExpectedName 'blocked.example.multi.surbl.org' -ExpectedZone 'multi.surbl.org'
$surblBlocked = ConvertFrom-DomainReputationProviderOutcome -Provider $surbl -ControlOutcome $surblControl -NegativeControlOutcome $negative -TargetOutcome $surblBlock -QueryDomain 'blocked.example'
Assert-Equal 'SURBL block bit is reported as blocked' 'blocked' $surblBlocked.state
Assert-Equal 'SURBL block bit is never a listing' $null $surblBlocked.listed
$surblReservedBytes = New-TestDnsResponse -TransactionId 3004 -Question 'reserved.example.multi.surbl.org' -AnswerAddress '127.0.0.2'
$surblReserved = Read-DomainReputationDnsResponse -Buffer $surblReservedBytes -TransactionId 3004 -ExpectedName 'reserved.example.multi.surbl.org' -ExpectedZone 'multi.surbl.org'
$surblInvalid = ConvertFrom-DomainReputationProviderOutcome -Provider $surbl -ControlOutcome $surblControl -NegativeControlOutcome $negative -TargetOutcome $surblReserved -QueryDomain 'reserved.example'
Assert-Equal 'SURBL reserved bit fails closed as invalid' 'invalid' $surblInvalid.state

$spamhaus = @(Get-DomainReputationProviderCatalog | Where-Object { $_.id -eq 'spamhaus' })[0]
$shControlBytes = New-TestDnsResponse -TransactionId 3010 -Question 'dbltest.com.dbl.spamhaus.org' -AnswerAddress '127.0.1.2'
$shControl = Read-DomainReputationDnsResponse -Buffer $shControlBytes -TransactionId 3010 -ExpectedName 'dbltest.com.dbl.spamhaus.org' -ExpectedZone 'dbl.spamhaus.org'
$shPhishBytes = New-TestDnsResponse -TransactionId 3011 -Question 'phish.example.dbl.spamhaus.org' -AnswerAddress '127.0.1.4'
$shPhish = Read-DomainReputationDnsResponse -Buffer $shPhishBytes -TransactionId 3011 -ExpectedName 'phish.example.dbl.spamhaus.org' -ExpectedZone 'dbl.spamhaus.org'
$shPhishResult = ConvertFrom-DomainReputationProviderOutcome -Provider $spamhaus -ControlOutcome $shControl -NegativeControlOutcome $negative -TargetOutcome $shPhish -QueryDomain 'phish.example'
Assert-Equal 'Spamhaus phishing code is listed' 'listed' $shPhishResult.state
Assert-Equal 'Spamhaus phishing code decodes its category' 'phishing' (@($shPhishResult.categories) -join ',')
$shAbusedBytes = New-TestDnsResponse -TransactionId 3012 -Question 'abused.example.dbl.spamhaus.org' -AnswerAddress '127.0.1.102'
$shAbused = Read-DomainReputationDnsResponse -Buffer $shAbusedBytes -TransactionId 3012 -ExpectedName 'abused.example.dbl.spamhaus.org' -ExpectedZone 'dbl.spamhaus.org'
$shAbusedResult = ConvertFrom-DomainReputationProviderOutcome -Provider $spamhaus -ControlOutcome $shControl -NegativeControlOutcome $negative -TargetOutcome $shAbused -QueryDomain 'abused.example'
Assert-Equal 'Spamhaus abused-legitimate code decodes its category' 'abused-legitimate' (@($shAbusedResult.categories) -join ',')
foreach ($shBlockIp in @('127.0.1.255', '127.255.255.254')) {
  $shBlockBytes = New-TestDnsResponse -TransactionId 3013 -Question 'blocked.example.dbl.spamhaus.org' -AnswerAddress $shBlockIp
  $shBlock = Read-DomainReputationDnsResponse -Buffer $shBlockBytes -TransactionId 3013 -ExpectedName 'blocked.example.dbl.spamhaus.org' -ExpectedZone 'dbl.spamhaus.org'
  $shBlockResult = ConvertFrom-DomainReputationProviderOutcome -Provider $spamhaus -ControlOutcome $shControl -NegativeControlOutcome $negative -TargetOutcome $shBlock -QueryDomain 'blocked.example'
  Assert-Equal ("Spamhaus block code {0} is reported as blocked" -f $shBlockIp) 'blocked' $shBlockResult.state
  Assert-Equal ("Spamhaus block code {0} is never a listing" -f $shBlockIp) $null $shBlockResult.listed
}

# Profiles are code-owned, so a typo in one is a build-time mistake. Catch it here
# rather than adding a request-path validation branch that can never fire in prod.
foreach ($providerProfile in @(Get-DomainReputationProviderCatalog)) {
  Assert-Equal ("profile {0} declares a known classifier" -f $providerProfile.id) $true (@('uribl', 'surbl', 'spamhausDbl', 'binary127002') -contains [string]$providerProfile.classifier)
  Assert-Equal ("profile {0} declares a known control match mode" -f $providerProfile.id) $true (@('anyOf', 'exactSet') -contains [string]$providerProfile.controlMatch)
  Assert-Equal ("profile {0} declares a known query name mode" -f $providerProfile.id) $true (@('registrableDomain', 'exactHost') -contains [string]$providerProfile.queryNameMode)
  Assert-Equal ("profile {0} declares a positive control" -f $providerProfile.id) $true (@($providerProfile.controlExpected).Count -gt 0)
}

# The SOA owner check is what authorizes a "not listed" verdict, so it is held to an
# EXACT match against the provider's configured zone. Loosening it to accept any
# ancestor was evaluated and rejected: the companion ownerCoversQuestion check is
# itself only a suffix match, so an SOA owned by the bare TLD would have satisfied
# both halves and manufactured a false clean.
$soaCases = @(
  @{ Owner = 'multi.uribl.com'; Expected = $true;  Label = 'exact zone proves a negative answer' },
  @{ Owner = 'uribl.com';       Expected = $false; Label = 'parent zone does not prove a negative answer' },
  @{ Owner = 'com';             Expected = $false; Label = 'bare TLD never proves a negative answer' },
  @{ Owner = 'other.uribl.com'; Expected = $false; Label = 'sibling zone never proves a negative answer' },
  @{ Owner = 'multi.uribl.net'; Expected = $false; Label = 'unrelated zone never proves a negative answer' }
)
foreach ($soaCase in $soaCases) {
  $soaBytes = New-TestDnsResponse -TransactionId 4001 -Question 'invalid.multi.uribl.com' -Rcode 3 -IncludeSoa $true -SoaOwner $soaCase.Owner
  $soaParsed = Read-DomainReputationDnsResponse -Buffer $soaBytes -TransactionId 4001 -ExpectedName 'invalid.multi.uribl.com' -ExpectedZone 'multi.uribl.com'
  Assert-Equal $soaCase.Label $soaCase.Expected ([bool]$soaParsed.negativeProof)
  if (-not $soaCase.Expected) {
    Assert-Equal ("{0} and is reported as an error" -f $soaCase.Label) $false ([string]::IsNullOrWhiteSpace([string]$soaParsed.error))
  }
}

# Replace network-facing seams with deterministic in-process doubles.
function Get-DomainReputationProviderEndpoints {
  param([object]$Provider, [int]$MaxEndpoints = 2)
  return @('93.184.216.34')
}
function Get-RegistrableDomain { param([string]$Domain) return $Domain }
function Test-DomainName { param([string]$Domain) return $true }
$script:domainControlOutcome = $control
$script:domainBinaryControlOutcome = $listedOutcome
$script:domainNegativeOutcome = $negative
$script:domainForceFailedControl = $false
$script:domainFanoutPurposes = [System.Collections.Generic.List[string]]::new()
function Invoke-DomainReputationDnsFanout {
  param([object[]]$Queries, [int]$TimeoutMs = 2500)
  $outcomes = @{}
  $script:domainFanoutPurposes.Add((@($Queries | ForEach-Object purpose) -join ','))
  foreach ($query in $Queries) {
    if ($query.purpose -eq 'control' -and $script:domainForceFailedControl) {
      $outcomes[$query.key] = $script:domainNegativeOutcome
    } elseif ($query.purpose -eq 'control' -and $query.key -like 'uribl|*') {
      $outcomes[$query.key] = $script:domainControlOutcome
    } elseif ($query.purpose -eq 'control') {
      $outcomes[$query.key] = $script:domainBinaryControlOutcome
    } else {
      $outcomes[$query.key] = $script:domainNegativeOutcome
    }
  }
  return $outcomes
}

$oldProviders = $env:ACS_DOMAIN_REPUTATION_PROVIDERS
$oldDisable = $env:ACS_DISABLE_DOMAIN_REPUTATION
try {
  $env:ACS_DOMAIN_REPUTATION_PROVIDERS = ''
  $env:ACS_DISABLE_DOMAIN_REPUTATION = '0'
  if ($global:AcsDomainReputationCache) { $global:AcsDomainReputationCache.Clear() }
  if ($global:AcsDomainReputationHealth) { $global:AcsDomainReputationHealth.Clear() }
  if ($global:AcsDomainReputationProviderBudgets) { $global:AcsDomainReputationProviderBudgets.Clear() }
  $global:AcsDomainReputationBudgetState.tokens = 120.0
  $global:AcsDomainReputationBudgetState.updatedAtUtc = [DateTime]::UtcNow
  $script:domainFanoutPurposes.Clear()
  $domainResult = Get-DomainReputationStatus -Domain 'ohiodnr.gov'
  Assert-Equal 'domain status emits one object' 1 @($domainResult).Count
  Assert-Equal 'Ohio DNR domain reputation is checked' 'clean' $domainResult.state
  Assert-Equal 'default orchestration requests three providers' 3 $domainResult.requestedCount
  Assert-Equal 'default orchestration configures three providers' 3 $domainResult.configuredCount
  Assert-Equal 'default orchestration drops no providers' 0 $domainResult.droppedCount
  Assert-Equal 'Ohio DNR has three validated negative providers' 3 $domainResult.summary.notListedCount
  Assert-Equal 'provider results remain arrays after JSON round trip' 'System.Object[]' (($domainResult | ConvertTo-Json -Depth 16 | ConvertFrom-Json).results.GetType().FullName)
  Assert-Equal 'API does not expose provider wire query names' $false (($domainResult | ConvertTo-Json -Depth 16 -Compress).Contains('ohiodnr.gov.multi.uribl.com'))
  Assert-Equal 'cache keys do not contain raw customer domains' $false (@($global:AcsDomainReputationCache.Keys | Where-Object { $_ -like '*ohiodnr.gov*' }).Count -gt 0)
  Assert-Equal 'cold provider lookup validates before target stage' 'control,control,control|negative,target,negative,target,negative,target' ($script:domainFanoutPurposes -join '|')

  $script:domainFanoutPurposes.Clear()
  $warmResult = Get-DomainReputationStatus -Domain 'second.example'
  # A cached positive control authorizes SENDING the customer name, but the verdict
  # must rest on a control observed in THIS request. Otherwise a provider that began
  # refusing access by answering NXDOMAIN for every name would be indistinguishable
  # from a genuine "not listed" answer, producing a false clean until the health
  # entry expired. The re-query rides in the SAME fan-out, so it costs no round trip.
  Assert-Equal 'warm provider lookup re-observes a fresh positive control' 'negative,target,control,negative,target,control,negative,target,control' ($script:domainFanoutPurposes -join '|')
  Assert-Equal 'warm provider lookup still performs a single fan-out' 1 $script:domainFanoutPurposes.Count
  Assert-Equal 'warm provider lookup sends one fresh control per provider' 3 (@(($script:domainFanoutPurposes -join ',') -split ',' | Where-Object { $_ -eq 'control' }).Count)
  Assert-Equal 'warm provider result remains clean' 'clean' $warmResult.state

  # Health is still cached at this point. Simulate a provider revoking access between
  # the cached probe and this request: the same empty answers that previously meant
  # "not listed" must stop being trusted the moment the fresh control fails. Without
  # the in-request control re-query this returns a FALSE CLEAN.
  $script:domainFanoutPurposes.Clear()
  $script:domainForceFailedControl = $true
  $revoked = Get-DomainReputationStatus -Domain 'revoked.example'
  Assert-Equal 'revoked access on a warm lookup still sends a fresh control' 3 (@(($script:domainFanoutPurposes -join ',') -split ',' | Where-Object { $_ -eq 'control' }).Count)
  Assert-Equal 'revoked access on a warm lookup never reports clean' $false ($revoked.state -eq 'clean')
  Assert-Equal 'revoked access on a warm lookup never reports listed' $false ($revoked.state -eq 'listed')
  Assert-Equal 'revoked access yields no not-listed providers' 0 $revoked.summary.notListedCount
  Assert-Equal 'revoked access is surfaced as a provider block' 'providerBlocked' $revoked.reasonCode
  $script:domainForceFailedControl = $false

  if ($global:AcsDomainReputationHealth) { $global:AcsDomainReputationHealth.Clear() }
  $script:domainFanoutPurposes.Clear()
  $script:domainForceFailedControl = $true
  $failedPreflight = Get-DomainReputationStatus -Domain 'blocked.example'
  Assert-Equal 'failed positive controls send no customer target query' 'control,control,control' ($script:domainFanoutPurposes -join '|')
  Assert-Equal 'failed positive control remains inconclusive' 'unknown' $failedPreflight.state
  $script:domainForceFailedControl = $false

  # A repeat lookup for the same domain must be served from the result cache and
  # must not touch the network again.
  if ($global:AcsDomainReputationCache) { $global:AcsDomainReputationCache.Clear() }
  if ($global:AcsDomainReputationHealth) { $global:AcsDomainReputationHealth.Clear() }
  if ($global:AcsDomainReputationProviderBudgets) { $global:AcsDomainReputationProviderBudgets.Clear() }
  $global:AcsDomainReputationBudgetState.tokens = 120.0
  $global:AcsDomainReputationBudgetState.updatedAtUtc = [DateTime]::UtcNow
  $script:domainFanoutPurposes.Clear()
  $firstLookup = Get-DomainReputationStatus -Domain 'cached.example'
  Assert-Equal 'first lookup queries the providers' $true ($script:domainFanoutPurposes.Count -gt 0)
  $script:domainFanoutPurposes.Clear()
  $secondLookup = Get-DomainReputationStatus -Domain 'cached.example'
  Assert-Equal 'repeat lookup is served from cache with no DNS queries' 0 $script:domainFanoutPurposes.Count
  Assert-Equal 'repeat lookup returns the same state' $firstLookup.state $secondLookup.state

  # With every concurrency permit held the request must fail fast instead of queueing.
  $heldPermits = 0
  while ($global:AcsDomainReputationGate.Wait(0)) { $heldPermits++ }
  $busyResult = Get-DomainReputationStatus -Domain 'busy.example'
  for ($i = 0; $i -lt $heldPermits; $i++) { $null = $global:AcsDomainReputationGate.Release() }
  Assert-Equal 'saturated concurrency gate reports busy' 'busy' $busyResult.reasonCode
  Assert-Equal 'saturated concurrency gate stays inconclusive' 'unknown' $busyResult.state

  # Budget exhaustion must be explained rather than surfacing as a bare 'unknown'.
  Assert-Equal 'a cost above the whole budget is denied' $false (Test-DomainReputationQueryBudget -Cost 1000)
  if ($global:AcsDomainReputationCache) { $global:AcsDomainReputationCache.Clear() }
  $global:AcsDomainReputationBudgetState.tokens = 0.0
  $global:AcsDomainReputationBudgetState.updatedAtUtc = [DateTime]::UtcNow
  $script:domainFanoutPurposes.Clear()
  $budgetResult = Get-DomainReputationStatus -Domain 'budget.example'
  Assert-Equal 'budget exhaustion stays inconclusive' 'unknown' $budgetResult.state
  Assert-Equal 'budget exhaustion is explained at the top level' 'queryBudget' $budgetResult.reasonCode
  Assert-Equal 'budget exhaustion is explained per provider' 'queryBudget' $budgetResult.results[0].reasonCode
  Assert-Equal 'budget exhaustion sends no DNS queries' 0 (@($script:domainFanoutPurposes) -join ',').Length
  $global:AcsDomainReputationBudgetState.tokens = 120.0
  $global:AcsDomainReputationBudgetState.updatedAtUtc = [DateTime]::UtcNow

  $env:ACS_DISABLE_DOMAIN_REPUTATION = '1'
  $disabledResult = Get-DomainReputationStatus -Domain 'disabled.example'
  Assert-Equal 'disable switch turns the scope off' 'disabled' $disabledResult.state
  Assert-Equal 'disable switch reports its reason' 'disabled' $disabledResult.reasonCode
  $env:ACS_DISABLE_DOMAIN_REPUTATION = '0'

  $env:ACS_DOMAIN_REPUTATION_PROVIDERS = 'not-a-real-provider'
  $noProviderResult = Get-DomainReputationStatus -Domain 'noprovider.example'
  Assert-Equal 'unmatched provider selection disables the scope' 'disabled' $noProviderResult.state
  Assert-Equal 'unmatched provider selection reports noProviders' 'noProviders' $noProviderResult.reasonCode
  Assert-Equal 'unmatched provider selection counts the drop' 1 $noProviderResult.droppedCount
  $env:ACS_DOMAIN_REPUTATION_PROVIDERS = ''

  # These two redefine shared doubles, so they run last.
  if ($global:AcsDomainReputationCache) { $global:AcsDomainReputationCache.Clear() }
  function Get-DomainReputationProviderEndpoints { param([object]$Provider, [int]$MaxEndpoints = 2) return @() }
  $noAuthorityResult = Get-DomainReputationStatus -Domain 'noauthority.example'
  Assert-Equal 'endpoint discovery failure degrades the provider' 'unavailable' $noAuthorityResult.results[0].state
  Assert-Equal 'endpoint discovery failure reports noAuthority' 'noAuthority' $noAuthorityResult.results[0].reasonCode

  if ($global:AcsDomainReputationCache) { $global:AcsDomainReputationCache.Clear() }
  function Test-DomainName { param([string]$Domain) return $false }
  $invalidNameResult = Get-DomainReputationStatus -Domain 'bad name.example'
  Assert-Equal 'unusable query name is rejected before any query' 'invalid' $invalidNameResult.results[0].state
  Assert-Equal 'unusable query name reports invalidName' 'invalidName' $invalidNameResult.results[0].reasonCode
} finally {
  $env:ACS_DOMAIN_REPUTATION_PROVIDERS = $oldProviders
  $env:ACS_DISABLE_DOMAIN_REPUTATION = $oldDisable
}

$runspaceSource = Get-Content $runspaceFile -Raw
foreach ($functionName in @(
  'Get-DomainReputationProviderCatalog',
  'New-DomainReputationDnsQueryPacket',
  'Read-DomainReputationDnsResponse',
  'Invoke-DomainReputationDnsFanout',
  'Test-DomainReputationPositiveControl',
  'Test-DomainReputationProviderControl',
  'ConvertFrom-DomainReputationProviderOutcome',
  'Get-DomainReputationProviderEndpoints',
  'Get-DomainReputationStatus'
)) {
  Assert-Equal "runspace registers $functionName" $true $runspaceSource.Contains("'$functionName'")
}

$uiSource = Get-Content $uiFile -Raw
Assert-Equal 'UI exposes one shared reputation view model' $true $uiSource.Contains('function getReputationViewModel(rep)')

if ($failures.Count -gt 0) {
  Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("`nPASS: {0} literal domain reputation checks passed." -f $checks) -ForegroundColor Green
