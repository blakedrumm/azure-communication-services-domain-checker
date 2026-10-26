# Offline regression checks for API key configuration, request authentication,
# and the built-in UI's single-key template injection.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-ApiKeys.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()
$checks = 0

function Assert-Condition {
  param([string]$Name, [bool]$Condition)

  $script:checks++
  if ($Condition) {
    Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
  } else {
    Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
    $script:failures.Add($Name)
  }
}

function New-TestRequest {
  param([hashtable]$Headers = @{}, [string]$QueryKey)

  $requestHeaders = [System.Collections.Specialized.NameValueCollection]::new()
  foreach ($name in $Headers.Keys) { $requestHeaders[$name] = [string]$Headers[$name] }
  $query = [System.Collections.Specialized.NameValueCollection]::new()
  if ($null -ne $QueryKey) { $query['apiKey'] = $QueryKey }
  return [pscustomobject]@{
    Request = [pscustomobject]@{ Headers = $requestHeaders; QueryString = $query }
  }
}

function Get-TestHtml {
  $htmlPage = "const acsApiKey = '__ACS_API_KEY__';"
  . (Join-Path $repoRoot 'src\20f-HtmlPostProcess.ps1')
  return $htmlPage
}

function Assert-InvalidConfiguration {
  param([string]$Name, [scriptblock]$Action)

  $rejected = $false
  try { & $Action | Out-Null }
  catch {
    $rejected = $_.Exception.Message -eq 'ACS_API_KEYS must contain at least one non-empty API key.'
  }
  Assert-Condition $Name $rejected
}

$savedApiKey = $env:ACS_API_KEY
$savedApiKeys = $env:ACS_API_KEYS
try {
  # Skip listener startup while importing the shared configuration helper.
  $TestDomain = 'example.com'
  . (Join-Path $repoRoot 'src\08-ServerStartup.ps1')
  . (Join-Path $repoRoot 'src\15-RequestUtilities.ps1')
  $script:AppVersion = 'test'

  Write-Host '=== API Key Authentication ===' -ForegroundColor Cyan

  $env:ACS_API_KEY = $null
  $env:ACS_API_KEYS = $null
  Assert-Condition 'unset configuration has no keys' (@(Get-ConfiguredApiKeys).Count -eq 0)
  Assert-Condition 'unset configuration preserves open access' (Test-ApiKey -Context (New-TestRequest))
  Assert-Condition 'open access accepts requests carrying a key' (Test-ApiKey -Context (New-TestRequest -QueryKey 'unused-key'))
  Assert-Condition 'open-access UI has an empty key' ((Get-TestHtml) -eq "const acsApiKey = '';")

  $env:ACS_API_KEY = ' '
  $env:ACS_API_KEYS = " `t`r`n "
  Assert-Condition 'whitespace-only configuration preserves open access' (Test-ApiKey -Context (New-TestRequest))

  $env:ACS_API_KEY = 'Legacy-Key'
  $env:ACS_API_KEYS = $null
  Assert-Condition 'single-key configuration remains supported' (Test-ApiKey -Context (New-TestRequest -Headers @{ 'X-Api-Key' = 'Legacy-Key' }))
  Assert-Condition 'single-key matching remains case-sensitive' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'legacy-key')))
  Assert-Condition 'single-key configuration rejects a missing key' (-not (Test-ApiKey -Context (New-TestRequest)))
  Assert-Condition 'single-key UI retains the legacy key' ((Get-TestHtml) -eq "const acsApiKey = 'Legacy-Key';")

  $env:ACS_API_KEY = 'legacy,key;literal'
  Assert-Condition 'legacy punctuation is not split into multiple keys' (@(Get-ConfiguredApiKeys).Count -eq 1)
  Assert-Condition 'legacy punctuation remains valid' (Test-ApiKey -Context (New-TestRequest -QueryKey 'legacy,key;literal'))
  Assert-Condition 'a fragment of the legacy key is rejected' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'legacy')))

  $env:ACS_API_KEY = $null
  $env:ACS_API_KEYS = 'only-key'
  Assert-Condition 'plural variable supports a single entry' (Test-ApiKey -Context (New-TestRequest -QueryKey 'only-key'))

  $separatorIndex = 0
  foreach ($separator in @(',', ';', "`r", "`n", "`r`n")) {
    $separatorIndex++
    $env:ACS_API_KEYS = 'first-key' + $separator + 'second-key'
    Assert-Condition ("separator {0} produces two keys" -f $separatorIndex) (@(Get-ConfiguredApiKeys).Count -eq 2)
    Assert-Condition ("separator {0} accepts the second key" -f $separatorIndex) (Test-ApiKey -Context (New-TestRequest -QueryKey 'second-key'))
  }

  $env:ACS_API_KEYS = " first-key , ; second-key;`r`nthird-key `nfourth-key,, "
  $keys = @(Get-ConfiguredApiKeys)
  Assert-Condition 'mixed separators trim entries and ignore empty entries' (($keys -join '|') -ceq 'first-key|second-key|third-key|fourth-key')
  $keyIndex = 0
  foreach ($key in $keys) {
    $keyIndex++
    foreach ($header in @('X-Api-Key', 'X-ACS-API-Key', 'Authorization')) {
      $value = if ($header -eq 'Authorization') { "aPiKeY $key" } else { $key }
      Assert-Condition ("key {0} is accepted through {1}" -f $keyIndex, $header) (Test-ApiKey -Context (New-TestRequest -Headers @{ $header = $value }))
    }
    Assert-Condition ("key {0} is accepted through the query fallback" -f $keyIndex) (Test-ApiKey -Context (New-TestRequest -QueryKey $key))
  }
  Assert-Condition 'request header whitespace is still trimmed' (Test-ApiKey -Context (New-TestRequest -Headers @{ 'X-Api-Key' = '  second-key  ' }))
  Assert-Condition 'multiple keys reject a missing key' (-not (Test-ApiKey -Context (New-TestRequest)))
  Assert-Condition 'multiple keys reject an unknown key' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'unknown-key')))
  Assert-Condition 'multiple keys reject a partial key' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'first')))
  Assert-Condition 'multiple keys reject mismatched case' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'FIRST-KEY')))
  Assert-Condition 'a list supplied as the request key is rejected' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'first-key,second-key')))
  Assert-Condition 'Bearer authorization is not treated as an API key' (-not (Test-ApiKey -Context (New-TestRequest -Headers @{ Authorization = 'Bearer first-key' })))
  Assert-Condition 'primary-header precedence is unchanged' (-not (Test-ApiKey -Context (New-TestRequest -Headers @{ 'X-Api-Key' = 'invalid-key'; 'X-ACS-API-Key' = 'second-key' } -QueryKey 'third-key')))
  Assert-Condition 'plural-only UI embeds only the first key' ((Get-TestHtml) -eq "const acsApiKey = 'first-key';")

  $env:ACS_API_KEY = 'legacy-key'
  Assert-Condition 'legacy key and list are combined' (@(Get-ConfiguredApiKeys).Count -eq 5)
  Assert-Condition 'legacy key remains accepted alongside the list' (Test-ApiKey -Context (New-TestRequest -QueryKey 'legacy-key'))
  Assert-Condition 'list keys remain accepted alongside the legacy key' (Test-ApiKey -Context (New-TestRequest -QueryKey 'fourth-key'))
  Assert-Condition 'legacy key takes precedence for UI injection' ((Get-TestHtml) -eq "const acsApiKey = 'legacy-key';")

  $env:ACS_API_KEY = $null
  $env:ACS_API_KEYS = 'Case-Key,case-key,Case-Key'
  Assert-Condition 'case-distinct keys are accepted independently' ((Test-ApiKey -Context (New-TestRequest -QueryKey 'Case-Key')) -and (Test-ApiKey -Context (New-TestRequest -QueryKey 'case-key')))
  Assert-Condition 'duplicate entries do not authorize another key' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'CASE-KEY')))

  $env:ACS_API_KEYS = 'replacement-key'
  Assert-Condition 'removed keys are rejected' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey 'Case-Key')))
  Assert-Condition 'replacement keys are accepted' (Test-ApiKey -Context (New-TestRequest -QueryKey 'replacement-key'))

  $base64Key = [Convert]::ToBase64String([byte[]]@(251,255,255,0))
  $guidKey = '11111111-2222-4333-8444-555555555555'
  $env:ACS_API_KEYS = $base64Key + ',' + $guidKey
  Assert-Condition 'Base64 plus, slash, and padding characters authenticate through headers' (Test-ApiKey -Context (New-TestRequest -Headers @{ 'X-Api-Key' = $base64Key }))
  Assert-Condition 'dashed GUID-style keys are also accepted' (Test-ApiKey -Context (New-TestRequest -QueryKey $guidKey))
  $encodedKey = [uri]::EscapeDataString($base64Key)
  $decodedKey = [System.Net.WebUtility]::UrlDecode($encodedKey)
  Assert-Condition 'URL-encoded Base64 keys survive query decoding' (Test-ApiKey -Context (New-TestRequest -QueryKey $decodedKey))
  $unencodedKey = [System.Net.WebUtility]::UrlDecode($base64Key)
  Assert-Condition 'raw Base64 plus signs do not survive query decoding' (-not (Test-ApiKey -Context (New-TestRequest -QueryKey $unencodedKey)))

  $env:ACS_API_KEYS = "browser'</script>\key,service-only-key"
  Assert-Condition 'UI key injection retains JavaScript escaping' ((Get-TestHtml) -eq "const acsApiKey = 'browser\'\u003C/script\u003E\\key';")

  $env:ACS_API_KEYS = " ,;`r`n ; "
  Assert-InvalidConfiguration 'separator-only lists are rejected' { Get-ConfiguredApiKeys }
  Assert-InvalidConfiguration 'separator-only lists cannot enable open access' { Test-ApiKey -Context (New-TestRequest) }
  $env:ACS_API_KEY = 'legacy-key'
  Assert-InvalidConfiguration 'a legacy key does not mask an invalid list' { Get-ConfiguredApiKeys }
}
finally {
  $env:ACS_API_KEY = $savedApiKey
  $env:ACS_API_KEYS = $savedApiKeys
}

if ($failures.Count -gt 0) {
  Write-Host ("FAIL: {0} of {1} API key checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("PASS: All {0} API key checks passed." -f $checks) -ForegroundColor Green
