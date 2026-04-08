# ===== CLI One-Shot Mode =====
# ------------------- CLI ONE-SHOT MODE -------------------
# When -TestDomain is provided, run a full check, print JSON to stdout, and exit
# without starting the web server.
if (-not [string]::IsNullOrWhiteSpace($TestDomain)) {
  $cliDomain = ConvertTo-NormalizedDomain -Raw $TestDomain
  if ([string]::IsNullOrWhiteSpace($cliDomain) -or -not (Test-DomainName -Domain $cliDomain)) {
    [pscustomobject]@{
      mode = 'CliTest'
      error = 'Invalid domain parameter.'
      input = $TestDomain
    } | ConvertTo-Json -Depth 8
    return
  }

  $aggregate = Get-AcsDnsStatus -Domain $cliDomain
  $reputation = Get-DnsReputationStatus -Domain $cliDomain

  [pscustomobject]@{
    mode = 'CliTest'
    domain = $cliDomain
    collectedAtUtc = ([DateTime]::UtcNow.ToString('o'))
    aggregate = $aggregate
    reputation = $reputation
  } | ConvertTo-Json -Depth 8
  return
}

