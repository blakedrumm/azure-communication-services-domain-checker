# ===== Email Quota Report =====
# ------------------- EMAIL QUOTA REPORT (/api/email-quota) -------------------
# Server-side equivalent of the SPA's "Email Quota" checklist card and its
# "Copy Email Quota" table, so automation can get the same verdict without
# driving the browser.
#
# The SPA builds this view in JavaScript (render() and getDomainQuotaStatus() in
# 20d-HtmlJsCore.ps1, with helpers in 20c-HtmlJsUtilities.ps1). The rules below
# MIRROR that code. When you change a verdict rule in one place, change it in
# the other, or the API and the UI will disagree for the same domain.
#
# Intentional differences from the SPA:
# - Text is English only. Localization lives in the SPA translation tables.
# - The SPA reads the expected sending tier from the Customer Intake form to
#   decide whether a monitor-only DMARC policy (p=none) is a warning. The API
#   has no intake form, so callers opt in with requireDmarcEnforcement=true.
# - The Customer Intake block appended by "Copy Email Quota" is not included.

# Runs every check that feeds the Email Quota card and returns the report.
function Get-AcsEmailQuotaStatus {
  param(
    [string]$Domain,
    [string]$SpfRequiredInclude,
    [object]$Dkim1Override,
    [object]$Dkim2Override,
    [bool]$RequireDmarcEnforcement = $false,
    [string]$PageLink
  )

  # /dns covers base TXT/SPF, MX, DNS records, WHOIS, DMARC, DKIM and CNAME.
  $status = Get-AcsDnsStatus -Domain $Domain -SpfRequiredInclude $SpfRequiredInclude -Dkim1Override $Dkim1Override -Dkim2Override $Dkim2Override

  # Reputation and website run separately in the SPA, so a failure in either
  # one becomes an ERROR row instead of failing the whole report. Raw exception
  # text is never returned to the caller; it goes to the secure logger only.
  $reputation = $null
  $reputationError = $null
  try {
    $reputation = Get-DnsReputationStatus -Domain $Domain
  } catch {
    $reputationError = 'Reputation check failed.'
    Write-AcsLogException -Level 'Warning' -Component 'EmailQuota' -Operation 'reputation' -EventId 'EMAIL-QUOTA-REPUTATION-ERROR' -ErrorCode 'ACS-EMAIL-QUOTA-REPUTATION' -Exception $_
  }

  $website = $null
  $websiteError = $null
  try {
    $website = Get-WebsiteProbeStatus -Domain $Domain
  } catch {
    $websiteError = 'Website check failed.'
    Write-AcsLogException -Level 'Warning' -Component 'EmailQuota' -Operation 'website' -EventId 'EMAIL-QUOTA-WEBSITE-ERROR' -ErrorCode 'ACS-EMAIL-QUOTA-WEBSITE' -Exception $_
  }

  # The SPA recovers SPF/ACS TXT records from the per-nameserver check only when
  # public DNS returned no TXT records at all. Query the nameservers only in that
  # case so healthy domains do not pay for the extra lookups.
  $nameservers = $null
  if (@($status.txtRecords | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0) {
    try {
      $nameservers = Get-NameserverTxtStatus -Domain $Domain
    } catch {
      $nameservers = $null
      Write-AcsLogException -Level 'Warning' -Component 'EmailQuota' -Operation 'nameservers' -EventId 'EMAIL-QUOTA-NAMESERVERS-ERROR' -ErrorCode 'ACS-EMAIL-QUOTA-NAMESERVERS' -Exception $_
    }
  }

  return ConvertTo-AcsEmailQuotaReport -Status $status -Reputation $reputation -ReputationError $reputationError -Website $website -WebsiteError $websiteError -Nameservers $nameservers -RequireDmarcEnforcement $RequireDmarcEnforcement -PageLink $PageLink
}

# Converts raw check results into the Email Quota report. Makes no network
# calls, so tools/Test-EmailQuota.ps1 can exercise every rule with fixtures.
function ConvertTo-AcsEmailQuotaReport {
  param(
    [Parameter(Mandatory = $true)][object]$Status,
    [object]$Reputation,
    [string]$ReputationError,
    [object]$Website,
    [string]$WebsiteError,
    [object]$Nameservers,
    [bool]$RequireDmarcEnforcement = $false,
    [string]$PageLink
  )

  # ---- Nested helpers (not registered in the runspace pool; see 22-RunspaceSetup.ps1) ----
  function Get-QuotaProp {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
  }

  function Get-QuotaStringArray {
    param([object]$Value)
    if ($null -eq $Value) { return @() }
    return @(@($Value) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
  }

  function Get-QuotaNumber {
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    $n = 0.0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $n }
    return 0
  }

  function Test-QuotaHasValue {
    param([object]$Value)
    return ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value))
  }

  $domain = [string](Get-QuotaProp $Status 'domain')
  $errors = [ordered]@{}
  if (-not [string]::IsNullOrWhiteSpace($ReputationError)) { $errors['reputation'] = $ReputationError }
  if (-not [string]::IsNullOrWhiteSpace($WebsiteError)) { $errors['website'] = $WebsiteError }

  # ================= Effective TXT / SPF / ACS view =================
  # Get-AcsDnsStatus already recovers TXT data from the detailed DNS records.
  # This adds the SPA's last fallback (getDnsTxtRecoveryState in 20c): the union
  # of TXT records served by the authoritative nameservers, used only when
  # public DNS returned no TXT records for the queried domain.
  $requiredInclude = [string](Get-QuotaProp $Status 'spfRequiredInclude')
  if ([string]::IsNullOrWhiteSpace($requiredInclude)) { $requiredInclude = 'spf.protection.outlook.com' }
  $requiredIncludePattern = '(?i)(^|\s)include:' + [regex]::Escape($requiredInclude) + '(?=\s|$)'

  $baseTxtRecords = Get-QuotaStringArray (Get-QuotaProp $Status 'txtRecords')
  $nameserverTxtUnion = [System.Collections.Generic.List[string]]::new()
  foreach ($ns in @(Get-QuotaProp $Nameservers 'results')) {
    if ($null -eq $ns -or (Get-QuotaProp $ns 'success') -ne $true) { continue }
    foreach ($rec in (Get-QuotaStringArray (Get-QuotaProp $ns 'txtRecords'))) {
      if (-not $nameserverTxtUnion.Contains($rec)) { $nameserverTxtUnion.Add($rec) }
    }
  }
  $recoveredFromNameservers = ($baseTxtRecords.Count -eq 0 -and $nameserverTxtUnion.Count -gt 0)

  if ($recoveredFromNameservers) {
    $spfRecords = @($nameserverTxtUnion | Where-Object { $_ -match '(?i)^v=spf1\b' })
    # Prefer the record carrying the required include, as Select-SpfRecordFromSet does.
    $spfValue = @($spfRecords | Where-Object { $_ -match $requiredIncludePattern }) | Select-Object -First 1
    if (-not $spfValue) { $spfValue = $spfRecords | Select-Object -First 1 }
    $acsValues = @($nameserverTxtUnion | Where-Object { $_ -match '(?i)ms-domain-verification' })
    $spfHasRequiredInclude = $null
    if ($spfValue) { $spfHasRequiredInclude = [bool]($spfValue -match $requiredIncludePattern) }
    $spfMatchType = Get-QuotaProp $Status 'spfRequiredIncludeMatchType'
    if ($spfValue -and (($spfValue -match '(?i)include:[^\s]*%\{[^\s]*outlook\.com') -or ($spfValue -match '%\{' -and $spfValue -match '(?i)include:|redirect=' -and -not $spfHasRequiredInclude))) {
      $spfMatchType = 'macro-delegated'
    }
  } else {
    $spfRecords = Get-QuotaStringArray (Get-QuotaProp $Status 'spfRecords')
    $spfValue = [string](Get-QuotaProp $Status 'spfValue')
    if ($spfRecords.Count -eq 0 -and $spfValue) { $spfRecords = @($spfValue) }
    $acsValues = Get-QuotaStringArray (Get-QuotaProp $Status 'acsValues')
    $spfHasRequiredInclude = Get-QuotaProp $Status 'spfHasRequiredInclude'
    $spfMatchType = Get-QuotaProp $Status 'spfRequiredIncludeMatchType'
  }

  $spfPresent = -not [string]::IsNullOrWhiteSpace([string]$spfValue)
  $spfMultipleRecords = (@($spfRecords).Count -gt 1)
  # Macro-delegated SPF cannot be confirmed statically, so it is indeterminate (null), not failed.
  if ([string]$spfMatchType -eq 'macro-delegated') { $spfHasRequiredInclude = $null }
  $spfIsMacroDelegated = ([string]$spfMatchType -eq 'macro-delegated') -or ($spfPresent -and $null -eq $spfHasRequiredInclude)
  $acsPresent = (@($acsValues).Count -gt 0)
  $dnsFailed = ((Get-QuotaProp $Status 'dnsFailed') -eq $true)
  $txtLookupResolved = (-not $dnsFailed) -or $recoveredFromNameservers
  $txtResolution = Get-QuotaProp $Status 'txtResolution'
  $txtServfailDetected = ((Get-QuotaProp $txtResolution 'isServfail') -eq $true) -and -not $spfPresent

  $spfAnalysis = Get-QuotaProp $Status 'spfAnalysis'
  $spfLookupCount = $null
  $rawLookupCount = Get-QuotaProp $spfAnalysis 'totalLookupTerms'
  if ($null -ne $rawLookupCount) {
    $parsedLookup = 0
    if ([int]::TryParse([string]$rawLookupCount, [ref]$parsedLookup) -and $parsedLookup -ge 0) { $spfLookupCount = $parsedLookup }
  }
  $spfExceedsLookupLimit = $spfPresent -and $null -ne $spfLookupCount -and $spfLookupCount -gt 10

  # ================= DMARC =================
  $dmarc = [string](Get-QuotaProp $Status 'dmarc')
  $dmarcPresent = -not [string]::IsNullOrWhiteSpace($dmarc)
  $dmarcFirstLine = if ($dmarcPresent) { ($dmarc -split '\r?\n')[0].Trim() } else { '' }
  $dmarcPolicy = ''
  $policyMatch = [regex]::Match($dmarcFirstLine, '(?:^|;)\s*p\s*=\s*([a-zA-Z]+)')
  if ($policyMatch.Success) { $dmarcPolicy = $policyMatch.Groups[1].Value.ToLowerInvariant() }
  $dmarcIsMonitoringOnly = $dmarcPresent -and ($dmarcPolicy -eq '' -or $dmarcPolicy -eq 'none')
  $dmarcNeedsEnforcement = $dmarcIsMonitoringOnly -and $RequireDmarcEnforcement
  $dmarcMultipleRecords = ((Get-QuotaProp $Status 'dmarcMultipleRecords') -eq $true)

  # ================= MX =================
  $hasUsableMxRaw = Get-QuotaProp $Status 'hasUsableMx'
  $mxRecords = Get-QuotaStringArray (Get-QuotaProp $Status 'mxRecords')
  $hasMx = ($hasUsableMxRaw -eq $true) -or ($null -eq $hasUsableMxRaw -and $mxRecords.Count -gt 0)

  # ================= Reputation view model (getReputationViewModel in 20c) =================
  $repView = $null
  if ($null -ne $Reputation) {
    $ipSummary = Get-QuotaProp $Reputation 'summary'
    $total = [int](Get-QuotaNumber (Get-QuotaProp $ipSummary 'totalQueries'))
    $repErrors = [int](Get-QuotaNumber (Get-QuotaProp $ipSummary 'errorCount'))
    $listed = [int](Get-QuotaNumber (Get-QuotaProp $ipSummary 'listedCount'))
    $notListed = [int](Get-QuotaNumber (Get-QuotaProp $ipSummary 'notListedCount'))
    $valid = [Math]::Max(0, $total - $repErrors)
    # JavaScript Math.round rounds halves up; [Math]::Round would round to even.
    $percent = if ($valid -gt 0) { [int][Math]::Max(0, [Math]::Min(100, [Math]::Floor((($notListed / $valid) * 100) + 0.5))) } else { $null }
    $ipNotApplicable = ([string](Get-QuotaProp $Reputation 'ipCheckState') -eq 'notApplicable')
    $ipState = if ($ipNotApplicable) { 'notApplicable' } elseif ($listed -gt 0) { 'listed' } elseif ($valid -gt 0) { 'clean' } else { 'unknown' }
    $rating = if ($null -eq $percent) { 'Unknown' } elseif ($percent -ge 99) { 'Excellent' } elseif ($percent -ge 90) { 'Great' } elseif ($percent -ge 75) { 'Good' } elseif ($percent -ge 50) { 'Fair' } else { 'Poor' }

    $domainRep = Get-QuotaProp $Reputation 'domainReputation'
    $domainState = if ($null -ne $domainRep) { $s = [string](Get-QuotaProp $domainRep 'state'); if ($s) { $s } else { 'unknown' } } else { 'disabled' }
    $combinedState = [string](Get-QuotaProp $Reputation 'overallReputationState')
    if (-not $combinedState) {
      if ($ipState -eq 'listed') { $combinedState = 'listed' }
      elseif ($null -eq $domainRep) { $combinedState = $ipState }
      elseif ($domainState -eq 'listed') { $combinedState = 'listed' }
      elseif ($domainState -eq 'clean' -and ($ipState -eq 'clean' -or $ipState -eq 'notApplicable')) { $combinedState = 'clean' }
      elseif ($domainState -eq 'disabled' -and $ipState -eq 'clean') { $combinedState = 'clean' }
      elseif ($domainState -eq 'disabled' -and $ipState -eq 'notApplicable') { $combinedState = 'notApplicable' }
      elseif ($domainState -eq 'partial' -or $ipState -eq 'clean') { $combinedState = 'partial' }
      else { $combinedState = 'unknown' }
    }
    $quotaState = if ($combinedState -eq 'clean') { 'pass' } elseif ($combinedState -eq 'notApplicable') { 'notApplicable' } else { 'warn' }

    $repView = [pscustomobject]@{
      total = $total; errors = $repErrors; listed = $listed; notListed = $notListed
      percent = $percent; rating = $rating; ipNotApplicable = $ipNotApplicable
      domainRep = $domainRep; domainState = $domainState; quotaState = $quotaState
      zones = @(Get-QuotaProp $Reputation 'rblZones' | Where-Object { $null -ne $_ }).Count
    }
  }

  # ================= Overall verdict (getDomainQuotaStatus in 20d) =================
  $quotaFail = $false
  $quotaWarn = $false
  if (-not $hasMx) { $quotaFail = $true }
  if ($repView -and $repView.quotaState -eq 'warn') { $quotaWarn = $true }

  $whoisError = [string](Get-QuotaProp $Status 'whoisError')
  $whoisRegistryWebForm = ([string](Get-QuotaProp $Status 'whoisRegistryWebForm')).Trim()
  $whoisIsExpired = ((Get-QuotaProp $Status 'whoisIsExpired') -eq $true)
  $whoisIsVeryYoung = ((Get-QuotaProp $Status 'whoisIsVeryYoungDomain') -eq $true)
  $whoisIsYoung = ((Get-QuotaProp $Status 'whoisIsYoungDomain') -eq $true)
  $whoisAgeHuman = [string](Get-QuotaProp $Status 'whoisAgeHuman')
  $whoisExpiryHuman = if ($whoisIsExpired) { 'Expired' } else { [string](Get-QuotaProp $Status 'whoisExpiryHuman') }
  # The verdict uses the SPA's looser "any WHOIS data" test, which includes the provider name.
  $whoisHasAnyData = [bool]((Test-QuotaHasValue (Get-QuotaProp $Status 'whoisSource')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisCreationDateUtc')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisExpiryDateUtc')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisRegistrar')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisRegistrant')) -or
    (Test-QuotaHasValue $whoisAgeHuman) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisExpiryHuman')))
  $whoisWebFormOnly = ($whoisRegistryWebForm -and -not $whoisHasAnyData)
  if (-not $whoisWebFormOnly -and ($whoisError -or -not $whoisHasAnyData)) { $quotaWarn = $true }
  if ($whoisIsExpired -or $whoisIsVeryYoung) { $quotaFail = $true } elseif ($whoisIsYoung) { $quotaWarn = $true }

  if ($spfMultipleRecords) { $quotaFail = $true }
  elseif ($recoveredFromNameservers -and $spfPresent) { $quotaWarn = $true }
  elseif ($spfPresent -and $null -eq $spfHasRequiredInclude) { $quotaWarn = $true }
  elseif (-not $spfPresent -or $spfHasRequiredInclude -ne $true) { $quotaFail = $true }
  if ($spfExceedsLookupLimit) { $quotaWarn = $true }

  if (-not $dmarcPresent -or $dmarcMultipleRecords -or $dmarcNeedsEnforcement) { $quotaWarn = $true }

  $verdict = if ($quotaFail) { 'fail' } elseif ($quotaWarn -or $errors.Count -gt 0) { 'warn' } else { 'pass' }
  $verdictLabel = switch ($verdict) { 'pass' { 'Passing' } 'warn' { 'Warning' } default { 'Failed' } }

  $acsReady = ((Get-QuotaProp $Status 'acsReady') -eq $true)
  $verification = if ($acsReady) { 'pass' } elseif ($acsPresent -and $recoveredFromNameservers) { 'warn' } else { 'fail' }
  $verificationLabel = switch ($verification) { 'pass' { 'Passing' } 'warn' { 'Warning' } default { 'Failed' } }

  # ================= Checklist rows (Email Quota card in 20d render()) =================
  $checklist = [System.Collections.Generic.List[object]]::new()
  $addRow = {
    param([string]$Id, [string]$Name, [string]$State, [string]$Detail)
    $checklist.Add([pscustomobject]@{ id = $Id; name = $Name; state = $State; detail = $Detail })
  }

  # 1) MX
  $mxDetail = if ($hasMx) {
    if ($mxRecords.Count -gt 0) { $mxRecords -join ', ' } else { 'MX Records' }
  } elseif ((Get-QuotaProp $Status 'nullMx') -eq $true) {
    'Domain publishes a Null MX record (MX 0 .), which means it does not accept email.'
  } else { 'No MX records detected.' }
  & $addRow 'mx' 'MX Records' $(if ($hasMx) { 'pass' } else { 'fail' }) $mxDetail

  # 2) Reputation
  $repState = 'unknown'
  $repDetail = ''
  if ($ReputationError) {
    $repState = 'error'
    $repDetail = $ReputationError
  } elseif ($repView) {
    $riskSummary = [string](Get-QuotaProp $Reputation 'overallRiskSummary')
    if (-not $riskSummary) { $riskSummary = [string](Get-QuotaProp (Get-QuotaProp $Reputation 'summary') 'riskSummary') }
    if (-not $riskSummary) { $riskSummary = 'Unknown' }
    $mailDetail = if ($repView.ipNotApplicable) {
      'This domain publishes a Null MX record (MX 0 .), so it declares that it operates no mail server. There are no sending-mail IPv4 addresses to check against IP blocklists. Literal-domain reputation is evaluated separately below.'
    } elseif ($null -eq $repView.percent) {
      ('Risk: {0} | Total queries: {1}, Not listed: {2}' -f $riskSummary, $repView.total, $repView.notListed)
    } else {
      ('Risk: {0} | Reputation: {1} ({2}%) | Listed: {3}, Not listed: {4}' -f $riskSummary, $repView.rating, $repView.percent, $repView.listed, $repView.notListed)
    }
    $repUsedApex = @(@(Get-QuotaProp $Reputation 'targets') | Where-Object { $_ -and [string](Get-QuotaProp $_ 'source') -eq 'apex' }).Count -gt 0
    $repLookupDomain = [string](Get-QuotaProp $Reputation 'lookupDomain')
    $repUsedParent = ((Get-QuotaProp $Reputation 'lookupUsedParent') -eq $true) -and $repLookupDomain -and $repLookupDomain -ne $domain
    $sourceNote = if ($repUsedApex) {
      "No MX record was published, so the domain's own IPv4 addresses were checked as a fallback. These may be website or shared-hosting addresses rather than sending-mail IPs."
    } elseif ($repUsedParent) {
      ('Using IP addresses from parent domain {0} (no A/AAAA on {1}).' -f $repLookupDomain, $domain)
    } else { '' }

    $domainDetail = ''
    $providerDetails = @()
    if ($null -ne $repView.domainRep) {
      $domainSummary = Get-QuotaProp $repView.domainRep 'summary'
      $domainDetail = switch ($repView.domainState) {
        'clean' { '{0} validated provider(s) reported no listing' -f [int](Get-QuotaNumber (Get-QuotaProp $domainSummary 'validatedCount')) }
        'listed' { 'Listed by {0} domain reputation provider(s)' -f [int](Get-QuotaNumber (Get-QuotaProp $domainSummary 'listedCount')) }
        'partial' { '{0} provider result(s) validated; coverage is incomplete' -f [int](Get-QuotaNumber (Get-QuotaProp $domainSummary 'validatedCount')) }
        'disabled' { 'Domain reputation providers are disabled' }
        default { 'No domain reputation provider returned a conclusive result' }
      }
      $providerDetails = @(foreach ($item in @(Get-QuotaProp $repView.domainRep 'results')) {
        if ($null -eq $item) { continue }
        $itemState = [string](Get-QuotaProp $item 'state')
        $stateText = switch ($itemState) {
          'listed' { 'Listed' }
          'notListed' { 'Not listed' }
          'blocked' { 'Provider blocked this query path' }
          'invalid' { 'Invalid provider response' }
          default { 'Provider unavailable' }
        }
        $providerName = [string](Get-QuotaProp $item 'providerName')
        if (-not $providerName) { $providerName = [string](Get-QuotaProp $item 'providerId') }
        if (-not $providerName) { $providerName = 'Unknown' }
        $categories = Get-QuotaStringArray (Get-QuotaProp $item 'categories')
        $text = '{0}: {1}' -f $providerName, $stateText
        if ($categories.Count -gt 0) { $text += ' (Categories: {0})' -f ($categories -join ', ') }
        $providerId = [string](Get-QuotaProp $item 'providerId')
        if (($providerId -eq 'surbl' -or $providerId -eq 'spamhaus') -and $itemState -in @('unavailable', 'invalid', 'blocked')) {
          $text += ' (opt-in list: requires provider eligibility and is not verified by this tool; this is not a listing)'
          $policyUrl = [string](Get-QuotaProp $item 'policyUrl')
          if ($policyUrl) { $text += ' ' + $policyUrl }
        }
        $text
      })
    }
    $repDetail = (@($mailDetail, $sourceNote, $domainDetail) + $providerDetails | Where-Object { $_ }) -join ' | '
    $repState = $repView.quotaState
  }
  & $addRow 'reputation' 'Reputation (DNSBL)' $repState $repDetail

  # 3) Domain registration. The row uses the SPA's stricter "real registration
  # fields" test so a provider name alone never produces a PASS.
  $whoisHasStructuredData = [bool]((Test-QuotaHasValue (Get-QuotaProp $Status 'whoisCreationDateUtc')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisExpiryDateUtc')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisRegistrar')) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisRegistrant')) -or
    (Test-QuotaHasValue $whoisAgeHuman) -or
    (Test-QuotaHasValue (Get-QuotaProp $Status 'whoisExpiryHuman')) -or
    ($null -ne (Get-QuotaProp $Status 'whoisAgeDays')) -or
    ($null -ne (Get-QuotaProp $Status 'whoisExpiryDays')) -or
    $whoisIsExpired -or $whoisIsVeryYoung -or $whoisIsYoung)
  if ($whoisRegistryWebForm -and -not $whoisHasStructuredData) {
    & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'info' 'Registry only publishes details via web form.'
  } elseif ($whoisError) {
    & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'error' $whoisError
  } elseif (-not $whoisHasStructuredData) {
    & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'error' 'Registration details unavailable.'
  } elseif ($whoisIsExpired) {
    $expiryDate = [string](Get-QuotaProp $Status 'whoisExpiryDateUtc')
    & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'fail' $(if ($expiryDate) { 'Expired on {0}' -f $expiryDate } else { 'Domain registration appears expired.' })
  } elseif ($whoisIsVeryYoung -or $whoisIsYoung) {
    $thresholdName = if ($whoisIsVeryYoung) { 'whoisNewDomainErrorThresholdDays' } else { 'whoisNewDomainWarnThresholdDays' }
    $threshold = Get-QuotaProp $Status $thresholdName
    if ($null -eq $threshold) { $threshold = if ($whoisIsVeryYoung) { 90 } else { 180 } }
    $suffix = if ($whoisAgeHuman) { ': ' + $whoisAgeHuman } else { '' }
    & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' $(if ($whoisIsVeryYoung) { 'fail' } else { 'warn' }) ('New domain (under {0} days){1}' -f $threshold, $suffix)
  } else {
    $parts = @()
    if ($whoisAgeHuman) { $parts += 'Age: ' + $whoisAgeHuman }
    if ($whoisExpiryHuman) { $parts += 'Expires in: ' + $whoisExpiryHuman }
    if ($parts.Count -eq 0) {
      & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'info' 'Registration details unavailable.'
    } else {
      & $addRow 'registration' 'Domain Registration (WHOIS/RDAP)' 'pass' ($parts -join ' | ')
    }
  }

  # 4) SPF
  if (-not $txtLookupResolved) {
    $dnsError = [string](Get-QuotaProp $Status 'dnsError')
    & $addRow 'spf' 'SPF (queried domain TXT)' 'fail' $(if ($dnsError) { $dnsError } else { 'TXT lookup failed or timed out.' })
  } else {
    $spfPasses = $spfPresent -and $spfHasRequiredInclude -eq $true
    $spfIndeterminate = -not $spfPasses -and $spfPresent -and $spfIsMacroDelegated
    $spfServfail = -not $spfPasses -and -not $spfPresent -and $txtServfailDetected
    $spfNsRecovered = $spfPresent -and $recoveredFromNameservers
    if ($spfPresent) {
      $requirementText = if ($recoveredFromNameservers) {
        if ($null -eq $spfHasRequiredInclude) { "The required include:$requiredInclude cannot be confirmed statically because SPF is delegated through a macro." }
        elseif ($spfHasRequiredInclude) { "Found direct include:$requiredInclude in the SPF record." }
        else { "Did not find include:$requiredInclude in the SPF record." }
      } else {
        $d = [string](Get-QuotaProp $Status 'spfRequiredIncludeDetail')
        if (-not $d) { $d = [string](Get-QuotaProp $Status 'spfRequiredIncludeError') }
        $d
      }
      $spfDetailParts = @(
        $(if ($spfMultipleRecords) { $spfRecords -join "`n" } else { [string]$spfValue }),
        $(if ($spfMultipleRecords) { 'This domain publishes {0} SPF records. RFC 7208 allows exactly one - receiving mail servers return a permanent error (PermError) and SPF fails for every message sent from this domain. Merge them into a single TXT record.' -f @($spfRecords).Count } else { '' }),
        $(if ($spfNsRecovered) { "This record was found by querying the domain's authoritative nameservers directly, but the public DNS resolver returned no record for this lookup. Email delivery and Azure verification rely on public DNS, so until the authoritative nameservers answer this query reliably the record may resolve only intermittently." } else { '' }),
        $(if ($spfExceedsLookupLimit) { 'SPF exceeds the RFC 7208 DNS lookup limit. Detected {0} DNS-lookup terms across the expanded SPF chain; you should reduce SPF DNS lookups to 10 or fewer to avoid recipient-side SPF errors.' -f $spfLookupCount } else { '' }),
        $requirementText
      ) | Where-Object { $_ }
      $spfDetail = $spfDetailParts -join "`n`n"
    } elseif ($spfServfail) {
      $spfDetail = "No SPF record returned - the TXT lookup failed upstream (SERVFAIL). The domain's authoritative nameservers are answering inconsistently (DNS propagation or misconfiguration), so the record may still exist and resolve elsewhere. Re-check once DNS has propagated."
    } else {
      $spfDetail = 'No SPF record detected.'
    }
    # A duplicate record set is a PermError, so it outranks every other SPF state.
    $spfState = if ($spfMultipleRecords) { 'fail' }
      elseif ($spfPasses -and -not $spfNsRecovered -and -not $spfExceedsLookupLimit) { 'pass' }
      elseif ($spfIndeterminate -or $spfServfail -or $spfNsRecovered -or $spfExceedsLookupLimit) { 'warn' }
      else { 'fail' }
    & $addRow 'spf' 'SPF (queried domain TXT)' $spfState $spfDetail
  }

  # 5) DMARC
  $dmarcLookupDomain = [string](Get-QuotaProp $Status 'dmarcLookupDomain')
  $inheritedSuffix = ''
  if (((Get-QuotaProp $Status 'dmarcInherited') -eq $true) -and $dmarcLookupDomain -and $dmarcLookupDomain -ne $domain) {
    $inheritedSuffix = "`n`nEffective policy inherited from parent domain $dmarcLookupDomain."
  }
  $dmarcMonitorOnlyText = "DMARC for $domain is monitor-only (p=none). For stronger protection against spoofing, move to enforcement with p=quarantine or p=reject after validating legitimate mail sources."
  $dmarcMissingText = "DMARC is missing. Add a _dmarc.$domain TXT record to reduce spoofing risk."
  if (-not $dmarcPresent) {
    & $addRow 'dmarc' 'DMARC' 'warn' $dmarcMissingText
  } elseif ($dmarcMultipleRecords) {
    $dupDomain = if ($dmarcLookupDomain) { $dmarcLookupDomain } else { $domain }
    $dupCount = [int](Get-QuotaNumber (Get-QuotaProp $Status 'dmarcRecordCount'))
    & $addRow 'dmarc' 'DMARC' 'warn' ("$dmarcFirstLine`n`n_dmarc.$dupDomain publishes $dupCount DMARC records. RFC 7489 allows exactly one - receiving mail servers discard all of them and apply no DMARC policy at all. Remove the extras until a single v=DMARC1 record remains.$inheritedSuffix")
  } elseif ($dmarcNeedsEnforcement) {
    & $addRow 'dmarc' 'DMARC' 'warn' ("$dmarcFirstLine`n`n$dmarcMonitorOnlyText$inheritedSuffix")
  } else {
    & $addRow 'dmarc' 'DMARC' 'pass' ("$dmarcFirstLine$inheritedSuffix")
  }

  # ================= Copy Email Quota table (20d render()) =================
  $repStateLabel = if ($repState -eq 'notApplicable') { 'NOT APPLICABLE' } else { $repState.ToUpperInvariant() }
  $repSummaryText = $repStateLabel + $(if ($repDetail) { ' - ' + $repDetail } else { '' })
  if ($repView -and -not $repView.ipNotApplicable) {
    $repSummaryText += ' | Zones queried: {0} | Total queries: {1} | Listed: {2} | Not listed: {3}' -f $repView.zones, $repView.total, $repView.listed, $repView.notListed
  }

  $websiteSummaryText = if ($WebsiteError) { 'Error - ' + $WebsiteError }
  elseif ($null -eq $Website) { 'Unknown' }
  elseif ((Get-QuotaProp $Website 'checked') -eq $false -and ([string](Get-QuotaProp $Website 'summary')).ToLowerInvariant() -eq 'disabled') {
    $reason = [string](Get-QuotaProp $Website 'disabledReason')
    if ($reason) { $reason } else { 'Website probe disabled by server configuration.' }
  } else {
    $reachable = ((Get-QuotaProp $Website 'reachable') -eq $true)
    $outcome = [string](Get-QuotaProp $Website 'summary')
    if (-not $outcome) { $outcome = if ($reachable) { 'Reachable' } else { 'Unreachable' } }
    # English text of localizeWebsiteSummary / localizeWebsiteSignal (20c).
    $outcome = switch ($outcome.ToLowerInvariant()) {
      'reachable' { 'Reachable (serves content)' }
      'placeholdercontent' { 'Placeholder / parked / minimal content' }
      'servererror' { 'Reachable but returned a server error (5xx)' }
      'clienterror' { 'Reachable but returned a client error (4xx)' }
      'unreachable' { 'No website responded' }
      default { $outcome }
    }
    $signalNames = @{
      underconstruction = 'Under construction'; comingsoon = 'Coming soon'; domainforsale = 'Domain offered for sale'
      parked = 'Parked domain page'; placeholder = 'Placeholder page'; defaultpage = 'Default web-server page'
      suspended = 'Account suspended page'; notconfigured = 'Site not configured'
    }
    $wParts = @($outcome)
    $finalUrl = [string](Get-QuotaProp $Website 'finalUrl')
    if ($finalUrl) { $wParts += $finalUrl }
    $statusCode = Get-QuotaProp $Website 'statusCode'
    if ($statusCode) { $wParts += 'HTTP status: ' + $statusCode }
    if ((Get-QuotaProp $Website 'redirected') -eq $true) { $wParts += 'Redirects: ' + @(Get-QuotaProp $Website 'redirectChain' | Where-Object { $null -ne $_ }).Count }
    if ((Get-QuotaProp $Website 'tlsError') -eq $true) { $wParts += 'TLS/SSL handshake failed (certificate or protocol error).' }
    $signals = @(Get-QuotaStringArray (Get-QuotaProp $Website 'placeholderSignals') | ForEach-Object {
      $key = $_.ToLowerInvariant()
      if ($signalNames.ContainsKey($key)) { $signalNames[$key] } else { $_ }
    })
    if ((Get-QuotaProp $Website 'placeholderDetected') -eq $true -and $signals.Count -gt 0) { $wParts += 'Placeholder indicators: ' + ($signals -join ', ') }
    elseif ((Get-QuotaProp $Website 'nearEmpty') -eq $true) { $wParts += 'The page returned little or no visible text.' }
    $websiteErrorText = [string](Get-QuotaProp $Website 'error')
    if (-not $reachable -and $websiteErrorText) { $wParts += $websiteErrorText }
    $wParts -join ' | '
  }

  $spfStatusText = if ($spfExceedsLookupLimit) { 'Warning' } elseif ($spfPresent -and $spfHasRequiredInclude -ne $false) { 'VERIFIED' } else { 'NOT STARTED' }
  if ($null -ne $spfLookupCount) {
    $spfStatusText += if ($spfExceedsLookupLimit) {
      ' - SPF DNS lookups: {0} (exceeds the RFC 7208 limit of 10; you should reduce SPF DNS lookups to 10 or fewer to avoid recipient-side SPF errors)' -f $spfLookupCount
    } else {
      ' - SPF DNS lookups: {0} (within the RFC 7208 limit of 10)' -f $spfLookupCount
    }
  }
  $dmarcStatusText = if (-not $dmarcPresent) { 'Warning - ' + $dmarcMissingText }
    elseif ($dmarcNeedsEnforcement) { 'Warning - ' + $dmarcMonitorOnlyText }
    else { 'VERIFIED' }

  $customParts = @()
  if ((Get-QuotaProp $Status 'spfRequiredIncludeCustom') -eq $true) { $customParts += 'SPF include:' + $requiredInclude }
  foreach ($slot in 1, 2) {
    if ((Get-QuotaProp $Status "dkim${slot}Custom") -eq $true) {
      $customParts += 'DKIM{0} {1} -> {2}' -f $slot, (Get-QuotaProp $Status "dkim${slot}Selector"), (Get-QuotaProp $Status "dkim${slot}ExpectedCname")
    }
  }

  $report = [System.Collections.Generic.List[object]]::new()
  $addReport = { param([string]$Field, [string]$Value) $report.Add([pscustomobject]@{ field = $Field; value = $Value }) }
  & $addReport 'Domain Name' $(if ($domain) { $domain } else { 'UNKNOWN' })
  & $addReport 'Email Quota' $verdictLabel
  & $addReport 'Domain Status' $(if ($acsPresent) { 'VERIFIED' } else { 'NOT VERIFIED' })
  & $addReport 'MX Records' ($(if ($hasMx) { 'Yes' } else { 'No' }) + ' - ' + $mxDetail)
  & $addReport 'Domain Age' $(if ($whoisAgeHuman) { $whoisAgeHuman } else { 'UNKNOWN' })
  & $addReport 'Domain Expiring in' $(if ($whoisExpiryHuman) { $whoisExpiryHuman } else { 'UNKNOWN' })
  & $addReport 'SPF Status' $spfStatusText
  & $addReport 'DKIM1 Status' $(if (Test-QuotaHasValue (Get-QuotaProp $Status 'dkim1')) { 'VERIFIED' } else { 'NOT STARTED' })
  & $addReport 'DKIM2 Status' $(if (Test-QuotaHasValue (Get-QuotaProp $Status 'dkim2')) { 'VERIFIED' } else { 'NOT STARTED' })
  if ($customParts.Count -gt 0) { & $addReport 'Custom requirements' ($customParts -join '; ') }
  & $addReport 'DMARC Status' $dmarcStatusText
  & $addReport 'Reputation (DNSBL)' ($repSummaryText + ' [MultiRBL: https://multirbl.valli.org/dnsbl-lookup/' + [uri]::EscapeDataString($domain) + '.html]')
  & $addReport 'Website' $websiteSummaryText
  if ($PageLink) { & $addReport 'Report link' $PageLink }

  # Markdown table matching the plain-text "Copy Email Quota" output. Pipes and
  # line breaks inside a value would break the table, so they are escaped/flattened.
  $markdownLines = [System.Collections.Generic.List[string]]::new()
  $markdownLines.Add('| Field | Value |')
  $markdownLines.Add('| --- | --- |')
  foreach ($row in $report) {
    $cell = ([string]$row.value -replace '\r?\n+', ' ') -replace '\|', '\|'
    $markdownLines.Add(('| {0} | {1} |' -f $row.field, $cell))
  }

  [pscustomobject]@{
    domain             = $domain
    generatedAtUtc     = ([DateTime]::UtcNow.ToString('o'))
    emailQuota         = [pscustomobject]@{ status = $verdict; label = $verdictLabel }
    domainVerification = [pscustomobject]@{ status = $verification; label = $verificationLabel }
    checklist          = @($checklist)
    report             = @($report)
    reportMarkdown     = ($markdownLines -join "`n")
    requirements       = [pscustomobject]@{
      spfInclude              = $requiredInclude
      spfIncludeCustom        = ((Get-QuotaProp $Status 'spfRequiredIncludeCustom') -eq $true)
      requireDmarcEnforcement = [bool]$RequireDmarcEnforcement
    }
    errors             = [pscustomobject]$errors
  }
}
