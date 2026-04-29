# ===== Aggregated DNS Readiness =====
# ------------------- AGGREGATED DNS READINESS -------------------
# The main "check everything" function called by /dns and the CLI -TestDomain mode.
# Runs all individual checks (TXT/SPF, MX, DMARC, DKIM, CNAME, WHOIS) and assembles
# a single result object with guidance strings for the UI.
function Get-AcsDnsStatus {
    param([string]$Domain)

  # Aggregated status used by the UI.
  # Combines the individual checks + generates human-friendly guidance strings.

  $base  = Get-DnsBaseStatus  -Domain $Domain
  $mx    = Get-DnsMxStatus    -Domain $Domain
  $records = Get-DnsRecordsStatus -Domain $Domain
  $whois = Get-DomainRegistrationStatus -Domain $Domain
  $dmarc = Get-DnsDmarcStatus -Domain $Domain
  $dkim  = Get-DnsDkimStatus  -Domain $Domain
  $cname = Get-DnsCnameStatus -Domain $Domain

  # Recover queried-domain TXT-derived state from the detailed DNS records payload
  # when the dedicated base TXT lookup timed out but record collection still
  # produced authoritative TXT rows for the queried domain.
  $recoveredTxtRecords = @()
  $recoveredIpv4Addresses = @()
  $recoveredIpv6Addresses = @()
  if ($base.dnsFailed -and $records -and $records.records) {
    try {
      $recoveredTxtRecords = @($records.records | Where-Object {
        $_ -and
        [string]$_.type -eq 'TXT' -and
        ([string]$_.name).TrimEnd('.').ToLowerInvariant() -eq ([string]$Domain).TrimEnd('.').ToLowerInvariant() -and
        -not [string]::IsNullOrWhiteSpace([string]$_.data)
      } | ForEach-Object { [string]$_.data })
    } catch { }
  }

  if ($records -and $records.records) {
    try {
      $recoveredIpv4Addresses = @($records.records | Where-Object {
        $_ -and
        [string]$_.type -eq 'A' -and
        ([string]$_.name).TrimEnd('.').ToLowerInvariant() -eq ([string]$Domain).TrimEnd('.').ToLowerInvariant() -and
        -not [string]::IsNullOrWhiteSpace([string]$_.data)
      } | ForEach-Object { [string]$_.data })
      $recoveredIpv6Addresses = @($records.records | Where-Object {
        $_ -and
        [string]$_.type -eq 'AAAA' -and
        ([string]$_.name).TrimEnd('.').ToLowerInvariant() -eq ([string]$Domain).TrimEnd('.').ToLowerInvariant() -and
        -not [string]::IsNullOrWhiteSpace([string]$_.data)
      } | ForEach-Object { [string]$_.data })
    } catch { }
  }

  $recoveredFromDetailedRecords = $recoveredTxtRecords.Count -gt 0
  $recoveredAddressesFromDetailedRecords = ($recoveredIpv4Addresses.Count -gt 0) -or ($recoveredIpv6Addresses.Count -gt 0)
  $effectiveDnsFailed = $base.dnsFailed -and -not $recoveredFromDetailedRecords
  $effectiveDnsError = if ($effectiveDnsFailed) { $base.dnsError } else { $null }
  $effectiveTxtRecords = if ($recoveredFromDetailedRecords) { $recoveredTxtRecords } else { @($base.txtRecords) }
  $effectiveIpv4Addresses = if ($recoveredAddressesFromDetailedRecords) { $recoveredIpv4Addresses } else { @($base.ipv4Addresses) }
  $effectiveIpv6Addresses = if ($recoveredAddressesFromDetailedRecords) { $recoveredIpv6Addresses } else { @($base.ipv6Addresses) }
  $effectiveIpLookupDomain = if ($recoveredAddressesFromDetailedRecords) { $Domain } else { $base.ipLookupDomain }
  $effectiveIpUsedParent = if ($recoveredAddressesFromDetailedRecords) { $false } else { $base.ipUsedParent }
  $effectiveSpf = if ($recoveredFromDetailedRecords) { @($effectiveTxtRecords | Where-Object { $_ -match '(?i)^v=spf1' } | Select-Object -First 1) } else { @($base.spfValue) }
  $effectiveSpfValue = if ($effectiveSpf.Count -gt 0) { $effectiveSpf[0] } else { $null }
  $effectiveAcs = if ($recoveredFromDetailedRecords) { @($effectiveTxtRecords | Where-Object { $_ -match '(?i)ms-domain-verification' } | Select-Object -First 1) } else { @($base.acsValue) }
  $effectiveAcsValue = if ($effectiveAcs.Count -gt 0) { $effectiveAcs[0] } else { $null }
  $effectiveSpfPresent = [bool]$effectiveSpfValue
  $effectiveAcsPresent = [bool]$effectiveAcsValue
  $effectiveSpfHasRequiredInclude = if ($recoveredFromDetailedRecords -and $effectiveSpfValue) {
    [regex]::IsMatch([string]$effectiveSpfValue, '(?i)(^|\s)include:spf\.protection\.outlook\.com(?=\s|$)')
  } else {
    $base.spfHasRequiredInclude
  }

  # ACS domain verification readiness is primarily based on the ms-domain-verification TXT record.
  # Other checks (SPF/MX/DMARC/DKIM/CNAME) are useful guidance but not required for ACS verification.
  $acsReady = (-not $effectiveDnsFailed) -and $effectiveAcsPresent
  $dmarcHelpUrl = 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records'

    # Guidance
    $guidance = New-Object System.Collections.Generic.List[string]

    if ($effectiveDnsFailed) {
        $guidance.Add("DNS TXT lookup failed or timed out. Other DNS records may still resolve.")
    } else {
      if (-not $effectiveSpfPresent) {
        if ($base.parentSpfPresent -and $base.txtUsedParent -and $base.txtLookupDomain -and $base.txtLookupDomain -ne $Domain) {
          $guidance.Add("SPF is missing on $Domain. Parent domain $($base.txtLookupDomain) publishes SPF, but SPF does not automatically apply to the queried subdomain.")
        } else {
          $guidance.Add("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).")
        }
      }
      foreach ($spfMessage in @($base.spfGuidance)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$spfMessage)) { $guidance.Add([string]$spfMessage) }
      }
      if (-not $effectiveAcsPresent) {
        if ($base.parentAcsPresent -and $base.txtUsedParent -and $base.txtLookupDomain -and $base.txtLookupDomain -ne $Domain) {
          $guidance.Add("ACS ms-domain-verification TXT is missing on $Domain. Parent domain $($base.txtLookupDomain) has an ACS TXT record, but it does not verify the queried subdomain.")
        } else {
          $guidance.Add("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.")
        }
      }
      if (-not $mx.mxRecords)    {
        if ($mx.mxFallbackDomainChecked -and $mx.mxFallbackUsed -and $mx.mxLookupDomain) {
          $guidance.Add("No MX records found on $Domain; using parent domain $($mx.mxLookupDomain) MX records as a fallback.")
        }
        elseif ($mx.mxFallbackDomainChecked -and -not $mx.mxFallbackUsed) {
          $guidance.Add("No MX records detected for $Domain or its parent $($mx.mxFallbackDomainChecked). Mail flow will not function until MX records are configured.")
        }
        else {
          $guidance.Add("No MX records detected. Mail flow will not function until MX records are configured.")
        }
      }
      elseif ($mx.mxFallbackUsed -and $mx.mxLookupDomain -and $mx.mxLookupDomain -ne $Domain) {
        $guidance.Add("No MX records found on $Domain; results shown are from parent domain $($mx.mxLookupDomain).")
      }
      if (-not $dmarc.dmarc)     { $guidance.Add("DMARC is missing. Add a _dmarc.$Domain TXT record to reduce spoofing risk.") }
      elseif ($dmarc.dmarcInherited -and $dmarc.dmarcLookupDomain -and $dmarc.dmarcLookupDomain -ne $Domain) { $guidance.Add("Effective DMARC policy is inherited from parent domain $($dmarc.dmarcLookupDomain).") }
      $dmarcGuidance = @(Get-DmarcSecurityGuidance -DmarcRecord $dmarc.dmarc -Domain $Domain -LookupDomain $dmarc.dmarcLookupDomain -Inherited $dmarc.dmarcInherited)
      foreach ($dmarcMessage in $dmarcGuidance) {
        if (-not [string]::IsNullOrWhiteSpace($dmarcMessage)) { $guidance.Add($dmarcMessage) }
      }
      if ((-not $dmarc.dmarc) -or ($dmarcGuidance.Count -gt 0)) { $guidance.Add("For more information about DMARC TXT record syntax, see: $dmarcHelpUrl") }
      # Tightened DKIM guidance: only emit the "wrong CNAME target" warning
      # when the ACS selector hostname itself has a record (CNAME or TXT).
      # `$dkim.dkim1` may be a fallback display string when an alternate
      # selector was found, so it cannot be used to detect ACS-side records.
      $dkim1HasAcsRecord = -not [string]::IsNullOrWhiteSpace([string]$dkim.dkim1CnameTarget) -or -not [string]::IsNullOrWhiteSpace([string]$dkim.dkim1TxtValue)
      $dkim2HasAcsRecord = -not [string]::IsNullOrWhiteSpace([string]$dkim.dkim2CnameTarget) -or -not [string]::IsNullOrWhiteSpace([string]$dkim.dkim2TxtValue)
      if (-not $dkim1HasAcsRecord) { $guidance.Add("DKIM selector1 (selector1-azurecomm-prod-net) is missing.") }
      elseif (-not $dkim.dkim1AcsConfigured) {
        $actual1 = if ($dkim.dkim1CnameTarget) { $dkim.dkim1CnameTarget } else { '(no CNAME)' }
        $guidance.Add("DKIM selector1 is published but does not point to ACS. Expected CNAME target: $($dkim.dkim1ExpectedCname); found: $actual1.")
      }
      if (-not $dkim2HasAcsRecord) { $guidance.Add("DKIM selector2 (selector2-azurecomm-prod-net) is missing.") }
      elseif (-not $dkim.dkim2AcsConfigured) {
        $actual2 = if ($dkim.dkim2CnameTarget) { $dkim.dkim2CnameTarget } else { '(no CNAME)' }
        $guidance.Add("DKIM selector2 is published but does not point to ACS. Expected CNAME target: $($dkim.dkim2ExpectedCname); found: $actual2.")
      }
      if (-not $cname.cname)     {
        if ($cname.cnameLookupDomain -and $cname.cnameLookupDomain -ne $Domain) {
          $guidance.Add("CNAME is not configured on $Domain. Validate whether the queried host or its www alias should resolve for your scenario.")
        } else {
          $guidance.Add("CNAME is not configured. Validate this is expected for your scenario.")
        }
      }

      # Provider-aware hints
      if ($mx.mxProvider -and $mx.mxProvider -ne 'Unknown') {
        $guidance.Add("Detected MX provider: $($mx.mxProvider)")
      }
      if ($mx.mxProvider -eq 'Microsoft 365 / Exchange Online' -and $effectiveSpfPresent -and ($effectiveSpfHasRequiredInclude -eq $false)) {
        $guidance.Add("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Google Workspace / Gmail' -and $effectiveSpfPresent -and ($effectiveSpfValue -notmatch '(?i)_spf\.google\.com')) {
        $guidance.Add("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Zoho Mail' -and $effectiveSpfPresent -and ($effectiveSpfValue -notmatch '(?i)include:zoho\.com')) {
        $guidance.Add("Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.")
      }
      if ($whois -and $whois.isExpired -eq $true) {
        $guidance.Add("Domain registration appears expired (expires/expired: $($whois.expiryDateUtc)). Renew the domain before proceeding.")
      }
      elseif ($whois -and $whois.isVeryYoungDomain -eq $true -and $whois.newDomainErrorThresholdDays -gt 0) {
        $guidance.Add("Domain was registered very recently (within $($whois.newDomainErrorThresholdDays) days). This is treated as an error signal for verification; ask the customer to allow more time.")
      }
      elseif ($whois -and $whois.isYoungDomain -eq $true -and $whois.newDomainWarnThresholdDays -gt 0) {
        $guidance.Add("Domain was registered recently (within $($whois.newDomainWarnThresholdDays) days). Ask the customer to allow more time; Microsoft uses this signal to help prevent spammers from setting up new web addresses.")
      }
        if ($acsReady)        { $guidance.Add("This domain appears ready for Azure Communication Services domain verification.") }
    }

    [pscustomobject]@{
        domain     = $Domain
      resolver   = $env:ACS_DNS_RESOLVER
      dohEndpoint = $(if ($env:ACS_DNS_RESOLVER -eq 'DoH' -or ($env:ACS_DNS_RESOLVER -eq 'Auto' -and -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue))) { $env:ACS_DNS_DOH_ENDPOINT } else { $null })
        dnsFailed  = $effectiveDnsFailed
        dnsError   = $effectiveDnsError

        txtLookupDomain = $base.txtLookupDomain
        txtUsedParent   = $base.txtUsedParent

        spfPresent = $effectiveSpfPresent
        spfValue   = $effectiveSpfValue
        spfAnalysis = $base.spfAnalysis
        spfExpandedText = $base.spfExpandedText
        spfGuidance = $base.spfGuidance
        spfHasRequiredInclude = $effectiveSpfHasRequiredInclude
        spfRequiredInclude = $base.spfRequiredInclude
        spfRequiredIncludeMatchType = $base.spfRequiredIncludeMatchType
        spfRequiredIncludeDetail = $base.spfRequiredIncludeDetail
        spfRequiredIncludeError = $base.spfRequiredIncludeError
        parentSpfPresent = $base.parentSpfPresent
        parentSpfValue   = $base.parentSpfValue
        acsPresent = $effectiveAcsPresent
        acsValue   = $effectiveAcsValue
        parentAcsPresent = $base.parentAcsPresent
        parentAcsValue   = $base.parentAcsValue

        txtRecords = $effectiveTxtRecords
        parentTxtRecords = $base.parentTxtRecords
        acsReady   = $acsReady

        mxRecords         = $mx.mxRecords
        mxRecordsDetailed = $mx.mxRecordsDetailed
        mxProvider        = $mx.mxProvider
        mxProviderHint    = $mx.mxProviderHint
        mxLookupDomain          = $mx.mxLookupDomain
        mxFallbackDomainChecked = $mx.mxFallbackDomainChecked
        mxFallbackUsed          = $mx.mxFallbackUsed

        dnsRecords      = $records.records
        dnsRecordsError = $records.error

        whoisSource       = $whois.source
        whoisLookupDomain = $whois.lookupDomain
        whoisCreationDateUtc = $whois.creationDateUtc
        whoisExpiryDateUtc   = $whois.expiryDateUtc
        whoisRegistrar     = $whois.registrar
        whoisRegistrant    = $whois.registrant
        whoisAgeDays       = $whois.ageDays
        whoisAgeHuman      = $whois.ageHuman
        whoisIsYoungDomain = $whois.isYoungDomain
        whoisIsVeryYoungDomain = $whois.isVeryYoungDomain
        whoisExpiryDays    = $whois.expiryDays
        whoisIsExpired     = $whois.isExpired
        whoisExpiryHuman   = $whois.expiryHuman
        whoisExpiryUnavailableReason = $whois.expiryUnavailableReason
        whoisNewDomainWarnThresholdDays = $whois.newDomainWarnThresholdDays
        whoisNewDomainErrorThresholdDays = $whois.newDomainErrorThresholdDays
        whoisError         = $whois.error

        dmarc      = $dmarc.dmarc
        dmarcLookupDomain = $dmarc.dmarcLookupDomain
        dmarcInherited = $dmarc.dmarcInherited
        dkim1                = $dkim.dkim1
        dkim1CnameTarget     = $dkim.dkim1CnameTarget
        dkim1TxtValue        = $dkim.dkim1TxtValue
        dkim1ExpectedCname   = $dkim.dkim1ExpectedCname
        dkim1AcsConfigured   = $dkim.dkim1AcsConfigured
        dkim1FallbackSelectors = $dkim.dkim1FallbackSelectors
        dkim2                = $dkim.dkim2
        dkim2CnameTarget     = $dkim.dkim2CnameTarget
        dkim2TxtValue        = $dkim.dkim2TxtValue
        dkim2ExpectedCname   = $dkim.dkim2ExpectedCname
        dkim2AcsConfigured   = $dkim.dkim2AcsConfigured
        dkim2FallbackSelectors = $dkim.dkim2FallbackSelectors
        cname      = $cname.cname
        cnameLookupDomain = $cname.cnameLookupDomain
        cnameUsedWwwFallback = $cname.cnameUsedWwwFallback

        guidance   = $guidance
    }
}

