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
  $whois = Get-DomainRegistrationStatus -Domain $Domain
  $dmarc = Get-DnsDmarcStatus -Domain $Domain
  $dkim  = Get-DnsDkimStatus  -Domain $Domain
  $cname = Get-DnsCnameStatus -Domain $Domain

  # ACS domain verification readiness is primarily based on the ms-domain-verification TXT record.
  # Other checks (SPF/MX/DMARC/DKIM/CNAME) are useful guidance but not required for ACS verification.
  $acsReady = (-not $base.dnsFailed) -and $base.acsPresent
  $dmarcHelpUrl = 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records'

    # Guidance
    $guidance = New-Object System.Collections.Generic.List[string]

    if ($base.dnsFailed) {
        $guidance.Add("DNS TXT lookup failed or timed out. Other DNS records may still resolve.")
    } else {
      if (-not $base.spfPresent) {
        if ($base.parentSpfPresent -and $base.txtUsedParent -and $base.txtLookupDomain -and $base.txtLookupDomain -ne $Domain) {
          $guidance.Add("SPF is missing on $Domain. Parent domain $($base.txtLookupDomain) publishes SPF, but SPF does not automatically apply to the queried subdomain.")
        } else {
          $guidance.Add("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).")
        }
      }
      foreach ($spfMessage in @($base.spfGuidance)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$spfMessage)) { $guidance.Add([string]$spfMessage) }
      }
      if (-not $base.acsPresent) {
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
      if (-not $dkim.dkim1)      { $guidance.Add("DKIM selector1 (selector1-azurecomm-prod-net) is missing.") }
      if (-not $dkim.dkim2)      { $guidance.Add("DKIM selector2 (selector2-azurecomm-prod-net) is missing.") }
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
      if ($mx.mxProvider -eq 'Microsoft 365 / Exchange Online' -and $base.spfPresent -and ($base.spfHasRequiredInclude -eq $false)) {
        $guidance.Add("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Google Workspace / Gmail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)_spf\.google\.com')) {
        $guidance.Add("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Zoho Mail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)include:zoho\.com')) {
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
        dnsFailed  = $base.dnsFailed
        dnsError   = $base.dnsError

        txtLookupDomain = $base.txtLookupDomain
        txtUsedParent   = $base.txtUsedParent

        spfPresent = $base.spfPresent
        spfValue   = $base.spfValue
        spfAnalysis = $base.spfAnalysis
        spfExpandedText = $base.spfExpandedText
        spfGuidance = $base.spfGuidance
        spfHasRequiredInclude = $base.spfHasRequiredInclude
        spfRequiredInclude = $base.spfRequiredInclude
        spfRequiredIncludeMatchType = $base.spfRequiredIncludeMatchType
        spfRequiredIncludeDetail = $base.spfRequiredIncludeDetail
        spfRequiredIncludeError = $base.spfRequiredIncludeError
        parentSpfPresent = $base.parentSpfPresent
        parentSpfValue   = $base.parentSpfValue
        acsPresent = $base.acsPresent
        acsValue   = $base.acsValue
        parentAcsPresent = $base.parentAcsPresent
        parentAcsValue   = $base.parentAcsValue

        txtRecords = $base.txtRecords
        parentTxtRecords = $base.parentTxtRecords
        acsReady   = $acsReady

        mxRecords         = $mx.mxRecords
        mxRecordsDetailed = $mx.mxRecordsDetailed
        mxProvider        = $mx.mxProvider
        mxProviderHint    = $mx.mxProviderHint
        mxLookupDomain          = $mx.mxLookupDomain
        mxFallbackDomainChecked = $mx.mxFallbackDomainChecked
        mxFallbackUsed          = $mx.mxFallbackUsed

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
        whoisNewDomainWarnThresholdDays = $whois.newDomainWarnThresholdDays
        whoisNewDomainErrorThresholdDays = $whois.newDomainErrorThresholdDays
        whoisError         = $whois.error

        dmarc      = $dmarc.dmarc
        dmarcLookupDomain = $dmarc.dmarcLookupDomain
        dmarcInherited = $dmarc.dmarcInherited
        dkim1      = $dkim.dkim1
        dkim2      = $dkim.dkim2
        cname      = $cname.cname
        cnameLookupDomain = $cname.cnameLookupDomain
        cnameUsedWwwFallback = $cname.cnameUsedWwwFallback

        guidance   = $guidance
    }
}

