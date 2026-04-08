# ===== Individual DNS Check Functions =====
function Get-DnsBaseStatus {
  param([string]$Domain)

  # Base/root TXT checks.
  # - Collect all root TXT strings.
  # - Detect SPF (v=spf1...) and ACS verification token (ms-domain-verification...).

  $spf        = $null
  $acsTxt     = $null
  $txtRecords = @()
  $dnsFailed  = $false
  $dnsError   = $null
  $ipv4Addrs  = @()
  $ipv6Addrs  = @()
  $ipLookupDomain = $Domain
  $ipUsedParent = $false
  $txtLookupDomain = $Domain
  $txtUsedParent = $false
  $parentTxtRecords = @()
  $parentSpf = $null
  $parentAcsTxt = $null
  $spfAnalysis = $null
  $spfExpandedText = $null
  $spfGuidance = @()
  $spfOutlookRequirement = $null

  try {
    $records = ResolveSafely $Domain "TXT" -ThrowOnError
    foreach ($r in $records) {
      $joined = ($r.Strings -join "").Trim()
      if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
        $joined = $joined.Substring(1, $joined.Length - 2)
      }
      if ($joined) { $txtRecords += $joined }
    }

    $aRecs = ResolveSafely $Domain "A"
    if ($aRecs) { $ipv4Addrs = @($aRecs | Get-DnsIpString) }
    $aaaaRecs = ResolveSafely $Domain "AAAA"
    if ($aaaaRecs) { $ipv6Addrs = @($aaaaRecs | Get-DnsIpString) }
  } catch {
    $dnsFailed = $true
    $dnsError  = $_.Exception.Message
  }

  if (-not $dnsFailed -and $ipv4Addrs.Count -eq 0 -and $ipv6Addrs.Count -eq 0) {
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

      try {
        $aRecsParent = ResolveSafely $parent "A"
        $aaaaRecsParent = ResolveSafely $parent "AAAA"
        $v4p = if ($aRecsParent) { @($aRecsParent | Get-DnsIpString) } else { @() }
        $v6p = if ($aaaaRecsParent) { @($aaaaRecsParent | Get-DnsIpString) } else { @() }
        if ($v4p.Count -gt 0 -or $v6p.Count -gt 0) {
          $ipv4Addrs = $v4p
          $ipv6Addrs = $v6p
          $ipLookupDomain = $parent
          $ipUsedParent = $true
          break
        }
      } catch { }
    }
  }

  if (-not $dnsFailed) {
    foreach ($t in $txtRecords) {
      if (-not $spf    -and $t -match '(?i)^v=spf1')                { $spf    = $t }
      if (-not $acsTxt -and $t -match '(?i)ms-domain-verification') { $acsTxt = $t }
    }

    if ($txtRecords.Count -eq 0) {
      foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

        try {
          $parentTxt = @()
          $parentRecords = ResolveSafely $parent "TXT"
          foreach ($pr in $parentRecords) {
            $joinedParent = ($pr.Strings -join "").Trim()
            if ($joinedParent.StartsWith('"') -and $joinedParent.EndsWith('"') -and $joinedParent.Length -ge 2) {
              $joinedParent = $joinedParent.Substring(1, $joinedParent.Length - 2)
            }
            if ($joinedParent) { $parentTxt += $joinedParent }
          }

          if ($parentTxt.Count -gt 0) {
            $parentTxtRecords = $parentTxt
            $txtLookupDomain = $parent
            $txtUsedParent = $true

            foreach ($t in $parentTxtRecords) {
              if (-not $parentSpf -and $t -match '(?i)^v=spf1') { $parentSpf = $t }
              if (-not $parentAcsTxt -and $t -match '(?i)ms-domain-verification') { $parentAcsTxt = $t }
            }
            break
          }
        } catch { }
      }
    }
  }

  $spfPresent = -not $dnsFailed -and [bool]$spf
  $acsPresent = -not $dnsFailed -and [bool]$acsTxt

  if ($spfPresent -and -not [string]::IsNullOrWhiteSpace($spf)) {
    try {
      $spfAnalysis = Get-SpfNestedAnalysis -SpfRecord $spf -Domain $Domain
      $spfOutlookRequirement = Get-SpfOutlookRequirementStatus -Domain $Domain -SpfRecord $spf -SpfAnalysis $spfAnalysis
      $spfExpandedLines = @(Format-SpfNestedAnalysisText -Analysis $spfAnalysis)
      if ($spfOutlookRequirement -and -not [string]::IsNullOrWhiteSpace([string]$spfOutlookRequirement.detail)) {
        $spfExpandedLines += ''
        $spfExpandedLines += 'ACS Outlook SPF requirement:'
        $spfExpandedLines += [string]$spfOutlookRequirement.detail
      }
      elseif ($spfOutlookRequirement -and -not [string]::IsNullOrWhiteSpace([string]$spfOutlookRequirement.error)) {
        $spfExpandedLines += ''
        $spfExpandedLines += 'ACS Outlook SPF requirement:'
        $spfExpandedLines += [string]$spfOutlookRequirement.error
      }
      if ($spfExpandedLines.Count -gt 0) {
        $spfExpandedText = ($spfExpandedLines -join "`n")
      }
      $spfGuidance = @(Get-SpfGuidance -SpfRecord $spf -Domain $Domain -SpfAnalysis $spfAnalysis -OutlookRequirementStatus $spfOutlookRequirement)
    } catch {
      try {
        $spfOutlookRequirement = Get-SpfOutlookRequirementStatus -Domain $Domain -SpfRecord $spf -SpfAnalysis $null
        $spfGuidance = @(Get-SpfGuidance -SpfRecord $spf -Domain $Domain -SpfAnalysis $null -OutlookRequirementStatus $spfOutlookRequirement)
      } catch { }
    }
  }

  [pscustomobject]@{
    domain     = $Domain
    dnsFailed  = $dnsFailed
    dnsError   = $dnsError

    txtLookupDomain = $txtLookupDomain
    txtUsedParent   = $txtUsedParent

    ipLookupDomain = $ipLookupDomain
    ipUsedParent   = $ipUsedParent

    ipv4Addresses = $ipv4Addrs
    ipv6Addresses = $ipv6Addrs

    spfPresent = $spfPresent
    spfValue   = $spf
    spfAnalysis = $spfAnalysis
    spfExpandedText = $spfExpandedText
    spfGuidance = $spfGuidance
    spfHasRequiredInclude = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.isPresent } else { $null })
    spfRequiredInclude = 'spf.protection.outlook.com'
    spfRequiredIncludeMatchType = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.matchType } else { $null })
    spfRequiredIncludeDetail = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.detail } else { $null })
    spfRequiredIncludeError = $(if ($spfOutlookRequirement) { $spfOutlookRequirement.error } else { $null })
    acsPresent = $acsPresent
    acsValue   = $acsTxt

    parentSpfPresent = (-not $dnsFailed) -and [bool]$parentSpf
    parentSpfValue   = $parentSpf
    parentAcsPresent = (-not $dnsFailed) -and [bool]$parentAcsTxt
    parentAcsValue   = $parentAcsTxt
    parentTxtRecords = $parentTxtRecords

    txtRecords = $txtRecords
  }
}

function Get-DnsMxStatus {
  param([string]$Domain)

  # MX checks.
  # - Resolve MX records.
  # - Guess the mail provider based on the lowest-preference MX host.
  # - Resolve A/AAAA for each MX host to show concrete IP targets.

  $mxLookupDomain = $Domain
  $mxFallbackDomainChecked = $null
  $mxFallbackUsed = $false

  function Invoke-MxLookupCore {
    param([string]$LookupDomain)

    $result = [pscustomobject]@{
      mxRecords = @()
      mxRecordsDetailed = @()
      mxProvider = $null
      mxProviderHint = $null
    }

    if ($mx = ResolveSafely $LookupDomain "MX") {
      $mxRecordsOnly = @(Get-MxRecordObjects -Records $mx)
      if (-not $mxRecordsOnly -or $mxRecordsOnly.Count -eq 0) {
        return $result
      }

      $mxSorted = $mxRecordsOnly | Sort-Object Preference, NameExchange

      $primaryMx = $null
      try { $primaryMx = ($mxSorted | Select-Object -First 1 -ExpandProperty NameExchange) } catch { $primaryMx = $null }

      if ($primaryMx) {
        $mxHost = $primaryMx.ToString().Trim().TrimEnd('.').ToLowerInvariant()
switch -Regex ($mxHost) {
          # --- Microsoft & Google ---
          'mail\.protection\.outlook\.com\.?$' {
            $result.mxProvider = 'Microsoft 365 / Exchange Online'
            $result.mxProviderHint = 'MX points to Exchange Online Protection (EOP).'
            break
          }
          '(^|\.)protection\.outlook\.com\.?$' {
            $result.mxProvider = 'Microsoft Defender for Office 365 / EOP'
            $result.mxProviderHint = 'MX points to Microsoft filtering service.'
            break
          }
          'aspmx\.l\.google\.com\.?$|\.aspmx\.l\.google\.com\.?$|google\.com\.?$' {
            $result.mxProvider = 'Google Workspace / Gmail'
            $result.mxProviderHint = 'MX points to Google mail exchangers.'
            break
          }

          # --- Major Commercial Email (Yahoo, Apple, Zoho, etc.) ---
          '(^|\.)yahoodns\.net\.?$|(^|\.)yahoodns\.com\.?$|(^|\.)bizmail\.yahoo\.com\.?$' {
            $result.mxProvider = 'Yahoo Mail'
            $result.mxProviderHint = 'MX points to Yahoo Mail.'
            break
          }
          '(^|\.)mail\.icloud\.com\.?$' {
            $result.mxProvider = 'Apple iCloud Mail'
            $result.mxProviderHint = 'MX points to Apple iCloud Mail.'
            break
          }
          'zoho\.com\.?$' {
            $result.mxProvider = 'Zoho Mail'
            $result.mxProviderHint = 'MX points to Zoho Mail.'
            break
          }
          '(^|\.)messagingengine\.com\.?$' {
            $result.mxProvider = 'Fastmail'
            $result.mxProviderHint = 'MX points to Fastmail.'
            break
          }

          # --- Privacy-Focused & Secure Webmail ---
          '(^|\.)protonmail\.ch\.?$|(^|\.)protonmail\.net\.?$' {
            $result.mxProvider = 'Proton Mail'
            $result.mxProviderHint = 'MX points to Proton Mail.'
            break
          }
          '(^|\.)tutanota\.de\.?$|(^|\.)tuta\.com\.?$' {
            $result.mxProvider = 'Tuta (Tutanota)'
            $result.mxProviderHint = 'MX points to Tuta secure email.'
            break
          }
          '(^|\.)hushmail\.com\.?$' {
            $result.mxProvider = 'Hushmail'
            $result.mxProviderHint = 'MX points to Hushmail encrypted email.'
            break
          }
          '(^|\.)runbox\.com\.?$' {
            $result.mxProvider = 'Runbox'
            $result.mxProviderHint = 'MX points to Runbox secure email.'
            break
          }
          '(^|\.)mailfence\.com\.?$' {
            $result.mxProvider = 'Mailfence'
            $result.mxProviderHint = 'MX points to Mailfence secure email.'
            break
          }
          '(^|\.)startmail\.com\.?$' {
            $result.mxProvider = 'StartMail'
            $result.mxProviderHint = 'MX points to StartMail private email.'
            break
          }

          # --- Security, Cloud Filtering & Gateways ---
          '(^|\.)mx\.cloudflare\.net\.?$' {
            $result.mxProvider = 'Cloudflare Email Routing'
            $result.mxProviderHint = 'MX points to Cloudflare (mx.cloudflare.net).'
            break
          }
          'pphosted\.com\.?$' {
            $result.mxProvider = 'Proofpoint'
            $result.mxProviderHint = 'MX points to Proofpoint-hosted mail.'
            break
          }
          '(^|\.)ppe-hosted\.com\.?$|(^|\.)pphostedmail\.com\.?$' {
            $result.mxProvider = 'Proofpoint Essentials'
            $result.mxProviderHint = 'MX points to Proofpoint Essentials.'
            break
          }
          'mimecast\.com\.?$' {
            $result.mxProvider = 'Mimecast'
            $result.mxProviderHint = 'MX points to Mimecast.'
            break
          }
          '(^|\.)iphmx\.com\.?$|(^|\.)esa\d*\..*\.iphmx\.com\.?$|(^|\.)ironport\.com\.?$' {
            $result.mxProvider = 'Cisco Secure Email / IronPort'
            $result.mxProviderHint = 'MX points to Cisco Secure Email (IronPort).'
            break
          }
          '(^|\.)mailcontrol\.com\.?$' {
            $result.mxProvider = 'Forcepoint / Websense Email Security'
            $result.mxProviderHint = 'MX points to Forcepoint-hosted email security.'
            break
          }
          '(^|\.)mailspamprotection\.com\.?$|(^|\.)spamh\.eu\.?$' {
            $result.mxProvider = 'SpamHero'
            $result.mxProviderHint = 'MX points to SpamHero email filtering.'
            break
          }
          '(^|\.)trendmicro\.eu\.?$|(^|\.)trendmicro\.com\.?$|(^|\.)hes\.ms$|(^|\.)mxthunder\.net\.?$' {
            $result.mxProvider = 'Trend Micro Hosted Email Security'
            $result.mxProviderHint = 'MX points to Trend Micro hosted email security.'
            break
          }
          '(^|\.)protection\.messagelabs\.com\.?$' {
            $result.mxProvider = 'Broadcom / Symantec Email Security.cloud'
            $result.mxProviderHint = 'MX points to Symantec Email Security.cloud.'
            break
          }
          '(^|\.)messagelabs\.com\.?$' {
            $result.mxProvider = 'Symantec MessageLabs'
            $result.mxProviderHint = 'MX points to Symantec MessageLabs.'
            break
          }
          '(^|\.)antispamcloud\.com\.?$' {
            $result.mxProvider = 'SpamExperts / N-able Mail Assure'
            $result.mxProviderHint = 'MX points to SpamExperts / Mail Assure filtering.'
            break
          }
          '(^|\.)mailfiltering\.com\.?$|(^|\.)spamtitan\.com\.?$' {
            $result.mxProvider = 'SpamTitan'
            $result.mxProviderHint = 'MX points to SpamTitan filtering.'
            break
          }
          '(^|\.)protection\.mailguard\.com\.au\.?$|(^|\.)mailguard\.com\.au\.?$' {
            $result.mxProvider = 'MailGuard'
            $result.mxProviderHint = 'MX points to MailGuard filtering.'
            break
          }
          '(^|\.)sophos\.com\.?$|(^|\.)sophosxl\.net\.?$' {
            $result.mxProvider = 'Sophos Email'
            $result.mxProviderHint = 'MX points to Sophos Email security.'
            break
          }
          '(^|\.)tessian\.com\.?$' {
            $result.mxProvider = 'Tessian'
            $result.mxProviderHint = 'MX points to Tessian email security.'
            break
          }
          '(^|\.)barracudanetworks\.com\.?$' {
            $result.mxProvider = 'Barracuda Networks'
            $result.mxProviderHint = 'MX points to Barracuda Email Security Gateway.'
            break
          }
          '(^|\.)appriver\.com\.?$' {
            $result.mxProvider = 'AppRiver / Zix'
            $result.mxProviderHint = 'MX points to AppRiver secure email.'
            break
          }
          '(^|\.)hornetsecurity\.com\.?$' {
            $result.mxProvider = 'Hornetsecurity'
            $result.mxProviderHint = 'MX points to Hornetsecurity cloud filtering.'
            break
          }
          '(^|\.)fortinet\.com\.?$' {
            $result.mxProvider = 'Fortinet FortiMail'
            $result.mxProviderHint = 'MX points to Fortinet email security.'
            break
          }
          '(^|\.)trustifi\.com\.?$' {
            $result.mxProvider = 'Trustifi'
            $result.mxProviderHint = 'MX points to Trustifi email security.'
            break
          }
          '(^|\.)halon\.io\.?$' {
            $result.mxProvider = 'Halon'
            $result.mxProviderHint = 'MX points to Halon MTA / Security.'
            break
          }
          '(^|\.)fireeye\.com\.?$' {
            $result.mxProvider = 'FireEye'
            $result.mxProviderHint = 'MX points to FireEye Email Security.'
            break
          }

          # --- Transactional, Delivery APIs & Marketing ---
          '(^|\.)mailgun\.org\.?$' {
            $result.mxProvider = 'Mailgun'
            $result.mxProviderHint = 'MX points to Mailgun.'
            break
          }
          '(^|\.)sendgrid\.net\.?$' {
            $result.mxProvider = 'SendGrid'
            $result.mxProviderHint = 'MX points to SendGrid.'
            break
          }
          '(^|\.)amazonses\.com\.?$' {
            $result.mxProvider = 'Amazon SES'
            $result.mxProviderHint = 'MX points to Amazon SES.'
            break
          }
          '(^|\.)inbound-smtp\.[a-z0-9-]+\.amazonaws\.com\.?$' {
            $result.mxProvider = 'Amazon SES'
            $result.mxProviderHint = 'MX points to Amazon SES inbound mail.'
            break
          }
          '(^|\.)postmarkapp\.com\.?$' {
            $result.mxProvider = 'Postmark'
            $result.mxProviderHint = 'MX points to Postmark inbound processing.'
            break
          }
          '(^|\.)sparkpostmail\.com\.?$' {
            $result.mxProvider = 'SparkPost'
            $result.mxProviderHint = 'MX points to SparkPost inbound.'
            break
          }
          '(^|\.)hubspotemail\.net\.?$' {
            $result.mxProvider = 'HubSpot'
            $result.mxProviderHint = 'MX points to HubSpot inbound routing.'
            break
          }

          # --- Web Hosting, Registrars & Hosted Email ---
          '(^|\.)secureserver\.net\.?$|(^|\.)hosteurope\.de\.?$' {
            $result.mxProvider = 'GoDaddy Email / Workspace Email'
            $result.mxProviderHint = 'MX points to GoDaddy-hosted email.'
            break
          }
          '(^|\.)mailstore1\.secureserver\.net\.?$|(^|\.)smtp\.secureserver\.net\.?$' {
            $result.mxProvider = 'GoDaddy Email / Workspace Email'
            $result.mxProviderHint = 'MX points to GoDaddy-hosted email.'
            break
          }
          '(^|\.)emailsrvr\.com\.?$' {
            $result.mxProvider = 'Rackspace Email'
            $result.mxProviderHint = 'MX points to Rackspace Email.'
            break
          }
          '(^|\.)mxroute\.com\.?$' {
            $result.mxProvider = 'Mxroute'
            $result.mxProviderHint = 'MX points to Mxroute.'
            break
          }
          '(^|\.)mailhostbox\.com\.?$' {
            $result.mxProvider = 'Titan Email'
            $result.mxProviderHint = 'MX points to Titan Email.'
            break
          }
          '(^|\.)titan\.email\.?$' {
            $result.mxProvider = 'Titan Email'
            $result.mxProviderHint = 'MX points to Titan Email.'
            break
          }
          '(^|\.)prolocation\.(nl|net)\.?$' {
            $result.mxProvider = 'Prolocation'
            $result.mxProviderHint = 'MX points to Prolocation-hosted mail.'
            break
          }
          '(^|\.)intermedia\.net\.?$' {
            $result.mxProvider = 'Intermedia'
            $result.mxProviderHint = 'MX points to Intermedia-hosted email.'
            break
          }
          '(^|\.)hostedemail\.com\.?$' {
            $result.mxProvider = 'Intermedia'
            $result.mxProviderHint = 'MX points to Intermedia-hosted email.'
            break
          }
          '(^|\.)ovh\.net\.?$|(^|\.)mail\.ovh\.net\.?$' {
            $result.mxProvider = 'OVH Mail'
            $result.mxProviderHint = 'MX points to OVH Mail.'
            break
          }
          '(^|\.)ionos\.com\.?$|(^|\.)kundenserver\.de\.?$' {
            $result.mxProvider = 'IONOS Mail'
            $result.mxProviderHint = 'MX points to IONOS-hosted mail.'
            break
          }
          '(^|\.)1and1\.(com|de)\.?$' {
            $result.mxProvider = 'IONOS Mail'
            $result.mxProviderHint = 'MX points to IONOS-hosted mail.'
            break
          }
          '(^|\.)privateemail\.com\.?$' {
            $result.mxProvider = 'Namecheap Private Email'
            $result.mxProviderHint = 'MX points to Namecheap Private Email.'
            break
          }
          '(^|\.)registrar-servers\.com\.?$' {
            $result.mxProvider = 'Namecheap (Default)'
            $result.mxProviderHint = 'MX points to Namecheap default mail routing.'
            break
          }
          '(^|\.)hostinger\.com\.?$|(^|\.)tigomail\.net\.?$' {
            $result.mxProvider = 'Hostinger Email'
            $result.mxProviderHint = 'MX points to Hostinger-hosted email.'
            break
          }
          '(^|\.)mxlogin\.com\.?$|(^|\.)myregistersite\.com\.?$' {
            $result.mxProvider = 'Fasthosts / Newfold Email'
            $result.mxProviderHint = 'MX points to Fasthosts / Newfold-hosted email.'
            break
          }
          '(^|\.)websitewelcome\.com\.?$' {
            $result.mxProvider = 'Newfold Digital (Bluehost/HostGator)'
            $result.mxProviderHint = 'MX points to Newfold Digital shared hosting.'
            break
          }
          '(^|\.)gandi\.net\.?$' {
            $result.mxProvider = 'Gandi Mail'
            $result.mxProviderHint = 'MX points to Gandi-hosted email.'
            break
          }
          '(^|\.)dreamhost\.com\.?$' {
            $result.mxProvider = 'DreamHost'
            $result.mxProviderHint = 'MX points to DreamHost email.'
            break
          }
          '(^|\.)siteground\.com\.?$|(^|\.)sgvps\.net\.?$' {
            $result.mxProvider = 'SiteGround'
            $result.mxProviderHint = 'MX points to SiteGround hosting.'
            break
          }
          '(^|\.)a2hosting\.com\.?$' {
            $result.mxProvider = 'A2 Hosting'
            $result.mxProviderHint = 'MX points to A2 Hosting.'
            break
          }
          '(^|\.)inmotionhosting\.com\.?$|(^|\.)servconfig\.com\.?$' {
            $result.mxProvider = 'InMotion Hosting'
            $result.mxProviderHint = 'MX points to InMotion Hosting.'
            break
          }
          '(^|\.)liquidweb\.com\.?$' {
            $result.mxProvider = 'Liquid Web'
            $result.mxProviderHint = 'MX points to Liquid Web hosting.'
            break
          }
          '(^|\.)squarespace\.com\.?$' {
            $result.mxProvider = 'Squarespace'
            $result.mxProviderHint = 'MX points to Squarespace default routing.'
            break
          }

          # --- International & ISPs ---
          '(^|\.)yandex\.(ru|net|com)\.?$' {
            $result.mxProvider = 'Yandex Mail'
            $result.mxProviderHint = 'MX points to Yandex Mail.'
            break
          }
          '(^|\.)mail\.ru\.?$' {
            $result.mxProvider = 'Mail.ru'
            $result.mxProviderHint = 'MX points to Mail.ru.'
            break
          }
          '(^|\.)comcast\.net\.?$' {
            $result.mxProvider = 'Comcast'
            $result.mxProviderHint = 'MX points to Comcast / Xfinity.'
            break
          }
          '(^|\.)verizon\.net\.?$' {
            $result.mxProvider = 'Verizon'
            $result.mxProviderHint = 'MX points to Verizon.'
            break
          }
          '(^|\.)att\.net\.?$|(^|\.)sbcglobal\.net\.?$' {
            $result.mxProvider = 'AT&T'
            $result.mxProviderHint = 'MX points to AT&T / Yahoo infrastructure.'
            break
          }
          '(^|\.)charter\.net\.?$|(^|\.)spectrum\.com\.?$' {
            $result.mxProvider = 'Spectrum / Charter'
            $result.mxProviderHint = 'MX points to Spectrum.'
            break
          }
          '(^|\.)btinternet\.com\.?$' {
            $result.mxProvider = 'BT Group'
            $result.mxProviderHint = 'MX points to BT Internet (UK).'
            break
          }
          '(^|\.)virginmedia\.com\.?$' {
            $result.mxProvider = 'Virgin Media'
            $result.mxProviderHint = 'MX points to Virgin Media (UK).'
            break
          }
          '(^|\.)optusnet\.com\.au\.?$' {
            $result.mxProvider = 'Optus'
            $result.mxProviderHint = 'MX points to Optus (Australia).'
            break
          }
          '(^|\.)telstra\.com\.?$' {
            $result.mxProvider = 'Telstra'
            $result.mxProviderHint = 'MX points to Telstra (Australia).'
            break
          }

          # --- Default Catch-All ---
          default {
            $result.mxProvider = 'Unknown'
            $result.mxProviderHint = 'Provider not recognized from MX hostname.'
          }
        }
      }

      foreach ($m in $mxSorted) {
        $mxHost = [string]$m.NameExchange
        if ([string]::IsNullOrWhiteSpace($mxHost)) { continue }
        $mxHost = $mxHost.Trim().TrimEnd('.')

        $result.mxRecords += "$mxHost (Priority $($m.Preference))"

        $ipv4 = @()
        $ipv6 = @()

        if ($aRecs = ResolveSafely $mxHost "A") {
          $ipv4 += $aRecs | Get-DnsIpString
        }
        if ($aaaaRecs = ResolveSafely $mxHost "AAAA") {
          $ipv6 += $aaaaRecs | Get-DnsIpString
        }

        if (-not $ipv4 -and -not $ipv6) {
          $result.mxRecordsDetailed += [pscustomobject]@{
            Hostname = $mxHost
            Priority = $m.Preference
            Type = "N/A"
            IPAddress = "(none found)"
          }
        } else {
          foreach ($ip in $ipv4) {
            $result.mxRecordsDetailed += [pscustomobject]@{
              Hostname = $mxHost
              Priority = $m.Preference
              Type = "IPv4"
              IPAddress = $ip
            }
          }
          foreach ($ip in $ipv6) {
            $result.mxRecordsDetailed += [pscustomobject]@{
              Hostname = $mxHost
              Priority = $m.Preference
              Type = "IPv6"
              IPAddress = $ip
            }
          }
        }
      }
    }

    return $result
  }

  # First, try the exact domain.
  $mxResult = Invoke-MxLookupCore -LookupDomain $Domain

  # If none found, try the registrable (parent) domain as a fallback.
  if (($mxResult.mxRecords.Count -eq 0) -and ($mxResult.mxRecordsDetailed.Count -eq 0)) {
    $parentsChecked = New-Object System.Collections.Generic.List[string]
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

      $parent = $parent.Trim().TrimEnd('.')
      $parentsChecked.Add($parent)
      $parentResult = Invoke-MxLookupCore -LookupDomain $parent
      if (($parentResult.mxRecords.Count -gt 0) -or ($parentResult.mxRecordsDetailed.Count -gt 0)) {
        $mxResult = $parentResult
        $mxLookupDomain = $parent
        $mxFallbackUsed = $true
        break
      }
    }

    if ($parentsChecked.Count -gt 0) {
      $mxFallbackDomainChecked = ($parentsChecked -join ', ')
    }
  }

  if ($mxLookupDomain) { $mxLookupDomain = $mxLookupDomain.Trim().TrimEnd('.') }

  [pscustomobject]@{
    domain                  = $Domain
    mxLookupDomain          = $mxLookupDomain
    mxFallbackDomainChecked = $mxFallbackDomainChecked
    mxFallbackUsed          = $mxFallbackUsed
    mxRecords               = $mxResult.mxRecords
    mxRecordsDetailed       = $mxResult.mxRecordsDetailed
    mxProvider              = $mxResult.mxProvider
    mxProviderHint          = $mxResult.mxProviderHint
  }
}

function Get-DnsDmarcStatus {
  param([string]$Domain)

  # DMARC is a TXT record at `_dmarc.<domain>`.

  $dmarc = $null
  $dmarcLookupDomain = $Domain
  $dmarcInherited = $false
  $organizationalDomain = Get-RegistrableDomain -Domain $Domain

  function Get-DmarcRecordValue {
    param([string]$LookupDomain)

    $recordValue = $null
    if ($dm = ResolveSafely "_dmarc.$LookupDomain" "TXT") {
      foreach ($r in $dm) {
        $j = ($r.Strings -join "").Trim()
        if ($j -match '(?i)^v=dmarc') {
          $recordValue = $j
          break
        }
      }
    }
    return $recordValue
  }

  $dmarc = Get-DmarcRecordValue -LookupDomain $Domain
  if (-not $dmarc) {
    $orgLabelCount = if ([string]::IsNullOrWhiteSpace($organizationalDomain)) { 0 } else { $organizationalDomain.Trim('.').Split('.').Count }
    foreach ($parent in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Domain) { continue }

      $parentLabelCount = $parent.Trim('.').Split('.').Count
      if ($orgLabelCount -gt 0 -and $parentLabelCount -lt $orgLabelCount) { continue }

      $candidate = Get-DmarcRecordValue -LookupDomain $parent
      if ($candidate) {
        $dmarc = $candidate
        $dmarcLookupDomain = $parent
        $dmarcInherited = $true
        break
      }
    }
  }

  [pscustomobject]@{
    domain = $Domain
    dmarc = $dmarc
    dmarcLookupDomain = $dmarcLookupDomain
    dmarcInherited = $dmarcInherited
    dmarcOrganizationalDomain = $organizationalDomain
  }
}

# Check for the two ACS-specific DKIM selector CNAME/TXT records:
#   selector1-azurecomm-prod-net._domainkey.<domain>
#   selector2-azurecomm-prod-net._domainkey.<domain>
function Get-DnsDkimStatus {
  param([string]$Domain)

  # ACS guidance expects these two DKIM selector TXT records.

  $dkim1 = $null
  if ($d1 = ResolveSafely "selector1-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim1 = (($d1.Strings -join "") -replace '\s+', '').Trim()
  }

  $dkim2 = $null
  if ($d2 = ResolveSafely "selector2-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim2 = (($d2.Strings -join "") -replace '\s+', '').Trim()
  }

  [pscustomobject]@{ domain = $Domain; dkim1 = $dkim1; dkim2 = $dkim2 }
}

# Extract the CNAME target from DNS resolution result objects.
# Handles multiple property-name variants (CanonicalName, NameHost, NameTarget, Target)
# and filters out non-CNAME record types (e.g., SOA in authority section).
function Get-CnameTargetFromRecords {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Records
  )

  foreach ($r in @($Records)) {
    if ($null -eq $r) { continue }

    $props = $r.PSObject.Properties

    # `Resolve-DnsName -Type CNAME` may return SOA in the Authority section when no CNAME exists.
    # Only treat actual CNAME records as a match.
    $typeValue = $null
    if ($props.Match('Type').Count -gt 0) { $typeValue = $r.Type }
    elseif ($props.Match('TypeName').Count -gt 0) { $typeValue = $r.TypeName }
    elseif ($props.Match('QueryType').Count -gt 0) { $typeValue = $r.QueryType }

    $typeString = [string]$typeValue
    if (-not [string]::IsNullOrWhiteSpace($typeString) -and $typeString -ne 'CNAME') {
      continue
    }

    $target = $null
    if ($props.Match('CanonicalName').Count -gt 0) { $target = $r.CanonicalName }
    elseif ($props.Match('NameHost').Count -gt 0) { $target = $r.NameHost }
    elseif ($props.Match('NameTarget').Count -gt 0) { $target = $r.NameTarget }
    elseif ($props.Match('Target').Count -gt 0) { $target = $r.Target }

    $targetString = [string]$target
    if ([string]::IsNullOrWhiteSpace($targetString)) { continue }

    return $targetString.Trim().TrimEnd('.')
  }

  return $null
}

function Get-DnsCnameStatus {
  param([string]$Domain)

  # Root CNAME check (not required for ACS verification; included as guidance).

  $cname = $null
  $cnameLookupDomain = $Domain
  $cnameUsedWwwFallback = $false
  $normalizedDomain = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant()
  $labelCount = if ([string]::IsNullOrWhiteSpace($normalizedDomain)) { 0 } else { $normalizedDomain.Split('.').Count }
  $checkWwwFallback = ($normalizedDomain -notmatch '^(?i)www\.') -and ($labelCount -le 3)

  $lookupNames = if ($normalizedDomain -match '^(?i)www\.') { @($normalizedDomain) } elseif ($checkWwwFallback) { @($normalizedDomain, "www.$normalizedDomain") } else { @($normalizedDomain) }
  foreach ($name in $lookupNames) {
    $target = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
    if (-not [string]::IsNullOrWhiteSpace($target)) {
      $cname = $target
      $cnameLookupDomain = $name
      $cnameUsedWwwFallback = ($name -ne $normalizedDomain)
      break
    }
  }

  [pscustomobject]@{
    domain = $Domain
    cname = $cname
    cnameLookupDomain = $cnameLookupDomain
    cnameUsedWwwFallback = $cnameUsedWwwFallback
  }
}

# ------------------- DNSBL / REPUTATION CHECK -------------------
# Check whether the mail-server IPs for a domain are listed on DNS-based blocklists (DNSBLs).
# DNSBL queries work by reversing the IPv4 octets and appending the blocklist zone
# (e.g., 2.1.168.192.bl.spamcop.net). An A record response means the IP is listed.

# Reverse the octets of an IPv4 address for DNSBL queries.
