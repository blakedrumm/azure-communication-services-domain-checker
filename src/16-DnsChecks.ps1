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
#
# ACS publishes DKIM keys via Azure-managed selector hostnames at azurecomm.net.
# The customer-side DNS only needs a CNAME pointing at the ACS-managed target;
# the actual public key (TXT) lives on Microsoft's side. So the deterministic
# "ACS configured" check is whether the customer's CNAME points at the expected
# ACS selector hostname. We also capture the resolved TXT public-key value (the
# CNAME chain is followed by both Resolve-DnsName and DoH) so the UI can show
# the full picture.
#
# When the ACS-specific selector is not published, we additionally probe a
# small set of well-known fallback DKIM selectors (Microsoft 365's bare
# `selector1._domainkey`, plus a few common ones) so the card body can still
# show the operator what DKIM IS configured for the domain. The pass/fail tag
# in the UI is always evaluated against the strict ACS expectation.
function Get-DnsDkimStatus {
  param([string]$Domain)

  # Lookup helper: resolves the CNAME target (if any) and the TXT value (which
  # follows the CNAME chain), then compares the CNAME target against the
  # expected ACS-managed selector hostname.
  function Invoke-AcsDkimSelectorLookup {
    param(
      [string]$LookupName,
      [string]$ExpectedCnameTarget
    )

    $cnameTarget = Get-CnameTargetFromRecords (ResolveSafely $LookupName 'CNAME')
    if ($cnameTarget) { $cnameTarget = $cnameTarget.Trim().TrimEnd('.') }

    $txtValue = $null
    if ($txtRecords = ResolveSafely $LookupName 'TXT') {
      $joined = (($txtRecords.Strings -join '') -replace '\s+', '').Trim()
      if ($joined) { $txtValue = $joined }
    }

    # Case-insensitive compare; both sides are normalized to no trailing dot.
    $expected = $ExpectedCnameTarget.Trim().TrimEnd('.')
    $acsConfigured = $false
    if ($cnameTarget) {
      $acsConfigured = [string]::Equals($cnameTarget, $expected, [System.StringComparison]::OrdinalIgnoreCase)
    }

    # Build a single human-readable display value combining both legs of the
    # chain. This is what gets surfaced in the legacy `dkim1`/`dkim2` fields so
    # existing UI/test-summary truthy checks still mean "something is published".
    $displayParts = New-Object System.Collections.Generic.List[string]
    if ($cnameTarget) { $displayParts.Add("CNAME -> $cnameTarget") }
    if ($txtValue)    { $displayParts.Add("TXT: $txtValue") }
    $display = if ($displayParts.Count -gt 0) { ($displayParts -join "`n") } else { $null }

    [pscustomobject]@{
      Display       = $display
      CnameTarget   = $cnameTarget
      TxtValue      = $txtValue
      Expected      = $expected
      AcsConfigured = $acsConfigured
    }
  }

  # Fallback probe: when no ACS record exists at the expected selector, scan a
  # small set of well-known DKIM selector names so the card can still show the
  # operator what is configured. Returns a multi-line display string of every
  # selector name with a CNAME or TXT plus a list of structured rows.
  function Invoke-DkimFallbackSelectorProbe {
    param(
      [string]$Domain,
      [int]$IndexHint
    )

    # Selector ordering matters: more specific / index-aligned names come first
    # so e.g. `selector1._domainkey` is preferred for the DKIM1 card.
    $hint = if ($IndexHint -eq 1 -or $IndexHint -eq 2) { $IndexHint } else { 1 }
    $selectors = @(
      "selector$hint",
      "s$hint",
      'default',
      'google',
      'k1',
      'mail',
      'dkim'
    ) | Select-Object -Unique

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($selector in $selectors) {
      $name = "$selector._domainkey.$Domain"

      $cnameTarget = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
      if ($cnameTarget) { $cnameTarget = $cnameTarget.Trim().TrimEnd('.') }

      $txtValue = $null
      if ($txtRecords = ResolveSafely $name 'TXT') {
        $joined = (($txtRecords.Strings -join '') -replace '\s+', '').Trim()
        if ($joined) { $txtValue = $joined }
      }

      if (-not $cnameTarget -and -not $txtValue) { continue }

      $rows.Add([pscustomobject]@{
        Name        = $name
        Selector    = $selector
        CnameTarget = $cnameTarget
        TxtValue    = $txtValue
      })
    }

    if ($rows.Count -eq 0) { return $null }

    # Compose a friendly multi-line display, e.g.:
    #   selector1._domainkey.example.com
    #     CNAME -> selector1-example-com._domainkey.example.onmicrosoft.com
    #     TXT: v=DKIM1;k=rsa;p=...
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
      $lines.Add($row.Name)
      if ($row.CnameTarget) { $lines.Add("  CNAME -> $($row.CnameTarget)") }
      if ($row.TxtValue)    { $lines.Add("  TXT: $($row.TxtValue)") }
    }

    [pscustomobject]@{
      Display = ($lines -join "`n")
      Rows    = $rows.ToArray()
    }
  }

  $dkim1Result = Invoke-AcsDkimSelectorLookup -LookupName "selector1-azurecomm-prod-net._domainkey.$Domain" -ExpectedCnameTarget 'selector1-azurecomm-prod-net._domainkey.azurecomm.net'
  $dkim2Result = Invoke-AcsDkimSelectorLookup -LookupName "selector2-azurecomm-prod-net._domainkey.$Domain" -ExpectedCnameTarget 'selector2-azurecomm-prod-net._domainkey.azurecomm.net'

  # If either ACS slot is empty, run the fallback probe so the card body can
  # show whatever DKIM is actually published. The ACS-specific PASS/FAIL flag
  # remains strict -- finding a non-ACS selector does not satisfy ACS DKIM.
  $dkim1FallbackDisplay = $null
  $dkim1FallbackRows    = @()
  if (-not $dkim1Result.Display) {
    $fb = Invoke-DkimFallbackSelectorProbe -Domain $Domain -IndexHint 1
    if ($fb) {
      $dkim1FallbackDisplay = $fb.Display
      $dkim1FallbackRows    = $fb.Rows
    }
  }

  $dkim2FallbackDisplay = $null
  $dkim2FallbackRows    = @()
  if (-not $dkim2Result.Display) {
    $fb = Invoke-DkimFallbackSelectorProbe -Domain $Domain -IndexHint 2
    if ($fb) {
      $dkim2FallbackDisplay = $fb.Display
      $dkim2FallbackRows    = $fb.Rows
    }
  }

  # Compose the final display value for the legacy `dkim1`/`dkim2` fields. We
  # keep the body to JUST the published record(s) -- no prose preface -- so the
  # card shows clean DNS data. The UI is responsible for surfacing the
  # "ACS selector not published" notice as a separate styled callout when the
  # strict ACS PASS/FAIL flag indicates the alternate selector data is what is
  # actually being shown.
  $dkim1Display = $dkim1Result.Display
  if (-not $dkim1Display -and $dkim1FallbackDisplay) {
    $dkim1Display = $dkim1FallbackDisplay
  }

  $dkim2Display = $dkim2Result.Display
  if (-not $dkim2Display -and $dkim2FallbackDisplay) {
    $dkim2Display = $dkim2FallbackDisplay
  }

  [pscustomobject]@{
    domain                    = $Domain
    dkim1                     = $dkim1Display
    dkim1CnameTarget          = $dkim1Result.CnameTarget
    dkim1TxtValue             = $dkim1Result.TxtValue
    dkim1ExpectedCname        = $dkim1Result.Expected
    dkim1AcsConfigured        = $dkim1Result.AcsConfigured
    dkim1FallbackSelectors    = $dkim1FallbackRows
    dkim2                     = $dkim2Display
    dkim2CnameTarget          = $dkim2Result.CnameTarget
    dkim2TxtValue             = $dkim2Result.TxtValue
    dkim2ExpectedCname        = $dkim2Result.Expected
    dkim2AcsConfigured        = $dkim2Result.AcsConfigured
    dkim2FallbackSelectors    = $dkim2FallbackRows
  }
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
