# ===== Domain Registration Status =====
function Get-DomainRegistrationStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [int]$NewDomainWarnThresholdDays = 180,
    [int]$NewDomainErrorThresholdDays = 90
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) {
    return [pscustomobject]@{
      domain = $Domain
      source = $null
      creationDateUtc = $null
      expiryDateUtc = $null
      registrar = $null
      registrant = $null
      ageDays = $null
      isYoungDomain = $null
      isVeryYoungDomain = $null
      newDomainThresholdDays = $NewDomainWarnThresholdDays
      newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
      newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
      error = 'Missing domain'
    }
  }

  # WHOIS/RDAP operates on the registrable domain, not arbitrary subdomains.
  # Use the registrable domain first, then fall back through parent domains if needed.
  $whoisDomain = Get-RegistrableDomain -Domain $d
  if ([string]::IsNullOrWhiteSpace($whoisDomain)) { $whoisDomain = $d }

  $creation = $null
  $expiry = $null
  $registrar = $null
  $registrant = $null
  $source = $null
  $raw = $null
  $whoisError = $null
  $rawWhoisText = $null

  $rdapError = $null
  try {
    # Throw on RDAP failures so fallback providers can be invoked.
    $raw = Invoke-RdapLookup -Domain $whoisDomain -ThrowOnError
    $source = 'RDAP'

    if ($raw -and $raw.events) {
      foreach ($ev in @($raw.events)) {
        $action = [string]$ev.eventAction
        if (-not $creation -and $action -eq 'registration') {
          $creation = ConvertTo-NullableUtcIso8601 $ev.eventDate
        }
        elseif (-not $expiry -and $action -eq 'expiration') {
          $expiry = ConvertTo-NullableUtcIso8601 $ev.eventDate
        }
      }
    }

    if (-not $registrar -and $raw -and $raw.registrarName) {
      $registrar = [string]$raw.registrarName
    } elseif ($raw -and $raw.entities) {
      foreach ($ent in @($raw.entities)) {
        $roles = @($ent.roles)
        if (-not $registrar -and $roles -contains 'registrar') {
          if ($ent.vcardArray -and $ent.vcardArray.Count -ge 2) {
            foreach ($kv in @($ent.vcardArray[1])) {
              if ($kv.Count -ge 4 -and [string]$kv[0] -eq 'fn') { $registrar = [string]$kv[3] }
            }
          }
        }
        if (-not $registrant -and $roles -contains 'registrant') {
          if ($ent.vcardArray -and $ent.vcardArray.Count -ge 2) {
            foreach ($kv in @($ent.vcardArray[1])) {
              if ($kv.Count -ge 4 -and [string]$kv[0] -eq 'fn') { $registrant = [string]$kv[3] }
            }
          }
        }
      }
    }
  }
  catch {
    $rdapError = $_.Exception.Message
    $usedFallback = $false
    $goDaddyError = $null
    $sysWhoisError = $null
    $linuxWhoisError = $null
    $tcpWhoisError = $null
    $whoisXmlError = $null

    # Prefer GoDaddy fallback when API key/secret are available.
    $gdKey = $env:GODADDY_API_KEY
    $gdSecret = $env:GODADDY_API_SECRET
    if ([string]::IsNullOrWhiteSpace($gdKey) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiKey)) { $gdKey = $GoDaddyApiKey }
    if ([string]::IsNullOrWhiteSpace($gdSecret) -and -not [string]::IsNullOrWhiteSpace($GoDaddyApiSecret)) { $gdSecret = $GoDaddyApiSecret }
    if (-not [string]::IsNullOrWhiteSpace($gdKey) -and -not [string]::IsNullOrWhiteSpace($gdSecret)) {
      try {
        $raw = Invoke-GoDaddyWhoisLookup -Domain $whoisDomain
        $source = 'GoDaddy'
        # GoDaddy domain API returns createdAt / expires fields (ISO8601).
        $creation = ConvertTo-NullableUtcIso8601 $raw.createdAt
        $expiry   = ConvertTo-NullableUtcIso8601 $raw.expires
        if (-not $registrar) { $registrar = 'GoDaddy' }
        $usedFallback = $true
      }
      catch {
        $goDaddyError = $_.Exception.Message
      }
    }

    # Platform detection: prefer runtime API; fall back to $IsWindows/PSVersionTable
    $isWindowsPlatform = $false
    try {
      $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    } catch { }
    if (-not $isWindowsPlatform) {
      try { if ($IsWindows -eq $true) { $isWindowsPlatform = $true } } catch { }
    }
    if (-not $isWindowsPlatform) {
      try { if ($PSVersionTable.Platform -eq 'Win32NT') { $isWindowsPlatform = $true } } catch { }
    }
    $isLinuxPlatform = -not $isWindowsPlatform

    # Linux whois fallback (generic CLI)
    if (-not $usedFallback -and $isLinuxPlatform) {
      try {
        $raw = Invoke-LinuxWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $linCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $linCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $linCreation = $raw.creationDate }

          $linExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $linExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $linExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $linCreation }
          if (-not $expiry)   { $expiry   = $linExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          # Best-effort: if creation/expiry still null, re-parse from raw text.
          if (-not $creation -and $rawWhoisText -match '(?im)^Creation date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $creation = if ($parsed) { $parsed } else { $val }
          }
          if (-not $expiry -and $rawWhoisText -match '(?im)^Expiration date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $expiry = if ($parsed) { $parsed } else { $val }
          }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            $source = 'LinuxWhois'
            $usedFallback = $true
          }
          else {
            $linuxWhoisError = if ($hasRawText) { "Linux whois returned no usable registration data for '$whoisDomain'." } else { "Linux whois returned output but no registrant/registrar/dates could be parsed." }
          }
        }
      }
      catch {
        $linuxWhoisError = $_.Exception.Message
      }
    }

    # Sysinternals whois fallback (Windows-only)
    if (-not $usedFallback -and $isWindowsPlatform) {
      try {
        $raw = Invoke-SysinternalsWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $sysCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $sysCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $sysCreation = $raw.creationDate }

          $sysExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $sysExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $sysExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $sysCreation }
          if (-not $expiry)   { $expiry   = $sysExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          # Best-effort: if creation/expiry still null, re-parse from raw text (Sysinternals label casing varies).
          if (-not $creation -and $rawWhoisText -match '(?im)^Creation date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $creation = if ($parsed) { $parsed } else { $val }
          }
          if (-not $expiry -and $rawWhoisText -match '(?im)^Expiration date:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $parsed = ConvertTo-NullableUtcIso8601 $val
            $expiry = if ($parsed) { $parsed } else { $val }
          }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            # Treat raw output as success when it contains registration output even if not fully parsed.
            $source = 'SysinternalsWhois'
            $usedFallback = $true
          }
          else {
            $sysWhoisError = if ($hasRawText) { "Sysinternals whois returned no usable registration data for '$whoisDomain'." } else { "Sysinternals whois returned output but no registrant/registrar/dates could be parsed." }
          }
        }
      }
      catch {
        $sysWhoisError = $_.Exception.Message
      }
    }

    # TCP whois fallback (pure PowerShell; bypasses CLI getaddrinfo service-name issues in Docker).
    if (-not $usedFallback) {
      try {
        $raw = Invoke-TcpWhoisLookup -Domain $whoisDomain -ThrowOnError
        if ($raw) {
          $tcpCreation = ConvertTo-NullableUtcIso8601 $raw.creationDate
          if (-not $tcpCreation -and -not [string]::IsNullOrWhiteSpace($raw.creationDate)) { $tcpCreation = $raw.creationDate }

          $tcpExpiry = ConvertTo-NullableUtcIso8601 $raw.expiryDate
          if (-not $tcpExpiry -and -not [string]::IsNullOrWhiteSpace($raw.expiryDate)) { $tcpExpiry = $raw.expiryDate }

          if (-not $creation) { $creation = $tcpCreation }
          if (-not $expiry)   { $expiry   = $tcpExpiry }
          if (-not $registrar -and $raw.registrar) { $registrar = [string]$raw.registrar }
          if (-not $registrant -and $raw.registrant) { $registrant = [string]$raw.registrant }
          if (-not [string]::IsNullOrWhiteSpace($raw.rawText)) { $rawWhoisText = $raw.rawText }

          $hasParsedFields = $creation -or $expiry -or $registrar -or $registrant
          $hasRawText      = -not [string]::IsNullOrWhiteSpace($raw.rawText)
          $rawHasUsableData = $hasRawText -and (Test-WhoisRawTextHasUsableData -Text $raw.rawText)

          if ($hasParsedFields) {
            $source = 'TcpWhois'
            $usedFallback = $true
          }
          elseif ($rawHasUsableData) {
            $source = 'TcpWhois'
            $usedFallback = $true
          }
          else {
            $tcpWhoisError = if ($hasRawText) { "TCP whois returned no usable registration data for '$whoisDomain'." } else { "TCP whois returned output but no registrant/registrar/dates could be parsed." }
          }
        }
      }
      catch {
        $tcpWhoisError = $_.Exception.Message
      }
    }

    # Secondary fallback: WhoisXML if configured.
    if (-not $usedFallback) {
      $apiKey = $env:ACS_WHOISXML_API_KEY
      if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
        try {
          $raw = Invoke-WhoisXmlLookup -Domain $d
          $source = 'WhoisXML'
          $w = $raw.WhoisRecord

          if ($w) {
            $creation = ConvertTo-NullableUtcIso8601 $w.createdDate
            if (-not $creation) { $creation = ConvertTo-NullableUtcIso8601 $w.registryData.createdDate }

            $expiry = ConvertTo-NullableUtcIso8601 $w.expiresDate
            if (-not $expiry) { $expiry = ConvertTo-NullableUtcIso8601 $w.registryData.expiresDate }

            if ($w.registrarName) { $registrar = [string]$w.registrarName }
            elseif ($w.registrar) { $registrar = [string]$w.registrar }
            elseif ($w.registryData.registrarName) { $registrar = [string]$w.registryData.registrarName }

            if ($w.registrant -and $w.registrant.name) { $registrant = [string]$w.registrant.name }
            elseif ($w.registryData.registrant -and $w.registryData.registrant.name) { $registrant = [string]$w.registryData.registrant.name }
          }
          $usedFallback = $true
        }
        catch {
          $whoisXmlError = $_.Exception.Message
        }
      }
    }

    if (-not $usedFallback) {
      $err = "RDAP lookup failed."
      if ($rdapError) { $err += " RDAP error: $rdapError." }
      if ($goDaddyError) { $err += " GoDaddy error: $goDaddyError." }
      elseif ([string]::IsNullOrWhiteSpace($gdKey) -or [string]::IsNullOrWhiteSpace($gdSecret)) { $err += " GoDaddy not configured." }
      if ($sysWhoisError) { $err += " Sysinternals whois error: $sysWhoisError." }
      if ($linuxWhoisError) { $err += " Linux whois error: $linuxWhoisError." }
      if ($tcpWhoisError) { $err += " TCP whois error: $tcpWhoisError." }
      if ($whoisXmlError) { $err += " WhoisXML error: $whoisXmlError." }
      elseif ([string]::IsNullOrWhiteSpace($apiKey)) { $err += " WhoisXML not configured." }

      $parentDomains = @(Get-ParentDomains -Domain $d)
      foreach ($parentDomain in $parentDomains) {
        $parentStatus = Get-DomainRegistrationStatus -Domain $parentDomain -NewDomainWarnThresholdDays $NewDomainWarnThresholdDays -NewDomainErrorThresholdDays $NewDomainErrorThresholdDays
        if ($parentStatus -and (
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.source) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.creationDateUtc) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.expiryDateUtc) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.registrar) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.registrant) -or
            -not [string]::IsNullOrWhiteSpace([string]$parentStatus.rawWhoisText)
          )) {
          try { $parentStatus.domain = $d } catch { }
          return $parentStatus
        }
      }

      return [pscustomobject]@{
        domain = $d
        lookupDomain = $whoisDomain
        source = $null
        creationDateUtc = $null
        expiryDateUtc = $null
        registrar = $null
        registrant = $null
        ageDays = $null
        ageHuman = $null
        isYoungDomain = $null
        isVeryYoungDomain = $null
        newDomainThresholdDays = $NewDomainWarnThresholdDays
        newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
        newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
        error = $err.Trim()
      }
    }
  }

  $ageDays = Get-DomainAgeDays -CreationDateUtc $creation
  $ageHuman = Format-DomainAge -CreationDateUtc $creation
  $isYoungWarn = if ($null -ne $ageDays) { $ageDays -lt $NewDomainWarnThresholdDays } else { $null }
  $isYoungError = if ($null -ne $ageDays) { $ageDays -lt $NewDomainErrorThresholdDays } else { $null }

  $expiryDays = $null
  $isExpired = $null
  $expiryHuman = $null
  if (-not [string]::IsNullOrWhiteSpace($expiry)) {
    $dtoExpiry = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($expiry, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dtoExpiry)) {
      $expiryDays = [int][Math]::Floor(($dtoExpiry.ToUniversalTime() - [DateTimeOffset]::UtcNow).TotalDays)
      $isExpired = ($expiryDays -le 0)
      $expiryHuman = Format-ExpiryRemaining -ExpiryDateUtc $expiry
    }
  }

  # If we obtained a source (success from any provider), suppress earlier fallback errors to avoid misleading UI.
  if ($source) {
    $rdapError = $null
    $goDaddyError = $null
    $sysWhoisError = $null
    $tcpWhoisError = $null
    $whoisXmlError = $null
  }

  if ($sysWhoisError -and -not $whoisError) { $whoisError = $sysWhoisError }
  if ($linuxWhoisError -and -not $whoisError) { $whoisError = $linuxWhoisError }
  if ($tcpWhoisError -and -not $whoisError) { $whoisError = $tcpWhoisError }
  if ($goDaddyError -and -not $whoisError) { $whoisError = $goDaddyError }
  if ($whoisXmlError -and -not $whoisError) { $whoisError = $whoisXmlError }
  if ($rdapError -and -not $whoisError) { $whoisError = $rdapError }

  [pscustomobject]@{
    domain = $d
    lookupDomain = $whoisDomain
    source = $source
    creationDateUtc = $creation
    expiryDateUtc = $expiry
    registrar = $registrar
    registrant = $registrant
    ageDays = $ageDays
    ageHuman = $ageHuman
    isYoungDomain = $isYoungWarn
    isVeryYoungDomain = $isYoungError
    expiryDays = $expiryDays
    isExpired = $isExpired
    expiryHuman = $expiryHuman
    newDomainThresholdDays = $NewDomainWarnThresholdDays
    newDomainWarnThresholdDays = $NewDomainWarnThresholdDays
    newDomainErrorThresholdDays = $NewDomainErrorThresholdDays
    rawWhoisText = $rawWhoisText
    error = $whoisError
  }
}

if (-not [string]::IsNullOrWhiteSpace($DohEndpoint)) {
  $env:ACS_DNS_DOH_ENDPOINT = $DohEndpoint
}

# ------------------- WEB SERVER STARTUP -------------------
