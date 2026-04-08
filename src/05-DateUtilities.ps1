# ===== Date / Age Formatting Utilities =====
function ConvertTo-NullableUtcIso8601 {
  param([object]$Value)

  if ($null -eq $Value) { return $null }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  # Normalize common timezone abbreviations that DateTime parsing often fails on (e.g., CLST/CLT from Sysinternals whois).
  $normalized = $s.Trim()
  $tzMap = @{
    'CLST' = '-03:00'  # Chile Summer Time (UTC-3)
    'CLT'  = '-04:00'  # Chile Standard Time (UTC-4)
  }
  foreach ($kv in $tzMap.GetEnumerator()) {
    $abbr = [regex]::Escape($kv.Key)
    if ([regex]::IsMatch($normalized, "(?i)\b$abbr\b")) {
      $normalized = [regex]::Replace($normalized, "(?i)\b$abbr\b", " $($kv.Value)")
      $normalized = $normalized.Trim()
      break
    }
  }
  $s = $normalized

  $dt = [DateTimeOffset]::MinValue
  if ([DateTimeOffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
    return $dt.UtcDateTime.ToString('o')
  }

  $dt2 = [DateTime]::MinValue
  if ([DateTime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt2)) {
    return ([DateTime]::SpecifyKind($dt2, [DateTimeKind]::Utc)).ToString('o')
  }

  # Explicit format fallbacks (helps strings like "yyyy-MM-dd HH:mm:ss -03:00" that sometimes fail generic parsing).
  $patterns = @(
    'yyyy-MM-dd HH:mm:ss zzz',
    'yyyy-MM-dd HH:mm:sszzz',
    'yyyy-MM-dd HH:mm:ssK'
  )
  foreach ($fmt in $patterns) {
    if ([DateTimeOffset]::TryParseExact($s, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
      return $dt.UtcDateTime.ToString('o')
    }
  }

  return $null
}

# Calculate the age of a domain in whole days from its creation date to now.
function Get-DomainAgeDays {
  param([string]$CreationDateUtc)

  if ([string]::IsNullOrWhiteSpace($CreationDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($CreationDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }
  $age = [DateTimeOffset]::UtcNow - $dto.ToUniversalTime()
  return [int][Math]::Floor($age.TotalDays)
}

# ------------------- SERVER STARTUP HELPERS -------------------
# Probe a local URL to check if something is already listening (used during startup
# to give a more helpful error message if the port is occupied).
function Test-LocalHttpEndpoint {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [int]$TimeoutSec = 3
  )

  try {
    $previousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
      $resp = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
    }
    finally {
      $ProgressPreference = $previousProgressPreference
    }
    return [pscustomobject]@{
      reachable = $true
      statusCode = [int]$resp.StatusCode
      statusDescription = [string]$resp.StatusDescription
      content = [string]$resp.Content
      error = $null
    }
  }
  catch {
    $webResp = $null
    try { $webResp = $_.Exception.Response } catch { $webResp = $null }

    if ($webResp) {
      $statusCode = $null
      $statusDescription = $null
      $content = $null
      try { $statusCode = [int]$webResp.StatusCode } catch { $statusCode = $null }
      try { $statusDescription = [string]$webResp.StatusDescription } catch { $statusDescription = $null }
      try {
        $stream = $webResp.GetResponseStream()
        if ($stream) {
          $reader = [System.IO.StreamReader]::new($stream)
          try { $content = $reader.ReadToEnd() } finally { try { $reader.Dispose() } catch { } }
        }
      } catch { $content = $null }

      return [pscustomobject]@{
        reachable = $true
        statusCode = $statusCode
        statusDescription = $statusDescription
        content = $content
        error = $null
      }
    }

    return [pscustomobject]@{
      reachable = $false
      statusCode = $null
      statusDescription = $null
      content = $null
      error = $_.Exception.Message
    }
  }
}

# Build a user-friendly error message when the HTTP listener fails to start.
# Probes the port to determine whether another ACS instance, a different service,
# or a permission issue is the cause.
function Get-ListenerStartupErrorMessage {
  param(
    [Parameter(Mandatory = $true)]
    [int]$Port,

    [string]$DisplayUrl,

    [string]$BindMode,

    [string]$AttemptedPrefix,

    [string]$AttemptedAddress,

    [string]$FailureMessage
  )

  $baseUrl = if ([string]::IsNullOrWhiteSpace($DisplayUrl)) { "http://localhost:$Port" } else { $DisplayUrl.TrimEnd('/') }
  $probe = $null
  try { $probe = Test-LocalHttpEndpoint -Url "$baseUrl/" -TimeoutSec 2 } catch { $probe = $null }

  if ($probe -and $probe.reachable) {
    $looksLikeChecker = $false
    if (-not [string]::IsNullOrWhiteSpace([string]$probe.content)) {
      if ($probe.content -match 'ACS Email Domain Checker|Azure Communication Services\s*-\s*Email Domain Checker') {
        $looksLikeChecker = $true
      }
    }

    if ($looksLikeChecker) {
      return "An ACS Email Domain Checker instance appears to already be running on port $Port at $baseUrl/. Reuse that instance, stop the existing process, or start this script with a different -Port value."
    }

    $statusPart = if ($null -ne $probe.statusCode) { " HTTP $($probe.statusCode)" } else { '' }
    return "Port $Port is already in use by another HTTP service at $baseUrl/.$statusPart Stop the process using that port or start this script with a different -Port value."
  }

  $attemptTarget = if (-not [string]::IsNullOrWhiteSpace($AttemptedPrefix)) { $AttemptedPrefix }
    elseif (-not [string]::IsNullOrWhiteSpace($AttemptedAddress)) { "$AttemptedAddress`:$Port" }
    else { "port $Port" }

  $reason = if ([string]::IsNullOrWhiteSpace($FailureMessage)) { 'The listener could not be started.' } else { $FailureMessage.Trim() }
  return "Could not start the local web server on $attemptTarget. $reason Try a different -Port or adjust -Bind ($BindMode)."
}

# Break domain age into years, months, and days for human-friendly display.
function Get-DomainAgeParts {
  param([string]$CreationDateUtc)

  if ([string]::IsNullOrWhiteSpace($CreationDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($CreationDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }

  $start = $dto.UtcDateTime.Date
  $now   = [DateTime]::UtcNow.Date
  if ($now -lt $start) { return $null }

  $years = $now.Year - $start.Year
  if ($now -lt $start.AddYears($years)) { $years-- }

  $months = $now.Month - $start.Month
  if ($now.Day -lt $start.Day) { $months-- }
  if ($months -lt 0) { $months += 12 }

  $days = ($now - $start.AddYears($years).AddMonths($months)).Days
  if ($days -lt 0) { $days = 0 }

  [pscustomobject]@{ years = $years; months = $months; days = $days }
}

# Format domain age as a human-readable string like "2 years, 3 months, 15 days".
function Format-DomainAge {
  param([string]$CreationDateUtc)

  $parts = Get-DomainAgeParts -CreationDateUtc $CreationDateUtc
  if (-not $parts) { return $null }

  $segments = New-Object System.Collections.Generic.List[string]
  if ($parts.years -gt 0)   { $segments.Add(('{0} year{1}'   -f $parts.years,  $(if ($parts.years  -eq 1) { '' } else { 's' }))) }
  if ($parts.months -gt 0)  { $segments.Add(('{0} month{1}'  -f $parts.months, $(if ($parts.months -eq 1) { '' } else { 's' }))) }
  if ($parts.days -gt 0 -or $segments.Count -eq 0) { $segments.Add(('{0} day{1}' -f $parts.days,   $(if ($parts.days   -eq 1) { '' } else { 's' }))) }

  return ($segments -join ', ')
}

# Break time until domain expiry into years, months, and days.
function Get-TimeUntilParts {
  param([string]$ExpiryDateUtc)

  if ([string]::IsNullOrWhiteSpace($ExpiryDateUtc)) { return $null }

  $dto = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($ExpiryDateUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $null }

  $start = [DateTime]::UtcNow.Date
  $end   = $dto.UtcDateTime.Date
  if ($end -le $start) { return $null }

  $years = $end.Year - $start.Year
  if ($end -lt $start.AddYears($years)) { $years-- }

  $months = $end.Month - $start.Month
  if ($end.Day -lt $start.Day) { $months-- }
  if ($months -lt 0) { $months += 12 }

  $days = ($end - $start.AddYears($years).AddMonths($months)).Days
  if ($days -lt 0) { $days = 0 }

  [pscustomobject]@{ years = $years; months = $months; days = $days }
}

# Format time until expiry as a human-readable string, or return "Expired" if past due.
function Format-ExpiryRemaining {
  param([string]$ExpiryDateUtc)

  if ([string]::IsNullOrWhiteSpace($ExpiryDateUtc)) { return $null }

  $parts = Get-TimeUntilParts -ExpiryDateUtc $ExpiryDateUtc
  if (-not $parts) { return 'Expired' }

  $segments = New-Object System.Collections.Generic.List[string]
  if ($parts.years -gt 0)   { $segments.Add(('{0} year{1}'   -f $parts.years,  $(if ($parts.years  -eq 1) { '' } else { 's' }))) }
  if ($parts.months -gt 0)  { $segments.Add(('{0} month{1}'  -f $parts.months, $(if ($parts.months -eq 1) { '' } else { 's' }))) }
  if ($parts.days -gt 0 -or $segments.Count -eq 0) { $segments.Add(('{0} day{1}' -f $parts.days,   $(if ($parts.days   -eq 1) { '' } else { 's' }))) }

  return ($segments -join ', ')
}

# ------------------- DMARC / SPF SECURITY GUIDANCE -------------------
# Analyze a DMARC record and produce human-readable security recommendations.
# Checks for weak policies (p=none), low pct values, relaxed alignment, missing
# aggregate/forensic reporting, and missing subdomain policies.
