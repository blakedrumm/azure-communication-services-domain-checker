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
