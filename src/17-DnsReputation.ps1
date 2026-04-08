# ===== DNSBL / Reputation Checking =====
function ConvertTo-ReversedIpv4 {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IPv4
  )

  $ipText = $IPv4.Trim()
  if ([string]::IsNullOrWhiteSpace($ipText)) { return $null }

  $ipObj = $null
  if (-not [System.Net.IPAddress]::TryParse($ipText, [ref]$ipObj)) { return $null }
  if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }

  $bytes = $ipObj.GetAddressBytes()
  [array]::Reverse($bytes)
  return ($bytes | ForEach-Object { $_.ToString() }) -join '.'
}

# In-memory DNSBL cache (per runspace). Short TTL to avoid stale reputation while reducing repeated queries.
if (-not $script:RblCacheTtlSec) { $script:RblCacheTtlSec = 180 }
if (-not $script:RblCache) {
  $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}

function Get-RblCacheEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [int]$TtlSec = 180
  )

  $entry = $null
  if (-not $script:RblCache.TryGetValue($Key, [ref]$entry)) { return $null }
  $age = [DateTime]::UtcNow - $entry.cachedAt
  if ($age.TotalSeconds -gt $TtlSec) {
    $null = $script:RblCache.TryRemove($Key, [ref]$null)
    return $null
  }
  return $entry.value
}

function Set-RblCacheEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [Parameter(Mandatory = $true)][object]$Value
  )

  if (-not $script:RblCache) {
    $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }

  $script:RblCache[$Key] = [pscustomobject]@{
    cachedAt = [DateTime]::UtcNow
    value    = $Value
  }
}

function Clear-ExpiredRblCacheEntries {
  param(
    [int]$TtlSec = 180,
    [int]$MaxRemovalsPerPass = 256
  )

  if (-not $script:RblCache -or $script:RblCache.Count -eq 0) { return 0 }
  if ($TtlSec -le 0) { $TtlSec = 180 }
  if ($MaxRemovalsPerPass -le 0) { $MaxRemovalsPerPass = 1 }

  $cutoff = [DateTime]::UtcNow.AddSeconds(-1 * $TtlSec)
  $removed = 0

  foreach ($entry in @($script:RblCache.GetEnumerator())) {
    if ($removed -ge $MaxRemovalsPerPass) { break }

    $shouldRemove = $false
    if ($null -eq $entry.Value) {
      $shouldRemove = $true
    } else {
      try {
        $cachedAt = $entry.Value.cachedAt
        if ($null -eq $cachedAt -or $cachedAt -lt $cutoff) {
          $shouldRemove = $true
        }
      } catch {
        $shouldRemove = $true
      }
    }

    if ($shouldRemove) {
      $removedEntry = $null
      if ($script:RblCache.TryRemove($entry.Key, [ref]$removedEntry)) {
        $removed++
      }
    }
  }

  return $removed
}

# Query a single IPv4 address against a single DNSBL zone.
# Returns a result object indicating whether the IP is listed, along with the response address.
function Invoke-RblLookup {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IPv4,
    [Parameter(Mandatory = $true)]
    [string]$Zone
  )

  $rev = ConvertTo-ReversedIpv4 -IPv4 $IPv4
  if ([string]::IsNullOrWhiteSpace($rev)) {
    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $false
      response = $null
      listedAddress = $null
      error = "Invalid IPv4 address"
    }
  }

  $query = "$rev.$Zone".TrimEnd('.')

  try {
    $a = ResolveSafely $query 'A'
    if (-not $a) {
      return [pscustomobject]@{
        ip = $IPv4
        queriedZone = $Zone
        listed = $false
        response = $query
        listedAddress = $null
        error = $null
      }
    }

    $ips = @($a | Get-DnsIpString)
    $listedAddr = if ($ips.Count -gt 0) { $ips[0] } else { $null }

    # Some DNSBLs (including optional user-supplied zones) return policy-block addresses
    # (e.g., 127.255.255.240-255) when queries are blocked via public resolvers or without auth.
    # Treat those as errors, not listings.
    $isPolicyBlock = $false
    if (-not [string]::IsNullOrWhiteSpace($listedAddr)) {
      if ($listedAddr -match '^127\.255\.255\.(24[0-9]|25[0-5])$') {
        $isPolicyBlock = $true
      }
    }

    if ($isPolicyBlock) {
      return [pscustomobject]@{
        ip = $IPv4
        queriedZone = $Zone
        listed = $false
        response = $query
        listedAddress = $listedAddr
        error = 'DNSBL query returned policy-block response (try an authenticated resolver)'
      }
    }

    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $true
      response = $query
      listedAddress = $listedAddr
      error = $null
    }
  }
  catch {
    return [pscustomobject]@{
      ip = $IPv4
      queriedZone = $Zone
      listed = $false
      response = $query
      listedAddress = $null
      error = $_.Exception.Message
    }
  }
}

# Perform DNSBL reputation checks for a domain by:
#   1. Resolving MX hosts (or A records as fallback) to get IPv4 addresses.
#   2. Querying each IP against each DNSBL zone (parallelized where possible).
#   3. Caching results with a short TTL to avoid repeated queries.
# Returns a summary with listed/clean/error counts and a risk assessment.
function Get-DnsReputationStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string[]]$RblZones,
    [int]$MaxTargets = 5
  )

  # Safer free/no-budget default DNSBL zones.
  $defaultZones = @(
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'psbl.surriel.com',
    'dnsbl.dronebl.org',
    'bl.0spam.org',
    'rbl.0spam.org'
  )

  $envZones = @()
  if ([string]::IsNullOrWhiteSpace(($RblZones -join ''))) {
    $envZoneText = [string]$env:ACS_RBL_ZONES
    if (-not [string]::IsNullOrWhiteSpace($envZoneText)) {
      $envZones = @($envZoneText -split '[,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
  }

  $zones = if ($RblZones -and $RblZones.Count -gt 0) { @($RblZones) } elseif ($envZones -and $envZones.Count -gt 0) { @($envZones) } else { $defaultZones }
  $zones = @($zones | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
  if (-not $zones -or $zones.Count -eq 0) {
    $zones = @($defaultZones)
  }

  $lookupDomain = $Domain
  $usedParent = $false

  function Get-IPv4FromHost {
    param([string]$HostName)

    $ips = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($HostName)) { return @() }

    $name = $HostName.Trim().TrimEnd('.')

    $aRecs = ResolveSafely $name 'A'
    if ($aRecs) { $ips.AddRange([string[]](@($aRecs | Get-DnsIpString))) }

    if ($ips.Count -eq 0) {
      $cnameTarget = Get-CnameTargetFromRecords (ResolveSafely $name 'CNAME')
      if (-not [string]::IsNullOrWhiteSpace($cnameTarget)) {
        $aRecs2 = ResolveSafely $cnameTarget 'A'
        if ($aRecs2) { $ips.AddRange([string[]](@($aRecs2 | Get-DnsIpString))) }
      }
    }

    return @($ips | Where-Object { $_ -and ($_ -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') } | Select-Object -Unique)
  }

  if (-not $script:RblCacheTtlSec -or $script:RblCacheTtlSec -le 0) { $script:RblCacheTtlSec = 180 }
  if (-not $script:RblCache) {
    $script:RblCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }
  $null = Clear-ExpiredRblCacheEntries -TtlSec $script:RblCacheTtlSec

  $targets = @()
  $ipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Prefer MX hosts, otherwise fall back to A on the root domain.
  $mx = @(Get-MxRecordObjects -Records (ResolveSafely $Domain 'MX'))
  $hosts = @()
  if ($mx) {
    $hosts = @($mx | Sort-Object Preference, NameExchange | Select-Object -First $MaxTargets -ExpandProperty NameExchange)
  }
  if (-not $hosts -or $hosts.Count -eq 0) {
    $hosts = @($Domain)
  }

  foreach ($h in $hosts) {
    $hostName = ([string]$h).Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($hostName)) { continue }

    $v4 = Get-IPv4FromHost -HostName $hostName
    foreach ($ip in $v4) { $null = $ipSet.Add($ip) }

    $targets += [pscustomobject]@{
      hostname = $hostName
      ipAddresses = $v4
    }
  }

  if ($ipSet.Count -eq 0) {
    foreach ($parentDomain in @(Get-ParentDomains -Domain $Domain)) {
      if ([string]::IsNullOrWhiteSpace($parentDomain) -or $parentDomain -eq $Domain) { continue }

      $lookupDomain = $parentDomain
      $usedParent = $true
      $parentHosts = @()
      $parentMx = @(Get-MxRecordObjects -Records (ResolveSafely $parentDomain 'MX'))
      if ($parentMx) {
        $parentHosts = @($parentMx | Sort-Object Preference, NameExchange | Select-Object -First $MaxTargets -ExpandProperty NameExchange)
      }
      if (-not $parentHosts -or $parentHosts.Count -eq 0) { $parentHosts = @($parentDomain) }

      foreach ($ph in $parentHosts) {
        $phName = ([string]$ph).Trim().TrimEnd('.')
        if ([string]::IsNullOrWhiteSpace($phName)) { continue }
        $v4p = Get-IPv4FromHost -HostName $phName
        foreach ($ip in $v4p) { $null = $ipSet.Add($ip) }
        $targets += [pscustomobject]@{
          hostname = $phName
          ipAddresses = $v4p
        }
      }

      if ($ipSet.Count -gt 0) { break }
    }
  }

  $ips = @($ipSet)
  $pairs = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($ip in $ips) {
    foreach ($z in $zones) {
      $pairs.Add([pscustomobject]@{ ip = $ip; zone = $z })
    }
  }

  $resultsBag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
  $maxParallel = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount * 2))
  $options = [System.Threading.Tasks.ParallelOptions]::new()
  $options.MaxDegreeOfParallelism = $maxParallel
  $ttl = [int]$script:RblCacheTtlSec

  try {
    [System.Threading.Tasks.Parallel]::ForEach(
      $pairs,
      $options,
      [System.Action[object]]{
        param($pair)
        if ($null -eq $pair) { return }
        $cacheKey = "{0}|{1}" -f $pair.ip, $pair.zone
        $cached = Get-RblCacheEntry -Key $cacheKey -TtlSec $ttl
        if ($cached) { $resultsBag.Add($cached); return }

        $res = Invoke-RblLookup -IPv4 $pair.ip -Zone $pair.zone
        Set-RblCacheEntry -Key $cacheKey -Value $res
        $resultsBag.Add($res)
      }
    )
  }
  catch {
    # Fallback to sequential processing if Parallel.ForEach fails for any reason.
    foreach ($pair in $pairs) {
      if ($null -eq $pair) { continue }
      $cacheKey = "{0}|{1}" -f $pair.ip, $pair.zone
      $cached = Get-RblCacheEntry -Key $cacheKey -TtlSec $ttl
      if ($cached) { $resultsBag.Add($cached); continue }

      $res = Invoke-RblLookup -IPv4 $pair.ip -Zone $pair.zone
      Set-RblCacheEntry -Key $cacheKey -Value $res
      $resultsBag.Add($res)
    }
  }

  $resultsArray = $resultsBag.ToArray()
  $listedCount = @($resultsArray | Where-Object { $_.listed -eq $true }).Count
  $errorCount = @($resultsArray | Where-Object { -not [string]::IsNullOrWhiteSpace($_.error) }).Count
  $totalCount = $resultsArray.Count
  $notListedCount = $totalCount - $listedCount - $errorCount
  $riskSummary = if ($listedCount -ge 2) { 'ElevatedRisk' } elseif ($listedCount -eq 1) { 'Warning' } else { 'Clean' }

  [pscustomobject]@{
    domain = $Domain
    lookupDomain = $lookupDomain
    lookupUsedParent = $usedParent
    generatedAtUtc = ([DateTime]::UtcNow.ToString('o'))
    targets = $targets
    rblZones = $zones
    results = $resultsArray
    summary = [pscustomobject]@{
      totalQueries = $totalCount
      listedCount = $listedCount
      notListedCount = $notListedCount
      errorCount = $errorCount
      riskSummary = $riskSummary
    }
  }
}

