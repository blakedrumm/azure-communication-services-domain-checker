# ===== Anonymous Metrics (In-Memory & Persistence) =====

# ------------------- ANONYMOUS METRICS (IN-MEMORY) -------------------
# Metrics are kept in-memory for this process lifetime only.
# No PII: do not store IP addresses, user agents, domains, or request query strings/headers.

# Domain-centric counters (no domain names persisted)
$AcsMetrics = @{
  startedAtUtc        = ([DateTime]::UtcNow.ToString('o'))
  totalDomains        = [ref][int64]0      # Session count of domain lookups (one per lookup)
  totalUniqueDomains  = [ref][int64]0      # Session unique domains (in-memory only)
  uniqueDomains       = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  lifetimeUniqueHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  activeLookups       = [ref][int64]0      # In-flight domain lookups (session only)
  sessions            = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Microsoft employee ID hashes (no PII, only HMAC-SHA256 hashes)
  msEmployeeIdHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
  lifetimeMsEmployeeIdHashes = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Auth counters (no PII; counts only)
  totalMsAuthVerifications = [ref][int64]0

  # Persisted, lifetime counters (no domain names stored)
  lifetimeFirstSeenUtc   = $null
  lifetimeTotalDomains   = [ref][int64]0
  lifetimeUniqueDomains  = [ref][int64]0
  lifetimeTotalUptimeBase = [int64]0

  lifetimeMsAuthVerifications = [ref][int64]0

  _lastPersistUtc        = $null
  _lastPersistDomains    = [ref][int64]0
}

# Monotonic uptime tracker (avoids skew from persisted timestamps or clock changes).
$AcsUptime = [System.Diagnostics.Stopwatch]::StartNew()

$AcsMetricsPersistLock = [object]::new()

# CRITICAL: Store these in global scope so they can be referenced when creating InitialSessionState
$global:AcsMetrics = $AcsMetrics
$global:AcsMetricsPersistLock = $AcsMetricsPersistLock
$global:AcsUptime = $AcsUptime

$AcsRateLimitStore = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$AcsRateLimitLock = [object]::new()
$global:AcsRateLimitStore = $AcsRateLimitStore
$global:AcsRateLimitLock = $AcsRateLimitLock

function Get-AnonymousMetricsPersistPath {
  $p = $env:ACS_ANON_METRICS_FILE
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  return $p
}

# SECURITY: Restrict the metrics persistence file to the current user only.
# The file contains the persistent HMAC `hashKey` used to compute hashed
# domain values; anyone with read access can use it to recompute the same
# hashes for any domain they choose, which would let them unmask values
# stored in the metrics file. This best-effort tightening covers Linux
# (chmod 600) and Windows (NTFS DACL limited to the current user); it is
# wrapped in try/catch so persistence still succeeds on file systems where
# the operation is unsupported (for example FAT32 or some container
# bind-mounted volumes).
function Set-AnonymousMetricsFilePermissions {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }

  try {
    $isWindowsHost = $true
    try {
      # `$IsWindows` only exists in PowerShell 7+. On Windows PowerShell 5.1
      # (Desktop edition) we default to true; otherwise probe the variable.
      if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) {
        $isWindowsHost = [bool]$IsWindows
      } elseif ($PSVersionTable.PSEdition -eq 'Desktop') {
        $isWindowsHost = $true
      }
    } catch { $isWindowsHost = $true }

    if ($isWindowsHost) {
      # Build the new restrictive DACL on a snapshot of the current ACL so we
      # never partially mutate the live SecurityDescriptor that Set-Acl will
      # commit. If anything throws while constructing or applying the ACL we
      # fall back to leaving the inherited ACL in place rather than wiping
      # all access; the persisted file is then no less protected than any
      # other file the process writes.
      try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existing in @($acl.Access)) {
          try { $null = $acl.RemoveAccessRule($existing) } catch { }
        }
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $currentUser,
          [System.Security.AccessControl.FileSystemRights]::FullControl,
          [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        # Verify the rebuilt ACL grants at least one explicit ACE for the
        # current user before applying. If somehow the rule list is empty we
        # skip the Set-Acl call entirely so the file does not end up with
        # zero ACEs (which would lock the metrics writer out of its own file).
        $hasOwnerRule = $false
        foreach ($r in @($acl.Access)) {
          if ($r.IdentityReference.Value -eq $currentUser) { $hasOwnerRule = $true; break }
        }
        if ($hasOwnerRule) {
          Set-Acl -LiteralPath $Path -AclObject $acl
        }
      } catch {
        # Best-effort: if ACL rebuild fails we leave the inherited ACL intact.
      }
    } else {
      try {
        $chmod = Get-Command -Name chmod -ErrorAction SilentlyContinue
        if ($chmod) {
          & $chmod.Source 600 -- $Path 2>$null
        }
      } catch { }
    }
  } catch { }
}

# Normalize a value (possibly [DateTime] from ConvertFrom-Json) to ISO 8601 round-trip string.
function ConvertTo-Iso8601Utc {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [DateTime]) {
    return $Value.ToUniversalTime().ToString('o')
  }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $dt = [DateTime]::MinValue
  if ([DateTime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
    return $dt.ToUniversalTime().ToString('o')
  }
  return $s
}

# Load previously persisted anonymous metrics from the JSON file on disk.
# Restores lifetime counters, the hash key, and unique domain hash sets so that
# metrics survive process restarts.
function Load-AnonymousMetricsPersisted {
  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  $path = Get-AnonymousMetricsPersistPath
  if ([string]::IsNullOrWhiteSpace($path)) { return }

  $mtx = Acquire-MetricsFileMutex
  if (-not $mtx) { return }

  $nowUtc = [DateTime]::UtcNow.ToString('o')

  try {
    if (-not (Test-Path -LiteralPath $path)) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
      return
    }

    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
      return
    }

    $data = $raw | ConvertFrom-Json -ErrorAction Stop

    $script:AcsMetrics['lifetimeFirstSeenUtc'] = ConvertTo-Iso8601Utc $data.firstSeenUtc
    if ([string]::IsNullOrWhiteSpace($script:AcsMetrics['lifetimeFirstSeenUtc'])) {
      $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
    }

    # If no env hash key was provided, reuse persisted hashKey for stable unique-domain counting across restarts.
    if ([string]::IsNullOrWhiteSpace($script:MetricsHashKey) -and $data.PSObject.Properties.Match('hashKey').Count -gt 0) {
      $k = [string]$data.hashKey
      if (-not [string]::IsNullOrWhiteSpace($k)) {
        $script:MetricsHashKey = $k
        $env:ACS_METRICS_HASH_KEY = $k
        $MetricsHashKey = $k
      }
    }

    # Backward compatibility: schemaVersion 1 used lifetimeTotalRequests
    $td = [int64]0
    $tud = [int64]0
    $ttu = [int64]0
    $tma = [int64]0
    try {
      if ($data.PSObject.Properties.Match('lifetimeTotalDomains').Count -gt 0) {
        $td = [int64]$data.lifetimeTotalDomains
      } elseif ($data.PSObject.Properties.Match('lifetimeTotalRequests').Count -gt 0) {
        $td = [int64]$data.lifetimeTotalRequests
      }

      if ($data.PSObject.Properties.Match('lifetimeUniqueDomains').Count -gt 0) {
        $tud = [int64]$data.lifetimeUniqueDomains
      } elseif ($td -gt 0) {
        # Best-effort: if no unique field, assume all were unique historically.
        $tud = $td
      }

      if ($data.PSObject.Properties.Match('lifetimeTotalUptimeSeconds').Count -gt 0) {
        $ttu = [int64]$data.lifetimeTotalUptimeSeconds
      } elseif ($data.PSObject.Properties.Match('lifetimeTotalUptime').Count -gt 0) {
        # Backward compat (older field name)
        $ttu = [int64]$data.lifetimeTotalUptime
      }

      if ($data.PSObject.Properties.Match('lifetimeMsAuthVerifications').Count -gt 0) {
        $tma = [int64]$data.lifetimeMsAuthVerifications
      }
    } catch { $td = 0; $tud = 0 }
    $script:AcsMetrics['lifetimeTotalDomains'].Value = $td
    $script:AcsMetrics['lifetimeTotalUptimeBase'] = $ttu
    $script:AcsMetrics['lifetimeMsAuthVerifications'].Value = $tma

    # Restore lifetime unique hash set (hashed domains only; no plaintext stored).
    try {
      $hashes = @()
      if ($data.PSObject.Properties.Match('lifetimeUniqueHashes').Count -gt 0) {
        $hashes = @($data.lifetimeUniqueHashes)
      }
      if (-not $hashes -or $hashes.Count -eq 0) {
        # Backward compatibility: if not present, fall back to count only.
        $script:AcsMetrics['lifetimeUniqueDomains'].Value = $tud
      } else {
        foreach ($h in $hashes) {
          $s = [string]$h
          if ([string]::IsNullOrWhiteSpace($s)) { continue }
          $null = $script:AcsMetrics['lifetimeUniqueHashes'].TryAdd($s, 0)
        }
        $script:AcsMetrics['lifetimeUniqueDomains'].Value = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count
      }
    } catch {
      $script:AcsMetrics['lifetimeUniqueDomains'].Value = $tud
    }

    # Restore lifetime Microsoft employee verification hash set.
    try {
      if ($data.PSObject.Properties.Match('lifetimeMsEmployeeIdHashes').Count -gt 0 -and $data.lifetimeMsEmployeeIdHashes) {
        foreach ($h in @($data.lifetimeMsEmployeeIdHashes)) {
          $s = [string]$h
          if ([string]::IsNullOrWhiteSpace($s)) { continue }
          $null = $script:AcsMetrics['lifetimeMsEmployeeIdHashes'].TryAdd($s, 0)
        }
      }
    } catch { }
  }
  catch {
    # If the file is corrupt/unreadable, start fresh (still no PII persisted).
    $script:AcsMetrics['lifetimeFirstSeenUtc'] = $nowUtc
  }
  finally {
    try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { }
  }

}

# Persist the current anonymous metrics to the JSON file on disk.
# Uses a cross-process mutex to prevent concurrent writers from clobbering data.
# Merges in-memory counters with any values already in the file (max-wins strategy)
# to handle race conditions across restarts or multiple saves.
function Save-AnonymousMetricsPersisted {
  param(
    [switch]$Force
  )

  $enabled = ($env:ACS_ENABLE_ANON_METRICS -eq '1') -or ($true -eq $AcsAnonMetricsEnabled) -or ($script:EnableAnonymousMetrics -eq $true)
  if (-not $enabled) { return }

  $path = Get-AnonymousMetricsPersistPath
  if ([string]::IsNullOrWhiteSpace($path)) { return }

  $mtx = Acquire-MetricsFileMutex
  if (-not $mtx) { return }

  $now = [DateTime]::UtcNow

  # Throttle writes unless forced, but always write when domain count changed.
  try {
    $domainsNow = $script:AcsMetrics['lifetimeTotalDomains'].Value
    if (-not $Force -and $script:AcsMetrics['_lastPersistDomains'].Value -ne $domainsNow) {
      $Force = $true
    }

    if (-not $Force -and $script:AcsMetrics['_lastPersistUtc']) {
      $age = $now - [DateTime]::Parse($script:AcsMetrics['_lastPersistUtc'])
      if ($age.TotalSeconds -lt 5) { return }
    }
  } catch { }

  try {
    [System.Threading.Monitor]::Enter($script:AcsMetricsPersistLock)

    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $existingLifetimeTotalDomains = [int64]0
    $existingLifetimeUniqueDomains = [int64]0
    $existingLifetimeTotalUptimeSeconds = [int64]0
    $existingLifetimeUniqueHashCount = [int64]0
    $existingFirstSeenUtc = $null
    try {
      if (Test-Path -LiteralPath $path) {
        $existingRaw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($existingRaw)) {
          $existingData = $existingRaw | ConvertFrom-Json -ErrorAction Stop
          if ($existingData.PSObject.Properties.Match('firstSeenUtc').Count -gt 0 -and $null -ne $existingData.firstSeenUtc) {
            $existingFirstSeenUtc = ConvertTo-Iso8601Utc $existingData.firstSeenUtc
          }
          if ($existingData.PSObject.Properties.Match('lifetimeTotalDomains').Count -gt 0) {
            $existingLifetimeTotalDomains = [int64]$existingData.lifetimeTotalDomains
          }
          if ($existingData.PSObject.Properties.Match('lifetimeUniqueDomains').Count -gt 0) {
            $existingLifetimeUniqueDomains = [int64]$existingData.lifetimeUniqueDomains
          }
          if ($existingData.PSObject.Properties.Match('lifetimeTotalUptimeSeconds').Count -gt 0) {
            $existingLifetimeTotalUptimeSeconds = [int64]$existingData.lifetimeTotalUptimeSeconds
          } elseif ($existingData.PSObject.Properties.Match('lifetimeTotalUptime').Count -gt 0) {
            $existingLifetimeTotalUptimeSeconds = [int64]$existingData.lifetimeTotalUptime
          }
          if ($existingData.PSObject.Properties.Match('lifetimeUniqueHashes').Count -gt 0 -and $existingData.lifetimeUniqueHashes) {
            foreach ($h in @($existingData.lifetimeUniqueHashes)) {
              $s = [string]$h
              if ([string]::IsNullOrWhiteSpace($s)) { continue }
              $null = $script:AcsMetrics['lifetimeUniqueHashes'].TryAdd($s, 0)
            }
            $existingLifetimeUniqueHashCount = [int64]$script:AcsMetrics['lifetimeUniqueHashes'].Count
          }
        }
      }
    } catch { }

    # Preserve the earliest firstSeenUtc: keep whichever is older between in-memory and on-disk.
    if ($existingFirstSeenUtc) {
      try {
        $existingDt = [DateTimeOffset]::Parse($existingFirstSeenUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        $memoryFirstSeen = $script:AcsMetrics['lifetimeFirstSeenUtc']
        if ([string]::IsNullOrWhiteSpace($memoryFirstSeen)) {
          $script:AcsMetrics['lifetimeFirstSeenUtc'] = $existingFirstSeenUtc
        } else {
          $memoryDt = [DateTimeOffset]::Parse($memoryFirstSeen, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
          if ($existingDt -lt $memoryDt) {
            $script:AcsMetrics['lifetimeFirstSeenUtc'] = $existingFirstSeenUtc
          }
        }
      } catch { }
    }

    $currentUptime = 0
    try {
      if ($AcsUptime) { $currentUptime = [int64][Math]::Floor($AcsUptime.Elapsed.TotalSeconds) }
    } catch { $currentUptime = 0 }

    $mergedLifetimeTotalDomains = [int64]([Math]::Max($script:AcsMetrics['lifetimeTotalDomains'].Value, $existingLifetimeTotalDomains))
    $mergedLifetimeUniqueDomains = [int64]([Math]::Max(
      [Math]::Max($script:AcsMetrics['lifetimeUniqueDomains'].Value, $existingLifetimeUniqueDomains),
      $existingLifetimeUniqueHashCount))
    $currentLifetimeUptime = [int64]($script:AcsMetrics['lifetimeTotalUptimeBase'] + $currentUptime)
    $mergedLifetimeTotalUptimeSeconds = [int64]([Math]::Max($currentLifetimeUptime, $existingLifetimeTotalUptimeSeconds))

    # lifetimeMsEmployeeVerifications is derived from lifetimeMsEmployeeIdHashes.Count, so
    # we do not need to merge per-counter values from the file. We keep only lifetimeMsAuthVerifications
    # for coarse-grained auth usage and rely on the hash set for unique employee counts.
    $existingLifetimeMsAuthVerifications = [int64]0
    try {
      if (Test-Path -LiteralPath $path) {
        $existingRaw2 = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($existingRaw2)) {
          $existingData2 = $existingRaw2 | ConvertFrom-Json -ErrorAction Stop
          if ($existingData2.PSObject.Properties.Match('lifetimeMsAuthVerifications').Count -gt 0) {
            $existingLifetimeMsAuthVerifications = [int64]$existingData2.lifetimeMsAuthVerifications
          }
        }
      }
    } catch { }

    $mergedLifetimeMsAuthVerifications = [int64]([Math]::Max($script:AcsMetrics['lifetimeMsAuthVerifications'].Value, $existingLifetimeMsAuthVerifications))

    if ($mergedLifetimeMsAuthVerifications -gt $script:AcsMetrics['lifetimeMsAuthVerifications'].Value) {
      $script:AcsMetrics['lifetimeMsAuthVerifications'].Value = $mergedLifetimeMsAuthVerifications
    }

    if ($mergedLifetimeTotalDomains -gt $script:AcsMetrics['lifetimeTotalDomains'].Value) {
      $script:AcsMetrics['lifetimeTotalDomains'].Value = $mergedLifetimeTotalDomains
    }
    if ($mergedLifetimeUniqueDomains -gt $script:AcsMetrics['lifetimeUniqueDomains'].Value) {
      $script:AcsMetrics['lifetimeUniqueDomains'].Value = $mergedLifetimeUniqueDomains
    }
    if ($mergedLifetimeTotalUptimeSeconds -gt $currentLifetimeUptime) {
      $script:AcsMetrics['lifetimeTotalUptimeBase'] = [int64]([Math]::Max($script:AcsMetrics['lifetimeTotalUptimeBase'], ($mergedLifetimeTotalUptimeSeconds - $currentUptime)))
    }

    $payload = [pscustomobject]@{
      schemaVersion = 3
      appVersion = $script:AppVersion
      firstSeenUtc = $script:AcsMetrics['lifetimeFirstSeenUtc']
      lastStartedAtUtc = $script:AcsMetrics['startedAtUtc']
      lifetimeTotalDomains = $mergedLifetimeTotalDomains
      lifetimeUniqueDomains = $mergedLifetimeUniqueDomains
      lifetimeUniqueHashes = @($script:AcsMetrics['lifetimeUniqueHashes'].Keys)
      lifetimeTotalUptimeSeconds = $mergedLifetimeTotalUptimeSeconds
      lifetimeMsAuthVerifications = $script:AcsMetrics['lifetimeMsAuthVerifications'].Value
      hashKey = $script:MetricsHashKey
      lifetimeMsEmployeeIdHashes = @($script:AcsMetrics['lifetimeMsEmployeeIdHashes'].Keys)
    }

    $tmp = "$path.tmp"
    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    # SECURITY: tighten file permissions after the rename so the persisted
    # hashKey cannot be read by other local users. Best-effort; failures are
    # swallowed so persistence keeps working on file systems that do not
    # support ACL/chmod operations.
    try { Set-AnonymousMetricsFilePermissions -Path $path } catch { }
    $script:AcsMetrics['_lastPersistUtc'] = $now.ToString('o')
    try { $script:AcsMetrics['_lastPersistDomains'].Value = $script:AcsMetrics['lifetimeTotalDomains'].Value } catch { }
  }
  catch {
    $null = $_
  }
  finally {
    try { $mtx.ReleaseMutex(); $mtx.Dispose() } catch { }
    try { [System.Threading.Monitor]::Exit($script:AcsMetricsPersistLock) } catch { }
  }
}

# ------------------- SESSION & COOKIE HANDLING -------------------
# Generate a random 32-character hex session ID. Used only for metrics counting;
# not derived from any PII.
