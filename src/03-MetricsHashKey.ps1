# ===== Anonymous Metrics Hash Key & App Version =====
# ------------------- ANONYMOUS METRICS HASH KEY -------------------
# The hash key is used to HMAC-SHA256 domain names before storing them in metrics.
# This ensures no plaintext domain names are ever persisted, only irreversible hashes.
# The key is reused across restarts to keep unique-domain counts consistent.
function Get-PersistedMetricsHashKey {
  param([string]$Path)
  try {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $data = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($data.PSObject.Properties.Match('hashKey').Count -gt 0) {
      $k = [string]$data.hashKey
      if (-not [string]::IsNullOrWhiteSpace($k)) { return $k }
    }
  } catch { }
  return $null
}

$script:MetricsHashKey = $env:ACS_METRICS_HASH_KEY
if ([string]::IsNullOrWhiteSpace($script:MetricsHashKey)) {
  $persistedKey = Get-PersistedMetricsHashKey -Path $AnonymousMetricsFile
  if (-not [string]::IsNullOrWhiteSpace($persistedKey)) {
    $script:MetricsHashKey = $persistedKey
  } else {
    $script:MetricsHashKey = [Guid]::NewGuid().ToString('N')
  }
  $env:ACS_METRICS_HASH_KEY = $script:MetricsHashKey
}
$MetricsHashKey = $script:MetricsHashKey

# Application version (for metrics/reporting)
$script:AppVersion = '2.0.0'
if (-not [string]::IsNullOrWhiteSpace($env:ACS_APP_VERSION)) {
  $script:AppVersion = $env:ACS_APP_VERSION
}

# Acquire a cross-process mutex to protect the metrics JSON file from concurrent writes.
# Tries multiple mutex naming strategies for compatibility across Windows, Linux, and containers.
# Returns the held mutex (caller must release), or $null if acquisition timed out.
function Acquire-MetricsFileMutex {
  param([int]$TimeoutMs = 5000)

  $names = @(
    'Global\\ACSAnonMetricsFileLock',
    'Local\\ACSAnonMetricsFileLock',
    'ACSAnonMetricsFileLock'
  )

  foreach ($n in $names) {
    try {
      $mtx = [System.Threading.Mutex]::new($false, $n)
      if ($mtx.WaitOne($TimeoutMs)) { return $mtx }
    } catch { try { if ($mtx) { $mtx.Dispose() } } catch { } }
  }
  return $null
}

# Capture GoDaddy creds (env) once so they can be passed into handler runspaces.
$script:GoDaddyApiKey = $env:GODADDY_API_KEY
$script:GoDaddyApiSecret = $env:GODADDY_API_SECRET

# Compute an HMAC-SHA256 hash of a domain name using the metrics hash key.
# Returns a Base64 string. This is a one-way hash so the original domain cannot be recovered.
function Get-HashedDomain {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  $d = $Domain.Trim().ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $key = $MetricsHashKey
  if ([string]::IsNullOrWhiteSpace($key)) { $key = $env:ACS_METRICS_HASH_KEY }
  if ([string]::IsNullOrWhiteSpace($key)) { return $null }

  $keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
  $dataBytes = [Text.Encoding]::UTF8.GetBytes($d)
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
  try {
    return [Convert]::ToBase64String($hmac.ComputeHash($dataBytes))
  }
  finally {
    try { $hmac.Dispose() } catch { }
  }
}

# Handle an incoming HTTP request to /api/metrics. Returns the current anonymous metrics snapshot.
function Handle-MetricsRequest {
  param($Context, [bool]$MetricsEnabled)

  $snap = $null
  try { $snap = Get-AnonymousMetricsSnapshot } catch { $snap = $null }
  if ($null -eq $snap) { $snap = @{ enabled = $false } }

  try {
    if ($snap -is [hashtable]) {
      $snap.enabled = $MetricsEnabled
    } else {
      $snap | Add-Member -NotePropertyName enabled -NotePropertyValue $MetricsEnabled -Force
    }
  } catch { }

  try {
    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $Context.Response.Headers['X-ACS-AnonMetrics-Enabled'] = ($(if ($MetricsEnabled) { '1' } else { '0' }))
    }
  } catch { }

  Write-Json -Context $Context -Object $snap
}
if (-not [string]::IsNullOrWhiteSpace($DohEndpoint)) {
  $env:ACS_DNS_DOH_ENDPOINT = $DohEndpoint
}

