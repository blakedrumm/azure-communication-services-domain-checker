# ===== Domain Parsing Utilities =====
# ------------------- DOMAIN PARSING UTILITIES -------------------
# Deriving a registrable ("pay-level") domain from an arbitrary subdomain requires
# the Public Suffix List (PSL) so multi-label zones like co.uk, com.au, co.th, and
# thousands of long-tail country/registry suffixes are handled correctly.
#
# Strategy:
#   1. Prefer a downloaded/cached copy of the official PSL (public_suffix_list.dat).
#      The file is refreshed at build time by Download-UiAssets.ps1 and, optionally,
#      lazily refreshed at runtime when it goes stale (TTL) or is missing.
#   2. If the PSL file is unavailable (offline build, download disabled, parse
#      failure), fall back to a small embedded subset of common multi-label zones
#      so the tool still produces sane results without network access.
#
# The parsed PSL is cached in-process (per runspace) keyed by file path + last
# write time so workers parse it at most once and re-parse only after a refresh.

# In-memory parsed-PSL cache (per runspace). Shape:
#   @{ key = '<path>|<lastWriteTicks>'; exact = HashSet; wildcards = HashSet; exceptions = HashSet }
$script:PublicSuffixCache = $null

# Resolve the on-disk PSL cache path. Worker runspaces read $env:ACS_PSL_FILE
# (set by 00-Header.ps1); standalone/CLI use falls back to a file next to the script.
function Get-PublicSuffixListPath {
  $configured = $env:ACS_PSL_FILE
  if (-not [string]::IsNullOrWhiteSpace($configured)) { return $configured }

  $root = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($root)) { $root = (Get-Location).Path }
  return (Join-Path -Path $root -ChildPath 'public_suffix_list.dat')
}

# Best-effort runtime download of the PSL to the cache path. Controlled by env vars:
#   ACS_PSL_DISABLE_DOWNLOAD=1  -> never download at runtime (offline/locked-down)
#   ACS_PSL_URL                 -> override the source URL
# Returns $true when a usable file exists at $Path afterwards.
function Update-PublicSuffixListFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$TimeoutSec = 15
  )

  if ($env:ACS_PSL_DISABLE_DOWNLOAD -eq '1') { return (Test-Path -LiteralPath $Path -PathType Leaf) }

  $url = $env:ACS_PSL_URL
  if ([string]::IsNullOrWhiteSpace($url)) { $url = 'https://publicsuffix.org/list/public_suffix_list.dat' }

  try {
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
      $null = New-Item -ItemType Directory -Path $dir -Force
    }
    Invoke-WebRequest -Uri $url -OutFile $Path -TimeoutSec $TimeoutSec -Headers @{ 'User-Agent' = 'ACS-DomainChecker/PSL' } -ErrorAction Stop
    return (Test-Path -LiteralPath $Path -PathType Leaf)
  } catch {
    # Network/offline failure: keep any existing file, otherwise signal unavailable.
    return (Test-Path -LiteralPath $Path -PathType Leaf)
  }
}

# Parse a PSL .dat file into rule sets. Only the ICANN section is consulted so the
# registrable domain stays WHOIS-queryable (PRIVATE domains like blogspot.com are
# intentionally skipped). Returns $null when the file is missing or yields no rules.
function ConvertFrom-PublicSuffixListFile {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

  $exact      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $wildcards  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $exceptions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

  try {
    $lines = [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)
  } catch {
    return $null
  }

  foreach ($raw in $lines) {
    $line = ([string]$raw).Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    # Stop at the private-domains section; we only want ICANN suffixes.
    if ($line -match '(?i)===BEGIN PRIVATE DOMAINS===') { break }
    if ($line.StartsWith('//')) { continue }

    # A rule ends at the first whitespace (the PSL format keeps one rule per line).
    $rule = ($line -split '\s+')[0]
    if ([string]::IsNullOrWhiteSpace($rule)) { continue }
    $rule = $rule.ToLowerInvariant()

    if ($rule.StartsWith('!')) {
      # Exception rule: the labels after '!' are NOT a public suffix.
      $null = $exceptions.Add($rule.Substring(1))
    }
    elseif ($rule.StartsWith('*.')) {
      # Wildcard rule: store only the fixed remainder after '*.'.
      $null = $wildcards.Add($rule.Substring(2))
    }
    else {
      $null = $exact.Add($rule)
    }
  }

  if ($exact.Count -eq 0 -and $wildcards.Count -eq 0) { return $null }

  return @{ exact = $exact; wildcards = $wildcards; exceptions = $exceptions }
}

# Load (and lazily refresh) the parsed PSL rule sets, caching in-process. Returns
# $null when no PSL file can be loaded so callers fall back to the embedded list.
function Get-PublicSuffixData {
  $path = Get-PublicSuffixListPath

  # Lazily refresh when missing or stale (TTL via ACS_PSL_MAX_AGE_DAYS, default 30).
  $needsDownload = $false
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    $needsDownload = $true
  } else {
    $maxAgeDays = 30
    if (-not [string]::IsNullOrWhiteSpace($env:ACS_PSL_MAX_AGE_DAYS)) {
      [int]::TryParse($env:ACS_PSL_MAX_AGE_DAYS, [ref]$maxAgeDays) | Out-Null
    }
    try {
      $age = [DateTime]::UtcNow - ([System.IO.File]::GetLastWriteTimeUtc($path))
      if ($age.TotalDays -ge $maxAgeDays) { $needsDownload = $true }
    } catch { $needsDownload = $false }
  }
  if ($needsDownload) { $null = Update-PublicSuffixListFile -Path $path }

  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }

  # Cache keyed by path + last write time so a refresh invalidates the parse.
  $lastWriteTicks = 0
  try { $lastWriteTicks = ([System.IO.File]::GetLastWriteTimeUtc($path)).Ticks } catch { $lastWriteTicks = 0 }
  $cacheKey = '{0}|{1}' -f $path, $lastWriteTicks

  if ($script:PublicSuffixCache -and $script:PublicSuffixCache.key -eq $cacheKey) {
    return $script:PublicSuffixCache
  }

  $parsed = ConvertFrom-PublicSuffixListFile -Path $path
  if (-not $parsed) { return $null }

  $script:PublicSuffixCache = @{
    key        = $cacheKey
    exact      = $parsed.exact
    wildcards  = $parsed.wildcards
    exceptions = $parsed.exceptions
  }
  return $script:PublicSuffixCache
}

# Apply the official PSL matching algorithm (https://publicsuffix.org/list/) to the
# given lowercase labels and return the public suffix as a dotted string.
# $Data is the rule-set hashtable from Get-PublicSuffixData.
function Get-PublicSuffixFromLabels {
  param(
    [Parameter(Mandatory = $true)][string[]]$Labels,
    [Parameter(Mandatory = $true)][hashtable]$Data
  )

  $n = $Labels.Count

  # 1. Exception rules win: the prevailing suffix is the rule minus its leftmost label.
  for ($i = 0; $i -lt $n; $i++) {
    $candidate = ($Labels[$i..($n - 1)] -join '.')
    if ($Data.exceptions.Contains($candidate)) {
      if (($i + 1) -le ($n - 1)) {
        return ($Labels[($i + 1)..($n - 1)] -join '.')
      }
      return $candidate
    }
  }

  # 2. Longest matching normal/wildcard rule wins.
  $bestLen = 0
  for ($i = 0; $i -lt $n; $i++) {
    $candidate = ($Labels[$i..($n - 1)] -join '.')
    $len = $n - $i

    if ($Data.exact.Contains($candidate)) {
      if ($len -gt $bestLen) { $bestLen = $len }
    }

    # Wildcard '*.<rest>' matches when the labels to the right of the wildcard
    # position equal a stored fixed remainder.
    if (($i + 1) -le ($n - 1)) {
      $rest = ($Labels[($i + 1)..($n - 1)] -join '.')
      if ($Data.wildcards.Contains($rest)) {
        if ($len -gt $bestLen) { $bestLen = $len }
      }
    }
  }

  # 3. Default rule '*' => the rightmost label is the public suffix.
  if ($bestLen -eq 0) { $bestLen = 1 }

  return ($Labels[($n - $bestLen)..($n - 1)] -join '.')
}

# Derive a registrable ("pay-level") domain from an arbitrary subdomain using the
# Public Suffix List when available, otherwise the embedded fallback list.
function Get-RegistrableDomain {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  $d = ([string]$Domain).Trim().Trim('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }
  $d = $d.ToLowerInvariant()

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $d }
  $n = $labels.Count

  # --- Preferred path: full PSL ---
  $psl = $null
  try { $psl = Get-PublicSuffixData } catch { $psl = $null }
  if ($psl) {
    $publicSuffix = Get-PublicSuffixFromLabels -Labels $labels -Data $psl
    $psLabelCount = ($publicSuffix.Split('.')).Count
    # Registrable domain = public suffix + exactly one more label.
    if ($n -gt $psLabelCount) {
      return ($labels[($n - $psLabelCount - 1)..($n - 1)] -join '.')
    }
    # The domain is itself a public suffix; return it unchanged.
    return $d
  }

  # --- Fallback path: embedded multi-label suffix list ---
  # Defined inline so it is available inside worker runspaces (only function
  # definitions are copied into the RunspacePool, not top-level script variables).
  $fallbackPublicSuffixes = @(
    'co.uk','org.uk','ac.uk','gov.uk',
    'co.jp','or.jp','ne.jp',
    'com.au','net.au','org.au',
    'com.nz','net.nz','org.nz','gov.nz','ac.nz',
    'com.br','net.br','org.br',
    'com.mx',
    'com.sg','net.sg','org.sg',
    'com.tr','net.tr','org.tr',
    'com.hk','net.hk','org.hk',
    'co.th','or.th','ac.th','go.th','in.th','net.th','mi.th',
    'co.kr','or.kr','ne.kr','re.kr','pe.kr','go.kr','ac.kr',
    'co.id','or.id','ac.id','go.id','web.id','net.id',
    'co.in','net.in','org.in','gen.in','firm.in','ind.in',
    'com.cn','net.cn','org.cn','gov.cn',
    'com.tw','net.tw','org.tw',
    'com.my','net.my','org.my',
    'co.za','org.za','net.za',
    'com.ph','net.ph','org.ph',
    'co.il','org.il','net.il','ac.il'
  )
  $tld = $labels[$n - 1]
  $sld = $labels[$n - 2]
  if ($n -ge 3 -and ($fallbackPublicSuffixes -contains ($sld + '.' + $tld))) {
    return ($labels[($n - 3)..($n - 1)] -join '.')
  }

  # Default: last two labels (e.g., example.com).
  return ($labels[($n - 2)..($n - 1)] -join '.')
}

# Walk up the label hierarchy of a domain and return all parent domains.
# For example, "sub.example.co.uk" returns @("example.co.uk", "co.uk").
# Used for fallback DNS lookups when the exact subdomain has no records.
function Get-ParentDomains {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return @() }

  $d = ([string]$Domain).Trim().Trim('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return @() }

  $labels = $d.Split('.')
  if ($labels.Count -lt 3) { return @() }

  $parents = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -lt ($labels.Count - 1); $i++) {
    $candidate = ($labels[$i..($labels.Count - 1)] -join '.').ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
      $parents.Add($candidate)
    }
  }

  return @($parents | Select-Object -Unique)
}

# ------------------- WHOIS / RDAP LOOKUP PROVIDERS -------------------
# These functions attempt to retrieve domain registration data (creation date, expiry,
# registrar, registrant) from multiple sources. The fallback chain is:
#   1. RDAP (IANA bootstrap) - preferred, structured JSON
#   2. GoDaddy API           - if credentials are configured
#   3. Linux whois CLI       - on Linux platforms
#   4. Sysinternals whois    - on Windows platforms
#   5. Pure TCP whois        - cross-platform fallback (bypasses CLI issues in containers)
#   6. WhoisXML API          - if API key is configured

# Quick check: does the raw whois text contain actual registration data,
# or is it an error/"not found" response from the whois server?
