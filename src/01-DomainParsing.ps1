# ===== Domain Parsing Utilities =====
# ------------------- DOMAIN PARSING UTILITIES -------------------
# Heuristic: derive a registrable ("pay-level") domain from an arbitrary subdomain.
# Uses a small hardcoded subset of the Public Suffix List (PSL) to handle common
# two-level TLDs like co.uk, com.au, etc.  Falls back to the last two labels.
function Get-RegistrableDomain {
  param([string]$Domain)

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  $d = ([string]$Domain).Trim().Trim('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $d.ToLowerInvariant() }

  $tld = $labels[$labels.Count - 1].ToLowerInvariant()
  $sld = $labels[$labels.Count - 2].ToLowerInvariant()
  $last3 = if ($labels.Count -ge 3) { ($labels[$labels.Count - 3] + '.' + $sld + '.' + $tld).ToLowerInvariant() } else { $null }

  $threeLabelZones = @(
    'co.uk','org.uk','ac.uk','gov.uk',
    'co.jp','or.jp','ne.jp',
    'com.au','net.au','org.au',
    'com.nz','net.nz','org.nz','gov.nz','ac.nz',
    'com.br','net.br','org.br',
    'com.mx',
    'com.sg','net.sg','org.sg',
    'com.tr','net.tr','org.tr',
    'com.hk','net.hk','org.hk'
  )

  if ($last3 -and $threeLabelZones -contains ($sld + '.' + $tld)) {
    return ($labels[($labels.Count - 3)..($labels.Count - 1)] -join '.').ToLowerInvariant()
  }

  # Default: use last two labels (e.g., example.com)
  return ($labels[($labels.Count - 2)..($labels.Count - 1)] -join '.').ToLowerInvariant()
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
