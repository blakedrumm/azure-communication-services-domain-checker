# ===== Input Normalization & Validation =====
function ConvertTo-NormalizedDomain {
  param([string]$Raw)

  # Normalize user input into a plain domain name:
  # - accepts: domain, email address, or URL
  # - strips: wildcard prefix and surrounding dots
  # - outputs: lowercase domain

  $domain = if ($null -eq $Raw) { "" } else { [string]$Raw }
  $domain = $domain.Trim()
  if ([string]::IsNullOrWhiteSpace($domain)) { return "" }

  # If user provided an email address, take everything after the last '@'
  $at = $domain.LastIndexOf("@")
  if ($at -ge 0 -and $at -lt ($domain.Length - 1)) {
    $domain = $domain.Substring($at + 1)
  }

  # If user provided a URL, extract hostname
  if ($domain -match '^(?i)https?://') {
    try {
      $domain = ([Uri]$domain).Host
    } catch {
      $null = $_
    }
  }

  # Remove wildcard prefix and surrounding dots/spaces
  $domain = $domain -replace '^\*\.', ''
  $domain = $domain.Trim().Trim('.')

  return $domain.ToLowerInvariant()
}

# Validate that a string looks like a legitimate domain name.
# Rejects obviously invalid input, prevents path/query injection, and enforces RFC label rules.
function Test-DomainName {
  param([string]$Domain)

  # Lightweight validation to avoid:
  # - obviously invalid domains
  # - path/query injection through the query string

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

  $d = $Domain.Trim().ToLowerInvariant()
  if ($d.Length -gt 253) { return $false }
  if ($d -notmatch '^[a-z0-9.-]+$') { return $false }
  if ($d.Contains('..')) { return $false }
  if ($d.StartsWith('-') -or $d.EndsWith('-')) { return $false }

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $false }
  foreach ($label in $labels) {
    if ([string]::IsNullOrWhiteSpace($label)) { return $false }
    if ($label.Length -gt 63) { return $false }
    if ($label.StartsWith('-') -or $label.EndsWith('-')) { return $false }
  }
  return $true
}

# ------------------- SPF ANALYSIS ENGINE -------------------
# Functions to parse, walk, and analyze SPF (Sender Policy Framework) records.
# The engine resolves nested includes and redirects up to 8 levels deep,
# detects SPF macros, counts DNS lookup terms, and checks for the ACS-required
# "include:spf.protection.outlook.com".

# Split an SPF record string into individual whitespace-delimited tokens.
