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

  # IDN to A-label BEFORE lowercasing: IDNA case-folds non-ASCII scripts correctly,
  # which ToLowerInvariant does not. Test-DomainName then validates the FINAL value.
  $domain = ConvertTo-AsciiDomainName -Name $domain

  return $domain.ToLowerInvariant()
}

# Validate that a string looks like a legitimate domain name.
# Rejects obviously invalid input, prevents path/query injection, and enforces RFC label rules.
function Test-DomainName {
  param(
    [string]$Domain,
    # SPF include targets and DKIM selector names legitimately use underscore labels
    # (_spf.example.com, selector1._domainkey); a queried domain never does.
    [switch]$AllowUnderscore
  )

  # Lightweight validation to avoid:
  # - obviously invalid domains
  # - path/query injection through the query string

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

  $d = $Domain.Trim().ToLowerInvariant()
  if ($d.Length -gt 253) { return $false }
  $allowedPattern = if ($AllowUnderscore) { '^[a-z0-9_.-]+$' } else { '^[a-z0-9.-]+$' }
  if ($d -notmatch $allowedPattern) { return $false }
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

# ------------------- OPTIONAL SPF / DKIM REQUIREMENT OVERRIDES -------------------
# The SPF and DKIM checks default to the Azure public cloud values
# (include:spf.protection.outlook.com and the selector1/selector2-azurecomm-prod-net
# CNAMEs). A domain set up in another environment, such as a sovereign or government
# cloud, is given a different SPF include and different DKIM selector records, so a
# caller may pass the values the Azure portal shows for that domain. Every value is
# normalized and validated here before it can reach a DNS query or a verdict. The
# SPA mirrors these rules in 20c-HtmlJsUtilities.ps1 (normalizeSpfIncludeOverride /
# normalizeDkimOverride), so keep the two in sync.

# Normalize an SPF include override. Accepts a bare host name, an "include:<host>"
# term, or a whole pasted SPF record (the first include term wins). Returns the
# lower-case include host, or $null when the input is unusable.
function ConvertTo-SpfIncludeOverride {
  param([string]$Raw)

  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
  $text = $Raw.Trim().Trim('"').Trim()
  if ($text.Length -eq 0 -or $text.Length -gt 512) { return $null }

  $candidate = $null
  foreach ($token in ($text -split '\s+')) {
    $term = $token.Trim('"') -replace '^[\+\-~\?]', ''
    if ($term -match '^(?i)include:(.+)$') {
      $candidate = $Matches[1]
      break
    }
  }
  if ($null -eq $candidate) {
    # A pasted record without any include term has nothing to require.
    if ($text -match '\s' -or $text -match '^(?i)v=spf1') { return $null }
    $candidate = $text
  }

  $candidate = $candidate.Trim('"').TrimEnd('.').ToLowerInvariant()
  if (-not (Test-DomainName -Domain $candidate -AllowUnderscore)) { return $null }
  return $candidate
}

# Normalize a DKIM selector override. The expected CNAME target (the portal's Value
# column) is required because it is what the check compares against. The selector
# (the Name column) is optional: when omitted it is derived from the target, and a
# pasted fully qualified name is trimmed back to "<selector>._domainkey".
# Returns [pscustomobject]@{ selector; target } or $null when the input is unusable.
function ConvertTo-DkimSelectorOverride {
  param(
    [string]$Selector,
    [string]$Target,
    [string]$Domain
  )

  $cleanTarget = if ($Target) { $Target.Trim().Trim('"').Trim().TrimEnd('.').ToLowerInvariant() } else { '' }
  $cleanSelector = if ($Selector) { $Selector.Trim().Trim('"').Trim().TrimEnd('.').ToLowerInvariant() } else { '' }

  if (-not (Test-DomainName -Domain $cleanTarget -AllowUnderscore)) { return $null }

  if ([string]::IsNullOrWhiteSpace($cleanSelector)) {
    if ($cleanTarget -notmatch '^(.+?\._domainkey)\.') { return $null }
    $cleanSelector = $Matches[1]
  }
  elseif ($cleanSelector -match '^(.+?\._domainkey)(\.|$)') {
    $cleanSelector = $Matches[1]
  }
  else {
    $cleanSelector = "$cleanSelector._domainkey"
  }

  if (-not (Test-DomainName -Domain $cleanSelector -AllowUnderscore)) { return $null }
  if (-not [string]::IsNullOrWhiteSpace($Domain) -and ("$cleanSelector.$Domain").Length -gt 253) { return $null }

  [pscustomobject]@{
    selector = $cleanSelector
    target   = $cleanTarget
  }
}

# Read the optional override parameters (spfInclude, dkim1Selector/dkim1Target,
# dkim2Selector/dkim2Target) from a request query string. An unusable value sets
# `error` instead of being ignored, so a caller never receives a default-requirement
# verdict it believes was checked against its custom value.
function Get-CheckOverridesFromQuery {
  param(
    [object]$QueryString,
    [string]$Domain
  )

  $result = [pscustomobject]@{
    spfInclude = $null
    dkim1      = $null
    dkim2      = $null
    error      = $null
  }
  if ($null -eq $QueryString) { return $result }

  $rawSpfInclude = [string]$QueryString['spfInclude']
  if (-not [string]::IsNullOrWhiteSpace($rawSpfInclude)) {
    $result.spfInclude = ConvertTo-SpfIncludeOverride -Raw $rawSpfInclude
    if (-not $result.spfInclude) {
      $result.error = 'Invalid spfInclude parameter.'
      return $result
    }
  }

  foreach ($slot in 1, 2) {
    $rawSelector = [string]$QueryString["dkim${slot}Selector"]
    $rawTarget = [string]$QueryString["dkim${slot}Target"]
    if ([string]::IsNullOrWhiteSpace($rawSelector) -and [string]::IsNullOrWhiteSpace($rawTarget)) { continue }

    $override = ConvertTo-DkimSelectorOverride -Selector $rawSelector -Target $rawTarget -Domain $Domain
    if (-not $override) {
      $result.error = "Invalid dkim${slot}Selector/dkim${slot}Target parameters."
      return $result
    }
    $result."dkim$slot" = $override
  }

  return $result
}

# ------------------- SPF ANALYSIS ENGINE -------------------
# Functions to parse, walk, and analyze SPF (Sender Policy Framework) records.
# The engine resolves nested includes and redirects up to 8 levels deep,
# detects SPF macros, counts DNS lookup terms, and checks for the ACS-required
# "include:spf.protection.outlook.com".

# Split an SPF record string into individual whitespace-delimited tokens.
