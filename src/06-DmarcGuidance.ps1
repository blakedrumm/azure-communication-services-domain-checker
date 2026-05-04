# ===== DMARC Security Guidance =====
function Get-DmarcSecurityGuidance {
  param(
    [string]$DmarcRecord,
    [string]$Domain,
    [string]$LookupDomain,
    [bool]$Inherited = $false
  )

  $messages = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($DmarcRecord)) { return @() }

  $recordText = ([string]$DmarcRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($recordText)) { return @() }

  $tagMap = @{}
  foreach ($segment in ($recordText -split ';')) {
    $part = ([string]$segment).Trim()
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $kv = $part -split '=', 2
    if ($kv.Count -ne 2) { continue }
    $name = ([string]$kv[0]).Trim().ToLowerInvariant()
    $value = ([string]$kv[1]).Trim()
    if (-not [string]::IsNullOrWhiteSpace($name)) {
      $tagMap[$name] = $value
    }
  }

  $targetDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } elseif (-not [string]::IsNullOrWhiteSpace($LookupDomain)) { $LookupDomain } else { 'the domain' }

  $policy = $null
  if ($tagMap.ContainsKey('p')) { $policy = ([string]$tagMap['p']).Trim().ToLowerInvariant() }
  $subdomainPolicy = $null
  if ($tagMap.ContainsKey('sp')) { $subdomainPolicy = ([string]$tagMap['sp']).Trim().ToLowerInvariant() }
  $pct = $null
  if ($tagMap.ContainsKey('pct')) {
    $pctValue = 0
    if ([int]::TryParse(([string]$tagMap['pct']).Trim(), [ref]$pctValue)) {
      $pct = $pctValue
    }
  }
  $adkim = if ($tagMap.ContainsKey('adkim')) { ([string]$tagMap['adkim']).Trim().ToLowerInvariant() } else { $null }
  $aspf = if ($tagMap.ContainsKey('aspf')) { ([string]$tagMap['aspf']).Trim().ToLowerInvariant() } else { $null }
  $rua = if ($tagMap.ContainsKey('rua')) { ([string]$tagMap['rua']).Trim() } else { $null }
  $ruf = if ($tagMap.ContainsKey('ruf')) { ([string]$tagMap['ruf']).Trim() } else { $null }

  if ($policy -eq 'none') {
    $messages.Add("DMARC for $targetDomain is monitor-only (`p=none`). For stronger protection against spoofing, move to enforcement with `p=quarantine` or `p=reject` after validating legitimate mail sources.")
    # Bulk-sender callout: monitor-only DMARC provides no enforcement and is
    # treated the same as "no DMARC" by major mailbox providers (Google, Yahoo,
    # Microsoft) for bulk-sender (>5,000 messages/day) deliverability rules.
    $messages.Add("DMARC is strongly recommended when sending more than 5,000 emails per day. Major mailbox providers (Google, Yahoo, Microsoft) require an enforced DMARC policy for bulk senders, and missing or weak DMARC frequently causes deliverability failures at high volume.")
  }
  elseif ($policy -eq 'quarantine') {
    $messages.Add("DMARC for $targetDomain is set to `p=quarantine`. For the strongest anti-spoofing posture, consider `p=reject` once you confirm valid mail is fully aligned.")
  }

  if ($null -ne $pct -and $pct -lt 100) {
    $messages.Add("DMARC enforcement for $targetDomain is only applied to $pct% of messages (`pct=$pct`). Use `pct=100` for full protection once rollout is validated.")
  }

  if ($adkim -eq 'r') {
    $messages.Add("DKIM alignment for $targetDomain uses relaxed mode (`adkim=r`). Consider strict alignment (`adkim=s`) if your sending infrastructure supports it for tighter domain protection.")
  }

  if ($aspf -eq 'r') {
    $messages.Add("SPF alignment for $targetDomain uses relaxed mode (`aspf=r`). Consider strict alignment (`aspf=s`) if your senders consistently use the exact domain.")
  }

  if (-not [string]::IsNullOrWhiteSpace($Domain) -and -not [string]::IsNullOrWhiteSpace($LookupDomain) -and $Inherited -and ($LookupDomain -ne $Domain) -and -not $tagMap.ContainsKey('sp')) {
    $messages.Add("DMARC for subdomains of $LookupDomain does not define an explicit subdomain policy (`sp=`). If you send from subdomains like $Domain, consider adding `sp=quarantine` or `sp=reject` for clearer protection.")
  }

  if ([string]::IsNullOrWhiteSpace($rua)) {
    $messages.Add("DMARC for $targetDomain does not publish aggregate reporting (`rua=`). Adding a reporting mailbox improves visibility into spoofing attempts and enforcement impact.")
  }

  if ([string]::IsNullOrWhiteSpace($ruf)) {
    $messages.Add("DMARC for $targetDomain does not publish forensic reporting (`ruf=`). If your process allows it, forensic reports can provide additional failure detail for investigations.")
  }

  return @($messages)
}

# ------------------- DOMAIN REGISTRATION STATUS -------------------
# Orchestrate domain registration lookups across all available providers (RDAP, GoDaddy,
# Sysinternals whois, Linux whois, TCP whois, WhoisXML). Returns a unified object with
# creation/expiry dates, registrar, domain age assessment, and any errors.
# If the exact domain fails, walks up parent domains as a last resort.
