# ===== DNS Resolution Layer =====
function Resolve-DohName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [ValidateSet('A','AAAA','CNAME','MX','TXT')]
    [string]$Type
  )

  # DNS-over-HTTPS resolver.
  # Returns objects shaped similarly to `Resolve-DnsName` output so downstream code can stay uniform.
  # SECURITY: read the resolver endpoint from the environment but do NOT mutate
  # process-wide $env:ACS_DNS_DOH_ENDPOINT here. Worker runspaces share the
  # parent process environment, so mutating it from concurrent workers races
  # and unnecessarily fingerprints internal state. The local variable is enough.
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
  }

  # Append `cd=1` (Checking Disabled per RFC 4035) so the upstream DoH resolver
  # returns the requested records even when the parent zone has a DNSSEC
  # anomaly (e.g. a malformed RRSIG anywhere in the chain of trust). Without
  # this flag, validating resolvers like Cloudflare/Google DoH return SERVFAIL
  # and an empty Answer section, which surfaced as "No MX records detected" /
  # "No SPF record" / blank DNS records grid for otherwise-healthy domains
  # whose TLD was temporarily mis-signed (observed for several .de domains
  # during a 2025 .de zone signing incident). This tool is a diagnostic
  # checker, not a DNSSEC validator, so we want the same view of DNS that
  # stub resolvers (`nslookup`, `dig +cd`) and tools like MXToolbox give.
  $uri = "{0}?name={1}&type={2}&cd=1" -f $endpoint, ([uri]::EscapeDataString($Name)), $Type

  # Cloudflare-style DoH JSON response (RFC 8484 compatible JSON format).
  # Routed through Invoke-OutboundHttp so HTTPS-only / redirect cap / timeout
  # are enforced consistently with the other user-driven lookups.
  $resp = Invoke-OutboundHttp -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10 -MaximumRedirection 3
  if ($null -eq $resp -or $null -eq $resp.Answer) { return $null }

  $answers = @($resp.Answer)
  if (-not $answers) { return $null }

  switch ($Type) {
    'TXT' {
      foreach ($a in $answers) {
        # Cloudflare DoH can return CNAME answers alongside the requested TXT type.
        # Only treat actual TXT (type 16) answers as TXT records to avoid leaking CNAME targets.
        $recType = $a.type
        if ($recType -ne 16 -and [string]$recType -ne 'TXT') { continue }

        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $data = $data.Trim()

        # A DNS TXT RDATA can hold multiple <character-string>s (RFC 1035 §3.3.14),
        # each up to 255 octets. Cloudflare DoH returns them in presentation form as a
        # space-separated sequence of double-quoted strings, e.g. `"foo" "bar"`.
        # Per RFC 7208 §3.3, SPF parsers MUST concatenate those strings together with
        # NO separator. Naively stripping only the outer quotes would leave the inner
        # `" "` literal embedded in the record (e.g.
        # `include:spf.protection." "outlook.com -all`), which breaks SPF tokenization.
        # Walk the data string and emit each character-string as a separate element of
        # `Strings`, mirroring the shape produced by Resolve-DnsName so downstream code
        # can rely on `($record.Strings -join '')` to reconstruct the canonical TXT value.
        $strings = New-Object System.Collections.Generic.List[string]
        $index = 0
        $length = $data.Length
        while ($index -lt $length) {
          # Skip inter-string whitespace.
          while ($index -lt $length -and [char]::IsWhiteSpace($data[$index])) { $index++ }
          if ($index -ge $length) { break }

          if ($data[$index] -ne '"') {
            # Defensive: if the payload isn't quoted (non-conforming server), take the
            # remainder as a single character-string and stop.
            $strings.Add($data.Substring($index))
            break
          }

          # Consume one quoted character-string, honoring backslash escapes for `\\` and `\"`.
          $index++  # opening quote
          $builder = New-Object System.Text.StringBuilder
          while ($index -lt $length -and $data[$index] -ne '"') {
            if ($data[$index] -eq '\' -and ($index + 1) -lt $length) {
              [void]$builder.Append($data[$index + 1])
              $index += 2
              continue
            }
            [void]$builder.Append($data[$index])
            $index++
          }
          if ($index -lt $length -and $data[$index] -eq '"') { $index++ }  # closing quote
          $strings.Add($builder.ToString())
        }

        if ($strings.Count -eq 0) { continue }
        [pscustomobject]@{ Strings = $strings.ToArray() }
      }
    }
    'MX' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $parts = $data.Trim() -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $pref = 0
        [int]::TryParse($parts[0], [ref]$pref) | Out-Null
        [pscustomobject]@{ Preference = $pref; NameExchange = $parts[1] }
      }
    }
    'CNAME' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ CanonicalName = $data.Trim() }
      }
    }
    'A' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP4Address = $data.Trim() }
      }
    }
    'AAAA' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP6Address = $data.Trim() }
      }
    }
  }
}

# Probe a DoH endpoint *without* the Checking Disabled (`cd=1`) flag so we can
# observe whether the upstream resolver is currently failing DNSSEC validation
# for this name. Our regular lookups always pass `cd=1` so the records grid
# stays usable when a parent zone is mis-signed (see Resolve-DohName for the
# full rationale and the .de incident this was originally written for). That
# fix has the side-effect of also hiding the EDE diagnostics, so we run a
# single extra probe here purely to surface an informational note.
#
# Returns $null when no anomaly is detected, otherwise a small object with:
#   status        : DoH status code (e.g. 2 = SERVFAIL)
#   statusLabel   : Human-readable status (e.g. 'SERVFAIL')
#   primaryEdeCode: EDE info code from the response (or $null)
#   primaryEdeText: EDE extra_text payload (or $null)
#   edeCodes      : Array of all EDE info codes in the response
#   summary       : Short single-line summary suitable for guidance UI
#   queriedName   : Name that was probed
#   queriedType   : Record type that was probed (string)
function Get-DohDnssecAnomaly {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [string]$Type = 'MX'
  )

  # Same endpoint resolution as Resolve-DohName so the probe matches the
  # transport the rest of the app is actually using.
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
  }

  # NOTE: deliberately NO `cd=1` here -- we want the resolver to perform DNSSEC
  # validation so that any failure is reported in `Status` / `extended_dns_errors`
  # / `Comment`.
  $uri = "{0}?name={1}&type={2}" -f $endpoint, ([uri]::EscapeDataString($Name)), ([uri]::EscapeDataString($Type))

  $resp = $null
  try {
    $resp = Invoke-OutboundHttp -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 8 -MaximumRedirection 3
  } catch {
    # If the probe itself fails (network error, timeout, etc.) just skip the
    # diagnostic. Real lookups have their own error handling and this is
    # purely an informational extra.
    return $null
  }
  if ($null -eq $resp) { return $null }

  # Status is an integer per RFC 8484. 0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN.
  $statusCode = $null
  try { $statusCode = [int]$resp.Status } catch { $statusCode = $null }

  # Collect every EDE we can find. There are two real-world response shapes:
  #
  #   1. Google + (sometimes) Cloudflare emit `extended_dns_errors` as an array
  #      of structured { info_code, extra_text } objects.
  #   2. Cloudflare also frequently emits a `Comment` field containing strings
  #      like "EDE(22): No Reachable Authority" -- either as a bare string or
  #      as an array of strings -- without populating extended_dns_errors at
  #      all. We parse those out so we don't lose the diagnostic just because
  #      the resolver decided to use the legacy presentation.
  $edeCodes = @()
  $primaryEdeCode = $null
  $primaryEdeText = $null

  # Shape #1 -- structured extended_dns_errors array.
  try {
    if ($resp.PSObject.Properties.Match('extended_dns_errors').Count -gt 0 -and $resp.extended_dns_errors) {
      foreach ($entry in @($resp.extended_dns_errors)) {
        if ($null -eq $entry) { continue }
        $code = $null
        try { $code = [int]$entry.info_code } catch { $code = $null }
        $text = $null
        try { $text = [string]$entry.extra_text } catch { $text = $null }
        if ($null -ne $code) {
          $edeCodes += $code
          if ($null -eq $primaryEdeCode) {
            $primaryEdeCode = $code
            if (-not [string]::IsNullOrWhiteSpace($text)) { $primaryEdeText = $text }
          }
        }
      }
    }
  } catch { }

  # Shape #2 -- string Comment(s) that include "EDE(N): text".
  # Also parse a free-form Comment that mentions "DNSSEC validation failure"
  # so we still get something useful when no EDE number is included.
  $commentSawDnssecPhrase = $false
  try {
    if ($resp.PSObject.Properties.Match('Comment').Count -gt 0 -and $resp.Comment) {
      foreach ($comment in @($resp.Comment)) {
        if ($null -eq $comment) { continue }
        $text = [string]$comment
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        $matches = [regex]::Matches($text, 'EDE\s*\(?\s*(\d+)\s*\)?\s*:\s*([^\r\n]*)')
        foreach ($match in $matches) {
          $code = $null
          try { $code = [int]$match.Groups[1].Value } catch { $code = $null }
          $extra = $null
          if ($match.Groups.Count -ge 3) { $extra = $match.Groups[2].Value.Trim() }
          if ($null -ne $code) {
            $edeCodes += $code
            if ($null -eq $primaryEdeCode) {
              $primaryEdeCode = $code
              if (-not [string]::IsNullOrWhiteSpace($extra)) { $primaryEdeText = $extra }
            }
          }
        }

        if ($text -match '(?i)DNSSEC') { $commentSawDnssecPhrase = $true }
      }
    }
  } catch { }

  # Decide whether this is actually a DNSSEC anomaly. Per RFC 8914 the codes we
  # treat as DNSSEC-related are 6-12. Code 22 ("No Reachable Authority") on its
  # own is NOT DNSSEC, but we still surface it when the same response also
  # mentions DNSSEC in the comment text -- that's the shape Cloudflare returns
  # when it gives up on a chain it could not validate. To avoid false positives
  # for run-of-the-mill SERVFAILs we additionally confirm the issue disappears
  # when DNSSEC validation is bypassed (`cd=1`).
  $dnssecRelevantCodes = @(6, 7, 8, 9, 10, 11, 12)
  $hasDnssecRelevantEde = @($edeCodes | Where-Object { $dnssecRelevantCodes -contains $_ }).Count -gt 0

  $looksLikeDnssec = $hasDnssecRelevantEde -or ($statusCode -eq 2 -and $commentSawDnssecPhrase)

  # If we got SERVFAIL but didn't see any DNSSEC indicator yet, fall back to
  # confirming with a cd=1 probe. If that succeeds, the validating layer is the
  # only difference between "broken" and "works" -- treat as a DNSSEC anomaly.
  if (-not $looksLikeDnssec -and $statusCode -eq 2) {
    $cdUri = "{0}?name={1}&type={2}&cd=1" -f $endpoint, ([uri]::EscapeDataString($Name)), ([uri]::EscapeDataString($Type))
    try {
      $cdResp = Invoke-OutboundHttp -Uri $cdUri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 8 -MaximumRedirection 3
      $cdStatus = $null
      try { $cdStatus = [int]$cdResp.Status } catch { $cdStatus = $null }
      $cdHasAnswer = $false
      try { $cdHasAnswer = $null -ne $cdResp.Answer -and (@($cdResp.Answer)).Count -gt 0 } catch { $cdHasAnswer = $false }
      if ($cdStatus -eq 0 -and $cdHasAnswer) { $looksLikeDnssec = $true }
    } catch { }
  }

  if (-not $looksLikeDnssec) { return $null }

  # Friendly labels for the well-known EDE codes we trigger on. Anything else
  # falls through to the raw code number so we still surface unknown values.
  $edeLabel = switch ($primaryEdeCode) {
    6  { 'DNSSEC Bogus (malformed signature in chain of trust)' }
    7  { 'DNSSEC Signature Expired' }
    8  { 'DNSSEC Signature Not Yet Valid' }
    9  { 'DNSKEY Missing' }
    10 { 'RRSIGs Missing' }
    11 { 'No Zone Key Bit Set' }
    12 { 'NSEC Missing' }
    22 { 'No Reachable Authority (validating resolver gave up)' }
    default {
      if ($null -ne $primaryEdeCode) { "EDE $primaryEdeCode" }
      elseif (-not [string]::IsNullOrWhiteSpace($primaryEdeText)) { $primaryEdeText }
      else { 'DNSSEC validation failure' }
    }
  }

  $statusLabel = switch ($statusCode) {
    0 { 'NOERROR' }
    2 { 'SERVFAIL' }
    3 { 'NXDOMAIN' }
    default { if ($null -ne $statusCode) { "RCODE $statusCode" } else { 'unknown' } }
  }

  # Compose a short summary so the front-end has a ready-to-display sentence
  # without needing to know the EDE numbering. We deliberately keep this
  # informational ("records were returned with DNSSEC checking disabled") to
  # convey that the tool worked around the issue rather than failing.
  # NOTE: use ${...} braces around variable names that precede a `:` since the
  # PowerShell parser otherwise reads `$primaryEdeCode:` as a scoped variable
  # reference and fails to load the module.
  $codeSuffix = if ($null -ne $primaryEdeCode) { " (EDE ${primaryEdeCode}: $edeLabel)" } else { '' }
  $summary = "Upstream DNSSEC validation failed for this zone$codeSuffix. Records were returned with DNSSEC checking disabled."

  [pscustomobject]@{
    status         = $statusCode
    statusLabel    = $statusLabel
    primaryEdeCode = $primaryEdeCode
    primaryEdeText = $primaryEdeText
    edeCodes       = $edeCodes
    summary        = $summary
    queriedName    = $Name
    queriedType    = $Type
  }
}

# Unified DNS lookup wrapper: selects the appropriate resolver (System vs DoH vs Auto)
# based on the ACS_DNS_RESOLVER env var, and optionally throws on failure.
# All DNS lookups in the script go through this function.
function ResolveSafely {
    param(
        [string]$Name,
        [string]$Type,
        [switch]$ThrowOnError
    )
    # One stop DNS lookup wrapper:
    # - picks System vs DoH vs Auto
    # - optionally throws (when the caller wants to surface DNS failures)
    try {
        $mode = $env:ACS_DNS_RESOLVER
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Auto' }

        switch ($mode) {
          'DoH' {
            return (Resolve-DohName -Name $Name -Type $Type)
          }
          'System' {
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if (-not $cmd) {
              throw "DnsResolver=System requires Resolve-DnsName (DnsClient module)."
            }
            return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
          }
          default {
            # Auto: prefer the System resolver when available because it is
            # typically faster and uses the host's configured nameservers.
            # However, when System fails with a *server-side* error (SERVFAIL,
            # timeout) -- as happens for zones whose parent DNSSEC chain is
            # broken (e.g. `.de` during 2025 incidents) -- fall back to DoH
            # with `cd=1` so the app can still surface records that other
            # tools see. We only fall back on transport failures, not on a
            # legitimate "no records" response, so that the existing fast
            # negative path is preserved.
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if ($cmd) {
              try {
                return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
              } catch {
                $errMsg = [string]$_.Exception.Message
                $nativeCode = $null
                try {
                  if ($_.Exception.PSObject.Properties.Match('NativeErrorCode').Count -gt 0) {
                    $nativeCode = [int]$_.Exception.NativeErrorCode
                  }
                } catch { $nativeCode = $null }

                # 9003 = NXDOMAIN, 9501 = no records -- those are real answers,
                # not transport failures, so re-throw / return null without
                # paying the cost of a DoH retry.
                $isNoRecords = ($nativeCode -eq 9003 -or $nativeCode -eq 9501)
                if ($isNoRecords) { throw }

                # 9002 = SERVFAIL, 9701 = timeout, plus generic message match
                # for older PS hosts that don't surface NativeErrorCode.
                if ($nativeCode -eq 9002 -or $nativeCode -eq 9701 -or $errMsg -match '(?i)timeout|server failure|SERVFAIL') {
                  return (Resolve-DohName -Name $Name -Type $Type)
                }
                throw
              }
            }
            return (Resolve-DohName -Name $Name -Type $Type)
          }
        }
    } catch {
        if ($ThrowOnError) { throw }
        $null
    }
}

# Extract IP address strings from DNS resolution result objects.
# Handles the different property names used by Resolve-DnsName (IP4Address, IP6Address, IPAddress)
# and the DoH shim objects. Returns deduplicated, normalized IP strings.
function Get-DnsIpString {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Record
  )

  begin {
    $results = [System.Collections.Generic.List[string]]::new()
  }

  process {
    if ($null -eq $Record) { return }

    $value = $null

    # Resolve-DnsName outputs vary by PS/DnsClient version: IP4Address/IP6Address are common,
    # and some versions expose an AliasProperty named IPAddress.
    $props = $Record.PSObject.Properties
    if ($props.Match('IPAddress').Count -gt 0) { $value = $Record.IPAddress }
    elseif ($props.Match('IP4Address').Count -gt 0) { $value = $Record.IP4Address }
    elseif ($props.Match('IP6Address').Count -gt 0) { $value = $Record.IP6Address }
    elseif ($Record -is [System.Net.IPAddress]) { $value = $Record.ToString() }

    foreach ($v in @($value)) {
      $s = [string]$v
      if ([string]::IsNullOrWhiteSpace($s)) { continue }
      $s = $s.Trim().TrimEnd('.')

      $ipObj = $null
      if ([System.Net.IPAddress]::TryParse($s, [ref]$ipObj)) {
        # Normalize formatting (also ensures IPv6 is compressed consistently)
        $results.Add($ipObj.ToString())
      }
    }
  }

  end {
    $results | Select-Object -Unique
  }
}

# Filter DNS result objects to only those that are actual MX records (have Preference + NameExchange).
function Get-MxRecordObjects {
  param([object[]]$Records)

  $filtered = New-Object System.Collections.Generic.List[object]
  foreach ($rec in @($Records)) {
    if ($null -eq $rec) { continue }

    $props = $rec.PSObject.Properties
    if ($props.Match('NameExchange').Count -le 0 -or $props.Match('Preference').Count -le 0) { continue }

    $typeValue = $null
    if ($props.Match('Type').Count -gt 0) { $typeValue = [string]$rec.Type }
    elseif ($props.Match('TypeName').Count -gt 0) { $typeValue = [string]$rec.TypeName }
    elseif ($props.Match('QueryType').Count -gt 0) { $typeValue = [string]$rec.QueryType }

    if (-not [string]::IsNullOrWhiteSpace($typeValue) -and $typeValue -ne 'MX') { continue }

    $filtered.Add($rec)
  }

  return $filtered.ToArray()
}

function Get-DnsRecordTypeCode {
  param([string]$Type)

  switch (([string]$Type).Trim().ToUpperInvariant()) {
    'A'     { return 1 }
    'NS'    { return 2 }
    'CNAME' { return 5 }
    'SOA'   { return 6 }
    'PTR'   { return 12 }
    'HINFO' { return 13 }
    'MX'    { return 15 }
    'TXT'   { return 16 }
    'AAAA'  { return 28 }
    'SRV'   { return 33 }
    'RRSIG' { return 46 }
    'NSEC'  { return 47 }
    'DNSKEY' { return 48 }
    'CAA'   { return 257 }
    default { return $null }
  }
}

function Get-DnsRecordTypeName {
  param([object]$Type)

  $typeInt = 0
  if ([int]::TryParse([string]$Type, [ref]$typeInt)) {
    switch ($typeInt) {
      1 { return 'A' }
      2 { return 'NS' }
      5 { return 'CNAME' }
      6 { return 'SOA' }
      12 { return 'PTR' }
      13 { return 'HINFO' }
      15 { return 'MX' }
      16 { return 'TXT' }
      28 { return 'AAAA' }
      33 { return 'SRV' }
      46 { return 'RRSIG' }
      47 { return 'NSEC' }
      48 { return 'DNSKEY' }
      257 { return 'CAA' }
      default { return [string]$typeInt }
    }
  }

  return ([string]$Type).Trim().ToUpperInvariant()
}

function New-DnsRecordDetail {
  param(
    [string]$LabelKey,
    [object]$Value
  )

  if ([string]::IsNullOrWhiteSpace($LabelKey) -or $null -eq $Value) { return $null }
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }

  [pscustomobject]@{
    labelKey = $LabelKey
    value = $text.Trim()
  }
}

function Format-DnsRecordDetailTtl {
  param([object]$Seconds)

  $ttl = 0
  if (-not [int]::TryParse([string]$Seconds, [ref]$ttl)) { return [string]$Seconds }
  $ttl = [Math]::Max(0, $ttl)
  $secondsPerMinute = 60
  $secondsPerHour = 60 * $secondsPerMinute
  $secondsPerDay = 24 * $secondsPerHour
  $secondsPerMonth = 30 * $secondsPerDay

  $months = [int][Math]::Floor($ttl / $secondsPerMonth)
  $remaining = $ttl % $secondsPerMonth
  $days = [int][Math]::Floor($remaining / $secondsPerDay)
  $remaining = $remaining % $secondsPerDay
  $hours = [int][Math]::Floor($remaining / $secondsPerHour)
  $minutes = [int][Math]::Floor(($remaining % $secondsPerHour) / $secondsPerMinute)
  $seconds = [int]($remaining % $secondsPerMinute)
  $parts = New-Object System.Collections.Generic.List[string]
  if ($months -gt 0) {
    $parts.Add("${months}mo")
  }
  if ($days -gt 0) {
    $parts.Add("${days}d")
  }

  if ($hours -gt 0) {
    $parts.Add("${hours}h")
  }
  if ($minutes -gt 0) {
    $parts.Add("${minutes}m")
  }
  if ($seconds -gt 0 -or $parts.Count -eq 0) {
    $parts.Add("${seconds}s")
  }

  return "$ttl ($($parts -join ', '))"
}

function Convert-DnssecTimestampToDisplay {
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  $text = ([string]$Value).Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }

  if ($text -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$') {
    return ('{0}-{1}-{2} {3}:{4}:{5}Z' -f $Matches[1], $Matches[2], $Matches[3], $Matches[4], $Matches[5], $Matches[6])
  }

  $dto = [DateTimeOffset]::MinValue
  if ([DateTimeOffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
    return $dto.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ssZ')
  }

  return $text
}

function Get-DnsEscapedByteDisplay {
  param([int]$Value)

  switch ($Value) {
    0 { return 'NUL' }
    9 { return 'TAB' }
    10 { return 'LF' }
    13 { return 'CR' }
    32 { return 'SPACE' }
    default {
      if ($Value -ge 33 -and $Value -le 126) {
        return [string][char]$Value
      }
      return ('0x{0:X2}' -f $Value)
    }
  }
}

function Convert-DnsEscapedLabelToDisplay {
  param([string]$Label)

  if ([string]::IsNullOrEmpty($Label)) { return $Label }

  $builder = New-Object System.Text.StringBuilder
  $index = 0
  while ($index -lt $Label.Length) {
    $char = $Label[$index]
    if ($char -ne '\') {
      [void]$builder.Append($char)
      $index++
      continue
    }

    if (($index + 3) -lt $Label.Length) {
      $octetText = $Label.Substring($index + 1, 3)
      $octetValue = 0
      if ([int]::TryParse($octetText, [ref]$octetValue)) {
        [void]$builder.Append('[')
        [void]$builder.Append((Get-DnsEscapedByteDisplay -Value $octetValue))
        [void]$builder.Append(']')
        $index += 4
        continue
      }
    }

    if (($index + 1) -lt $Label.Length) {
      [void]$builder.Append('[')
      [void]$builder.Append([string]$Label[$index + 1])
      [void]$builder.Append(']')
      $index += 2
      continue
    }

    [void]$builder.Append($char)
    $index++
  }

  return $builder.ToString()
}

function Convert-DnsNameToDisplay {
  param([object]$Name)

  if ($null -eq $Name) { return $null }
  $text = ([string]$Name).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }

  $labels = @($text -split '\.')
  if ($labels.Count -eq 0) { return $text }

  return ((@($labels | ForEach-Object { Convert-DnsEscapedLabelToDisplay -Label $_ })) -join '.')
}

function Convert-DnsBinaryDataToDisplay {
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [byte[]]) {
    return ((@($Value | ForEach-Object { $_.ToString('X2') })) -join '')
  }

  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  return $text.Trim()
}

function Get-DnssecAlgorithmDisplay {
  param([object]$Algorithm)

  $code = 0
  if ([int]::TryParse([string]$Algorithm, [ref]$code)) {
    switch ($code) {
      5 { return 'RSA/SHA-1 (5)' }
      7 { return 'RSASHA1-NSEC3-SHA1 (7)' }
      8 { return 'RSA/SHA-256 (8)' }
      10 { return 'RSA/SHA-512 (10)' }
      13 { return 'ECDSA Curve P-256 with SHA-256 (13)' }
      14 { return 'ECDSA Curve P-384 with SHA-384 (14)' }
      15 { return 'Ed25519 (15)' }
      16 { return 'Ed448 (16)' }
      default { return [string]$code }
    }
  }

  return ([string]$Algorithm).Trim()
}

function Get-DnsRecordTypeDisplay {
  param([object]$Type)

  $name = Get-DnsRecordTypeName -Type $Type
  $code = Get-DnsRecordTypeCode -Type $name
  if ($null -ne $code) { return "$name ($code)" }
  return $name
}

function Get-DnsRecordDetails {
  param(
    [object]$Record,
    [string]$Type,
    [string]$RawData
  )

  $normalizedType = ([string]$Type).Trim().ToUpperInvariant()
  $props = $null
  if ($Record) { $props = $Record.PSObject.Properties }
  $details = New-Object System.Collections.Generic.List[object]

  switch ($normalizedType) {
    'HINFO' {
      $cpu = $null
      $os = $null
      if ($props) {
        if ($props.Match('CPU').Count -gt 0 -and $Record.CPU) { $cpu = [string]$Record.CPU }
        elseif ($props.Match('Cpu').Count -gt 0 -and $Record.Cpu) { $cpu = [string]$Record.Cpu }
        if ($props.Match('OS').Count -gt 0 -and $null -ne $Record.OS) { $os = [string]$Record.OS }
        elseif ($props.Match('Os').Count -gt 0 -and $null -ne $Record.Os) { $os = [string]$Record.Os }
        elseif ($props.Match('Strings').Count -gt 0 -and $Record.Strings) {
          $parts = @($Record.Strings | ForEach-Object { [string]$_ })
          if (-not $cpu -and $parts.Count -ge 1) { $cpu = $parts[0] }
          if ($null -eq $os -and $parts.Count -ge 2) { $os = $parts[1] }
        }
        elseif ($props.Match('Text').Count -gt 0 -and $Record.Text) {
          $parts = @($Record.Text | ForEach-Object { [string]$_ })
          if (-not $cpu -and $parts.Count -ge 1) { $cpu = $parts[0] }
          if ($null -eq $os -and $parts.Count -ge 2) { $os = $parts[1] }
        }
      }
      if (($null -eq $cpu) -and ($null -eq $os) -and -not [string]::IsNullOrWhiteSpace($RawData)) {
        if ($RawData -match '^\s*"([^"]*)"\s+"([^"]*)"\s*$') {
          $cpu = $Matches[1]
          $os = $Matches[2]
        }
        elseif ($RawData -match '^\s*(\S+)\s+(.*)$') {
          $cpu = $Matches[1]
          $os = $Matches[2].Trim('"')
        }
      }
      foreach ($item in @(
        (New-DnsRecordDetail -LabelKey 'dnsRecordCpu' -Value $cpu),
        (New-DnsRecordDetail -LabelKey 'dnsRecordOs' -Value $os)
      )) { if ($item) { $details.Add($item) } }
    }
    'RRSIG' {
      $typeCovered = $null; $algorithm = $null; $labels = $null; $originalTtl = $null
      $signatureExpiration = $null; $signatureInception = $null; $keyTag = $null; $signerName = $null; $signature = $null
      if ($props) {
        if ($props.Match('TypeCovered').Count -gt 0) { $typeCovered = Get-DnsRecordTypeDisplay -Type $Record.TypeCovered }
        if ($props.Match('Algorithm').Count -gt 0) { $algorithm = Get-DnssecAlgorithmDisplay -Algorithm $Record.Algorithm }
        if ($props.Match('Labels').Count -gt 0) { $labels = [string]$Record.Labels }
        elseif ($props.Match('LabelCount').Count -gt 0) { $labels = [string]$Record.LabelCount }
        if ($props.Match('OriginalTTL').Count -gt 0) { $originalTtl = Format-DnsRecordDetailTtl -Seconds $Record.OriginalTTL }
        elseif ($props.Match('OriginalTtl').Count -gt 0) { $originalTtl = Format-DnsRecordDetailTtl -Seconds $Record.OriginalTtl }
        if ($props.Match('SignatureExpiration').Count -gt 0) { $signatureExpiration = Convert-DnssecTimestampToDisplay -Value $Record.SignatureExpiration }
        elseif ($props.Match('Expiration').Count -gt 0) { $signatureExpiration = Convert-DnssecTimestampToDisplay -Value $Record.Expiration }
        if ($props.Match('SignatureInception').Count -gt 0) { $signatureInception = Convert-DnssecTimestampToDisplay -Value $Record.SignatureInception }
        elseif ($props.Match('Signed').Count -gt 0) { $signatureInception = Convert-DnssecTimestampToDisplay -Value $Record.Signed }
        if ($props.Match('KeyTag').Count -gt 0) { $keyTag = [string]$Record.KeyTag }
        elseif ($props.Match('Key').Count -gt 0) { $keyTag = [string]$Record.Key }
        if ($props.Match('SignersName').Count -gt 0) { $signerName = Convert-DnsNameToDisplay -Name $Record.SignersName }
        elseif ($props.Match('Signer').Count -gt 0) { $signerName = Convert-DnsNameToDisplay -Name $Record.Signer }
        if ($props.Match('Signature').Count -gt 0) { $signature = Convert-DnsBinaryDataToDisplay -Value $Record.Signature }
      }
      if ([string]::IsNullOrWhiteSpace($signature) -and -not [string]::IsNullOrWhiteSpace($RawData)) {
        $parts = @($RawData.Trim() -split '\s+', 9)
        if ($parts.Count -ge 9) {
          if (-not $typeCovered) { $typeCovered = Get-DnsRecordTypeDisplay -Type $parts[0] }
          if (-not $algorithm) { $algorithm = Get-DnssecAlgorithmDisplay -Algorithm $parts[1] }
          if (-not $labels) { $labels = $parts[2] }
          if (-not $originalTtl) { $originalTtl = Format-DnsRecordDetailTtl -Seconds $parts[3] }
          if (-not $signatureExpiration) { $signatureExpiration = Convert-DnssecTimestampToDisplay -Value $parts[4] }
          if (-not $signatureInception) { $signatureInception = Convert-DnssecTimestampToDisplay -Value $parts[5] }
          if (-not $keyTag) { $keyTag = $parts[6] }
          if (-not $signerName) { $signerName = Convert-DnsNameToDisplay -Name $parts[7] }
          if (-not $signature) { $signature = $parts[8] }
        }
      }
      foreach ($item in @(
        (New-DnsRecordDetail -LabelKey 'dnsRecordTypeCovered' -Value $typeCovered),
        (New-DnsRecordDetail -LabelKey 'dnsRecordAlgorithm' -Value $algorithm),
        (New-DnsRecordDetail -LabelKey 'dnsRecordLabels' -Value $labels),
        (New-DnsRecordDetail -LabelKey 'dnsRecordOriginalTtl' -Value $originalTtl),
        (New-DnsRecordDetail -LabelKey 'dnsRecordSignatureExpiration' -Value $signatureExpiration),
        (New-DnsRecordDetail -LabelKey 'dnsRecordSignatureInception' -Value $signatureInception),
        (New-DnsRecordDetail -LabelKey 'dnsRecordKeyTag' -Value $keyTag),
        (New-DnsRecordDetail -LabelKey 'dnsRecordSignerName' -Value $signerName),
        (New-DnsRecordDetail -LabelKey 'dnsRecordSignature' -Value $signature)
      )) { if ($item) { $details.Add($item) } }
    }
    'DNSKEY' {
      $flags = $null; $protocol = $null; $algorithm = $null; $publicKey = $null
      if ($props) {
        if ($props.Match('Flags').Count -gt 0) { $flags = [string]$Record.Flags }
        if ($props.Match('Protocol').Count -gt 0) { $protocol = [string]$Record.Protocol }
        if ($props.Match('Algorithm').Count -gt 0) { $algorithm = Get-DnssecAlgorithmDisplay -Algorithm $Record.Algorithm }
        if ($props.Match('PublicKey').Count -gt 0) { $publicKey = [string]$Record.PublicKey }
      }
      if ([string]::IsNullOrWhiteSpace($publicKey) -and -not [string]::IsNullOrWhiteSpace($RawData)) {
        $parts = @($RawData.Trim() -split '\s+', 4)
        if ($parts.Count -ge 4) {
          if (-not $flags) { $flags = $parts[0] }
          if (-not $protocol) { $protocol = $parts[1] }
          if (-not $algorithm) { $algorithm = Get-DnssecAlgorithmDisplay -Algorithm $parts[2] }
          if (-not $publicKey) { $publicKey = $parts[3] }
        }
      }
      foreach ($item in @(
        (New-DnsRecordDetail -LabelKey 'dnsRecordFlags' -Value $flags),
        (New-DnsRecordDetail -LabelKey 'dnsRecordProtocol' -Value $protocol),
        (New-DnsRecordDetail -LabelKey 'dnsRecordAlgorithm' -Value $algorithm),
        (New-DnsRecordDetail -LabelKey 'dnsRecordPublicKey' -Value $publicKey)
      )) { if ($item) { $details.Add($item) } }
    }
    'NSEC' {
      $nextDomain = $null; $types = $null
      if ($props) {
        if ($props.Match('NextDomainName').Count -gt 0) { $nextDomain = Convert-DnsNameToDisplay -Name $Record.NextDomainName }
        elseif ($props.Match('NextDomain').Count -gt 0) { $nextDomain = Convert-DnsNameToDisplay -Name $Record.NextDomain }
        if ($props.Match('TypeBitMaps').Count -gt 0 -and $Record.TypeBitMaps) { $types = (@($Record.TypeBitMaps) -join ' ') }
        elseif ($props.Match('Types').Count -gt 0 -and $Record.Types) { $types = (@($Record.Types) -join ' ') }
      }
      if ((-not $nextDomain -or -not $types) -and -not [string]::IsNullOrWhiteSpace($RawData)) {
        $parts = @($RawData.Trim() -split '\s+', 2)
        if ($parts.Count -ge 2) {
          if (-not $nextDomain) { $nextDomain = Convert-DnsNameToDisplay -Name $parts[0] }
          if (-not $types) { $types = $parts[1] }
        }
      }
      foreach ($item in @(
        (New-DnsRecordDetail -LabelKey 'dnsRecordNextDomain' -Value $nextDomain),
        (New-DnsRecordDetail -LabelKey 'dnsRecordTypes' -Value $types)
      )) { if ($item) { $details.Add($item) } }
    }
  }

  return $details.ToArray()
}

function Get-ReverseLookupSupplementTargets {
  param([string]$ReverseName)

  $targets = New-Object System.Collections.Generic.List[object]
  $reverse = ([string]$ReverseName).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($reverse)) { return @() }

  $parts = @($reverse -split '\.')
  if ($parts.Count -lt 3) { return @() }

  $targets.Add([pscustomobject]@{ Name = $reverse; Types = @('PTR', 'HINFO') })

  if ($reverse -match '(?i)\.in-addr\.arpa$' -and $parts.Count -ge 6) {
    $delegationZone = ($parts[2..($parts.Count - 1)] -join '.')
    $targets.Add([pscustomobject]@{ Name = $delegationZone; Types = @('NS') })
  }
  elseif ($reverse -match '(?i)\.ip6\.arpa$' -and $parts.Count -ge 12) {
    $delegationZone = ($parts[($parts.Count - 10)..($parts.Count - 1)] -join '.')
    $targets.Add([pscustomobject]@{ Name = $delegationZone; Types = @('NS') })
  }

  return @($targets | Sort-Object Name -Unique)
}

function Get-DnsRecordDataString {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Record,
    [string]$Type
  )

  if ($null -eq $Record) { return $null }

  $normalizedType = ([string]$Type).Trim().ToUpperInvariant()
  $props = $null
  if ($Record) { $props = $Record.PSObject.Properties }

  switch ($normalizedType) {
    'A' {
      if ($props.Match('IPAddress').Count -gt 0 -and $Record.IPAddress) { return ([string]$Record.IPAddress).Trim() }
      if ($props.Match('IP4Address').Count -gt 0 -and $Record.IP4Address) { return ([string]$Record.IP4Address).Trim() }
    }
    'AAAA' {
      if ($props.Match('IPAddress').Count -gt 0 -and $Record.IPAddress) { return ([string]$Record.IPAddress).Trim() }
      if ($props.Match('IP6Address').Count -gt 0 -and $Record.IP6Address) { return ([string]$Record.IP6Address).Trim() }
    }
    'CNAME' {
      if ($props.Match('CanonicalName').Count -gt 0 -and $Record.CanonicalName) { return (Convert-DnsNameToDisplay -Name $Record.CanonicalName) }
      if ($props.Match('NameHost').Count -gt 0 -and $Record.NameHost) { return (Convert-DnsNameToDisplay -Name $Record.NameHost) }
    }
    'NS' {
      if ($props.Match('NameHost').Count -gt 0 -and $Record.NameHost) { return (Convert-DnsNameToDisplay -Name $Record.NameHost) }
      if ($props.Match('NSDName').Count -gt 0 -and $Record.NSDName) { return (Convert-DnsNameToDisplay -Name $Record.NSDName) }
    }
    'PTR' {
      if ($props.Match('NameHost').Count -gt 0 -and $Record.NameHost) { return (Convert-DnsNameToDisplay -Name $Record.NameHost) }
      if ($props.Match('PtrDomainName').Count -gt 0 -and $Record.PtrDomainName) { return (Convert-DnsNameToDisplay -Name $Record.PtrDomainName) }
    }
    'HINFO' {
      $cpu = $null
      $os = $null
      if ($props.Match('CPU').Count -gt 0) { $cpu = [string]$Record.CPU }
      elseif ($props.Match('Cpu').Count -gt 0) { $cpu = [string]$Record.Cpu }
      if ($props.Match('OS').Count -gt 0) { $os = [string]$Record.OS }
      elseif ($props.Match('Os').Count -gt 0) { $os = [string]$Record.Os }
      elseif ($props.Match('Strings').Count -gt 0 -and $Record.Strings) {
        $parts = @($Record.Strings | ForEach-Object { [string]$_ })
        if ($parts.Count -ge 1) { $cpu = $parts[0] }
        if ($parts.Count -ge 2) { $os = $parts[1] }
      }
      elseif ($props.Match('Text').Count -gt 0 -and $Record.Text) {
        $parts = @($Record.Text | ForEach-Object { [string]$_ })
        if ($parts.Count -ge 1) { $cpu = $parts[0] }
        if ($parts.Count -ge 2) { $os = $parts[1] }
      }
      if (-not [string]::IsNullOrWhiteSpace($cpu) -or $null -ne $os) {
        return ("CPU: {0}; OS: {1}" -f $cpu, $os).Trim()
      }
    }
    'MX' {
      if ($props.Match('NameExchange').Count -gt 0 -and $props.Match('Preference').Count -gt 0) {
        return ("{0} {1}" -f ([string]$Record.Preference).Trim(), (Convert-DnsNameToDisplay -Name $Record.NameExchange)).Trim()
      }
    }
    'TXT' {
      if ($props.Match('Strings').Count -gt 0 -and $Record.Strings) {
        $strings = @($Record.Strings | ForEach-Object {
          $text = [string]$_
          if ($text.StartsWith('"') -and $text.EndsWith('"') -and $text.Length -ge 2) {
            $text = $text.Substring(1, $text.Length - 2)
          }
          $text -replace '\\"','"'
        })
        if ($strings.Count -gt 0) { return ($strings -join '') }
      }
    }
    'SOA' {
      $segments = @()
      if ($props.Match('PrimaryServer').Count -gt 0 -and $Record.PrimaryServer) { $segments += "PrimaryServer=$(Convert-DnsNameToDisplay -Name $Record.PrimaryServer)" }
      if ($props.Match('NameAdministrator').Count -gt 0 -and $Record.NameAdministrator) { $segments += "ResponsiblePerson=$([string]$Record.NameAdministrator)" }
      elseif ($props.Match('ResponsiblePerson').Count -gt 0 -and $Record.ResponsiblePerson) { $segments += "ResponsiblePerson=$([string]$Record.ResponsiblePerson)" }
      if ($props.Match('SerialNumber').Count -gt 0 -and $null -ne $Record.SerialNumber) { $segments += "Serial=$([string]$Record.SerialNumber)" }
      if ($segments.Count -gt 0) { return ($segments -join '; ') }
    }
    'CAA' {
      $segments = @()
      if ($props.Match('Flags').Count -gt 0 -and $null -ne $Record.Flags) { $segments += [string]$Record.Flags }
      elseif ($props.Match('Flag').Count -gt 0 -and $null -ne $Record.Flag) { $segments += [string]$Record.Flag }
      if ($props.Match('Tag').Count -gt 0 -and $Record.Tag) { $segments += [string]$Record.Tag }
      if ($props.Match('Value').Count -gt 0 -and $Record.Value) { $segments += [string]$Record.Value }
      if ($segments.Count -gt 0) { return ($segments -join ' ') }
    }
    'RRSIG' {
      $signature = if ($props.Match('Signature').Count -gt 0) { Convert-DnsBinaryDataToDisplay -Value $Record.Signature } else { $null }
      if (-not [string]::IsNullOrWhiteSpace($signature)) { return $signature.Trim() }
    }
    'DNSKEY' {
      if ($props.Match('PublicKey').Count -gt 0 -and $Record.PublicKey) { return ([string]$Record.PublicKey).Trim() }
    }
    'NSEC' {
      if ($props.Match('NextDomainName').Count -gt 0 -and $Record.NextDomainName) {
        return (Convert-DnsNameToDisplay -Name $Record.NextDomainName)
      }
    }
  }

  foreach ($candidate in @('Data', 'Text', 'Target', 'DomainName', 'HostName', 'NameHost', 'CanonicalName', 'Exchange', 'MailExchange')) {
    if ($props.Match($candidate).Count -gt 0) {
      $value = [string]$props[$candidate].Value
      if (-not [string]::IsNullOrWhiteSpace($value)) {
        return (Convert-DnsNameToDisplay -Name $value)
      }
    }
  }

  return $null
}

function ConvertTo-ReverseLookupName {
  param([string]$IpAddress)

  $ip = $null
  if (-not [System.Net.IPAddress]::TryParse([string]$IpAddress, [ref]$ip)) { return $null }

  if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    $bytes = $ip.GetAddressBytes()
    [Array]::Reverse($bytes)
    return (($bytes | ForEach-Object { [string]$_ }) -join '.') + '.in-addr.arpa'
  }

  if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    $hex = ($ip.GetAddressBytes() | ForEach-Object { $_.ToString('x2') }) -join ''
    $nibbles = @()
    foreach ($char in $hex.ToCharArray()) { $nibbles += [string]$char }
    [Array]::Reverse($nibbles)
    return (($nibbles -join '.') + '.ip6.arpa')
  }

  return $null
}

function Resolve-DohRecordsDetailed {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [string]$Type
  )

  # SECURITY: read the resolver endpoint from the environment but do NOT mutate
  # process-wide $env:ACS_DNS_DOH_ENDPOINT here. Worker runspaces share the
  # parent process environment, so mutating it from concurrent workers races
  # and unnecessarily fingerprints internal state. The local variable is enough.
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
  }

  $typeCode = Get-DnsRecordTypeCode -Type $Type
  # Append `cd=1` (Checking Disabled) for the same reason as Resolve-DohName:
  # we want the resolver to return the records even if the parent zone has a
  # broken DNSSEC chain (e.g. malformed RRSIG in the .de zone). Otherwise the
  # detailed DNS records grid renders empty for affected domains while
  # nslookup/dig still return data. We keep `do=true` so DNSSEC RRs (RRSIG,
  # NSEC, etc.) are still included in the answer when present.
  $uri = "{0}?name={1}&type={2}&do=true&cd=1" -f $endpoint, ([uri]::EscapeDataString($Name)), ([uri]::EscapeDataString($Type))
  # Same outbound guardrails as Resolve-DohName.
  $resp = Invoke-OutboundHttp -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10 -MaximumRedirection 3
  if ($null -eq $resp -or $null -eq $resp.Answer) { return @() }

  $results = New-Object System.Collections.Generic.List[object]
  foreach ($answer in @($resp.Answer)) {
    if ($null -ne $typeCode -and [int]$answer.type -ne $typeCode) { continue }

    $recordType = Get-DnsRecordTypeName -Type $answer.type
    $rawData = [string]$answer.data
    $data = $rawData
    if ($recordType -eq 'TXT') {
      if ($data.StartsWith('"') -and $data.EndsWith('"') -and $data.Length -ge 2) {
        $data = $data.Substring(1, $data.Length - 2)
      }
      $data = $data -replace '\\"','"'
    }
    elseif ($recordType -eq 'MX') {
      $parts = $data.Trim() -split '\s+', 2
      if ($parts.Count -eq 2) {
        $data = ("{0} {1}" -f $parts[0], (Convert-DnsNameToDisplay -Name $parts[1])).Trim()
      }
    }
    elseif ($recordType -in @('CNAME', 'NS', 'PTR')) {
      $data = Convert-DnsNameToDisplay -Name $data
    }
    else {
      $data = $data.Trim().TrimEnd('.')
    }

    if ([string]::IsNullOrWhiteSpace($data)) { continue }

    $results.Add([pscustomobject]@{
      name = Convert-DnsNameToDisplay -Name $answer.name
      class = 'IN'
      type = $recordType
      data = $data
      ttlSeconds = [int]$answer.TTL
      details = @(Get-DnsRecordDetails -Type $recordType -RawData $rawData)
    })
  }

  return $results.ToArray()
}

function Resolve-DnsRecordsDetailed {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [string[]]$Types
  )

  $mode = $env:ACS_DNS_RESOLVER
  if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Auto' }

  $cmd = $null
  try { $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue } catch { $cmd = $null }
  $useSystem = (($mode -eq 'System') -or ($mode -eq 'Auto' -and $cmd)) -and $cmd

  $results = New-Object System.Collections.Generic.List[object]

  function Get-AuthoritativeNameServer {
    param([string]$LookupName)

    $trimmed = ([string]$LookupName).Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $null }

    $labels = @($trimmed -split '\.')
    for ($i = 0; $i -lt ($labels.Count - 1); $i++) {
      $candidate = ($labels[$i..($labels.Count - 1)] -join '.')
      if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

      try {
        $nsRecords = @(Resolve-DnsName -Name $candidate -Type NS -DnssecOk -ErrorAction Stop)
        foreach ($nsRecord in $nsRecords) {
          if ($null -eq $nsRecord) { continue }
          if ($nsRecord.PSObject.Properties.Match('NameHost').Count -gt 0 -and $nsRecord.NameHost) {
            return ([string]$nsRecord.NameHost).Trim().TrimEnd('.')
          }
          if ($nsRecord.PSObject.Properties.Match('NSDName').Count -gt 0 -and $nsRecord.NSDName) {
            return ([string]$nsRecord.NSDName).Trim().TrimEnd('.')
          }
        }
      }
      catch { }
    }

    return $null
  }

  function Resolve-AuthoritativeAnySupplementRecords {
    param(
      [string]$LookupName,
      [string[]]$DesiredTypes
    )

    $server = Get-AuthoritativeNameServer -LookupName $LookupName
    if ([string]::IsNullOrWhiteSpace($server)) { return @() }

    $supplemental = New-Object System.Collections.Generic.List[object]
    try {
      $records = @(Resolve-DnsName -Name $LookupName -Type ANY -Server $server -DnssecOk -ErrorAction Stop)
      foreach ($record in $records) {
        if ($null -eq $record) { continue }

        $props = $record.PSObject.Properties
        $recordType = $null
        if ($props.Match('Type').Count -gt 0 -and $record.Type) { $recordType = [string]$record.Type }
        elseif ($props.Match('QueryType').Count -gt 0 -and $record.QueryType) { $recordType = [string]$record.QueryType }
        if ([string]::IsNullOrWhiteSpace($recordType)) { continue }
        $recordType = Get-DnsRecordTypeName -Type $recordType

        if ($recordType -notin @($DesiredTypes | ForEach-Object { Get-DnsRecordTypeName -Type $_ })) { continue }

        $data = Get-DnsRecordDataString -Record $record -Type $recordType
        $details = @(Get-DnsRecordDetails -Record $record -Type $recordType -RawData $data)
        if ([string]::IsNullOrWhiteSpace($data) -and $details.Count -eq 0) { continue }
        if ([string]::IsNullOrWhiteSpace($data)) { $data = $recordType }

        $ttl = $null
        if ($props.Match('TTL').Count -gt 0 -and $null -ne $record.TTL) {
          try { $ttl = [int]$record.TTL } catch { $ttl = $null }
        }

        $recordName = $LookupName
        if ($props.Match('Name').Count -gt 0 -and $record.Name) { $recordName = [string]$record.Name }

        $supplemental.Add([pscustomobject]@{
          name = Convert-DnsNameToDisplay -Name $recordName
          class = 'IN'
          type = $recordType
          data = $data
          ttlSeconds = $ttl
          details = $details
        })
      }
    }
    catch { }

    return $supplemental.ToArray()
  }

  # Per-name short-circuit: when the System resolver returns a *server* failure
  # (typically SERVFAIL from a broken upstream DNSSEC chain like `.de`), every
  # subsequent type query for the same name is going to take the full client
  # timeout (~15s) before we fall back to DoH. With ~12 types per name and
  # ~15+ names probed per request, that adds up to multi-minute hangs that
  # leave the UI cards stuck on "Loading...". Once we've seen one server-side
  # failure for this name in this call, force the remaining types straight to
  # DoH so the records grid finishes in a bounded amount of time.
  $skipSystemForName = $false

  foreach ($type in @($Types)) {
    if ([string]::IsNullOrWhiteSpace($type)) { continue }

    $typeResultsAdded = $false
    $systemLookupFailed = $false

    if ($useSystem -and -not $skipSystemForName) {
      try {
        $queryParams = @{ Name = $Name; Type = $type; ErrorAction = 'Stop' }
        if ($type -in @('RRSIG', 'NSEC', 'DNSKEY')) { $queryParams['DnssecOk'] = $true }
        $records = @(Resolve-DnsName @queryParams)
        foreach ($record in $records) {
          if ($null -eq $record) { continue }

          $props = $record.PSObject.Properties
          $recordType = $type
          if ($props.Match('Type').Count -gt 0 -and $record.Type) { $recordType = [string]$record.Type }
          elseif ($props.Match('QueryType').Count -gt 0 -and $record.QueryType) { $recordType = [string]$record.QueryType }
          if ((Get-DnsRecordTypeName -Type $recordType) -ne (Get-DnsRecordTypeName -Type $type)) { continue }

          $data = Get-DnsRecordDataString -Record $record -Type $recordType
          if ([string]::IsNullOrWhiteSpace($data)) { continue }

          $recordName = $Name
          if ($props.Match('Name').Count -gt 0 -and $record.Name) { $recordName = [string]$record.Name }
          elseif ($props.Match('NameHost').Count -gt 0 -and $recordType -eq 'PTR' -and $record.NameHost) { $recordName = [string]$record.NameHost }

          $ttl = $null
          if ($props.Match('TTL').Count -gt 0 -and $null -ne $record.TTL) {
            try { $ttl = [int]$record.TTL } catch { $ttl = $null }
          }

          $results.Add([pscustomobject]@{
            name = Convert-DnsNameToDisplay -Name $recordName
            class = 'IN'
            type = Get-DnsRecordTypeName -Type $recordType
            data = $data
            ttlSeconds = $ttl
            details = @(Get-DnsRecordDetails -Record $record -Type $recordType -RawData $data)
          })
          $typeResultsAdded = $true
        }
      }
      catch {
        $systemLookupFailed = $true

        # Inspect the underlying Win32 DNS error code so we can distinguish a
        # legitimate "this record doesn't exist" (NXDOMAIN/no records) from a
        # broken upstream resolver chain (SERVFAIL, timeout, etc.). Only the
        # latter justifies blacklisting the System resolver for the remainder
        # of this name -- NXDOMAIN is fast and we want to keep using System
        # for the next type if it's working.
        $errMsg = [string]$_.Exception.Message
        $nativeCode = $null
        try {
          if ($_.Exception.PSObject.Properties.Match('NativeErrorCode').Count -gt 0) {
            $nativeCode = [int]$_.Exception.NativeErrorCode
          }
        } catch { $nativeCode = $null }

        # 9002 = DNS_ERROR_RCODE_SERVER_FAILURE, 9501 = DNS_INFO_NO_RECORDS,
        # 9003 = DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN), 9701 = timeout.
        # Treat anything that is NOT a "no records / NXDOMAIN" as a transport
        # failure that warrants short-circuiting.
        $isNoRecords = ($nativeCode -eq 9003 -or $nativeCode -eq 9501)
        if (-not $isNoRecords -and ($nativeCode -eq 9002 -or $nativeCode -eq 9701 -or $errMsg -match '(?i)timeout|server failure|SERVFAIL')) {
          $skipSystemForName = $true
        }
      }

      if (-not $typeResultsAdded -and $mode -eq 'Auto') {
        try {
          foreach ($row in @(Resolve-DohRecordsDetailed -Name $Name -Type $type)) {
            if ($row) {
              $results.Add($row)
              $typeResultsAdded = $true
            }
          }
        }
        catch { }
      }

      if (-not $typeResultsAdded -and $type -in @('HINFO', 'RRSIG')) {
        foreach ($row in @(Resolve-AuthoritativeAnySupplementRecords -LookupName $Name -DesiredTypes @($type))) {
          if ($row) {
            $results.Add($row)
            $typeResultsAdded = $true
          }
        }
      }

      if (-not $typeResultsAdded -and $systemLookupFailed -and $mode -eq 'System') {
        continue
      }
    }
    else {
      # Either DoH-only mode, or System has already failed for this name in
      # this call -- go straight to DoH so we don't pay another System
      # timeout. The aggregate caller will still see results because DoH is
      # generally able to return records (the app passes cd=1).
      try {
        foreach ($row in @(Resolve-DohRecordsDetailed -Name $Name -Type $type)) {
          if ($row) {
            $results.Add($row)
            $typeResultsAdded = $true
          }
        }
      }
      catch { }
    }
  }

  return $results.ToArray()
}

function Get-DnsRecordsStatus {
  param([string]$Domain)

  $records = New-Object System.Collections.Generic.List[object]
  $errors = New-Object System.Collections.Generic.List[string]
  $types = @('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'RRSIG', 'DNSKEY', 'NSEC', 'HINFO')

  try {
    foreach ($row in @(Resolve-DnsRecordsDetailed -Name $Domain -Types $types)) {
      if ($row) { $records.Add($row) }
    }
  }
  catch {
    $errors.Add($_.Exception.Message)
  }

  $ipAddresses = @($records | Where-Object { $_.type -in @('A', 'AAAA') } | ForEach-Object { [string]$_.data } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
  foreach ($ipAddress in $ipAddresses) {
    $reverseName = ConvertTo-ReverseLookupName -IpAddress $ipAddress
    if ([string]::IsNullOrWhiteSpace($reverseName)) { continue }

    foreach ($target in @(Get-ReverseLookupSupplementTargets -ReverseName $reverseName)) {
      try {
        foreach ($row in @(Resolve-DnsRecordsDetailed -Name $target.Name -Types $target.Types)) {
          if ($row) { $records.Add($row) }
        }
      }
      catch {
        $errors.Add($_.Exception.Message)
      }
    }
  }

  # Related-name supplements: query well-known ACS-related subdomains so they
  # show up in the DNS records grid alongside the apex records. The dedupe step
  # below collapses duplicates if any of these were already discovered through
  # other code paths. Each entry asks for the record types most likely to exist
  # at that name so the grid reflects the actual published chain (e.g., a
  # selector CNAME plus the resolved TXT public key on the ACS side).
  #
  # The DKIM selector list mirrors `Invoke-DkimFallbackSelectorProbe` in
  # `Get-DnsDkimStatus` so any selector the DKIM card surfaces also appears in
  # the records table. Selectors that are not published return NXDOMAIN
  # quickly and are filtered out by `Resolve-DnsRecordsDetailed`, so the cost
  # of probing them is negligible.
  $relatedTargets = @(
    [pscustomobject]@{ Name = "selector1-azurecomm-prod-net._domainkey.$Domain"; Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "selector2-azurecomm-prod-net._domainkey.$Domain"; Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "selector1._domainkey.$Domain";                    Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "selector2._domainkey.$Domain";                    Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "s1._domainkey.$Domain";                           Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "s2._domainkey.$Domain";                           Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "default._domainkey.$Domain";                      Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "google._domainkey.$Domain";                       Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "k1._domainkey.$Domain";                           Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "mail._domainkey.$Domain";                         Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "dkim._domainkey.$Domain";                         Types = @('CNAME', 'TXT') },
    [pscustomobject]@{ Name = "_dmarc.$Domain";                                  Types = @('TXT') },
    [pscustomobject]@{ Name = "www.$Domain";                                     Types = @('CNAME', 'A', 'AAAA') }
  )
  foreach ($target in $relatedTargets) {
    try {
      foreach ($row in @(Resolve-DnsRecordsDetailed -Name $target.Name -Types $target.Types)) {
        if ($row) { $records.Add($row) }
      }
    }
    catch {
      $errors.Add($_.Exception.Message)
    }
  }

  # CNAME-target follow-up: when a related-name probe returns a CNAME row,
  # explicitly query the CNAME's target hostname for TXT records (and CNAME,
  # in case of a multi-hop chain). `Resolve-DnsName -Type TXT` follows CNAME
  # chains inconsistently across resolvers/runs -- sometimes it emits the
  # target's TXT and sometimes it does not -- which previously produced
  # asymmetric output (e.g., DKIM TXT shown for selector1 but not selector2).
  # Probing the targets explicitly makes the records grid deterministic and
  # symmetric for all CNAME-fronted records (DKIM selectors, www aliases,
  # etc.). Each target is probed once even if multiple parents point at it.
  $cnameFollowupTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  # PowerShell 7.6 regression: wrapping a List[object] with @(...) (e.g.,
  # @($records)) throws "Argument types do not match". Materialize the list
  # via .ToArray() before iterating so this loop survives on PS 7.6+.
  foreach ($record in $records.ToArray()) {
    if (-not $record) { continue }
    if ([string]$record.type -ne 'CNAME') { continue }
    $cnameTarget = ([string]$record.data).Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($cnameTarget)) { continue }
    [void]$cnameFollowupTargets.Add($cnameTarget)
  }
  foreach ($cnameTarget in $cnameFollowupTargets) {
    try {
      foreach ($row in @(Resolve-DnsRecordsDetailed -Name $cnameTarget -Types @('CNAME', 'TXT'))) {
        if ($row) { $records.Add($row) }
      }
    }
    catch {
      $errors.Add($_.Exception.Message)
    }
  }

  $uniqueRecords = @(
    $records |
      Where-Object { $_ } |
      Group-Object -Property name, type, data |
      ForEach-Object {
        $groupRecords = @($_.Group)
        $selected = $groupRecords |
          Sort-Object @{ Expression = { if ($null -ne $_.ttlSeconds) { [int]$_.ttlSeconds } else { -1 } }; Descending = $true } |
          Select-Object -First 1

        if ($null -eq $selected) { return }

        [pscustomobject]@{
          name = $selected.name
          class = $selected.class
          type = $selected.type
          data = $selected.data
          ttlSeconds = $selected.ttlSeconds
          details = @($selected.details)
        }
      } |
      Sort-Object name, type, data, ttlSeconds
  )
  $errorText = $null
  if ($uniqueRecords.Count -eq 0 -and $errors.Count -gt 0) {
    $errorText = ($errors | Select-Object -Unique) -join ' '
  }

  [pscustomobject]@{
    domain = $Domain
    records = $uniqueRecords
    error = $errorText
  }
}

# ------------------- INPUT NORMALIZATION -------------------
# Normalize raw user input into a clean domain name.
# Accepts: plain domain, email address (takes part after @), or URL (extracts hostname).
# Strips wildcard prefixes (*.) and surrounding dots, then lowercases the result.
