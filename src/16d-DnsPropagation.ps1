# ===== Global DNS Propagation Check =====
# ------------------- DNS PROPAGATION PROBE -------------------
# This check answers the other question operators hit constantly: "I added the
# record -- has it actually propagated everywhere yet?"
#
# A single recursive resolver (the one this server uses) can only ever tell you
# what THAT resolver currently has cached. When a zone was just edited, when the
# authoritative nameservers are out of sync, or when a stale delegation is still
# being served, different public resolvers around the world return DIFFERENT
# answers for the same name. Azure Communication Services verifies domains
# through public DNS, so a record that is only visible from some vantage points
# will verify intermittently (or not at all).
#
# We therefore query a curated catalog of well-known public DNS resolvers spread
# across regions and compare their answers:
#   * every responder returns the same non-empty answer  -> fully propagated
#   * some responders have the record, others do not     -> still propagating
#   * responders return DIFFERENT non-empty answers      -> inconsistent answers
#
# DESIGN NOTES
#
# 1) NO bulk resolver dataset. The standalone propagation tool ships a 60k-row
#    public-dns.info CSV plus a processed cache. That is far too heavy for this
#    single-file app, so we embed a small, curated, geographically spread
#    catalog instead. Operators can override it entirely with
#    ACS_PROPAGATION_RESOLVERS (see Get-DnsPropagationResolverCatalog).
#
# 2) SINGLE-THREADED PARALLEL I/O. We deliberately do NOT use
#    [Parallel]::ForEach here. That helper invokes PowerShell functions on .NET
#    worker threads that share ONE runspace, which is not thread-safe. Instead
#    we open one UDP socket per resolver, send every query up front, and then
#    wait on all sockets at once with [Socket]::Select. That is genuinely
#    concurrent at the network level, completes in roughly one timeout window
#    regardless of resolver count, and touches no PowerShell state concurrently.
#
# 3) EDNS0. Each query advertises a 4096-byte UDP payload size (RFC 6891) so
#    large TXT/DKIM answers come back in one datagram. Truncated answers still
#    get a bounded, sequential TCP retry pass.
#
# SECURITY: the resolver list is operator-controlled (never derived from the
# queried domain), every entry is validated as a public IP literal via
# Test-IsPublicIpAddress (16b-WebsiteProbe.ps1) before a socket is opened, the
# fan-out size is capped, and both the socket timeout and the receive buffer are
# bounded so a hostile resolver cannot pin a worker or exhaust memory.

# Map a user-facing record type to its DNS QTYPE code. Returns 0 for anything we
# do not support, which the caller treats as a validation failure.
function Get-DnsPropagationTypeCode {
  param([string]$RecordType)

  switch (([string]$RecordType).Trim().ToUpperInvariant()) {
    'A'     { return 1 }
    'NS'    { return 2 }
    'CNAME' { return 5 }
    'SOA'   { return 6 }
    'MX'    { return 15 }
    'TXT'   { return 16 }
    'AAAA'  { return 28 }
    'CAA'   { return 257 }
    default { return 0 }
  }
}

# The curated public-resolver catalog.
#
# Each entry carries the geography we render on the mini map. `anycast` marks
# operators that announce the same address from many points of presence: those
# resolvers answer from the POP nearest to THIS server, so the coordinates are
# the operator's primary location rather than where the query was actually
# served. The UI renders them with a distinct marker and says so.
#
# Regions: global (large anycast networks), namer, samer, europe, asia, oceania.
#
# Operators can replace the whole catalog with ACS_PROPAGATION_RESOLVERS using a
# simple pipe-delimited, semicolon-separated format:
#   ip|provider|countryCode|city|lat|lon|region|anycast(0|1); ip|...
# Malformed entries are skipped; if nothing valid parses we fall back to the
# built-in catalog so the check never silently degrades to zero resolvers.
function Get-DnsPropagationResolverCatalog {
  $builtIn = @(
    # ---- Large anycast networks (global reach, answered from the nearest POP) ----
    [pscustomobject]@{ ip = '1.1.1.1';         provider = 'Cloudflare';            countryCode = 'US'; city = 'San Francisco'; latitude = 37.77;  longitude = -122.42; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '8.8.8.8';         provider = 'Google Public DNS';     countryCode = 'US'; city = 'Mountain View'; latitude = 37.42;  longitude = -122.08; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '9.9.9.9';         provider = 'Quad9';                 countryCode = 'CH'; city = 'Zurich';        latitude = 47.37;  longitude = 8.54;    region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '208.67.222.222';  provider = 'OpenDNS (Cisco)';       countryCode = 'US'; city = 'San Jose';      latitude = 37.33;  longitude = -121.89; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '94.140.14.14';    provider = 'AdGuard DNS';           countryCode = 'CY'; city = 'Limassol';      latitude = 34.71;  longitude = 33.02;   region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '45.90.28.0';      provider = 'NextDNS';               countryCode = 'FR'; city = 'Paris';         latitude = 48.86;  longitude = 2.35;    region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '193.110.81.0';    provider = 'dns0.eu';               countryCode = 'DE'; city = 'Berlin';        latitude = 52.52;  longitude = 13.40;   region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '76.76.2.0';       provider = 'Control D';             countryCode = 'CA'; city = 'Toronto';       latitude = 43.65;  longitude = -79.38;  region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '185.228.168.9';   provider = 'CleanBrowsing';         countryCode = 'US'; city = 'Washington';    latitude = 38.90;  longitude = -77.04;  region = 'global'; anycast = $true }

    # ---- North America ----
    [pscustomobject]@{ ip = '4.2.2.1';         provider = 'Lumen (Level 3)';       countryCode = 'US'; city = 'Broomfield';    latitude = 39.92;  longitude = -105.09; region = 'namer';  anycast = $true }
    [pscustomobject]@{ ip = '74.82.42.42';     provider = 'Hurricane Electric';    countryCode = 'US'; city = 'Fremont';       latitude = 37.55;  longitude = -121.99; region = 'namer';  anycast = $false }
    [pscustomobject]@{ ip = '149.112.121.10';  provider = 'CIRA Canadian Shield';  countryCode = 'CA'; city = 'Toronto';       latitude = 43.65;  longitude = -79.38;  region = 'namer';  anycast = $true }
    [pscustomobject]@{ ip = '156.154.70.1';    provider = 'Vercara UltraDNS';      countryCode = 'US'; city = 'Sterling';      latitude = 39.01;  longitude = -77.42;  region = 'namer';  anycast = $true }

    # ---- South America ----
    [pscustomobject]@{ ip = '200.221.11.100';  provider = 'UOL DNS';               countryCode = 'BR'; city = 'Sao Paulo';     latitude = -23.55; longitude = -46.63;  region = 'samer';  anycast = $false }

    # ---- Europe ----
    [pscustomobject]@{ ip = '84.200.69.80';    provider = 'DNS.WATCH';             countryCode = 'DE'; city = 'Frankfurt';     latitude = 50.11;  longitude = 8.68;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '91.239.100.100';  provider = 'UncensoredDNS';         countryCode = 'DK'; city = 'Copenhagen';    latitude = 55.68;  longitude = 12.57;   region = 'europe'; anycast = $true }
    [pscustomobject]@{ ip = '89.233.43.71';    provider = 'UncensoredDNS (unicast)'; countryCode = 'DK'; city = 'Copenhagen';  latitude = 55.68;  longitude = 12.57;   region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.67.169.12';    provider = 'FDN';                   countryCode = 'FR'; city = 'Paris';         latitude = 48.86;  longitude = 2.35;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '46.182.19.48';    provider = 'Digitale Gesellschaft'; countryCode = 'CH'; city = 'Zurich';        latitude = 47.37;  longitude = 8.54;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.88.8.8';       provider = 'Yandex DNS';            countryCode = 'RU'; city = 'Moscow';        latitude = 55.76;  longitude = 37.62;   region = 'europe'; anycast = $true }
    [pscustomobject]@{ ip = '194.150.168.168'; provider = 'AS250.net';             countryCode = 'DE'; city = 'Berlin';        latitude = 52.52;  longitude = 13.40;   region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.80.80.80';     provider = 'Freenom World';         countryCode = 'NL'; city = 'Amsterdam';     latitude = 52.37;  longitude = 4.90;    region = 'europe'; anycast = $true }

    # ---- Asia ----
    [pscustomobject]@{ ip = '223.5.5.5';       provider = 'AliDNS';                countryCode = 'CN'; city = 'Hangzhou';      latitude = 30.27;  longitude = 120.16;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '119.29.29.29';    provider = 'DNSPod (Tencent)';      countryCode = 'CN'; city = 'Shenzhen';      latitude = 22.54;  longitude = 114.06;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '114.114.114.114'; provider = '114DNS';                countryCode = 'CN'; city = 'Nanjing';       latitude = 32.06;  longitude = 118.80;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '180.76.76.76';    provider = 'Baidu DNS';             countryCode = 'CN'; city = 'Beijing';       latitude = 39.90;  longitude = 116.41;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '168.126.63.1';    provider = 'KT (Korea Telecom)';    countryCode = 'KR'; city = 'Seoul';         latitude = 37.57;  longitude = 126.98;  region = 'asia';   anycast = $false }
    [pscustomobject]@{ ip = '203.248.252.2';   provider = 'LG U+';                 countryCode = 'KR'; city = 'Seoul';         latitude = 37.57;  longitude = 126.98;  region = 'asia';   anycast = $false }
    [pscustomobject]@{ ip = '129.250.35.250';  provider = 'NTT';                   countryCode = 'JP'; city = 'Tokyo';         latitude = 35.68;  longitude = 139.69;  region = 'asia';   anycast = $true }

    # ---- Oceania ----
    [pscustomobject]@{ ip = '139.130.4.5';     provider = 'Telstra';               countryCode = 'AU'; city = 'Sydney';        latitude = -33.87; longitude = 151.21;  region = 'oceania'; anycast = $false }
  )

  $override = [string]$env:ACS_PROPAGATION_RESOLVERS
  if ([string]::IsNullOrWhiteSpace($override)) { return $builtIn }

  # NOTE: use ::new() rather than `New-Object ...List[object]` throughout this
  # file. On PowerShell 7.6 / .NET 10 a List[object] built with New-Object throws
  # "Argument types do not match" the moment it is wrapped in @( ... ).
  $custom = [System.Collections.Generic.List[object]]::new()
  foreach ($entry in ($override -split ';')) {
    $parts = ($entry -split '\|')
    if ($parts.Count -lt 1) { continue }
    $ip = ([string]$parts[0]).Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    $lat = 0.0
    $lon = 0.0
    if ($parts.Count -gt 4) { [void][double]::TryParse(([string]$parts[4]).Trim(), [ref]$lat) }
    if ($parts.Count -gt 5) { [void][double]::TryParse(([string]$parts[5]).Trim(), [ref]$lon) }

    $custom.Add([pscustomobject]@{
      ip          = $ip
      provider    = if ($parts.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($parts[1])) { ([string]$parts[1]).Trim() } else { $ip }
      countryCode = if ($parts.Count -gt 2) { ([string]$parts[2]).Trim().ToUpperInvariant() } else { '' }
      city        = if ($parts.Count -gt 3) { ([string]$parts[3]).Trim() } else { '' }
      latitude    = $lat
      longitude   = $lon
      region      = if ($parts.Count -gt 6 -and -not [string]::IsNullOrWhiteSpace($parts[6])) { ([string]$parts[6]).Trim().ToLowerInvariant() } else { 'global' }
      anycast     = ($parts.Count -gt 7 -and ([string]$parts[7]).Trim() -eq '1')
    })
  }

  if ($custom.Count -eq 0) { return $builtIn }
  return @($custom)
}

# Pick the resolvers to query for one propagation run.
#
# The selection is deliberately *balanced*: we round-robin across the requested
# regions so a small MaxResolvers budget still produces a geographically spread
# sample instead of, say, five Chinese resolvers. Within a region the catalog
# order is preserved so results are stable and reproducible across runs (the
# card would otherwise flicker between lookups for no reason).
function Select-DnsPropagationResolvers {
  param(
    [string[]]$Regions = @(),
    [int]$MaxResolvers = 25
  )

  $catalog = @(Get-DnsPropagationResolverCatalog)

  # Only keep entries whose IP literal is public and parseable. This is the SSRF
  # guard for the operator-supplied ACS_PROPAGATION_RESOLVERS override.
  $usable = [System.Collections.Generic.List[object]]::new()
  foreach ($item in $catalog) {
    if ($null -eq $item) { continue }
    $ip = ([string]$item.ip).Trim()
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) { continue }
    # IPv4 only: many hosts (and most containers) have no working IPv6 path, and
    # a v6-only resolver would show up as a false "unavailable" data point.
    if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
    if (-not (Test-IsPublicIpAddress -IpAddress $ip)) { continue }
    $usable.Add($item)
  }

  $wanted = @($Regions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
  if ($wanted.Count -gt 0) {
    $filtered = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $usable) {
      if ($wanted -contains ([string]$item.region).ToLowerInvariant()) { $filtered.Add($item) }
    }
    $usable = $filtered
  }

  if ($usable.Count -eq 0) { return @() }
  if ($MaxResolvers -le 0 -or $MaxResolvers -ge $usable.Count) { return $usable.ToArray() }

  # Group by region (preserving catalog order inside each group), then take one
  # from each group in turn until the budget is spent.
  $groups = [ordered]@{}
  foreach ($item in $usable) {
    $key = ([string]$item.region).ToLowerInvariant()
    if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
    $groups[$key].Add($item)
  }

  $selected = [System.Collections.Generic.List[object]]::new()
  $index = 0
  while ($selected.Count -lt $MaxResolvers) {
    $addedThisPass = $false
    foreach ($key in @($groups.Keys)) {
      if ($selected.Count -ge $MaxResolvers) { break }
      $bucket = $groups[$key]
      if ($index -lt $bucket.Count) {
        $selected.Add($bucket[$index])
        $addedThisPass = $true
      }
    }
    if (-not $addedThisPass) { break }
    $index++
  }

  return $selected.ToArray()
}

# Read a (possibly compressed) DNS name starting at $Offset.
#
# Returns a hashtable @{ name = 'label.label'; next = <offset after the name> }.
# `next` is the offset immediately after the name AS ENCODED AT $Offset, so a
# compression pointer consumes exactly 2 bytes even though the name continues
# elsewhere in the message. A hop budget defends against pointer loops in a
# malformed/hostile response.
function Read-DnsNameFromBuffer {
  param([byte[]]$Buffer, [int]$Offset)

  $labels = New-Object System.Collections.Generic.List[string]
  $pos = $Offset
  $next = -1
  $hops = 0

  while ($true) {
    if ($pos -lt 0 -or $pos -ge $Buffer.Length) { break }
    $len = [int]$Buffer[$pos]

    if ($len -eq 0) {
      if ($next -lt 0) { $next = $pos + 1 }
      break
    }

    if (($len -band 0xC0) -eq 0xC0) {
      if (($pos + 1) -ge $Buffer.Length) { break }
      if ($next -lt 0) { $next = $pos + 2 }
      $hops++
      if ($hops -gt 24) { break }
      $pos = ((($len -band 0x3F) -shl 8) -bor [int]$Buffer[$pos + 1])
      continue
    }

    if ($len -gt 63) { break }
    $start = $pos + 1
    if (($start + $len) -gt $Buffer.Length) { break }
    $labels.Add([System.Text.Encoding]::ASCII.GetString($Buffer, $start, $len))
    $pos = $start + $len
  }

  if ($next -lt 0) { $next = $pos }
  return @{ name = ($labels -join '.'); next = $next }
}

# Convert one resource record's RDATA into the display string we compare across
# resolvers. Unsupported types fall back to lowercase hex so a mismatch is still
# detectable even when we cannot pretty-print the payload.
function ConvertFrom-DnsPropagationRdata {
  param(
    [byte[]]$Buffer,
    [int]$Type,
    [int]$RdataOffset,
    [int]$RdLength
  )

  if ($RdLength -le 0 -or ($RdataOffset + $RdLength) -gt $Buffer.Length) { return $null }
  $end = $RdataOffset + $RdLength

  switch ($Type) {
    1 {
      # A
      if ($RdLength -ne 4) { return $null }
      return ('{0}.{1}.{2}.{3}' -f $Buffer[$RdataOffset], $Buffer[$RdataOffset + 1], $Buffer[$RdataOffset + 2], $Buffer[$RdataOffset + 3])
    }
    28 {
      # AAAA -- let IPAddress do the canonical (compressed) formatting.
      if ($RdLength -ne 16) { return $null }
      $raw = New-Object byte[] 16
      [Array]::Copy($Buffer, $RdataOffset, $raw, 0, 16)
      try { return ([System.Net.IPAddress]::new($raw)).ToString() } catch { return $null }
    }
    16 {
      # TXT: one or more <character-string>s, concatenated with no separator
      # (RFC 7208) so a split long record reassembles into the original value.
      $sb = New-Object System.Text.StringBuilder
      $p = $RdataOffset
      while ($p -lt $end) {
        $clen = [int]$Buffer[$p]; $p++
        if (($p + $clen) -gt $end) { break }
        if ($clen -gt 0) {
          [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($Buffer, $p, $clen))
          $p += $clen
        }
      }
      $value = $sb.ToString().Trim()
      if ([string]::IsNullOrWhiteSpace($value)) { return $null }
      return $value
    }
    15 {
      # MX: 16-bit preference followed by the exchange name.
      if ($RdLength -lt 3) { return $null }
      $pref = (([int]$Buffer[$RdataOffset]) -shl 8) -bor [int]$Buffer[$RdataOffset + 1]
      $parsed = Read-DnsNameFromBuffer -Buffer $Buffer -Offset ($RdataOffset + 2)
      if ([string]::IsNullOrWhiteSpace($parsed.name)) { return $null }
      return ('{0} {1}' -f $pref, $parsed.name.ToLowerInvariant())
    }
    257 {
      # CAA: flags(1) tag-length(1) tag value
      if ($RdLength -lt 3) { return $null }
      $flags = [int]$Buffer[$RdataOffset]
      $tagLen = [int]$Buffer[$RdataOffset + 1]
      $tagStart = $RdataOffset + 2
      if (($tagStart + $tagLen) -gt $end) { return $null }
      $tag = [System.Text.Encoding]::ASCII.GetString($Buffer, $tagStart, $tagLen)
      $valStart = $tagStart + $tagLen
      $val = ''
      if ($valStart -lt $end) { $val = [System.Text.Encoding]::UTF8.GetString($Buffer, $valStart, ($end - $valStart)) }
      return ('{0} {1} "{2}"' -f $flags, $tag, $val)
    }
    6 {
      # SOA: mname rname serial refresh retry expire minimum. Only the primary
      # nameserver and serial are worth comparing across resolvers -- a serial
      # difference is the clearest signal that a zone transfer is still in flight.
      $mname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $RdataOffset
      $rname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $mname.next
      $p = $rname.next
      if (($p + 4) -gt $end) { return $null }
      $serial = ((([long]$Buffer[$p]) -shl 24) -bor (([long]$Buffer[$p + 1]) -shl 16) -bor (([long]$Buffer[$p + 2]) -shl 8) -bor ([long]$Buffer[$p + 3]))
      return ('{0} {1} {2}' -f $mname.name.ToLowerInvariant(), $rname.name.ToLowerInvariant(), $serial)
    }
    default {
      # NS (2), CNAME (5), PTR (12) and anything else name-shaped.
      if ($Type -eq 2 -or $Type -eq 5 -or $Type -eq 12) {
        $parsed = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $RdataOffset
        if ([string]::IsNullOrWhiteSpace($parsed.name)) { return $null }
        return $parsed.name.ToLowerInvariant()
      }
      $hex = New-Object System.Text.StringBuilder
      for ($i = $RdataOffset; $i -lt $end; $i++) { [void]$hex.Append($Buffer[$i].ToString('x2')) }
      return $hex.ToString()
    }
  }
}

# Build a recursive DNS query packet for $Name / $TypeCode.
#
# RD (recursion desired) is 1 here -- unlike the authoritative probe in
# 16c-NameserverChecks.ps1 we WANT each public resolver's own recursive view,
# cache and all, because that is exactly what a real client (and Azure) sees.
# An EDNS0 OPT record advertises a 4096-byte UDP payload so large TXT sets are
# not truncated.
function New-DnsPropagationQueryPacket {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][int]$TypeCode,
    [Parameter(Mandatory = $true)][int]$TransactionId
  )

  $packet = New-Object System.Collections.Generic.List[byte]

  # ---- Header (12 bytes) ----
  $packet.Add([byte](($TransactionId -shr 8) -band 0xFF))
  $packet.Add([byte]($TransactionId -band 0xFF))
  $packet.Add([byte]0x01)                            # QR=0 Opcode=0 AA=0 TC=0 RD=1
  $packet.Add([byte]0x00)                            # RA=0 Z=0 RCODE=0
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)   # QDCOUNT = 1
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # ANCOUNT = 0
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # NSCOUNT = 0
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)   # ARCOUNT = 1 (the OPT record)

  # ---- Question ----
  foreach ($label in ($Name -split '\.')) {
    if ([string]::IsNullOrEmpty($label)) { continue }
    $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
    if ($labelBytes.Length -gt 63) { throw 'DNS label exceeds 63 octets.' }
    $packet.Add([byte]$labelBytes.Length)
    $packet.AddRange($labelBytes)
  }
  $packet.Add([byte]0)                                                   # root label
  $packet.Add([byte](($TypeCode -shr 8) -band 0xFF))
  $packet.Add([byte]($TypeCode -band 0xFF))                              # QTYPE
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)                       # QCLASS = IN

  # ---- Additional: EDNS0 OPT (RFC 6891) ----
  $packet.Add([byte]0x00)                            # NAME = root
  $packet.Add([byte]0x00); $packet.Add([byte]0x29)   # TYPE = 41 (OPT)
  $packet.Add([byte]0x10); $packet.Add([byte]0x00)   # CLASS = 4096 UDP payload size
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # extended RCODE + version
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # flags (DO=0)
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # RDLENGTH = 0

  return , ($packet.ToArray())
}

# Parse a DNS response into @{ rcode; rcodeLabel; truncated; answers[] }.
# Answers are filtered to the requested QTYPE so a CNAME chain returned
# alongside an A lookup does not pollute the comparison, EXCEPT when the caller
# asked for CNAME itself.
function Read-DnsPropagationResponse {
  param(
    [byte[]]$Buffer,
    [int]$TransactionId,
    [int]$TypeCode
  )

  $parsed = @{ rcode = $null; rcodeLabel = $null; truncated = $false; answers = @(); error = $null }

  if ($null -eq $Buffer -or $Buffer.Length -lt 12) {
    $parsed.error = 'Short DNS response.'
    return $parsed
  }

  # Cast to [int] BEFORE shifting: PowerShell's -shl on a [byte] truncates back
  # to 8 bits, silently zeroing the high half of every 16-bit field.
  $respId = ([int]$Buffer[0] -shl 8) -bor [int]$Buffer[1]
  if ($respId -ne $TransactionId) {
    $parsed.error = 'DNS transaction ID mismatch.'
    return $parsed
  }

  $parsed.truncated = (($Buffer[2] -band 0x02) -ne 0)
  $rcode = ($Buffer[3] -band 0x0F)
  $parsed.rcode = $rcode
  $parsed.rcodeLabel = switch ($rcode) {
    0 { 'NOERROR' }
    1 { 'FORMERR' }
    2 { 'SERVFAIL' }
    3 { 'NXDOMAIN' }
    4 { 'NOTIMP' }
    5 { 'REFUSED' }
    default { "RCODE $rcode" }
  }

  $qdCount = ([int]$Buffer[4] -shl 8) -bor [int]$Buffer[5]
  $anCount = ([int]$Buffer[6] -shl 8) -bor [int]$Buffer[7]

  # Skip the question section.
  $offset = 12
  for ($q = 0; $q -lt $qdCount; $q++) {
    $name = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $offset
    $offset = $name.next + 4   # QTYPE + QCLASS
  }

  $answers = New-Object System.Collections.Generic.List[string]
  for ($a = 0; $a -lt $anCount; $a++) {
    if ($offset -ge $Buffer.Length) { break }
    $owner = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $offset
    $offset = $owner.next
    if (($offset + 10) -gt $Buffer.Length) { break }

    $type = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
    $offset += 8   # TYPE (2) + CLASS (2) + TTL (4)
    $rdLength = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
    $offset += 2
    if (($offset + $rdLength) -gt $Buffer.Length) { break }

    if ($type -eq $TypeCode) {
      $value = ConvertFrom-DnsPropagationRdata -Buffer $Buffer -Type $type -RdataOffset $offset -RdLength $rdLength
      if (-not [string]::IsNullOrWhiteSpace($value)) { $answers.Add($value) }
    }

    $offset += $rdLength
  }

  # Sorted so two resolvers returning the same record set in a different order
  # (round-robin rotation is standard) still produce an identical signature.
  $parsed.answers = @($answers | Sort-Object)
  return $parsed
}

# Recover truncated (TC=1) answers by re-asking the affected resolvers over TCP,
# concurrently.
#
# EDNS0 keeps truncation rare, but domains with very large TXT sets (dozens of
# verification tokens) still overflow a 4096-byte UDP datagram. Retrying those
# sequentially would add one full timeout PER resolver to the request, so this
# uses the same non-blocking + [Socket]::Select pattern as the UDP fan-out:
# every connection is opened and driven forward in one loop, so the whole
# recovery pass costs about one timeout window no matter how many resolvers
# need it.
#
# TCP DNS frames the message with a 2-byte big-endian length prefix in both
# directions (RFC 1035 4.2.2), and TCP is a stream, so each socket accumulates
# bytes until the declared length has arrived.
#
# $Queries maps resolver IP -> query packet. Returns resolver IP -> response bytes
# for the resolvers that answered.
function Invoke-DnsPropagationTcpFanout {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Queries,
    [int]$TimeoutMs = 4000
  )

  $responses = @{}
  if ($Queries.Count -eq 0) { return $responses }

  $states = @{}       # socket -> per-connection state
  $sockets = [System.Collections.Generic.List[System.Net.Sockets.Socket]]::new()
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

  try {
    foreach ($ip in @($Queries.Keys)) {
      $parsedIp = $null
      if (-not [System.Net.IPAddress]::TryParse(([string]$ip).Trim(), [ref]$parsedIp)) { continue }

      $sock = $null
      try {
        $sock = New-Object System.Net.Sockets.Socket($parsedIp.AddressFamily, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        $sock.Blocking = $false
        try {
          $sock.Connect((New-Object System.Net.IPEndPoint($parsedIp, 53)))
        } catch [System.Net.Sockets.SocketException] {
          # WouldBlock is the expected result of a non-blocking connect; the
          # socket becoming writable is what tells us the handshake finished.
          if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::WouldBlock) { throw }
        }
        # Re-assert non-blocking and add socket-level timeouts: every Send/Receive
        # below happens only after Select reports the socket ready, but these are
        # a hard backstop against a blocking call pinning the request thread.
        $sock.Blocking = $false
        $sock.ReceiveTimeout = $TimeoutMs
        $sock.SendTimeout = $TimeoutMs
        $sockets.Add($sock)
        $states[$sock] = @{
          ip        = [string]$ip
          query     = $Queries[$ip]
          connected = $false
          buffer    = [System.Collections.Generic.List[byte]]::new()
          expected  = -1
        }
      } catch {
        if ($sock) { try { $sock.Dispose() } catch { } }
      }
    }

    $chunk = New-Object byte[] 8192
    while ($states.Count -gt 0) {
      $remainingMs = $TimeoutMs - $stopwatch.ElapsedMilliseconds
      if ($remainingMs -le 0) { break }

      # Select() empties the lists it is handed, so rebuild them every pass.
      # Sockets still handshaking are watched for writability; connected ones
      # for readability.
      $writeList = New-Object System.Collections.ArrayList
      $readList = New-Object System.Collections.ArrayList
      $errorList = New-Object System.Collections.ArrayList
      foreach ($sock in $states.Keys) {
        if ($states[$sock].connected) { [void]$readList.Add($sock) } else { [void]$writeList.Add($sock) }
        [void]$errorList.Add($sock)
      }

      $waitMicroseconds = [int]([Math]::Min(500000, [Math]::Max(1000, $remainingMs * 1000)))
      # Pass the ArrayLists through plain variables. A $( if (...) { $list } )
      # subexpression would ENUMERATE the list and hand Select a fixed-size
      # object[] copy instead, so Select could not strip the not-ready sockets
      # and we would go on to Receive() from sockets with nothing to read.
      $readArg = $null
      if ($readList.Count -gt 0) { $readArg = $readList }
      $writeArg = $null
      if ($writeList.Count -gt 0) { $writeArg = $writeList }
      try {
        [System.Net.Sockets.Socket]::Select($readArg, $writeArg, $errorList, $waitMicroseconds)
      } catch {
        break
      }

      foreach ($sock in @($errorList)) {
        [void]$states.Remove($sock)
      }

      # Newly connected sockets: send the framed query.
      foreach ($sock in @($writeList)) {
        $state = $states[$sock]
        if ($null -eq $state -or $state.connected) { continue }
        try {
          $query = $state.query
          $framed = New-Object byte[] (2 + $query.Length)
          $framed[0] = [byte](($query.Length -shr 8) -band 0xFF)
          $framed[1] = [byte]($query.Length -band 0xFF)
          [Array]::Copy($query, 0, $framed, 2, $query.Length)
          [void]$sock.Send($framed)
          $state.connected = $true
        } catch {
          [void]$states.Remove($sock)
        }
      }

      # Readable sockets: accumulate until the declared message length arrives.
      foreach ($sock in @($readList)) {
        $state = $states[$sock]
        if ($null -eq $state) { continue }
        try {
          $received = $sock.Receive($chunk)
          if ($received -le 0) { [void]$states.Remove($sock); continue }
          for ($i = 0; $i -lt $received; $i++) { $state.buffer.Add($chunk[$i]) }

          if ($state.expected -lt 0 -and $state.buffer.Count -ge 2) {
            $state.expected = ([int]$state.buffer[0] -shl 8) -bor [int]$state.buffer[1]
            if ($state.expected -le 0 -or $state.expected -gt 65535) { [void]$states.Remove($sock); continue }
          }
          if ($state.expected -ge 0 -and $state.buffer.Count -ge ($state.expected + 2)) {
            $message = New-Object byte[] $state.expected
            $state.buffer.CopyTo(2, $message, 0, $state.expected)
            $responses[$state.ip] = $message
            [void]$states.Remove($sock)
          }
        } catch {
          [void]$states.Remove($sock)
        }
      }
    }
  } finally {
    foreach ($sock in $sockets) { try { $sock.Dispose() } catch { } }
    $stopwatch.Stop()
  }

  return $responses
}


# Query every resolver in $Resolvers concurrently and return the raw outcome for
# each one, keyed by resolver IP.
#
# HOW THE CONCURRENCY WORKS: we open one connected UDP socket per resolver and
# send every query before waiting for anything. Then we block in
# [Socket]::Select on the whole set, draining whichever sockets became readable,
# until either all resolvers answered or the deadline expires. The total wall
# time is therefore ~one timeout window no matter how many resolvers we query,
# and -- crucially -- no PowerShell code ever runs on more than one thread, so
# this is safe inside the shared request runspace pool.
#
# Returns a hashtable: ip -> @{ answers[]; rcode; rcodeLabel; transport; responseMs; error; truncated }
function Invoke-DnsPropagationFanout {
  param(
    [Parameter(Mandatory = $true)][object[]]$Resolvers,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][int]$TypeCode,
    [int]$TimeoutMs = 4000
  )

  $outcomes = @{}
  if ($Resolvers.Count -eq 0) { return $outcomes }

  $pending = @{}          # socket -> state
  $sockets = [System.Collections.Generic.List[System.Net.Sockets.Socket]]::new()
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

  try {
    foreach ($resolver in $Resolvers) {
      $ip = ([string]$resolver.ip).Trim()
      $outcomes[$ip] = @{ answers = @(); rcode = $null; rcodeLabel = $null; transport = $null; responseMs = $null; error = 'No response from resolver (UDP timeout).'; truncated = $false; query = $null; txid = 0 }

      $parsedIp = $null
      if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) {
        $outcomes[$ip].error = 'Invalid resolver IP.'
        continue
      }

      $txid = Get-Random -Minimum 1 -Maximum 65535
      $query = $null
      try {
        $query = New-DnsPropagationQueryPacket -Name $Name -TypeCode $TypeCode -TransactionId $txid
      } catch {
        $outcomes[$ip].error = 'Failed to build DNS query.'
        continue
      }
      $outcomes[$ip].query = $query
      $outcomes[$ip].txid = $txid

      $sock = $null
      try {
        $sock = New-Object System.Net.Sockets.Socket($parsedIp.AddressFamily, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $sock.Blocking = $false
        $sock.Connect((New-Object System.Net.IPEndPoint($parsedIp, 53)))
        [void]$sock.Send($query)
        $sockets.Add($sock)
        $pending[$sock] = @{ ip = $ip; txid = $txid; sentAtMs = $stopwatch.ElapsedMilliseconds }
      } catch {
        $outcomes[$ip].error = 'Could not send query to resolver.'
        if ($sock) { try { $sock.Dispose() } catch { } }
      }
    }

    # ---- Wait for answers on all sockets at once ----
    $deadlineMs = $TimeoutMs
    $buffer = New-Object byte[] 4096
    while ($pending.Count -gt 0) {
      $remainingMs = $deadlineMs - $stopwatch.ElapsedMilliseconds
      if ($remainingMs -le 0) { break }

      # Select() mutates the list it is given (leaving only ready sockets), so
      # rebuild it from the still-pending set on every iteration.
      $readList = New-Object System.Collections.ArrayList
      foreach ($sock in $pending.Keys) { [void]$readList.Add($sock) }

      # Cap the per-iteration wait so we re-evaluate the deadline regularly.
      $waitMicroseconds = [int]([Math]::Min(500000, [Math]::Max(1000, $remainingMs * 1000)))
      try {
        [System.Net.Sockets.Socket]::Select($readList, $null, $null, $waitMicroseconds)
      } catch {
        break
      }
      if ($readList.Count -eq 0) { continue }

      foreach ($sock in @($readList)) {
        $state = $pending[$sock]
        if ($null -eq $state) { continue }
        $ip = $state.ip
        try {
          $received = $sock.Receive($buffer)
          if ($received -gt 0) {
            $exact = New-Object byte[] $received
            [Array]::Copy($buffer, 0, $exact, 0, $received)
            $parsed = Read-DnsPropagationResponse -Buffer $exact -TransactionId $state.txid -TypeCode $TypeCode
            if ($parsed.error) {
              # A stray/mismatched datagram: keep waiting on this socket rather
              # than accepting an answer we cannot attribute to our query.
              continue
            }
            $outcomes[$ip].answers = @($parsed.answers)
            $outcomes[$ip].rcode = $parsed.rcode
            $outcomes[$ip].rcodeLabel = $parsed.rcodeLabel
            $outcomes[$ip].truncated = $parsed.truncated
            $outcomes[$ip].transport = 'udp'
            $outcomes[$ip].responseMs = [int]($stopwatch.ElapsedMilliseconds - $state.sentAtMs)
            $outcomes[$ip].error = $null
          }
        } catch {
          $outcomes[$ip].error = 'Resolver connection error.'
        }
        [void]$pending.Remove($sock)
      }
    }
  } finally {
    foreach ($sock in $sockets) { try { $sock.Dispose() } catch { } }
    $stopwatch.Stop()
  }

  # ---- Concurrent TCP recovery pass for truncated answers ----
  # A TC=1 answer is NOT "no record" -- it means the answer did not fit in the
  # UDP datagram. Re-ask over TCP (all affected resolvers at once) so a domain
  # with a very large TXT set is still measured accurately. Anything still
  # truncated afterwards is reported as such and excluded from the verdict
  # rather than being silently misread as a missing record.
  $tcpQueries = @{}
  foreach ($ip in @($outcomes.Keys)) {
    $outcome = $outcomes[$ip]
    if ($outcome.truncated -and $null -ne $outcome.query) { $tcpQueries[$ip] = $outcome.query }
  }
  if ($tcpQueries.Count -gt 0) {
    $tcpResponses = Invoke-DnsPropagationTcpFanout -Queries $tcpQueries -TimeoutMs $TimeoutMs
    foreach ($ip in @($tcpResponses.Keys)) {
      $outcome = $outcomes[$ip]
      if ($null -eq $outcome) { continue }
      $parsed = Read-DnsPropagationResponse -Buffer $tcpResponses[$ip] -TransactionId $outcome.txid -TypeCode $TypeCode
      if ($parsed.error) { continue }
      $outcome.answers = @($parsed.answers)
      $outcome.rcode = $parsed.rcode
      $outcome.rcodeLabel = $parsed.rcodeLabel
      $outcome.truncated = $parsed.truncated
      $outcome.transport = 'tcp'
      $outcome.error = $null
    }
  }

  # Drop the internal fields the caller does not need (and must not serialize).
  foreach ($ip in @($outcomes.Keys)) {
    $outcomes[$ip].Remove('query')
    $outcomes[$ip].Remove('txid')
  }

  return $outcomes
}

# Orchestrate the propagation check for $Domain.
#
# The verdict is CONSENSUS-based rather than expectation-based: we take the most
# common non-empty answer set across resolvers that actually responded and
# measure everyone else against it. That answers "has my change propagated?"
# without the user having to type in what they expect to see, while an optional
# -ExpectedValue substring lets them assert a specific record when they want to.
#
# Resolvers that did not respond at all are reported but deliberately EXCLUDED
# from the verdict. Public resolvers are frequently rate-limited or firewalled
# from a given network, and a flaky resolver must never turn a healthy domain
# into a FAIL.
#
# Returned payload (stable contract for the SPA):
#   domain, generatedAtUtc, checked, disabledReason, recordType, queryName
#   resolverCount / respondedCount / unavailableCount / answeredCount /
#   emptyCount / matchingCount / mismatchCount / errorCount
#   consensusAnswers[], distinctAnswerSets, propagationPercent
#   state    : 'propagated' | 'partial' | 'mismatch' | 'norecord' | 'unknown'
#   summary  : short server-side fallback sentence key
#   regions[], availableRegions[], results[], locations[]
function Get-DnsPropagationStatus {
  param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [string]$RecordType = 'TXT',
    [string[]]$Regions = @(),
    [int]$MaxResolvers = 0,
    [int]$TimeoutMs = 0,
    [string]$ExpectedValue = ''
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  $normalizedType = ([string]$RecordType).Trim().ToUpperInvariant()
  if ([string]::IsNullOrWhiteSpace($normalizedType)) { $normalizedType = 'TXT' }

  $status = [pscustomobject]@{
    domain             = $d
    generatedAtUtc     = ([DateTime]::UtcNow.ToString('o'))
    checked            = $true
    disabledReason     = $null
    recordType         = $normalizedType
    queryName          = $d
    expectedValue      = ([string]$ExpectedValue).Trim()
    expectedProvided   = (-not [string]::IsNullOrWhiteSpace($ExpectedValue))
    timeoutMs          = 0
    resolverCount      = 0
    respondedCount     = 0
    unavailableCount   = 0
    truncatedCount     = 0
    answeredCount      = 0
    emptyCount         = 0
    matchingCount      = 0
    mismatchCount      = 0
    errorCount         = 0
    consensusAnswers   = @()
    distinctAnswerSets = 0
    propagationPercent = 0
    state              = 'unknown'
    summary            = 'Unknown'
    error              = $null
    regions            = @()
    availableRegions   = @()
    results            = @()
    locations          = @()
  }

  if ([string]::IsNullOrWhiteSpace($d)) {
    $status.checked = $false
    $status.error = 'Missing domain.'
    return $status
  }

  # Operator opt-out for networks where outbound UDP/53 is undesirable or blocked.
  if (([string]$env:ACS_DISABLE_PROPAGATION_PROBE).Trim() -eq '1') {
    $status.checked = $false
    $status.summary = 'Disabled'
    $status.disabledReason = 'DNS propagation probe disabled by server configuration.'
    return $status
  }

  $typeCode = Get-DnsPropagationTypeCode -RecordType $normalizedType
  if ($typeCode -eq 0) {
    $status.checked = $false
    $status.error = 'Unsupported record type.'
    return $status
  }

  # ---- Bounded, tunable knobs (mirrors the website / nameserver / RBL checks) ----
  $defaultMax = 25
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_PROPAGATION_MAX_RESOLVERS, [ref]$parsed) -and $parsed -gt 0) {
    $defaultMax = [Math]::Min(100, $parsed)
  }
  $effectiveMax = if ($MaxResolvers -gt 0) { [Math]::Min(100, $MaxResolvers) } else { $defaultMax }

  $defaultTimeout = 4000
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_PROPAGATION_TIMEOUT_MS, [ref]$parsed) -and $parsed -gt 0) {
    $defaultTimeout = [Math]::Min(15000, [Math]::Max(500, $parsed))
  }
  $effectiveTimeout = if ($TimeoutMs -gt 0) { [Math]::Min(15000, [Math]::Max(500, $TimeoutMs)) } else { $defaultTimeout }
  $status.timeoutMs = $effectiveTimeout

  # Advertise the regions the catalog can serve so the SPA settings panel can
  # build its region picker from live server data instead of a hard-coded list.
  $catalog = @(Get-DnsPropagationResolverCatalog)
  $regionCounts = [ordered]@{}
  foreach ($item in $catalog) {
    $key = ([string]$item.region).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) { $key = 'global' }
    if (-not $regionCounts.Contains($key)) { $regionCounts[$key] = 0 }
    $regionCounts[$key]++
  }
  $status.availableRegions = @($regionCounts.Keys | ForEach-Object {
    [pscustomobject]@{ region = $_; resolverCount = $regionCounts[$_] }
  })

  $selected = @(Select-DnsPropagationResolvers -Regions $Regions -MaxResolvers $effectiveMax)
  if ($selected.Count -eq 0) {
    $status.error = 'No public resolvers available for the selected regions.'
    $status.summary = 'NoResolvers'
    return $status
  }
  $status.resolverCount = $selected.Count
  $status.regions = @($selected | ForEach-Object { ([string]$_.region).ToLowerInvariant() } | Sort-Object -Unique)

  $outcomes = Invoke-DnsPropagationFanout -Resolvers $selected -Name $d -TypeCode $typeCode -TimeoutMs $effectiveTimeout

  # ---- Build per-resolver rows ----
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($resolver in $selected) {
    $ip = ([string]$resolver.ip).Trim()
    $outcome = $outcomes[$ip]
    if ($null -eq $outcome) { $outcome = @{ answers = @(); rcode = $null; rcodeLabel = $null; transport = $null; responseMs = $null; error = 'No response.' } }

    $answers = @($outcome.answers)
    # "Responding" means the resolver gave us a usable view of the zone: NOERROR
    # (here is the record / here is nothing) or NXDOMAIN (the name does not
    # exist). A still-truncated answer is unreadable, and SERVFAIL / REFUSED is
    # the resolver failing rather than the domain, so neither is a vantage point
    # we can measure propagation from. Both are reported but kept out of the
    # verdict, the counts, and the map.
    $stillTruncated = [bool]$outcome.truncated
    $responded = (-not $stillTruncated) -and ($outcome.rcode -eq 0 -or $outcome.rcode -eq 3)

    $rows.Add([pscustomobject]@{
      ip          = $ip
      provider    = [string]$resolver.provider
      countryCode = [string]$resolver.countryCode
      city        = [string]$resolver.city
      latitude    = [double]$resolver.latitude
      longitude   = [double]$resolver.longitude
      region      = ([string]$resolver.region).ToLowerInvariant()
      anycast     = [bool]$resolver.anycast
      responded   = $responded
      truncated   = $stillTruncated
      rcode       = $outcome.rcode
      rcodeLabel  = $outcome.rcodeLabel
      transport   = $outcome.transport
      responseMs  = $outcome.responseMs
      answers     = $answers
      # Signature used for cross-resolver comparison. The parser already sorts
      # each set, so a plain join is a stable, order-independent fingerprint.
      signature   = ($answers -join "`n")
      error       = $outcome.error
      status      = 'unavailable'   # refined below
    })
  }

  $responders = @($rows | Where-Object { $_.responded -eq $true })
  $status.respondedCount = $responders.Count
  $status.truncatedCount = @($rows | Where-Object { $_.truncated -eq $true }).Count
  # Answered, but with a resolver-side failure rcode (SERVFAIL/REFUSED/...).
  $status.errorCount = @($rows | Where-Object { $_.responded -ne $true -and $_.truncated -ne $true -and $null -ne $_.rcode }).Count
  $status.unavailableCount = $rows.Count - $status.respondedCount - $status.truncatedCount - $status.errorCount

  if ($responders.Count -eq 0) {
    # Nothing answered: almost always outbound UDP/53 being blocked, not a
    # domain problem, so we report it as indeterminate rather than a failure.
    $status.results = $rows.ToArray()
    $status.state = 'unknown'
    $status.summary = 'NoResponders'
    $status.locations = @()
    return $status
  }

  $withAnswers = @($responders | Where-Object { $_.answers.Count -gt 0 })
  $status.answeredCount = $withAnswers.Count
  $status.emptyCount = $responders.Count - $withAnswers.Count

  # ---- Consensus = the most common NON-EMPTY answer set ----
  # Computing consensus over non-empty sets only is what makes the "some
  # resolvers have the record, some do not" case read correctly: the resolvers
  # still missing it are clearly 'norecord' instead of silently becoming the
  # majority and inverting the verdict.
  $signatureCounts = @{}
  foreach ($row in $withAnswers) {
    if (-not $signatureCounts.ContainsKey($row.signature)) { $signatureCounts[$row.signature] = 0 }
    $signatureCounts[$row.signature]++
  }
  $status.distinctAnswerSets = $signatureCounts.Keys.Count

  $consensusSignature = $null
  $consensusCount = 0
  foreach ($key in $signatureCounts.Keys) {
    if ($signatureCounts[$key] -gt $consensusCount) {
      $consensusCount = $signatureCounts[$key]
      $consensusSignature = $key
    }
  }
  if ($null -ne $consensusSignature) {
    $consensusRow = @($withAnswers | Where-Object { $_.signature -eq $consensusSignature })[0]
    $status.consensusAnswers = @($consensusRow.answers)
  }

  # ---- Classify each resolver ----
  $expected = ([string]$ExpectedValue).Trim()
  $useExpected = -not [string]::IsNullOrWhiteSpace($expected)
  foreach ($row in $rows) {
    if ($row.truncated -eq $true) { $row.status = 'truncated'; continue }
    if ($row.responded -ne $true) {
      $row.status = if ($null -ne $row.rcode) { 'error' } else { 'unavailable' }
      continue
    }
    if ($row.answers.Count -eq 0) {
      # NOERROR-with-no-answers and NXDOMAIN both mean "this resolver has no
      # such record" -- the signal that a change has not propagated here yet.
      $row.status = 'norecord'
      continue
    }
    if ($useExpected) {
      $matched = $false
      foreach ($answer in $row.answers) {
        if (([string]$answer).IndexOf($expected, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $matched = $true; break }
      }
      $row.status = if ($matched) { 'propagated' } else { 'mismatch' }
      continue
    }
    $row.status = if ($row.signature -eq $consensusSignature) { 'propagated' } else { 'mismatch' }
  }

  $status.matchingCount = @($rows | Where-Object { $_.status -eq 'propagated' }).Count
  $status.mismatchCount = @($rows | Where-Object { $_.status -eq 'mismatch' }).Count
  $noRecordCount = @($rows | Where-Object { $_.status -eq 'norecord' }).Count
  $status.propagationPercent = if ($responders.Count -gt 0) { [int][Math]::Round(100.0 * $status.matchingCount / $responders.Count) } else { 0 }

  # ---- Overall state ----
  if ($status.matchingCount -eq 0 -and $status.mismatchCount -eq 0) {
    # Every responder agrees the record does not exist.
    $status.state = 'norecord'
    $status.summary = 'NoRecordAnywhere'
  } elseif ($noRecordCount -gt 0 -and $status.matchingCount -gt 0) {
    # The classic "still propagating" signature: present at some vantage points,
    # absent at others. This is the case that breaks ACS domain verification.
    $status.state = 'partial'
    $status.summary = 'PartiallyPropagated'
  } elseif ($status.mismatchCount -gt 0) {
    # Everyone has *a* record, but not the same one (stale cache, split-horizon,
    # geo-DNS, or an edit that is still rolling out).
    $status.state = 'mismatch'
    $status.summary = 'InconsistentAnswers'
  } else {
    $status.state = 'propagated'
    $status.summary = 'FullyPropagated'
  }

  $status.results = $rows.ToArray()

  # ---- Roll up to map markers ----
  # Several resolvers share a city (two in Seoul, two in Copenhagen, ...), so we
  # group by rounded coordinates and emit one marker per location. A location is
  # only green when every resolver there agrees.
  #
  # Only resolvers that actually returned a usable answer are rolled up: a pin
  # for a resolver that never replied says nothing about the domain and only
  # adds noise to the map. Non-responding resolvers remain in `results` for
  # callers that want the full picture.
  $locationMap = [ordered]@{}
  foreach ($row in ($rows | Where-Object { $_.responded -eq $true })) {
    $key = '{0:N2}|{1:N2}' -f $row.latitude, $row.longitude
    if (-not $locationMap.Contains($key)) {
      $locationMap[$key] = [pscustomobject]@{
        key         = $key
        name        = if ([string]::IsNullOrWhiteSpace($row.city)) { $row.countryCode } else { $row.city }
        countryCode = $row.countryCode
        latitude    = $row.latitude
        longitude   = $row.longitude
        anycast     = $row.anycast
        total       = 0
        propagated  = 0
        mismatch    = 0
        norecord    = 0
        providers   = @()
        status      = 'unknown'
      }
    }
    $entry = $locationMap[$key]
    $entry.total++
    $entry.providers = @($entry.providers + $row.provider)
    if (-not $row.anycast) { $entry.anycast = $false }
    switch ($row.status) {
      'propagated'  { $entry.propagated++ }
      'mismatch'    { $entry.mismatch++ }
      'norecord'    { $entry.norecord++ }
    }
  }
  foreach ($key in $locationMap.Keys) {
    $entry = $locationMap[$key]
    # Worst-first: one disagreeing or missing resolver colors the whole marker.
    $entry.status = if ($entry.mismatch -gt 0) { 'mismatch' }
      elseif ($entry.norecord -gt 0) { 'norecord' }
      else { 'propagated' }
  }
  $status.locations = @($locationMap.Values)

  return $status
}
