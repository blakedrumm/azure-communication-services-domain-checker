# ===== Per-Nameserver TXT Consistency Check =====
# ------------------- NAMESERVER TXT PROBE -------------------
# This check answers a question operators hit constantly: "all the nameservers
# are responding, so why does my TXT / SPF record look missing?"
#
# The usual culprit is that the domain's authoritative nameservers are NOT
# serving an identical zone -- one or more of them is missing records (or fails
# to resolve entirely), so a public recursive resolver that happens to hit the
# "bad" nameserver returns an incomplete TXT set. Because recursive resolvers
# pick a nameserver more-or-less at random (and cache the answer), the symptom
# is intermittent: the record "resolves in MXToolbox" but shows as missing here,
# or vice versa.
#
# To surface this, we query EACH authoritative nameserver directly for the
# domain's TXT records and compare the answers. The card then shows whether the
# nameservers agree, which ones are missing SPF / the ms-domain-verification
# token, and (behind a details button) the exact TXT records each nameserver
# returned.
#
# CROSS-PLATFORM: the Linux container runs PowerShell 7, which has NO
# Resolve-DnsName cmdlet (that ships only with the Windows DnsClient module).
# We therefore implement a small, self-contained raw DNS client over
# System.Net.Sockets (UDP with a TCP-on-truncation fallback) so the exact same
# code path works on Windows and Linux.
#
# SECURITY: a domain's NS records (and the A/AAAA records of those nameservers)
# are fully attacker-influenceable, so querying them is an SSRF vector. Every
# resolved nameserver IP is run through Test-IsPublicIpAddress (defined in
# 16b-WebsiteProbe.ps1) before we open a socket to it; private / loopback /
# link-local / CGNAT targets are refused. The query is bounded by a short
# socket timeout and a small response buffer so a hostile/slow nameserver
# cannot pin a worker.

# Perform a single raw DNS TXT lookup for $Name against the authoritative
# nameserver at $Server (an IP literal). Returns a stable result object; it
# never throws so the orchestrator can keep going when one nameserver misbehaves.
#
# Result shape:
#   server      : the server IP we queried
#   success     : $true only when the server returned RCODE 0 (NOERROR)
#   rcode       : numeric RCODE (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED...)
#   rcodeLabel  : human-readable RCODE
#   truncated   : whether the UDP answer had the TC bit set (we then retried TCP)
#   transport   : 'udp' or 'tcp' (which transport produced the parsed answer)
#   txtRecords  : array of reconstructed TXT strings (each char-string sequence
#                 concatenated per RFC 7208, sorted for stable comparison)
#   error       : a short message when the lookup could not be completed
function Invoke-RawDnsTxtQuery {
  param(
	[Parameter(Mandatory = $true)][string]$Server,
	[Parameter(Mandatory = $true)][string]$Name,
	[int]$TimeoutMs = 4000,
	[switch]$NoTcpFallback
  )

  $result = [pscustomobject]@{
	server     = $Server
	success    = $false
	rcode      = $null
	rcodeLabel = $null
	truncated  = $false
	transport  = $null
	txtRecords = @()
	error      = $null
  }

  # Validate the server is a parseable IP. We never accept hostnames here -- the
  # caller resolves + SSRF-vets the IP first so the socket target is known-good.
  $serverIp = $null
  if (-not [System.Net.IPAddress]::TryParse(([string]$Server).Trim(), [ref]$serverIp)) {
	$result.error = 'Invalid server IP.'
	return $result
  }

  $cleanName = ([string]$Name).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($cleanName)) {
	$result.error = 'Missing name.'
	return $result
  }

  if ($TimeoutMs -lt 250) { $TimeoutMs = 250 }
  if ($TimeoutMs -gt 15000) { $TimeoutMs = 15000 }

  # ---- nested helper: encode a domain name into DNS QNAME wire format ----
  # Each label is length-prefixed (1 byte) and the name is terminated by a
  # zero-length root label. Nested so it needs no runspace registration.
  function ConvertTo-DnsQName {
	param([string]$DnsName)
	$bytes = New-Object System.Collections.Generic.List[byte]
	foreach ($label in ($DnsName -split '\.')) {
	  if ([string]::IsNullOrEmpty($label)) { continue }
	  $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
	  if ($labelBytes.Length -gt 63) { throw 'DNS label exceeds 63 octets.' }
	  $bytes.Add([byte]$labelBytes.Length)
	  $bytes.AddRange($labelBytes)
	}
	$bytes.Add([byte]0)
	return , ($bytes.ToArray())
  }

  # ---- nested helper: build the full DNS query packet (header + question) ----
  function New-DnsTxtQueryPacket {
	param([string]$DnsName, [int]$TransactionId)
	$packet = New-Object System.Collections.Generic.List[byte]
	# Header (12 bytes).
	$packet.Add([byte](($TransactionId -shr 8) -band 0xFF))   # ID high
	$packet.Add([byte]($TransactionId -band 0xFF))            # ID low
	# Flags: QR=0, Opcode=0, AA=0, TC=0, RD=0 | RA=0, Z=0, RCODE=0.
	# RD (recursion desired) is intentionally 0: we query each AUTHORITATIVE
	# server directly and want its own answer, not a recursive lookup.
	$packet.Add([byte]0x00)
	$packet.Add([byte]0x00)
	$packet.Add([byte]0x00); $packet.Add([byte]0x01)          # QDCOUNT = 1
	$packet.Add([byte]0x00); $packet.Add([byte]0x00)          # ANCOUNT = 0
	$packet.Add([byte]0x00); $packet.Add([byte]0x00)          # NSCOUNT = 0
	$packet.Add([byte]0x00); $packet.Add([byte]0x00)          # ARCOUNT = 0
	# Question.
	$packet.AddRange((ConvertTo-DnsQName -DnsName $DnsName))
	$packet.Add([byte]0x00); $packet.Add([byte]0x10)          # QTYPE = 16 (TXT)
	$packet.Add([byte]0x00); $packet.Add([byte]0x01)          # QCLASS = 1 (IN)
	return , ($packet.ToArray())
  }

  # ---- nested helper: advance past a DNS name, honoring 0xC0 compression ----
  # Returns the offset of the byte immediately after the name. We only need to
  # SKIP names (owner NAME of each RR + the question QNAME); TXT RDATA is read
  # via RDLENGTH so compression never has to be expanded.
  function Step-PastDnsName {
	param([byte[]]$Buffer, [int]$Offset)
	$i = $Offset
	while ($true) {
	  if ($i -ge $Buffer.Length) { return $Buffer.Length }
	  $len = $Buffer[$i]
	  if ($len -eq 0) { return ($i + 1) }
	  if (($len -band 0xC0) -eq 0xC0) { return ($i + 2) }   # pointer terminates the name
	  $i += ($len + 1)
	}
  }

  # ---- nested helper: parse TXT answers out of a raw DNS response ----
  # Mutates and returns $result fields. Returns $true when parsing reached a
  # usable state (even RCODE != 0 is "usable" -- it tells us the server's view).
  function Read-DnsTxtResponse {
	param([byte[]]$Buffer, [int]$TransactionId, [string]$Transport)

	if ($null -eq $Buffer -or $Buffer.Length -lt 12) {
	  $result.error = 'Short DNS response.'
	  return $false
	}

	# Verify the transaction ID matches so a stray datagram can't be parsed as
	# our answer. NOTE: cast the high byte to [int] before shifting -- PowerShell's
	# -shl on a [byte] truncates the result back to 8 bits (so [byte]218 -shl 8 == 0),
	# which would silently drop the high half of every 16-bit field we read.
	$respId = ([int]$Buffer[0] -shl 8) -bor [int]$Buffer[1]
	if ($respId -ne $TransactionId) {
	  $result.error = 'DNS transaction ID mismatch.'
	  return $false
	}

	$result.truncated = (($Buffer[2] -band 0x02) -ne 0)
	$rcode = ($Buffer[3] -band 0x0F)
	$result.rcode = $rcode
	$result.rcodeLabel = switch ($rcode) {
	  0 { 'NOERROR' }
	  1 { 'FORMERR' }
	  2 { 'SERVFAIL' }
	  3 { 'NXDOMAIN' }
	  4 { 'NOTIMP' }
	  5 { 'REFUSED' }
	  default { "RCODE $rcode" }
	}
	$result.transport = $Transport

	$anCount = ([int]$Buffer[6] -shl 8) -bor [int]$Buffer[7]

	# Walk past the header + question section.
	$offset = 12
	$offset = Step-PastDnsName -Buffer $Buffer -Offset $offset   # QNAME
	$offset += 4                                                  # QTYPE + QCLASS

	$txt = New-Object System.Collections.Generic.List[string]
	for ($a = 0; $a -lt $anCount; $a++) {
	  if ($offset -ge $Buffer.Length) { break }
	  $offset = Step-PastDnsName -Buffer $Buffer -Offset $offset  # owner NAME
	  if (($offset + 10) -gt $Buffer.Length) { break }
	  $type = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
	  $offset += 2          # TYPE
	  $offset += 2          # CLASS
	  $offset += 4          # TTL
	  $rdlength = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
	  $offset += 2          # RDLENGTH
	  if (($offset + $rdlength) -gt $Buffer.Length) { break }

	  if ($type -eq 16 -and $rdlength -gt 0) {
		# TXT RDATA is one or more <character-string>s: a length byte followed
		# by that many octets. Concatenate them with NO separator per RFC 7208.
		$sb = New-Object System.Text.StringBuilder
		$p = $offset
		$rdEnd = $offset + $rdlength
		while ($p -lt $rdEnd) {
		  $clen = $Buffer[$p]; $p++
		  if (($p + $clen) -gt $rdEnd) { break }
		  if ($clen -gt 0) {
			[void]$sb.Append([System.Text.Encoding]::UTF8.GetString($Buffer, $p, $clen))
			$p += $clen
		  }
		}
		$value = $sb.ToString().Trim()
		if (-not [string]::IsNullOrWhiteSpace($value)) { $txt.Add($value) }
	  }

	  $offset += $rdlength
	}

	# Sort for stable cross-nameserver comparison (the orchestrator hashes the
	# set, so order must not matter).
	$result.txtRecords = @($txt | Sort-Object)
	$result.success = ($rcode -eq 0)
	return $true
  }

  # ---- nested helper: send the query over UDP, return raw response bytes ----
  function Send-DnsUdp {
	param([System.Net.IPAddress]$Ip, [byte[]]$Query, [int]$TimeoutMilliseconds)
	$sock = $null
	try {
	  $sock = New-Object System.Net.Sockets.Socket($Ip.AddressFamily, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
	  $sock.ReceiveTimeout = $TimeoutMilliseconds
	  $sock.SendTimeout = $TimeoutMilliseconds
	  $sock.Connect((New-Object System.Net.IPEndPoint($Ip, 53)))
	  [void]$sock.Send($Query)
	  $buf = New-Object byte[] 4096
	  $n = $sock.Receive($buf)
	  if ($n -le 0) { return $null }
	  $exact = New-Object byte[] $n
	  [Array]::Copy($buf, 0, $exact, 0, $n)
	  return , $exact
	} finally {
	  if ($sock) { try { $sock.Dispose() } catch { } }
	}
  }

  # ---- nested helper: send the query over TCP (used on UDP truncation) ----
  # TCP DNS frames the message with a 2-byte big-endian length prefix in both
  # directions (RFC 1035 4.2.2).
  function Send-DnsTcp {
	param([System.Net.IPAddress]$Ip, [byte[]]$Query, [int]$TimeoutMilliseconds)
	$client = $null
	$stream = $null
	try {
	  $client = New-Object System.Net.Sockets.TcpClient($Ip.AddressFamily)
	  $iar = $client.BeginConnect($Ip, 53, $null, $null)
	  if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) { return $null }
	  $client.EndConnect($iar)
	  $client.ReceiveTimeout = $TimeoutMilliseconds
	  $client.SendTimeout = $TimeoutMilliseconds
	  $stream = $client.GetStream()

	  $framed = New-Object byte[] (2 + $Query.Length)
	  $framed[0] = [byte](($Query.Length -shr 8) -band 0xFF)
	  $framed[1] = [byte]($Query.Length -band 0xFF)
	  [Array]::Copy($Query, 0, $framed, 2, $Query.Length)
	  $stream.Write($framed, 0, $framed.Length)
	  $stream.Flush()

	  # Read the 2-byte response length, then exactly that many bytes.
	  $lenBuf = New-Object byte[] 2
	  if (-not (Read-StreamExact -Stream $stream -Target $lenBuf -Count 2)) { return $null }
	  $respLen = ([int]$lenBuf[0] -shl 8) -bor [int]$lenBuf[1]
	  if ($respLen -le 0 -or $respLen -gt 65535) { return $null }
	  $respBuf = New-Object byte[] $respLen
	  if (-not (Read-StreamExact -Stream $stream -Target $respBuf -Count $respLen)) { return $null }
	  return , $respBuf
	} finally {
	  if ($stream) { try { $stream.Dispose() } catch { } }
	  if ($client) { try { $client.Dispose() } catch { } }
	}
  }

  # ---- nested helper: read exactly N bytes from a NetworkStream ----
  # NetworkStream.Read may return fewer bytes than requested, so loop until the
  # buffer is filled or the peer closes the connection.
  function Read-StreamExact {
	param([System.Net.Sockets.NetworkStream]$Stream, [byte[]]$Target, [int]$Count)
	$read = 0
	while ($read -lt $Count) {
	  $chunk = $Stream.Read($Target, $read, ($Count - $read))
	  if ($chunk -le 0) { return $false }
	  $read += $chunk
	}
	return $true
  }

  # ---- main: build query, try UDP, fall back to TCP on truncation ----
  $transactionId = Get-Random -Minimum 1 -Maximum 65535
  $query = $null
  try {
	$query = New-DnsTxtQueryPacket -DnsName $cleanName -TransactionId $transactionId
  } catch {
	$result.error = "Failed to build DNS query: $($_.Exception.Message)"
	return $result
  }

  try {
	$udpResponse = Send-DnsUdp -Ip $serverIp -Query $query -TimeoutMilliseconds $TimeoutMs
	if ($null -ne $udpResponse) {
	  [void](Read-DnsTxtResponse -Buffer $udpResponse -TransactionId $transactionId -Transport 'udp')

	  # If the UDP answer was truncated, retry over TCP to get the complete set.
	  if ($result.truncated -and -not $NoTcpFallback) {
		try {
		  $tcpResponse = Send-DnsTcp -Ip $serverIp -Query $query -TimeoutMilliseconds $TimeoutMs
		  if ($null -ne $tcpResponse) {
			[void](Read-DnsTxtResponse -Buffer $tcpResponse -TransactionId $transactionId -Transport 'tcp')
		  }
		} catch {
		  # Keep the (partial) UDP answer; note the TCP issue but don't fail.
		  if ([string]::IsNullOrWhiteSpace($result.error)) {
			$result.error = "TCP retry failed: $($_.Exception.Message)"
		  }
		}
	  }
	  return $result
	}

	# No UDP answer at all (timeout / unreachable). Try TCP directly as a last
	# resort -- some networks block UDP/53 outbound but allow TCP/53.
	if (-not $NoTcpFallback) {
	  $tcpResponse = Send-DnsTcp -Ip $serverIp -Query $query -TimeoutMilliseconds $TimeoutMs
	  if ($null -ne $tcpResponse) {
		[void](Read-DnsTxtResponse -Buffer $tcpResponse -TransactionId $transactionId -Transport 'tcp')
		return $result
	  }
	}

	$result.error = 'No response from nameserver (UDP/TCP timeout or unreachable).'
	return $result
  } catch {
	$result.error = "Nameserver query failed: $($_.Exception.Message)"
	return $result
  }
}

# Discover the authoritative nameserver hostnames for a domain via DNS-over-HTTPS.
# Resolve-DohName's ValidateSet doesn't include NS (it only handles the record
# types the rest of the app needs), and the Linux container has no Resolve-DnsName,
# so we query the DoH JSON endpoint for NS directly here. We try the queried name
# first and then walk up to its registrable parents, because NS records live at
# the zone apex (e.g. NS is published at example.com, not at www.example.com).
#
# Returns an array of lowercased nameserver hostnames (deduped), or @() when none
# could be found.
function Get-AuthoritativeNameserverHosts {
  param([Parameter(Mandatory = $true)][string]$Domain)

  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
	$endpoint = 'https://cloudflare-dns.com/dns-query'
  }

  # Build the candidate zone list: the domain itself, then each parent, then the
  # registrable apex. Deduped while preserving order.
  $candidates = New-Object System.Collections.Generic.List[string]
  $clean = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant()
  if (-not [string]::IsNullOrWhiteSpace($clean)) { $candidates.Add($clean) }
  foreach ($parent in @(Get-ParentDomains -Domain $clean)) {
	if (-not [string]::IsNullOrWhiteSpace($parent) -and -not $candidates.Contains($parent)) {
	  $candidates.Add($parent)
	}
  }
  try {
	$registrable = Get-RegistrableDomain -Domain $clean
	if (-not [string]::IsNullOrWhiteSpace($registrable) -and -not $candidates.Contains($registrable)) {
	  $candidates.Add($registrable)
	}
  } catch { }

  foreach ($zone in $candidates) {
	$uri = "{0}?name={1}&type=NS&cd=1" -f $endpoint, ([uri]::EscapeDataString($zone))
	$resp = $null
	try {
	  $resp = Invoke-OutboundHttp -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 8 -MaximumRedirection 3
	} catch {
	  continue
	}
	if ($null -eq $resp -or $null -eq $resp.Answer) { continue }

	$hosts = New-Object System.Collections.Generic.List[string]
	foreach ($answer in @($resp.Answer)) {
	  # NS answers are type 2. Some resolvers echo CNAME/SOA alongside; skip them.
	  $recType = $answer.type
	  if ($recType -ne 2 -and [string]$recType -ne 'NS') { continue }
	  $data = ([string]$answer.data).Trim().TrimEnd('.').ToLowerInvariant()
	  if ([string]::IsNullOrWhiteSpace($data)) { continue }
	  if (-not $hosts.Contains($data)) { $hosts.Add($data) }
	}

	if ($hosts.Count -gt 0) { return @($hosts) }
  }

  return @()
}

# Resolve a nameserver hostname to the set of IP addresses we may safely query.
# SECURITY: each resolved address is vetted with Test-IsPublicIpAddress (from
# 16b-WebsiteProbe.ps1) so we never open a socket to a private/loopback/CGNAT
# target an attacker could publish for their own nameserver (SSRF defense).
# Returns @() when the host doesn't resolve or resolves only to non-public IPs.
function Resolve-NameserverPublicIps {
  param([Parameter(Mandatory = $true)][string]$NameserverHost)

  $ips = New-Object System.Collections.Generic.List[string]
  foreach ($type in @('A', 'AAAA')) {
	try {
	  $records = ResolveSafely $NameserverHost $type
	  if ($records) {
		foreach ($ip in @($records | Get-DnsIpString)) {
		  if ([string]::IsNullOrWhiteSpace($ip)) { continue }
		  if (-not (Test-IsPublicIpAddress -IpAddress $ip)) { continue }
		  if (-not $ips.Contains($ip)) { $ips.Add($ip) }
		}
	  }
	} catch { }
  }
  return @($ips)
}

# Orchestrate the per-nameserver TXT consistency check for $Domain.
#
# For each authoritative nameserver we resolve a public IP and query it directly
# for the domain's TXT records, then compare the per-nameserver TXT sets to
# detect the "some nameservers are missing records" misconfiguration that makes
# TXT/SPF appear intermittently missing to public resolvers.
#
# The returned payload is intentionally shaped to stay stable for the SPA:
#   domain            : queried domain
#   checked           : whether the probe ran ($false when disabled / no NS)
#   disabledReason    : populated when checked is $false by operator opt-out
#   nameserverCount   : number of authoritative NS hostnames discovered
#   respondingCount   : how many nameservers returned a usable (NOERROR) answer
#   failingCount      : how many failed to resolve / answer / returned an error
#   consistent        : $true only when every responding NS returned the same set
#   consistencyState  : 'consistent' | 'inconsistent' | 'partial' | 'unknown' | 'none'
#   spfAllPresent     : $true when every responding NS carries an SPF record
#   acsAllPresent     : $true when every responding NS carries ms-domain-verification
#   distinctTxtSets   : count of unique TXT sets observed across nameservers
#   summary           : short server-side fallback sentence
#   results           : per-nameserver detail array (host, ip, status, txt, spf/acs flags)
function Get-NameserverTxtStatus {
  param([Parameter(Mandatory = $true)][string]$Domain)

  $d = ([string]$Domain).Trim().TrimEnd('.')

  $status = [pscustomobject]@{
	domain           = $d
	generatedAtUtc   = ([DateTime]::UtcNow.ToString('o'))
	checked          = $true
	disabledReason   = $null
	nameserverCount  = 0
	respondingCount  = 0
	failingCount     = 0
	consistent       = $null
	consistencyState = 'unknown'
	spfAllPresent    = $null
	acsAllPresent    = $null
	distinctTxtSets  = 0
	summary          = 'Unknown'
	error            = $null
	results          = @()
  }

  if ([string]::IsNullOrWhiteSpace($d)) {
	$status.checked = $false
	$status.consistencyState = 'unknown'
	$status.summary = 'Unknown'
	$status.error = 'Missing domain.'
	return $status
  }

  # Operator opt-out (e.g. on networks where outbound DNS/53 is undesirable).
  if (([string]$env:ACS_DISABLE_NAMESERVER_PROBE).Trim() -eq '1') {
	$status.checked = $false
	$status.consistencyState = 'unknown'
	$status.summary = 'Disabled'
	$status.disabledReason = 'Nameserver TXT probe disabled by server configuration.'
	return $status
  }

  # Bounded, tunable knobs (read inline, mirroring the website / RBL checks).
  $maxNameservers = 12
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_NAMESERVER_PROBE_MAX, [ref]$parsed) -and $parsed -gt 0) {
	$maxNameservers = [Math]::Min(25, $parsed)
  }
  $timeoutMs = 4000
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_NAMESERVER_PROBE_TIMEOUT_MS, [ref]$parsed) -and $parsed -gt 0) {
	$timeoutMs = [Math]::Min(15000, [Math]::Max(500, $parsed))
  }

  $nsHosts = @(Get-AuthoritativeNameserverHosts -Domain $d)
  if ($nsHosts.Count -eq 0) {
	$status.consistencyState = 'none'
	$status.summary = 'NoNameservers'
	$status.error = 'No authoritative nameservers found for the domain.'
	return $status
  }

  if ($nsHosts.Count -gt $maxNameservers) {
	$nsHosts = @($nsHosts | Select-Object -First $maxNameservers)
  }
  $status.nameserverCount = $nsHosts.Count

  $perServer = New-Object System.Collections.Generic.List[object]
  foreach ($nsHost in $nsHosts) {
	$ips = @(Resolve-NameserverPublicIps -NameserverHost $nsHost)
	if ($ips.Count -eq 0) {
	  # The nameserver hostname itself doesn't resolve to a public IP (this is
	  # exactly the zenithbank.com sv001dns06 "No such host is known" case).
	  $perServer.Add([pscustomobject]@{
		host       = $nsHost
		ip         = $null
		success    = $false
		rcode      = $null
		rcodeLabel = $null
		transport  = $null
		txtRecords = @()
		spfPresent = $false
		acsPresent = $false
		error      = 'Nameserver hostname did not resolve to a public IP address.'
	  })
	  continue
	}

	# Query the first usable IP for this nameserver. One IP per NS is enough to
	# represent that server's view of the zone and keeps the fan-out bounded.
	$queryIp = $ips[0]
	$answer = Invoke-RawDnsTxtQuery -Server $queryIp -Name $d -TimeoutMs $timeoutMs

	$txt = @($answer.txtRecords)
	$spfPresent = [bool](@($txt | Where-Object { $_ -match '(?i)^v=spf1' }).Count -gt 0)
	$acsPresent = [bool](@($txt | Where-Object { $_ -match '(?i)ms-domain-verification' }).Count -gt 0)

	$perServer.Add([pscustomobject]@{
	  host       = $nsHost
	  ip         = $queryIp
	  success    = [bool]$answer.success
	  rcode      = $answer.rcode
	  rcodeLabel = $answer.rcodeLabel
	  transport  = $answer.transport
	  txtRecords = $txt
	  spfPresent = $spfPresent
	  acsPresent = $acsPresent
	  error      = $answer.error
	})
  }

  $status.results = $perServer.ToArray()

  # Aggregate. "Responding" = the server returned NOERROR (a real, usable view
  # of the zone). A SERVFAIL/REFUSED/no-answer server is counted as failing.
  $responders = @($perServer | Where-Object { $_.success -eq $true })
  $status.respondingCount = $responders.Count
  $status.failingCount = $perServer.Count - $responders.Count

  if ($responders.Count -eq 0) {
	# Nobody answered cleanly. The card should surface this as a hard problem.
	$status.consistent = $false
	$status.consistencyState = 'unknown'
	$status.spfAllPresent = $false
	$status.acsAllPresent = $false
	$status.distinctTxtSets = 0
	$status.summary = 'NoResponders'
	return $status
  }

  # Build a normalized signature for each responder's TXT set so we can count
  # distinct views. The raw client already sorts each set, so a simple join is a
  # stable signature.
  $signatures = @{}
  foreach ($responder in $responders) {
	$sig = (@($responder.txtRecords) -join "`n")
	if (-not $signatures.ContainsKey($sig)) { $signatures[$sig] = 0 }
	$signatures[$sig]++
  }
  $status.distinctTxtSets = $signatures.Keys.Count

  $spfAll = [bool](@($responders | Where-Object { $_.spfPresent -ne $true }).Count -eq 0)
  $acsAll = [bool](@($responders | Where-Object { $_.acsPresent -ne $true }).Count -eq 0)
  $status.spfAllPresent = $spfAll
  $status.acsAllPresent = $acsAll

  $allConsistent = ($status.distinctTxtSets -le 1)
  $status.consistent = $allConsistent

  # Consistency state drives the badge color/text in the SPA:
  #   consistent   - every responding NS returned the identical TXT set AND no NS failed.
  #   partial      - the responders all agree, but at least one NS failed to answer.
  #   inconsistent - responding nameservers returned DIFFERENT TXT sets.
  if (-not $allConsistent) {
	$status.consistencyState = 'inconsistent'
	$status.summary = 'Inconsistent'
  } elseif ($status.failingCount -gt 0) {
	$status.consistencyState = 'partial'
	$status.summary = 'PartialFailure'
  } else {
	$status.consistencyState = 'consistent'
	$status.summary = 'Consistent'
  }

  return $status
}

