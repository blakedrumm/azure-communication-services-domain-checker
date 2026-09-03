# ===== Literal-Domain Reputation (RHSBL / URIBL) =====
# This is deliberately separate from 17-DnsReputation.ps1's mail-server IPv4
# DNSBL checks. URI/domain lists query a registrable domain directly and have
# provider-specific access controls and response codes; mixing both scopes into
# one percentage would produce misleading results.

if (-not $global:AcsDomainReputationCache) {
  $global:AcsDomainReputationCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}
if (-not $global:AcsDomainReputationHealth) {
  $global:AcsDomainReputationHealth = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}
if (-not $global:AcsDomainReputationProviderBudgets) {
  $global:AcsDomainReputationProviderBudgets = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}
if (-not $global:AcsDomainReputationGate) {
  $global:AcsDomainReputationGate = [System.Threading.SemaphoreSlim]::new(4, 4)
}
if (-not $global:AcsDomainReputationBudgetLock) {
  $global:AcsDomainReputationBudgetLock = [System.Threading.SemaphoreSlim]::new(1, 1)
}
if (-not $global:AcsDomainReputationBudgetState) {
  $global:AcsDomainReputationBudgetState = [pscustomobject]@{ tokens = 120.0; updatedAtUtc = [DateTime]::UtcNow }
}
if (-not $global:AcsDomainReputationCacheKey) {
  $keyBytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($keyBytes) } finally { $rng.Dispose() }
  $global:AcsDomainReputationCacheKey = $keyBytes
}

# Provider profiles are code-owned because each service has different controls,
# categories and policy-block responses. Operator configuration selects IDs only;
# it cannot inject an arbitrary DNS destination or decoder.
function Get-DomainReputationProviderCatalog {
  return @(
    [pscustomobject]@{
      id = 'uribl'
      displayName = 'URIBL Multi'
      queryZone = 'multi.uribl.com'
      authorityDomain = 'multi.uribl.com'
      controlDomain = 'test.uribl.com'
      controlExpected = @('127.0.0.14')
      controlMatch = 'exactSet'
      negativeControlDomain = 'invalid'
      classifier = 'uribl'
      queryNameMode = 'registrableDomain'
      defaultEnabled = $true
      profileVersion = 2
      queriesPerMinute = 60
      queryBurst = 60
      policyUrl = 'https://www.uribl.com/about.shtml'
    },
    [pscustomobject]@{
      id = 'nordspam'
      displayName = 'NordSpam DBL'
      queryZone = 'dbl.nordspam.com'
      authorityDomain = 'dbl.nordspam.com'
      controlDomain = 'test'
      controlExpected = @('127.0.0.2')
      controlMatch = 'exactSet'
      negativeControlDomain = 'invalid'
      classifier = 'binary127002'
      queryNameMode = 'registrableDomain'
      defaultEnabled = $true
      profileVersion = 1
      # Sustained refill governs the daily total (6/min = 8,640/day, under the
      # published ~10,000/day contact threshold). Burst only shapes short spikes,
      # and must cover a full 10-domain sweep at 3 queries per domain.
      queriesPerMinute = 6
      queryBurst = 36
      policyUrl = 'https://www.nordspam.com/usage/'
    },
    [pscustomobject]@{
      id = 'sem-uri'
      displayName = 'Spam Eating Monkey URI'
      queryZone = 'uribl.spameatingmonkey.net'
      authorityDomain = 'uribl.spameatingmonkey.net'
      controlDomain = '_DNSBL_.test'
      controlExpected = @('127.0.0.2')
      controlMatch = 'exactSet'
      negativeControlDomain = '_DNSBLNEG_.test'
      classifier = 'binary127002'
      queryNameMode = 'registrableDomain'
      defaultEnabled = $true
      profileVersion = 1
      queriesPerMinute = 120
      queryBurst = 60
      policyUrl = 'https://spameatingmonkey.com/services/SEM-URI'
    },
    [pscustomobject]@{
      id = 'surbl'
      displayName = 'SURBL Multi'
      queryZone = 'multi.surbl.org'
      authorityDomain = 'surbl.org'
      controlDomain = 'test.surbl.org'
      controlExpected = @('127.0.0.126', '127.0.0.254')
      controlMatch = 'anyOf'
      negativeControlDomain = 'invalid'
      classifier = 'surbl'
      queryNameMode = 'registrableDomain'
      defaultEnabled = $false
      profileVersion = 2
      queriesPerMinute = 30
      queryBurst = 30
      policyUrl = 'https://www.surbl.org/usage-policy'
    },
    [pscustomobject]@{
      id = 'spamhaus'
      displayName = 'Spamhaus DBL'
      queryZone = 'dbl.spamhaus.org'
      authorityDomain = 'dbl.spamhaus.org'
      controlDomain = 'dbltest.com'
      controlExpected = @('127.0.1.2')
      controlMatch = 'exactSet'
      negativeControlDomain = 'invalid'
      classifier = 'spamhausDbl'
      queryNameMode = 'exactHost'
      defaultEnabled = $false
      profileVersion = 1
      queriesPerMinute = 30
      queryBurst = 30
      policyUrl = 'https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy/'
    }
  )
}

function Get-DomainReputationCacheKey {
  param([Parameter(Mandatory = $true)][string]$Value)

  $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$AcsDomainReputationCacheKey)
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    return ([Convert]::ToBase64String($hmac.ComputeHash($bytes))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  } finally {
    $hmac.Dispose()
  }
}

function Get-DomainReputationCacheEntry {
  param([Parameter(Mandatory = $true)][string]$Key)

  if (-not $AcsDomainReputationCache) { return $null }
  $entry = $null
  if (-not $AcsDomainReputationCache.TryGetValue($Key, [ref]$entry)) { return $null }
  if ($null -eq $entry -or $null -eq $entry.expiresAtUtc -or [DateTime]$entry.expiresAtUtc -le [DateTime]::UtcNow) {
    $removed = $null
    $null = $AcsDomainReputationCache.TryRemove($Key, [ref]$removed)
    return $null
  }
  return $entry.value
}

function Set-DomainReputationCacheEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [Parameter(Mandatory = $true)][object]$Value,
    [int]$TtlSeconds = 120
  )

  if (-not $AcsDomainReputationCache) { return }
  $ttl = [Math]::Min(3600, [Math]::Max(5, $TtlSeconds))

  # Keep provider traffic bounded without turning cache maintenance into a long
  # request-path pause. Expired entries are removed in a bounded pass.
  if ($AcsDomainReputationCache.Count -gt 5000) {
    $removedCount = 0
    foreach ($item in @($AcsDomainReputationCache.GetEnumerator())) {
      if ($removedCount -ge 512) { break }
      if ($null -eq $item.Value -or $null -eq $item.Value.expiresAtUtc -or [DateTime]$item.Value.expiresAtUtc -le [DateTime]::UtcNow) {
        $removed = $null
        if ($AcsDomainReputationCache.TryRemove($item.Key, [ref]$removed)) { $removedCount++ }
      }
    }
    if ($AcsDomainReputationCache.Count -gt 5000) { return }
  }

  $AcsDomainReputationCache[$Key] = [pscustomobject]@{
    expiresAtUtc = [DateTime]::UtcNow.AddSeconds($ttl)
    value = $Value
  }
}

function Remove-DomainReputationCacheEntry {
  param([Parameter(Mandatory = $true)][string]$Key)

  if (-not $AcsDomainReputationCache) { return }
  $removed = $null
  $null = $AcsDomainReputationCache.TryRemove($Key, [ref]$removed)
}

function Get-DomainReputationHealthEntry {
  param(
    [Parameter(Mandatory = $true)][string]$ProviderId,
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [int]$ProfileVersion = 1
  )

  if (-not $AcsDomainReputationHealth) { return $null }
  $key = Get-DomainReputationCacheKey -Value "health|$ProviderId|$ProfileVersion|$Endpoint"
  $entry = $null
  if (-not $AcsDomainReputationHealth.TryGetValue($key, [ref]$entry)) { return $null }
  if ($null -eq $entry -or $null -eq $entry.expiresAtUtc -or [DateTime]$entry.expiresAtUtc -le [DateTime]::UtcNow) {
    $removed = $null
    $null = $AcsDomainReputationHealth.TryRemove($key, [ref]$removed)
    return $null
  }
  return $entry.value
}

function Set-DomainReputationHealthEntry {
  param(
    [Parameter(Mandatory = $true)][string]$ProviderId,
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][object]$Value,
    [int]$ProfileVersion = 1,
    [int]$TtlSeconds = 300
  )

  if (-not $AcsDomainReputationHealth) { return }
  if ($AcsDomainReputationHealth.Count -gt 256) {
    foreach ($item in @($AcsDomainReputationHealth.GetEnumerator())) {
      if ($null -eq $item.Value -or $null -eq $item.Value.expiresAtUtc -or [DateTime]$item.Value.expiresAtUtc -le [DateTime]::UtcNow) {
        $removed = $null
        $null = $AcsDomainReputationHealth.TryRemove($item.Key, [ref]$removed)
      }
    }
    if ($AcsDomainReputationHealth.Count -gt 256) { return }
  }

  $key = Get-DomainReputationCacheKey -Value "health|$ProviderId|$ProfileVersion|$Endpoint"
  $AcsDomainReputationHealth[$key] = [pscustomobject]@{
    expiresAtUtc = [DateTime]::UtcNow.AddSeconds([Math]::Min(900, [Math]::Max(30, $TtlSeconds)))
    value = $Value
  }
}

# Process-wide token bucket. The ordinary endpoint rate limiter is per client;
# this second bound protects provider fair-use limits across all clients.
function Test-DomainReputationQueryBudget {
  param([int]$Cost = 1)

  if ($Cost -le 0) { return $true }
  if (-not $AcsDomainReputationBudgetLock -or -not $AcsDomainReputationBudgetState) { return $false }

  $limitPerMinute = 120
  $configured = 0
  if ([int]::TryParse([string]$env:ACS_DOMAIN_REPUTATION_QUERIES_PER_MIN, [ref]$configured) -and $configured -gt 0) {
    $limitPerMinute = [Math]::Min(600, [Math]::Max(10, $configured))
  }

  # Never wait unbounded: request runspaces are force-stopped after 90 seconds, so a
  # worker aborted inside this critical section could orphan the lock and deadlock
  # the whole feature process-wide. Time out and deny the budget (fail closed).
  if (-not $AcsDomainReputationBudgetLock.Wait(2000)) { return $false }
  try {
    $now = [DateTime]::UtcNow
    $elapsedSeconds = [Math]::Max(0.0, ($now - [DateTime]$AcsDomainReputationBudgetState.updatedAtUtc).TotalSeconds)
    $refill = $elapsedSeconds * ($limitPerMinute / 60.0)
    $AcsDomainReputationBudgetState.tokens = [Math]::Min([double]$limitPerMinute, [double]$AcsDomainReputationBudgetState.tokens + $refill)
    $AcsDomainReputationBudgetState.updatedAtUtc = $now
    if ([double]$AcsDomainReputationBudgetState.tokens -lt $Cost) { return $false }
    $AcsDomainReputationBudgetState.tokens = [double]$AcsDomainReputationBudgetState.tokens - $Cost
    return $true
  } finally {
    $null = $AcsDomainReputationBudgetLock.Release()
  }
}

function Test-DomainReputationProviderBudget {
  param(
    [Parameter(Mandatory = $true)][string]$ProviderId,
    [int]$Cost = 1,
    [int]$RatePerMinute = 60,
    [int]$Burst = 60
  )

  if ($Cost -le 0) { return $true }
  if (-not $AcsDomainReputationProviderBudgets -or -not $AcsDomainReputationBudgetLock) { return $false }
  $rate = [Math]::Min(600, [Math]::Max(1, $RatePerMinute))
  $capacity = [Math]::Min(600, [Math]::Max($Cost, $Burst))

  # Bounded wait for the same reason as the global budget lock: an aborted worker
  # must not be able to strand this lock and disable every future lookup.
  if (-not $AcsDomainReputationBudgetLock.Wait(2000)) { return $false }
  try {
    $state = $null
    if (-not $AcsDomainReputationProviderBudgets.TryGetValue($ProviderId, [ref]$state) -or $null -eq $state) {
      $state = [pscustomobject]@{ tokens = [double]$capacity; updatedAtUtc = [DateTime]::UtcNow }
      $AcsDomainReputationProviderBudgets[$ProviderId] = $state
    }
    $now = [DateTime]::UtcNow
    $elapsedSeconds = [Math]::Max(0.0, ($now - [DateTime]$state.updatedAtUtc).TotalSeconds)
    $state.tokens = [Math]::Min([double]$capacity, [double]$state.tokens + ($elapsedSeconds * ($rate / 60.0)))
    $state.updatedAtUtc = $now
    if ([double]$state.tokens -lt $Cost) { return $false }
    $state.tokens = [double]$state.tokens - $Cost
    return $true
  } finally {
    $null = $AcsDomainReputationBudgetLock.Release()
  }
}

function Get-DomainReputationAuthorityHosts {
  param([Parameter(Mandatory = $true)][object]$Provider)

  $authorityDomain = ([string]$Provider.authorityDomain).Trim().TrimEnd('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($authorityDomain)) { return @() }
  $endpoint = [string]$env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) { $endpoint = 'https://cloudflare-dns.com/dns-query' }

  $hosts = [System.Collections.Generic.List[string]]::new()
  foreach ($type in @('NS', 'SOA')) {
    # DNSSEC validation is deliberately left ENABLED here (no cd=1). These records
    # decide which servers receive the customer's domain name, so a forged answer
    # would both leak the lookup and forge the verdict. Measured against all five
    # provider zones, cd=1 and cd=0 return identical status and answer counts, so
    # validating costs nothing today and fails closed if a zone is ever tampered with.
    $uri = "{0}?name={1}&type={2}" -f $endpoint, ([uri]::EscapeDataString($authorityDomain)), $type
    try {
      $response = Invoke-OutboundHttp -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 8 -MaximumRedirection 3
      foreach ($answer in @($response.Answer)) {
        if ($type -eq 'NS' -and ([int]$answer.type -eq 2 -or [string]$answer.type -eq 'NS')) {
          $hostName = ([string]$answer.data).Trim().TrimEnd('.').ToLowerInvariant()
          if ($hostName -and -not $hosts.Contains($hostName)) { $hosts.Add($hostName) }
        }
        elseif ($type -eq 'SOA' -and ([int]$answer.type -eq 6 -or [string]$answer.type -eq 'SOA')) {
          $hostName = (([string]$answer.data).Trim() -split '\s+', 2)[0].TrimEnd('.').ToLowerInvariant()
          if ($hostName -and -not $hosts.Contains($hostName)) { $hosts.Add($hostName) }
        }
      }
    } catch { }
  }

  if ($hosts.Count -eq 0) {
    foreach ($hostName in @(Get-AuthoritativeNameserverHosts -Domain $authorityDomain)) {
      if ($hostName -and -not $hosts.Contains([string]$hostName)) { $hosts.Add([string]$hostName) }
    }
  }
  return $hosts.ToArray()
}

function New-DomainReputationDnsQueryPacket {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][int]$TransactionId
  )

  $queryName = ([string]$Name).Trim().TrimEnd('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($queryName) -or $queryName.Length -gt 253 -or $queryName -notmatch '^[a-z0-9._-]+$') {
    throw 'Invalid DNS query name.'
  }

  $packet = [System.Collections.Generic.List[byte]]::new()
  $packet.Add([byte](($TransactionId -shr 8) -band 0xFF))
  $packet.Add([byte]($TransactionId -band 0xFF))
  $packet.Add([byte]0x00)                            # QR=0, opcode=0, RD=0
  $packet.Add([byte]0x00)
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)   # QDCOUNT=1
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)

  foreach ($label in ($queryName -split '\.')) {
    if ([string]::IsNullOrWhiteSpace($label) -or $label.Length -gt 63) { throw 'Invalid DNS label.' }
    $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
    $packet.Add([byte]$labelBytes.Length)
    $packet.AddRange($labelBytes)
  }
  $packet.Add([byte]0)
  $packet.Add([byte]0); $packet.Add([byte]1)          # QTYPE=A
  $packet.Add([byte]0); $packet.Add([byte]1)          # QCLASS=IN
  return ,$packet.ToArray()
}

# Strict reader used only for direct authoritative domain-list queries. It does
# not modify propagation parsing or health state. An NXDOMAIN becomes usable
# only when it is authoritative, echoes the exact question, and carries an SOA
# whose owner proves authority for the configured provider zone.
function Read-DomainReputationDnsResponse {
  param(
    [byte[]]$Buffer,
    [int]$TransactionId,
    [Parameter(Mandatory = $true)][string]$ExpectedName,
    [Parameter(Mandatory = $true)][string]$ExpectedZone
  )

  $result = [pscustomobject]@{
    rcode = $null
    rcodeLabel = $null
    authoritative = $false
    truncated = $false
    negativeProof = $false
    answers = @()
    error = $null
  }

  function Read-DomainReputationRecord {
    param([byte[]]$Data, [int]$Offset)

    $owner = Read-DnsNameFromBuffer -Buffer $Data -Offset $Offset
    if ($null -eq $owner -or $owner.next -lt 0 -or ($owner.next + 10) -gt $Data.Length) { throw 'Malformed DNS resource record.' }
    $type = ([int]$Data[$owner.next] -shl 8) -bor [int]$Data[$owner.next + 1]
    $class = ([int]$Data[$owner.next + 2] -shl 8) -bor [int]$Data[$owner.next + 3]
    $rdLength = ([int]$Data[$owner.next + 8] -shl 8) -bor [int]$Data[$owner.next + 9]
    $rdOffset = $owner.next + 10
    if (($rdOffset + $rdLength) -gt $Data.Length) { throw 'DNS RDATA exceeds response bounds.' }
    return [pscustomobject]@{
      owner = ([string]$owner.name).TrimEnd('.').ToLowerInvariant()
      type = $type
      class = $class
      rdOffset = $rdOffset
      rdLength = $rdLength
      next = $rdOffset + $rdLength
    }
  }

  try {
    if ($null -eq $Buffer -or $Buffer.Length -lt 12) { throw 'Short DNS response.' }
    $responseId = ([int]$Buffer[0] -shl 8) -bor [int]$Buffer[1]
    if ($responseId -ne $TransactionId) { throw 'DNS transaction ID mismatch.' }

    $flags1 = [int]$Buffer[2]
    if (($flags1 -band 0x80) -eq 0) { throw 'DNS response flag is not set.' }
    if ((($flags1 -shr 3) -band 0x0F) -ne 0) { throw 'Unexpected DNS opcode.' }
    $result.authoritative = (($flags1 -band 0x04) -ne 0)
    $result.truncated = (($flags1 -band 0x02) -ne 0)
    if ($result.truncated) { throw 'Truncated DNS response.' }
    if (-not $result.authoritative) { throw 'DNS response is not authoritative.' }

    $rcode = ([int]$Buffer[3] -band 0x0F)
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

    $qdCount = ([int]$Buffer[4] -shl 8) -bor [int]$Buffer[5]
    $answerCount = ([int]$Buffer[6] -shl 8) -bor [int]$Buffer[7]
    $authorityCount = ([int]$Buffer[8] -shl 8) -bor [int]$Buffer[9]
    $additionalCount = ([int]$Buffer[10] -shl 8) -bor [int]$Buffer[11]
    if ($qdCount -ne 1 -or $answerCount -gt 32 -or $authorityCount -gt 32 -or $additionalCount -gt 32) {
      throw 'Unexpected DNS section count.'
    }

    $expectedName = ([string]$ExpectedName).Trim().TrimEnd('.').ToLowerInvariant()
    $expectedZone = ([string]$ExpectedZone).Trim().TrimEnd('.').ToLowerInvariant()
    $question = Read-DnsNameFromBuffer -Buffer $Buffer -Offset 12
    if ($null -eq $question -or ($question.next + 4) -gt $Buffer.Length) { throw 'Malformed DNS question.' }
    if (([string]$question.name).TrimEnd('.').ToLowerInvariant() -ne $expectedName) { throw 'DNS question name mismatch.' }
    $questionType = ([int]$Buffer[$question.next] -shl 8) -bor [int]$Buffer[$question.next + 1]
    $questionClass = ([int]$Buffer[$question.next + 2] -shl 8) -bor [int]$Buffer[$question.next + 3]
    if ($questionType -ne 1 -or $questionClass -ne 1) { throw 'DNS question type or class mismatch.' }

    $offset = $question.next + 4
    $answers = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $answerCount; $index++) {
      $record = Read-DomainReputationRecord -Data $Buffer -Offset $offset
      $offset = $record.next
      if ($record.type -ne 1 -or $record.class -ne 1 -or $record.owner -ne $expectedName -or $record.rdLength -ne 4) {
        throw 'Unexpected DNS answer record.'
      }
      $address = [System.Net.IPAddress]::new([byte[]]@(
        $Buffer[$record.rdOffset],
        $Buffer[$record.rdOffset + 1],
        $Buffer[$record.rdOffset + 2],
        $Buffer[$record.rdOffset + 3]
      )).ToString()
      $answers.Add($address)
    }

    for ($index = 0; $index -lt $authorityCount; $index++) {
      $record = Read-DomainReputationRecord -Data $Buffer -Offset $offset
      $offset = $record.next
      if ($record.type -eq 6 -and $record.class -eq 1) {
        $ownerCoversQuestion = ($expectedName -eq $record.owner -or $expectedName.EndsWith(".$($record.owner)", [StringComparison]::OrdinalIgnoreCase))
        $ownerCoversZone = ($expectedZone -eq $record.owner)
        if ($ownerCoversQuestion -and $ownerCoversZone) {
          $mname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $record.rdOffset
          $rname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $mname.next
          if ($null -eq $mname -or $null -eq $rname -or ($rname.next + 20) -gt ($record.rdOffset + $record.rdLength)) {
            throw 'Malformed SOA negative proof.'
          }
          $result.negativeProof = $true
        }
      }
    }

    for ($index = 0; $index -lt $additionalCount; $index++) {
      $record = Read-DomainReputationRecord -Data $Buffer -Offset $offset
      $offset = $record.next
    }

    if ($rcode -eq 3 -and -not $result.negativeProof) { throw 'NXDOMAIN lacks authoritative SOA proof.' }
    if ($rcode -eq 0 -and $answers.Count -eq 0 -and -not $result.negativeProof) { throw 'NOERROR response contains no recognized A answer or SOA proof.' }
    if ($rcode -ne 0 -and $rcode -ne 3) { throw "Provider returned $($result.rcodeLabel)." }

    $result.answers = @($answers | Sort-Object -Unique)
  } catch {
    $result.error = if ($_.Exception.Message -eq 'DNS transaction ID mismatch.') {
      'DNS transaction ID mismatch.'
    } else {
      'Invalid authoritative DNS response.'
    }
  }

  return $result
}

# Query heterogeneous provider/name pairs in one UDP Select window. Every socket
# is connected to one public authority endpoint, binding accepted datagrams to
# that source IP/port; the strict reader validates the transaction and question.
function Invoke-DomainReputationDnsFanout {
  param(
    [Parameter(Mandatory = $true)][object[]]$Queries,
    [int]$TimeoutMs = 2500
  )

  $outcomes = @{}
  if ($Queries.Count -eq 0) { return $outcomes }
  $timeout = [Math]::Min(5000, [Math]::Max(500, $TimeoutMs))
  $pending = @{}
  $sockets = [System.Collections.Generic.List[System.Net.Sockets.Socket]]::new()
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  # The transaction ID is one of only two entropy sources protecting these raw UDP
  # queries from off-path spoofing (the other is the OS-assigned source port), so it
  # must not come from Get-Random: that is not cryptographic, and concurrent worker
  # runspaces can seed correlated streams. Create() + GetBytes() works on 5.1 and 7.
  $txRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $txBytes = [byte[]]::new(2)

  try {
    foreach ($item in @($Queries)) {
      $socket = $null
      $key = ([string]$item.key).Trim()
      $ipText = ([string]$item.ip).Trim()
      $name = ([string]$item.name).Trim().TrimEnd('.').ToLowerInvariant()
      $zone = ([string]$item.zone).Trim().TrimEnd('.').ToLowerInvariant()
      if ([string]::IsNullOrWhiteSpace($key) -or $outcomes.ContainsKey($key)) { continue }

      $outcomes[$key] = [pscustomobject]@{
        rcode = $null; rcodeLabel = $null; authoritative = $false; truncated = $false
        negativeProof = $false; answers = @(); error = 'No response from provider authority.'
      }

      $parsedIp = $null
      if (-not [Net.IPAddress]::TryParse($ipText, [ref]$parsedIp) -or $parsedIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or -not (Test-IsPublicIpAddress -IpAddress $ipText)) {
        $outcomes[$key].error = 'Invalid provider authority address.'
        continue
      }

      $txRng.GetBytes($txBytes)
      $transactionId = ((([int]$txBytes[0]) -shl 8) -bor ([int]$txBytes[1]))
      if ($transactionId -le 0) { $transactionId = 1 }
      try {
        $packet = New-DomainReputationDnsQueryPacket -Name $name -TransactionId $transactionId
        $socket = [Net.Sockets.Socket]::new($parsedIp.AddressFamily, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
        $socket.Blocking = $false
        $socket.Connect([Net.IPEndPoint]::new($parsedIp, 53))
        [void]$socket.Send($packet)
        $sockets.Add($socket)
        $pending[$socket] = [pscustomobject]@{ key = $key; txid = $transactionId; name = $name; zone = $zone }
      } catch {
        $outcomes[$key].error = 'Could not query provider authority.'
        if ($socket) { try { $socket.Dispose() } catch { } }
      }
    }

    $buffer = New-Object byte[] 4096
    while ($pending.Count -gt 0) {
      $remaining = $timeout - $stopwatch.ElapsedMilliseconds
      if ($remaining -le 0) { break }
      $readList = New-Object System.Collections.ArrayList
      foreach ($socket in $pending.Keys) { [void]$readList.Add($socket) }
      $waitMicroseconds = [int]([Math]::Min(500000, [Math]::Max(1000, $remaining * 1000)))
      try { [Net.Sockets.Socket]::Select($readList, $null, $null, $waitMicroseconds) } catch { break }
      if ($readList.Count -eq 0) { continue }

      foreach ($socket in @($readList)) {
        $state = $pending[$socket]
        if ($null -eq $state) { continue }
        try {
          $received = $socket.Receive($buffer)
          if ($received -gt 0) {
            $exact = New-Object byte[] $received
            [Array]::Copy($buffer, $exact, $received)
            $parsed = Read-DomainReputationDnsResponse -Buffer $exact -TransactionId $state.txid -ExpectedName $state.name -ExpectedZone $state.zone
            if ($parsed.error -eq 'DNS transaction ID mismatch.') { continue }
            $outcomes[$state.key] = $parsed
          }
        } catch {
          $outcomes[$state.key].error = 'Provider authority connection error.'
        }
        $null = $pending.Remove($socket)
      }
    }
  } finally {
    foreach ($socket in $sockets) { try { $socket.Dispose() } catch { } }
    try { $txRng.Dispose() } catch { }
    $stopwatch.Stop()
  }

  return $outcomes
}

function Test-DomainReputationPositiveControl {
  param(
    [Parameter(Mandatory = $true)][object]$Provider,
    [AllowNull()][object]$ControlOutcome
  )

  $result = [pscustomobject]@{ state = 'unavailable'; accessValidated = $false; reasonCode = 'controlUnavailable' }
  if ($null -eq $ControlOutcome -or -not [string]::IsNullOrWhiteSpace([string]$ControlOutcome.error)) { return $result }
  if ([int]$ControlOutcome.rcode -eq 3) { $result.state = 'blocked'; $result.reasonCode = 'controlNxDomain'; return $result }
  if ([int]$ControlOutcome.rcode -ne 0) { $result.reasonCode = 'controlError'; return $result }

  $actual = @($ControlOutcome.answers | Sort-Object -Unique)
  $expected = @($Provider.controlExpected | Sort-Object -Unique)
  $controlMatches = $false
  if ([string]$Provider.controlMatch -eq 'anyOf') {
    $controlMatches = ($actual.Count -gt 0 -and @($actual | Where-Object { $expected -notcontains $_ }).Count -eq 0)
  } else {
    $controlMatches = (($actual -join '|') -eq ($expected -join '|'))
  }
  if (-not $controlMatches) {
    $result.state = if (@($actual | Where-Object { $_ -eq '127.0.0.1' -or $_ -eq '127.0.0.255' -or $_ -match '^127\.255\.255\.' }).Count -gt 0) { 'blocked' } else { 'invalid' }
    $result.reasonCode = 'controlUnexpected'
    return $result
  }

  $result.state = 'valid'
  $result.accessValidated = $true
  $result.reasonCode = $null
  return $result
}

function Test-DomainReputationProviderControl {
  param(
    [Parameter(Mandatory = $true)][object]$Provider,
    [AllowNull()][object]$ControlOutcome,
    [AllowNull()][object]$NegativeControlOutcome
  )

  $result = Test-DomainReputationPositiveControl -Provider $Provider -ControlOutcome $ControlOutcome
  if ($result.state -ne 'valid') { return $result }

  if ($null -eq $NegativeControlOutcome -or -not [string]::IsNullOrWhiteSpace([string]$NegativeControlOutcome.error)) {
    $result.state = 'unavailable'
    $result.accessValidated = $false
    $result.reasonCode = 'negativeControlUnavailable'
    return $result
  }
  $negativeAnswers = @($NegativeControlOutcome.answers)
  $isNegative = (([int]$NegativeControlOutcome.rcode -eq 3 -or [int]$NegativeControlOutcome.rcode -eq 0) -and
    $NegativeControlOutcome.negativeProof -eq $true -and $negativeAnswers.Count -eq 0)
  if (-not $isNegative) {
    $result.state = 'invalid'
    $result.accessValidated = $false
    $result.reasonCode = if ($negativeAnswers.Count -gt 0) { 'wildcardDetected' } else { 'negativeControlUnexpected' }
    return $result
  }

  $result.state = 'valid'
  $result.accessValidated = $true
  $result.reasonCode = $null
  return $result
}

function ConvertFrom-DomainReputationProviderOutcome {
  param(
    [Parameter(Mandatory = $true)][object]$Provider,
    [AllowNull()][object]$ControlOutcome,
    [AllowNull()][object]$NegativeControlOutcome,
    [AllowNull()][object]$TargetOutcome,
    [Parameter(Mandatory = $true)][string]$QueryDomain
  )

  $base = [ordered]@{
    providerId = [string]$Provider.id
    providerName = [string]$Provider.displayName
    queryDomain = $QueryDomain
    queriedNameCategory = [string]$Provider.queryNameMode
    state = 'unavailable'
    listed = $null
    categories = @()
    responseCodes = @()
    accessValidated = $false
    degraded = $false
    reasonCode = 'controlUnavailable'
    policyUrl = [string]$Provider.policyUrl
  }

  $controlState = Test-DomainReputationProviderControl -Provider $Provider -ControlOutcome $ControlOutcome -NegativeControlOutcome $NegativeControlOutcome
  if ($controlState.state -ne 'valid') {
    $base.state = $controlState.state
    $base.reasonCode = $controlState.reasonCode
    return [pscustomobject]$base
  }
  $base.accessValidated = $true

  if ($null -eq $TargetOutcome -or -not [string]::IsNullOrWhiteSpace([string]$TargetOutcome.error)) {
    $base.reasonCode = 'targetUnavailable'
    return [pscustomobject]$base
  }
  if (([int]$TargetOutcome.rcode -eq 3 -or [int]$TargetOutcome.rcode -eq 0) -and
    @($TargetOutcome.answers).Count -eq 0 -and $TargetOutcome.negativeProof -eq $true) {
    $base.state = 'notListed'; $base.listed = $false; $base.reasonCode = $null
    return [pscustomobject]$base
  }
  if ([int]$TargetOutcome.rcode -ne 0) {
    $base.reasonCode = 'targetError'
    return [pscustomobject]$base
  }

  $answers = @($TargetOutcome.answers | Sort-Object -Unique)
  $base.responseCodes = $answers
  if ($answers.Count -eq 0 -or @($answers | Where-Object { $_ -notmatch '^127\.' }).Count -gt 0) {
    $base.state = 'invalid'; $base.reasonCode = 'invalidAnswer'
    return [pscustomobject]$base
  }

  $categories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $blocked = $false
  $invalid = $false
  foreach ($answer in $answers) {
    $parts = @($answer -split '\.')
    if ($parts.Count -ne 4) { $invalid = $true; continue }
    $last = [int]$parts[3]
    switch ([string]$Provider.classifier) {
      'uribl' {
        if ($last -eq 255 -or (($last -band 1) -ne 0)) { $blocked = $true; continue }
        $answerRecognized = $false
        if (($last -band 2) -ne 0) { $null = $categories.Add('black'); $answerRecognized = $true }
        if (($last -band 4) -ne 0) { $null = $categories.Add('grey'); $answerRecognized = $true }
        if (($last -band 8) -ne 0) { $null = $categories.Add('red'); $answerRecognized = $true }
        if (($last -band 0xF0) -ne 0 -or -not $answerRecognized) { $invalid = $true }
      }
      'surbl' {
        if (($last -band 1) -ne 0) { $blocked = $true; continue }
        $answerRecognized = $false
        if (($last -band 4) -ne 0) { $null = $categories.Add('disposable-mail'); $answerRecognized = $true }
        if (($last -band 8) -ne 0) { $null = $categories.Add('phishing'); $answerRecognized = $true }
        if (($last -band 16) -ne 0) { $null = $categories.Add('malware'); $answerRecognized = $true }
        if (($last -band 32) -ne 0) { $null = $categories.Add('click-tracker'); $answerRecognized = $true }
        if (($last -band 64) -ne 0) { $null = $categories.Add('abuse'); $answerRecognized = $true }
        if (($last -band 128) -ne 0) { $null = $categories.Add('cracked'); $answerRecognized = $true }
        if (($last -band 2) -ne 0 -or -not $answerRecognized) { $invalid = $true }
      }
      'spamhausDbl' {
        if ($answer -match '^127\.255\.255\.' -or $answer -eq '127.0.1.255') { $blocked = $true; continue }
        $category = switch ($answer) {
          '127.0.1.2' { 'low-reputation' }
          '127.0.1.4' { 'phishing' }
          '127.0.1.5' { 'malware' }
          '127.0.1.6' { 'botnet-c2' }
          '127.0.1.102' { 'abused-legitimate' }
          '127.0.1.103' { 'abused-redirector' }
          '127.0.1.104' { 'abused-phishing' }
          '127.0.1.105' { 'abused-malware' }
          '127.0.1.106' { 'abused-botnet-c2' }
          default { $null }
        }
        if ($category) { $null = $categories.Add($category) } else { $invalid = $true }
      }
      'binary127002' {
        # Providers in this family signal an access/policy block with 127.0.0.1,
        # 127.0.0.255 or the 127.255.255.x range. Those must fail closed as
        # 'blocked' so the operator is told access was refused, rather than being
        # reported as a merely unreadable answer.
        if ($answer -eq '127.0.0.1' -or $answer -eq '127.0.0.255' -or $answer -match '^127\.255\.255\.') { $blocked = $true; continue }
        if ($answer -eq '127.0.0.2') { $null = $categories.Add('listed') } else { $invalid = $true }
      }
      default { $invalid = $true }
    }
  }

  if ($blocked) {
    $base.state = 'blocked'; $base.reasonCode = 'providerBlocked'
  } elseif ($invalid) {
    $base.state = 'invalid'; $base.reasonCode = 'invalidAnswer'
  } else {
    $base.state = 'listed'; $base.listed = $true; $base.categories = @($categories | Sort-Object); $base.reasonCode = $null
  }
  return [pscustomobject]$base
}

function Get-DomainReputationProviderEndpoints {
  param(
    [Parameter(Mandatory = $true)][object]$Provider,
    [int]$MaxEndpoints = 2
  )

  $limit = [Math]::Min(2, [Math]::Max(1, $MaxEndpoints))
  # Key on the fields that determine WHICH servers get discovered, so correcting a
  # profile cannot be masked by a 30-minute cache entry keyed on the id alone.
  $cacheKey = "endpoints:{0}|v{1}|{2}|{3}" -f ([string]$Provider.id).ToLowerInvariant(), [int]$Provider.profileVersion, ([string]$Provider.authorityDomain).Trim().TrimEnd('.').ToLowerInvariant(), ([string]$Provider.queryZone).Trim().TrimEnd('.').ToLowerInvariant()
  $cached = Get-DomainReputationCacheEntry -Key $cacheKey
  if ($cached) { return @($cached | Select-Object -First $limit) }

  $addresses = [System.Collections.Generic.List[string]]::new()
  $hosts = @(Get-DomainReputationAuthorityHosts -Provider $Provider | Sort-Object -Unique | Select-Object -First 4)
  foreach ($hostName in $hosts) {
    foreach ($ip in @(Resolve-NameserverPublicIps -NameserverHost $hostName)) {
      $parsedIp = $null
      if (-not [Net.IPAddress]::TryParse(([string]$ip).Trim(), [ref]$parsedIp)) { continue }
      if ($parsedIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
      if (-not (Test-IsPublicIpAddress -IpAddress ([string]$ip))) { continue }
      if (-not $addresses.Contains([string]$ip)) { $addresses.Add([string]$ip) }
    }
  }

  $result = @($addresses | Sort-Object | Select-Object -First 2)
  if ($result.Count -gt 0) { Set-DomainReputationCacheEntry -Key $cacheKey -Value $result -TtlSeconds 1800 }
  return @($result | Select-Object -First $limit)
}

function Get-DomainReputationStatus {
  param([Parameter(Mandatory = $true)][string]$Domain)

  $status = [pscustomobject]@{
    state = 'unknown'
    reasonCode = $null
    queryDomain = $null
    requestedCount = 0
    configuredCount = 0
    droppedCount = 0
    results = @()
    summary = [pscustomobject]@{
      providerCount = 0; validatedCount = 0; listedCount = 0; notListedCount = 0
      blockedCount = 0; errorCount = 0; riskSummary = 'Unknown'
    }
  }

  if (([string]$env:ACS_DISABLE_DOMAIN_REPUTATION).Trim() -eq '1') {
    $status.state = 'disabled'; $status.reasonCode = 'disabled'; return $status
  }

  $catalog = @(Get-DomainReputationProviderCatalog)
  $requestedIds = @()
  $configuredText = ([string]$env:ACS_DOMAIN_REPUTATION_PROVIDERS).Trim()
  if ([string]::IsNullOrWhiteSpace($configuredText)) {
    $requestedIds = @($catalog | Where-Object defaultEnabled | ForEach-Object id)
  } else {
    $requestedIds = @($configuredText -split '[,;\s]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
  }
  $status.requestedCount = $requestedIds.Count
  $providers = @($catalog | Where-Object { $requestedIds -contains $_.id } | Select-Object -First 8)
  $status.configuredCount = $providers.Count
  $status.droppedCount = [Math]::Max(0, $status.requestedCount - $status.configuredCount)
  if ($providers.Count -eq 0) { $status.state = 'disabled'; $status.reasonCode = 'noProviders'; return $status }

  $gateAcquired = $false
  try {
    $gateAcquired = $AcsDomainReputationGate.Wait(0)
    if (-not $gateAcquired) { $status.reasonCode = 'busy'; return $status }

    $timeout = 2500
    $configuredTimeout = 0
    if ([int]::TryParse([string]$env:ACS_DOMAIN_REPUTATION_TIMEOUT_MS, [ref]$configuredTimeout) -and $configuredTimeout -gt 0) {
      $timeout = [Math]::Min(5000, [Math]::Max(500, $configuredTimeout))
    }
    $maxEndpoints = 1
    $configuredEndpoints = 0
    if ([int]::TryParse([string]$env:ACS_DOMAIN_REPUTATION_MAX_ENDPOINTS, [ref]$configuredEndpoints) -and $configuredEndpoints -gt 0) {
      $maxEndpoints = [Math]::Min(2, [Math]::Max(1, $configuredEndpoints))
    }

    $pendingProviders = [System.Collections.Generic.List[object]]::new()
    $providerResults = [System.Collections.Generic.List[object]]::new()

    foreach ($provider in $providers) {
      $queryDomain = if ($provider.queryNameMode -eq 'registrableDomain') { Get-RegistrableDomain -Domain $Domain } else { ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant() }
      if ([string]::IsNullOrWhiteSpace($queryDomain) -or -not (Test-DomainName -Domain $queryDomain)) {
        $providerResults.Add([pscustomobject]@{ providerId=$provider.id;providerName=$provider.displayName;queryDomain=$queryDomain;queriedNameCategory=$provider.queryNameMode;state='invalid';listed=$null;categories=@();responseCodes=@();accessValidated=$false;degraded=$false;reasonCode='invalidName';policyUrl=$provider.policyUrl })
        continue
      }
      if ([string]::IsNullOrWhiteSpace($status.queryDomain)) { $status.queryDomain = $queryDomain }

      $domainHash = Get-DomainReputationCacheKey -Value "$($provider.id)|$($provider.profileVersion)|$($provider.classifier)|$($provider.queryZone)|$queryDomain"
      $resultCacheKey = "result:$domainHash"
      $cachedResult = Get-DomainReputationCacheEntry -Key $resultCacheKey
      if ($cachedResult) { $providerResults.Add($cachedResult); continue }

      $endpoints = @(Get-DomainReputationProviderEndpoints -Provider $provider -MaxEndpoints $maxEndpoints)
      if ($endpoints.Count -eq 0) {
        $providerResults.Add([pscustomobject]@{ providerId=$provider.id;providerName=$provider.displayName;queryDomain=$queryDomain;queriedNameCategory=$provider.queryNameMode;state='unavailable';listed=$null;categories=@();responseCodes=@();accessValidated=$false;degraded=$false;reasonCode='noAuthority';policyUrl=$provider.policyUrl })
        continue
      }

      $endpointStates = [System.Collections.Generic.List[object]]::new()
      foreach ($endpoint in $endpoints) {
        $endpointKey = ([string]$endpoint).Replace(':', '_')
        $health = Get-DomainReputationHealthEntry -ProviderId $provider.id -Endpoint $endpoint -ProfileVersion ([int]$provider.profileVersion)
        $control = if ($health) { $health.control } else { $null }
        $endpointStates.Add([pscustomobject]@{ endpoint=$endpoint;endpointKey=$endpointKey;control=$control;controlFromCache=($null -ne $control) })
      }
      # Every endpoint costs three queries regardless of cache state: one positive
      # control (sent in stage 1 when absent, re-sent in stage 2 when cached), plus
      # the negative control and the target.
      $estimatedCost = 3 * $endpointStates.Count
      $pendingProviders.Add([pscustomobject]@{ provider=$provider;queryDomain=$queryDomain;cacheKey=$resultCacheKey;endpointStates=$endpointStates.ToArray();estimatedCost=$estimatedCost })
    }

    $activeProviders = [System.Collections.Generic.List[object]]::new()
    foreach ($pending in $pendingProviders) {
      $provider = $pending.provider
      # Charge the shared budget PER PROVIDER, not as one all-or-nothing total.
      # An aggregate reservation let a single unreachable opt-in provider push the
      # combined cost over the limit and drop every provider, including the ones
      # that work. Catalog order puts the default-enabled providers first.
      $providerBudgetAvailable = ($pending.estimatedCost -le 0 -or (Test-DomainReputationQueryBudget -Cost $pending.estimatedCost))
      if ($providerBudgetAvailable) {
        $providerBudgetAvailable = Test-DomainReputationProviderBudget -ProviderId $provider.id -Cost $pending.estimatedCost -RatePerMinute ([int]$provider.queriesPerMinute) -Burst ([int]$provider.queryBurst)
      }
      if ($providerBudgetAvailable) {
        $activeProviders.Add($pending)
      } else {
        $providerResults.Add([pscustomobject]@{ providerId=$provider.id;providerName=$provider.displayName;queryDomain=$pending.queryDomain;queriedNameCategory=$provider.queryNameMode;state='unavailable';listed=$null;categories=@();responseCodes=@();accessValidated=$false;degraded=$false;reasonCode='queryBudget';policyUrl=$provider.policyUrl })
      }
    }

    # Stage 1: a provider sees no customer domain until its documented positive
    # control succeeds. Successful controls are cached briefly per endpoint.
    $controlQueries = [System.Collections.Generic.List[object]]::new()
    foreach ($pending in $activeProviders) {
      foreach ($endpointState in @($pending.endpointStates)) {
        if ($null -ne $endpointState.control) { continue }
        $provider = $pending.provider
        $controlQueries.Add([pscustomobject]@{
          key="$($provider.id)|$($endpointState.endpointKey)|control"
          ip=$endpointState.endpoint
          name="$($provider.controlDomain).$($provider.queryZone)"
          zone=$provider.queryZone
          purpose='control'
        })
      }
    }
    $controlOutcomes = if ($controlQueries.Count -gt 0) { Invoke-DomainReputationDnsFanout -Queries $controlQueries.ToArray() -TimeoutMs $timeout } else { @{} }

    foreach ($pending in $activeProviders) {
      foreach ($endpointState in @($pending.endpointStates)) {
        if ($null -eq $endpointState.control) {
          $key = "$($pending.provider.id)|$($endpointState.endpointKey)|control"
          $endpointState.control = $controlOutcomes[$key]
          $positiveState = Test-DomainReputationPositiveControl -Provider $pending.provider -ControlOutcome $endpointState.control
          if ($positiveState.state -eq 'valid') {
            Set-DomainReputationHealthEntry -ProviderId $pending.provider.id -Endpoint $endpointState.endpoint -ProfileVersion ([int]$pending.provider.profileVersion) -Value ([pscustomobject]@{control=$endpointState.control}) -TtlSeconds 300
          }
        }
      }
    }

    # Stage 2: only positive-control-valid endpoints receive the customer name.
    # A fresh negative control is sent in the same window; wildcarded or
    # repurposed zones therefore cannot create a listing or a clean verdict.
    $targetQueries = [System.Collections.Generic.List[object]]::new()
    foreach ($pending in $activeProviders) {
      foreach ($endpointState in @($pending.endpointStates)) {
        $positiveState = Test-DomainReputationPositiveControl -Provider $pending.provider -ControlOutcome $endpointState.control
        if ($positiveState.state -ne 'valid') { continue }
        $provider = $pending.provider
        $targetQueries.Add([pscustomobject]@{ key="$($provider.id)|$($endpointState.endpointKey)|negative";ip=$endpointState.endpoint;name="$($provider.negativeControlDomain).$($provider.queryZone)";zone=$provider.queryZone;purpose='negative' })
        $targetQueries.Add([pscustomobject]@{ key="$($provider.id)|$($endpointState.endpointKey)|target";ip=$endpointState.endpoint;name="$($pending.queryDomain).$($provider.queryZone)";zone=$provider.queryZone;purpose='target' })
        # A cached positive control only authorizes SENDING the customer name. The
        # verdict itself must rest on a control observed in THIS request: a provider
        # that begins refusing access by answering NXDOMAIN for every name is
        # otherwise indistinguishable from a genuine "not listed" answer, which
        # would produce a false clean for the life of the health entry. Re-querying
        # it inside the same fan-out window costs one packet and no extra round trip.
        if ($endpointState.controlFromCache) {
          $targetQueries.Add([pscustomobject]@{ key="$($provider.id)|$($endpointState.endpointKey)|control2";ip=$endpointState.endpoint;name="$($provider.controlDomain).$($provider.queryZone)";zone=$provider.queryZone;purpose='control' })
        }
      }
    }
    $targetOutcomes = if ($targetQueries.Count -gt 0) { Invoke-DomainReputationDnsFanout -Queries $targetQueries.ToArray() -TimeoutMs $timeout } else { @{} }

    # Replace every cache-sourced control with the freshly observed one before any
    # verdict is computed, so the classifier fails closed when access was revoked.
    # A failed refresh deliberately does NOT overwrite the cached entry: caching a
    # failure would block the endpoint from re-probing until the entry expired.
    foreach ($pending in $activeProviders) {
      foreach ($endpointState in @($pending.endpointStates)) {
        if (-not $endpointState.controlFromCache) { continue }
        $freshControl = $targetOutcomes["$($pending.provider.id)|$($endpointState.endpointKey)|control2"]
        if ($null -eq $freshControl) {
          # Never fall back to the stale cached control: keep the freshness guarantee
          # local rather than depending on the fan-out pre-populating every key.
          $endpointState.control = [pscustomobject]@{ rcode=$null;rcodeLabel=$null;authoritative=$false;truncated=$false;negativeProof=$false;answers=@();error='Fresh positive control unavailable.' }
          continue
        }
        $endpointState.control = $freshControl
        $freshState = Test-DomainReputationPositiveControl -Provider $pending.provider -ControlOutcome $freshControl
        if ($freshState.state -eq 'valid') {
          Set-DomainReputationHealthEntry -ProviderId $pending.provider.id -Endpoint $endpointState.endpoint -ProfileVersion ([int]$pending.provider.profileVersion) -Value ([pscustomobject]@{control=$freshControl}) -TtlSeconds 300
        }
      }
    }

    foreach ($pending in $activeProviders) {
      $endpointResults = [System.Collections.Generic.List[object]]::new()
      foreach ($endpointState in @($pending.endpointStates)) {
        $control = $endpointState.control
        $negative = $targetOutcomes["$($pending.provider.id)|$($endpointState.endpointKey)|negative"]
        $target = $targetOutcomes["$($pending.provider.id)|$($endpointState.endpointKey)|target"]
        if ($null -eq $control) { $control = [pscustomobject]@{rcode=$null;answers=@();negativeProof=$false;error='Query budget unavailable.'} }
        if ($null -eq $negative) { $negative = [pscustomobject]@{rcode=$null;answers=@();negativeProof=$false;error='Negative control unavailable.'} }
        if ($null -eq $target) { $target = [pscustomobject]@{rcode=$null;answers=@();negativeProof=$false;error='Query budget unavailable.'} }
        $endpointResults.Add((ConvertFrom-DomainReputationProviderOutcome -Provider $pending.provider -ControlOutcome $control -NegativeControlOutcome $negative -TargetOutcome $target -QueryDomain $pending.queryDomain))
      }

      $listedResults = @($endpointResults | Where-Object state -eq 'listed')
      $cleanResults = @($endpointResults | Where-Object state -eq 'notListed')
      $blockedResults = @($endpointResults | Where-Object state -eq 'blocked')
      $result = $null
      if ($listedResults.Count -gt 0) {
        $first = $listedResults[0]
        $result = [pscustomobject]@{ providerId=$first.providerId;providerName=$first.providerName;queryDomain=$first.queryDomain;queriedNameCategory=$first.queriedNameCategory;state='listed';listed=$true;categories=@($listedResults.categories|Sort-Object -Unique);responseCodes=@($listedResults.responseCodes|Sort-Object -Unique);accessValidated=$true;degraded=($endpointResults.Count -gt $listedResults.Count);reasonCode=$(if($cleanResults.Count -gt 0){'endpointDisagreement'}else{$null});policyUrl=$first.policyUrl }
      } elseif ($cleanResults.Count -gt 0) {
        $first = $cleanResults[0]
        $result = [pscustomobject]@{ providerId=$first.providerId;providerName=$first.providerName;queryDomain=$first.queryDomain;queriedNameCategory=$first.queriedNameCategory;state='notListed';listed=$false;categories=@();responseCodes=@();accessValidated=$true;degraded=($endpointResults.Count -gt $cleanResults.Count);reasonCode=$(if($endpointResults.Count -gt $cleanResults.Count){'partialEndpoints'}else{$null});policyUrl=$first.policyUrl }
      } elseif ($blockedResults.Count -gt 0) {
        $first = $blockedResults[0]
        $result = [pscustomobject]@{ providerId=$first.providerId;providerName=$first.providerName;queryDomain=$first.queryDomain;queriedNameCategory=$first.queriedNameCategory;state='blocked';listed=$null;categories=@();responseCodes=@();accessValidated=$false;degraded=$false;reasonCode=$first.reasonCode;policyUrl=$first.policyUrl }
      } else {
        $first = $endpointResults[0]
        $result = [pscustomobject]@{ providerId=$pending.provider.id;providerName=$pending.provider.displayName;queryDomain=$pending.queryDomain;queriedNameCategory=$pending.provider.queryNameMode;state='unavailable';listed=$null;categories=@();responseCodes=@();accessValidated=$false;degraded=$false;reasonCode=$(if($first){$first.reasonCode}else{'unavailable'});policyUrl=$pending.provider.policyUrl }
      }
      $providerResults.Add($result)
      # An unreachable provider is cached longer than a few seconds so a sequential
      # multi-domain sweep does not re-probe it once per domain.
      $ttl = if ($result.state -eq 'listed') { 300 } elseif ($result.state -eq 'notListed') { 120 } elseif ($result.state -eq 'blocked') { 300 } else { 60 }
      Set-DomainReputationCacheEntry -Key $pending.cacheKey -Value $result -TtlSeconds $ttl
    }

    $results = @($providerResults | Sort-Object providerId)
    $validated = @($results | Where-Object { $_.state -eq 'listed' -or $_.state -eq 'notListed' })
    $listed = @($results | Where-Object state -eq 'listed')
    $notListed = @($results | Where-Object state -eq 'notListed')
    $blocked = @($results | Where-Object state -eq 'blocked')
    $errors = @($results | Where-Object { $_.state -eq 'unavailable' -or $_.state -eq 'invalid' -or $_.degraded -eq $true })

    $status.results = @($results)
    $status.summary = [pscustomobject]@{
      providerCount = $results.Count
      validatedCount = $validated.Count
      listedCount = $listed.Count
      notListedCount = $notListed.Count
      blockedCount = $blocked.Count
      errorCount = $errors.Count
      riskSummary = if ($listed.Count -gt 0) { 'Warning' } elseif ($validated.Count -gt 0 -and $errors.Count -eq 0 -and $blocked.Count -eq 0) { 'Clean' } else { 'Unknown' }
    }
    $status.state = if ($listed.Count -gt 0) { 'listed' } elseif ($validated.Count -gt 0 -and $errors.Count -eq 0 -and $blocked.Count -eq 0) { 'clean' } elseif ($validated.Count -gt 0) { 'partial' } else { 'unknown' }
    if ($status.state -eq 'unknown' -and $blocked.Count -gt 0) { $status.reasonCode = 'providerBlocked' }
    # Surface a budget exhaustion at the top level too. Without this the operator
    # sees a bare 'unknown' with no explanation of why nothing was queried.
    elseif ($status.state -eq 'unknown' -and $results.Count -gt 0 -and @($results | Where-Object { $_.reasonCode -eq 'queryBudget' }).Count -eq $results.Count) { $status.reasonCode = 'queryBudget' }
  } catch {
    # Keep the failure diagnosable without leaking the domain, the provider
    # response, or the raw exception text into the log.
    try { Write-AcsLogException -Component 'DomainReputation' -Operation 'GetDomainReputationStatus' -EventId 'ACS-DOMAINREP-FAIL' -ErrorCode 'internalError' -Exception $_.Exception -Level 'Error' } catch { $null = $_ }
    $status.state = 'unknown'
    $status.reasonCode = 'internalError'
  } finally {
    if ($gateAcquired) { $null = $AcsDomainReputationGate.Release() }
  }

  return $status
}

function Get-CombinedReputationState {
  param(
    [Parameter(Mandatory = $true)][object]$IpSummary,
    [Parameter(Mandatory = $true)][string]$IpCheckState,
    [Parameter(Mandatory = $true)][object]$DomainReputation
  )

  $ipValid = [Math]::Max(0, [int]$IpSummary.totalQueries - [int]$IpSummary.errorCount)
  $ipErrors = [Math]::Max(0, [int]$IpSummary.errorCount)
  $ipListed = [int]$IpSummary.listedCount -gt 0
  $domainState = if ($DomainReputation) { [string]$DomainReputation.state } else { 'disabled' }

  # A mail-IP scope that had ANY failed query is not proof of a clean domain, and
  # the legacy summary.riskSummary already reports Warning in exactly that case.
  # Returning 'clean' here would put two contradictory verdicts in the SAME payload
  # (green badge above its own "errors: N" detail line), which is the recurring
  # failure this codebase forbids. Degrade to 'partial' (WARN) instead.
  $ipClean = ($IpCheckState -eq 'checked' -and $ipValid -gt 0 -and $ipErrors -eq 0)

  if ($ipListed -or $domainState -eq 'listed') { return 'listed' }
  if ($domainState -eq 'clean') {
    if ($IpCheckState -eq 'notApplicable' -or $ipClean) { return 'clean' }
    return 'partial'
  }
  if ($domainState -eq 'partial') { return 'partial' }
  if ($domainState -eq 'disabled') {
    if ($IpCheckState -eq 'notApplicable') { return 'notApplicable' }
    if ($ipClean) { return 'clean' }
  }
  if ($IpCheckState -eq 'checked' -and $ipValid -gt 0) { return 'partial' }
  return 'unknown'
}
