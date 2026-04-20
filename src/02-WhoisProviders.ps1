# ===== WHOIS Lookup Providers =====
# Registries such as SWITCH (.ch / .li), DENIC (.de) and AFNIC (.fr) aggressively
# block port-43 WHOIS queries from datacenter or repeat-offender IP ranges and
# return a short refusal message instead of registration data. Detect those
# refusals here so Get-DomainRegistrationStatus can keep walking the provider
# chain (RDAP -> alternate WHOIS hosts -> APIs) instead of surfacing the block
# text to the user as if it were the registration record.
function Test-WhoisResponseIsRegistryBlock {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  # SWITCH (.ch / .li): "Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries."
  # DENIC (.de):        "Your queries are too fast. Please slow down ..." / "% Excessive querying, blocked."
  # AFNIC (.fr):        "%% Excessive number of queries."
  # ARIN/RIPE generic:  "Query rate of your IP exceeded the maximum ..." / "AUTHENTICATION_REQUIRED"
  if ($Text -match '(?im)(Requests of this client are not permitted|Excessive (?:number of )?quer(?:y|ies|ying)|Query rate of your IP|queries are too fast|rate[- ]?limit(?:ed|ing)?|too many requests|temporarily blocked|access (?:has been )?(?:denied|blocked)|AUTHENTICATION_REQUIRED|please use https?://[^\s]+/whois)') {
    return $true
  }

  return $false
}

function Test-WhoisRawTextHasUsableData {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  if ($Text -match '(?im)\b(No Data Found|No match for|NOT FOUND|Status:\s*AVAILABLE|Malformed request\.?|Invalid query|Invalid domain name|This query returned 0 objects)\b') {
    return $false
  }

  if ($Text -match '(?im)\b(getaddrinfo\(|Name or service not known|Temporary failure in name resolution|Connection timed out|Network is unreachable|No route to host|Connection refused|Servname not supported for ai_socktype|socket error|connect\s+failed|No such host is known|The remote name could not be resolved|Unable to connect)\b') {
    return $false
  }

  # Treat registry refusal/rate-limit responses as not-usable so the chain continues.
  if (Test-WhoisResponseIsRegistryBlock -Text $Text) {
    return $false
  }

  return $true
}

function Get-WhoisCreationDateLabelRegex {
  '(?im)^(Creation Date|Created On|Registered On|Registered on|Registration Date|Registered|Domain Create Date|Creation date|Domain record activated):\s*(.+)$'
}

function Get-WhoisExpiryDateLabelRegex {
  '(?im)^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Registrar Registration Expiration date|Domain expires):\s*(.+)$'
}

# Keep WHOIS field extraction in one place so all fallback providers recognize
# the same registry-specific labels and block-style sections such as EDUCAUSE's
# multi-line "Registrant:" blocks for .edu domains.
function Get-WhoisParsedRegistrationData {
  param([string]$Text)

  $creation = $null
  $expiry = $null
  $registrar = $null
  $registrant = $null

  if ([string]::IsNullOrWhiteSpace($Text)) {
    return [pscustomobject]@{
      creationDate = $creation
      expiryDate   = $expiry
      registrar    = $registrar
      registrant   = $registrant
    }
  }

  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  $creationPattern = Get-WhoisCreationDateLabelRegex
  $expiryPattern = Get-WhoisExpiryDateLabelRegex
  $lines = $Text -split "`r?`n"

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $l = [string]$lines[$i]
    $trimmed = $l.Trim()
    if (-not $trimmed) { continue }

    if (-not $creation -and $trimmed -match $creationPattern) {
      $val = $Matches[2].Trim()
      if ($canConvertDates) {
        try { $creation = ConvertTo-NullableUtcIso8601 $val } catch { $creation = $val }
      } else {
        $creation = $val
      }
      continue
    }

    if (-not $expiry -and $trimmed -match $expiryPattern) {
      $val = $Matches[2].Trim()
      if ($canConvertDates) {
        try { $expiry = ConvertTo-NullableUtcIso8601 $val } catch { $expiry = $val }
      } else {
        $expiry = $val
      }
      continue
    }

    if (-not $registrar -and $trimmed -match '(?i)^(Registrar|Registrar name|Registrar Name|Sponsoring Registrar):\s*(.+)$') {
      $registrar = $Matches[2].Trim()
      continue
    }

    if (-not $registrant -and $trimmed -match '(?i)^(Registrant Name|Registrant Organisation|Registrant Organization):\s*(.+)$') {
      $registrant = $Matches[2].Trim()
      continue
    }

    if (-not $registrant -and $trimmed -match '(?i)^Registrant:\s*$') {
      for ($j = $i + 1; $j -lt $lines.Count; $j++) {
        $candidate = [string]$lines[$j]
        $candidateTrimmed = $candidate.Trim()
        if (-not $candidateTrimmed) {
          if ($j -gt ($i + 1)) { break }
          continue
        }

        if ($candidateTrimmed -match '^[A-Za-z][A-Za-z0-9 .''()&,/+-]{0,80}:\s*') {
          break
        }

        $registrant = $candidateTrimmed
        break
      }
    }
  }

  return [pscustomobject]@{
    creationDate = $creation
    expiryDate   = $expiry
    registrar    = $registrar
    registrant   = $registrant
  }
}

# Windows-only WHOIS lookup using the Sysinternals whois.exe tool.
# Launches whois.exe as a child process, captures stdout/stderr, and parses
# registration fields (creation date, expiry, registrar, registrant) from the raw output.
function Invoke-SysinternalsWhoisLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$WhoisPath,

    [int]$TimeoutSec = 25,

    # Set this if you want errors to bubble up instead of returning $null
    [switch]$ThrowOnError
  )

  $exe = $WhoisPath
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = $env:SYSINTERNALS_WHOIS_PATH }
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = 'whois.exe' }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  # If caller provided a path (or env var did), validate it exists.
  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:SYSINTERNALS_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois.exe' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Sysinternals whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  # Ensure we can parse dates without crashing the whole lookup
  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  $p = $null

  try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe

    # Sysinternals whois usage supports -v to follow referrals; /accepteula avoids interactive prompt
    # Use ArgumentList (array form) to avoid shell injection via crafted domain names.
    try {
      $psi.ArgumentList.Add('/accepteula')
      $psi.ArgumentList.Add('-v')
      $psi.ArgumentList.Add($d)
    } catch {
      # Older .NET runtimes may not support ArgumentList; fall back to Arguments with validation.
      # Domain is already validated by Test-DomainName (alphanumeric, dots, hyphens only).
      $psi.Arguments = "/accepteula -v `"$d`""
    }

    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    # Best-effort encoding
    try {
      $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
      $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
    } catch { }

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) {
      $msg = "Failed to start whois process."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()

    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
      try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      $msg = "Sysinternals whois timed out after $TimeoutSec seconds for '$d'."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    # Some tools write normal output to stderr; combine both safely
    $text = (($out, $err) -join "`r`n").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = "Sysinternals whois returned no output for '$d'. ExitCode=$($p.ExitCode)."
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    # Parse what we can (never fail the whole lookup on parse issues).
    $parsed = Get-WhoisParsedRegistrationData -Text $text
    $creation = $parsed.creationDate
    $expiry = $parsed.expiryDate
    $registrar = $parsed.registrar
    $registrant = $parsed.registrant

    return [pscustomobject]@{
      creationDate = $creation
      expiryDate   = $expiry
      registrar    = $registrar
      registrant   = $registrant
      rawText      = $text
      exitCode     = $p.ExitCode
      whoisExe     = $exe
    }
  }
  catch {
    $msg = "Sysinternals whois failed: $($_.Exception.Message)"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }
  finally {
    try { if ($p) { $p.Dispose() } } catch { }
  }
}

# Linux WHOIS lookup using the system `whois` CLI binary.
# Tries the default whois server first, then cycles through TLD-specific fallback servers
# (e.g., whois.verisign-grs.com for .com/.net) if the initial query returns no useful data.
function Invoke-LinuxWhoisLookup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$WhoisPath,

    [int]$TimeoutSec = 25,

    [switch]$ThrowOnError
  )

  # Inner helper: execute a single whois query against a specific server.
  function Invoke-LinuxWhoisQuery {
    param(
      [Parameter(Mandatory = $true)]
      [string]$Exe,

      [Parameter(Mandatory = $true)]
      [string]$LookupDomain,

      [string]$Server,

      [int]$ServerPort = 43,

      [int]$QueryTimeoutSec = 25
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Exe

    try {
      if ([string]::IsNullOrWhiteSpace($Server)) {
        $psi.ArgumentList.Add('--')
        $psi.ArgumentList.Add($LookupDomain)
      } else {
        $psi.ArgumentList.Add('-h')
        $psi.ArgumentList.Add($Server)
        if ($ServerPort -ne 43) {
          $psi.ArgumentList.Add('-p')
          $psi.ArgumentList.Add($ServerPort.ToString())
        }
        $psi.ArgumentList.Add('--')
        $psi.ArgumentList.Add($LookupDomain)
      }
    } catch {
      if ([string]::IsNullOrWhiteSpace($Server)) {
        $psi.Arguments = "-- `"$LookupDomain`""
      } else {
        if ($ServerPort -ne 43) {
          $psi.Arguments = "-h `"$Server`" -p $ServerPort -- `"$LookupDomain`""
        } else {
          $psi.Arguments = "-h `"$Server`" -- `"$LookupDomain`""
        }
      }
    }

    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    try {
      $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
      $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
    } catch { }

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) {
      throw 'Failed to start whois process.'
    }

    try {
      $out = $p.StandardOutput.ReadToEnd()
      $err = $p.StandardError.ReadToEnd()

      if (-not $p.WaitForExit($QueryTimeoutSec * 1000)) {
        try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
        throw "whois timed out after $QueryTimeoutSec seconds for '$LookupDomain'."
      }

      return [pscustomobject]@{
        text = (($out, $err) -join "`r`n").Trim()
        exitCode = $p.ExitCode
        server = $Server
        port = $ServerPort
      }
    }
    finally {
      try { $p.Dispose() } catch { }
    }
  }

  $exe = $WhoisPath
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = $env:LINUX_WHOIS_PATH }
  if ([string]::IsNullOrWhiteSpace($exe)) { $exe = 'whois' }

  $cmdExists = $null
  try { $cmdExists = Get-Command -Name $exe -ErrorAction SilentlyContinue } catch { $cmdExists = $null }
  if (-not $cmdExists) {
    $msg = "Linux whois executable not found (expected '$exe'). Install the 'whois' package in the container image."
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  $serverList = New-Object System.Collections.Generic.List[string]
  $null = $serverList.Add($null)

  $envServerText = [string]$env:ACS_LINUX_WHOIS_SERVERS
  if (-not [string]::IsNullOrWhiteSpace($envServerText)) {
    foreach ($serverCandidate in @($envServerText -split '[,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      $normalizedServer = ([string]$serverCandidate).Trim()
      if (-not [string]::IsNullOrWhiteSpace($normalizedServer) -and -not $serverList.Contains($normalizedServer)) {
        $null = $serverList.Add($normalizedServer)
      }
    }
  }

  $defaultFallbackServers = @()
  switch -Regex ($d) {
    '(?i)\.com$|\.net$' { $defaultFallbackServers = @('whois.verisign-grs.com'); break }
    '(?i)\.org$'         { $defaultFallbackServers = @('whois.pir.org'); break }
    '(?i)\.info$'        { $defaultFallbackServers = @('whois.afilias.net'); break }
    '(?i)\.biz$'         { $defaultFallbackServers = @('whois.biz'); break }
    '(?i)\.io$'          { $defaultFallbackServers = @('whois.nic.io'); break }
    '(?i)\.ai$'          { $defaultFallbackServers = @('whois.nic.ai'); break }
    '(?i)\.app$|\.dev$' { $defaultFallbackServers = @('whois.nic.google'); break }
    '(?i)\.eu$'          { $defaultFallbackServers = @('whois.eu'); break }
    '(?i)\.uk$|\.co\.uk$|\.org\.uk$|\.gov\.uk$|\.ac\.uk$' { $defaultFallbackServers = @('whois.nic.uk'); break }
    '(?i)\.de$'          { $defaultFallbackServers = @('whois.denic.de'); break }
    '(?i)\.fr$'          { $defaultFallbackServers = @('whois.nic.fr'); break }
    '(?i)\.au$|\.com\.au$|\.net\.au$|\.org\.au$' { $defaultFallbackServers = @('whois.auda.org.au'); break }
    '(?i)\.ca$'          { $defaultFallbackServers = @('whois.cira.ca'); break }
    '(?i)\.jp$|\.co\.jp$|\.ne\.jp$|\.or\.jp$' { $defaultFallbackServers = @('whois.jprs.jp'); break }
    '(?i)\.us$'          { $defaultFallbackServers = @('whois.nic.us', 'us.whois-servers.net'); break }
    '(?i)\.co$'          { $defaultFallbackServers = @('whois.registry.co'); break }
    '(?i)\.gov$'         { $defaultFallbackServers = @('whois.dotgov.gov'); break }
    '(?i)\.edu$'         { $defaultFallbackServers = @('whois.educause.edu'); break }
    '(?i)\.mil$'         { $defaultFallbackServers = @('whois.nic.mil'); break }
  }

  foreach ($defaultServer in $defaultFallbackServers) {
    if (-not [string]::IsNullOrWhiteSpace($defaultServer) -and -not $serverList.Contains($defaultServer)) {
      if (-not $serverList.Contains($defaultServer)) {
        $null = $serverList.Add($defaultServer)
      }
    }
  }

  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:LINUX_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Linux whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  try {
    $text = $null
    $exitCode = $null
    $usedServer = $null
    $lastQueryError = $null

    foreach ($server in $serverList) {
      try {
        $queryResult = Invoke-LinuxWhoisQuery -Exe $exe -LookupDomain $d -Server $server -ServerPort 43 -QueryTimeoutSec $TimeoutSec
        $exitCode = $queryResult.exitCode

        if (Test-WhoisRawTextHasUsableData -Text $queryResult.text) {
          $text = $queryResult.text
          $usedServer = $queryResult.server
          break
        }

        if (-not [string]::IsNullOrWhiteSpace($queryResult.text)) {
          $lastQueryError = ($queryResult.text -split "`r?`n" | Select-Object -First 1)
        }
      }
      catch {
        $lastQueryError = $_.Exception.Message
      }
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = if (-not [string]::IsNullOrWhiteSpace($lastQueryError)) {
        "whois failed for '$d'. $lastQueryError"
      } else {
        "whois returned no output for '$d'." + $(if ($null -ne $exitCode) { " ExitCode=$exitCode." } else { '' })
      }
      if ($ThrowOnError) { throw $msg } else { return $null }
    }

    $parsed = Get-WhoisParsedRegistrationData -Text $text
    $creation = $parsed.creationDate
    $expiry = $parsed.expiryDate
    $registrar = $parsed.registrar
    $registrant = $parsed.registrant

    return [pscustomobject]@{
      creationDate = $creation
      expiryDate   = $expiry
      registrar    = $registrar
      registrant   = $registrant
      rawText      = $text
      exitCode     = $exitCode
      whoisExe     = $exe
      whoisServer  = $usedServer
    }
  }
  catch {
    $innerMsg = $_.Exception.Message
    # Avoid double-wrapping errors that were explicitly thrown from the no-data path above
    $msg = if ($innerMsg -match '^whois (failed for|returned no output for)\b') { $innerMsg } else { "whois failed: $innerMsg" }
    if ($ThrowOnError) { throw $msg } else { return $null }
  }
}

function Invoke-TcpWhoisLookup {
  <#
  .SYNOPSIS
    Pure PowerShell TCP-based whois client that connects directly to port 43.
    Bypasses the Linux whois CLI getaddrinfo() service-name resolution issue
    ("Servname not supported for ai_socktype") that occurs in minimal Docker containers.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [int]$TimeoutSec = 15,

    [switch]$ThrowOnError
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($d)) { return $null }

  # Build server list based on TLD (same mapping as Invoke-LinuxWhoisLookup).
  $servers = New-Object System.Collections.Generic.List[string]

  switch -Regex ($d) {
    '(?i)\.com$|\.net$'                                     { $servers.Add('whois.verisign-grs.com'); break }
    '(?i)\.org$'                                            { $servers.Add('whois.pir.org'); break }
    '(?i)\.info$'                                           { $servers.Add('whois.afilias.net'); break }
    '(?i)\.biz$'                                            { $servers.Add('whois.biz'); break }
    '(?i)\.io$'                                             { $servers.Add('whois.nic.io'); break }
    '(?i)\.ai$'                                             { $servers.Add('whois.nic.ai'); break }
    '(?i)\.app$|\.dev$'                                     { $servers.Add('whois.nic.google'); break }
    '(?i)\.eu$'                                             { $servers.Add('whois.eu'); break }
    '(?i)\.uk$|\.co\.uk$|\.org\.uk$|\.gov\.uk$|\.ac\.uk$'  { $servers.Add('whois.nic.uk'); break }
    '(?i)\.de$'                                             { $servers.Add('whois.denic.de'); break }
    '(?i)\.fr$'                                             { $servers.Add('whois.nic.fr'); break }
    '(?i)\.au$|\.com\.au$|\.net\.au$|\.org\.au$'            { $servers.Add('whois.auda.org.au'); break }
    '(?i)\.ca$'                                             { $servers.Add('whois.cira.ca'); break }
    '(?i)\.jp$|\.co\.jp$|\.ne\.jp$|\.or\.jp$'               { $servers.Add('whois.jprs.jp'); break }
    '(?i)\.us$'                                             { $servers.Add('whois.nic.us'); break }
    '(?i)\.co$'                                             { $servers.Add('whois.registry.co'); break }
    '(?i)\.gov$'                                            { $servers.Add('whois.dotgov.gov'); break }
    '(?i)\.edu$'                                            { $servers.Add('whois.educause.edu'); break }
    '(?i)\.mil$'                                            { $servers.Add('whois.nic.mil'); break }
  }

  # For TLDs not in the mapping, try IANA referral to discover the authoritative server.
  if ($servers.Count -eq 0) {
    $servers.Add('whois.iana.org')
  }

  $canConvertDates = $true
  if (-not (Get-Command -Name ConvertTo-NullableUtcIso8601 -ErrorAction SilentlyContinue)) {
    $canConvertDates = $false
  }

  $lastError = $null

  foreach ($server in $servers) {
    $tcpClient = $null
    try {
      $tcpClient = [System.Net.Sockets.TcpClient]::new()
      $connectTask = $tcpClient.ConnectAsync($server, 43)
      if (-not $connectTask.Wait($TimeoutSec * 1000)) {
        throw "TCP connection to ${server}:43 timed out after $TimeoutSec seconds."
      }
      if ($connectTask.IsFaulted) {
        throw $connectTask.Exception.InnerException
      }

      $stream = $tcpClient.GetStream()
      $stream.ReadTimeout  = $TimeoutSec * 1000
      $stream.WriteTimeout = $TimeoutSec * 1000

      $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
      $writer.AutoFlush = $true
      $writer.WriteLine($d)

      $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
      $text   = $reader.ReadToEnd()

      if ([string]::IsNullOrWhiteSpace($text)) { continue }

      # If IANA returned a referral, follow it with a recursive call using the referred server.
      if ($server -eq 'whois.iana.org' -and $text -match '(?im)^whois:\s*(.+)$') {
        $referralServer = $Matches[1].Trim()
        if (-not [string]::IsNullOrWhiteSpace($referralServer) -and $referralServer -ne 'whois.iana.org') {
          try { $reader.Dispose() } catch { }
          try { $writer.Dispose() } catch { }
          try { $stream.Dispose() } catch { }
          try { $tcpClient.Close() } catch { }
          try { $tcpClient.Dispose() } catch { }
          $tcpClient = $null

          # Query the referral server directly.
          $tcpClient = [System.Net.Sockets.TcpClient]::new()
          $refTask = $tcpClient.ConnectAsync($referralServer, 43)
          if (-not $refTask.Wait($TimeoutSec * 1000)) {
            throw "TCP connection to ${referralServer}:43 timed out after $TimeoutSec seconds."
          }
          if ($refTask.IsFaulted) { throw $refTask.Exception.InnerException }

          $stream = $tcpClient.GetStream()
          $stream.ReadTimeout  = $TimeoutSec * 1000
          $stream.WriteTimeout = $TimeoutSec * 1000
          $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
          $writer.AutoFlush = $true
          $writer.WriteLine($d)
          $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
          $text   = $reader.ReadToEnd()
          $server = $referralServer

          if ([string]::IsNullOrWhiteSpace($text)) { continue }
        }
      }

      # Skip responses that indicate no data or invalid queries / malformed subdomain lookups.
      if ($text -match '(?im)\b(No Data Found|No match for|NOT FOUND|Status:\s*AVAILABLE|Malformed request\.?|Invalid query|Invalid domain name|This query returned 0 objects)\b') { continue }

      # Parse registration fields using the same normalization as the other
      # WHOIS providers so registry-specific labels stay consistent.
      $parsed = Get-WhoisParsedRegistrationData -Text $text
      $creation = $parsed.creationDate
      $expiry = $parsed.expiryDate
      $registrar = $parsed.registrar
      $registrant = $parsed.registrant

      return [pscustomobject]@{
        creationDate = $creation
        expiryDate   = $expiry
        registrar    = $registrar
        registrant   = $registrant
        rawText      = $text
        whoisServer  = $server
      }
    }
    catch {
      $lastError = $_.Exception.Message
    }
    finally {
      if ($tcpClient) {
        try { $tcpClient.Close() } catch { }
        try { $tcpClient.Dispose() } catch { }
      }
    }
  }

  $msg = if ($lastError) { "TCP whois failed for '$d'. $lastError" } else { "TCP whois returned no usable data for '$d'." }
  if ($ThrowOnError) { throw $msg } else { return $null }
}

if ([string]::IsNullOrWhiteSpace($AnonymousMetricsFile)) {
  $AnonymousMetricsFile = Join-Path -Path $PSScriptRoot -ChildPath 'acs-anon-metrics.json'
}
$AnonymousMetricsFile = [System.IO.Path]::GetFullPath($AnonymousMetricsFile)
$env:ACS_ANON_METRICS_FILE = $AnonymousMetricsFile

if ([string]::IsNullOrWhiteSpace($DohEndpoint)) {
  if (-not [string]::IsNullOrWhiteSpace($env:ACS_DNS_DOH_ENDPOINT)) {
    $DohEndpoint = $env:ACS_DNS_DOH_ENDPOINT
  }
}

