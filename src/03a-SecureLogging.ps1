# ===== Secure Structured Logging =====
# Privacy-first diagnostics for security review readiness.
#
# Design principles:
# - Deny-by-default fields: only the allowlisted keys in Get-AcsApprovedLogFields
#   can be emitted.
# - No request/response bodies, headers, query strings, domains, IP addresses,
#   user-entered text, identifiers, tokens, secrets, or local usernames/paths are
#   logged.
# - Correlation IDs are random non-semantic values generated per operation.
# - Exception objects are never serialized; only sanitized summaries are emitted.
# - Logging failures are swallowed so diagnostics cannot break primary flows.

$script:AcsLogAppName = 'ACS Email Domain Checker'
$script:AcsLogMinLevel = if ([string]::IsNullOrWhiteSpace($env:ACS_LOG_LEVEL)) { 'Information' } else { [string]$env:ACS_LOG_LEVEL }
$script:AcsLogFilePath = if ([string]::IsNullOrWhiteSpace($env:ACS_LOG_FILE)) { $null } else { [string]$env:ACS_LOG_FILE }
$script:AcsLogMaxBytes = 5242880
try {
  if ($env:ACS_LOG_MAX_BYTES -and $env:ACS_LOG_MAX_BYTES -match '^\d+$') {
	$script:AcsLogMaxBytes = [Math]::Max(65536, [Math]::Min([int64]$env:ACS_LOG_MAX_BYTES, 104857600))
  }
} catch { $script:AcsLogMaxBytes = 5242880 }

# Console output format for humans. The file sink (ACS_LOG_FILE) ALWAYS receives
# compact JSON for machine parsing; this only controls what is shown on the
# interactive console.
#   ACS_LOG_CONSOLE = 'text' -> clean, colored, single-line human output
#   ACS_LOG_CONSOLE = 'json' -> raw compact JSON (legacy behavior)
# When unset, text is used for interactive terminals and JSON is used when the
# output is redirected/piped (containers, CI, log collectors).
$script:AcsLogConsoleMode = if ([string]::IsNullOrWhiteSpace($env:ACS_LOG_CONSOLE)) { $null } else { ([string]$env:ACS_LOG_CONSOLE).Trim().ToLowerInvariant() }

function Get-AcsApprovedLogFields {
  return @(
	'timestampUtc','level','app','version','environment','component','operation',
	'eventId','message','correlationId','errorCode','exceptionType',
	'exceptionMessage','stackTraceHash','innerExceptionType','durationMs',
	'dependency','statusCode','resultCategory','retryAfterSec','fallback',
	'listenerMode','port','limit','remaining','shutdownRequested',
	'method','route'
  )
}

function Get-AcsLogLevelValue {
  param([string]$Level)
  switch -Regex ([string]$Level) {
	'^(?i:trace)$'       { return 0 }
	'^(?i:debug)$'       { return 1 }
	'^(?i:information|info)$' { return 2 }
	'^(?i:warning|warn)$' { return 3 }
	'^(?i:error)$'       { return 4 }
	'^(?i:critical|fatal)$' { return 5 }
	default              { return 2 }
  }
}

function Test-AcsLogLevelEnabled {
  param([string]$Level)
  try {
	return ((Get-AcsLogLevelValue -Level $Level) -ge (Get-AcsLogLevelValue -Level $script:AcsLogMinLevel))
  } catch { return $true }
}

function New-AcsCorrelationId {
  # 128 bits of randomness, base64url encoded. No semantics, no user data.
  # Uses RandomNumberGenerator.Create().GetBytes(), which exists on BOTH .NET
  # Framework (Windows PowerShell 5.1) and .NET (PowerShell 7+). The static
  # RandomNumberGenerator.Fill() is .NET Core 2.1+ only, so on 5.1 it is missing
  # and previously left the buffer all zeros -> every correlation id rendered as
  # "AAAAAAAAAAAAAAAAAAAAAA" (16 zero bytes). GetBytes(byte[]) mutates the array
  # in place, so there is no Span-copy pitfall either.
  $bytes = [byte[]]::new(16)
  try {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  } catch {
    # Last-resort fallback so a correlation id is always unique and non-zero.
    $guid = [System.Guid]::NewGuid().ToByteArray()
    [System.Array]::Copy($guid, $bytes, [Math]::Min($guid.Length, $bytes.Length))
  }
  return ([Convert]::ToBase64String($bytes).TrimEnd('=') -replace '\+','-' -replace '/','_')
}

function Get-AcsLogEnvironmentName {
  $raw = [string]$env:ACS_ENVIRONMENT
  if ([string]::IsNullOrWhiteSpace($raw)) { return 'unspecified' }
  $v = $raw.Trim()
  if ($v -match '^(?i:prod|production)$') { return 'production' }
  if ($v -match '^(?i:dev|development)$') { return 'development' }
  if ($v -match '^(?i:test|testing)$') { return 'test' }
  if ($v -match '^(?i:stage|staging)$') { return 'staging' }
  return 'custom'
}

function ConvertTo-AcsLogToken {
  param(
	[AllowNull()]$Value,
	[int]$MaxLength = 96
  )
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $s = $s.Trim()

  # Defense-in-depth redaction. The logger still uses an allowlist, but any
  # string that reaches this point is sanitized before output.
  $s = $s -replace '(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*', '[REDACTED_TOKEN]'
	$s = $s -replace '(?i)\b(ApiKey|X-Api-Key|X-ACS-API-Key|Authorization|Cookie|Set-Cookie|Password|Secret|Token)\b\s*[:=]\s*\S+', '[REDACTED_SECRET_FIELD]'
  $s = $s -replace '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '[REDACTED_EMAIL]'
  $s = $s -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]'
  $s = $s -replace '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[REDACTED_ID]'
	$s = $s -replace '(?i)(AccountKey|SharedAccessKey|Endpoint|DefaultEndpointsProtocol|ConnectionString)=[^;\s]+', '[REDACTED_CONNECTION_FIELD]'
  $s = $s -replace '(?i)\b(?:[a-z]:\\|/home/|/users/|/var/|/etc/)\S+', '[REDACTED_PATH]'
  $s = $s -replace '[\r\n\t]+', ' '
  if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength) + '…' }
  return $s
}

function Get-AcsSafeExceptionSummary {
  param(
	[AllowNull()]$Exception,
	[string]$ErrorCode = 'ACS-ERR-UNSPECIFIED'
  )

  $ex = $Exception
  if ($ex -is [System.Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
  if ($null -eq $ex) {
	return [ordered]@{
	  errorCode = $ErrorCode
	  exceptionType = $null
	  exceptionMessage = $null
	  innerExceptionType = $null
	  stackTraceHash = $null
	}
  }

  $typeName = 'Exception'
  try { $typeName = $ex.GetType().FullName } catch { $typeName = 'Exception' }
  $innerType = $null
  try { if ($ex.InnerException) { $innerType = $ex.InnerException.GetType().FullName } } catch { $innerType = $null }

  # Secure default: do not emit raw exception messages or stack traces because
  # they frequently include request values, file paths, DNS names, URLs, tokens,
  # or user-entered content. Emit a generic sanitized message and a stack hash.
  $stackHash = $null
  try {
	$stack = [string]$ex.StackTrace
	if (-not [string]::IsNullOrWhiteSpace($stack)) {
	  $bytes = [Text.Encoding]::UTF8.GetBytes($stack)
	  $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
	  $stackHash = ([Convert]::ToBase64String($hash).TrimEnd('=') -replace '\+','-' -replace '/','_')
	}
  } catch { $stackHash = $null }

  return [ordered]@{
	errorCode = $ErrorCode
	exceptionType = ConvertTo-AcsLogToken -Value $typeName -MaxLength 160
	exceptionMessage = 'Exception message suppressed by secure logging policy.'
	innerExceptionType = ConvertTo-AcsLogToken -Value $innerType -MaxLength 160
	stackTraceHash = $stackHash
  }
}

function ConvertTo-AcsAllowedLogEvent {
  param([hashtable]$Fields)

  $approved = Get-AcsApprovedLogFields
  $out = [ordered]@{}
  foreach ($k in $approved) {
	if (-not $Fields.ContainsKey($k)) { continue }
	$v = $Fields[$k]
	if ($null -eq $v) { continue }
	switch ($k) {
	  'durationMs' { try { $out[$k] = [int64]$v } catch { } ; break }
	  'statusCode' { try { $out[$k] = [int]$v } catch { } ; break }
	  'retryAfterSec' { try { $out[$k] = [int]$v } catch { } ; break }
	  'port' { try { $out[$k] = [int]$v } catch { } ; break }
	  'limit' { try { $out[$k] = [int64]$v } catch { } ; break }
	  'remaining' { try { $out[$k] = [int64]$v } catch { } ; break }
	  'shutdownRequested' { try { $out[$k] = [bool]$v } catch { } ; break }
	  default { $out[$k] = ConvertTo-AcsLogToken -Value $v }
	}
  }
  return $out
}

function Test-AcsConsoleJsonMode {
  # Decide whether console output should be raw JSON (machine) or human text.
  # Explicit ACS_LOG_CONSOLE wins; otherwise JSON is used only when the process
  # output is redirected/piped (containers, CI, log collectors) so structured
  # logs are preserved for machine consumers.
  if ($script:AcsLogConsoleMode -eq 'json') { return $true }
  if ($script:AcsLogConsoleMode -eq 'text') { return $false }
  try { return [System.Console]::IsOutputRedirected } catch { return $false }
}

function Write-AcsConsoleEvent {
  # Render one already-sanitized log event as a clean, colored, single line.
  # The input MUST be the output of ConvertTo-AcsAllowedLogEvent so it inherits
  # the allowlist + redaction guarantees; this function never sees raw input.
  # The whole line is emitted with a single Write-Host so concurrent request
  # runspaces cannot interleave partial segments.
  param([AllowNull()]$Event)
  try {
    if ($null -eq $Event) { return }

    # Only emit ANSI color when the host can actually render it.
    $ansi = $false
    try { $ansi = [bool]$Host.UI.SupportsVirtualTerminal } catch { $ansi = $false }
    $esc = [char]27
    $reset   = if ($ansi) { "$esc[0m" }  else { '' }
    $dim     = if ($ansi) { "$esc[90m" } else { '' }
    $cyan    = if ($ansi) { "$esc[36m" } else { '' }
    $green   = if ($ansi) { "$esc[32m" } else { '' }
    $yellow  = if ($ansi) { "$esc[33m" } else { '' }
    $red     = if ($ansi) { "$esc[31m" } else { '' }
    $magenta = if ($ansi) { "$esc[35m" } else { '' }

    # Level -> short fixed-width tag + color.
    $tag = 'INFO '; $levelColor = $green; $msgColor = ''
    switch -Regex ([string]$Event['level']) {
      '^(?i:critical|fatal)$' { $tag = 'CRIT '; $levelColor = $magenta; $msgColor = $magenta; break }
      '^(?i:error)$'          { $tag = 'ERROR'; $levelColor = $red;     $msgColor = $red;     break }
      '^(?i:warning|warn)$'   { $tag = 'WARN '; $levelColor = $yellow;  $msgColor = $yellow;  break }
      '^(?i:debug)$'          { $tag = 'DEBUG'; $levelColor = $dim;     $msgColor = $dim;     break }
      '^(?i:trace)$'          { $tag = 'TRACE'; $levelColor = $dim;     $msgColor = $dim;     break }
      default                 { $tag = 'INFO '; $levelColor = $green;   $msgColor = '';       break }
    }

    # Local HH:mm:ss from the UTC ISO timestamp (humans prefer local time; the
    # JSON file sink keeps the exact UTC value).
    $timeText = ''
    try { $timeText = ([DateTimeOffset]::Parse([string]$Event['timestampUtc'])).LocalDateTime.ToString('HH:mm:ss') }
    catch { $timeText = (Get-Date).ToString('HH:mm:ss') }

    $component = [string]$Event['component']
    if ([string]::IsNullOrWhiteSpace($component)) { $component = '-' }
    if ($component.Length -gt 16) { $component = $component.Substring(0, 16) }
    $componentPadded = $component.PadRight(16)

    $message = [string]$Event['message']

    # Trailing dim key=value details for the non-structural fields (port,
    # statusCode, durationMs, errorCode, route, listenerMode, etc.). The
    # correlationId is hidden for Information-level lines to keep the routine
    # request flow clean, but kept for Warning/Error/Critical so problems can be
    # cross-referenced against the JSON file sink; it is always present in JSON.
    $isProblemLevel = ([string]$Event['level'] -match '^(?i:warning|warn|error|critical|fatal)$')
    $skip = @('timestampUtc','level','app','version','environment','component','operation','eventId','message','exceptionMessage')
    if (-not $isProblemLevel) { $skip += 'correlationId' }
    $extraParts = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($Event.Keys)) {
      if ($skip -contains $key) { continue }
      $val = $Event[$key]
      if ($null -eq $val) { continue }
      $sval = [string]$val
      if ([string]::IsNullOrWhiteSpace($sval)) { continue }
      $extraParts.Add(("{0}={1}" -f $key, $sval))
    }
    $extras = if ($extraParts.Count -gt 0) { ($extraParts -join '  ') } else { '' }

    $line = "$dim$timeText$reset $levelColor$tag$reset  $cyan$componentPadded$reset  "
    if ($msgColor) { $line += "$msgColor$message$reset" } else { $line += $message }
    if ($extras) { $line += "  $dim$extras$reset" }

    Write-Host $line
  } catch {
    # Never let console rendering break logging; fall back to raw JSON.
    try { Write-Information -InformationAction Continue -MessageData ($Event | ConvertTo-Json -Compress -Depth 3) } catch { }
  }
}

function Write-AcsStartupBanner {
  # Prominent, human-friendly startup banner with a clickable web URL. Skipped
  # when the console is in JSON mode so machine log streams stay clean. The URL
  # is the server's own loopback address (never user data) and the port is an
  # already-approved log field, so this is safe to print verbatim.
  param([string]$Url, [int]$Port)
  try {
    if (Test-AcsConsoleJsonMode) { return }
    if ([string]::IsNullOrWhiteSpace($Url)) { $Url = "http://localhost:$Port" }

    $ansi = $false
    try { $ansi = [bool]$Host.UI.SupportsVirtualTerminal } catch { $ansi = $false }
    $esc = [char]27
    $reset = if ($ansi) { "$esc[0m" }  else { '' }
    $dim   = if ($ansi) { "$esc[90m" } else { '' }
    $cyan  = if ($ansi) { "$esc[96m" } else { '' }
    $bold  = if ($ansi) { "$esc[1m" }  else { '' }

    $version = [string]$script:AppVersion
    $title = if ([string]::IsNullOrWhiteSpace($version)) { [string]$script:AcsLogAppName } else { "$($script:AcsLogAppName) v$version" }
    $rule = '-' * [Math]::Max(8, $title.Length)

    Write-Host ''
    Write-Host "  $bold$cyan$title$reset"
    Write-Host "  $dim$rule$reset"
    Write-Host "  $($dim)Open the web UI in your browser:$reset"
    Write-Host "     $bold$cyan$Url$reset"
    Write-Host ''
    Write-Host "  $($dim)Press Ctrl+C or Q to stop the server.$reset"
    Write-Host ''
  } catch { }
}

function Write-AcsLogEvent {
  param(
	[ValidateSet('Trace','Debug','Information','Warning','Error','Critical')]
	[string]$Level = 'Information',
	[string]$Component,
	[string]$Operation,
	[string]$EventId,
	[string]$Message,
	[string]$CorrelationId,
	[string]$ErrorCode,
	[AllowNull()]$Exception,
	[hashtable]$Fields
  )

  try {
	if (-not (Test-AcsLogLevelEnabled -Level $Level)) { return }
	$logEvent = @{
	  timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
	  level = $Level
	  app = $script:AcsLogAppName
	  version = $script:AppVersion
	  environment = Get-AcsLogEnvironmentName
	  component = $Component
	  operation = $Operation
	  eventId = $EventId
	  message = $Message
	  correlationId = $CorrelationId
	  errorCode = $ErrorCode
	}
	if ($Fields) {
	  foreach ($k in $Fields.Keys) { $logEvent[$k] = $Fields[$k] }
	}
	if ($Exception) {
	  $summary = Get-AcsSafeExceptionSummary -Exception $Exception -ErrorCode $ErrorCode
	  foreach ($k in $summary.Keys) { $logEvent[$k] = $summary[$k] }
	}

	$safe = ConvertTo-AcsAllowedLogEvent -Fields $logEvent
	$json = $safe | ConvertTo-Json -Compress -Depth 3
	if ([string]::IsNullOrWhiteSpace($json)) { return }

	# Console: JSON for machine consumers (redirected/piped output or an explicit
	# ACS_LOG_CONSOLE=json), otherwise a clean, colored, human-readable line built
	# from the SAME already-sanitized event (never from raw input).
	if (Test-AcsConsoleJsonMode) {
		Write-Information -InformationAction Continue -MessageData $json
	} else {
		Write-AcsConsoleEvent -Event $safe
	}

	if (-not [string]::IsNullOrWhiteSpace($script:AcsLogFilePath)) {
	  try {
		$logDir = Split-Path -Parent $script:AcsLogFilePath
		if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -LiteralPath $logDir)) {
		  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
		}
		if (Test-Path -LiteralPath $script:AcsLogFilePath) {
		  $len = 0
		  try { $len = (Get-Item -LiteralPath $script:AcsLogFilePath).Length } catch { $len = 0 }
		  if ($len -gt $script:AcsLogMaxBytes) {
			$archive = "$($script:AcsLogFilePath).1"
			try { if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue } } catch { }
			try { Move-Item -LiteralPath $script:AcsLogFilePath -Destination $archive -Force -ErrorAction SilentlyContinue } catch { }
		  }
		}
		Add-Content -LiteralPath $script:AcsLogFilePath -Value $json -Encoding UTF8 -ErrorAction SilentlyContinue
	  } catch { }
	}
  } catch { }
}

function Write-AcsLogException {
  param(
	[string]$Component,
	[string]$Operation,
	[string]$EventId,
	[string]$ErrorCode,
	[AllowNull()]$Exception,
	[string]$CorrelationId,
	[hashtable]$Fields,
	[ValidateSet('Warning','Error','Critical')]
	[string]$Level = 'Error'
  )
  Write-AcsLogEvent -Level $Level -Component $Component -Operation $Operation -EventId $EventId -Message 'Operation failed. See errorCode and correlationId.' -CorrelationId $CorrelationId -ErrorCode $ErrorCode -Exception $Exception -Fields $Fields
}
