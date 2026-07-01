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

function Get-AcsApprovedLogFields {
  return @(
	'timestampUtc','level','app','version','environment','component','operation',
	'eventId','message','correlationId','errorCode','exceptionType',
	'exceptionMessage','stackTraceHash','innerExceptionType','durationMs',
	'dependency','statusCode','resultCategory','retryAfterSec','fallback',
	'listenerMode','port','limit','remaining','shutdownRequested'
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
  $bytes = [byte[]]::new(16)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
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
	$event = @{
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
	  foreach ($k in $Fields.Keys) { $event[$k] = $Fields[$k] }
	}
	if ($Exception) {
	  $summary = Get-AcsSafeExceptionSummary -Exception $Exception -ErrorCode $ErrorCode
	  foreach ($k in $summary.Keys) { $event[$k] = $summary[$k] }
	}

	$safe = ConvertTo-AcsAllowedLogEvent -Fields $event
	$json = $safe | ConvertTo-Json -Compress -Depth 3
	if ([string]::IsNullOrWhiteSpace($json)) { return }

	Write-Information -InformationAction Continue -MessageData $json

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
