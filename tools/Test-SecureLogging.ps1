# Validates privacy-safe logging controls with synthetic sensitive data only.
# No real customer, employee, production, or tenant data is used.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

. (Join-Path $repoRoot 'src/03-MetricsHashKey.ps1')
. (Join-Path $repoRoot 'src/03a-SecureLogging.ps1')

$script:CapturedLogs = [System.Collections.Generic.List[string]]::new()

function Assert-Condition {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Add-CapturedLogEvent {
  param([hashtable]$Fields)
  $safe = ConvertTo-AcsAllowedLogEvent -Fields $Fields
  $script:CapturedLogs.Add(($safe | ConvertTo-Json -Compress -Depth 5))
}

function Assert-NoForbiddenLogContent {
  param([string[]]$Logs)

  $patterns = [ordered]@{
	EmailAddress = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
	PhoneNumber = '\+?1?[\s\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}'
	BearerToken = '(?i)Bearer\s+[A-Za-z0-9._~+\-/]+=*'
	AuthorizationHeader = '(?i)Authorization\s*[:=]'
	ApiKey = '(?i)(X-Api-Key|X-ACS-API-Key|ApiKey)\s*[:=]'
	PasswordSecretToken = '(?i)(password|secret|token)\s*[:=]'
	Cookie = '(?i)(Cookie|Set-Cookie)\s*[:=]'
	ConnectionString = '(?i)(DefaultEndpointsProtocol|AccountKey|SharedAccessKey|ConnectionString)='
	GuidIdentifier = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
	IpAddress = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
	DomainFromInput = '(?i)customer-example\.com|sensitive-domain\.example'
	LocalUserPath = '(?i)C:\\Users\\[^\\]+'
	QueryString = '\?(domain|apiKey|token|password)='
	RequestBody = '(?i)free-form customer text|request body|response body'
  }

  foreach ($line in $Logs) {
	foreach ($name in $patterns.Keys) {
	  if ($line -match $patterns[$name]) {
		throw "Forbidden log pattern '$name' found in: $line"
	  }
	}
  }
}

# Correlation IDs: random, non-semantic, no source data.
$id1 = New-AcsCorrelationId
$id2 = New-AcsCorrelationId
Assert-Condition ($id1 -ne $id2) 'Correlation IDs should be random and unique.'
Assert-Condition ($id1 -notmatch 'customer|example|user|@|\.|-domain') 'Correlation ID appears semantic.'
Assert-Condition ($id1 -match '^[A-Za-z0-9_-]{20,32}$') 'Correlation ID format is unexpected.'

# Allowlist: unknown fields and rich objects must be dropped.
$event = ConvertTo-AcsAllowedLogEvent -Fields @{
  timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
  level = 'Information'
  app = 'ACS Email Domain Checker'
  version = 'test'
  component = 'Test'
  operation = 'sanitize'
  eventId = 'TEST-EVENT'
  message = 'Synthetic event.'
  correlationId = $id1
  headers = @{ Authorization = 'Bearer eyJhbGciOi.fake.token'; Cookie = 'session=abc' }
  queryString = '?domain=customer-example.com&apiKey=secret'
  body = 'free-form customer text alice@example.com'
  domain = 'sensitive-domain.example'
  ip = '10.1.2.3'
}
$json = $event | ConvertTo-Json -Compress -Depth 5
$eventKeys = @($event.Keys)
foreach ($forbiddenKey in @('headers','queryString','body','domain','ip')) {
  Assert-Condition (-not ($eventKeys -contains $forbiddenKey)) "Non-allowlisted field '$forbiddenKey' was logged."
}
$script:CapturedLogs.Add($json)

# Exception sanitization: messages/inner messages/stack bodies must not leak data.
try {
  try { throw "Inner secret token=abc alice@example.com 10.1.2.3" }
  catch { throw [System.InvalidOperationException]::new('Outer failure for customer-example.com Authorization: Bearer secret', $_.Exception) }
} catch {
  $summary = Get-AcsSafeExceptionSummary -Exception $_ -ErrorCode 'TEST-EX'
  $script:CapturedLogs.Add(($summary | ConvertTo-Json -Compress -Depth 5))
  Assert-Condition ($summary.exceptionMessage -eq 'Exception message suppressed by secure logging policy.') 'Exception message was not suppressed.'
  Assert-Condition (-not [string]::IsNullOrWhiteSpace($summary.exceptionType)) 'Exception type missing.'
}

# Redaction defense in depth for fields that are allowed strings.
Add-CapturedLogEvent -Fields @{
  timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
  level = 'Error'
  app = 'ACS Email Domain Checker'
  version = 'test'
  component = 'Dependency'
  operation = 'external-call'
  eventId = 'TEST-DEPENDENCY'
  message = 'Dependency failed for alice@example.com Authorization: Bearer abc.def.ghi from 192.0.2.10'
  correlationId = $id2
  errorCode = 'TEST-DEPENDENCY'
  dependency = 'synthetic-service'
  statusCode = 503
  resultCategory = 'timeout'
}

# Verbosity must not bypass privacy protections.
$script:AcsLogMinLevel = 'Trace'
Add-CapturedLogEvent -Fields @{
  timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
  level = 'Trace'
  app = 'ACS Email Domain Checker'
  version = 'test'
  component = 'VerboseTest'
  operation = 'trace'
  eventId = 'TEST-TRACE'
  message = 'Trace includes password=abc123 and token=def456 and customer@example.com'
  correlationId = New-AcsCorrelationId
}

Assert-NoForbiddenLogContent -Logs $script:CapturedLogs.ToArray()

Write-Host 'PASS: Secure logging validation completed. Captured synthetic logs contained no prohibited patterns.'
