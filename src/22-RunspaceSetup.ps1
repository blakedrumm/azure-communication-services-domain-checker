# ===== Runspace Pool Initialization =====
# ------------------- MAIN LOOP -------------------
# Request handling uses a RunspacePool to process multiple HTTP requests concurrently.
# This keeps the UI responsive while DNS lookups are in flight.
# Each incoming request is dispatched to a PowerShell runspace from the pool, which
# executes the $handlerScript (defined below). The main thread only accepts connections
# and dispatches; all DNS work happens in runspace workers.

# Maximum number of concurrent request-handling runspaces.
$maxConcurrentRequests = 64

# Per-domain/route throttling: only one lookup for the same domain + endpoint at a time.
# This prevents duplicate requests from hammering DNS while still allowing independent
# lookup stages (TXT, MX, WHOIS, DMARC, etc.) to run in parallel for the same domain.

$domainLocks = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Threading.SemaphoreSlim]]::new([System.StringComparer]::OrdinalIgnoreCase)

# List all functions that need to be available inside the runspace workers.
# These are injected into the InitialSessionState so each runspace can call them.
$functionNames = @(
  'Set-SecurityHeaders','Write-Json','Write-Html','Write-FileResponse',
  'New-AnonSessionId','Get-RequestCookies','Get-RequestHeaderValue','Get-AnonymousAnalyticsConsentState','Clear-AnonymousSessionCookie','Get-OrCreate-AnonymousSessionId',
  'Get-HashedDomain',
  'Get-AnonymousMetricsPersistPath','Load-AnonymousMetricsPersisted','Save-AnonymousMetricsPersisted',
  'Update-AnonymousMetrics','Get-AnonymousMetricsSnapshot',
  'Get-RegistrableDomain','Get-ParentDomains','Test-WhoisRawTextHasUsableData','Test-WhoisResponseIsRegistryBlock','Get-WhoisCreationDateLabelRegex','Get-WhoisExpiryDateLabelRegex','Get-WhoisParsedRegistrationData','Get-FirstNonEmptyPropertyValue',
  'Resolve-DohName','ResolveSafely','Get-DnsIpString','Get-MxRecordObjects','Get-DnsRecordTypeCode','Get-DnsRecordTypeName','New-DnsRecordDetail','Format-DnsRecordDetailTtl','Convert-DnssecTimestampToDisplay','Get-DnsEscapedByteDisplay','Convert-DnsEscapedLabelToDisplay','Convert-DnsNameToDisplay','Convert-DnsBinaryDataToDisplay','Get-DnssecAlgorithmDisplay','Get-DnsRecordTypeDisplay','Get-DnsRecordDetails','Get-ReverseLookupSupplementTargets','Get-DnsRecordDataString','ConvertTo-ReverseLookupName','Resolve-DohRecordsDetailed','Resolve-DnsRecordsDetailed','Get-DnsRecordsStatus','ConvertTo-NormalizedDomain','Test-DomainName','Write-RequestLog',
  'Get-SpfTokens','Test-SpfOutlookIncludeToken','Find-SpfOutlookRequirementMatch','Get-SpfOutlookRequirementStatus','Get-SpfNestedAnalysis','Format-SpfNestedAnalysisText','Get-SpfGuidance',
  'Get-ClientIp','Get-ApiKeyFromRequest','Test-ApiKey','Test-RateLimit',
  'Get-DnsBaseStatus','Get-DnsMxStatus','Get-DnsDmarcStatus','Get-DnsDkimStatus','Get-CnameTargetFromRecords','Get-DnsCnameStatus','Invoke-RblLookup','ConvertTo-ReversedIpv4','Get-DnsReputationStatus',
  'Get-RblCacheEntry','Set-RblCacheEntry','Clear-ExpiredRblCacheEntries',
  'Get-RdapBootstrapData','Get-RdapBuiltInTldMap','Get-RdapBaseUrlForDomain','Invoke-RdapLookup','Invoke-WhoisXmlLookup','Invoke-GoDaddyWhoisLookup','ConvertTo-NullableUtcIso8601','Get-DomainAgeDays','Get-DomainRegistrationStatus',
  'Get-DmarcSecurityGuidance',
  'Invoke-SysinternalsWhoisLookup','Invoke-LinuxWhoisLookup','Invoke-TcpWhoisLookup','Get-DomainAgeParts','Format-DomainAge','Get-TimeUntilParts','Format-ExpiryRemaining',
  'Get-AcsDnsStatus'
)

# Create an InitialSessionState that will be shared by all runspace workers.
# This seeds each runspace with the function definitions, shared variables, and config.
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

# Provide a stable flag inside handler runspaces.
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsAnonMetricsEnabled', $anonMetricsEnabled, 'Anonymous metrics enabled flag'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('MetricsHashKey', $MetricsHashKey, 'Hash key used for anonymous domain hashing'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('GoDaddyApiKey', $script:GoDaddyApiKey, 'GoDaddy API key'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('GoDaddyApiSecret', $script:GoDaddyApiSecret, 'GoDaddy API secret'))

# Share the global metrics objects with handler runspaces (must be added before pool creation).
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsMetrics', $global:AcsMetrics, 'Shared metrics object'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsMetricsPersistLock', $global:AcsMetricsPersistLock, 'Shared metrics persist lock'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsUptime', $global:AcsUptime, 'Shared uptime stopwatch'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsRateLimitStore', $global:AcsRateLimitStore, 'Shared rate limit store'))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('AcsRateLimitLock', $global:AcsRateLimitLock, 'Shared rate limit lock'))

foreach ($name in $functionNames) {
  # Copy function *definitions* into the runspace pool so handler runspaces can call them.
  $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
  if (-not $cmd -and $name -eq 'Invoke-LinuxWhoisLookup') {
    # Define a no-op placeholder for Windows hosts where Invoke-LinuxWhoisLookup isn't defined/needed.
    function Invoke-LinuxWhoisLookup { param([string]$Domain,[string]$WhoisPath,[int]$TimeoutSec = 25,[switch]$ThrowOnError) return $null }
    $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
  }
  if (-not $cmd) { continue }
  $def = $cmd.Definition
  $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $def))
}

# Create and open the RunspacePool. Workers will be allocated from this pool on demand.
$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxConcurrentRequests, $iss, $Host)
$pool.Open()

# Track in-flight async invocations so we can dispose them promptly from the main runspace.
$inflight = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Complete-InflightInvocation {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InvocationId,

    [switch]$Force
  )

  $item = $null
  if (-not $inflight.TryGetValue($InvocationId, [ref]$item)) { return }
  if (-not $Force -and -not $item.Async.IsCompleted) { return }

  if ($inflight.TryRemove($InvocationId, [ref]$item)) {
    $completed = $false
    try { $completed = ($item.Async -and $item.Async.IsCompleted) } catch { $completed = $false }

    if ($completed) {
      try { $item.Ps.EndInvoke($item.Async) } catch { $null = $_ }
    }
    elseif ($Force) {
      try { $item.Ps.Stop() } catch { $null = $_ }
    }

    try {
      if ($item.Async -and $item.Async.AsyncWaitHandle) {
        $item.Async.AsyncWaitHandle.Close()
      }
    } catch { $null = $_ }
    try { $item.Ps.Dispose() } catch { $null = $_ }
  }
}

function Register-InflightInvocation {
  param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PowerShell]$PowerShellInstance,

    [Parameter(Mandatory = $true)]
    [object]$AsyncResult
  )

  $invocationId = [Guid]::NewGuid().ToString('N')
  $item = [pscustomobject]@{
    Ps = $PowerShellInstance
    Async = $AsyncResult
  }

  $null = $inflight.TryAdd($invocationId, $item)

  return $invocationId
}

# Reap any completed async PowerShell invocations from the main runspace.
function Invoke-InflightCleanup {
  foreach ($invocationId in @($inflight.Keys)) {
    Complete-InflightInvocation -InvocationId $invocationId
  }
}

