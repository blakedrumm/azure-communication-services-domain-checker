# ===== WHOIS Lookup Providers =====
# Registries such as SWITCH (.ch / .li), DENIC (.de) and AFNIC (.fr) aggressively
# block port-43 WHOIS queries from datacenter or repeat-offender IP ranges and
# return a short refusal message instead of registration data. Detect those
# refusals here so Get-DomainRegistrationStatus can keep walking the provider
# chain (RDAP -> alternate WHOIS hosts -> APIs) instead of surfacing the block
# text to the user as if it were the registration record.
function Test-WhoisResponseIsRegistryBlock {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Text
  )

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  # If the response already contains structured WHOIS fields then any rate-limit
  # phrase further down is part of a registry disclaimer ("Abuse of this
  # service may result in rate-limiting"), not a block of THIS query. Treat the
  # response as real data and return $false so the chain stops walking.
  if ($Text -match '(?im)^\s*(Domain Name|Registry Domain ID|Registrar|Registrar URL|Creation Date|Registry Expiry Date|Registrant|Name Server|Status)\s*:') {
    return $false
  }

  # SWITCH (.ch / .li): "Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries."
  # DENIC (.de):        "Your queries are too fast. Please slow down ..." / "% Excessive querying, blocked."
  # AFNIC (.fr):        "%% Excessive number of queries."
  # ARIN/RIPE generic:  "Query rate of your IP exceeded the maximum ..." / "AUTHENTICATION_REQUIRED"
  # Anchor phrases to start-of-line (optionally after a WHOIS comment marker:
  # %, #, //) so legitimate disclaimer text floating mid-paragraph does not
  # incorrectly mark a successful response as a block.
  if ($Text -match '(?im)^(?:%+|#|//)?\s*(Requests of this client are not permitted|Excessive (?:number of )?quer(?:y|ies|ying)|Query rate of your IP|queries are too fast|rate[- ]?limit(?:ed|ing)?|too many requests|temporarily blocked|access (?:has been )?(?:denied|blocked)|AUTHENTICATION_REQUIRED|please use https?://[^\s]+/whois)') {
    return $true
  }

  return $false
}

function Test-WhoisRawTextHasUsableData {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Text
  )

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  if ($Text -match '(?im)\b(No Data Found|No match for|NOT FOUND|Status:\s*AVAILABLE|Malformed request\.?|Invalid query|Invalid domain name|This query returned 0 objects)\b') {
    return $false
  }

  if ($Text -match '(?im)\b(getaddrinfo\(|Name or service not known|Temporary failure in name resolution|Connection timed out|Network is unreachable|No route to host|Connection refused|Servname not supported for ai_socktype|socket error|connect\s+failed|No such host is known|The remote name could not be resolved|Unable to connect)\b') {
    return $false
  }

  # IANA referral notice for ccTLDs without a port-43 WHOIS server (.gr, .ελ, ...).
  # The text technically "has content" but it never contains structured registration
  # data, so the provider chain should keep walking (RDAP -> APIs -> registry web form).
  if ($Text -match '(?im)^This TLD has no whois server') {
    return $false
  }

  # Treat registry refusal/rate-limit responses as not-usable so the chain continues.
  if (Test-WhoisResponseIsRegistryBlock -Text $Text) {
    return $false
  }

  return $true
}

# Extract the registry web-form URL advertised by the IANA "This TLD has no whois
# server" notice (printed by the Linux 'whois' client for ccTLDs like .gr / .ελ
# whose registries do not run a port-43 WHOIS service). Returns $null when the
# text is not that notice. The notice is typically wrapped across two lines so we
# only require the marker phrase to be present and then pull the first http(s)
# URL out of the response. Callers use this to (a) decide that a provider's raw
# text is not real registration data and (b) surface the registry's web form to
# the user so they can complete the lookup manually.
function Get-RegistryWebFormUrl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Text,

    # Optional: when supplied, the captured URL host must end with this domain's
    # public suffix (last label). Port 43 is plaintext, so a man-in-the-middle
    # could spoof the IANA "no whois server" notice and inject any URL. The
    # SPA renders this URL as a clickable link so we treat it as untrusted.
    [string]$Domain
  )

  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  if ($Text -notmatch '(?im)This TLD has no whois server') { return $null }
  if ($Text -notmatch '(?im)(https?://[^\s<>"'']+)') { return $null }

  # Strip only punctuation that commonly trails a URL inside prose. Brackets
  # and parentheses are legal URL characters - dropping them silently mutates
  # otherwise valid URLs.
  $candidate = $Matches[1].TrimEnd('.', ',', ';')

  $uri = $null
  try { $uri = [System.Uri]::new($candidate) } catch { return $null }
  if (-not $uri.IsAbsoluteUri) { return $null }
  if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') { return $null }
  if ([string]::IsNullOrWhiteSpace($uri.Host)) { return $null }
  # Host must look like an RFC-1123 hostname so we never hand the SPA a URL
  # whose host is a userinfo blob, an IPv6 literal with embedded credentials,
  # or anything else that would render strangely as a clickable link.
  if ($uri.Host -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$') { return $null }

  if (-not [string]::IsNullOrWhiteSpace($Domain)) {
    $tld = $null
    try {
      $parts = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant().Split('.')
      if ($parts.Count -ge 1) { $tld = $parts[$parts.Count - 1] }
    } catch { return $null }
    if (-not [string]::IsNullOrWhiteSpace($tld)) {
      $hostLower = $uri.Host.ToLowerInvariant()
      if (-not ($hostLower -eq $tld -or $hostLower.EndsWith(".$tld"))) {
        return $null
      }
    }
  }

  return $uri.AbsoluteUri.TrimEnd('/')
}

# Static fallback for ccTLD registries that do not operate a port-43 WHOIS or
# RDAP service and only expose registration data through a public web form. The
# Linux `whois` client prints an IANA referral pointing at these URLs, but other
# clients (Sysinternals on Windows, raw-TCP fallbacks) will instead query a
# server that returns garbage like RIPE's "%ERROR:101: no entries found" or
# "No such host is known". Returning the canonical web-form URL here lets the
# SPA render the same friendly link panel regardless of which provider was
# tried. Callers use this only when no provider produced structured data.
function Get-KnownRegistryWebFormUrl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Domain
  )

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

  # Map of TLDs (single- or multi-label) known to publish registration data
  # only via a web form. Keep this list narrow: only include TLDs whose
  # registries explicitly state they do not provide WHOIS/RDAP. Punycode forms
  # are listed for IDN ccTLDs.
  $webFormByTld = @{
    'gr'         = 'https://grweb.ics.forth.gr/public/whois?lang=en'   # Greek registry (FORTH)
    'xn--qxam'   = 'https://grweb.ics.forth.gr/public/whois?lang=en'   # .ελ (IDN of Greece)
  }

  $labels = $null
  try {
    $labels = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant().Split('.')
  } catch { return $null }
  if (-not $labels -or $labels.Count -eq 0) { return $null }

  # Walk labels right-to-left, longest match wins. A future entry like
  # 'gov.in' will be matched before its single-label parent 'in'.
  for ($i = 0; $i -lt $labels.Count; $i++) {
    $candidate = ($labels[$i..($labels.Count - 1)] -join '.')
    if ($webFormByTld.ContainsKey($candidate)) {
      return $webFormByTld[$candidate]
    }
  }
  return $null
}

function Get-WhoisCreationDateLabelRegex {
  # NOTE: the bare 'Registered' label was removed because many registrar templates
  # emit lines like 'Registered: yes' or 'Registered: contact@example.com', which
  # silently produced bogus creation dates. Use the more specific 'Registered On'
  # / 'Registered on' variants instead.
  #
  # The optional '[.\s]*' between the label and the colon lets us match the
  # dotted padding TRABIS (nic.tr) emits, e.g. 'Created on..............:'.
  '(?im)^(Creation Date|Created On|Created on|Registered On|Registered on|Registration Date|Domain Create Date|Creation date|Domain record activated)[.\s]*:\s*(.+)$'
}

function Get-WhoisExpiryDateLabelRegex {
  # 'Expires on' (with optional dotted padding) is the label TRABIS (.tr) uses;
  # the rest of the alternatives cover gTLD/ICANN templates.
  '(?im)^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Registrar Registration Expiration date|Domain expires|Expires on)[.\s]*:\s*(.+)$'
}

# Lazy-initialize compiled regex objects once per script process. The previous
# implementation re-evaluated the pattern strings via -match on every WHOIS
# line, which both recompiled the regex per line and also mutated the global
# $Matches automatic variable (less safe in concurrent runspaces). Compiled
# regex objects are JIT-emitted once and reused, giving a measurable speedup
# on long Verisign-style responses.
$script:WhoisCreationRegexCompiled = $null
$script:WhoisExpiryRegexCompiled   = $null
$script:WhoisRegistrarRegexCompiled = $null
$script:WhoisRegistrantRegexCompiled = $null
$script:WhoisRegistrantBlockRegexCompiled = $null
$script:WhoisLabelLineRegexCompiled = $null

function Initialize-WhoisFieldRegexes {
  if ($null -ne $script:WhoisCreationRegexCompiled) { return }

  $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase `
     -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant `
     -bor [System.Text.RegularExpressions.RegexOptions]::Compiled

  # Field-line patterns. Each pattern matches the entire trimmed line and
  # captures the value into group 1. The optional '[.\s]*' between the label
  # and the colon lets us match TRABIS (.tr) lines such as
  # 'Created on..............: 2014-Dec-30.' where the registry pads the label
  # out with dots. 'Created on' / 'Expires on' (lowercase 'on') and
  # 'Organization Name' (the registrar line inside nic.tr's '** Registrar:'
  # block) are added as additional aliases for the same reason.
  $script:WhoisCreationRegexCompiled        = [regex]::new('^(?:Creation Date|Created On|Created on|Registered On|Registered on|Registration Date|Domain Create Date|Creation date|Domain record activated)[.\s]*:\s*(.+)$', $opt)
  $script:WhoisExpiryRegexCompiled          = [regex]::new('^(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Registrar Registration Expiration date|Domain expires|Expires on)[.\s]*:\s*(.+)$', $opt)
  $script:WhoisRegistrarRegexCompiled       = [regex]::new('^(?:Registrar|Registrar name|Registrar Name|Sponsoring Registrar|Organization Name)[.\s]*:\s*(.+)$', $opt)
  $script:WhoisRegistrantRegexCompiled      = [regex]::new('^(?:Registrant Name|Registrant Organisation|Registrant Organization)[.\s]*:\s*(.+)$', $opt)
  $script:WhoisRegistrantBlockRegexCompiled = [regex]::new('^Registrant:\s*$', $opt)
  # Heuristic: any line that starts with an alphabetic label followed by a colon
  # is a structured field. Used by the EDUCAUSE-style block-Registrant parser to
  # detect when the Registrant name block has ended.
  $script:WhoisLabelLineRegexCompiled       = [regex]::new('^[A-Za-z][A-Za-z0-9 .''()&,/+-]{0,80}:\s*', $opt)
}

# Keep WHOIS field extraction in one place so all fallback providers recognize
# the same registry-specific labels and block-style sections such as EDUCAUSE's
# multi-line "Registrant:" blocks for .edu domains.
function Get-WhoisParsedRegistrationData {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Text
  )

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

  Initialize-WhoisFieldRegexes

  $lines = $Text -split "`r?`n"

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $trimmed = ([string]$lines[$i]).Trim()
    if (-not $trimmed) { continue }

    # Cheap label-first short-circuit: WHOIS data lines always start with an
    # ASCII letter (label) and contain a colon. Skip free-form disclaimer text
    # and comment-marker lines (% / # / >) without ever invoking a regex.
    $first = $trimmed[0]
    if (-not ((($first -ge 'A') -and ($first -le 'Z')) -or (($first -ge 'a') -and ($first -le 'z')))) {
      continue
    }
    if ($trimmed.IndexOf(':') -lt 0) { continue }

    if (-not $creation) {
      $m = $script:WhoisCreationRegexCompiled.Match($trimmed)
      if ($m.Success) {
        # ConvertTo-NullableUtcIso8601 is documented to return $null on parse
        # failure, so a try/catch fallback is dead code; assigning the raw
        # string into a date field would also corrupt downstream consumers.
        # TRABIS (.tr) terminates date values with a trailing period
        # (e.g. '2014-Dec-30.') which DateTimeOffset.TryParse rejects, so
        # strip any trailing periods/whitespace before parsing.
        $val = $m.Groups[1].Value.Trim().TrimEnd('.', ' ', "`t")
        $creation = ConvertTo-NullableUtcIso8601 $val
        continue
      }
    }

    if (-not $expiry) {
      $m = $script:WhoisExpiryRegexCompiled.Match($trimmed)
      if ($m.Success) {
        $val = $m.Groups[1].Value.Trim().TrimEnd('.', ' ', "`t")
        $expiry = ConvertTo-NullableUtcIso8601 $val
        continue
      }
    }

    if (-not $registrar) {
      $m = $script:WhoisRegistrarRegexCompiled.Match($trimmed)
      if ($m.Success) {
        $registrar = $m.Groups[1].Value.Trim()
        continue
      }
    }

    if (-not $registrant) {
      $m = $script:WhoisRegistrantRegexCompiled.Match($trimmed)
      if ($m.Success) {
        $registrant = $m.Groups[1].Value.Trim()
        continue
      }
    }

    if (-not $registrant -and $script:WhoisRegistrantBlockRegexCompiled.IsMatch($trimmed)) {
      # EDUCAUSE-style "Registrant:" header followed by indented value lines.
      # Walk forward until we hit either a blank-then-blank gap or a line that
      # itself looks like a labeled field (e.g., "Address:").
      for ($j = $i + 1; $j -lt $lines.Count; $j++) {
        $candidateTrimmed = ([string]$lines[$j]).Trim()
        if (-not $candidateTrimmed) {
          if ($j -gt ($i + 1)) { break }
          continue
        }
        if ($script:WhoisLabelLineRegexCompiled.IsMatch($candidateTrimmed)) { break }
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

# 5.1 Defensive validation at the syscall boundary. Public WHOIS provider
# functions are reachable from CLI mode and from every request handler; we do
# not want a crafted domain name to ever land in a process command line or
# WHOIS protocol payload without an RFC-1123 sanity check first. The check is
# free and is the last line of defense if a future caller forgets to invoke
# Test-DomainName before us.
function Test-WhoisDomainNameSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Domain
  )

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
  $d = ([string]$Domain).Trim()
  if ($d.Length -gt 253) { return $false }
  if ($d -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$') { return $false }
  if ($d.Contains('..')) { return $false }
  return $true
}

# 5.3 WHOIS responses are attacker-controlled (any registrant can put arbitrary
# bytes in their record's free-form fields). Sanitize at the source so a hostile
# record cannot embed control characters / a multi-megabyte payload that the
# SPA later renders inline. Strips C0 control characters except TAB/LF/CR and
# clamps the response to 64 KB by default.
function ConvertTo-SafeWhoisRawText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Text,

    [int]$MaxLength = 65536
  )

  if ([string]::IsNullOrEmpty($Text)) { return $Text }

  $cleaned = ($Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '?')
  if ($cleaned.Length -gt $MaxLength) {
    $cleaned = $cleaned.Substring(0, $MaxLength) + "`n... [truncated]"
  }
  return $cleaned
}

# 1.2 Single source of truth for TLD -> fallback WHOIS server mapping. The map
# was previously duplicated between Invoke-LinuxWhoisLookup and
# Invoke-TcpWhoisLookup and had already begun drifting (.us secondary server
# was only in the Linux path). Order matters because longer TLDs (e.g.
# .co.uk) must be matched before their shorter parents.
$script:WhoisTldServerMap = $null
function Get-FallbackWhoisServersForDomain {
  param([Parameter(Mandatory = $true)][string]$Domain)

  if ($null -eq $script:WhoisTldServerMap) {
    $script:WhoisTldServerMap = @(
      @{ Pattern = '\.com$|\.net$';                                    Servers = @('whois.verisign-grs.com') }
      @{ Pattern = '\.org$';                                           Servers = @('whois.pir.org') }
      @{ Pattern = '\.info$';                                          Servers = @('whois.afilias.net') }
      @{ Pattern = '\.biz$';                                           Servers = @('whois.biz') }
      @{ Pattern = '\.io$';                                            Servers = @('whois.nic.io') }
      @{ Pattern = '\.ai$';                                            Servers = @('whois.nic.ai') }
      @{ Pattern = '\.app$|\.dev$';                                    Servers = @('whois.nic.google') }
      @{ Pattern = '\.eu$';                                            Servers = @('whois.eu') }
      @{ Pattern = '\.uk$|\.co\.uk$|\.org\.uk$|\.gov\.uk$|\.ac\.uk$';  Servers = @('whois.nic.uk') }
      @{ Pattern = '\.de$';                                            Servers = @('whois.denic.de') }
      @{ Pattern = '\.fr$';                                            Servers = @('whois.nic.fr') }
      @{ Pattern = '\.au$|\.com\.au$|\.net\.au$|\.org\.au$';           Servers = @('whois.auda.org.au') }
      @{ Pattern = '\.ca$';                                            Servers = @('whois.cira.ca') }
      @{ Pattern = '\.jp$|\.co\.jp$|\.ne\.jp$|\.or\.jp$';              Servers = @('whois.jprs.jp') }
      # `.us` lists two servers because nic.us has been intermittently unreliable;
      # us.whois-servers.net is a stable Verisign mirror used as a backup.
      @{ Pattern = '\.us$';                                            Servers = @('whois.nic.us', 'us.whois-servers.net') }
      @{ Pattern = '\.co$';                                            Servers = @('whois.registry.co') }
      @{ Pattern = '\.gov$';                                           Servers = @('whois.dotgov.gov') }
      @{ Pattern = '\.edu$';                                           Servers = @('whois.educause.edu') }
      @{ Pattern = '\.mil$';                                           Servers = @('whois.nic.mil') }
    )
  }

  $d = ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($d)) { return @() }

  foreach ($entry in $script:WhoisTldServerMap) {
    if ($d -match $entry.Pattern) { return ,@($entry.Servers) }
  }
  return @()
}

# 3.3 Negative cache: when a WHOIS server times out or repeatedly returns
# unusable data we want to stop wasting wall-clock per request hammering the
# same dead endpoint. Each entry maps server -> UTC datetime when the cooldown
# expires. The default cooldown window is 5 minutes which is short enough to
# self-heal once a registry recovers but long enough to spare the SPA the full
# 25-second per-server timeout on every subsequent request.
#
# IMPORTANT: this dictionary lives in the GLOBAL scope (and is also seeded into
# the runspace InitialSessionState in 22-RunspaceSetup.ps1 under the name
# "AcsWhoisServerCooldown") so that all request-handler runspaces observe the
# same set of cooled-down servers. The helpers below resolve the dictionary by
# unqualified variable name so PowerShell's scope walk picks up either the
# main-process global or the runspace-injected copy without code duplication.
if (-not $global:AcsWhoisServerCooldown) {
  $global:AcsWhoisServerCooldown = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
}
$script:WhoisServerCooldownSeconds = 300

# Helper: locate the cooldown dictionary in whichever scope the caller is in.
# In the main process the global wins; in worker runspaces the variable is
# named $AcsWhoisServerCooldown by SessionStateVariableEntry. Returns $null
# if neither exists, so callers gracefully no-op rather than crashing.
function Get-WhoisCooldownDictionary {
  $entry = Get-Variable -Name 'AcsWhoisServerCooldown' -Scope Global -ErrorAction SilentlyContinue
  if ($entry -and $entry.Value) { return $entry.Value }
  $entry = Get-Variable -Name 'AcsWhoisServerCooldown' -ErrorAction SilentlyContinue
  if ($entry -and $entry.Value) { return $entry.Value }
  return $null
}

function Test-WhoisServerOnCooldown {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Server
  )

  if ([string]::IsNullOrWhiteSpace($Server)) { return $false }
  $dict = Get-WhoisCooldownDictionary
  if (-not $dict) { return $false }

  $expiresAt = [datetime]::MinValue
  if ($dict.TryGetValue($Server, [ref]$expiresAt)) {
    if ([datetime]::UtcNow -lt $expiresAt) { return $true }
    # Cooldown expired; opportunistically remove the stale entry so the
    # dictionary does not grow unbounded across long-lived processes.
    $removed = [datetime]::MinValue
    [void]$dict.TryRemove($Server, [ref]$removed)
  }
  return $false
}

function Add-WhoisServerCooldown {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Server,

    [int]$Seconds = 0
  )

  if ([string]::IsNullOrWhiteSpace($Server)) { return }
  $dict = Get-WhoisCooldownDictionary
  if (-not $dict) { return }

  $window = $Seconds
  if ($window -le 0) { $window = $script:WhoisServerCooldownSeconds }

  $expiresAt = [datetime]::UtcNow.AddSeconds($window)
  $dict.AddOrUpdate(
    $Server,
    $expiresAt,
    { param($k, $existing) if ($expiresAt -gt $existing) { $expiresAt } else { $existing } }) | Out-Null
}

# 4.1 / 1.4 Shared WHOIS child-process launcher. Both Sysinternals whois.exe
# and the Linux `whois` CLI need the same plumbing: ProcessStartInfo with
# argument-array isolation (falling back to a quoted .Arguments string on
# older .NET runtimes that lack ArgumentList), async stdout/stderr drains so
# WaitForExit() is the authoritative timeout, and an authoritative kill on
# timeout that disposes the process. Centralizing the ceremony here means
# future hardening (sandboxing, output-size caps, telemetry) lands in one
# place instead of two providers that have already begun to drift.
function Invoke-WhoisProcess {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    # Argument tokens to pass to the child process. Each element becomes one
    # argv entry on platforms that honor ArgumentList. NEVER pre-quote tokens
    # here - the caller's job is to validate every value, not to shell-escape.
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]$Arguments,

    # Optional pre-quoted command line used only when the runtime does not
    # support ProcessStartInfo.ArgumentList (very old PowerShell on .NET FX).
    # Callers are responsible for ensuring all interpolated values have
    # already been validated against an allow-list.
    [string]$LegacyArgumentString,

    [Parameter(Mandatory = $true)]
    [int]$TimeoutSec,

    # Human-readable label for error messages. Defaults to the file name.
    [string]$DisplayName
  )

  if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $FilePath }

  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $FilePath
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute        = $false
  $psi.CreateNoWindow         = $true

  # Best-effort UTF-8 decoding; some runtimes do not expose these properties.
  try {
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
  } catch { }

  $argumentListAssigned = $false
  try {
    foreach ($token in $Arguments) { $null = $psi.ArgumentList.Add($token) }
    $argumentListAssigned = $true
  } catch {
    # Older .NET runtimes lack ArgumentList; fall back to the caller-supplied
    # pre-quoted string. Refuse to fall back without one - silently
    # space-joining argv on Windows would re-introduce the quoting bugs we
    # are trying to avoid.
    if ([string]::IsNullOrWhiteSpace($LegacyArgumentString)) {
      throw "ProcessStartInfo.ArgumentList is unavailable and no LegacyArgumentString was supplied for '$DisplayName'."
    }
    $psi.Arguments = $LegacyArgumentString
  }

  $p = $null
  try {
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) {
      throw "Failed to start process '$DisplayName'."
    }

    # Async drains so the timeout below is wall-clock authoritative even
    # when the remote end keeps the pipes open after the child should have
    # exited.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()

    $exited = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $exited) {
      try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      try { $p.WaitForExit(2000) | Out-Null } catch { }
      throw "Process '$DisplayName' timed out after $TimeoutSec seconds."
    }

    $out = ''
    $err = ''
    try { $out = $outTask.GetAwaiter().GetResult() } catch { $out = '' }
    try { $err = $errTask.GetAwaiter().GetResult() } catch { $err = '' }

    return [pscustomobject]@{
      stdout   = $out
      stderr   = $err
      text     = (($out, $err) -join "`r`n").Trim()
      exitCode = $p.ExitCode
    }
  }
  finally {
    try { if ($p) { $p.Dispose() } } catch { }
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

  # 5.1 Defense in depth: refuse to launch the WHOIS process unless $d already
  # passes RFC-1123 sanity checks. Test-DomainName is the upstream gate, but
  # this function is exported and could be invoked from CLI mode or future
  # callers that forget the check, and the .Arguments string fallback below
  # would otherwise interpolate user input directly into a command line.
  if (-not (Test-WhoisDomainNameSafe -Domain $d)) {
    $msg = "Refusing to launch Sysinternals whois with invalid domain: '$d'."
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  # If caller provided a path (or env var did), validate it exists.
  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:SYSINTERNALS_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois.exe' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Sysinternals whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $p = $null

  try {
    # Sysinternals whois usage supports -v to follow referrals; /accepteula
    # avoids the interactive EULA prompt. The shared helper handles argv
    # isolation, async pipe drains, timeout enforcement, and process disposal.
    $result = Invoke-WhoisProcess `
      -FilePath $exe `
      -Arguments @('/accepteula', '-v', $d) `
      -LegacyArgumentString "/accepteula -v `"$d`"" `
      -TimeoutSec $TimeoutSec `
      -DisplayName "Sysinternals whois ($d)"

    $text = $result.text
    if ([string]::IsNullOrWhiteSpace($text)) {
      $msg = "Sysinternals whois returned no output for '$d'. ExitCode=$($result.exitCode)."
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
      rawText      = (ConvertTo-SafeWhoisRawText -Text $text)
      exitCode     = $result.exitCode
      whoisExe     = $exe
    }
  }
  catch {
    $msg = "Sysinternals whois failed: $($_.Exception.Message)"
    if ($ThrowOnError) { throw $msg } else { return $null }
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

  # 5.1 Defense in depth: same boundary check as the Sysinternals provider.
  if (-not (Test-WhoisDomainNameSafe -Domain $d)) {
    $msg = "Refusing to launch Linux whois with invalid domain: '$d'."
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  $serverList = New-Object System.Collections.Generic.List[string]
  $null = $serverList.Add($null)

  # 5.2 Operator-supplied WHOIS servers from ACS_LINUX_WHOIS_SERVERS could land
  # on a `whois -h` command line. Validate each token against an RFC-1123 host
  # regex and silently drop anything that does not look like a hostname so a
  # hostile env var cannot inject extra arguments through the .Arguments string
  # fallback path below.
  $envServerText = [string]$env:ACS_LINUX_WHOIS_SERVERS
  if (-not [string]::IsNullOrWhiteSpace($envServerText)) {
    foreach ($serverCandidate in @($envServerText -split '[,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      $normalizedServer = ([string]$serverCandidate).Trim()
      if ([string]::IsNullOrWhiteSpace($normalizedServer)) { continue }
      if ($normalizedServer -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$') { continue }
      if (-not $serverList.Contains($normalizedServer)) {
        $null = $serverList.Add($normalizedServer)
      }
    }
  }

  # 1.2 Single source of truth for TLD -> WHOIS server mapping (shared with
  # Invoke-TcpWhoisLookup). Previously each provider had its own copy of the
  # switch -Regex block; the .us secondary server already drifted between them.
  $defaultFallbackServers = Get-FallbackWhoisServersForDomain -Domain $d

  foreach ($defaultServer in $defaultFallbackServers) {
    if (-not [string]::IsNullOrWhiteSpace($defaultServer) -and -not $serverList.Contains($defaultServer)) {
      $null = $serverList.Add($defaultServer)
    }
  }

  $explicitPathProvided = (-not [string]::IsNullOrWhiteSpace($WhoisPath)) -or (-not [string]::IsNullOrWhiteSpace($env:LINUX_WHOIS_PATH))
  if ($explicitPathProvided -and $exe -ne 'whois' -and -not (Test-Path -LiteralPath $exe)) {
    $msg = "Linux whois executable not found at: $exe"
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  try {
    $text = $null
    $exitCode = $null
    $usedServer = $null
    $lastQueryError = $null

    foreach ($server in $serverList) {
      # 3.3 Skip servers we recently observed as dead. The default-server slot
      # ($null) is never put on cooldown - it just falls through to the next
      # entry in the list and the whois client picks its own server.
      if (-not [string]::IsNullOrWhiteSpace($server) -and (Test-WhoisServerOnCooldown -Server $server)) {
        $lastQueryError = "Skipping '$server' (recent failures, on cooldown)."
        continue
      }

      # Build the argv. We use array form via the shared helper which handles
      # the legacy .Arguments fallback for older runtimes.
      $argList = New-Object System.Collections.Generic.List[string]
      $legacyArgs = $null
      if ([string]::IsNullOrWhiteSpace($server)) {
        $null = $argList.Add('--')
        $null = $argList.Add($d)
        $legacyArgs = "-- `"$d`""
      } else {
        $null = $argList.Add('-h')
        $null = $argList.Add($server)
        $null = $argList.Add('--')
        $null = $argList.Add($d)
        $legacyArgs = "-h `"$server`" -- `"$d`""
      }

      try {
        $queryResult = Invoke-WhoisProcess `
          -FilePath $exe `
          -Arguments $argList.ToArray() `
          -LegacyArgumentString $legacyArgs `
          -TimeoutSec $TimeoutSec `
          -DisplayName ("Linux whois ($d via " + ($(if ($server) { $server } else { 'default' })) + ')')

        $exitCode = $queryResult.exitCode

        if (Test-WhoisRawTextHasUsableData -Text $queryResult.text) {
          $text = $queryResult.text
          $usedServer = $server
          break
        }

        if (-not [string]::IsNullOrWhiteSpace($queryResult.text)) {
          $lastQueryError = ($queryResult.text -split "`r?`n" | Select-Object -First 1)
        }
      }
      catch {
        $lastQueryError = $_.Exception.Message
        # 3.3 Treat timeouts and process-launch failures against a specific
        # server as a hard failure for that server and put it on cooldown so
        # the next request does not pay the same per-server timeout cost.
        if (-not [string]::IsNullOrWhiteSpace($server)) {
          Add-WhoisServerCooldown -Server $server
        }
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
      rawText      = (ConvertTo-SafeWhoisRawText -Text $text)
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

  .NOTES
    Port 43 is plaintext. This client must NEVER be reused as the underlying
    transport for an authenticated relay; the response sanitization here
    assumes adversarial input on the wire.
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

  # 5.1 Boundary validation: refuse to put an unvetted domain on the wire.
  if (-not (Test-WhoisDomainNameSafe -Domain $d)) {
    $msg = "Refusing to issue TCP whois with invalid domain: '$d'."
    if ($ThrowOnError) { throw $msg } else { return $null }
  }

  # 1.2 Use the shared TLD -> server map so this provider stays in sync with
  # Invoke-LinuxWhoisLookup as new TLDs are added.
  $servers = New-Object System.Collections.Generic.List[string]
  foreach ($s in (Get-FallbackWhoisServersForDomain -Domain $d)) {
    if (-not [string]::IsNullOrWhiteSpace($s) -and -not $servers.Contains($s)) {
      $null = $servers.Add($s)
    }
  }

  # For TLDs not in the mapping, try IANA referral to discover the authoritative server.
  if ($servers.Count -eq 0) {
    $null = $servers.Add('whois.iana.org')
  }

  # 2.5 Bounded byte-by-byte read with a wall-clock deadline. StreamReader's
  # ReadToEnd() is unbounded in both time and size: a slowloris-style server
  # can drip-feed bytes forever (each individual read is inside the per-read
  # ReadTimeout window) and a hostile server can stream gigabytes. We cap both.
  # 5.6 The decode is delayed until after we have all the bytes so we can try
  # UTF-8 strict and fall back to ISO-8859-1 for legacy registries instead of
  # silently producing U+FFFD for every non-ASCII byte.
  $maxResponseBytes = 1MB
  $readBufferSize   = 8192

  $readWhoisStream = {
    param([System.IO.Stream]$NetworkStream, [int]$DeadlineMs)

    $buffer = New-Object byte[] $readBufferSize
    $ms = [System.IO.MemoryStream]::new()
    $deadline = [DateTime]::UtcNow.AddMilliseconds($DeadlineMs)
    try {
      while ([DateTime]::UtcNow -lt $deadline -and $ms.Length -lt $maxResponseBytes) {
        $remainingMs = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        $task = $NetworkStream.ReadAsync($buffer, 0, $buffer.Length)
        if (-not $task.Wait($remainingMs)) { break }
        if ($task.IsFaulted) { throw $task.Exception.InnerException }
        $n = $task.GetAwaiter().GetResult()
        if ($n -le 0) { break }
        $ms.Write($buffer, 0, $n)
      }
      $bytes = $ms.ToArray()
    }
    finally {
      $ms.Dispose()
    }

    if ($bytes.Length -eq 0) { return '' }

    # Try strict UTF-8 first (the common case today). If the registry sent a
    # legacy code page, fall back to ISO-8859-1 which never throws and is a
    # strict superset of ASCII so it cannot corrupt label-style fields.
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    try { return $strictUtf8.GetString($bytes) }
    catch { return [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($bytes) }
  }

  # Inner helper: connect to one WHOIS server, send the query, return the raw
  # response text (or throw). Centralizes the dispose ordering so the IANA
  # referral path no longer leaks the stream/reader/writer triple it created.
  $sendWhoisQuery = {
    param([string]$Server, [string]$Query)

    $client = $null
    $stream = $null
    $writer = $null
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $connectTask = $client.ConnectAsync($Server, 43)
      if (-not $connectTask.Wait($TimeoutSec * 1000)) {
        throw "TCP connection to ${Server}:43 timed out after $TimeoutSec seconds."
      }
      if ($connectTask.IsFaulted) { throw $connectTask.Exception.InnerException }

      $stream = $client.GetStream()
      $stream.ReadTimeout  = $TimeoutSec * 1000
      $stream.WriteTimeout = $TimeoutSec * 1000

      $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
      $writer.AutoFlush = $true
      $writer.WriteLine($Query)

      return (& $readWhoisStream $stream ($TimeoutSec * 1000))
    }
    finally {
      if ($writer) { try { $writer.Dispose() } catch { } }
      if ($stream) { try { $stream.Dispose() } catch { } }
      if ($client) {
        try { $client.Close() } catch { }
        try { $client.Dispose() } catch { }
      }
    }
  }

  $lastError = $null

  foreach ($server in $servers) {
    # 3.3 Skip TCP servers we recently observed as dead so a transient outage
    # at one registry does not turn into a multi-second tax on every request.
    if (Test-WhoisServerOnCooldown -Server $server) {
      $lastError = "Skipping '$server' (recent failures, on cooldown)."
      continue
    }

    try {
      $text = & $sendWhoisQuery $server $d

      if ([string]::IsNullOrWhiteSpace($text)) { continue }

      # If IANA returned a referral, follow it once. 2.7 The referral server
      # is attacker-controllable on a plaintext port-43 channel, so validate
      # it against an RFC-1123 hostname regex AND require it to look like a
      # WHOIS server (.<tld> suffix or .net/.org/.info) before connecting.
      if ($server -eq 'whois.iana.org' -and $text -match '(?im)^whois:\s*(.+)$') {
        $referralServer = $Matches[1].Trim()
        if (-not [string]::IsNullOrWhiteSpace($referralServer) `
            -and $referralServer -ne 'whois.iana.org' `
            -and $referralServer -match '^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$' `
            -and $referralServer.Contains('.') `
            -and -not (Test-WhoisServerOnCooldown -Server $referralServer)) {
          try {
            $text = & $sendWhoisQuery $referralServer $d
            $server = $referralServer
          }
          catch {
            # Cooldown the referral target the same way we cooldown a primary
            # server; the IANA referral itself is still useful so don't poison
            # whois.iana.org for a downstream failure.
            Add-WhoisServerCooldown -Server $referralServer
            throw
          }
          if ([string]::IsNullOrWhiteSpace($text)) { continue }
        }
      }

      # Skip responses that indicate no data or invalid queries / malformed subdomain lookups.
      if (-not (Test-WhoisRawTextHasUsableData -Text $text)) { continue }

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
        rawText      = (ConvertTo-SafeWhoisRawText -Text $text)
        whoisServer  = $server
      }
    }
    catch {
      $lastError = $_.Exception.Message
      # 3.3 Cooldown the server we were just trying. Connection timeouts and
      # TCP read timeouts both surface as exceptions here, so this catches
      # both classes of failure without needing to inspect the message text.
      Add-WhoisServerCooldown -Server $server
    }
  }

  $msg = if ($lastError) { "TCP whois failed for '$d'. $lastError" } else { "TCP whois returned no usable data for '$d'." }
  if ($ThrowOnError) { throw $msg } else { return $null }
}

