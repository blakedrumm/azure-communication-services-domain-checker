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
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
    $env:ACS_DNS_DOH_ENDPOINT = $endpoint
  }

  $uri = "{0}?name={1}&type={2}" -f $endpoint, ([uri]::EscapeDataString($Name)), $Type

  # Cloudflare-style DoH JSON response (RFC 8484 compatible JSON format).
  $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10 -ErrorAction Stop
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
        if ($data.StartsWith('"') -and $data.EndsWith('"') -and $data.Length -ge 2) {
          $data = $data.Substring(1, $data.Length - 2)
        }
        $data = $data -replace '\\"','"'
        [pscustomobject]@{ Strings = @($data) }
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
            # Auto
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if ($cmd) {
              return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
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

# ------------------- INPUT NORMALIZATION -------------------
# Normalize raw user input into a clean domain name.
# Accepts: plain domain, email address (takes part after @), or URL (extracts hostname).
# Strips wildcard prefixes (*.) and surrounding dots, then lowercases the result.
