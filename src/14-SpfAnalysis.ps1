# ===== SPF Analysis Engine =====
function Get-SpfTokens {
  param([string]$SpfRecord)

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return @() }

  $text = ([string]$SpfRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { return @() }

  return @($text -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

# Check whether a string contains SPF macro syntax (e.g., %{s}, %{d}, %%)
# which requires sender-specific context to expand.
function Test-SpfMacroText {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  return (([string]$Text) -match '%\{' -or ([string]$Text) -match '%%|%_|%-')
}

# Extract the target domain from an SPF mechanism's domain-spec (e.g., "a:mail.example.com/24").
# Strips CIDR notation and returns the domain portion, or falls back to the queried domain.
function Get-SpfDomainSpecTarget {
  param(
    [string]$Spec,
    [string]$Domain
  )

  $fallbackDomain = if ([string]::IsNullOrWhiteSpace($Domain)) { $null } else { ([string]$Domain).Trim().TrimEnd('.').ToLowerInvariant() }
  if ([string]::IsNullOrWhiteSpace($Spec)) { return $fallbackDomain }

  $candidate = ([string]$Spec).Trim()
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $fallbackDomain }

  $slashIndex = $candidate.IndexOf('/')
  if ($slashIndex -ge 0) {
    $candidate = $candidate.Substring(0, $slashIndex)
  }

  $candidate = $candidate.Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $fallbackDomain }

  return $candidate.ToLowerInvariant()
}

# Classify an SPF token into its mechanism type (include, redirect, exists, a, mx, ptr).
# Returns $null for tokens that are not DNS-lookup mechanisms (e.g., ip4, ip6, all).
function Get-SpfMechanismType {
  param([string]$Token)

  if ([string]::IsNullOrWhiteSpace($Token)) { return $null }

  $normalized = ([string]$Token).Trim()
  if ([string]::IsNullOrWhiteSpace($normalized)) { return $null }
  $normalized = $normalized -replace '^[\+\-~\?]', ''

  if ($normalized -match '^(?i)include:') { return 'include' }
  if ($normalized -match '^(?i)redirect=') { return 'redirect' }
  if ($normalized -match '^(?i)exists:') { return 'exists' }
  if ($normalized -match '^(?i)a(?=$|:|/)') { return 'a' }
  if ($normalized -match '^(?i)mx(?=$|:|/)') { return 'mx' }
  if ($normalized -match '^(?i)ptr(?=$|:|/)') { return 'ptr' }

  return $null
}

# Check whether an SPF record string contains a direct "include:spf.protection.outlook.com" token.
function Test-SpfOutlookIncludeToken {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

  foreach ($token in @(Get-SpfTokens -SpfRecord $Text)) {
    $normalized = ([string]$token).Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) { continue }

    $normalized = $normalized -replace '^[\+\-~\?]', ''
    if ($normalized -notmatch '^(?i)include:') { continue }

    $target = ($normalized -replace '^(?i)include:', '')
    $slashIndex = $target.IndexOf('/')
    if ($slashIndex -ge 0) {
      $target = $target.Substring(0, $slashIndex)
    }
    $target = $target.Trim().TrimEnd('.').ToLowerInvariant()
    if ($target -eq 'spf.protection.outlook.com') {
      return $true
    }
  }

  return $false
}

# Recursively search the entire expanded SPF analysis tree for any reference to
# spf.protection.outlook.com — whether via direct include, nested include, redirect, exists,
# a/mx mechanism, or macro. Returns the first match found with its match type.
function Find-SpfOutlookRequirementMatch {
  param([object]$Analysis)

  if (-not $Analysis) { return $null }

  if (Test-SpfOutlookIncludeToken -Text ([string]$Analysis.record)) {
    return [pscustomobject]@{
      matchType = 'direct-include'
      value = 'include:spf.protection.outlook.com'
    }
  }

  foreach ($include in @($Analysis.includes)) {
    $includeDomain = ([string]$include.domain).Trim().TrimEnd('.').ToLowerInvariant()
    if ($includeDomain -eq 'spf.protection.outlook.com') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = $include.domain
      }
    }

    if (Test-SpfOutlookIncludeToken -Text ([string]$include.record)) {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    if (([string]$include.domain) -match '(?i)(^|\.)spf\.protection\.outlook\.com$') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = $include.domain
      }
    }

    if ($include.record -and ([string]$include.record) -match '(?i)\binclude:spf\.protection\.outlook\.com\b') {
      return [pscustomobject]@{
        matchType = 'nested-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    $childMatch = Find-SpfOutlookRequirementMatch -Analysis $include.analysis
    if ($childMatch) { return $childMatch }
  }

  if ($Analysis.redirect) {
    $redirectDomain = ([string]$Analysis.redirect.domain).Trim().TrimEnd('.').ToLowerInvariant()
    if ($redirectDomain -eq 'spf.protection.outlook.com') {
      return [pscustomobject]@{
        matchType = 'redirect-reference'
        value = $Analysis.redirect.domain
      }
    }

    if (Test-SpfOutlookIncludeToken -Text ([string]$Analysis.redirect.record)) {
      return [pscustomobject]@{
        matchType = 'redirect-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    if ($Analysis.redirect.record -and ([string]$Analysis.redirect.record) -match '(?i)\binclude:spf\.protection\.outlook\.com\b') {
      return [pscustomobject]@{
        matchType = 'redirect-include'
        value = 'include:spf.protection.outlook.com'
      }
    }

    $redirectMatch = Find-SpfOutlookRequirementMatch -Analysis $Analysis.redirect.analysis
    if ($redirectMatch) { return $redirectMatch }
  }

  foreach ($existsTerm in @($Analysis.existsTerms)) {
    if (([string]$existsTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'exists-reference'
        value = $existsTerm.target
      }
    }
  }

  foreach ($aTerm in @($Analysis.aTerms)) {
    if (([string]$aTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'a-reference'
        value = $aTerm.target
      }
    }
  }

  foreach ($mxTerm in @($Analysis.mxTerms)) {
    if (([string]$mxTerm.target) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'mx-reference'
        value = $mxTerm.target
      }
    }
  }

  foreach ($macro in @($Analysis.macros)) {
    if (([string]$macro) -match '(?i)spf\.protection\.outlook\.com') {
      return [pscustomobject]@{
        matchType = 'macro-reference'
        value = $macro
      }
    }
  }

  return $null
}

# Determine whether the ACS-required "include:spf.protection.outlook.com" is present
# in the domain's SPF record (directly or through nested includes/redirects).
# Returns an object with isPresent, matchType, detail, and error.
function Get-SpfOutlookRequirementStatus {
  param(
    [string]$Domain,
    [string]$SpfRecord,
    [object]$SpfAnalysis
  )

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) {
    return [pscustomobject]@{
      isPresent = $false
      matchType = 'missing-spf'
      detail = 'No SPF record was found.'
      error = 'SPF record is missing, so the required include:spf.protection.outlook.com could not be validated.'
    }
  }

  if (Test-SpfOutlookIncludeToken -Text $SpfRecord) {
    return [pscustomobject]@{
      isPresent = $true
      matchType = 'direct-include'
      detail = 'Found direct include:spf.protection.outlook.com in the SPF record.'
      error = $null
    }
  }

  $match = Find-SpfOutlookRequirementMatch -Analysis $SpfAnalysis
  if ($match) {
    switch ($match.matchType) {
      'nested-include' {
        return [pscustomobject]@{
          isPresent = $true
          matchType = $match.matchType
          detail = "Found include:spf.protection.outlook.com in the expanded SPF chain ($($match.value))."
          error = $null
        }
      }
      'redirect-include' {
        return [pscustomobject]@{
          isPresent = $true
          matchType = $match.matchType
          detail = 'Found include:spf.protection.outlook.com through an SPF redirect target.'
          error = $null
        }
      }
      default {
        return [pscustomobject]@{
          isPresent = $false
          matchType = $match.matchType
          detail = $null
          error = "SPF for $targetDomain references spf.protection.outlook.com indirectly ($($match.value)), but the required include:spf.protection.outlook.com could not be confirmed in the expanded SPF chain."
        }
      }
    }
  }

  $targetDomain = if ([string]::IsNullOrWhiteSpace($Domain)) { 'the domain' } else { $Domain }
  $analysisScope = if ($SpfAnalysis -and $SpfAnalysis.analysisScope) { [string]$SpfAnalysis.analysisScope } else { 'full-static' }
  $error = if ($analysisScope -eq 'message-context-required' -or $analysisScope -eq 'partial-static') {
    "SPF for $targetDomain could not be confirmed to include include:spf.protection.outlook.com. The record uses nested or macro-based logic, and the required Outlook include was not found during static analysis."
  } else {
    "SPF for $targetDomain does not include include:spf.protection.outlook.com in the expanded SPF chain. This is required for ACS SPF validation."
  }

  return [pscustomobject]@{
    isPresent = $false
    matchType = 'not-found'
    detail = 'Did not find include:spf.protection.outlook.com in the expanded SPF chain.'
    error = $error
  }
}

# Recursively parse an SPF record, resolving includes and redirects up to MaxDepth levels.
# For each mechanism (include, redirect, a, mx, exists, ptr), performs live DNS lookups
# and builds a tree of results. Tracks visited domains to detect include loops.
# Also counts total DNS-lookup-style terms to warn about the SPF 10-lookup limit.
function Get-SpfNestedAnalysis {
  param(
    [string]$SpfRecord,
    [string]$Domain,
    [int]$MaxDepth = 8,
    [hashtable]$Visited
  )

  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return $null }
  if ($MaxDepth -lt 0) { $MaxDepth = 0 }
  if ($null -eq $Visited) { $Visited = @{} }

  $tokens = @(Get-SpfTokens -SpfRecord $SpfRecord)
  if ($tokens.Count -eq 0) { return $null }

  $includes = New-Object System.Collections.Generic.List[object]
  $redirect = $null
  $existsTerms = New-Object System.Collections.Generic.List[object]
  $aTerms = New-Object System.Collections.Generic.List[object]
  $mxTerms = New-Object System.Collections.Generic.List[object]
  $ptrTerms = New-Object System.Collections.Generic.List[object]
  $macros = New-Object System.Collections.Generic.List[string]
  $warnings = New-Object System.Collections.Generic.List[string]
  $errors = New-Object System.Collections.Generic.List[string]
  $lookupTerms = 0
  $nestedLookupTerms = 0
  $analysisScope = 'full-static'

  foreach ($token in $tokens) {
    $item = ([string]$token).Trim()
    if ([string]::IsNullOrWhiteSpace($item)) { continue }

    if (Test-SpfMacroText -Text $item) {
      if (-not $macros.Contains($item)) { $macros.Add($item) }
      if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
    }

    $mechanismType = Get-SpfMechanismType -Token $item
    if ($mechanismType) {
      $lookupTerms++
    }

    if ($mechanismType -eq 'include' -and $item -match '^(?i)[+\-~?]?include:(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      if ([string]::IsNullOrWhiteSpace($target)) { continue }

      $includeRecord = $null
      $includeError = $null
      $includeResult = $null
      $visitedKey = $target.ToLowerInvariant()

      if ($Visited.ContainsKey($visitedKey)) {
        $includeError = "Include loop detected for $target."
      }
      elseif ($MaxDepth -le 0) {
        $includeError = "Maximum SPF include depth reached at $target."
      }
      elseif (Test-SpfMacroText -Text $target) {
        $includeError = "Include target $target uses SPF macros and requires sender-specific context to expand."
        if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
      }
      else {
        $Visited[$visitedKey] = $true
        try {
          $txtRecords = ResolveSafely $target 'TXT'
          foreach ($txt in @($txtRecords)) {
            $joined = ($txt.Strings -join '').Trim()
            if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
              $joined = $joined.Substring(1, $joined.Length - 2)
            }
            if ($joined -match '(?i)^v=spf1\b') {
              $includeRecord = $joined
              break
            }
          }

          if ($includeRecord) {
            $includeResult = Get-SpfNestedAnalysis -SpfRecord $includeRecord -Domain $target -MaxDepth ($MaxDepth - 1) -Visited $Visited
            if ($includeResult -and $includeResult.totalLookupTerms -ne $null) {
              $nestedLookupTerms += [int]$includeResult.totalLookupTerms
            }
          }
          else {
            $includeError = "No SPF TXT record found for include target $target."
          }
        }
        catch {
          $includeError = $_.Exception.Message
        }
        finally {
          $Visited.Remove($visitedKey) | Out-Null
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($includeError) -and -not $errors.Contains($includeError)) {
        $errors.Add($includeError)
      }

      $includes.Add([pscustomobject]@{
        domain = $target
        record = $includeRecord
        error = $includeError
        analysis = $includeResult
      })
      continue
    }

    if ($mechanismType -eq 'redirect' -and $item -match '^(?i)redirect=(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      if ([string]::IsNullOrWhiteSpace($target)) { continue }

      $redirectRecord = $null
      $redirectError = $null
      $redirectAnalysis = $null
      $visitedKey = $target.ToLowerInvariant()

      if ($Visited.ContainsKey($visitedKey)) {
        $redirectError = "Redirect loop detected for $target."
      }
      elseif ($MaxDepth -le 0) {
        $redirectError = "Maximum SPF redirect depth reached at $target."
      }
      elseif (Test-SpfMacroText -Text $target) {
        $redirectError = "Redirect target $target uses SPF macros and requires sender-specific context to expand."
        if ($analysisScope -ne 'message-context-required') { $analysisScope = 'partial-static' }
      }
      else {
        $Visited[$visitedKey] = $true
        try {
          $txtRecords = ResolveSafely $target 'TXT'
          foreach ($txt in @($txtRecords)) {
            $joined = ($txt.Strings -join '').Trim()
            if ($joined.StartsWith('"') -and $joined.EndsWith('"') -and $joined.Length -ge 2) {
              $joined = $joined.Substring(1, $joined.Length - 2)
            }
            if ($joined -match '(?i)^v=spf1\b') {
              $redirectRecord = $joined
              break
            }
          }

          if ($redirectRecord) {
            $redirectAnalysis = Get-SpfNestedAnalysis -SpfRecord $redirectRecord -Domain $target -MaxDepth ($MaxDepth - 1) -Visited $Visited
            if ($redirectAnalysis -and $redirectAnalysis.totalLookupTerms -ne $null) {
              $nestedLookupTerms += [int]$redirectAnalysis.totalLookupTerms
            }
          }
          else {
            $redirectError = "No SPF TXT record found for redirect target $target."
          }
        }
        catch {
          $redirectError = $_.Exception.Message
        }
        finally {
          $Visited.Remove($visitedKey) | Out-Null
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($redirectError) -and -not $errors.Contains($redirectError)) {
        $errors.Add($redirectError)
      }

      $redirect = [pscustomobject]@{
        domain = $target
        record = $redirectRecord
        error = $redirectError
        analysis = $redirectAnalysis
      }
      continue
    }

    if ($mechanismType -eq 'exists' -and $item -match '^(?i)[+\-~?]?exists:(.+)$') {
      $target = ([string]$Matches[1]).Trim().TrimEnd('.')
      $existsError = $null
      $resolved = @()
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $existsError = 'SPF exists mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $existsError = "Exists target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $resolved = @((ResolveSafely $target 'A' | Get-DnsIpString) + (ResolveSafely $target 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
        }
        catch {
          $analysisStatus = 'error'
          $existsError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($existsError) -and -not $errors.Contains($existsError)) {
        $errors.Add($existsError)
      }

      $existsTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedAddresses = @($resolved)
        error = $existsError
      })
      continue
    }

    if ($mechanismType -eq 'a') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(1)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $aError = $null
      $resolved = @()
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $aError = 'SPF a mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $aError = "A mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $resolved = @((ResolveSafely $target 'A' | Get-DnsIpString) + (ResolveSafely $target 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
        }
        catch {
          $analysisStatus = 'error'
          $aError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($aError) -and -not $errors.Contains($aError)) {
        $errors.Add($aError)
      }

      $aTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedAddresses = @($resolved)
        error = $aError
      })
      continue
    }

    if ($mechanismType -eq 'mx') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(2)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $mxError = $null
      $resolvedHosts = New-Object System.Collections.Generic.List[object]
      $analysisStatus = 'resolved'

      if ([string]::IsNullOrWhiteSpace($target)) {
        $analysisStatus = 'invalid'
        $mxError = 'SPF mx mechanism target is empty.'
      }
      elseif (Test-SpfMacroText -Text $target) {
        $analysisStatus = 'context-required'
        $mxError = "MX mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
        $analysisScope = 'message-context-required'
      }
      else {
        try {
          $mxRecords = @(Get-MxRecordObjects -Records (ResolveSafely $target 'MX'))
          foreach ($mxRecord in $mxRecords) {
            $mxHost = ([string]$mxRecord.NameExchange).Trim().TrimEnd('.')
            if ([string]::IsNullOrWhiteSpace($mxHost)) { continue }
            $hostAddresses = @((ResolveSafely $mxHost 'A' | Get-DnsIpString) + (ResolveSafely $mxHost 'AAAA' | Get-DnsIpString) | Select-Object -Unique)
            $resolvedHosts.Add([pscustomobject]@{
              hostname = $mxHost
              preference = $mxRecord.Preference
              addresses = @($hostAddresses)
            })
          }
        }
        catch {
          $analysisStatus = 'error'
          $mxError = $_.Exception.Message
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($mxError) -and -not $errors.Contains($mxError)) {
        $errors.Add($mxError)
      }

      # PowerShell 7.6 regression: @($genericList[object]) throws
      # "Argument types do not match". Use .ToArray() to materialize the
      # List[object] into a plain object[] that the pscustomobject literal
      # can safely embed.
      $mxTerms.Add([pscustomobject]@{
        target = $target
        status = $analysisStatus
        resolvedHosts = $resolvedHosts.ToArray()
        error = $mxError
      })
      continue
    }

    if ($mechanismType -eq 'ptr') {
      $normalized = $item -replace '^[\+\-~\?]', ''
      $spec = $normalized.Substring(3)
      $target = Get-SpfDomainSpecTarget -Spec $spec -Domain $Domain
      $ptrMessage = if ([string]::IsNullOrWhiteSpace($target)) {
        'PTR mechanism present. Static analysis cannot validate PTR authorization safely and SPF PTR is discouraged.'
      } elseif (Test-SpfMacroText -Text $target) {
        $analysisScope = 'message-context-required'
        "PTR mechanism target $target uses SPF macros and requires sender-specific context to evaluate."
      } else {
        "PTR mechanism target $target requires sender IP context and reverse DNS evaluation; only presence is reported."
      }

      if (-not $warnings.Contains($ptrMessage)) { $warnings.Add($ptrMessage) }
      $ptrTerms.Add([pscustomobject]@{
        target = $target
        message = $ptrMessage
      })
      continue
    }
  }

  $totalLookupTerms = $lookupTerms + $nestedLookupTerms
  if ($totalLookupTerms -gt 10) {
    $warnings.Add("SPF record for $Domain may exceed the 10-DNS-lookup guidance limit. Detected lookup-style terms across the expanded chain: $totalLookupTerms.")
  }
  if ($analysisScope -eq 'partial-static') {
    $warnings.Add("SPF record for $Domain includes macro-based targets. This tool performs best-effort static analysis, but some nested paths require sender-specific context to expand fully.")
  }
  elseif ($analysisScope -eq 'message-context-required') {
    $warnings.Add("SPF record for $Domain includes mechanisms that require sender-specific context (for example macros, exists, or ptr). Full SPF evaluation requires message inputs such as sender IP, HELO, and MAIL FROM.")
  }

  # PowerShell 7.6 introduced a regression where @($genericList[object])
  # throws "Argument types do not match" (repro:
  # @((New-Object System.Collections.Generic.List[object]))). That caused
  # Get-SpfNestedAnalysis to silently return $null on every call, which in
  # turn hid the SPF Expansion Records card in the UI. Using .ToArray() on
  # each List[object] materializes a plain object[] that survives the
  # pscustomobject literal on affected PowerShell versions. List[string]
  # fields are unaffected so we leave them on the simpler @() form.
  [pscustomobject]@{
    domain = $Domain
    record = $SpfRecord
    includes = $includes.ToArray()
    redirect = $redirect
    existsTerms = $existsTerms.ToArray()
    aTerms = $aTerms.ToArray()
    mxTerms = $mxTerms.ToArray()
    ptrTerms = $ptrTerms.ToArray()
    macros = @($macros | Select-Object -Unique)
    lookupTerms = $lookupTerms
    nestedLookupTerms = $nestedLookupTerms
    totalLookupTerms = $totalLookupTerms
    analysisScope = $analysisScope
    warnings = @($warnings)
    errors = @($errors | Select-Object -Unique)
  }
}

# Render the SPF analysis tree as indented plain-text lines for display in the UI's
# "expanded SPF" section. Each level of nesting adds two spaces of indentation.
function Format-SpfNestedAnalysisText {
  param(
    [object]$Analysis,
    [int]$Depth = 0
  )

  if (-not $Analysis) { return @() }

  $lines = New-Object System.Collections.Generic.List[string]
  $indent = ('  ' * $Depth)
  $domainLabel = if (-not [string]::IsNullOrWhiteSpace([string]$Analysis.domain)) { [string]$Analysis.domain } else { 'SPF' }
  $lines.Add("${indent}Domain: $domainLabel")
  if ($Analysis.record) {
    $lines.Add("${indent}Record: $([string]$Analysis.record)")
  }
  if ($Analysis.lookupTerms -ne $null) {
    $lines.Add("${indent}Lookup-style terms: $([string]$Analysis.lookupTerms)")
  }
  if ($Analysis.totalLookupTerms -ne $null -and [int]$Analysis.totalLookupTerms -ne [int]$Analysis.lookupTerms) {
    $lines.Add("${indent}Expanded-chain lookup terms: $([string]$Analysis.totalLookupTerms)")
  }
  foreach ($macro in @($Analysis.macros)) {
    $lines.Add("${indent}Macro term: $([string]$macro)")
  }
  foreach ($warning in @($Analysis.warnings)) {
    $lines.Add("${indent}Warning: $([string]$warning)")
  }
  foreach ($errorText in @($Analysis.errors)) {
    $lines.Add("${indent}Note: $([string]$errorText)")
  }

  foreach ($existsTerm in @($Analysis.existsTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$existsTerm.target)) { [string]$existsTerm.target } else { '(empty)' }
    $existsLine = "${indent}Exists: $target"
    if ($existsTerm.status) { $existsLine += " [$([string]$existsTerm.status)]" }
    if ($existsTerm.error) {
      $existsLine += " (note: $([string]$existsTerm.error))"
    }
    elseif (@($existsTerm.resolvedAddresses).Count -gt 0) {
      $existsLine += ": $((@($existsTerm.resolvedAddresses) -join ', '))"
    }
    $lines.Add($existsLine)
  }

  foreach ($aTerm in @($Analysis.aTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$aTerm.target)) { [string]$aTerm.target } else { '(empty)' }
    $aLine = "${indent}A: $target"
    if ($aTerm.status) { $aLine += " [$([string]$aTerm.status)]" }
    if ($aTerm.error) {
      $aLine += " (note: $([string]$aTerm.error))"
    }
    elseif (@($aTerm.resolvedAddresses).Count -gt 0) {
      $aLine += ": $((@($aTerm.resolvedAddresses) -join ', '))"
    }
    $lines.Add($aLine)
  }

  foreach ($mxTerm in @($Analysis.mxTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$mxTerm.target)) { [string]$mxTerm.target } else { '(empty)' }
    $mxLine = "${indent}MX: $target"
    if ($mxTerm.status) { $mxLine += " [$([string]$mxTerm.status)]" }
    if ($mxTerm.error) {
      $mxLine += " (note: $([string]$mxTerm.error))"
      $lines.Add($mxLine)
      continue
    }

    $lines.Add($mxLine)
    foreach ($host in @($mxTerm.resolvedHosts)) {
      $hostLine = "${indent}  Host: $([string]$host.hostname)"
      if ($null -ne $host.preference) { $hostLine += " (priority $([string]$host.preference))" }
      if (@($host.addresses).Count -gt 0) {
        $hostLine += ": $((@($host.addresses) -join ', '))"
      }
      $lines.Add($hostLine)
    }
  }

  foreach ($ptrTerm in @($Analysis.ptrTerms)) {
    $target = if (-not [string]::IsNullOrWhiteSpace([string]$ptrTerm.target)) { [string]$ptrTerm.target } else { '(queried domain)' }
    $lines.Add("${indent}PTR: $target ($([string]$ptrTerm.message))")
  }

  foreach ($include in @($Analysis.includes)) {
    $includeDomain = [string]$include.domain
    if ($include.error) {
      $lines.Add("${indent}Include: $includeDomain (error: $([string]$include.error))")
    }
    else {
      $lines.Add("${indent}Include: $includeDomain")
      foreach ($childLine in @(Format-SpfNestedAnalysisText -Analysis $include.analysis -Depth ($Depth + 1))) {
        $lines.Add($childLine)
      }
    }
  }

  if ($Analysis.redirect) {
    $redirectDomain = [string]$Analysis.redirect.domain
    if ($Analysis.redirect.error) {
      $lines.Add("${indent}Redirect: $redirectDomain (error: $([string]$Analysis.redirect.error))")
    }
    else {
      $lines.Add("${indent}Redirect: $redirectDomain")
      foreach ($childLine in @(Format-SpfNestedAnalysisText -Analysis $Analysis.redirect.analysis -Depth ($Depth + 1))) {
        $lines.Add($childLine)
      }
    }
  }

  return @($lines)
}

# Generate human-readable SPF security recommendations based on the record content
# and the analysis results. Warns about +all, ?all, ~all, macros, many lookup terms,
# and the ACS Outlook include requirement.
function Get-SpfGuidance {
  param(
    [string]$SpfRecord,
    [string]$Domain,
    [object]$SpfAnalysis,
    [object]$OutlookRequirementStatus
  )

  $messages = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($SpfRecord)) { return @() }

  $recordText = ([string]$SpfRecord).Trim()
  if ([string]::IsNullOrWhiteSpace($recordText)) { return @() }

  $targetDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } else { 'the domain' }

  if ($recordText -match '(?i)\s\+all(\s|$)') {
    $messages.Add("SPF for $targetDomain allows all senders (`+all`), which is insecure. Replace it with a restrictive qualifier such as `-all` or `~all` after validating legitimate senders.")
  }
  elseif ($recordText -match '(?i)\s\?all(\s|$)') {
    $messages.Add("SPF for $targetDomain ends with `?all`, which is neutral and provides little protection. Consider `~all` during rollout or `-all` for strict enforcement.")
  }
  elseif ($recordText -match '(?i)\s~all(\s|$)') {
    $messages.Add("SPF for $targetDomain ends with soft fail (`~all`). For a stricter anti-spoofing posture, consider `-all` once all valid senders are confirmed.")
  }
  elseif ($recordText -notmatch '(?i)\s[-~?+]all(\s|$)') {
    $messages.Add("SPF for $targetDomain does not appear to end with an `all` mechanism. Add an explicit `~all` or `-all` so unauthorized senders are handled predictably.")
  }

  if ($recordText -match '%\{' -or $recordText -match '%%|%_|%-') {
    $messages.Add("SPF for $targetDomain uses macros. This tool performs best-effort static analysis, but macro-based SPF can require sender-specific context to evaluate fully.")
  }

  if ($SpfAnalysis) {
    if ($SpfAnalysis.totalLookupTerms -gt 8) {
      $messages.Add("SPF for $targetDomain uses many DNS-lookup-style terms ($($SpfAnalysis.totalLookupTerms) detected across the expanded chain). Complex nested SPF records can approach the SPF 10-lookup evaluation limit.")
    }
    if (@($SpfAnalysis.includes).Count -gt 0) {
      $messages.Add("SPF for $targetDomain includes nested sender policies. Review the expanded SPF chain in the SPF card to confirm all included services are expected.")
    }
    if (@($SpfAnalysis.existsTerms).Count -gt 0) {
      $messages.Add("SPF for $targetDomain uses `exists:` mechanisms. These can be analyzed structurally, but full authorization depends on sender-specific evaluation context.")
    }
    if (@($SpfAnalysis.ptrTerms).Count -gt 0) {
      $messages.Add("SPF for $targetDomain uses `ptr`, which is discouraged and cannot be fully evaluated by this static domain checker without sender context.")
    }
    if ($SpfAnalysis.analysisScope -eq 'message-context-required') {
      $messages.Add("SPF for $targetDomain requires message context for full evaluation. Use a sender IP, HELO, and MAIL FROM if you need a true SPF pass/fail simulation.")
    }
    foreach ($warning in @($SpfAnalysis.warnings)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$warning)) { $messages.Add([string]$warning) }
    }
  }

  if ($OutlookRequirementStatus) {
    if ($OutlookRequirementStatus.isPresent -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$OutlookRequirementStatus.detail)) {
      $messages.Add([string]$OutlookRequirementStatus.detail)
    }
    elseif ($OutlookRequirementStatus.isPresent -ne $true -and -not [string]::IsNullOrWhiteSpace([string]$OutlookRequirementStatus.error)) {
      $messages.Add([string]$OutlookRequirementStatus.error)
    }
  }

  return @($messages | Select-Object -Unique)
}

# ------------------- REQUEST HANDLING UTILITIES -------------------
# Log a request to the console. Intentionally omits IP addresses and user agents (PII).
