# Validates domain input normalization, including internationalized (IDN) input,
# the Public Suffix List handling that depends on it, and the optional custom
# SPF/DKIM requirement parameters. No network access.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-InputValidation.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()
$checks = 0

function Assert-Equal {
  param([string]$Name, $Expected, $Actual)

  $script:checks++
  if ($Expected -eq $Actual) {
    Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    return
  }

  Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
  Write-Host ("        expected='{0}' actual='{1}'" -f $Expected, $Actual) -ForegroundColor DarkYellow
  $script:failures.Add($Name)
}

Write-Host '=== Domain Input Normalization and IDN Validation ===' -ForegroundColor Cyan

# Keep the PSL lookup entirely offline; the committed list is what we validate against.
$env:ACS_PSL_DISABLE_DOWNLOAD = '1'
. (Join-Path $repoRoot 'src/01-DomainParsing.ps1')
. (Join-Path $repoRoot 'src/13-InputValidation.ps1')

# Non-ASCII literals are built from code points so this file stays ASCII-safe on
# hosts that would otherwise mangle it, matching the repo's encoding convention.
$muenchen = "m" + [char]0x00FC + "nchen.de"
$japanese = [string]([char]0x4F8B + [char]0x3048) + "." + [string]([char]0x30C6 + [char]0x30B9 + [char]0x30C8)
$cyrillicUpper = [string]([char]0x041F + [char]0x0420 + [char]0x0418 + [char]0x041C + [char]0x0415 + [char]0x0420) + "." + [string]([char]0x0420 + [char]0x0424)
$chineseSuffix = [string]([char]0x516C + [char]0x53F8)

Write-Host '--- normalization ---' -ForegroundColor Cyan
Assert-Equal 'ASCII domain is unchanged' 'example.com' (ConvertTo-NormalizedDomain -Raw 'example.com')
Assert-Equal 'ASCII domain is lowercased' 'example.com' (ConvertTo-NormalizedDomain -Raw 'EXAMPLE.COM')
Assert-Equal 'Unicode domain becomes an A-label' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw $muenchen)
Assert-Equal 'multi-label non-Latin domain becomes A-labels' 'xn--r8jz45g.xn--zckzah' (ConvertTo-NormalizedDomain -Raw $japanese)
# IDNA case-folds non-ASCII scripts correctly; ToLowerInvariant alone does not.
Assert-Equal 'uppercase non-Latin domain folds correctly' 'xn--e1afmkfd.xn--p1ai' (ConvertTo-NormalizedDomain -Raw $cyrillicUpper)
Assert-Equal 'already-punycode input is idempotent' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw 'xn--mnchen-3ya.de')
Assert-Equal 'email address with a Unicode domain' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ("kontakt@" + $muenchen))
Assert-Equal 'https URL with a Unicode host' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ("https://" + $muenchen + "/path?q=1#f"))
Assert-Equal 'URL with a port and Unicode host' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ("http://" + $muenchen + ":8080/api"))
Assert-Equal 'trailing dot is stripped from a Unicode domain' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ($muenchen + "."))
Assert-Equal 'surrounding whitespace is trimmed' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ("   " + $muenchen + "   "))
Assert-Equal 'wildcard prefix is stripped from a Unicode domain' 'xn--mnchen-3ya.de' (ConvertTo-NormalizedDomain -Raw ("*." + $muenchen))
Assert-Equal 'empty input stays empty' '' (ConvertTo-NormalizedDomain -Raw '')
Assert-Equal 'whitespace-only input stays empty' '' (ConvertTo-NormalizedDomain -Raw '    ')

Write-Host '--- validation ---' -ForegroundColor Cyan
Assert-Equal 'converted Unicode domain passes validation' $true (Test-DomainName -Domain (ConvertTo-NormalizedDomain -Raw $muenchen))
Assert-Equal 'converted non-Latin domain passes validation' $true (Test-DomainName -Domain (ConvertTo-NormalizedDomain -Raw $japanese))
Assert-Equal 'plain ASCII domain still passes validation' $true (Test-DomainName -Domain (ConvertTo-NormalizedDomain -Raw 'example.com'))
# Conversion must never let a non-ASCII character reach the DNS/WHOIS/URL paths:
# malformed IDN is returned unchanged and then rejected by the final LDH gate.
$unpaired = [string]([char]0xD800) + ".de"
Assert-Equal 'malformed IDN input is rejected' $false (Test-DomainName -Domain (ConvertTo-NormalizedDomain -Raw $unpaired))
Assert-Equal 'raw Unicode never survives validation' $false (Test-DomainName -Domain $muenchen)
# Punycode expands, so a label that fits in Unicode can exceed 63 octets encoded.
# Distinct characters are required here: punycode compresses repetition, so 40
# IDENTICAL characters still encode to only 46 octets and would pass.
$longLabel = (-join (0..44 | ForEach-Object { [char](0x4E00 + $_) })) + ".com"
Assert-Equal 'label too long after conversion is rejected' $false (Test-DomainName -Domain (ConvertTo-NormalizedDomain -Raw $longLabel))
Assert-Equal 'single label is rejected' $false (Test-DomainName -Domain 'localhost')
Assert-Equal 'path injection is rejected' $false (Test-DomainName -Domain 'example.com/evil')

Write-Host '--- registrable domain (Public Suffix List) ---' -ForegroundColor Cyan
Assert-Equal 'plain two-label domain' 'example.com' (Get-RegistrableDomain -Domain 'example.com')
Assert-Equal 'multi-label ICANN suffix' 'example.co.uk' (Get-RegistrableDomain -Domain 'shop.example.co.uk')
# REGRESSION GUARD: the PSL publishes IDN suffixes ONLY in Unicode, but queries
# arrive as A-labels. If the parser stores just the Unicode form, the suffix never
# matches and the registrable domain silently collapses to the suffix itself.
$chineseNormalized = ConvertTo-NormalizedDomain -Raw ("example." + $chineseSuffix + ".cn")
Assert-Equal 'IDN suffix normalizes to an A-label' 'example.xn--55qx5d.cn' $chineseNormalized
Assert-Equal 'IDN suffix keeps the registrable label' 'example.xn--55qx5d.cn' (Get-RegistrableDomain -Domain $chineseNormalized)
$accentNormalized = ConvertTo-NormalizedDomain -Raw ("example.a" + [char]0x00E9 + "roport.ci")
Assert-Equal 'accented IDN suffix keeps the registrable label' 'example.xn--aroport-bya.ci' (Get-RegistrableDomain -Domain $accentNormalized)
Assert-Equal 'fully internationalized domain resolves to itself' 'xn--e1afmkfd.xn--p1ai' (Get-RegistrableDomain -Domain (ConvertTo-NormalizedDomain -Raw $cyrillicUpper))

Write-Host '--- custom SPF / DKIM requirement overrides ---' -ForegroundColor Cyan
Assert-Equal 'underscore label is rejected for a queried domain' $false (Test-DomainName -Domain '_spf.example.com')
Assert-Equal 'underscore label is allowed for an include target' $true (Test-DomainName -Domain '_spf.example.com' -AllowUnderscore)
$govInclude = 'spf.protection.office365.us'
Assert-Equal 'SPF override accepts a bare include host' $govInclude (ConvertTo-SpfIncludeOverride -Raw $govInclude)
Assert-Equal 'SPF override accepts an include term' $govInclude (ConvertTo-SpfIncludeOverride -Raw 'INCLUDE:SPF.Protection.Office365.US')
Assert-Equal 'SPF override accepts a qualified include term' $govInclude (ConvertTo-SpfIncludeOverride -Raw ('+include:' + $govInclude))
Assert-Equal 'SPF override accepts a pasted SPF record' $govInclude (ConvertTo-SpfIncludeOverride -Raw ('v=spf1 include:' + $govInclude + ' -all'))
Assert-Equal 'SPF override accepts a quoted SPF record' $govInclude (ConvertTo-SpfIncludeOverride -Raw ('"v=spf1 ip4:192.0.2.1 include:' + $govInclude + ' -all"'))
Assert-Equal 'SPF override uses the first include of a record' '_spf.example.net' (ConvertTo-SpfIncludeOverride -Raw ('v=spf1 include:_spf.example.net include:' + $govInclude + ' -all'))
Assert-Equal 'SPF override strips a trailing dot' $govInclude (ConvertTo-SpfIncludeOverride -Raw ($govInclude + '.'))
Assert-Equal 'SPF override rejects a record without an include' $null (ConvertTo-SpfIncludeOverride -Raw 'v=spf1 ip4:192.0.2.1 -all')
Assert-Equal 'SPF override rejects a macro include' $null (ConvertTo-SpfIncludeOverride -Raw 'include:%{i}._spf.example.net')
Assert-Equal 'SPF override rejects path injection' $null (ConvertTo-SpfIncludeOverride -Raw ($govInclude + '/evil'))
Assert-Equal 'SPF override rejects a single label' $null (ConvertTo-SpfIncludeOverride -Raw 'localhost')

$govDkimTarget = 'selector1-azurecomm-gcch._domainkey.azurecomm.azure.us'
$govDkimSelector = 'selector1-azurecomm-gcch._domainkey'
$derived = ConvertTo-DkimSelectorOverride -Target $govDkimTarget -Domain 'contoso.gov'
Assert-Equal 'DKIM override derives the selector from the value' $govDkimSelector $derived.selector
Assert-Equal 'DKIM override keeps the value as the target' $govDkimTarget $derived.target
Assert-Equal 'DKIM override trims a fully qualified name' $govDkimSelector (ConvertTo-DkimSelectorOverride -Selector ($govDkimSelector + '.contoso.gov') -Target $govDkimTarget -Domain 'contoso.gov').selector
Assert-Equal 'DKIM override appends _domainkey to a bare selector' $govDkimSelector (ConvertTo-DkimSelectorOverride -Selector 'selector1-azurecomm-gcch' -Target $govDkimTarget -Domain 'contoso.gov').selector
Assert-Equal 'DKIM override lowercases and strips a trailing dot' $govDkimTarget (ConvertTo-DkimSelectorOverride -Target ($govDkimTarget.ToUpperInvariant() + '.') -Domain 'contoso.gov').target
Assert-Equal 'DKIM override requires a target' $null (ConvertTo-DkimSelectorOverride -Selector $govDkimSelector -Target '' -Domain 'contoso.gov')
Assert-Equal 'DKIM override without a derivable selector is rejected' $null (ConvertTo-DkimSelectorOverride -Target 'dkim.azurecomm.azure.us' -Domain 'contoso.gov')
Assert-Equal 'DKIM override rejects path injection' $null (ConvertTo-DkimSelectorOverride -Target ($govDkimTarget + '/evil') -Domain 'contoso.gov')

$query = [System.Collections.Specialized.NameValueCollection]::new()
$query.Add('spfInclude', 'include:' + $govInclude)
$query.Add('dkim1Target', $govDkimTarget)
$parsed = Get-CheckOverridesFromQuery -QueryString $query -Domain 'contoso.gov'
Assert-Equal 'query overrides parse the SPF include' $govInclude $parsed.spfInclude
Assert-Equal 'query overrides parse the DKIM1 selector' $govDkimSelector $parsed.dkim1.selector
Assert-Equal 'query overrides leave DKIM2 on the default' $null $parsed.dkim2
Assert-Equal 'valid query overrides report no error' $null $parsed.error
$badSpfQuery = [System.Collections.Specialized.NameValueCollection]::new()
$badSpfQuery.Add('spfInclude', 'not a host')
Assert-Equal 'invalid spfInclude is reported, not ignored' 'Invalid spfInclude parameter.' (Get-CheckOverridesFromQuery -QueryString $badSpfQuery -Domain 'contoso.gov').error
$badDkimQuery = [System.Collections.Specialized.NameValueCollection]::new()
$badDkimQuery.Add('dkim2Selector', 'selector2-azurecomm-gcch')
Assert-Equal 'DKIM selector without a target is reported' 'Invalid dkim2Selector/dkim2Target parameters.' (Get-CheckOverridesFromQuery -QueryString $badDkimQuery -Domain 'contoso.gov').error
Assert-Equal 'no query means no overrides' $null (Get-CheckOverridesFromQuery -QueryString $null -Domain 'contoso.gov').spfInclude

if ($failures.Count -gt 0) {
  Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("`nPASS: {0} input validation checks passed." -f $checks) -ForegroundColor Green
