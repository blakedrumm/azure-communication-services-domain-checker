# Validates domain input normalization, including internationalized (IDN) input,
# and the Public Suffix List handling that depends on it. No network access.
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

if ($failures.Count -gt 0) {
  Write-Host ("`nFAILED: {0} of {1} checks failed." -f $failures.Count, $checks) -ForegroundColor Red
  exit 1
}

Write-Host ("`nPASS: {0} input validation checks passed." -f $checks) -ForegroundColor Green
