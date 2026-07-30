# Static validation for the SEO / AI-agent discovery metadata.
#
# Guards the couplings that are easy to break because they live in different
# files and nothing at runtime complains until a crawler sees the damage:
#   1. Supported-language list is duplicated in 3 places and must stay in sync.
#   2. Every __TOKEN__ in the HTML templates must have a replacement site, or it
#      ships literally into the served page.
#   3. -f format strings must escape literal braces (this shipped broken once
#      and only surfaced as an HTTP 500 on /openapi.json).
#   4. Every public lookup endpoint must be advertised in /llms.txt and
#      /openapi.json, otherwise AI agents cannot discover it.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/Test-SeoMetadata.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$srcRoot = Join-Path $repoRoot 'src'

$failures = New-Object System.Collections.Generic.List[string]
$checks = 0

function Assert-Condition {
    param([string]$Name, [bool]$Condition, [string]$Detail)
    $script:checks++
    if ($Condition) {
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
        if ($Detail) { Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkYellow }
        $script:failures.Add($Name)
    }
}

Write-Host "=== SEO / AI Metadata Validation ===" -ForegroundColor Cyan

# --- 1) Supported-language parity -------------------------------------------
Write-Host "`n[1] Language list parity"

$seoFile = Join-Path $srcRoot '11a-SeoMetadata.ps1'
. $seoFile   # only defines functions; safe to dot-source
$seoLanguages = @(Get-AcsSeoLanguages)

$translationsRaw = Get-Content (Join-Path $srcRoot '20b-HtmlTranslations.ps1') -Raw
$spaMatch = [regex]::Match($translationsRaw, "(?m)^const LANGUAGE_OPTIONS\s*=\s*\[([^\]]*)\]")
$spaLanguages = @()
if ($spaMatch.Success) {
    $spaLanguages = @([regex]::Matches($spaMatch.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
}

$cssRaw = Get-Content (Join-Path $srcRoot '20-HtmlCss.ps1') -Raw
$headLanguages = @([regex]::Matches($cssRaw, 'rel="alternate" hreflang="([^"]+)"') |
    ForEach-Object { $_.Groups[1].Value } |
    Where-Object { $_ -ne 'x-default' })

Assert-Condition 'SPA LANGUAGE_OPTIONS was found' ($spaLanguages.Count -gt 0) 'regex did not match 20b-HtmlTranslations.ps1'
Assert-Condition 'Get-AcsSeoLanguages matches the SPA language list' `
    (-not (Compare-Object $seoLanguages $spaLanguages)) `
    ("seo=[{0}] spa=[{1}]" -f ($seoLanguages -join ','), ($spaLanguages -join ','))
Assert-Condition 'hreflang links match the SPA language list' `
    (-not (Compare-Object $headLanguages $spaLanguages)) `
    ("head=[{0}] spa=[{1}]" -f ($headLanguages -join ','), ($spaLanguages -join ','))
Assert-Condition 'head declares an x-default alternate' `
    ($cssRaw -match 'hreflang="x-default"') 'missing x-default hreflang'

# --- 2) Template token coverage ---------------------------------------------
Write-Host "`n[2] Template token replacement coverage"

$templateFiles = Get-ChildItem -Path $srcRoot -Filter '2*.ps1' -File
$usedTokens = New-Object System.Collections.Generic.HashSet[string]
foreach ($file in $templateFiles) {
    foreach ($line in (Get-Content $file.FullName)) {
        # Skip PowerShell comment lines so documentation examples (e.g. the
        # literal "__TOKEN__ -> value" note) are not treated as real tokens.
        if ($line -match '^\s*#') { continue }
        foreach ($m in [regex]::Matches($line, '__[A-Z][A-Z0-9_]*__')) {
            [void]$usedTokens.Add($m.Value)
        }
    }
}

$allSrc = (Get-ChildItem -Path $srcRoot -Filter '*.ps1' -File | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
$replacedTokens = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($allSrc, "Replace\('(__[A-Z][A-Z0-9_]*__)'")) {
    [void]$replacedTokens.Add($m.Groups[1].Value)
}

Assert-Condition 'template tokens were discovered' ($usedTokens.Count -gt 0) 'no tokens found - regex may be wrong'
foreach ($token in ($usedTokens | Sort-Object)) {
    Assert-Condition ("token {0} has a replacement site" -f $token) `
        ($replacedTokens.Contains($token)) `
        'no .Replace() call found in src/ - it would ship literally into the page'
}

# --- 3) Format-string brace escaping ----------------------------------------
Write-Host "`n[3] Format-string validity in 11a-SeoMetadata.ps1"

$seoRaw = Get-Content $seoFile -Raw
$badFormats = New-Object System.Collections.Generic.List[string]
$formatCount = 0
foreach ($m in [regex]::Matches($seoRaw, "'((?:[^']|'')*)'\s*-f\s")) {
    $fmt = $m.Groups[1].Value -replace "''", "'"
    $formatCount++
    try { [void][string]::Format($fmt, @('a', 'b', 'c', 'd')) }
    catch { $badFormats.Add($fmt) }
}
Assert-Condition 'format strings were discovered' ($formatCount -gt 0) 'regex found none'
Assert-Condition 'all -f format strings are valid' ($badFormats.Count -eq 0) `
    ("literal { or } must be doubled in: " + ($badFormats -join ' | '))

# --- 4) Endpoint discoverability --------------------------------------------
Write-Host "`n[4] Endpoint coverage in /llms.txt and /openapi.json"

$handlerRaw = Get-Content (Join-Path $srcRoot '23-RequestHandler.ps1') -Raw
$apiListMatch = [regex]::Match($handlerRaw, '\$path -in @\(("/api/[^)]*)\)')
$servedEndpoints = @()
if ($apiListMatch.Success) {
    $servedEndpoints = @([regex]::Matches($apiListMatch.Groups[1].Value, '"(/api/[^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}
$servedEndpoints += '/dns'

$llms = Get-AcsLlmsTxt -BaseUrl 'https://example.test' -Version '0.0.0'
$openApi = Get-AcsOpenApiJson -BaseUrl 'https://example.test' -Version '0.0.0'

Assert-Condition 'handler endpoint list was parsed' ($servedEndpoints.Count -gt 1) 'regex did not match 23-RequestHandler.ps1'

$openApiParses = $false
try { $null = $openApi | ConvertFrom-Json; $openApiParses = $true } catch { $openApiParses = $false }
Assert-Condition '/openapi.json is valid JSON' $openApiParses 'ConvertFrom-Json threw'

foreach ($endpoint in ($servedEndpoints | Sort-Object -Unique)) {
    Assert-Condition ("{0} documented in llms.txt" -f $endpoint) ($llms -like ("*{0}?domain=*" -f $endpoint)) 'add it to Get-AcsLlmsTxt'
    Assert-Condition ("{0} documented in openapi.json" -f $endpoint) ($openApi -like ("*`"{0}`":*" -f $endpoint)) 'add it to the $endpoints table in Get-AcsOpenApiJson'
}

# --- 5) Required head metadata ----------------------------------------------
Write-Host "`n[5] Required <head> metadata"

$requiredMeta = [ordered]@{
    'meta description'   = '<meta name="description"'
    'meta robots token'  = '<meta name="robots" content="__ACS_ROBOTS__"'
    'canonical link'     = '<link rel="canonical"'
    'og:title'           = 'property="og:title"'
    'og:description'     = 'property="og:description"'
    'og:url'             = 'property="og:url"'
    'og:image'           = 'property="og:image"'
    'twitter:card'       = 'name="twitter:card"'
    'JSON-LD block'      = 'application/ld+json'
    'llms.txt discovery' = '/llms.txt'
    'openapi discovery'  = '/openapi.json'
}
foreach ($name in $requiredMeta.Keys) {
    Assert-Condition ("head contains {0}" -f $name) ($cssRaw.Contains($requiredMeta[$name])) 'missing from 20-HtmlCss.ps1 <head>'
}

# JSON-LD must be nonce-bound or the strict CSP blocks it.
$ldMatch = [regex]::Match($cssRaw, '<script type="application/ld\+json"([^>]*)>')
Assert-Condition 'JSON-LD script carries the CSP nonce' `
    ($ldMatch.Success -and $ldMatch.Groups[1].Value -match '__CSP_NONCE__') `
    'add nonce="__CSP_NONCE__" or the strict CSP will block it'

# The static <title> and the en pageTitle translation must agree, because
# updateTitle() overwrites document.title from t('pageTitle') on every render.
$staticTitle = [regex]::Match($cssRaw, '<title>([^<]+)</title>').Groups[1].Value
$enPageTitle = [regex]::Match($translationsRaw, "pageTitle:\s*'([^']+)'").Groups[1].Value
Assert-Condition 'static <title> matches the en pageTitle translation' `
    ($staticTitle -eq $enPageTitle) `
    ("title='{0}' pageTitle='{1}' - JS would overwrite the crawler-visible title" -f $staticTitle, $enPageTitle)

# --- 6) HEAD request support -------------------------------------------------
Write-Host "`n[6] HEAD request support"

$helpersFile = Join-Path $srcRoot '11-HttpHelpers.ps1'
$helpersRaw = Get-Content $helpersFile -Raw
$runspaceRaw = Get-Content (Join-Path $srcRoot '22-RunspaceSetup.ps1') -Raw
$requestLoopRaw = Get-Content (Join-Path $srcRoot '24-RequestLoop.ps1') -Raw

. $helpersFile
$headContext = [pscustomobject]@{ Request = [pscustomobject]@{ HttpMethod = 'HEAD' } }
$getContext = [pscustomobject]@{ Request = [pscustomobject]@{ HttpMethod = 'GET' } }
Assert-Condition 'Test-AcsHeadRequest recognizes HEAD only' `
    ((Test-AcsHeadRequest -Context $headContext) -and -not (Test-AcsHeadRequest -Context $getContext)) `
    'HEAD responses would either write a forbidden body or suppress normal GET bodies'

$helperHeadGuards = [regex]::Matches($helpersRaw, 'if \(Test-AcsHeadRequest -Context \$Context\)').Count
Assert-Condition 'JSON, file, and HTML writers suppress HEAD bodies' `
    ($helperHeadGuards -ge 3) `
    ("expected at least 3 response guards in 11-HttpHelpers.ps1, found {0}" -f $helperHeadGuards)
Assert-Condition 'text response writer suppresses HEAD bodies' `
    ($seoRaw -match 'if \(Test-AcsHeadRequest -Context \$Context\)') `
    'Write-TextResponse would make discovery routes return HTTP 500 to HEAD requests'
Assert-Condition 'HEAD detector is registered in worker runspaces' `
    ($runspaceRaw -match "'Test-AcsHeadRequest'") `
    'request handlers would fail with command-not-found inside the runspace pool'
Assert-Condition 'TcpListener accepts HEAD requests' `
    ($requestLoopRaw -match "@\('GET', 'HEAD', 'POST'\)") `
    'fallback listener would return 405 before reaching the request handler'
Assert-Condition 'TcpListener emits headers but suppresses HEAD body bytes' `
    ($requestLoopRaw -match '_suppressBody\s*=\s*\(\$Method -eq ''HEAD''\)' -and
     $requestLoopRaw -match '-not \$this\._suppressBody') `
    'fallback listener would send the GET body on a HEAD request'

# --- 7) Share-link bootstrap -------------------------------------------------
Write-Host "`n[7] Share-link bootstrap"

$coreRaw = Get-Content (Join-Path $srcRoot '20d-HtmlJsCore.ps1') -Raw
Assert-Condition 'initial lookup has a hidden-tab timer fallback' `
    ($coreRaw -match 'window\.setTimeout\(startInitialLookup,\s*250\)') `
    'requestAnimationFrame pauses in hidden tabs, leaving ?domain= links stuck until foregrounded'
Assert-Condition 'initial lookup dispatch is idempotent' `
    ($coreRaw -match 'const startInitialLookup = \(\) => \{\s*if \(initialLookupHasStarted\) return;') `
    'the animation-frame and timer paths could launch the same lookup twice'

# --- Summary -----------------------------------------------------------------
Write-Host ("`n{0}" -f ('-' * 50))
if ($failures.Count -eq 0) {
    Write-Host ("PASS: SEO metadata validation completed. {0} checks passed." -f $checks) -ForegroundColor Green
    exit 0
}
Write-Host ("FAIL: {0} of {1} checks failed:" -f $failures.Count, $checks) -ForegroundColor Red
$failures | ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor Red }
exit 1
