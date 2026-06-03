#requires -Version 5.1
# Audit script: verifies every server-side PowerShell function that is reachable
# from the HTTP request-handler runspace entry point is registered in the
# $functionNames list in 22-RunspaceSetup.ps1. Reports missing registrations.
# This is a development/diagnostic tool, not part of the shipped build.

$ErrorActionPreference = 'Stop'
$srcDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'

# Only server-side PowerShell files (exclude embedded SPA JS in 20*/21*).
$psFiles = Get-ChildItem (Join-Path $srcDir '*.ps1') | Where-Object { $_.Name -notmatch '^(20|21)' }

# 1) Collect function definitions: name -> body text, plus the character span
#    of each definition so we can detect nested (inner) functions later.
$defBody = @{}
$defFile = @{}
$defSpan = @{}   # name -> [pscustomobject]@{ File; Start; End }
foreach ($f in $psFiles) {
    $raw = Get-Content $f.FullName -Raw
    # Find each "function Name" and capture body via brace matching. The matcher
    # ignores braces inside single/double-quoted strings, here-strings, and line
    # comments so SPF regex/macros (e.g. '%{i}', '{1,3}') don't desync the depth.
    foreach ($m in [regex]::Matches($raw, '(?m)^\s*function\s+([A-Za-z0-9\-]+)')) {
        $name = $m.Groups[1].Value
        $braceStart = $raw.IndexOf('{', $m.Index)
        if ($braceStart -lt 0) { continue }
        $depth = 0; $i = $braceStart; $end = -1
        $inS = $false; $inD = $false; $inComment = $false; $inHere = $false; $hereTag = $null
        for (; $i -lt $raw.Length; $i++) {
            $c = $raw[$i]
            $next = if ($i + 1 -lt $raw.Length) { $raw[$i + 1] } else { "`0" }
            if ($inComment) { if ($c -eq "`n") { $inComment = $false }; continue }
            if ($inHere) {
                # here-string terminator: newline + tag + '@
                if ($c -eq "`n") {
                    $rest = $raw.Substring($i + 1)
                    if ($rest -match ('^\s*' + [regex]::Escape($hereTag) + '@')) { $inHere = $false; $hereTag = $null }
                }
                continue
            }
            if ($inS) { if ($c -eq "'") { $inS = $false }; continue }
            if ($inD) { if ($c -eq '"') { $inD = $false }; continue }
            if ($c -eq '#') { $inComment = $true; continue }
            if (($c -eq '@') -and ($next -eq "'" -or $next -eq '"')) { $inHere = $true; $hereTag = "$next"; $i++; continue }
            if ($c -eq "'") { $inS = $true; continue }
            if ($c -eq '"') { $inD = $true; continue }
            if ($c -eq '{') { $depth++ }
            elseif ($c -eq '}') { $depth--; if ($depth -eq 0) { $end = $i; break } }
        }
        if ($end -gt $braceStart) {
            $defBody[$name] = $raw.Substring($braceStart, $end - $braceStart)
            $defFile[$name] = $f.Name
            $defSpan[$name] = [pscustomobject]@{ File = $f.Name; Start = $m.Index; End = $end }
        }
    }
}

# Identify nested functions: a function whose definition start falls inside the
# brace-body span of a different function in the same file. Nested functions are
# copied into runspaces together with their parent, so they don't need their own
# entry in $functionNames.
$nested = New-Object System.Collections.Generic.HashSet[string]
foreach ($name in $defSpan.Keys) {
    $s = $defSpan[$name]
    foreach ($other in $defSpan.Keys) {
        if ($other -eq $name) { continue }
        $o = $defSpan[$other]
        if ($o.File -eq $s.File -and $s.Start -gt $o.Start -and $s.Start -lt $o.End) {
            [void]$nested.Add($name); break
        }
    }
}

$allNames = $defBody.Keys

# 2) Helper: strip line comments and quoted strings so call detection only
#    matches real invocations (not function names mentioned in comments/docs).
function Remove-CommentsAndStrings {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    $inS = $false; $inD = $false; $inComment = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($inComment) { if ($c -eq "`n") { $inComment = $false; [void]$sb.Append($c) }; continue }
        if ($inS) { if ($c -eq "'") { $inS = $false }; continue }
        if ($inD) { if ($c -eq '"') { $inD = $false }; continue }
        if ($c -eq '#') { $inComment = $true; continue }
        if ($c -eq "'") { $inS = $true; continue }
        if ($c -eq '"') { $inD = $true; continue }
        [void]$sb.Append($c)
    }
    return $sb.ToString()
}

# 3) Helper: find which defined functions a body calls.
function Get-Calls {
    param([string]$Body, $Names)
    $clean = Remove-CommentsAndStrings -Text $Body
    $found = New-Object System.Collections.Generic.HashSet[string]
    foreach ($n in $Names) {
        # Word-boundary match for the command name. Escape hyphens.
        if ([regex]::IsMatch($clean, '(?<![A-Za-z0-9\-\.])' + [regex]::Escape($n) + '(?![A-Za-z0-9\-])')) {
            [void]$found.Add($n)
        }
    }
    return $found
}

# 3) Determine entry points: functions invoked from the handler script body
#    plus Get-DomainSemaphore (defined inline in the handler).
$handlerRaw = Get-Content (Join-Path $srcDir '23-RequestHandler.ps1') -Raw
$hStart = $handlerRaw.IndexOf("@'")
$hEnd = $handlerRaw.IndexOf("'@", $hStart)
$handlerBody = $handlerRaw.Substring($hStart, $hEnd - $hStart)

$entry = Get-Calls -Body $handlerBody -Names $allNames

# 4) Transitive closure.
$reachable = New-Object System.Collections.Generic.HashSet[string]
$queue = New-Object System.Collections.Generic.Queue[string]
foreach ($e in $entry) { if ($reachable.Add($e)) { $queue.Enqueue($e) } }
while ($queue.Count -gt 0) {
    $cur = $queue.Dequeue()
    if (-not $defBody.ContainsKey($cur)) { continue }
    $calls = Get-Calls -Body $defBody[$cur] -Names $allNames
    foreach ($c in $calls) { if ($reachable.Add($c)) { $queue.Enqueue($c) } }
}

# 5) Parse the registered $functionNames list from 22-RunspaceSetup.ps1.
$runspaceRaw = Get-Content (Join-Path $srcDir '22-RunspaceSetup.ps1') -Raw
$listMatch = [regex]::Match($runspaceRaw, '\$functionNames\s*=\s*@\((?<body>[\s\S]*?)\)')
$registered = New-Object System.Collections.Generic.HashSet[string]
foreach ($q in [regex]::Matches($listMatch.Groups['body'].Value, "'([^']+)'")) {
    [void]$registered.Add($q.Groups[1].Value)
}

# Functions defined inline in the handler script don't need registration.
$inlineHandler = @('Get-DomainSemaphore')

# 6) Report.
Write-Host "=== Runspace Function Registration Audit ===" -ForegroundColor Cyan
Write-Host ("Server-side functions defined : {0}" -f $allNames.Count)
Write-Host ("Reachable from handler        : {0}" -f $reachable.Count)
Write-Host ("Registered in `$functionNames  : {0}" -f $registered.Count)
Write-Host ""

$missing = @()
foreach ($r in ($reachable | Sort-Object)) {
    if ($inlineHandler -contains $r) { continue }
    if ($nested.Contains($r)) { continue }   # nested funcs travel with their parent
    if (-not $registered.Contains($r)) { $missing += $r }
}

if ($missing.Count -eq 0) {
    Write-Host "PASS: All reachable functions are registered." -ForegroundColor Green
} else {
    Write-Host "MISSING REGISTRATIONS (reachable but NOT in `$functionNames):" -ForegroundColor Red
    foreach ($m in $missing) { Write-Host ("  {0}  <-- {1}" -f $m, $defFile[$m]) -ForegroundColor Yellow }
}

Write-Host ""
# 7) Also report registered-but-not-defined (stale entries / typos).
$stale = @()
foreach ($r in ($registered | Sort-Object)) {
    if (-not $defBody.ContainsKey($r)) { $stale += $r }
}
if ($stale.Count -gt 0) {
    Write-Host "REGISTERED BUT NOT DEFINED (possible typo / platform-specific):" -ForegroundColor Magenta
    foreach ($s in $stale) { Write-Host ("  {0}" -f $s) }
}
