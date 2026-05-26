$tokens = $null
$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'acs-domain-checker.ps1'), [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
    foreach ($e in $errs) { Write-Host ("{0}: {1}" -f $e.Extent.StartLineNumber, $e.Message) }
    exit 1
}
Write-Host 'PS parse OK'
