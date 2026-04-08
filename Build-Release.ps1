<#
.SYNOPSIS
  Bundles the modular source files under src/ back into a single acs-domain-checker.ps1 release file.

.DESCRIPTION
  Concatenates all numbered .ps1 files in the src/ directory (sorted by filename) into the
  monolithic acs-domain-checker.ps1 that is used for distribution, Docker images, and CI/CD.

  Source files follow the naming convention NN-SectionName.ps1 (e.g. 00-Header.ps1, 01-DomainParsing.ps1).
  They are concatenated in lexicographic order so the numbering controls the output sequence.

  Run this script after editing any file under src/ to regenerate the release artifact.

.PARAMETER OutputPath
  Path for the bundled output file. Defaults to acs-domain-checker.ps1 in the repository root.

.PARAMETER Force
  Overwrite the output file without prompting.

.EXAMPLE
  # Rebuild the release file from source modules
  .\Build-Release.ps1

.EXAMPLE
  # Rebuild to a custom path
  .\Build-Release.ps1 -OutputPath ./dist/acs-domain-checker.ps1

.NOTES
  Author: Blake Drumm (blakedrumm@microsoft.com)
  This script is part of the development workflow. It is NOT needed at runtime.
#>
param(
  [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'acs-domain-checker.ps1'),
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$srcDir = Join-Path -Path $PSScriptRoot -ChildPath 'src'

if (-not (Test-Path -LiteralPath $srcDir -PathType Container)) {
  Write-Error "Source directory not found: $srcDir"
  return
}

# Collect all .ps1 files sorted by name (the NN- prefix controls order).
$sourceFiles = Get-ChildItem -Path $srcDir -Filter '*.ps1' | Sort-Object Name
if ($sourceFiles.Count -eq 0) {
  Write-Error "No .ps1 files found in $srcDir"
  return
}

# Prompt before overwriting unless -Force is specified.
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
  $answer = Read-Host "Output file already exists at '$OutputPath'. Overwrite? (y/N)"
  if ($answer -notin @('y', 'Y', 'yes', 'Yes')) {
    Write-Host 'Build cancelled.' -ForegroundColor Yellow
    return
  }
}

Write-Host "Bundling $($sourceFiles.Count) source files from $srcDir ..." -ForegroundColor Cyan

# Read and concatenate all source files.
$combined = [System.Text.StringBuilder]::new()
foreach ($file in $sourceFiles) {
  $content = [System.IO.File]::ReadAllText($file.FullName)
  $null = $combined.Append($content)
}

# Write the bundled output using UTF-8 with BOM to match the original file encoding.
$utf8Bom = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($OutputPath, $combined.ToString(), $utf8Bom)

# Extract the version from the bundled file for display.
$version = 'unknown'
$versionMatch = [regex]::Match($combined.ToString(), '\$script:AppVersion\s*=\s*''([^'']+)''')
if ($versionMatch.Success) {
  $version = $versionMatch.Groups[1].Value
}

$lineCount = ($combined.ToString() -split "`n").Count

Write-Host ''
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  Version : $version"
Write-Host "  Output  : $OutputPath"
Write-Host "  Lines   : $lineCount"
Write-Host "  Files   : $($sourceFiles.Count)"
Write-Host ''
Write-Host 'Source files included:' -ForegroundColor Cyan
foreach ($file in $sourceFiles) {
  $lines = (Get-Content -LiteralPath $file.FullName).Count
  Write-Host "  $($file.Name) ($lines lines)"
}
