<#
.SYNOPSIS
  Downloads third-party UI SVG assets into the local `assets/` folder.

.DESCRIPTION
  Fetches the Lucide toolbar/status icons and the flag-icons SVG files used by the
  ACS Email Domain Checker SPA so they can be served from same-origin `/assets/*`
  paths instead of loading from public CDNs.

  By default, files are stored under:
    assets/vendor/lucide-static/icons
    assets/vendor/flag-icons/flags/4x3

.PARAMETER DestinationRoot
  Root directory that will contain the downloaded assets. Defaults to `assets`
  beneath the repository root.

.PARAMETER Force
  Re-download and overwrite existing files.

.EXAMPLE
  pwsh -NoProfile -File .\Download-UiAssets.ps1

.EXAMPLE
  pwsh -NoProfile -File .\Download-UiAssets.ps1 -Force
#>
param(
  [string]$DestinationRoot = (Join-Path -Path $PSScriptRoot -ChildPath 'assets'),
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Save-RemoteFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Uri,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [switch]$ForceDownload
  )

  $directory = Split-Path -Path $Path -Parent
  if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $directory -Force
  }

  if ((Test-Path -LiteralPath $Path) -and -not $ForceDownload) {
    Write-Host "Skipping existing file: $Path" -ForegroundColor DarkYellow
    return 'Skipped'
  }

  Write-Host "Downloading $Uri" -ForegroundColor Cyan
  Invoke-WebRequest -Uri $Uri -OutFile $Path -Headers @{ 'User-Agent' = 'ACS-UiAssetDownloader/1.0' }
  return 'Downloaded'
}

$lucideBase = 'https://cdn.jsdelivr.net/npm/lucide-static/icons'
$flagBase = 'https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/flags/4x3'

# Keep this list in sync with the icon names referenced by `UI_LABEL_ICONS` and
# the guidance/status rendering in `src/20c-HtmlJsUtilities.ps1` and `src/20d-HtmlJsCore.ps1`.
$lucideIcons = @(
  'moon-star',
  'sun',
  'link',
  'camera',
  'download',
  'bug',
  'lock-keyhole',
  'lightbulb',
  'triangle-alert',
  'info',
  'check-circle',
  'alert-circle'
)

# Keep this list in sync with `LANGUAGE_FLAG_URLS` in `src/20b-HtmlTranslations.ps1`.
$flagFiles = @(
  'us.svg',
  'es.svg',
  'fr.svg',
  'de.svg',
  'br.svg',
  'sa.svg',
  'cn.svg',
  'in.svg',
  'jp.svg',
  'ru.svg'
)

$lucideTargetRoot = Join-Path -Path $DestinationRoot -ChildPath 'vendor/lucide-static/icons'
$flagTargetRoot = Join-Path -Path $DestinationRoot -ChildPath 'vendor/flag-icons/flags/4x3'

$downloaded = 0
$skipped = 0

Write-Host ''
Write-Host 'Downloading Lucide SVG assets...' -ForegroundColor Green
foreach ($icon in $lucideIcons) {
  $uri = "$lucideBase/$icon.svg"
  $path = Join-Path -Path $lucideTargetRoot -ChildPath "$icon.svg"
  $result = Save-RemoteFile -Uri $uri -Path $path -ForceDownload:$Force
  if ($result -eq 'Downloaded') { $downloaded++ } else { $skipped++ }
}

Write-Host ''
Write-Host 'Downloading flag SVG assets...' -ForegroundColor Green
foreach ($flagFile in $flagFiles) {
  $uri = "$flagBase/$flagFile"
  $path = Join-Path -Path $flagTargetRoot -ChildPath $flagFile
  $result = Save-RemoteFile -Uri $uri -Path $path -ForceDownload:$Force
  if ($result -eq 'Downloaded') { $downloaded++ } else { $skipped++ }
}

Write-Host ''
Write-Host 'UI asset download complete.' -ForegroundColor Green
Write-Host "  DestinationRoot : $DestinationRoot"
Write-Host "  Downloaded      : $downloaded"
Write-Host "  Skipped         : $skipped"
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Run the application normally.'
Write-Host '  2. The SPA will now request icons and flags from same-origin `/assets/*` paths.'
Write-Host '  3. Re-run this script with `-Force` if you want to refresh the local copies.'
