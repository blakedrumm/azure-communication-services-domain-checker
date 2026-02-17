<#
.SYNOPSIS
  Builds and releases limitlessworlds/acs-domain-checker for Linux + Windows and publishes multi-arch tags.

.DESCRIPTION
  - Extracts version from acs-domain-checker.ps1 by parsing: "$script:AppVersion = 'X.Y.Z'"
  - Builds Linux image from Dockerfile.linux (linux/amd64)
  - Switches engine to Windows, builds Windows image from Dockerfile.windows (windows/amd64)
  - Publishes multi-arch tags using docker buildx imagetools create
  - Validates Docker Desktop is running and Docker Hub credentials are configured
  - Supports -DryRun (no pushes, no tag updates)
  - Always switches Docker engine back to Linux at end (even on failure)

.PARAMETER Version
  Optional override. If not provided, version is extracted from acs-domain-checker.ps1.

.PARAMETER ScriptPath
  Path to the PowerShell script that contains the version assignment.

.PARAMETER DryRun
  If set, performs validation + builds but does NOT push images or update tags in Docker Hub.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidatePattern('^\d+\.\d+\.\d+([\-+].+)?$')]
  [string]$Version,

  [Parameter(Mandatory = $false)]
  [string]$ScriptPath = ".\acs-domain-checker.ps1",

  [Parameter(Mandatory = $false)]
  [string]$WindowsBaseTag = "nanoserver-ltsc2022",

  [switch]$DryRun
)

# =========================
# Variables
# =========================
$Repo = "limitlessworlds/acs-domain-checker"

# =========================
# Helpers
# =========================
function Invoke-Docker {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$IgnoreExitCode
  )

  $display = "docker " + ($Arguments -join " ")
  Write-Output $display

  $output = & docker @Arguments 2>&1
  $exit = $LASTEXITCODE

  if ($output) { $output | Write-Output }

  if (-not $IgnoreExitCode -and $exit -ne 0) {
    throw "Command failed (exit $exit): $display"
  }

  return [pscustomobject]@{
    ExitCode = $exit
    Output   = $output
  }
}

function Assert-DockerEngine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('linux','windows')]
    [string]$Expected
  )

  $osType = (& docker info --format '{{.OSType}}' 2>$null).Trim()
  if (-not $osType) { throw "Unable to determine Docker OSType." }

  if ($osType -ne $Expected) {
    $context = (& docker context show 2>$null)
    $builder = (& docker buildx ls 2>$null | Select-Object -First 20)
    throw @(
      "Docker engine mismatch. Expected OSType='$Expected' but got '$osType'.",
      "Active docker context: $context",
      "Buildx builders (first lines):",
      ($builder -join "`n")
    ) -join "`n"
  }
}

function Start-DockerDesktopBestEffort {
  [CmdletBinding()]
  param()

  # 1) Start Docker Windows service if present
  try {
    $svc = Get-Service -Name "com.docker.service" -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
      Write-Output "Docker service 'com.docker.service' is $($svc.Status). Attempting to start..."
      try {
        Start-Service -Name "com.docker.service" -ErrorAction Stop
        Write-Output "Start-Service issued for 'com.docker.service'."
      }
      catch {
        Write-Output "Warning: failed to start 'com.docker.service'. Error: $($_.Exception.Message)"
      }
    }
  }
  catch {
    # Not fatal; some environments may not have the service visible (or Docker isn't installed)
    Write-Output "Note: Docker service 'com.docker.service' not found or not accessible."
  }

  # 2) Start Docker Desktop UI if installed and not running
  try {
    $desktopProc = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
    if (-not $desktopProc) {
      $desktopExeCandidates = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LocalAppData "Programs\Docker\Docker\Docker Desktop.exe")
      ) | Where-Object { $_ -and (Test-Path $_) }

      $desktopExe = $desktopExeCandidates | Select-Object -First 1
      if ($desktopExe) {
        Write-Output "Docker Desktop process not detected. Attempting to start: $desktopExe"
        try {
          Start-Process -FilePath $desktopExe -ErrorAction Stop | Out-Null
        }
        catch {
          Write-Output "Warning: failed to start Docker Desktop. Error: $($_.Exception.Message)"
        }
      }
      else {
        Write-Output "Note: Docker Desktop executable not found in common locations."
      }
    }
  }
  catch {
    Write-Output "Warning: could not evaluate/start Docker Desktop process. Error: $($_.Exception.Message)"
  }
}

function Wait-DockerDaemon {
  [CmdletBinding()]
  param(
    [int]$TimeoutSeconds = 90,
    [int]$PollSeconds = 2
  )

  Write-Output "Checking Docker daemon availability..."
  Start-DockerDesktopBestEffort

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $lastErr = $null

  while ((Get-Date) -lt $deadline) {
    # docker info is a solid daemon-reachability check
    $r = Invoke-Docker -Arguments @("info") -IgnoreExitCode
    if ($r.ExitCode -eq 0) {
      Write-Output "Docker daemon is reachable."
      return
    }

    $lastErr = ($r.Output | Select-Object -Last 1)
    Start-Sleep -Seconds $PollSeconds
  }

  $hint = @(
    "Docker daemon did not become available within $TimeoutSeconds seconds.",
    "Make sure Docker Desktop is running and the engine is started.",
    "If you are using WSL2 backend, ensure WSL is installed and 'Use the WSL 2 based engine' is enabled in Docker Desktop."
  ) -join " "

  if ($lastErr) {
    throw "$hint Last docker output: $lastErr"
  }

  throw $hint
}

function Switch-DockerEngine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('linux','windows')]
    [string]$To
  )

  $cli = Join-Path $Env:ProgramFiles "Docker\Docker\DockerCli.exe"
  if (-not (Test-Path $cli)) {
    throw "DockerCli.exe not found at: $cli"
  }

  if ($To -eq 'windows') {
    Write-Output "Switching Docker Desktop to Windows engine..."
    & $cli -SwitchWindowsEngine | Out-Null
  } else {
    Write-Output "Switching Docker Desktop to Linux engine..."
    & $cli -SwitchLinuxEngine | Out-Null
  }

  Start-Sleep -Seconds 3

  $osType = (& docker info --format '{{.OSType}}' 2>$null).Trim()
  if ($osType -ne $To) {
    throw "Docker engine switch failed. Expected OSType='$To' but got '$osType'."
  }

  Write-Output "Docker engine is now: $osType"
}

function Get-DockerConfigPath {
  if (-not [string]::IsNullOrWhiteSpace($env:DOCKER_CONFIG)) {
    return (Join-Path $env:DOCKER_CONFIG "config.json")
  }
  return (Join-Path $env:USERPROFILE ".docker\config.json")
}

function Test-DockerHubLoginConfigured {
  [CmdletBinding()]
  param()

  $cfgPath = Get-DockerConfigPath

  if (-not (Test-Path $cfgPath)) {
    return [pscustomobject]@{
      IsLoggedIn = $false
      Reason     = "Docker config.json not found at '$cfgPath'. Run 'docker login' first."
      Path       = $cfgPath
    }
  }

  try {
    $raw = Get-Content -Path $cfgPath -Raw -ErrorAction Stop
    $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
  }
  catch {
    return [pscustomobject]@{
      IsLoggedIn = $false
      Reason     = "Failed to read/parse Docker config.json at '$cfgPath'. Error: $($_.Exception.Message)"
      Path       = $cfgPath
    }
  }

  $hasCredsStore  = -not [string]::IsNullOrWhiteSpace($cfg.credsStore)
  $hasCredHelpers = $false
  if ($cfg.PSObject.Properties.Name -contains 'credHelpers' -and $cfg.credHelpers) {
    $hasCredHelpers = ($cfg.credHelpers.PSObject.Properties.Count -gt 0)
  }

  $auths = $null
  if ($cfg.PSObject.Properties.Name -contains 'auths') { $auths = $cfg.auths }

  $dockerIoKeys = @(
    "https://index.docker.io/v1/",
    "https://registry-1.docker.io/v2/",
    "docker.io",
    "registry-1.docker.io"
  )

  $hasDockerIoAuth = $false
  if ($auths) {
    foreach ($k in $dockerIoKeys) {
      if ($auths.PSObject.Properties.Name -contains $k) {
        $entry = $auths.$k
        if ($entry -and ($entry.auth -or $entry.identitytoken)) {
          $hasDockerIoAuth = $true
          break
        }
      }
    }
  }

  if ($hasDockerIoAuth -or $hasCredsStore -or $hasCredHelpers) {
    $method = @()
    if ($hasDockerIoAuth) { $method += "auths" }
    if ($hasCredsStore)   { $method += "credsStore=$($cfg.credsStore)" }
    if ($hasCredHelpers)  { $method += "credHelpers" }

    return [pscustomobject]@{
      IsLoggedIn = $true
      Reason     = "Docker credentials appear configured via: $($method -join ', ')."
      Path       = $cfgPath
    }
  }

  return [pscustomobject]@{
    IsLoggedIn = $false
    Reason     = "No Docker Hub credentials found in config.json (no auths entry and no credsStore/credHelpers). Run 'docker login'."
    Path       = $cfgPath
  }
}

function Get-VersionFromScript {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path
  )

  if (-not (Test-Path $Path)) {
    throw "ScriptPath not found: $Path"
  }

  $content = Get-Content -Path $Path -Raw -ErrorAction Stop

  # Matches: $script:AppVersion = '1.0.3' (also supports -beta.1, etc.)
  $pattern = '\$script:AppVersion\s*=\s*["\''](?<ver>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z\.\-]+)?)["\'']'
  $m = [regex]::Match($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

  if (-not $m.Success) {
    throw "Unable to extract version from '$Path'. Expected text like: `$script:AppVersion = '1.0.3'"
  }

  return $m.Groups['ver'].Value
}

function Assert-RemoteTagExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ImageRef
  )

  Write-Output "Verifying remote tag exists: $ImageRef"
  Invoke-Docker -Arguments @("buildx","imagetools","inspect",$ImageRef) | Out-Null
}

# =========================
# Resolve Version
# =========================
if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = Get-VersionFromScript -Path $ScriptPath
  Write-Output "Resolved version from '$ScriptPath': $Version"
} else {
  Write-Output "Using provided version: $Version"
}

$LinuxTag  = "linux-$Version"
$WinTag    = "windows-$Version"
$VerTag    = $Version
$LatestTag = "latest"

# =========================
# Main
# =========================
try {
  # Docker running (ensure + wait)?
  Wait-DockerDaemon -TimeoutSeconds 90 -PollSeconds 2

  $startedInOsType = (& docker info --format '{{.OSType}}' 2>$null).Trim()
  if (-not $startedInOsType) { throw "Unable to determine Docker OSType." }
  Write-Output "Starting Docker engine: $startedInOsType"

  # Docker login?
  $loginCheck = Test-DockerHubLoginConfigured
  Write-Output "Docker config path: $($loginCheck.Path)"
  Write-Output $loginCheck.Reason

  if (-not $DryRun -and -not $loginCheck.IsLoggedIn) {
    throw "Docker Hub login does not appear configured. Run 'docker login' and retry."
  }

  # Dockerfiles?
  if (-not (Test-Path -Path ".\Dockerfile.linux"))   { throw "Dockerfile.linux not found in current directory." }
  if (-not (Test-Path -Path ".\Dockerfile.windows")) { throw "Dockerfile.windows not found in current directory." }

  # Script file present? (so Dockerfile COPY succeeds)
  if (-not (Test-Path -Path $ScriptPath)) {
    throw "ScriptPath not found (needed for Docker build context): $ScriptPath"
  }

  # 1) Linux build
  Write-Output "Building $Repo`:$LinuxTag (linux/amd64) from Dockerfile.linux..."

  # Ensure we're on Linux engine before using the desktop-linux buildx instance.
  Assert-DockerEngine -Expected linux

  if ($DryRun) {
    Invoke-Docker -Arguments @(
      "buildx","build",
      "-f",".\Dockerfile.linux",
      "--platform","linux/amd64",
      "-t","$Repo`:$LinuxTag",
      "--load",
      "."
    ) | Out-Null
  }
  else {
    Invoke-Docker -Arguments @(
      "buildx","build",
      "-f",".\Dockerfile.linux",
      "--platform","linux/amd64",
      "-t","$Repo`:$LinuxTag",
      "--push",
      "."
    ) | Out-Null
  }

  # 2) Windows build
  Switch-DockerEngine -To windows

  # Ensure engine switch actually took effect before attempting a Windows build.
  Assert-DockerEngine -Expected windows

  Write-Output "Building $Repo`:$WinTag (windows/amd64) from Dockerfile.windows..."
  $prevBuildkit = $env:DOCKER_BUILDKIT
  $env:DOCKER_BUILDKIT = '0'
  Invoke-Docker -Arguments @(
    "build",
    "-f",".\Dockerfile.windows",
    "--build-arg","WINDOWS_BASE_TAG=$WindowsBaseTag",
    "-t","$Repo`:$WinTag",
    "."
  ) | Out-Null
  if ($null -eq $prevBuildkit) {
    Remove-Item Env:DOCKER_BUILDKIT -ErrorAction SilentlyContinue
  } else {
    $env:DOCKER_BUILDKIT = $prevBuildkit
  }

  if (-not $DryRun) {
    Write-Output "Pushing $Repo`:$WinTag..."
    Invoke-Docker -Arguments @("push","$Repo`:$WinTag") | Out-Null
  } else {
    Write-Output "DryRun enabled: skipping push of $Repo`:$WinTag."
  }

  # 3) Switch back to Linux engine before registry tag operations
  Switch-DockerEngine -To linux

  # 4) Multi-arch tags (preferred)
  if (-not $DryRun) {
    Assert-RemoteTagExists -ImageRef "$Repo`:$LinuxTag"
    Assert-RemoteTagExists -ImageRef "$Repo`:$WinTag"

    Write-Output "Creating multi-arch tag: $Repo`:$VerTag"
    Invoke-Docker -Arguments @(
      "buildx","imagetools","create",
      "-t","$Repo`:$VerTag",
      "$Repo`:$LinuxTag",
      "$Repo`:$WinTag"
    ) | Out-Null

    Write-Output "Creating/updating multi-arch tag: $Repo`:$LatestTag"
    Invoke-Docker -Arguments @(
      "buildx","imagetools","create",
      "-t","$Repo`:$LatestTag",
      "$Repo`:$LinuxTag",
      "$Repo`:$WinTag"
    ) | Out-Null

    Write-Output "Verifying multi-arch tags in registry..."
    Invoke-Docker -Arguments @("buildx","imagetools","inspect","$Repo`:$VerTag") | Out-Null
    Invoke-Docker -Arguments @("buildx","imagetools","inspect","$Repo`:$LatestTag") | Out-Null
  }
  else {
    Write-Output "DryRun enabled: skipping remote tag verification and multi-arch tag creation."
    Write-Output "Local validation complete (Linux build + Windows build succeeded)."
  }

  Write-Output "Release $Version completed."
}
finally {
  try {
    Write-Output "Switching Docker engine back to Linux (requested)..."
    Switch-DockerEngine -To linux
  }
  catch {
    Write-Output "Warning: failed to switch Docker engine back to Linux. Error: $($_.Exception.Message)"
  }
}
