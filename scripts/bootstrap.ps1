[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PythonExecutable = "",
    [string]$ConfigPath = "",
    [switch]$IncludeDevelopmentTools
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$virtualEnvironment = Join-Path $repositoryRoot ".venv"
$venvPython = Join-Path $virtualEnvironment "Scripts\python.exe"
$stateRoot = Join-Path $env:LOCALAPPDATA "Gatehouse\state"

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $env:APPDATA "Gatehouse\config.yaml"
} else {
    $ConfigPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigPath)
}
$configurationRoot = Split-Path -Parent $ConfigPath

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $candidate = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -eq $candidate) {
        throw "Python 3.12 or newer was not found. Pass -PythonExecutable explicitly."
    }
    $PythonExecutable = $candidate.Source
}

$version = & $PythonExecutable -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or [version]$version -lt [version]"3.12") {
    throw "Gatehouse requires Python 3.12 or newer."
}

if ($PSCmdlet.ShouldProcess($virtualEnvironment, "Create project virtual environment")) {
    & $PythonExecutable -m venv $virtualEnvironment
    if ($LASTEXITCODE -ne 0) { throw "Virtual-environment creation failed." }
}

$installTarget = if ($IncludeDevelopmentTools) { "${repositoryRoot}[dev]" } else { $repositoryRoot }
if ($PSCmdlet.ShouldProcess($repositoryRoot, "Install Gatehouse package ($installTarget)")) {
    & $venvPython -m pip install --disable-pip-version-check -e $installTarget
    if ($LASTEXITCODE -ne 0) { throw "Package installation failed." }
}

foreach ($directory in @($configurationRoot, $stateRoot)) {
    if ($PSCmdlet.ShouldProcess($directory, "Create local Gatehouse directory")) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    if ($PSCmdlet.ShouldProcess($ConfigPath, "Seed example configuration")) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot "config\config.example.yaml") -Destination $ConfigPath
    }
}

Write-Host "Gatehouse environment: $virtualEnvironment"
Write-Host "Configuration: $ConfigPath"
Write-Host "State directory: $stateRoot"
Write-Host "Validate configuration before registering scheduled tasks."
