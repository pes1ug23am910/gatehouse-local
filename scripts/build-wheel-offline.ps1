[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Wheelhouse,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string]$BuildEnvironment = "",
    [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$requirementsFile = Join-Path $repositoryRoot "requirements\build-wheel.txt"
$expectedWheelName = "gatehouse_local-0.0.1-py3-none-any.whl"

if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
    throw "Wheelhouse does not exist or is not a directory: $Wheelhouse"
}
$resolvedWheelhouse = (Resolve-Path -LiteralPath $Wheelhouse).Path
$resolvedOutputDirectory =
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)

if ([string]::IsNullOrWhiteSpace($BuildEnvironment)) {
    $BuildEnvironment = Join-Path $repositoryRoot ".local\offline-build-venv"
}
$resolvedBuildEnvironment =
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BuildEnvironment)

if (Test-Path -LiteralPath $resolvedBuildEnvironment) {
    throw "Build environment already exists; refusing to reuse or overwrite it: $resolvedBuildEnvironment"
}

$pathComparer = [StringComparer]::OrdinalIgnoreCase
if ($pathComparer.Equals($resolvedWheelhouse, $resolvedOutputDirectory)) {
    throw "Wheelhouse and output directory must be different paths."
}
if ($pathComparer.Equals($resolvedWheelhouse, $resolvedBuildEnvironment)) {
    throw "Wheelhouse and build environment must be different paths."
}
if ($pathComparer.Equals($resolvedOutputDirectory, $resolvedBuildEnvironment)) {
    throw "Output directory and build environment must be different paths."
}

$expectedArtifact = Join-Path $resolvedOutputDirectory $expectedWheelName
if (Test-Path -LiteralPath $expectedArtifact) {
    throw "Output artifact already exists; refusing to overwrite it: $expectedArtifact"
}
if (-not (Test-Path -LiteralPath $requirementsFile -PathType Leaf)) {
    throw "Locked build requirements are missing: $requirementsFile"
}

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $pythonCommand) {
        throw "Python 3.12 or newer was not found. Pass -PythonExecutable explicitly."
    }
} else {
    $pythonCommand = Get-Command $PythonExecutable -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
}
$PythonExecutable = $pythonCommand.Source

$operation = "Create an offline build environment and build $expectedWheelName"
if (-not $PSCmdlet.ShouldProcess($resolvedBuildEnvironment, $operation)) {
    Write-Host "WhatIf: no environment, package, or wheel was changed."
    return
}

$version = & $PythonExecutable -I -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or [version]$version -lt [version]"3.12") {
    throw "Gatehouse requires Python 3.12 or newer."
}

& $PythonExecutable -I -m venv $resolvedBuildEnvironment
if ($LASTEXITCODE -ne 0) {
    throw "Offline build-environment creation failed."
}

$buildPython = Join-Path $resolvedBuildEnvironment "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $buildPython -PathType Leaf)) {
    throw "Build-environment Python was not created: $buildPython"
}

$pipEnvironmentNames = @(
    "PIP_CONFIG_FILE",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "PIP_INDEX_URL",
    "PIP_NO_INDEX",
    "PIP_ONLY_BINARY",
    "PIP_REQUIRE_HASHES"
)
$savedPipEnvironment = @{}
foreach ($name in $pipEnvironmentNames) {
    $savedPipEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    [Environment]::SetEnvironmentVariable("PIP_CONFIG_FILE", "NUL", "Process")
    [Environment]::SetEnvironmentVariable("PIP_DISABLE_PIP_VERSION_CHECK", "1", "Process")
    [Environment]::SetEnvironmentVariable("PIP_EXTRA_INDEX_URL", $null, "Process")
    [Environment]::SetEnvironmentVariable("PIP_FIND_LINKS", $resolvedWheelhouse, "Process")
    [Environment]::SetEnvironmentVariable("PIP_INDEX_URL", $null, "Process")
    [Environment]::SetEnvironmentVariable("PIP_NO_INDEX", "1", "Process")
    [Environment]::SetEnvironmentVariable("PIP_ONLY_BINARY", ":all:", "Process")
    [Environment]::SetEnvironmentVariable("PIP_REQUIRE_HASHES", "1", "Process")

    & $buildPython -I -m pip `
        --isolated `
        --disable-pip-version-check `
        --no-cache-dir `
        install `
        --no-index `
        "--only-binary=:all:" `
        --require-hashes `
        --find-links $resolvedWheelhouse `
        --requirement $requirementsFile
    if ($LASTEXITCODE -ne 0) {
        throw "Hash-locked offline build-dependency installation failed."
    }

    & $buildPython -I -m build `
        --wheel `
        --no-isolation `
        --outdir $resolvedOutputDirectory `
        $repositoryRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Standard no-isolation wheel build failed."
    }
} finally {
    foreach ($name in $pipEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedPipEnvironment[$name], "Process")
    }
}

if (-not (Test-Path -LiteralPath $expectedArtifact -PathType Leaf)) {
    throw "Build reported success but the expected artifact is missing: $expectedArtifact"
}

$artifact = Get-Item -LiteralPath $expectedArtifact
$artifactHash = (Get-FileHash -LiteralPath $expectedArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Offline wheel: $($artifact.FullName)"
Write-Host "Size: $($artifact.Length) bytes"
Write-Host "SHA-256: $artifactHash"
