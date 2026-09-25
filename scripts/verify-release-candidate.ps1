[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateWheel,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$RuntimeWheelhouse,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CleanEnvironment,

    [string]$EvidenceDirectory = "",
    [string]$SourceTestPython = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$privateEvidenceRoot = Join-Path $repositoryRoot ".local\release-evidence"
$wheelhouseManifestPath = Join-Path $repositoryRoot "requirements\runtime-wheelhouse.json"
$vulnerabilitySnapshotPath = Join-Path $repositoryRoot "requirements\osv-runtime-snapshot.json"

function Resolve-UncreatedPath {
    param([Parameter(Mandatory)][string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Test-PathInside {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Parent
    )
    $comparer = [StringComparer]::OrdinalIgnoreCase
    $prefix = "$Parent$([System.IO.Path]::DirectorySeparatorChar)"
    return $comparer.Equals($Candidate, $Parent) -or $Candidate.StartsWith(
        $prefix,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    try {
        $cursor = [System.IO.Path]::GetFullPath($Path)
    } catch {
        throw "$Label path is invalid."
    }
    while ($true) {
        try {
            $exists = Test-Path -LiteralPath $cursor -ErrorAction Stop
        } catch {
            throw "$Label path ancestry could not be inspected."
        }
        if ($exists) {
            break
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            throw "$Label path has no existing filesystem ancestor."
        }
        $cursor = $parent.FullName
    }
    while ($null -ne $cursor) {
        try {
            $attributes = [System.IO.File]::GetAttributes($cursor)
        } catch {
            throw "$Label path ancestry could not be inspected."
        }
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label path ancestry contains a reparse point."
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        $cursor = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label
    )
    $output = & $Executable @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed."
    }
    return (($output | Out-String).Trim())
}

function Write-NewUtf8File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-NoReparsePoint -Path $Path -Label $Label
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $payload = $encoding.GetBytes($Content)
    $stream = $null
    $created = $false
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $created = $true
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush($true)
    } catch {
        if ($null -ne $stream) {
            $stream.Dispose()
            $stream = $null
        }
        if ($created) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
        throw "$Label could not be written create-only."
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "$Label changed during release verification."
    }
}

function Assert-WheelhouseState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Expected
    )
    $current = @(
        Get-ChildItem -LiteralPath $Path -Force |
            Sort-Object Name
    )
    if ($current.Count -ne $Expected.Count) {
        throw "Runtime wheelhouse changed during release verification."
    }
    for ($index = 0; $index -lt $Expected.Count; $index += 1) {
        $item = $current[$index]
        $reviewed = $Expected[$index]
        if (
            -not $item.PSIsContainer -and
            $item.Name -ceq $reviewed.name -and
            $item.Length -eq $reviewed.size_bytes
        ) {
            Assert-FileSha256 `
                -Path $item.FullName `
                -Expected $reviewed.sha256 `
                -Label "Runtime wheel $($item.Name)"
            continue
        }
        throw "Runtime wheelhouse changed during release verification."
    }
}

function Get-GatehouseTaskState {
    $states = foreach ($taskName in @("Gatehouse Daemon", "Gatehouse Watchdog")) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            [ordered]@{
                name = $task.TaskName
                state = [string]$task.State
            }
        }
    }
    return @($states)
}

if (-not (Test-Path -LiteralPath $CandidateWheel -PathType Leaf)) {
    throw "Candidate wheel does not exist: $CandidateWheel"
}
if (-not (Test-Path -LiteralPath $RuntimeWheelhouse -PathType Container)) {
    throw "Runtime wheelhouse does not exist: $RuntimeWheelhouse"
}

$resolvedCandidateWheel = (Resolve-Path -LiteralPath $CandidateWheel).Path
$resolvedRuntimeWheelhouse = (Resolve-Path -LiteralPath $RuntimeWheelhouse).Path
$resolvedCleanEnvironment = Resolve-UncreatedPath -Path $CleanEnvironment
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $evidenceName = "{0}-{1}" -f (
        [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssZ")
    ), [Guid]::NewGuid().ToString("N")
    $EvidenceDirectory = Join-Path $privateEvidenceRoot $evidenceName
}
$resolvedEvidenceDirectory = Resolve-UncreatedPath -Path $EvidenceDirectory

foreach ($pathCheck in @(
    @{ path = $resolvedCandidateWheel; label = "Candidate wheel" },
    @{ path = $resolvedRuntimeWheelhouse; label = "Runtime wheelhouse" },
    @{ path = $resolvedCleanEnvironment; label = "Clean release environment" },
    @{ path = $resolvedEvidenceDirectory; label = "Release evidence" }
)) {
    Assert-NoReparsePoint -Path $pathCheck.path -Label $pathCheck.label
}

if (Test-PathInside -Candidate $resolvedCandidateWheel -Parent $repositoryRoot) {
    throw "Candidate wheel must be outside the repository checkout."
}
if (Test-PathInside -Candidate $resolvedRuntimeWheelhouse -Parent $repositoryRoot) {
    throw "Runtime wheelhouse must be outside the repository checkout."
}
if (Test-PathInside -Candidate $resolvedCleanEnvironment -Parent $repositoryRoot) {
    throw "Clean release environment must be outside the repository checkout."
}
if (-not (Test-PathInside -Candidate $resolvedEvidenceDirectory -Parent $privateEvidenceRoot)) {
    throw "Release evidence must stay under the ignored .local\release-evidence directory."
}
if (Test-Path -LiteralPath $resolvedCleanEnvironment) {
    throw "Clean release environment already exists; refusing to reuse it."
}
if (Test-Path -LiteralPath $resolvedEvidenceDirectory) {
    throw "Evidence directory already exists; refusing to overwrite it."
}

$pathComparer = [StringComparer]::OrdinalIgnoreCase
foreach ($pair in @(
    @($resolvedCandidateWheel, $resolvedRuntimeWheelhouse),
    @($resolvedCandidateWheel, $resolvedCleanEnvironment),
    @($resolvedRuntimeWheelhouse, $resolvedCleanEnvironment)
)) {
    if ($pathComparer.Equals($pair[0], $pair[1])) {
        throw "Candidate, wheelhouse, and clean-environment paths must be distinct."
    }
}

$runtimeWheels = @(Get-ChildItem -LiteralPath $resolvedRuntimeWheelhouse -File -Filter "*.whl")
if ($runtimeWheels.Count -lt 1 -or $runtimeWheels.Count -gt 512) {
    throw "Runtime wheelhouse must contain between 1 and 512 wheel files."
}
foreach ($wheel in $runtimeWheels) {
    if ($wheel.Length -gt 256MB) {
        throw "Runtime wheel exceeds the 256 MiB evidence ceiling: $($wheel.Name)"
    }
}
$candidateItem = Get-Item -LiteralPath $resolvedCandidateWheel
$candidateSizeBytes = $candidateItem.Length
$candidateSha256 = (
    Get-FileHash -LiteralPath $resolvedCandidateWheel -Algorithm SHA256
).Hash.ToLowerInvariant()
$runtimeWheelhouseState = @(
    foreach ($wheel in $runtimeWheels | Sort-Object Name) {
        [ordered]@{
            name = $wheel.Name
            size_bytes = $wheel.Length
            sha256 = (
                Get-FileHash -LiteralPath $wheel.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
    }
)

if ([string]::IsNullOrWhiteSpace($SourceTestPython)) {
    $SourceTestPython = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
}
$sourcePythonCommand = Get-Command $SourceTestPython -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
$SourceTestPython = $sourcePythonCommand.Source
$runtimePythonMinor = Invoke-Captured -Executable $SourceTestPython -Arguments @(
    "-I", "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
) -Label "Release Python minor resolution"
$runtimePythonFullVersion = Invoke-Captured -Executable $SourceTestPython -Arguments @(
    "-I", "-c", "import platform; print(platform.python_version())"
) -Label "Release Python full-version resolution"
if ($runtimePythonMinor -notin @("3.12", "3.13", "3.14")) {
    throw "Release Python minor is outside the reviewed runtime-lock set."
}
if (-not $runtimePythonFullVersion.StartsWith("$runtimePythonMinor.", [StringComparison]::Ordinal)) {
    throw "Release Python full version differs from its reviewed minor."
}
$runtimeLockName = "runtime-py$($runtimePythonMinor.Replace('.', '')).txt"
$runtimeLockPath = Join-Path $repositoryRoot "requirements\$runtimeLockName"
foreach ($supplyChainInput in @(
    @{ path = $runtimeLockPath; label = "Runtime dependency lock" },
    @{ path = $wheelhouseManifestPath; label = "Runtime wheelhouse manifest" },
    @{ path = $vulnerabilitySnapshotPath; label = "Vulnerability snapshot" }
)) {
    if (-not (Test-Path -LiteralPath $supplyChainInput.path -PathType Leaf)) {
        throw "$($supplyChainInput.label) is unavailable."
    }
    Assert-NoReparsePoint -Path $supplyChainInput.path -Label $supplyChainInput.label
}

Push-Location $repositoryRoot
try {
    $head = Invoke-Captured -Executable "git" -Arguments @(
        "-c", "core.excludesFile=/dev/null", "rev-parse", "HEAD"
    ) -Label "Git HEAD resolution"
    $status = Invoke-Captured -Executable "git" -Arguments @(
        "-c", "core.excludesFile=/dev/null", "status", "--porcelain", "--untracked-files=all"
    ) -Label "Git status inspection"
    if (-not [string]::IsNullOrWhiteSpace($status)) {
        throw "Release evidence requires a clean source checkout."
    }
    & git -c "core.excludesFile=/dev/null" diff --check
    if ($LASTEXITCODE -ne 0) {
        throw "Git whitespace/conflict-marker validation failed."
    }

    $operation = "Create a clean offline installation and private release evidence"
    if (-not $PSCmdlet.ShouldProcess($resolvedCleanEnvironment, $operation)) {
        Write-Host "WhatIf: no environment or evidence was created."
        return
    }

    New-Item -ItemType Directory -Path $resolvedEvidenceDirectory -Force:$false | Out-Null

    $wheelAuditPath = Join-Path $resolvedEvidenceDirectory "wheel-audit.json"
    Invoke-Captured -Executable $SourceTestPython -Arguments @(
        "-I",
        (Join-Path $repositoryRoot "scripts\audit_release_wheel.py"),
        $resolvedCandidateWheel,
        "--repository-root",
        $repositoryRoot,
        "--output",
        $wheelAuditPath
    ) -Label "Wheel audit" | Out-Null
    $wheelAudit = Get-Content -LiteralPath $wheelAuditPath -Raw -Encoding utf8 | ConvertFrom-Json
    if (
        [string]$wheelAudit.sha256 -cne $candidateSha256 -or
        [long]$wheelAudit.size_bytes -ne $candidateSizeBytes
    ) {
        throw "Wheel audit evidence differs from the selected candidate."
    }
    Assert-FileSha256 `
        -Path $resolvedCandidateWheel `
        -Expected $candidateSha256 `
        -Label "Candidate wheel"

    $hygienePath = Join-Path $resolvedEvidenceDirectory "publication-hygiene.json"
    Invoke-Captured -Executable $SourceTestPython -Arguments @(
        "-I",
        (Join-Path $repositoryRoot "scripts\check_publication_hygiene.py"),
        "--repository-root",
        $repositoryRoot,
        "--output",
        $hygienePath
    ) -Label "Publication hygiene check" | Out-Null

    $sbomPath = Join-Path $resolvedEvidenceDirectory "gatehouse.cdx.json"
    $supplyChainPath = Join-Path $resolvedEvidenceDirectory "supply-chain.json"
    Invoke-Captured -Executable $SourceTestPython -Arguments @(
        "-I",
        (Join-Path $repositoryRoot "scripts\verify_release_supply_chain.py"),
        "--repository-root", $repositoryRoot,
        "--candidate-wheel", $resolvedCandidateWheel,
        "--wheelhouse", $resolvedRuntimeWheelhouse,
        "--runtime-lock", $runtimeLockPath,
        "--wheelhouse-manifest", $wheelhouseManifestPath,
        "--vulnerability-snapshot", $vulnerabilitySnapshotPath,
        "--python-minor", $runtimePythonMinor,
        "--python-full-version", $runtimePythonFullVersion,
        "--sbom-output", $sbomPath,
        "--output", $supplyChainPath
    ) -Label "Offline release supply-chain gate" | Out-Null
    $supplyChainEvidence = Get-Content -LiteralPath $supplyChainPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    if (
        [string]$supplyChainEvidence.candidate_sha256 -cne $candidateSha256 -or
        [string]$supplyChainEvidence.python_full_version -cne $runtimePythonFullVersion
    ) {
        throw "Supply-chain evidence differs from the selected candidate or Python runtime."
    }
    Assert-FileSha256 `
        -Path $resolvedCandidateWheel `
        -Expected $candidateSha256 `
        -Label "Candidate wheel"
    Assert-WheelhouseState `
        -Path $resolvedRuntimeWheelhouse `
        -Expected $runtimeWheelhouseState

    $wheelhouseManifest = $runtimeWheelhouseState

    $candidateInstallPath = Join-Path $resolvedEvidenceDirectory "candidate-install.txt"
    $candidateUri = [System.Uri]::new($resolvedCandidateWheel).AbsoluteUri
    Write-NewUtf8File `
        -Path $candidateInstallPath `
        -Content "gatehouse-local @ $candidateUri --hash=sha256:$candidateSha256$([Environment]::NewLine)" `
        -Label "Candidate installation lock"

    $taskStateBefore = Get-GatehouseTaskState
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
        [Environment]::SetEnvironmentVariable("PIP_CONFIG_FILE", "nul", "Process")
        [Environment]::SetEnvironmentVariable("PIP_DISABLE_PIP_VERSION_CHECK", "1", "Process")
        [Environment]::SetEnvironmentVariable("PIP_EXTRA_INDEX_URL", $null, "Process")
        [Environment]::SetEnvironmentVariable("PIP_FIND_LINKS", $resolvedRuntimeWheelhouse, "Process")
        [Environment]::SetEnvironmentVariable("PIP_INDEX_URL", $null, "Process")
        [Environment]::SetEnvironmentVariable("PIP_NO_INDEX", "1", "Process")
        [Environment]::SetEnvironmentVariable("PIP_ONLY_BINARY", ":all:", "Process")
        [Environment]::SetEnvironmentVariable("PIP_REQUIRE_HASHES", $null, "Process")

        Assert-WheelhouseState `
            -Path $resolvedRuntimeWheelhouse `
            -Expected $runtimeWheelhouseState
        Assert-FileSha256 `
            -Path $resolvedCandidateWheel `
            -Expected $candidateSha256 `
            -Label "Candidate wheel"

        Invoke-Captured -Executable $SourceTestPython -Arguments @(
            "-I", "-m", "venv", $resolvedCleanEnvironment
        ) -Label "Clean environment creation" | Out-Null
        $cleanPython = Join-Path $resolvedCleanEnvironment "Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $cleanPython -PathType Leaf)) {
            throw "Clean environment Python was not created."
        }
        Invoke-Captured -Executable $cleanPython -Arguments @(
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links",
            $resolvedRuntimeWheelhouse,
            "--requirement",
            $runtimeLockPath
        ) -Label "Hash-locked offline runtime dependency installation" | Out-Null
        Invoke-Captured -Executable $cleanPython -Arguments @(
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-deps",
            "--requirement",
            $candidateInstallPath
        ) -Label "Offline candidate installation" | Out-Null
        Assert-FileSha256 `
            -Path $resolvedCandidateWheel `
            -Expected $candidateSha256 `
            -Label "Candidate wheel"
        Assert-WheelhouseState `
            -Path $resolvedRuntimeWheelhouse `
            -Expected $runtimeWheelhouseState
    } finally {
        foreach ($name in $pipEnvironmentNames) {
            [Environment]::SetEnvironmentVariable($name, $savedPipEnvironment[$name], "Process")
        }
    }

    $pipCheck = Invoke-Captured -Executable $cleanPython -Arguments @(
        "-I", "-m", "pip", "check"
    ) -Label "pip check"
    $installedPackages = Invoke-Captured -Executable $cleanPython -Arguments @(
        "-I", "-m", "pip", "list", "--format=json"
    ) -Label "Installed package inventory"

    $installedAuditPath = Join-Path $resolvedEvidenceDirectory "installed-audit.json"
    Invoke-Captured -Executable $cleanPython -Arguments @(
        "-I",
        (Join-Path $repositoryRoot "scripts\audit_installed_release.py"),
        $repositoryRoot,
        "--output",
        $installedAuditPath
    ) -Label "Installed distribution audit" | Out-Null

    $e2eTemp = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("gatehouse-release-e2e-" + [Guid]::NewGuid().ToString("N"))
    $savedE2eBin = [Environment]::GetEnvironmentVariable("GATEHOUSE_E2E_BIN_DIR", "Process")
    $e2eOutput = ""
    $installedProcessFailure = $null
    try {
        [Environment]::SetEnvironmentVariable(
            "GATEHOUSE_E2E_BIN_DIR",
            (Join-Path $resolvedCleanEnvironment "Scripts"),
            "Process"
        )
        try {
            $e2eOutput = Invoke-Captured -Executable $SourceTestPython -Arguments @(
                "-B",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                $e2eTemp,
                (Join-Path $repositoryRoot "tests\e2e\test_installed_process.py")
            ) -Label "Installed-process release test"
        } catch {
            $installedProcessFailure = $_
        }
    } finally {
        [Environment]::SetEnvironmentVariable(
            "GATEHOUSE_E2E_BIN_DIR",
            $savedE2eBin,
            "Process"
        )
    }
    $e2eOutputPath = Join-Path $resolvedEvidenceDirectory "installed-process-e2e.txt"
    Write-NewUtf8File `
        -Path $e2eOutputPath `
        -Content "$e2eOutput$([Environment]::NewLine)" `
        -Label "Installed-process transcript"

    $residueFailures = [System.Collections.Generic.List[string]]::new()
    $ownedProcesses = @()
    try {
        $ownedProcesses = @(
            Get-CimInstance Win32_Process |
                Where-Object {
                    $_.ExecutablePath -and
                    (Test-PathInside -Candidate $_.ExecutablePath -Parent $resolvedCleanEnvironment)
                }
        )
        if ($ownedProcesses.Count -ne 0) {
            $residueFailures.Add(
                "Installed-process test left a clean-environment process running."
            )
        }
    } catch {
        $residueFailures.Add("Owned-process residue inspection failed: $($_.Exception.Message)")
    }

    try {
        $taskStateAfter = Get-GatehouseTaskState
        if (
            ($taskStateBefore | ConvertTo-Json -Compress) -cne
            ($taskStateAfter | ConvertTo-Json -Compress)
        ) {
            $residueFailures.Add(
                "Installed-process test changed Gatehouse scheduled-task state."
            )
        }
    } catch {
        $residueFailures.Add("Scheduled-task residue inspection failed: $($_.Exception.Message)")
    }

    if ($null -ne $installedProcessFailure) {
        foreach ($residueFailure in $residueFailures) {
            Write-Warning "Additional release-test residue failure: $residueFailure"
        }
        $PSCmdlet.ThrowTerminatingError($installedProcessFailure)
    }
    if ($residueFailures.Count -ne 0) {
        throw ($residueFailures -join " ")
    }

    Assert-FileSha256 `
        -Path $resolvedCandidateWheel `
        -Expected $candidateSha256 `
        -Label "Candidate wheel"
    Assert-WheelhouseState `
        -Path $resolvedRuntimeWheelhouse `
        -Expected $runtimeWheelhouseState

    $sourceVersions = [ordered]@{
        python = Invoke-Captured -Executable $SourceTestPython -Arguments @("--version") -Label "Source Python version"
        pip = Invoke-Captured -Executable $SourceTestPython -Arguments @("-m", "pip", "--version") -Label "Source pip version"
        pytest = Invoke-Captured -Executable $SourceTestPython -Arguments @("-m", "pytest", "--version") -Label "pytest version"
        ruff = Invoke-Captured -Executable $SourceTestPython -Arguments @("-m", "ruff", "--version") -Label "Ruff version"
        mypy = Invoke-Captured -Executable $SourceTestPython -Arguments @("-m", "mypy", "--version") -Label "mypy version"
    }
    $cleanVersions = [ordered]@{
        python = Invoke-Captured -Executable $cleanPython -Arguments @("--version") -Label "Installed Python version"
        pip = Invoke-Captured -Executable $cleanPython -Arguments @("-m", "pip", "--version") -Label "Installed pip version"
    }

    $manifest = [ordered]@{
        schema_version = 2
        status = "passed_non_publishing_candidate_evidence"
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
        source_head = $head
        source_checkout_clean = $true
        candidate_wheel = [ordered]@{
            name = $candidateItem.Name
            size_bytes = $candidateSizeBytes
            sha256 = $candidateSha256
        }
        source_toolchain = $sourceVersions
        clean_toolchain = $cleanVersions
        pip_check = $pipCheck
        installed_packages = ConvertFrom-Json $installedPackages
        entry_point_and_process_test = "passed"
        process_residue_count = $ownedProcesses.Count
        scheduled_task_state_unchanged = $true
        evidence_files = [ordered]@{
            wheel_audit_sha256 = (Get-FileHash -LiteralPath $wheelAuditPath -Algorithm SHA256).Hash.ToLowerInvariant()
            installed_audit_sha256 = (Get-FileHash -LiteralPath $installedAuditPath -Algorithm SHA256).Hash.ToLowerInvariant()
            publication_hygiene_sha256 = (Get-FileHash -LiteralPath $hygienePath -Algorithm SHA256).Hash.ToLowerInvariant()
            supply_chain_sha256 = (Get-FileHash -LiteralPath $supplyChainPath -Algorithm SHA256).Hash.ToLowerInvariant()
            sbom_sha256 = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
            installed_process_e2e_sha256 = (Get-FileHash -LiteralPath $e2eOutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
            candidate_install_lock_sha256 = (Get-FileHash -LiteralPath $candidateInstallPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        runtime_wheelhouse = @($wheelhouseManifest)
        runtime_dependency_lock = [ordered]@{
            path = "requirements/$runtimeLockName"
            sha256 = (Get-FileHash -LiteralPath $runtimeLockPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        target_python_full_version = $runtimePythonFullVersion
        reviewed_wheelhouse_manifest_sha256 = (Get-FileHash -LiteralPath $wheelhouseManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        sbom = [ordered]@{
            format = "CycloneDX 1.6 JSON"
            sha256 = $supplyChainEvidence.sbom_sha256
        }
        vulnerability_scan = $supplyChainEvidence.vulnerability_scan
        vulnerability_snapshot_sha256 = $supplyChainEvidence.vulnerability_snapshot_sha256
        publication_authorized = $false
    }
    $manifestPath = Join-Path $resolvedEvidenceDirectory "manifest.json"
    Write-NewUtf8File `
        -Path $manifestPath `
        -Content "$(ConvertTo-Json $manifest -Depth 8)$([Environment]::NewLine)" `
        -Label "Release evidence manifest"
    Write-Host "Private release evidence: $resolvedEvidenceDirectory"
    Write-Host "Candidate SHA-256: $($manifest.candidate_wheel.sha256)"
    Write-Host "Publication remains disabled; this workflow only records private candidate evidence."
} finally {
    Pop-Location
}
