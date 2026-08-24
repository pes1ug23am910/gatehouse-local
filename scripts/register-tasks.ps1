[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [string]$ConfigPath = "",
    [string]$DatabasePath = "",
    [int]$AgentPort = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "Task registration is supported only on Windows."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$windowlessPython = Join-Path $repositoryRoot ".venv\Scripts\pythonw.exe"
if (-not (Test-Path -LiteralPath $windowlessPython -PathType Leaf)) {
    throw "Required windowless Python executable is missing: $windowlessPython. Run scripts\bootstrap.ps1 first."
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $env:APPDATA "Gatehouse\config.yaml"
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
if ($AgentPort -lt 0 -or $AgentPort -gt 65535) {
    throw "AgentPort must be zero (load from config) or between 1 and 65535."
}
if (-not [string]::IsNullOrWhiteSpace($DatabasePath)) {
    $DatabasePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DatabasePath)
}

function ConvertTo-TaskArgument {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value.Contains('"') -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "Scheduled-task arguments cannot contain quotes or newlines."
    }
    return '"' + $Value + '"'
}

$daemonArgumentParts = @("-I", "-B", "-m", "gatehouse.daemon.main", "--config", (ConvertTo-TaskArgument -Value $ConfigPath))
$daemonArguments = $daemonArgumentParts -join " "
$watchdogArgumentParts = @("-I", "-B", "-m", "gatehouse.watchdog.main", "--once", "--config", (ConvertTo-TaskArgument -Value $ConfigPath))
if (-not [string]::IsNullOrWhiteSpace($DatabasePath)) {
    $watchdogArgumentParts += @("--database", (ConvertTo-TaskArgument -Value $DatabasePath))
}
if ($AgentPort -ne 0) {
    $watchdogArgumentParts += @("--agent-port", [string]$AgentPort)
}
$watchdogArguments = $watchdogArgumentParts -join " "

$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$daemonAction = New-ScheduledTaskAction -Execute $windowlessPython -Argument $daemonArguments -WorkingDirectory $repositoryRoot
$daemonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $principal.UserId
$watchdogAction = New-ScheduledTaskAction -Execute $windowlessPython -Argument $watchdogArguments -WorkingDirectory $repositoryRoot
$watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable
$registeredTaskNames = [System.Collections.Generic.List[string]]::new()

if ($PSCmdlet.ShouldProcess("Gatehouse Daemon", "Register current-user scheduled task")) {
    Register-ScheduledTask -TaskName "Gatehouse Daemon" -Action $daemonAction -Trigger $daemonTrigger -Principal $principal -Settings $settings -Force | Out-Null
    $null = $registeredTaskNames.Add("Gatehouse Daemon")
}
if ($PSCmdlet.ShouldProcess("Gatehouse Watchdog", "Register current-user scheduled task")) {
    Register-ScheduledTask -TaskName "Gatehouse Watchdog" -Action $watchdogAction -Trigger $watchdogTrigger -Principal $principal -Settings $settings -Force | Out-Null
    $null = $registeredTaskNames.Add("Gatehouse Watchdog")
}

if ($WhatIfPreference) {
    Write-Host "Validated Gatehouse Daemon and Gatehouse Watchdog registration for $($principal.UserId); no tasks were changed."
} elseif ($registeredTaskNames.Count -eq 0) {
    Write-Host "No Gatehouse scheduled tasks were registered for $($principal.UserId)."
} else {
    Write-Host "Registered $($registeredTaskNames -join ' and ') for $($principal.UserId)."
}
