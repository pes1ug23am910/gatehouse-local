[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

foreach ($taskName in @("Gatehouse Daemon", "Gatehouse Watchdog")) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $task -and $PSCmdlet.ShouldProcess($taskName, "Unregister scheduled task")) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Removed $taskName."
    }
}
