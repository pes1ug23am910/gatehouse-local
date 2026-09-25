[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [string]$ConfigPath = "",
    [string]$DatabasePath = "",
    [int]$AgentPort = 0
)

throw "Task registration is unavailable: a reviewed native task adapter is required."
