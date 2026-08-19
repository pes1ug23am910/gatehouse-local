[CmdletBinding()]
param(
    [string]$ConfigPath = "",
    [int]$AgentPort = 0,
    [int]$TimeoutSeconds = 5,
    [switch]$RequireReady
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http | Out-Null

if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 30) {
    throw "TimeoutSeconds must be between 1 and 30."
}
if ($AgentPort -lt 0 -or $AgentPort -gt 65535) {
    throw "AgentPort must be zero (load from config) or between 1 and 65535."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ($AgentPort -eq 0) {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path $env:APPDATA "Gatehouse\config.yaml"
    }
    $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
    $watchdogExecutable = Join-Path $repositoryRoot ".venv\Scripts\gatehouse-watchdog.exe"
    if (-not (Test-Path -LiteralPath $watchdogExecutable -PathType Leaf)) {
        throw "The Gatehouse watchdog entry point is missing. Run scripts\bootstrap.ps1 first or pass -AgentPort."
    }
    $settingsText = & $watchdogExecutable --config $ConfigPath --print-settings
    if ($LASTEXITCODE -ne 0) {
        throw "The Gatehouse configuration could not be resolved."
    }
    $settings = $settingsText | ConvertFrom-Json -ErrorAction Stop
    $AgentPort = [int]$settings.agent_port
}

function Invoke-HealthRequest {
    param([Parameter(Mandatory)][string]$Uri)

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $response = $null
    try {
        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    } finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
        $client.Dispose()
        $handler.Dispose()
    }
}

function Read-HealthStatus {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    try {
        $payload = $Content | ConvertFrom-Json -ErrorAction Stop
        if ($payload.PSObject.Properties.Name -contains "status") {
            return ([string]$payload.status).Trim().ToUpperInvariant()
        }
    } catch {
        return $null
    }
    return $null
}

$baseUri = "http://127.0.0.1:$AgentPort"
$live = Invoke-HealthRequest -Uri "$baseUri/health/live"
$ready = Invoke-HealthRequest -Uri "$baseUri/health/ready"
$liveState = Read-HealthStatus -Content $live.Content
$readyState = Read-HealthStatus -Content $ready.Content

Write-Output ([pscustomobject]@{
    AgentPort = $AgentPort
    LiveStatusCode = $live.StatusCode
    LiveState = $liveState
    ReadyStatusCode = $ready.StatusCode
    ReadyState = $readyState
})

if ($live.StatusCode -ne 200 -or $readyState -eq "FAILED_CLOSED") {
    exit 1
}
if ($RequireReady -and ($ready.StatusCode -ne 200 -or $readyState -ne "READY")) {
    exit 1
}
