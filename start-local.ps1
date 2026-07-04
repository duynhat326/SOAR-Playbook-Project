param(
    [string]$BackendHost = "127.0.0.1",
    [int]$BackendPort = 8000,
    [int]$DashboardPort = 5173,
    [int]$StartupTimeoutSec = 45,
    [switch]$OpenBrowser,
    [switch]$CheckOnly,
    [switch]$FreePorts,
    [switch]$NoWorker
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DashboardUrl = "http://localhost:$DashboardPort"
$BackendHealthUrl = "http://$BackendHost`:$BackendPort/health"
$DashboardBootstrapUrl = "$DashboardUrl/soar-api/api/v1/dashboard/bootstrap"
$DashboardIncidentsUrl = "$DashboardUrl/soar-api/api/v1/incidents?limit=1"
$LocalDbPath = Join-Path $RepoRoot "output\soar-local.db"

function Get-RequiredCommandPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Required command '$Name' was not found in PATH."
    }

    return $command.Source
}

function Get-PortConflict {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $listener) {
        return $null
    }

    $processName = "<unknown>"
    try {
        $processName = (Get-Process -Id $listener.OwningProcess -ErrorAction Stop).ProcessName
    } catch {
    }

    return [pscustomobject]@{
        Port = $Port
        ProcessId = $listener.OwningProcess
        ProcessName = $processName
        LocalAddress = $listener.LocalAddress
    }
}

function Stop-PortOwner {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Conflict
    )

    $process = Get-Process -Id $Conflict.ProcessId -ErrorAction SilentlyContinue
    if (-not $process) {
        return $false
    }

    Stop-Process -Id $Conflict.ProcessId -Force -ErrorAction Stop
    return $true
}

function Wait-HttpReady {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSec = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
            return [pscustomobject]@{
                Ready = $true
                StatusCode = [int]$response.StatusCode
                Body = $response.Content
            }
        } catch {
            Start-Sleep -Milliseconds 700
        }
    } while ((Get-Date) -lt $deadline)

    return [pscustomobject]@{
        Ready = $false
        StatusCode = $null
        Body = $null
    }
}

function Invoke-HttpProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
        return [pscustomobject]@{
            Ok = $true
            StatusCode = [int]$response.StatusCode
            Body = $response.Content
        }
    } catch {
        $statusCode = $null
        $body = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
            } catch {
            }
        }

        return [pscustomobject]@{
            Ok = $false
            StatusCode = $statusCode
            Body = $body
        }
    }
}

function New-PowerShellWindow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $escapedTitle = $Title.Replace("'", "''")
    $wrapped = "& { try { `$host.UI.RawUI.WindowTitle = '$escapedTitle' } catch {}; $Command }"
    Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-Command", $wrapped) | Out-Null
}

Write-Host ""
Write-Host "SOAR local startup" -ForegroundColor Cyan
Write-Host "Repo root: $RepoRoot"
Write-Host ""

foreach ($requiredPath in @(".env.local", "requirements.txt", "dashboard\package.json")) {
    $fullPath = Join-Path $RepoRoot $requiredPath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Required file is missing: $requiredPath"
    }
}

$pythonExe = Get-RequiredCommandPath -Name "python"
$npmExe = Get-RequiredCommandPath -Name "npm.cmd"

$conflicts = @(@(
    Get-PortConflict -Port $BackendPort
    Get-PortConflict -Port $DashboardPort
) | Where-Object { $_ -ne $null })

if ($conflicts.Count -gt 0) {
    Write-Host "Startup aborted because one or more ports are already in use:" -ForegroundColor Yellow
    foreach ($conflict in $conflicts) {
        Write-Host "  Port $($conflict.Port): PID $($conflict.ProcessId) ($($conflict.ProcessName)) on $($conflict.LocalAddress)"
    }

    if (-not $FreePorts) {
        throw "Free ports $BackendPort and $DashboardPort, then re-run start-local.ps1."
    }

    Write-Host ""
    Write-Host "FreePorts enabled. Stopping conflicting listeners..." -ForegroundColor Cyan
    foreach ($conflict in $conflicts) {
        if (Stop-PortOwner -Conflict $conflict) {
            Write-Host "  Stopped PID $($conflict.ProcessId) on port $($conflict.Port)." -ForegroundColor Green
        } else {
            Write-Host "  PID $($conflict.ProcessId) was already gone." -ForegroundColor Yellow
        }
    }

    Start-Sleep -Seconds 2
    $remainingConflicts = @(@(
        Get-PortConflict -Port $BackendPort
        Get-PortConflict -Port $DashboardPort
    ) | Where-Object { $_ -ne $null })
    if ($remainingConflicts.Count -gt 0) {
        throw "Could not free ports $BackendPort and $DashboardPort automatically."
    }

    Write-Host "Ports are now free. Continuing startup..." -ForegroundColor Green
}

$escapedRepoRoot = $RepoRoot.Replace("'", "''")
$escapedPythonExe = $pythonExe.Replace("'", "''")
$escapedNpmExe = $npmExe.Replace("'", "''")

$escapedLocalDbPath = $LocalDbPath.Replace("'", "''")
$backendCommand = "Set-Location -LiteralPath '$escapedRepoRoot'; `$env:SOAR_POLICY_EXECUTION_MODE='queued'; `$env:SOAR_APPROVAL_REQUIRED_ACTIONS='isolate_host,kill_process,block_ip'; `$env:SOAR_DB_TARGET='$escapedLocalDbPath'; & '$escapedPythonExe' -m uvicorn api.app:app --host $BackendHost --port $BackendPort --reload"
$workerCommand = "Set-Location -LiteralPath '$escapedRepoRoot'; `$env:SOAR_POLICY_EXECUTION_MODE='queued'; `$env:SOAR_APPROVAL_REQUIRED_ACTIONS='isolate_host,kill_process,block_ip'; `$env:SOAR_DB_TARGET='$escapedLocalDbPath'; & '$escapedPythonExe' scripts\run_remediation_worker.py"
$dashboardCommand = "Set-Location -LiteralPath '$escapedRepoRoot'; & '$escapedNpmExe' --prefix dashboard run dev"

Write-Host "Python: $pythonExe"
Write-Host "npm:    $npmExe"
Write-Host "Local DB: $LocalDbPath"
Write-Host "Backend health:    $BackendHealthUrl"
Write-Host "Dashboard proxy:   $DashboardBootstrapUrl"
Write-Host ""

if ($CheckOnly) {
    Write-Host "CheckOnly enabled. No processes were started." -ForegroundColor Green
    Write-Host ""
    Write-Host "Would run backend command:"
    Write-Host "  $backendCommand"
    Write-Host ""
    Write-Host "Would run dashboard command:"
    Write-Host "  $dashboardCommand"
    if (-not $NoWorker) {
        Write-Host ""
        Write-Host "Would run worker command:"
        Write-Host "  $workerCommand"
    }
    exit 0
}

Write-Host "Starting backend window..." -ForegroundColor Cyan
New-PowerShellWindow -Title "SOAR Backend" -Command $backendCommand

Write-Host "Waiting for backend health..." -ForegroundColor Cyan
$backendProbe = Wait-HttpReady -Url $BackendHealthUrl -TimeoutSec $StartupTimeoutSec
if (-not $backendProbe.Ready) {
    throw "Backend did not become ready within $StartupTimeoutSec seconds."
}

Write-Host "Backend is healthy." -ForegroundColor Green
if (-not $NoWorker) {
    Write-Host "Starting remediation worker window..." -ForegroundColor Cyan
    New-PowerShellWindow -Title "SOAR Remediation Worker" -Command $workerCommand
}
Write-Host "Starting dashboard window..." -ForegroundColor Cyan
New-PowerShellWindow -Title "SOAR Dashboard" -Command $dashboardCommand

Write-Host "Waiting for dashboard proxy bootstrap..." -ForegroundColor Cyan
$dashboardProbe = Wait-HttpReady -Url $DashboardBootstrapUrl -TimeoutSec $StartupTimeoutSec
if (-not $dashboardProbe.Ready) {
    throw "Dashboard proxy did not become ready within $StartupTimeoutSec seconds."
}

Write-Host "Dashboard proxy is healthy." -ForegroundColor Green

$incidentsProbe = Invoke-HttpProbe -Url $DashboardIncidentsUrl
if ($incidentsProbe.Ok) {
    Write-Host "Incident list probe succeeded." -ForegroundColor Green
} elseif ($incidentsProbe.StatusCode -eq 500) {
    Write-Host "Incident list probe returned HTTP 500." -ForegroundColor Yellow
    Write-Host "This usually means the backend is up but cannot reach Supabase/Postgres."
} else {
    Write-Host "Incident list probe did not succeed." -ForegroundColor Yellow
    if ($incidentsProbe.StatusCode) {
        Write-Host "HTTP status: $($incidentsProbe.StatusCode)"
    }
}

Write-Host ""
Write-Host "Local stack is up." -ForegroundColor Green
Write-Host "Open dashboard: $DashboardUrl"
Write-Host "Backend health:  $BackendHealthUrl"
Write-Host ""
if ($NoWorker) {
    Write-Host "Stop the stack by closing the two PowerShell windows opened by this script."
} else {
    Write-Host "Stop the stack by closing the three PowerShell windows opened by this script."
}

if ($OpenBrowser) {
    Start-Process $DashboardUrl | Out-Null
}
