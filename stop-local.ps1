[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [int]$BackendPort = 8000,
    [int]$DashboardPort = 5173,
    [switch]$Force,
    [switch]$ListOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-PortListeners {
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$Ports
    )

    $listeners = @()
    foreach ($port in $Ports) {
        $listeners += Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    }

    return @($listeners)
}

function Get-ManagedShellCandidates {
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    $candidates = @()

    foreach ($process in $processes) {
        $commandLine = ""
        if ($null -ne $process.CommandLine) {
            $commandLine = [string]$process.CommandLine
        }
        $role = $null

        if ($commandLine -match "-m\s+uvicorn\s+api\.app:app") {
            $role = "backend"
        } elseif ($commandLine -match "--prefix\s+dashboard\s+run\s+dev") {
            $role = "dashboard"
        } elseif ($commandLine -match "scripts\\run_remediation_worker\.py") {
            $role = "worker"
        } else {
            continue
        }

        $windowTitle = ""
        try {
            $windowTitle = (Get-Process -Id $process.ProcessId -ErrorAction Stop).MainWindowTitle
        } catch {
        }

        $candidates += [pscustomobject]@{
            Role = $role
            ProcessId = [int]$process.ProcessId
            WindowTitle = $windowTitle
            CommandLine = $commandLine
        }
    }

    return @($candidates | Sort-Object Role, ProcessId -Unique)
}

function Stop-ManagedShell {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Candidate,
        [switch]$Force
    )

    $process = Get-Process -Id $Candidate.ProcessId -ErrorAction SilentlyContinue
    if (-not $process) {
        return $false
    }

    if (-not $Force -and $process.MainWindowHandle -ne 0) {
        $null = $process.CloseMainWindow()
        Start-Sleep -Seconds 2
        $process.Refresh()
    }

    if (-not $process.HasExited) {
        Stop-Process -Id $Candidate.ProcessId -Force:$Force.IsPresent -ErrorAction Stop
    }

    return $true
}

function Stop-PortOwner {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process) {
        return $false
    }

    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
    return $true
}

Write-Host ""
Write-Host "SOAR local shutdown" -ForegroundColor Cyan
Write-Host ""

$ports = @($BackendPort, $DashboardPort)
$candidates = @(Get-ManagedShellCandidates)
$listenersBefore = @(Get-PortListeners -Ports $ports)

if ($candidates.Count -eq 0) {
    Write-Host "No managed backend/dashboard/worker PowerShell windows were found." -ForegroundColor Yellow
} else {
    Write-Host "Managed windows found:" -ForegroundColor Cyan
    foreach ($candidate in $candidates) {
        $title = if ([string]::IsNullOrWhiteSpace($candidate.WindowTitle)) { "<no title>" } else { $candidate.WindowTitle }
        Write-Host "  [$($candidate.Role)] PID $($candidate.ProcessId) - $title"
    }
}

if ($listenersBefore.Count -gt 0) {
    Write-Host ""
    Write-Host "Ports currently listening:" -ForegroundColor Cyan
    foreach ($listener in $listenersBefore | Sort-Object LocalPort, OwningProcess -Unique) {
        Write-Host "  Port $($listener.LocalPort) -> PID $($listener.OwningProcess)"
    }
}

if ($ListOnly) {
    Write-Host ""
    Write-Host "ListOnly enabled. No processes were stopped." -ForegroundColor Green
    return
}

Write-Host ""
$stopped = 0
foreach ($candidate in $candidates) {
    $label = "$($candidate.Role) PowerShell PID $($candidate.ProcessId)"
    if ($PSCmdlet.ShouldProcess($label, "Stop")) {
        if (Stop-ManagedShell -Candidate $candidate -Force:$Force.IsPresent) {
            Write-Host "Stopped $label" -ForegroundColor Green
            $stopped += 1
        } else {
            Write-Host "$label was already stopped." -ForegroundColor Yellow
        }
    }
}

if ($Force -and $listenersBefore.Count -gt 0) {
    Write-Host ""
    Write-Host "Force enabled. Stopping any remaining listener owners on target ports..." -ForegroundColor Cyan
    foreach ($processId in @($listenersBefore | Select-Object -ExpandProperty OwningProcess -Unique)) {
        $label = "listener PID $processId on ports $($ports -join ', ')"
        if ($PSCmdlet.ShouldProcess($label, "Stop")) {
            if (Stop-PortOwner -ProcessId $processId) {
                Write-Host "Stopped $label" -ForegroundColor Green
            } else {
                Write-Host "$label was already stopped." -ForegroundColor Yellow
            }
        }
    }
}

Start-Sleep -Seconds 2
$listenersAfter = @(Get-PortListeners -Ports $ports)

Write-Host ""
if ($listenersAfter.Count -eq 0) {
    Write-Host "Ports $BackendPort and $DashboardPort are free." -ForegroundColor Green
} else {
    Write-Host "Some ports are still busy:" -ForegroundColor Yellow
    foreach ($listener in $listenersAfter | Sort-Object LocalPort, OwningProcess -Unique) {
        Write-Host "  Port $($listener.LocalPort) -> PID $($listener.OwningProcess)"
    }
    Write-Host "Those listeners may belong to processes not started by start-local.ps1."
}

Write-Host ""
Write-Host "Stopped managed windows: $stopped"
