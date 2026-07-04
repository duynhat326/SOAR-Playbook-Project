param(
    [int]$Port = 4174
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$server = $null

Push-Location $root

function Wait-ForServer {
    param(
        [string]$Url,
        [int]$Attempts = 40
    )

    for ($index = 0; $index -lt $Attempts; $index += 1) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }

    throw "Static smoke-test server did not start on $Url."
}

try {
    if (-not (Test-Path -LiteralPath (Join-Path $root "dist\\index.html"))) {
        throw "Missing dashboard\\dist build output. Run 'npm.cmd run build' before executing smoke tests."
    }

    $server = Start-Process -FilePath "node" `
        -ArgumentList "tests/static-server.cjs" `
        -PassThru `
        -WindowStyle Hidden `
        -WorkingDirectory $root

    Wait-ForServer -Url "http://127.0.0.1:$Port/"

    & npx.cmd playwright test --workers=1 --reporter=line
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    Pop-Location
}
