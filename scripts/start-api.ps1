param(
    [string]$DbPassword = $env:OSINT_DB_PASSWORD,
    [string]$DbUser = "postgres",
    [string]$DbUrl = "jdbc:postgresql://127.0.0.1:5432/osint",
    [string]$JdbcJar = "C:\Program Files\NetBeans-25\netbeans\ide\modules\ext\postgresql-42.5.4.jar",
    [string]$EnricherUrl = "http://127.0.0.1:8091/enrich",
    [int]$ApiPort = 8080
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DbPassword)) {
    throw "Provide -DbPassword or set OSINT_DB_PASSWORD."
}

if (-not (Test-Path -LiteralPath $JdbcJar)) {
    throw "PostgreSQL JDBC jar not found: $JdbcJar"
}

Set-Location (Resolve-Path "$PSScriptRoot\..")

function Test-LocalPortOpen {
    param([int]$Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(500)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

if (Test-LocalPortOpen -Port $ApiPort) {
    throw "Port $ApiPort is already in use. Stop the old API process or run with -ApiPort another_port."
}

$env:OSINT_DB_URL = $DbUrl
$env:OSINT_DB_USER = $DbUser
$env:OSINT_DB_PASSWORD = $DbPassword
$env:OSINT_ENRICHER_URL = $EnricherUrl
$env:OSINT_API_PORT = $ApiPort

& "$PSScriptRoot\compile.ps1"
java -cp "out;$JdbcJar" com.osintcorrelator.Main
