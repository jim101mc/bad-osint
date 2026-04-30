param(
    [string]$DbPassword = $env:OSINT_DB_PASSWORD,
    [string]$DbUser = "postgres",
    [string]$DbUrl = "jdbc:postgresql://127.0.0.1:5432/osint",
    [string]$JdbcJar = "C:\Program Files\NetBeans-25\netbeans\ide\modules\ext\postgresql-42.5.4.jar",
    [string]$EnricherUrl = "http://127.0.0.1:8091/enrich",
    [int]$ApiPort = 8080,
    [switch]$EnableSherlock,
    [switch]$EnableSocialAnalyzer,
    [switch]$EnableMaigret,
    [switch]$EnablePhoneInfoga,
    [switch]$EnableTheHarvester,
    [switch]$EnableAmass,
    [switch]$EnableGHunt,
    [switch]$EnableHolehe,
    [switch]$EnableSpiderFoot,
    [string]$MaigretCmd = "",
    [string]$PhoneInfogaCmd = "",
    [string]$TheHarvesterCmd = "",
    [string]$AmassCmd = "",
    [string]$GHuntCmd = "",
    [string]$HoleheCmd = "",
    [string]$SpiderFootBaseUrl = "http://127.0.0.1:5001",
    [int]$ConnectorTimeoutSec = 25,
    [int]$HoleheMaxEmails = 2,
    [int]$HoleheTimeoutSec = 60,
    [int]$SpiderFootScanTimeoutSec = 90,
    [int]$SpiderFootMaxEvents = 40
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DbPassword)) {
    $secure = Read-Host "PostgreSQL password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $DbPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if (-not (Test-Path -LiteralPath $JdbcJar)) {
    throw "PostgreSQL JDBC jar not found: $JdbcJar"
}

$root = Resolve-Path "$PSScriptRoot\.."
Set-Location $root
New-Item -ItemType Directory -Force -Path logs | Out-Null

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

$enricherPort = ([Uri]$EnricherUrl).Port
if (Test-LocalPortOpen -Port $ApiPort) {
    throw "Port $ApiPort is already in use. Stop the old Java/API window first, or run this script with -ApiPort another_port."
}
if (Test-LocalPortOpen -Port $enricherPort) {
    throw "Port $enricherPort is already in use. Stop the old Python/enricher window first, or run this script with a different -EnricherUrl."
}

& "$PSScriptRoot\compile.ps1"

function Start-AppProcess {
    param(
        [string]$File,
        [string]$Arguments,
        [string]$OutFile,
        [string]$ErrFile,
        [hashtable]$Environment = @{}
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $File
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    foreach ($key in $Environment.Keys) {
        $psi.EnvironmentVariables[$key] = [string]$Environment[$key]
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    [void]$process.Start()

    $outputJob = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
        if ($EventArgs.Data) { Add-Content -LiteralPath $Event.MessageData.OutFile -Value $EventArgs.Data }
    } -MessageData @{ OutFile = $OutFile }
    $errorJob = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
        if ($EventArgs.Data) { Add-Content -LiteralPath $Event.MessageData.ErrFile -Value $EventArgs.Data }
    } -MessageData @{ ErrFile = $ErrFile }
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()

    return [pscustomobject]@{
        Process = $process
        OutputJob = $outputJob
        ErrorJob = $errorJob
    }
}

function Stop-AppProcess {
    param([pscustomobject]$App)
    if ($null -eq $App) {
        return
    }

    if ($App.Process -and -not $App.Process.HasExited) {
        Stop-Process -Id $App.Process.Id -Force
    }

    foreach ($job in @($App.OutputJob, $App.ErrorJob)) {
        if ($job) {
            Unregister-Event -SourceIdentifier $job.Name -ErrorAction SilentlyContinue
            Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$envValues = @{
    OSINT_DB_URL = $DbUrl
    OSINT_DB_USER = $DbUser
    OSINT_DB_PASSWORD = $DbPassword
    OSINT_ENRICHER_URL = $EnricherUrl
    OSINT_API_PORT = $ApiPort
}
$enricherEnvValues = @{
    OSINT_ENRICHER_HOST = ([Uri]$EnricherUrl).Host
    OSINT_ENRICHER_PORT = ([Uri]$EnricherUrl).Port
    OSINT_ENABLE_SHERLOCK = if ($EnableSherlock.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_SOCIAL_ANALYZER = if ($EnableSocialAnalyzer.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_MAIGRET = if ($EnableMaigret.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_PHONEINFOGA = if ($EnablePhoneInfoga.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_THEHARVESTER = if ($EnableTheHarvester.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_AMASS = if ($EnableAmass.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_GHUNT = if ($EnableGHunt.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_HOLEHE = if ($EnableHolehe.IsPresent) { "1" } else { "0" }
    OSINT_ENABLE_SPIDERFOOT = if ($EnableSpiderFoot.IsPresent) { "1" } else { "0" }
    OSINT_MAIGRET_CMD = $MaigretCmd
    OSINT_PHONEINFOGA_CMD = $PhoneInfogaCmd
    OSINT_THEHARVESTER_CMD = $TheHarvesterCmd
    OSINT_AMASS_CMD = $AmassCmd
    OSINT_GHUNT_CMD = $GHuntCmd
    OSINT_HOLEHE_CMD = $HoleheCmd
    OSINT_SPIDERFOOT_BASE_URL = $SpiderFootBaseUrl
    OSINT_CONNECTOR_TIMEOUT_SEC = [string]$ConnectorTimeoutSec
    OSINT_HOLEHE_MAX_EMAILS = [string]$HoleheMaxEmails
    OSINT_HOLEHE_TIMEOUT_SEC = [string]$HoleheTimeoutSec
    OSINT_SPIDERFOOT_SCAN_TIMEOUT_SEC = [string]$SpiderFootScanTimeoutSec
    OSINT_SPIDERFOOT_MAX_EVENTS = [string]$SpiderFootMaxEvents
}

$pythonScript = Join-Path $root "services\enricher\enricher.py"
$enricherApp = Start-AppProcess `
    -File "python" `
    -Arguments "-u `"$pythonScript`"" `
    -OutFile (Join-Path $root "logs\enricher.out.log") `
    -ErrFile (Join-Path $root "logs\enricher.err.log") `
    -Environment $enricherEnvValues

Start-Sleep -Seconds 1

$apiApp = Start-AppProcess `
    -File "java" `
    -Arguments "-cp `"out;$JdbcJar`" com.osintcorrelator.Main" `
    -OutFile (Join-Path $root "logs\api.out.log") `
    -ErrFile (Join-Path $root "logs\api.err.log") `
    -Environment $envValues

$healthUrl = "http://127.0.0.1:$ApiPort/health"
$databaseUrl = "http://127.0.0.1:$ApiPort/api/database"
$appUrl = "http://127.0.0.1:$ApiPort/"
$ready = $false

for ($i = 0; $i -lt 30; $i++) {
    try {
        $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
        if ($health.status -eq "ok") {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if (-not $ready) {
    Write-Host "API did not become ready. Check logs\api.err.log and logs\api.out.log."
    Stop-AppProcess -App $apiApp
    Stop-AppProcess -App $enricherApp
    exit 1
}

try {
    [void](Invoke-RestMethod -Uri $databaseUrl -TimeoutSec 5)
} catch {
    Write-Host "API started, but PostgreSQL is not usable with the provided credentials."
    Write-Host $_.Exception.Message
    Stop-AppProcess -App $apiApp
    Stop-AppProcess -App $enricherApp
    exit 1
}

Write-Host "OSINT Profile Correlator is running at $appUrl"
Start-Process $appUrl
Write-Host "Keep this window open. Press Enter to stop both services."
[void][Console]::ReadLine()

Stop-AppProcess -App $apiApp
Stop-AppProcess -App $enricherApp
Write-Host "Stopped."
