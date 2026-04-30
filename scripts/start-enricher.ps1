param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8091,
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

if (Test-LocalPortOpen -Port $Port) {
    throw "Port $Port is already in use. Stop the old enricher process or run with -Port another_port."
}

$env:OSINT_ENRICHER_HOST = $HostName
$env:OSINT_ENRICHER_PORT = $Port
$env:OSINT_ENABLE_SHERLOCK = if ($EnableSherlock.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_SOCIAL_ANALYZER = if ($EnableSocialAnalyzer.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_MAIGRET = if ($EnableMaigret.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_PHONEINFOGA = if ($EnablePhoneInfoga.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_THEHARVESTER = if ($EnableTheHarvester.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_AMASS = if ($EnableAmass.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_GHUNT = if ($EnableGHunt.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_HOLEHE = if ($EnableHolehe.IsPresent) { "1" } else { "0" }
$env:OSINT_ENABLE_SPIDERFOOT = if ($EnableSpiderFoot.IsPresent) { "1" } else { "0" }
$env:OSINT_MAIGRET_CMD = $MaigretCmd
$env:OSINT_PHONEINFOGA_CMD = $PhoneInfogaCmd
$env:OSINT_THEHARVESTER_CMD = $TheHarvesterCmd
$env:OSINT_AMASS_CMD = $AmassCmd
$env:OSINT_GHUNT_CMD = $GHuntCmd
$env:OSINT_HOLEHE_CMD = $HoleheCmd
$env:OSINT_SPIDERFOOT_BASE_URL = $SpiderFootBaseUrl
$env:OSINT_CONNECTOR_TIMEOUT_SEC = [string]$ConnectorTimeoutSec
$env:OSINT_HOLEHE_MAX_EMAILS = [string]$HoleheMaxEmails
$env:OSINT_HOLEHE_TIMEOUT_SEC = [string]$HoleheTimeoutSec
$env:OSINT_SPIDERFOOT_SCAN_TIMEOUT_SEC = [string]$SpiderFootScanTimeoutSec
$env:OSINT_SPIDERFOOT_MAX_EVENTS = [string]$SpiderFootMaxEvents
python -u services/enricher/enricher.py
