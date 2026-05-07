param(
    [Alias("h")]
    [switch]$Help,
    [string]$DbPassword = $env:OSINT_DB_PASSWORD,
    [string]$DbUser = "postgres",
    [string]$DbUrl = "jdbc:postgresql://127.0.0.1:5432/osint",
    [string]$JdbcJar = "C:\Program Files\NetBeans-25\netbeans\ide\modules\ext\postgresql-42.5.4.jar",
    [string]$EnricherUrl = "http://127.0.0.1:8091/enrich",
    [int]$ApiPort = 8080,
    [string]$PythonExe = "",
    [string[]]$DisableTools = @(),
    [switch]$StopExisting,
    [switch]$AutoPort,
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
    [string]$SocialAnalyzerCmd = "",
    [string]$SpiderFootBaseUrl = "http://127.0.0.1:5001",
    [string]$SpiderFootDir = "",
    [string]$SpiderFootPython = "",
    [int]$ConnectorTimeoutSec = 25,
    [int]$HoleheMaxEmails = 2,
    [int]$HoleheTimeoutSec = 60,
    [int]$SpiderFootScanTimeoutSec = 90,
    [int]$SpiderFootMaxEvents = 40
)

$ErrorActionPreference = "Stop"

function Show-StartupHelp {
    @"
Bad OSINT startup

Default startup:
  PowerShell: powershell -ExecutionPolicy Bypass -File .\start.badosint.ps1
  CMD:        start.badosint.cmd

Disable selected tools:
  PowerShell: powershell -ExecutionPolicy Bypass -File .\start.badosint.ps1 -DisableTools ghunt,amass
  CMD:        start.badosint.cmd -DisableTools ghunt,amass

Advanced startup:
  powershell -ExecutionPolicy Bypass -File .\scripts\start-all.ps1 -DisableTools ghunt,amass
  powershell -ExecutionPolicy Bypass -File .\scripts\start-all.ps1 -StopExisting
  powershell -ExecutionPolicy Bypass -File .\scripts\start-all.ps1 -AutoPort

Install tools:
  powershell -ExecutionPolicy Bypass -File .\install.badosint.ps1

Default-enabled tools:
  holehe, sherlock, social-analyzer, maigret, phoneinfoga, theharvester, amass, ghunt, spiderfoot

Command overrides:
  -GHuntCmd "C:\tools\ghunt.exe"
  -AmassCmd "C:\tools\amass.exe"
  -PhoneInfogaCmd "C:\tools\phoneinfoga.exe"
  -SpiderFootBaseUrl "http://127.0.0.1:5001"

Database password:
  Pass -DbPassword, set OSINT_DB_PASSWORD, or enter it when prompted.

Missing tools:
  Enabled tools are checked before startup. If optional tools are missing, you can continue without them for this run or stop startup.

After startup:
  App URL: http://127.0.0.1:$ApiPort/
  Logs:    logs\api.out.log, logs\api.err.log, logs\enricher.out.log, logs\enricher.err.log

Checkup:
  powershell -ExecutionPolicy Bypass -File .\scripts\checkup.ps1
"@
}

if ($Help.IsPresent) {
    Show-StartupHelp
    exit 0
}

$root = Resolve-Path "$PSScriptRoot\.."

function Import-LocalEnvFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (($value -match '^"[^"]*"$') -or ($value -match "^'[^']*'$")) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($name) {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Use-EnvDefault {
    param(
        [string]$CurrentValue,
        [string]$EnvName
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        return $CurrentValue
    }
    $envValue = [Environment]::GetEnvironmentVariable($EnvName, "Process")
    if ([string]::IsNullOrWhiteSpace($envValue)) {
        return $CurrentValue
    }
    return $envValue
}

Import-LocalEnvFile -Path (Join-Path $root ".badosint.local.env")

$DbPassword = Use-EnvDefault -CurrentValue $DbPassword -EnvName "OSINT_DB_PASSWORD"
$PythonExe = Use-EnvDefault -CurrentValue $PythonExe -EnvName "BADOSINT_VENV_PYTHON"
$MaigretCmd = Use-EnvDefault -CurrentValue $MaigretCmd -EnvName "OSINT_MAIGRET_CMD"
$PhoneInfogaCmd = Use-EnvDefault -CurrentValue $PhoneInfogaCmd -EnvName "OSINT_PHONEINFOGA_CMD"
$TheHarvesterCmd = Use-EnvDefault -CurrentValue $TheHarvesterCmd -EnvName "OSINT_THEHARVESTER_CMD"
$AmassCmd = Use-EnvDefault -CurrentValue $AmassCmd -EnvName "OSINT_AMASS_CMD"
$GHuntCmd = Use-EnvDefault -CurrentValue $GHuntCmd -EnvName "OSINT_GHUNT_CMD"
$HoleheCmd = Use-EnvDefault -CurrentValue $HoleheCmd -EnvName "OSINT_HOLEHE_CMD"
$SocialAnalyzerCmd = Use-EnvDefault -CurrentValue $SocialAnalyzerCmd -EnvName "OSINT_SOCIAL_ANALYZER_CMD"
$SpiderFootBaseUrl = Use-EnvDefault -CurrentValue $SpiderFootBaseUrl -EnvName "OSINT_SPIDERFOOT_BASE_URL"
$SpiderFootDir = Use-EnvDefault -CurrentValue $SpiderFootDir -EnvName "OSINT_SPIDERFOOT_DIR"
$SpiderFootPython = Use-EnvDefault -CurrentValue $SpiderFootPython -EnvName "OSINT_SPIDERFOOT_PYTHON"

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

Set-Location $root
New-Item -ItemType Directory -Force -Path logs | Out-Null

if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $localPython = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $localPython) {
        $PythonExe = $localPython
    } else {
        $PythonExe = "python"
    }
}

$localVenvScripts = Join-Path $root ".venv\Scripts"
$localToolBin = Join-Path $root ".tools\bin"

function Use-LocalCommandDefault {
    param(
        [string]$CurrentValue,
        [string[]]$Candidates
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        return $CurrentValue
    }

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $CurrentValue
}

$HoleheCmd = Use-LocalCommandDefault -CurrentValue $HoleheCmd -Candidates @((Join-Path $localVenvScripts "holehe.exe"))
$MaigretCmd = Use-LocalCommandDefault -CurrentValue $MaigretCmd -Candidates @((Join-Path $localVenvScripts "maigret.exe"))
$GHuntCmd = Use-LocalCommandDefault -CurrentValue $GHuntCmd -Candidates @((Join-Path $localVenvScripts "ghunt.exe"))
$PhoneInfogaCmd = Use-LocalCommandDefault -CurrentValue $PhoneInfogaCmd -Candidates @((Join-Path $localToolBin "phoneinfoga.exe"))
$AmassCmd = Use-LocalCommandDefault -CurrentValue $AmassCmd -Candidates @((Join-Path $localToolBin "amass.exe"))
$TheHarvesterCmd = Use-LocalCommandDefault -CurrentValue $TheHarvesterCmd -Candidates @((Join-Path $localVenvScripts "theHarvester.exe"), (Join-Path $localVenvScripts "theharvester.exe"))
$SocialAnalyzerCmd = Use-LocalCommandDefault -CurrentValue $SocialAnalyzerCmd -Candidates @((Join-Path $localVenvScripts "social-analyzer"), (Join-Path $localVenvScripts "social-analyzer.exe"))

function Normalize-ToolName {
    param([string]$Name)

    $value = ""
    if ($null -ne $Name) {
        $value = $Name.Trim().ToLowerInvariant()
    }
    if (-not $value) {
        return ""
    }

    switch ($value) {
        "socialanalyzer" { return "social-analyzer" }
        "social_analyzer" { return "social-analyzer" }
        "the-harvester" { return "theharvester" }
        "the_harvester" { return "theharvester" }
        "theharvester" { return "theharvester" }
        "phone-infoga" { return "phoneinfoga" }
        "phone_infoga" { return "phoneinfoga" }
        "spider-foot" { return "spiderfoot" }
        "spider_foot" { return "spiderfoot" }
        default { return $value }
    }
}

function Normalize-ToolList {
    param([string[]]$Items)

    $known = @(
        "holehe",
        "sherlock",
        "social-analyzer",
        "maigret",
        "phoneinfoga",
        "theharvester",
        "amass",
        "ghunt",
        "spiderfoot"
    )
    $set = @{}

    foreach ($item in $Items) {
        foreach ($part in ([string]$item -split ",")) {
            $name = Normalize-ToolName $part
            if (-not $name) {
                continue
            }
            if ($known -notcontains $name) {
                throw "Unknown tool '$part'. Accepted tools: $($known -join ', ')"
            }
            $set[$name] = $true
        }
    }

    return $set
}

function Test-ToolEnabled {
    param(
        [string]$Name,
        [hashtable]$Disabled
    )
    return -not $Disabled.ContainsKey((Normalize-ToolName $Name))
}

function Test-PythonModuleAvailable {
    param([string]$PythonModule)

    if ([string]::IsNullOrWhiteSpace($PythonModule)) {
        return $false
    }

    $pythonPath = ""
    if (Test-Path -LiteralPath $PythonExe) {
        $pythonPath = $PythonExe
    } else {
        $python = Get-Command $PythonExe -ErrorAction SilentlyContinue
        if ($python) {
            $pythonPath = $python.Source
        }
    }

    if ([string]::IsNullOrWhiteSpace($pythonPath)) {
        return $false
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $pythonPath
    $psi.Arguments = "-c `"import $PythonModule`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $process = [System.Diagnostics.Process]::Start($psi)
        $process.WaitForExit()
        return $process.ExitCode -eq 0
    } catch {
        return $false
    }
}

function Test-CommandAvailable {
    param(
        [string]$ExplicitCommand,
        [string[]]$Commands,
        [string]$PythonModule = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitCommand)) {
        $trimmed = $ExplicitCommand.Trim()
        if ($trimmed.StartsWith('"')) {
            $match = [regex]::Match($trimmed, '^"([^"]+)"')
            $first = if ($match.Success) { $match.Groups[1].Value } else { $trimmed.Trim('"') }
        } else {
            $first = ($trimmed -split "\s+", 2)[0]
        }
        if (
            (Test-Path -LiteralPath $first) -or
            (Test-Path -LiteralPath "$first.exe") -or
            (Test-Path -LiteralPath "$first.cmd") -or
            (Test-Path -LiteralPath "$first.bat") -or
            (Get-Command $first -ErrorAction SilentlyContinue)
        ) {
            return $true
        }
        return $false
    }

    foreach ($command in $Commands) {
        if (Get-Command $command -ErrorAction SilentlyContinue) {
            return $true
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PythonModule)) {
        if (Test-PythonModuleAvailable -PythonModule $PythonModule) {
            return $true
        }
    }

    return $false
}

function Test-ServiceAvailable {
    param([string]$Url)
    try {
        [void](Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2)
        return $true
    } catch {
        return $false
    }
}

function Test-LocalSpiderFootInstalled {
    if ([string]::IsNullOrWhiteSpace($SpiderFootDir) -or [string]::IsNullOrWhiteSpace($SpiderFootPython)) {
        return $false
    }
    $script = Join-Path $SpiderFootDir "sf.py"
    return (Test-Path -LiteralPath $SpiderFootDir) -and (Test-Path -LiteralPath $SpiderFootPython) -and (Test-Path -LiteralPath $script)
}

function Disable-MissingTools {
    param([hashtable]$Disabled)

    $missing = [System.Collections.Generic.List[string]]::new()
    if ((Test-ToolEnabled "holehe" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $HoleheCmd -Commands @("holehe") -PythonModule "holehe")) {
        $missing.Add("holehe")
    }
    if ((Test-ToolEnabled "sherlock" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand "" -Commands @("sherlock") -PythonModule "sherlock_project")) {
        $missing.Add("sherlock")
    }
    if ((Test-ToolEnabled "social-analyzer" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $SocialAnalyzerCmd -Commands @("social-analyzer", "social-analyzer.exe") -PythonModule "social_analyzer")) {
        $missing.Add("social-analyzer")
    }
    if ((Test-ToolEnabled "maigret" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $MaigretCmd -Commands @("maigret") -PythonModule "maigret")) {
        $missing.Add("maigret")
    }
    if ((Test-ToolEnabled "phoneinfoga" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $PhoneInfogaCmd -Commands @("phoneinfoga", "phoneinfoga.exe"))) {
        $missing.Add("phoneinfoga")
    }
    if ((Test-ToolEnabled "theharvester" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $TheHarvesterCmd -Commands @("theHarvester", "theharvester") -PythonModule "theHarvester")) {
        $missing.Add("theharvester")
    }
    if ((Test-ToolEnabled "amass" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $AmassCmd -Commands @("amass", "amass.exe"))) {
        $missing.Add("amass")
    }
    if ((Test-ToolEnabled "ghunt" $Disabled) -and -not (Test-CommandAvailable -ExplicitCommand $GHuntCmd -Commands @("ghunt") -PythonModule "ghunt")) {
        $missing.Add("ghunt")
    }
    if ((Test-ToolEnabled "spiderfoot" $Disabled) -and -not (Test-ServiceAvailable -Url $SpiderFootBaseUrl) -and -not (Test-LocalSpiderFootInstalled)) {
        $missing.Add("spiderfoot")
    }

    if ($missing.Count -eq 0) {
        return $Disabled
    }

    Write-Host "Missing or unreachable optional tools: $($missing -join ', ')"
    $answer = Read-Host "Continue without these tools for this run? [Y/n]"
    if ($answer.Trim().ToLowerInvariant() -in @("n", "no")) {
        throw "Startup stopped because optional tools are missing."
    }

    foreach ($tool in $missing) {
        $Disabled[$tool] = $true
    }
    return $Disabled
}

$disabledTools = Normalize-ToolList -Items $DisableTools
$disabledTools = Disable-MissingTools -Disabled $disabledTools

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

function Find-FreeLocalPort {
    param(
        [int]$StartPort,
        [int]$MaxAttempts = 50
    )

    for ($offset = 0; $offset -lt $MaxAttempts; $offset++) {
        $candidate = $StartPort + $offset
        if (-not (Test-LocalPortOpen -Port $candidate)) {
            return $candidate
        }
    }
    throw "Could not find a free local port starting at $StartPort."
}

function Get-PortOwningProcessIds {
    param([int]$Port)

    try {
        return @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
    } catch {
        return @()
    }
}

function Get-ProcessCommandLine {
    param([int]$ProcessId)

    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        return [string]$process.CommandLine
    } catch {
        return ""
    }
}

function Test-BadOsintProcess {
    param([int]$ProcessId)

    $commandLine = Get-ProcessCommandLine -ProcessId $ProcessId
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        return $false
    }

    $rootText = [regex]::Escape([string]$root)
    return (
        ($commandLine -match "com\.osintcorrelator\.Main") -or
        ($commandLine -match "services\\enricher\\enricher\.py") -or
        ($commandLine -match "spiderfoot.*sf\.py")
    ) -and ($commandLine -match $rootText)
}

function Stop-ExistingBadOsintOnPort {
    param(
        [int]$Port,
        [string]$Name
    )

    $processIds = Get-PortOwningProcessIds -Port $Port
    if ($processIds.Count -eq 0) {
        return $false
    }

    $stoppable = @()
    foreach ($processId in $processIds) {
        if (Test-BadOsintProcess -ProcessId $processId) {
            $stoppable += $processId
        }
    }

    if ($stoppable.Count -eq 0) {
        return $false
    }

    if (-not $StopExisting.IsPresent) {
        $answer = Read-Host "$Name port $Port is already used by an old Bad OSINT process. Stop it now? [Y/n]"
        if ($answer.Trim().ToLowerInvariant() -in @("n", "no")) {
            return $false
        }
    }

    foreach ($processId in $stoppable) {
        Write-Host "Stopping old Bad OSINT process $processId on port $Port..."
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    return $true
}

$enricherPort = ([Uri]$EnricherUrl).Port
if (Test-LocalPortOpen -Port $ApiPort) {
    [void](Stop-ExistingBadOsintOnPort -Port $ApiPort -Name "API")
}
if (Test-LocalPortOpen -Port $ApiPort) {
    if ($AutoPort.IsPresent) {
        $oldPort = $ApiPort
        $ApiPort = Find-FreeLocalPort -StartPort ($ApiPort + 1)
        Write-Host "Port $oldPort is unavailable. Using API port $ApiPort instead."
    }
}
if (Test-LocalPortOpen -Port $ApiPort) {
    throw "Port $ApiPort is already in use by another process. Stop it, or run this script with -ApiPort another_port."
}
if (Test-LocalPortOpen -Port $enricherPort) {
    [void](Stop-ExistingBadOsintOnPort -Port $enricherPort -Name "Enricher")
}
if (Test-LocalPortOpen -Port $enricherPort) {
    if ($AutoPort.IsPresent) {
        $oldPort = $enricherPort
        $enricherPort = Find-FreeLocalPort -StartPort ($enricherPort + 1)
        $uri = [Uri]$EnricherUrl
        $EnricherUrl = "$($uri.Scheme)://$($uri.Host):$enricherPort$($uri.AbsolutePath)"
        Write-Host "Port $oldPort is unavailable. Using enricher port $enricherPort instead."
    }
}
if (Test-LocalPortOpen -Port $enricherPort) {
    throw "Port $enricherPort is already in use by another process. Stop it, or run this script with a different -EnricherUrl."
}

& "$PSScriptRoot\compile.ps1"

function Start-AppProcess {
    param(
        [string]$File,
        [string]$Arguments,
        [string]$OutFile,
        [string]$ErrFile,
        [hashtable]$Environment = @{},
        [string]$WorkDir = $root
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $File
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $WorkDir
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

$localPathParts = @()
foreach ($pathPart in @($localVenvScripts, $localToolBin)) {
    if (Test-Path -LiteralPath $pathPart) {
        $localPathParts += $pathPart
    }
}
$localPathPrefix = $localPathParts -join ";"
$childPath = if ($localPathPrefix) { "$localPathPrefix;$env:PATH" } else { $env:PATH }

$spiderFootApp = $null
if ((Test-ToolEnabled "spiderfoot" $disabledTools) -and -not (Test-ServiceAvailable -Url $SpiderFootBaseUrl) -and (Test-LocalSpiderFootInstalled)) {
    $spiderFootUri = [Uri]$SpiderFootBaseUrl
    $spiderFootListen = "$($spiderFootUri.Host):$($spiderFootUri.Port)"
    $spiderFootScript = Join-Path $SpiderFootDir "sf.py"
    Write-Host "Starting local SpiderFoot at $SpiderFootBaseUrl..."
    $spiderFootApp = Start-AppProcess `
        -File $SpiderFootPython `
        -Arguments "-u `"$spiderFootScript`" -l $spiderFootListen" `
        -OutFile (Join-Path $root "logs\spiderfoot.out.log") `
        -ErrFile (Join-Path $root "logs\spiderfoot.err.log") `
        -Environment @{ PATH = $childPath } `
        -WorkDir $SpiderFootDir

    for ($i = 0; $i -lt 20; $i++) {
        if (Test-ServiceAvailable -Url $SpiderFootBaseUrl) {
            break
        }
        Start-Sleep -Seconds 1
    }

    if (-not (Test-ServiceAvailable -Url $SpiderFootBaseUrl)) {
        Write-Host "Local SpiderFoot did not become reachable. Continuing without SpiderFoot for this run."
        Stop-AppProcess -App $spiderFootApp
        $spiderFootApp = $null
        $disabledTools["spiderfoot"] = $true
    }
}

$envValues = @{
    OSINT_DB_URL = $DbUrl
    OSINT_DB_USER = $DbUser
    OSINT_DB_PASSWORD = $DbPassword
    # Agentic rewrite v2: the enricher URL now points to the orchestrator, which calls local tool agents.
    OSINT_ENRICHER_URL = $EnricherUrl
    OSINT_API_PORT = $ApiPort
}
$enricherEnvValues = @{
    PATH = $childPath
    OSINT_ENRICHER_HOST = ([Uri]$EnricherUrl).Host
    OSINT_ENRICHER_PORT = ([Uri]$EnricherUrl).Port
    OSINT_ENABLE_SHERLOCK = if (Test-ToolEnabled "sherlock" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_SOCIAL_ANALYZER = if (Test-ToolEnabled "social-analyzer" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_MAIGRET = if (Test-ToolEnabled "maigret" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_PHONEINFOGA = if (Test-ToolEnabled "phoneinfoga" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_THEHARVESTER = if (Test-ToolEnabled "theharvester" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_AMASS = if (Test-ToolEnabled "amass" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_GHUNT = if (Test-ToolEnabled "ghunt" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_HOLEHE = if (Test-ToolEnabled "holehe" $disabledTools) { "1" } else { "0" }
    OSINT_ENABLE_SPIDERFOOT = if (Test-ToolEnabled "spiderfoot" $disabledTools) { "1" } else { "0" }
    OSINT_MAIGRET_CMD = $MaigretCmd
    OSINT_PHONEINFOGA_CMD = $PhoneInfogaCmd
    OSINT_THEHARVESTER_CMD = $TheHarvesterCmd
    OSINT_AMASS_CMD = $AmassCmd
    OSINT_GHUNT_CMD = $GHuntCmd
    OSINT_HOLEHE_CMD = $HoleheCmd
    OSINT_SOCIAL_ANALYZER_CMD = $SocialAnalyzerCmd
    OSINT_SPIDERFOOT_BASE_URL = $SpiderFootBaseUrl
    OSINT_CONNECTOR_TIMEOUT_SEC = [string]$ConnectorTimeoutSec
    OSINT_HOLEHE_MAX_EMAILS = [string]$HoleheMaxEmails
    OSINT_HOLEHE_TIMEOUT_SEC = [string]$HoleheTimeoutSec
    OSINT_SPIDERFOOT_SCAN_TIMEOUT_SEC = [string]$SpiderFootScanTimeoutSec
    OSINT_SPIDERFOOT_MAX_EVENTS = [string]$SpiderFootMaxEvents
}

$pythonScript = Join-Path $root "services\orchestrator\orchestrator.py"
$enricherApp = Start-AppProcess `
    -File $PythonExe `
    -Arguments "-u `"$pythonScript`"" `
    -OutFile (Join-Path $root "logs\enricher.out.log") `
    -ErrFile (Join-Path $root "logs\enricher.err.log") `
    -Environment $enricherEnvValues

# Start tool-per-agent services (agentic rewrite v2).
$agentScripts = @(
    @{ Name = "agent-holehe"; Path = (Join-Path $root "services\agents\holehe_agent.py"); Port = 8111; EnvPort = "OSINT_AGENT_PORT_HOLEHE" },
    @{ Name = "agent-sherlock"; Path = (Join-Path $root "services\agents\sherlock_agent.py"); Port = 8112; EnvPort = "OSINT_AGENT_PORT_SHERLOCK" },
    @{ Name = "agent-social-analyzer"; Path = (Join-Path $root "services\agents\social_analyzer_agent.py"); Port = 8113; EnvPort = "OSINT_AGENT_PORT_SOCIAL_ANALYZER" },
    @{ Name = "agent-maigret"; Path = (Join-Path $root "services\agents\maigret_agent.py"); Port = 8114; EnvPort = "OSINT_AGENT_PORT_MAIGRET" },
    @{ Name = "agent-phoneinfoga"; Path = (Join-Path $root "services\agents\phoneinfoga_agent.py"); Port = 8115; EnvPort = "OSINT_AGENT_PORT_PHONEINFOGA" },
    @{ Name = "agent-theharvester"; Path = (Join-Path $root "services\agents\theharvester_agent.py"); Port = 8116; EnvPort = "OSINT_AGENT_PORT_THEHARVESTER" },
    @{ Name = "agent-amass"; Path = (Join-Path $root "services\agents\amass_agent.py"); Port = 8117; EnvPort = "OSINT_AGENT_PORT_AMASS" },
    @{ Name = "agent-ghunt"; Path = (Join-Path $root "services\agents\ghunt_agent.py"); Port = 8118; EnvPort = "OSINT_AGENT_PORT_GHUNT" },
    @{ Name = "agent-spiderfoot"; Path = (Join-Path $root "services\agents\spiderfoot_agent.py"); Port = 8119; EnvPort = "OSINT_AGENT_PORT_SPIDERFOOT" },
    @{ Name = "agent-catalog"; Path = (Join-Path $root "services\agents\catalog_agent.py"); Port = 8120; EnvPort = "OSINT_AGENT_PORT_CATALOG" }
)

$agentApps = @()
foreach ($agent in $agentScripts) {
    $agentPort = $agent.Port
    if ($enricherEnvValues.ContainsKey($agent.EnvPort) -and $enricherEnvValues[$agent.EnvPort]) {
        $agentPort = [int]$enricherEnvValues[$agent.EnvPort]
    } else {
        $enricherEnvValues[$agent.EnvPort] = [string]$agentPort
    }

    if (Test-LocalPortOpen -Port $agentPort) {
        if ($AutoPort) {
            $oldPort = $agentPort
            $agentPort = Find-FreeLocalPort -StartPort ($agentPort + 1)
            $enricherEnvValues[$agent.EnvPort] = [string]$agentPort
            Write-Host "Port $oldPort is unavailable. Using agent port $agentPort for $($agent.Name) instead."
        } else {
            throw "Port $agentPort is already in use by another process. Stop it, or run this script with -AutoPort."
        }
    }

    $agentApps += Start-AppProcess `
        -File $PythonExe `
        -Arguments "-u `"$($agent.Path)`"" `
        -OutFile (Join-Path $root "logs\$($agent.Name).out.log") `
        -ErrFile (Join-Path $root "logs\$($agent.Name).err.log") `
        -Environment $enricherEnvValues
}

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
    foreach ($agentApp in ($agentApps | Where-Object { $_ })) { Stop-AppProcess -App $agentApp }
    Stop-AppProcess -App $enricherApp
    Stop-AppProcess -App $spiderFootApp
    exit 1
}

try {
    [void](Invoke-RestMethod -Uri $databaseUrl -TimeoutSec 5)
} catch {
    Write-Host "API started, but PostgreSQL is not usable with the provided credentials."
    Write-Host $_.Exception.Message
    Stop-AppProcess -App $apiApp
    foreach ($agentApp in ($agentApps | Where-Object { $_ })) { Stop-AppProcess -App $agentApp }
    Stop-AppProcess -App $enricherApp
    Stop-AppProcess -App $spiderFootApp
    exit 1
}

Write-Host "OSINT Profile Correlator is running at $appUrl"
Start-Process $appUrl
Write-Host "Keep this window open. Press Enter to stop services."
[void][Console]::ReadLine()

Stop-AppProcess -App $apiApp
foreach ($agentApp in ($agentApps | Where-Object { $_ })) { Stop-AppProcess -App $agentApp }
Stop-AppProcess -App $enricherApp
Stop-AppProcess -App $spiderFootApp
Write-Host "Stopped."
