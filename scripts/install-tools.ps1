param(
    [Alias("h")]
    [switch]$Help,
    [string[]]$Tools = @(),
    [string[]]$SkipTools = @(),
    [string]$InstallRoot = "",
    [string]$VenvPath = "",
    [switch]$Force,
    [switch]$NoPrompt,
    [switch]$SkipGhuntLogin
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Resolve-Path "$PSScriptRoot\.."
Set-Location $root

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Join-Path $root ".tools"
}
if ([string]::IsNullOrWhiteSpace($VenvPath)) {
    $VenvPath = Join-Path $root ".venv"
}

$knownTools = @(
    "holehe",
    "sherlock",
    "social-analyzer",
    "maigret",
    "phoneinfoga",
    "theharvester",
    "amass",
    "ghunt",
    "spiderfoot",
    "cobalt"
)

$pythonPackageByTool = [ordered]@{
    "holehe" = "holehe"
    "sherlock" = "sherlock-project"
    "social-analyzer" = "social-analyzer"
    "maigret" = "maigret"
    "ghunt" = "ghunt"
}

$python312Version = "3.12.10"
$python312InstallerUrl = "https://www.python.org/ftp/python/$python312Version/python-$python312Version-amd64.exe"

function Show-InstallHelp {
    @"
Bad OSINT tool installer

Default install:
  PowerShell: powershell -ExecutionPolicy Bypass -File .\install.badosint.ps1
  CMD:        install.badosint.cmd

Install selected tools:
  powershell -ExecutionPolicy Bypass -File .\install.badosint.ps1 -Tools holehe,sherlock,ghunt
  install.badosint.cmd -Tools holehe,sherlock,ghunt

Skip selected tools:
  powershell -ExecutionPolicy Bypass -File .\install.badosint.ps1 -SkipTools cobalt,spiderfoot
  install.badosint.cmd -SkipTools cobalt,spiderfoot

Local install locations:
  Python venv: $VenvPath
  Tool files:  $InstallRoot
  Python 3.12: $InstallRoot\python312
  Config:      .badosint.local.env

Supported tool names:
  $($knownTools -join ', ')

Prompts:
  - GHunt login can be launched after install.
  - Python 3.12 can be downloaded into .tools if no usable python.org Python 3.12 is found.
  - Cobalt Docker image pull is offered only when Docker is available.
  - Existing git-based tool folders are updated only after confirmation.

After install:
  Run start.badosint.cmd or powershell -ExecutionPolicy Bypass -File .\start.badosint.ps1
"@
}

if ($Help.IsPresent) {
    Show-InstallHelp
    exit 0
}

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
        "phone-infoga" { return "phoneinfoga" }
        "phone_infoga" { return "phoneinfoga" }
        "spider-foot" { return "spiderfoot" }
        "spider_foot" { return "spiderfoot" }
        default { return $value }
    }
}

function Normalize-ToolSet {
    param([string[]]$Items)

    $set = [ordered]@{}
    foreach ($item in $Items) {
        foreach ($part in ([string]$item -split ",")) {
            $name = Normalize-ToolName $part
            if (-not $name) {
                continue
            }
            if ($knownTools -notcontains $name) {
                throw "Unknown tool '$part'. Accepted tools: $($knownTools -join ', ')"
            }
            $set[$name] = $true
        }
    }
    return $set
}

function Confirm-Step {
    param(
        [string]$Question,
        [bool]$DefaultYes = $true
    )

    if ($NoPrompt.IsPresent) {
        return $DefaultYes
    }

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Question $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }
    return $answer.Trim().ToLowerInvariant() -in @("y", "yes")
}

function Join-ProcessArguments {
    param([string[]]$Arguments)

    $quoted = @()
    foreach ($argument in $Arguments) {
        $value = [string]$argument
        if ($value -match '[\s"]') {
            $value = '"' + ($value -replace '"', '\"') + '"'
        }
        $quoted += $value
    }
    return $quoted -join " "
}

function Invoke-External {
    param(
        [string]$File,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $root
    )

    $argumentLine = Join-ProcessArguments -Arguments $Arguments
    Write-Host "> $File $argumentLine"
    $process = Start-Process -FilePath $File -ArgumentList $argumentLine -WorkingDirectory $WorkingDirectory -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $File $argumentLine"
    }
}

function Ensure-Command {
    param(
        [string]$Name,
        [string]$InstallHint
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "$Name was not found. $InstallHint"
    }
    return $command.Source
}

function Test-VersionAtLeast {
    param(
        [int]$Major,
        [int]$Minor,
        [int]$MinimumMajor,
        [int]$MinimumMinor
    )

    return ($Major -gt $MinimumMajor) -or (($Major -eq $MinimumMajor) -and ($Minor -ge $MinimumMinor))
}

function Get-PythonVersion {
    param(
        [string]$File,
        [string[]]$PrefixArgs = @()
    )

    $argumentLine = Join-ProcessArguments -Arguments ($PrefixArgs + @("-c", "import sys; print(sys.executable); print(f'{sys.version_info.major}.{sys.version_info.minor}')"))
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $File
    $psi.Arguments = $argumentLine
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $process = [System.Diagnostics.Process]::Start($psi)
        $stdout = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            return $null
        }
        $lines = $stdout -split "\r?\n" | Where-Object { $_.Trim() }
        if ($lines.Count -lt 2) {
            return $null
        }
        $versionParts = $lines[1].Trim() -split "\."
        if ($versionParts.Count -lt 2) {
            return $null
        }
        return [pscustomobject]@{
            File = $File
            PrefixArgs = $PrefixArgs
            Executable = $lines[0].Trim()
            Major = [int]$versionParts[0]
            Minor = [int]$versionParts[1]
        }
    } catch {
        return $null
    }
}

function Find-PythonAtLeast {
    param(
        [int]$MinimumMajor,
        [int]$MinimumMinor
    )

    $candidates = @(
        @{ File = "py"; Args = @("-3.12") },
        @{ File = "python3.12"; Args = @() },
        @{ File = "py"; Args = @("-3.13") },
        @{ File = "python3.13"; Args = @() },
        @{ File = "py"; Args = @("-3.14") },
        @{ File = "python3.14"; Args = @() },
        @{ File = "python"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        if (-not (Get-Command $candidate.File -ErrorAction SilentlyContinue)) {
            continue
        }
        $version = Get-PythonVersion -File $candidate.File -PrefixArgs $candidate.Args
        if ($version -and ($version.Executable -match '\\msys64\\|/msys64/')) {
            continue
        }
        if ($version -and (Test-VersionAtLeast -Major $version.Major -Minor $version.Minor -MinimumMajor $MinimumMajor -MinimumMinor $MinimumMinor)) {
            return $version
        }
    }

    return $null
}

function Find-PythonVersion {
    param(
        [int]$Major,
        [int]$Minor
    )

    $candidates = @(
        @{ File = (Join-Path $InstallRoot "python312\python.exe"); Args = @() },
        @{ File = "py"; Args = @("-$Major.$Minor") },
        @{ File = "python$Major.$Minor"; Args = @() },
        @{ File = "python"; Args = @() },
        @{ File = "$env:LOCALAPPDATA\Programs\Python\Python$Major$Minor\python.exe"; Args = @() },
        @{ File = "C:\Program Files\Python$Major$Minor\python.exe"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate.File) -and -not (Get-Command $candidate.File -ErrorAction SilentlyContinue)) {
            continue
        }
        $version = Get-PythonVersion -File $candidate.File -PrefixArgs $candidate.Args
        if ($version -and ($version.Executable -match '\\msys64\\|/msys64/')) {
            continue
        }
        if ($version -and $version.Major -eq $Major -and $version.Minor -eq $Minor) {
            return $version
        }
    }

    return $null
}

function Install-ProjectPython312 {
    $target = Join-Path $InstallRoot "python312"
    $pythonExe = Join-Path $target "python.exe"
    if (Test-PythonUsable -PythonExe $pythonExe) {
        return Find-PythonVersion -Major 3 -Minor 12
    }

    Ensure-Directory -Path $target
    $downloads = Join-Path $InstallRoot "downloads"
    Ensure-Directory -Path $downloads
    $installer = Join-Path $downloads "python-$python312Version-amd64.exe"

    if (-not (Test-Path -LiteralPath $installer)) {
        Write-Host "Downloading project-local Python $python312Version..."
        Invoke-WebRequest -Uri $python312InstallerUrl -OutFile $installer -Headers @{ "User-Agent" = "bad-osint-installer" }
    }

    Write-Host "Installing project-local Python $python312Version to $target..."
    Invoke-External -File $installer -Arguments @(
        "/quiet",
        "InstallAllUsers=0",
        "TargetDir=$target",
        "Include_launcher=0",
        "Include_pip=1",
        "Include_test=0",
        "PrependPath=0",
        "Shortcuts=0",
        "SimpleInstall=1"
    )

    $python = Find-PythonVersion -Major 3 -Minor 12
    if (-not $python) {
        throw "Project-local Python $python312Version was installed, but python.exe is not usable at $pythonExe"
    }
    return $python
}

function Ensure-PythonVersion {
    param(
        [int]$Major,
        [int]$Minor,
        [string]$Reason
    )

    $python = Find-PythonVersion -Major $Major -Minor $Minor
    if ($python) {
        return $python
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget -and (Confirm-Step -Question "$Reason Install Python $Major.$Minor with winget now?" -DefaultYes $true)) {
        Invoke-External -File $winget.Source -Arguments @(
            "install",
            "-e",
            "--id",
            "Python.Python.$Major.$Minor",
            "--accept-package-agreements",
            "--accept-source-agreements"
        )
        $python = Find-PythonVersion -Major $Major -Minor $Minor
        if ($python) {
            return $python
        }
    }

    if ($Major -eq 3 -and $Minor -eq 12 -and (Confirm-Step -Question "$Reason Download and install project-local Python $python312Version now?" -DefaultYes $true)) {
        return Install-ProjectPython312
    }

    throw "$Reason Install python.org Python $Major.$Minor and rerun this installer, or skip the affected tool."
}

function Get-PythonExeVersion {
    param([string]$PythonExe)

    if (-not (Test-Path -LiteralPath $PythonExe)) {
        return $null
    }
    return Get-PythonVersion -File $PythonExe
}

function Test-PythonUsable {
    param([string]$PythonExe)
    return $null -ne (Get-PythonExeVersion -PythonExe $PythonExe)
}

function Ensure-Directory {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Assert-PathInside {
    param(
        [string]$Path,
        [string]$Parent
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullParent = [IO.Path]::GetFullPath($Parent)
    if (-not $fullPath.StartsWith($fullParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify path outside install root: $fullPath"
    }
}

function Ensure-Venv {
    $python = Ensure-PythonVersion `
        -Major 3 `
        -Minor 12 `
        -Reason "Bad OSINT needs python.org Python 3.12 for Windows venvs. MSYS Python and Python 3.13 can break some OSINT dependencies."
    $venvPython = Join-Path $VenvPath "Scripts\python.exe"
    $existingVersion = Get-PythonExeVersion -PythonExe $venvPython
    if ((Test-Path -LiteralPath $VenvPath) -and (-not $existingVersion -or $existingVersion.Major -ne 3 -or $existingVersion.Minor -ne 12)) {
        Write-Host "Existing Python venv is broken or not Python 3.12. Recreating: $VenvPath"
        Assert-PathInside -Path $VenvPath -Parent $root
        Remove-Item -LiteralPath $VenvPath -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $VenvPath)) {
        Invoke-External -File $python.File -Arguments ($python.PrefixArgs + @("-m", "venv", $VenvPath))
    }

    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Virtual environment Python was not created at $venvPython"
    }
    if (-not (Test-PythonUsable -PythonExe $venvPython)) {
        throw "Virtual environment Python is not usable at $venvPython"
    }

    Invoke-External -File $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
    return $venvPython
}

function Install-PythonToolPackages {
    param(
        [string]$PythonExe,
        [System.Collections.IDictionary]$SelectedTools
    )

    $requirements = Join-Path $root "requirements.txt"
    if (-not (Test-Path -LiteralPath $requirements)) {
        throw "requirements.txt was not found at $requirements"
    }

    $packages = @()
    foreach ($tool in $pythonPackageByTool.Keys) {
        if ($SelectedTools.Contains($tool)) {
            $packages += $pythonPackageByTool[$tool]
        }
    }

    if ($packages.Count -eq 0) {
        return
    }

    if ($packages.Count -eq $pythonPackageByTool.Count) {
        Invoke-External -File $PythonExe -Arguments @("-m", "pip", "install", "-r", $requirements)
    } else {
        Invoke-External -File $PythonExe -Arguments (@("-m", "pip", "install") + $packages)
    }
}

function Clone-Or-UpdateRepo {
    param(
        [string]$RepoUrl,
        [string]$TargetDir,
        [string]$ToolName
    )

    $git = Ensure-Command -Name "git" -InstallHint "Install Git for Windows and rerun this installer."
    if (Test-Path -LiteralPath (Join-Path $TargetDir ".git")) {
        if ($Force.IsPresent -or (Confirm-Step -Question "$ToolName already exists. Update it with git pull?" -DefaultYes $true)) {
            Invoke-External -File $git -Arguments @("-C", $TargetDir, "pull", "--ff-only")
        }
        return
    }

    if (Test-Path -LiteralPath $TargetDir) {
        Write-Host "$ToolName folder already exists and is not a git repo: $TargetDir"
        return
    }

    Invoke-External -File $git -Arguments @("clone", $RepoUrl, $TargetDir)
}

function Download-LatestGitHubAsset {
    param(
        [string]$Repository,
        [string[]]$NamePatterns,
        [string]$DownloadsDir
    )

    Ensure-Directory -Path $DownloadsDir
    $releaseUrl = "https://api.github.com/repos/$Repository/releases/latest"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{ "User-Agent" = "bad-osint-installer" }
    foreach ($pattern in $NamePatterns) {
        $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($asset) {
            $destination = Join-Path $DownloadsDir $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $destination -Headers @{ "User-Agent" = "bad-osint-installer" }
            return $destination
        }
    }
    throw "No matching release asset found for $Repository. Patterns: $($NamePatterns -join ', ')"
}

function Expand-DownloadedTool {
    param(
        [string]$ArchivePath,
        [string]$ExtractDir
    )

    if (Test-Path -LiteralPath $ExtractDir) {
        if ($Force.IsPresent) {
            Assert-PathInside -Path $ExtractDir -Parent $InstallRoot
            Remove-Item -LiteralPath $ExtractDir -Recurse -Force
        } else {
            return
        }
    }
    Ensure-Directory -Path $ExtractDir

    if ($ArchivePath.EndsWith(".zip", [StringComparison]::OrdinalIgnoreCase)) {
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractDir -Force
        return
    }

    if ($ArchivePath.EndsWith(".tar.gz", [StringComparison]::OrdinalIgnoreCase)) {
        Ensure-Command -Name "tar" -InstallHint "Install Windows tar support or extract the archive manually." | Out-Null
        Invoke-External -File "tar" -Arguments @("-xzf", $ArchivePath, "-C", $ExtractDir)
        return
    }

    throw "Unsupported archive format: $ArchivePath"
}

function Copy-ExecutableToBin {
    param(
        [string]$SearchRoot,
        [string]$ExecutableName,
        [string]$BinDir
    )

    $match = Get-ChildItem -LiteralPath $SearchRoot -Recurse -Filter $ExecutableName -File | Select-Object -First 1
    if (-not $match) {
        throw "$ExecutableName was not found under $SearchRoot"
    }

    Ensure-Directory -Path $BinDir
    $destination = Join-Path $BinDir $ExecutableName
    Copy-Item -LiteralPath $match.FullName -Destination $destination -Force
    return $destination
}

function Install-PhoneInfoga {
    param([string]$BinDir)

    $downloads = Join-Path $InstallRoot "downloads"
    $archive = Download-LatestGitHubAsset `
        -Repository "sundowndev/phoneinfoga" `
        -NamePatterns @("Windows.*(x86_64|amd64).*\.tar\.gz$") `
        -DownloadsDir $downloads
    $extract = Join-Path $InstallRoot "phoneinfoga"
    Expand-DownloadedTool -ArchivePath $archive -ExtractDir $extract
    return Copy-ExecutableToBin -SearchRoot $extract -ExecutableName "phoneinfoga.exe" -BinDir $BinDir
}

function Install-Amass {
    param([string]$BinDir)

    $downloads = Join-Path $InstallRoot "downloads"
    try {
        $archive = Download-LatestGitHubAsset `
            -Repository "owasp-amass/amass" `
            -NamePatterns @("amass.*windows.*(x86_64|amd64).*\.(zip|tar\.gz)$", "windows.*(x86_64|amd64).*\.(zip|tar\.gz)$") `
            -DownloadsDir $downloads
    } catch {
        Write-Host "Latest Amass release did not expose a matching Windows asset. Falling back to official v4.2.0 Windows asset."
        Ensure-Directory -Path $downloads
        $archive = Join-Path $downloads "amass_Windows_amd64.zip"
        Invoke-WebRequest `
            -Uri "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Windows_amd64.zip" `
            -OutFile $archive `
            -Headers @{ "User-Agent" = "bad-osint-installer" }
    }
    $extract = Join-Path $InstallRoot "amass"
    Expand-DownloadedTool -ArchivePath $archive -ExtractDir $extract
    return Copy-ExecutableToBin -SearchRoot $extract -ExecutableName "amass.exe" -BinDir $BinDir
}

function Install-TheHarvester {
    param([string]$PythonExe)

    $target = Join-Path $InstallRoot "theHarvester"
    Clone-Or-UpdateRepo -RepoUrl "https://github.com/laramies/theHarvester.git" -TargetDir $target -ToolName "theHarvester"

    $python312 = Ensure-PythonVersion `
        -Major 3 `
        -Minor 12 `
        -Reason "theHarvester uses Python dependencies that are most reliable on Windows with python.org Python 3.12."

    $toolVenv = Join-Path $target ".venv"
    $toolPython = Join-Path $toolVenv "Scripts\python.exe"
    $existingVersion = Get-PythonExeVersion -PythonExe $toolPython
    if ((Test-Path -LiteralPath $toolVenv) -and (-not $existingVersion -or $existingVersion.Major -ne 3 -or $existingVersion.Minor -ne 12)) {
        Write-Host "Existing theHarvester venv is broken or not Python 3.12. Recreating: $toolVenv"
        Assert-PathInside -Path $toolVenv -Parent $InstallRoot
        Remove-Item -LiteralPath $toolVenv -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $toolVenv)) {
        Invoke-External -File $python312.File -Arguments ($python312.PrefixArgs + @("-m", "venv", $toolVenv))
    }

    Invoke-External -File $toolPython -Arguments @("-m", "pip", "install", "--upgrade", "pip", "uv")
    $uv = Join-Path $toolVenv "Scripts\uv.exe"
    Invoke-External -File $uv -Arguments @("sync", "--python", $toolPython) -WorkingDirectory $target

    foreach ($commandName in @("theHarvester.exe", "theharvester.exe")) {
        $command = Join-Path $toolVenv "Scripts\$commandName"
        if (Test-Path -LiteralPath $command) {
            return $command
        }
    }

    throw "theHarvester command was not found after setup under $toolVenv\Scripts"
}

function Install-SpiderFoot {
    $target = Join-Path $InstallRoot "spiderfoot"
    Clone-Or-UpdateRepo -RepoUrl "https://github.com/smicallef/spiderfoot.git" -TargetDir $target -ToolName "SpiderFoot"

    $python = Ensure-PythonVersion `
        -Major 3 `
        -Minor 12 `
        -Reason "SpiderFoot needs python.org Python 3.12 because its lxml<5 dependency does not provide Python 3.13 Windows wheels."
    $spiderVenv = Join-Path $target ".venv"
    $spiderPython = Join-Path $spiderVenv "Scripts\python.exe"
    $existingVersion = Get-PythonExeVersion -PythonExe $spiderPython
    if ((Test-Path -LiteralPath $spiderVenv) -and (-not $existingVersion -or $existingVersion.Major -ne 3 -or $existingVersion.Minor -ne 12)) {
        Write-Host "Existing SpiderFoot venv is broken or not Python 3.12. Recreating: $spiderVenv"
        Assert-PathInside -Path $spiderVenv -Parent $InstallRoot
        Remove-Item -LiteralPath $spiderVenv -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $spiderVenv)) {
        Invoke-External -File $python.File -Arguments ($python.PrefixArgs + @("-m", "venv", $spiderVenv))
    }

    Invoke-External -File $spiderPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
    Invoke-External -File $spiderPython -Arguments @("-m", "pip", "install", "-r", (Join-Path $target "requirements.txt"))
    return @{
        Dir = $target
        Python = $spiderPython
    }
}

function Install-Cobalt {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Host "Docker was not found. Skipping Cobalt image setup."
        return $false
    }

    if (-not (Confirm-Step -Question "Pull Cobalt Docker image ghcr.io/imputnet/cobalt:latest?" -DefaultYes $true)) {
        return $false
    }

    Invoke-External -File $docker.Source -Arguments @("pull", "ghcr.io/imputnet/cobalt:latest")
    return $true
}

function Get-VenvCommandPath {
    param(
        [string]$ScriptsDir,
        [string]$Name
    )

    $path = Join-Path $ScriptsDir "$Name.exe"
    if (Test-Path -LiteralPath $path) {
        return $path
    }
    return ""
}

function Write-LocalEnv {
    param(
        [string]$PythonExe,
        [string]$BinDir,
        [hashtable]$ExtraValues
    )

    $scriptsDir = Join-Path $VenvPath "Scripts"
    $values = [ordered]@{
        BADOSINT_TOOL_ROOT = $InstallRoot
        BADOSINT_VENV_PYTHON = $PythonExe
        BADOSINT_TOOL_BIN = $BinDir
        OSINT_HOLEHE_CMD = Get-VenvCommandPath -ScriptsDir $scriptsDir -Name "holehe"
        OSINT_MAIGRET_CMD = Get-VenvCommandPath -ScriptsDir $scriptsDir -Name "maigret"
        OSINT_GHUNT_CMD = Get-VenvCommandPath -ScriptsDir $scriptsDir -Name "ghunt"
        OSINT_SOCIAL_ANALYZER_CMD = Join-Path $scriptsDir "social-analyzer"
        OSINT_PHONEINFOGA_CMD = Join-Path $BinDir "phoneinfoga.exe"
        OSINT_AMASS_CMD = Join-Path $BinDir "amass.exe"
        OSINT_SPIDERFOOT_BASE_URL = "http://127.0.0.1:5001"
    }

    foreach ($key in $ExtraValues.Keys) {
        $values[$key] = $ExtraValues[$key]
    }

    $lines = @(
        "# Local Bad OSINT tool configuration. This file is ignored by git.",
        "# Generated by scripts/install-tools.ps1."
    )
    foreach ($key in $values.Keys) {
        $value = [string]$values[$key]
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $lines += "$key=$value"
        }
    }

    Set-Content -LiteralPath (Join-Path $root ".badosint.local.env") -Value $lines -Encoding ASCII
}

$selected = Normalize-ToolSet -Items $Tools
$skipped = Normalize-ToolSet -Items $SkipTools
if ($selected.Count -eq 0) {
    foreach ($tool in $knownTools) {
        $selected[$tool] = $true
    }
}
foreach ($tool in $skipped.Keys) {
    $selected.Remove($tool)
}

Ensure-Directory -Path $InstallRoot
$binDir = Join-Path $InstallRoot "bin"
Ensure-Directory -Path $binDir

$extraEnv = @{}
$failures = [System.Collections.Generic.List[string]]::new()

try {
    $venvPython = Ensure-Venv
    Install-PythonToolPackages -PythonExe $venvPython -SelectedTools $selected
} catch {
    $failures.Add("python requirements: $($_.Exception.Message)")
}

if ($selected.Contains("phoneinfoga")) {
    try {
        [void](Install-PhoneInfoga -BinDir $binDir)
    } catch {
        $failures.Add("phoneinfoga: $($_.Exception.Message)")
    }
}

if ($selected.Contains("amass")) {
    try {
        [void](Install-Amass -BinDir $binDir)
    } catch {
        $failures.Add("amass: $($_.Exception.Message)")
    }
}

if ($selected.Contains("theharvester")) {
    try {
        $extraEnv["OSINT_THEHARVESTER_CMD"] = Install-TheHarvester -PythonExe $venvPython
    } catch {
        $failures.Add("theharvester: $($_.Exception.Message)")
    }
}

if ($selected.Contains("spiderfoot")) {
    try {
        $spiderFoot = Install-SpiderFoot
        $extraEnv["OSINT_SPIDERFOOT_DIR"] = $spiderFoot.Dir
        $extraEnv["OSINT_SPIDERFOOT_PYTHON"] = $spiderFoot.Python
    } catch {
        $failures.Add("spiderfoot: $($_.Exception.Message)")
    }
}

if ($selected.Contains("cobalt")) {
    try {
        if (Install-Cobalt) {
            $extraEnv["OSINT_COBALT_IMAGE"] = "ghcr.io/imputnet/cobalt:latest"
        }
    } catch {
        $failures.Add("cobalt: $($_.Exception.Message)")
    }
}

if (-not $SkipGhuntLogin.IsPresent -and $selected.Contains("ghunt")) {
    $ghunt = Join-Path $VenvPath "Scripts\ghunt.exe"
    if ((Test-Path -LiteralPath $ghunt) -and (Confirm-Step -Question "Run GHunt login now?" -DefaultYes $false)) {
        try {
            Invoke-External -File $ghunt -Arguments @("login")
        } catch {
            $failures.Add("ghunt login: $($_.Exception.Message)")
        }
    }
}

if (-not $venvPython) {
    $venvPython = Join-Path $VenvPath "Scripts\python.exe"
}
Write-LocalEnv -PythonExe $venvPython -BinDir $binDir -ExtraValues $extraEnv

Write-Host ""
Write-Host "Bad OSINT installer summary"
Write-Host "Tool root: $InstallRoot"
Write-Host "Python venv: $VenvPath"
Write-Host "Local config: .badosint.local.env"

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Some tools did not install:"
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host "All selected tool setup steps completed."
