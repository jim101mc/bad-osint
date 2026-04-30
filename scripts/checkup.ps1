param(
    [switch]$ProbeHttp,
    [switch]$RequireHttp,
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [int]$HttpTimeoutSec = 4,
    [int]$LogLookbackMinutes = 30,
    [int]$LogTailLines = 300
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Set-Location $root

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet("PASS", "WARN", "FAIL")] [string]$Status,
        [string]$Detail
    )
    $results.Add([pscustomobject]@{
            Name = $Name
            Status = $Status
            Detail = $Detail
        })
}

function Run-Check {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        & $Action
        Add-Result -Name $Name -Status "PASS" -Detail "OK"
    } catch {
        Add-Result -Name $Name -Status "FAIL" -Detail $_.Exception.Message
    }
}

Run-Check -Name "Java compile" -Action {
    & "$PSScriptRoot\compile.ps1"
}

Run-Check -Name "Python syntax" -Action {
    python -m py_compile "services/enricher/enricher.py" "services/enricher/connectors.py"
}

Run-Check -Name "Frontend syntax" -Action {
    node --check "web/app.js"
}

function Scan-LogForSignatures {
    param(
        [string]$Path,
        [string[]]$Patterns,
        [datetime]$RecentCutoffUtc,
        [int]$TailLines
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Result -Name "Log scan: $Path" -Status "WARN" -Detail "Log file not found."
        return
    }

    $item = Get-Item -LiteralPath $Path
    $tail = Get-Content -LiteralPath $Path -Tail ([Math]::Max(50, $TailLines))
    $hits = @()
    foreach ($line in $tail) {
        foreach ($pattern in $Patterns) {
            if ($line -match $pattern) {
                $hits += $line.Trim()
                break
            }
        }
    }

    $isRecent = $item.LastWriteTimeUtc -ge $RecentCutoffUtc
    if ($hits.Count -gt 0) {
        $sample = ($hits | Select-Object -Unique | Select-Object -First 3) -join " | "
        if ($isRecent) {
            Add-Result -Name "Log scan: $Path" -Status "FAIL" -Detail "Recent critical signature found: $sample"
        } else {
            Add-Result -Name "Log scan: $Path" -Status "WARN" -Detail (
                "Historical critical signature found outside $LogLookbackMinutes-minute window " +
                "(last update $($item.LastWriteTime.ToString('s'))): $sample"
            )
        }
    } else {
        Add-Result -Name "Log scan: $Path" -Status "PASS" -Detail "No critical signatures in last $([Math]::Max(50, $TailLines)) lines."
    }
}

$criticalPatterns = @(
    "Address already in use",
    "BindException",
    "Traceback \(most recent call last\)",
    "Exception in thread ""main""",
    "could not connect",
    "FATAL:"
)
$recentCutoffUtc = (Get-Date).ToUniversalTime().AddMinutes(-1 * [Math]::Abs($LogLookbackMinutes))

Scan-LogForSignatures -Path "logs\api.err.log" -Patterns $criticalPatterns -RecentCutoffUtc $recentCutoffUtc -TailLines $LogTailLines
Scan-LogForSignatures -Path "logs\enricher.err.log" -Patterns $criticalPatterns -RecentCutoffUtc $recentCutoffUtc -TailLines $LogTailLines

if ($ProbeHttp -or $RequireHttp) {
    $paths = @("/health", "/", "/assets/app.js")
    foreach ($path in $paths) {
        $url = "$BaseUrl$path"
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $HttpTimeoutSec
            if ($response.StatusCode -eq 200) {
                Add-Result -Name "HTTP $path" -Status "PASS" -Detail "200 OK"
            } else {
                $detail = "Expected 200, got $($response.StatusCode)"
                if ($RequireHttp) {
                    Add-Result -Name "HTTP $path" -Status "FAIL" -Detail $detail
                } else {
                    Add-Result -Name "HTTP $path" -Status "WARN" -Detail $detail
                }
            }
        } catch {
            $detail = "Endpoint unavailable: $url"
            if ($RequireHttp) {
                Add-Result -Name "HTTP $path" -Status "FAIL" -Detail $detail
            } else {
                Add-Result -Name "HTTP $path" -Status "WARN" -Detail $detail
            }
        }
    }
} else {
    Add-Result -Name "HTTP probes" -Status "WARN" -Detail "Skipped. Use -ProbeHttp or -RequireHttp to enable endpoint checks."
}

Write-Host ""
Write-Host "OSINT Project Checkup Summary"
Write-Host "Workspace: $root"
Write-Host ("-" * 72)
$results | Format-Table -AutoSize

$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count
$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count

Write-Host ("-" * 72)
Write-Host "PASS: $passCount  WARN: $warnCount  FAIL: $failCount"

if ($failCount -gt 0) {
    exit 1
}
exit 0
