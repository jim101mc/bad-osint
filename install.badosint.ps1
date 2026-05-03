$helpArgs = @("-h", "--help", "-Help", "/?")

foreach ($arg in $args) {
    if ($helpArgs -contains $arg) {
        & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\scripts\install-tools.ps1" -Help
        exit $LASTEXITCODE
    }
}

& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\scripts\install-tools.ps1" @args
exit $LASTEXITCODE
