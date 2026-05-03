$helpArgs = @("-h", "--help", "-Help", "/?")

foreach ($arg in $args) {
    if ($helpArgs -contains $arg) {
        & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\scripts\start-all.ps1" -Help
        exit $LASTEXITCODE
    }
}

$forwardArgs = @($args)
if ($forwardArgs -notcontains "-StopExisting") {
    $forwardArgs += "-StopExisting"
}
if ($forwardArgs -notcontains "-AutoPort") {
    $forwardArgs += "-AutoPort"
}

& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\scripts\start-all.ps1" @forwardArgs
exit $LASTEXITCODE
