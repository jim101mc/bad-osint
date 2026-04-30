$ErrorActionPreference = "Stop"

if (Test-Path out) {
    Remove-Item out -Recurse -Force
}

New-Item -ItemType Directory -Path out | Out-Null
$sources = Get-ChildItem -Path src/main/java -Recurse -Filter *.java | ForEach-Object { $_.FullName }

if (-not $sources) {
    throw "No Java sources found."
}

javac -d out $sources
Write-Host "Compiled $($sources.Count) Java source files into out/"
