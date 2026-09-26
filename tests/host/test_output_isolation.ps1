$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$protocolDir = Join-Path $PSScriptRoot 'protocol'
$outputDir = Join-Path ([System.IO.Path]::GetTempPath()) ("capstone-output-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $outputDir | Out-Null

$before = @(Get-ChildItem -LiteralPath $protocolDir -File | Select-Object -ExpandProperty Name)
$oldOutput = $env:CAPSTONE_TEST_OUTPUT_DIR
$oldUtf8 = $env:PYTHONUTF8
$oldProjectEnvironment = $env:UV_PROJECT_ENVIRONMENT
$oldNoBytecode = $env:PYTHONDONTWRITEBYTECODE
try {
    $env:CAPSTONE_TEST_OUTPUT_DIR = $outputDir
    $env:PYTHONUTF8 = '1'
    $env:UV_PROJECT_ENVIRONMENT = Join-Path ([System.IO.Path]::GetTempPath()) 'iot-capstone-public-venv'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    & uv run --project $root --frozen python (Join-Path $protocolDir 'fuzz_protocol.py')
    if ($LASTEXITCODE -ne 0) { throw "Protocol test exited $LASTEXITCODE" }

    $after = @(Get-ChildItem -LiteralPath $protocolDir -File | Select-Object -ExpandProperty Name)
    $newSourceFiles = @($after | Where-Object { $_ -notin $before })
    if ($newSourceFiles.Count -gt 0) {
        throw "Protocol test wrote into the source tree: $($newSourceFiles -join ', ')"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $outputDir 'protocol_test_report.md'))) {
        throw 'Protocol test did not write its report to CAPSTONE_TEST_OUTPUT_DIR.'
    }
    Write-Output 'TEST OUTPUT ISOLATION OK'
}
finally {
    Get-ChildItem -LiteralPath $protocolDir -File | Where-Object {
        $_.Name -notin $before
    } | Remove-Item -Force
    Remove-Item -LiteralPath $outputDir -Recurse -Force -ErrorAction SilentlyContinue
    $env:CAPSTONE_TEST_OUTPUT_DIR = $oldOutput
    $env:PYTHONUTF8 = $oldUtf8
    $env:UV_PROJECT_ENVIRONMENT = $oldProjectEnvironment
    $env:PYTHONDONTWRITEBYTECODE = $oldNoBytecode
}
