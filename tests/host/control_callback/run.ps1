$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$source = Join-Path $PSScriptRoot 'control_callback_test.cpp'
$header = Join-Path $root 'firmware\libraries\ControlProtocol\src\ControlProtocol.h'
$wslRoot = "/tmp/capstone-control-$PID"

function Send-BytesToWsl([byte[]]$Bytes, [string]$LinuxPath) {
    $base64 = [Convert]::ToBase64String($Bytes)
    & wsl.exe bash -lc "printf '%s' '$base64' | base64 -d > '$LinuxPath'"
    if ($LASTEXITCODE -ne 0) { throw "Unable to copy bytes into $LinuxPath." }
}

try {
    & wsl.exe bash -lc "mkdir -p '$wslRoot/tests/host/control_callback' '$wslRoot/firmware/libraries/ControlProtocol/src'"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Send-BytesToWsl ([IO.File]::ReadAllBytes($source)) "$wslRoot/tests/host/control_callback/control_callback_test.cpp"
    Send-BytesToWsl ([IO.File]::ReadAllBytes($header)) "$wslRoot/firmware/libraries/ControlProtocol/src/ControlProtocol.h"

    $build = @'
set -euo pipefail
cd '__ROOT__'
for std in c++11 c++17; do
  g++ -std=$std -Wall -Wextra -Wpedantic -Werror -O2 \
    -o "control_$std" tests/host/control_callback/control_callback_test.cpp
done
output=$(./control_c++17)
printf '%s\n' "$output"
count=$(printf '%s\n' "$output" | grep -c '^checks run: 55, failed: 0$' || true)
test "$count" -eq 1
'@
    $build = $build.Replace('__ROOT__', $wslRoot).Replace("`r", '')
    Send-BytesToWsl ([Text.Encoding]::UTF8.GetBytes($build)) "$wslRoot/run.sh"
    & wsl.exe bash "$wslRoot/run.sh"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output 'CONTROL CALLBACK HOST TEST OK'
}
finally {
    & wsl.exe bash -lc "rm -rf '$wslRoot'" | Out-Null
}
