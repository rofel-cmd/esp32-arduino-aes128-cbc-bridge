$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$source = Join-Path $PSScriptRoot 'receiver_safety_test.cpp'
$header = Join-Path $root 'firmware\arduino_slave\ReceiverSafety.h'
$receiver = Join-Path $root 'firmware\arduino_slave\arduino_slave.ino'
$wslRoot = "/tmp/capstone-safety-$PID"

function Send-BytesToWsl([byte[]]$Bytes, [string]$LinuxPath) {
    $base64 = [Convert]::ToBase64String($Bytes)
    & wsl.exe bash -lc "printf '%s' '$base64' | base64 -d > '$LinuxPath'"
    if ($LASTEXITCODE -ne 0) { throw "Unable to copy bytes into $LinuxPath." }
}

try {
    & wsl.exe bash -lc "mkdir -p '$wslRoot/tests/host/receiver_safety' '$wslRoot/firmware/arduino_slave'"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Send-BytesToWsl ([IO.File]::ReadAllBytes($source)) "$wslRoot/tests/host/receiver_safety/receiver_safety_test.cpp"
    Send-BytesToWsl ([IO.File]::ReadAllBytes($header)) "$wslRoot/firmware/arduino_slave/ReceiverSafety.h"
    Send-BytesToWsl ([IO.File]::ReadAllBytes($receiver)) "$wslRoot/firmware/arduino_slave/arduino_slave.ino"

    $build = @'
set -euo pipefail
cd '__ROOT__'
for std in c++11 c++17; do
  g++ -std=$std -Wall -Wextra -Wpedantic -Werror -O2 \
    -o "safety_$std" tests/host/receiver_safety/receiver_safety_test.cpp
done
output=$(./safety_c++17)
printf '%s\n' "$output"
count=$(printf '%s\n' "$output" | grep -c '^checks run: 14, failed: 0$' || true)
test "$count" -eq 1
'@
    $build = $build.Replace('__ROOT__', $wslRoot).Replace("`r", '')
    Send-BytesToWsl ([Text.Encoding]::UTF8.GetBytes($build)) "$wslRoot/run.sh"
    & wsl.exe bash "$wslRoot/run.sh"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (Select-String -Quiet -LiteralPath $receiver -Pattern 'entropyPin|extractEntropy|generateTRNG_Avalanche|randomSeed') {
        throw 'Obsolete receiver randomness found.'
    }
    Write-Output 'RECEIVER SAFETY HOST TEST OK'
}
finally {
    & wsl.exe bash -lc "rm -rf '$wslRoot'" | Out-Null
}
