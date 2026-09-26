param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$PrivateSource = '',
    [switch]$AuditOnly
)
$ErrorActionPreference = 'Stop'
function Fail([string]$Message){ Write-Error $Message; exit 1 }
$rootPath=[System.IO.Path]::GetFullPath($Root)
$treeTest=Join-Path $rootPath 'tests\host\test_public_tree.ps1'
$evidenceTest=Join-Path $rootPath 'tests\host\test_evidence_sanitization.ps1'
foreach($test in @($treeTest,$evidenceTest)){ if(-not(Test-Path -LiteralPath $test)){ Fail "Missing verifier dependency: $test" }; & 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File $test -Root $rootPath; if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE } }

$textExtensions=@('.md','.txt','.ps1','.py','.ino','.h','.cpp','.toml','.json','.properties','.kicad_pro','.kicad_sch','.kicad_sym','.kicad_mod')
$files=Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force
$checks=[ordered]@{
    'private path'=('(?i)(C:\\Use'+'rs\\|/Use'+'rs/|\.co'+'dex[\\/]|App'+'Data[\\/])')
    'email address'='(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
    'task ID'='(?i)\b01a[0-9a-f]{5,}-[0-9a-f-]{20,}\b'
    'student number'='(?i)student\s*(number|id)\s*[:#-]?\s*\d{6,}'
    'Bluetooth address'='(?i)\b(?!00:00:00:00:00:00)([0-9a-f]{2}:){5}[0-9a-f]{2}\b'
    'internal hardware label'='(?i)(module\s+B|sticker\s*`?0F)'
}
foreach($file in $files){
    $ext=[System.IO.Path]::GetExtension($file.Name).ToLowerInvariant()
    if($textExtensions -contains $ext -or $file.Name -in @('LICENSE','.gitignore')){$content=Get-Content -Raw -LiteralPath $file.FullName}else{continue}
    foreach($entry in $checks.GetEnumerator()){ if($content -match $entry.Value){ Fail "$($entry.Key) found in $([System.IO.Path]::GetRelativePath($rootPath,$file.FullName))" } }
}

$notices=Get-Content -Raw -LiteralPath (Join-Path $rootPath 'THIRD_PARTY_NOTICES.md')
foreach($token in @('Arduino_UNO.kicad_sym','ESP32_DOIT_30pin.kicad_sym','HC05_Carrier.kicad_sym')){if($notices -notmatch [regex]::Escape($token)){Fail "Missing attribution for $token"}}

$provenancePath=Join-Path $rootPath 'PROVENANCE.md'
if(-not(Test-Path -LiteralPath $provenancePath)){ Fail 'Missing PROVENANCE.md' }
$prov=Get-Content -Raw -LiteralPath $provenancePath
$allowed=Get-Content -LiteralPath (Join-Path $rootPath 'tools\public-allowlist.txt') | Where-Object { $_ -and -not $_.StartsWith('#') }
foreach($relative in $allowed | Where-Object { $_ -ne 'PROVENANCE.md' }){
    $normalized=$relative.Replace('\','/')
    $prefix='| `'+$normalized+'` |'
    $row=@(Get-Content -LiteralPath $provenancePath | Where-Object { $_.StartsWith($prefix) })
    if($row.Count -ne 1){ Fail "Missing provenance row for $relative" }
    $hash=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $rootPath $relative)).Hash.ToLowerInvariant()
    if($row[0] -notmatch [regex]::Escape('`'+$hash+'` |')){ Fail "Provenance hash mismatch for $relative" }
}
if(-not $AuditOnly){
    python (Join-Path $rootPath 'tests\evidence\verify_results.py'); if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    $oldOutput=$env:CAPSTONE_TEST_OUTPUT_DIR; $oldEnv=$env:UV_PROJECT_ENVIRONMENT; $oldUtf8=$env:PYTHONUTF8; $oldNoBytecode=$env:PYTHONDONTWRITEBYTECODE
    try{
        $env:UV_PROJECT_ENVIRONMENT=Join-Path ([System.IO.Path]::GetTempPath()) 'iot-capstone-public-venv'
        $env:PYTHONUTF8='1'
        $env:PYTHONDONTWRITEBYTECODE='1'
        foreach($item in @(
            @('loopback','tests\host\loopback\loopback_test.py'),
            @('protocol','tests\host\protocol\fuzz_protocol.py'),
            @('emulator','tests\host\arduino_emulator\arduino_emulator.py'),
            @('security','tests\host\security\security_analysis.py')
        )){
            $env:CAPSTONE_TEST_OUTPUT_DIR=Join-Path ([System.IO.Path]::GetTempPath()) ("iot-capstone-public-"+$item[0])
            $scriptPath=Join-Path $rootPath $item[1]
            if($item[0] -eq 'emulator'){ uv run --project $rootPath --frozen python $scriptPath --test }
            else { uv run --project $rootPath --frozen python $scriptPath }
            if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
        }
    } finally { $env:CAPSTONE_TEST_OUTPUT_DIR=$oldOutput; $env:UV_PROJECT_ENVIRONMENT=$oldEnv; $env:PYTHONUTF8=$oldUtf8; $env:PYTHONDONTWRITEBYTECODE=$oldNoBytecode }
    foreach($runner in @('tests\host\control_callback\run.ps1','tests\host\receiver_safety\run.ps1')){& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File (Join-Path $rootPath $runner); if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}}
    & 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File (Join-Path $rootPath 'tests\host\test_output_isolation.ps1') -Root $rootPath; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    & 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File $treeTest -Root $rootPath; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
}
Write-Output 'PUBLIC CANDIDATE VERIFIED'
