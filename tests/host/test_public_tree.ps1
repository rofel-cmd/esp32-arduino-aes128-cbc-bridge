param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$RequireNoGit
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

$rootPath = [System.IO.Path]::GetFullPath($Root)
$allowlistPath = Join-Path $rootPath 'tools\public-allowlist.txt'

if (-not (Test-Path -LiteralPath $allowlistPath -PathType Leaf)) {
    Fail "Missing allowlist: $allowlistPath"
}

if ($RequireNoGit -and (Test-Path -LiteralPath (Join-Path $rootPath '.git'))) {
    Fail 'Candidate must not contain .git before publication approval.'
}

$allowed = @(Get-Content -LiteralPath $allowlistPath | Where-Object {
    $_ -and -not $_.StartsWith('#')
} | ForEach-Object { $_.Replace('/', '\') })

$gitMetadataRoot = [System.IO.Path]::GetFullPath((Join-Path $rootPath '.git'))
$actual = @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force | Where-Object {
    -not $_.FullName.StartsWith($gitMetadataRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object {
    [System.IO.Path]::GetRelativePath($rootPath, $_.FullName)
})

$unexpected = @($actual | Where-Object { $_ -notin $allowed })
if ($unexpected.Count -gt 0) {
    Fail ("Unexpected files outside allowlist: " + ($unexpected -join ', '))
}

$forbiddenExtensions = @('.docx', '.pptx', '.zip')
$forbidden = @($actual | Where-Object {
    $forbiddenExtensions -contains [System.IO.Path]::GetExtension($_).ToLowerInvariant()
})
if ($forbidden.Count -gt 0) {
    Fail ("Private/generated document type present: " + ($forbidden -join ', '))
}

$configPath = Join-Path $rootPath 'firmware\libraries\CapstoneConfig\src\CapstoneConfig.h'
$esp32Path = Join-Path $rootPath 'firmware\esp32_master\esp32_master.ino'
$arduinoPath = Join-Path $rootPath 'firmware\arduino_slave\arduino_slave.ino'
foreach ($requiredPath in @($configPath, $esp32Path, $arduinoPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Fail "Missing public firmware file: $requiredPath"
    }
}

$config = Get-Content -Raw -LiteralPath $configPath
$esp32 = Get-Content -Raw -LiteralPath $esp32Path
$arduino = Get-Content -Raw -LiteralPath $arduinoPath
$combinedFirmware = "$config`n$esp32`n$arduino"

$privateAddressText = ('98:da:50' + ':04:28:5e')
if ($combinedFirmware -match '(?i)0x98\s*,\s*0xDA\s*,\s*0x50\s*,\s*0x04\s*,\s*0x28\s*,\s*0x5E' -or
    $combinedFirmware -match ('(?i)' + [regex]::Escape($privateAddressText))) {
    Fail 'Private HC-05 address is present in public firmware.'
}
$internalLabelPattern = '(?i)' + ('module' + '\s+B|sti' + 'cker\s*0F')
if ($combinedFirmware -match $internalLabelPattern) {
    Fail 'Internal hardware label is present in public firmware.'
}
if ($config -notmatch 'CAPSTONE_HC05_ADDRESS\s*\[\s*6\s*\].*\{\s*0x00\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00\s*\}') {
    Fail 'Public HC-05 address must default to six zero bytes.'
}
if ($esp32 -notmatch 'CAPSTONE_AES128_DEMO_KEY' -or $arduino -notmatch 'CAPSTONE_AES128_DEMO_KEY') {
    Fail 'Both production sketches must use the shared demonstration key.'
}
if ($config -notmatch '(?i)public demonstration value' -or $config -notmatch 'CAPSTONE_PAIRING_PIN') {
    Fail 'Public key and pairing PIN must be labelled as demonstration values.'
}

$requiredPublicFiles = @(
    'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md',
    'docs\protocol.md', 'docs\reproduction.md', 'docs\results.md', 'docs\limitations.md',
    'hardware\README.md', 'hardware\bom.md', 'hardware\schematic.pdf',
    'LICENSES\CC-BY-SA-4.0.txt', 'LICENSES\ESP32-SYMBOL-MIT.txt',
    'LICENSES\KICAD-LIBRARY-EXCEPTION.txt'
)
foreach ($relativePath in $requiredPublicFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $rootPath $relativePath) -PathType Leaf)) {
        Fail "Missing required public file: $relativePath"
    }
}

$readme = Get-Content -Raw -LiteralPath (Join-Path $rootPath 'README.md')
$security = Get-Content -Raw -LiteralPath (Join-Path $rootPath 'SECURITY.md')
$reproduction = Get-Content -Raw -LiteralPath (Join-Path $rootPath 'docs\reproduction.md')
$notices = Get-Content -Raw -LiteralPath (Join-Path $rootPath 'THIRD_PARTY_NOTICES.md')
if ($readme -notmatch '(?i)six[- ]command' -or $readme -notmatch '(?i)confidentiality') {
    Fail 'README must state the tested six-command claim and the confidentiality boundary.'
}
if ($security -notmatch '(?i)no authentication' -or $security -notmatch '(?i)no replay protection') {
    Fail 'SECURITY must state the authentication and replay boundaries.'
}
if ($reproduction -notmatch '(?i)your own HC-05 address') {
    Fail 'Reproduction instructions must require the user to supply an HC-05 address.'
}
foreach ($noticeToken in @('Arduino_UNO.kicad_sym', 'ESP32_DOIT_30pin.kicad_sym', 'HC05_Carrier.kicad_sym')) {
    if ($notices -notmatch [regex]::Escape($noticeToken)) {
        Fail "Missing third-party attribution for $noticeToken"
    }
}

Write-Output "PUBLIC TREE OK ($($actual.Count) files)"
