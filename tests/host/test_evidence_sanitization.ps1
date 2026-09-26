param([string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = 'Stop'
function Fail([string]$Message) { Write-Error $Message; exit 1 }
$evidenceRoot = Join-Path ([System.IO.Path]::GetFullPath($Root)) 'tests\evidence'
$paths = @('september-08-boundaries.json','september-11-callback.json','september-14-six-command.json') | ForEach-Object { Join-Path $evidenceRoot $_ }
foreach($path in $paths) { if(-not (Test-Path -LiteralPath $path -PathType Leaf)){ Fail "Missing evidence file: $path" } }
$text = ($paths | ForEach-Object { Get-Content -Raw -LiteralPath $_ }) -join "`n"
$privateMac = ('98:da:50' + ':04:28:5e')
foreach($pattern in @(('(?i)' + [regex]::Escape($privateMac)),'(?i)COM\d+','(?i)sticker','(?i)C:\\Users','(?i)\.codex','(?i)@[a-z0-9.-]+\.[a-z]{2,}','(?i)01a[0-9a-f-]{20,}')) {
    if($text -match $pattern){ Fail "Prohibited evidence identifier matched: $pattern" }
}
$sep08 = Get-Content -Raw -LiteralPath $paths[0] | ConvertFrom-Json
if(($sep08.padding.plaintext_bytes -join ',') -ne '15,16,17'){ Fail 'Missing 15/16/17 padding observations.' }
if($sep08.sender_limit.accepted_bytes -ne 255 -or $sep08.sender_limit.refused_bytes -ne 256){ Fail 'Missing 255/256 sender boundary.' }
if($sep08.repeated_delivery.message_count -ne 3 -or -not $sep08.recovery.esp32_restart -or -not $sep08.recovery.receiver_power_cycle){ Fail 'Missing repeated-delivery or recovery observation.' }
$sep11 = Get-Content -Raw -LiteralPath $paths[1] | ConvertFrom-Json
if(-not $sep11.initial_attempt.timeout -or $sep11.later_matches.Count -ne 2){ Fail 'September 11 timeout and two later matches are required.' }
$sep14 = Get-Content -Raw -LiteralPath $paths[2] | ConvertFrom-Json
if(($sep14.commands.id -join ',') -ne 'FE3F76E4,FE3F76E5,FE3F76E6,FE3F76E7,FE3F76E8,FE3F76E9'){ Fail 'Unexpected September 14 command IDs.' }
if(($sep14.commands.rtt_ms -join ',') -ne '139,142,130,138,168,142'){ Fail 'Unexpected RTT series.' }
if(($sep14.commands.encryption_us_per_byte -join ',') -ne '3.09,0.44,0.47,0.44,0.47,0.47'){ Fail 'Unexpected encryption series.' }
if(($sep14.commands.decryption_us_per_byte -join ',') -ne '74.25,74.37,74.37,74.25,74.25,74.25'){ Fail 'Unexpected decryption series.' }
Write-Output 'EVIDENCE SANITIZATION OK'
