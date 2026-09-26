param([string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = 'Stop'
$verifier = Join-Path $Root 'tools\verify_public_repository.ps1'
if(-not (Test-Path -LiteralPath $verifier)){ throw 'Verifier implementation is missing.' }

function Invoke-Defect([string]$Name, [scriptblock]$Mutate, [string]$Expected) {
    $fixture = Join-Path ([System.IO.Path]::GetTempPath()) ("capstone-verifier-$Name-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $fixture | Out-Null
    try {
        $allowed = Get-Content -LiteralPath (Join-Path $Root 'tools\public-allowlist.txt') | Where-Object { $_ -and -not $_.StartsWith('#') }
        foreach($relative in $allowed){
            $src=Join-Path $Root $relative; if(Test-Path -LiteralPath $src -PathType Leaf){$dst=Join-Path $fixture $relative; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst)|Out-Null; Copy-Item -LiteralPath $src -Destination $dst}
        }
        & $Mutate $fixture
        $output = & 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File $verifier -Root $fixture -AuditOnly 2>&1 | Out-String
        if($LASTEXITCODE -eq 0){ throw "Defect '$Name' was accepted." }
        if($output -notmatch [regex]::Escape($Expected)){ throw "Defect '$Name' did not name '$Expected'. Output: $output" }
    } finally { if(Test-Path -LiteralPath $fixture){ Remove-Item -LiteralPath $fixture -Recurse -Force } }
}

Invoke-Defect 'unlisted' { param($p) Set-Content -LiteralPath (Join-Path $p 'UNLISTED.txt') -Value 'x' } 'allowlist'
Invoke-Defect 'private-path' { param($p) Add-Content -LiteralPath (Join-Path $p 'README.md') -Value (('C'+':')+'\Users\Someone\private') } 'private path'
Invoke-Defect 'email' { param($p) Add-Content -LiteralPath (Join-Path $p 'README.md') -Value ('person'+'@'+'example.com') } 'email address'
Invoke-Defect 'task-id' { param($p) Add-Content -LiteralPath (Join-Path $p 'README.md') -Value ('01a08d9b'+'-35db-7573-9d19-3927c00dd1af') } 'task ID'
Invoke-Defect 'student' { param($p) Add-Content -LiteralPath (Join-Path $p 'README.md') -Value ('student num'+'ber 123456789') } 'student number'
Invoke-Defect 'mac' { param($p) Add-Content -LiteralPath (Join-Path $p 'README.md') -Value ('98:da:50'+':04:28:5e') } 'Bluetooth address'
Invoke-Defect 'provenance' { param($p) $x=Get-Content -LiteralPath (Join-Path $p 'PROVENANCE.md'); $x | Where-Object { $_ -notmatch 'README\.md' } | Set-Content -LiteralPath (Join-Path $p 'PROVENANCE.md') } 'provenance row'
Invoke-Defect 'attribution' { param($p) (Get-Content -Raw -LiteralPath (Join-Path $p 'THIRD_PARTY_NOTICES.md')).Replace('HC05_Carrier.kicad_sym','removed') | Set-Content -LiteralPath (Join-Path $p 'THIRD_PARTY_NOTICES.md') } 'attribution'
Write-Output 'PUBLIC VERIFIER FIXTURES OK (8 defects rejected)'
