$phpDir = "C:\Users\dmbs3\AppData\Local\Microsoft\WinGet\Packages\PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe"
$iniSrc = Join-Path $phpDir "php.ini-development"
$iniDst = Join-Path $phpDir "php.ini"
$extDir = Join-Path $phpDir "ext"

Copy-Item $iniSrc $iniDst -Force

$content = Get-Content $iniDst -Raw
$content = $content -replace '(?m)^;extension=openssl', 'extension=openssl'
$content = $content -replace '(?m)^;extension=curl', 'extension=curl'
$content = $content -replace '(?m)^;extension=mbstring', 'extension=mbstring'
$content = $content -replace '(?m)^;extension=xmlrpc', 'extension=xmlrpc'
$content = $content -replace '(?m)^; extension_dir = "ext"', "extension_dir = `"$extDir`""
$content | Set-Content $iniDst -Encoding UTF8 -NoNewline

Write-Host "php.ini configured at: $iniDst"
& (Join-Path $phpDir "php.exe") -m 2>&1 | Select-String "openssl|curl|mbstring|xml"
