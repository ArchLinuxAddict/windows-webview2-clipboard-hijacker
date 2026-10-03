param(
    [switch]$Force
)

$iocHash = '397F3CA8E8B3F8498E319E645EB8331478ED495F47EBB41D3D1FAA9A5C30EEC5'
$clsid = '{AAA288BA-9A4C-45B0-95D7-94D524869DB5}'
$hkcuRoot = 'HKCU:\Software\Classes\CLSID\' + $clsid
$fakeDll = Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\msedgeview.dll'
$fakeDir = Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView'

Write-Host ''
Write-Host 'Removing WebView2 masquerading clipboard hijacker' -ForegroundColor Cyan
Write-Host ''

Write-Host 'Step 1: remove HKCU COM hijack'
if (Test-Path $hkcuRoot) {
    Remove-Item -LiteralPath $hkcuRoot -Recurse -Force
    Write-Host ('  removed: ' + $hkcuRoot)
    if (Test-Path $hkcuRoot) {
        Write-Host '  ERROR: key still present - run this script again' -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host '  key already absent'
}
Write-Host ''

Write-Host 'Step 2: restart explorer to unload the payload'
$oldExplorer = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
if ($oldExplorer) {
    Stop-Process -Id $oldExplorer.Id -Force
    $newExplorer = $null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 250
        $newExplorer = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($newExplorer -and $newExplorer.Id -ne $oldExplorer.Id) { break }
    }
    if (-not $newExplorer -or $newExplorer.Id -eq $oldExplorer.Id) {
        Start-Process explorer.exe
        Start-Sleep -Seconds 3
    }
    Write-Host '  explorer restarted'
} else {
    Write-Host '  explorer was not running'
}
Write-Host ''

Write-Host 'Step 3: delete the planted runtime file'
if (Test-Path -LiteralPath $fakeDll) {
    $hash = (Get-FileHash -LiteralPath $fakeDll -Algorithm SHA256).Hash
    Write-Host ('  found: ' + $fakeDll)
    Write-Host ('  sha256: ' + $hash)
    if ($hash -eq $iocHash -or $Force) {
        Remove-Item -LiteralPath $fakeDll -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $fakeDll) {
            Write-Host '  ERROR: file could not be deleted (still loaded?). Close extra Explorer windows and retry.' -ForegroundColor Red
        } else {
            Write-Host '  deleted'
        }
    } else {
        Write-Host '  REFUSED: hash does not match the IOC. Re-run with -Force only if you are sure.' -ForegroundColor Yellow
        exit 1
    }
    if ((Test-Path -LiteralPath $fakeDir) -and -not (Get-ChildItem -LiteralPath $fakeDir -Force -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $fakeDir -Force -ErrorAction SilentlyContinue
        Write-Host '  removed empty folder'
    }
} else {
    Write-Host ('  not present: ' + $fakeDll)
}
Write-Host ''

Write-Host 'Step 4: verify'
Write-Host ('  HKCU hijack key present: ' + (Test-Path $hkcuRoot))
Write-Host ('  fake DLL present      : ' + (Test-Path -LiteralPath $fakeDll))
$loaded = (Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).Modules | Where-Object { $_.FileName -match 'msedgeview|EdgeWebView' }
if ($loaded) {
    foreach ($module in $loaded) { Write-Host ('  still loaded: ' + $module.FileName) -ForegroundColor Yellow }
} else {
    Write-Host '  no EdgeWebView module loaded in explorer'
}
Write-Host ''

Write-Host 'Step 5: clipboard canary test'
$canaries = @(
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    'LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9',
    '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A'
)
$allClean = $true
foreach ($canary in $canaries) {
    Set-Clipboard $canary
    Start-Sleep -Milliseconds 800
    $seen = Get-Clipboard -Raw
    $clean = ($seen.Trim() -eq $canary.Trim())
    if (-not $clean) { $allClean = $false }
    Write-Host ("  {0,-12} {1}" -f $(if ($clean) { 'CLEAN' } else { 'HIJACKED' }), $canary)
}
Write-Host ''

if ($allClean) {
    Write-Host 'RESULT: clipboard is CLEAN - hijacker removed.' -ForegroundColor Green
} else {
    Write-Host 'RESULT: clipboard still being hijacked - do not use this machine for crypto.' -ForegroundColor Red
    exit 1
}
