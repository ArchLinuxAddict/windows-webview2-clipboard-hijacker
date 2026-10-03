param()

$iocHash = '397F3CA8E8B3F8498E319E645EB8331478ED495F47EBB41D3D1FAA9A5C30EEC5'
$clsid = '{AAA288BA-9A4C-45B0-95D7-94D524869DB5}'
$hkcuRoot = 'HKCU:\Software\Classes\CLSID\' + $clsid
$hkcuKey = Join-Path $hkcuRoot 'InprocServer32'
$hklmKey = 'HKLM:\SOFTWARE\Classes\CLSID\' + $clsid + '\InprocServer32'
$fakeDll = Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\msedgeview.dll'

$findings = New-Object System.Collections.Generic.List[string]

Write-Host ''
Write-Host 'WebView2 masquerading clipboard hijacker - IOC check' -ForegroundColor Cyan
Write-Host ('IOC SHA256: ' + $iocHash)
Write-Host ''

Write-Host 'HKCU WPDShServiceObj override:'
if (Test-Path $hkcuRoot) {
    $value = (Get-ItemProperty -Path $hkcuKey -ErrorAction SilentlyContinue).'(default)'
    $findings.Add(('HKCU override present: ' + $value))
    Write-Host ('  [SUSPECT] key exists: ' + $hkcuKey) -ForegroundColor Red
    Write-Host ('  [SUSPECT] value      : ' + $value) -ForegroundColor Red
} else {
    Write-Host '  [ok] no HKCU override' -ForegroundColor Green
}
$legit = (Get-ItemProperty -Path $hklmKey -ErrorAction SilentlyContinue).'(default)'
Write-Host ('  [info] legitimate HKLM server: ' + $legit)
Write-Host ''

Write-Host 'Fake runtime file:'
if (Test-Path -LiteralPath $fakeDll) {
    $item = Get-Item -LiteralPath $fakeDll -Force
    $hash = (Get-FileHash -LiteralPath $fakeDll -Algorithm SHA256).Hash
    $matchesIOC = ($hash -eq $iocHash)
    $findings.Add(('Fake msedgeview.dll present: ' + $fakeDll + ' sha256=' + $hash))
    Write-Host ('  [SUSPECT] ' + $fakeDll) -ForegroundColor Red
    Write-Host ('  [SUSPECT] size=' + $item.Length + ' attributes=' + $item.Attributes)
    Write-Host ('  [SUSPECT] sha256=' + $hash + ' matchesIOC=' + $matchesIOC)
} else {
    Write-Host ('  [ok] not present: ' + $fakeDll) -ForegroundColor Green
}
Write-Host ''

Write-Host 'Other HKCU CLSID entries pointing at msedgeview/EdgeWebView:'
$other = 0
foreach ($entry in (Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue)) {
    foreach ($server in @('InprocServer32', 'LocalServer32')) {
        $value = (Get-ItemProperty -Path (Join-Path $entry.PSPath $server) -ErrorAction SilentlyContinue).'(default)'
        if ($value -and $value -match 'msedgeview|EdgeWebView') {
            $other++
            $findings.Add(('HKCU CLSID ' + $entry.PSChildName + ' -> ' + $value))
            Write-Host ('  [SUSPECT] ' + $entry.PSChildName + ' -> ' + $value) -ForegroundColor Red
        }
    }
}
if ($other -eq 0) { Write-Host '  [ok] none' -ForegroundColor Green }
Write-Host ''

Write-Host 'Modules loaded in explorer.exe from EdgeWebView paths:'
$explorer = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
if ($explorer) {
    $loaded = $explorer.Modules | Where-Object { $_.FileName -match 'msedgeview|EdgeWebView' }
    if ($loaded) {
        foreach ($module in $loaded) {
            $findings.Add(('Loaded in explorer: ' + $module.FileName))
            Write-Host ('  [SUSPECT] ' + $module.FileName) -ForegroundColor Red
        }
    } else {
        Write-Host '  [ok] none' -ForegroundColor Green
    }
} else {
    Write-Host '  [info] explorer.exe not running'
}
Write-Host ''

if ($findings.Count -eq 0) {
    Write-Host 'RESULT: no indicators of this hijacker found.' -ForegroundColor Green
} else {
    Write-Host ('RESULT: ' + $findings.Count + ' indicator(s) found. Run Remove-WebView2Hijack.ps1 to clean.') -ForegroundColor Red
}
