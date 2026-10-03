param(
    [int]$MonitorSeconds = 8,
    [int]$PollMs = 200,
    [switch]$SkipNotepadTest
)

$ErrorActionPreference = 'Stop'

$canaries = [ordered]@{
    'BTC legacy' = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    'BTC bech32' = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    'ETH'        = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
    'LTC'        = 'LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9'
    'XMR'        = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A'
}

function Get-ClipText {
    try {
        $value = Get-Clipboard -Raw -ErrorAction Stop
        if ($null -eq $value) { return '' }
        return [string]$value
    } catch {
        return ''
    }
}

function Set-ClipText {
    param([string]$Text)
    Set-Clipboard -Value $Text
}

$originalClipboard = Get-ClipText
$alerts = New-Object System.Collections.Generic.List[string]

Write-Host ''
Write-Host '==== Clipboard hijack canary test ====' -ForegroundColor Cyan
Write-Host ("Each sample is placed on the clipboard and watched for {0}s ({1} ms polling)." -f $MonitorSeconds, $PollMs)
Write-Host 'Do not copy or paste anything while this test runs.'
Write-Host ''

$index = 0
foreach ($name in $canaries.Keys) {
    $index++
    $canary = $canaries[$name]
    Write-Host ("[{0}/{1}] {2}" -f $index, $canaries.Count, $name)
    Write-Host ("      written : {0}" -f $canary)

    Set-ClipText $canary
    Start-Sleep -Milliseconds 400
    $seen = Get-ClipText

    if ($seen.Trim() -ne $canary.Trim()) {
        $message = "{0}: replaced immediately. written='{1}' observed='{2}'" -f $name, $canary, $seen
        $alerts.Add($message)
        Write-Host ("      ALERT   : immediately replaced with -> {0}" -f $seen) -ForegroundColor Red
        continue
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $replaced = $false
    while ($stopwatch.Elapsed.TotalMilliseconds -lt ($MonitorSeconds * 1000)) {
        Start-Sleep -Milliseconds $PollMs
        $current = Get-ClipText
        if ($current.Trim() -ne $canary.Trim()) {
            $replaced = $true
            $message = "{0}: replaced after {1:n0} ms. written='{2}' observed='{3}'" -f $name, $stopwatch.Elapsed.TotalMilliseconds, $canary, $current
            $alerts.Add($message)
            Write-Host ("      ALERT   : replaced after {0:n0} ms with -> {1}" -f $stopwatch.Elapsed.TotalMilliseconds, $current) -ForegroundColor Red
            break
        }
    }
    if (-not $replaced) {
        Write-Host '      OK      : unchanged during observation window.' -ForegroundColor Green
    }
}

if (-not $SkipNotepadTest) {
    Write-Host ''
    Write-Host '==== Real copy test via Notepad (Ctrl+A, Ctrl+C) ====' -ForegroundColor Cyan

    $marker = 'CLIPBOARD-EMPTY-MARKER'
    $tmpFile = Join-Path $env:TEMP ('clipboard_canary_' + [guid]::NewGuid().ToString('N') + '.txt')
    Set-Content -LiteralPath $tmpFile -Value $canaries['BTC legacy']
    $notepad = Start-Process notepad.exe -ArgumentList $tmpFile -PassThru
    Start-Sleep -Milliseconds 1500

    Set-ClipText $marker
    $shell = New-Object -ComObject WScript.Shell
    $shell.SendKeys('^a')
    Start-Sleep -Milliseconds 250
    $shell.SendKeys('^c')
    Start-Sleep -Milliseconds 1000

    $copied = (Get-ClipText).Trim()
    if ($copied -eq $marker) {
        Write-Host '      SKIPPED : keystrokes did not reach Notepad (window focus), copy path not tested.' -ForegroundColor Yellow
    } elseif ($copied -eq $canaries['BTC legacy'].Trim()) {
        Write-Host '      OK      : Ctrl+C produced the exact address, watching for silent swap...' -ForegroundColor Green
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $replaced = $false
        while ($stopwatch.Elapsed.TotalMilliseconds -lt 6000) {
            Start-Sleep -Milliseconds $PollMs
            $current = Get-ClipText
            if ($current.Trim() -ne $canaries['BTC legacy'].Trim()) {
                $replaced = $true
                $message = "Notepad copy: replaced after {0:n0} ms. observed='{1}'" -f $stopwatch.Elapsed.TotalMilliseconds, $current
                $alerts.Add($message)
                Write-Host ("      ALERT   : replaced after {0:n0} ms with -> {1}" -f $stopwatch.Elapsed.TotalMilliseconds, $current) -ForegroundColor Red
                break
            }
        }
        if (-not $replaced) {
            Write-Host '      OK      : copied address stayed intact.' -ForegroundColor Green
        }
    } else {
        $message = "Notepad copy: clipboard did not contain the copied address. observed='{0}'" -f $copied
        $alerts.Add($message)
        Write-Host ("      ALERT   : Ctrl+C result differs from file content -> {0}" -f $copied) -ForegroundColor Red
    }

    Stop-Process -Id $notepad.Id -Force
    Remove-Item -LiteralPath $tmpFile -Force
}

if ($originalClipboard.Length -gt 0) {
    Set-ClipText $originalClipboard
}

Write-Host ''
if ($alerts.Count -gt 0) {
    Write-Host 'VERDICT: CLIPBOARD HIJACKING DETECTED' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Evidence (addresses your clipboard was swapped to):'
    foreach ($alert in $alerts) {
        Write-Host (' - ' + $alert) -ForegroundColor Red
    }
    Write-Host ''
    Write-Host 'Do NOT send crypto from this machine. Treat any wallet copied here as untrusted.'
} else {
    Write-Host 'VERDICT: no clipboard tampering observed in this test.' -ForegroundColor Green
    Write-Host 'Note: some hijackers activate only on specific triggers or after reboot; run the scan script too.'
}
