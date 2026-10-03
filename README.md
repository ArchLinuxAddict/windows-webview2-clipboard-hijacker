# Windows Crypto Clipboard Hijacker: Fake WebView2 `msedgeview.dll` (WPDShServiceObj COM Hijack)

A documented field report and detection toolkit for a Windows cryptocurrency **clipboard hijacker** ("clipper") that hides inside `explorer.exe` by masquerading as the Microsoft Edge WebView2 loader and persisting through a per-user **COM hijack of the legitimate WPDShServiceObj shell class**.

| | |
|---|---|
| **Platform** | Windows 11 (build 26200) |
| **Malware file planted** | 19 August 2026 |
| **Detected / removed** | 3 October 2026 |
| **Sample (SHA-256)** | `397f3ca8e8b3f8498e319e645eb8331478ed495f47ebb41d3d1faa9a5c30eec5` · [VirusTotal submission](https://www.virustotal.com/gui/file/397f3ca8e8b3f8498e319e645eb8331478ed495f47ebb41d3d1faa9a5c30eec5) |
| **AV detection** | Missed by a fully updated Bitdefender for ~2 months (Windows Defender was disabled by Bitdefender) |
| **Impact** | Cryptocurrency payments redirected to attacker wallets after copying an exchange deposit address |

> **If you are reading this because you lost funds:** report immediately to the receiving exchange/platform with the transaction ID and file a police/cybercrime report (in India: `cybercrime.gov.in` or call `1930`). Recoveries are rare and time-critical, but exchanges can sometimes freeze a receiving account. Move remaining funds using a clean device or hardware wallet, not the infected PC.

---

## TL;DR

- Every crypto address copied on the machine is silently replaced, within milliseconds, with the attacker's address for that coin (BTC, ETH, LTC, XMR).
- The malware persists as a **fake `%LOCALAPPDATA%\Microsoft\EdgeWebView\msedgeview.dll`** loaded into `explorer.exe` via a user-space COM hijack:
  `HKCU\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32`
- That CLSID is really **WPDShServiceObj** (legitimate server: `C:\WINDOWS\system32\wpdshserviceobj.dll`). `HKCU\Software\Classes` wins over `HKLM`, so Explorer loads the attacker's DLL on every start.
- Inside Explorer the DLL registers a hidden **message-only window of class `MsEdgeWV`** (impersonating WebView2), subscribes to clipboard updates, regex-matches wallet addresses and replaces them, using that hidden window as the clipboard owner.
- Killing Explorer stops the hijack; restarting Explorer brings it back until the registry key and file are removed.
- Detection and removal scripts are included in [`scripts/`](scripts).

## Behavior

| Copied address type | Replaced with (attacker) |
|---|---|
| BTC legacy `1...` | `bc1q00h2kl4uvwcvzp7zdl80yx97f0p8jv450qdzwc` |
| BTC bech32 `bc1...` | `bc1q00h2kl4uvwcvzp7zdl80yx97f0p8jv450qdzwc` |
| ETH `0x...` | `0xcEBDCBA0a42B2dE9Be38c48d648471C672C007C1` |
| LTC `L...` | `ltc1q36llsr6s3n4c8ur6g0prf8c9l0gs7ufwdakmng` |
| XMR `4...` | `8BEWfuRJwdjJ1cVwmgfH4bRh8Ki4NcAMeK7uGVfkqjivNnK8ZumjoMfGYyMyr6VE8YB96ZZSseacWFaQWbtXoQy5K2xCTJf` |

Observed characteristics:

- Swap occurs in **under 400 ms** after any clipboard change, including programmatic `SetClipboard` and real `Ctrl+C` from Notepad.
- The clipboard owner is a hidden window of class `MsEdgeWV` belonging to `explorer.exe`.
- Clipboard content is stable after Explorer is restarted **only if** the COM hijack is removed first; otherwise the payload reloads with Explorer.
- No plaintext attacker addresses were found in Explorer's memory or on disk scans — the payload stores its data obfuscated or fetches it remotely (a simple ASCII/UTF-16 string hunt fails).

## Execution chain

1. `explorer.exe` starts and instantiates the `WPDShServiceObj` shell service object (Windows Portable Devices shell integration).
2. COM class resolution checks `HKCU\Software\Classes\CLSID\...` **before** `HKLM\...`. The hijacked key points `InprocServer32` at the attacker DLL, so Windows loads it instead of `wpdshserviceobj.dll`.
3. The malicious DLL runs in-process inside `explorer.exe`, registers the hidden message-only class `MsEdgeWV` and begins monitoring `WM_CLIPBOARDUPDATE`.
4. When the clipboard contains a wallet address, the payload writes the attacker's per-coin address back to the clipboard using its hidden window as owner — so the clipboard appears to be owned by a legitimate-looking WebView2 component in Explorer.

## Indicators of Compromise (IOCs)

See [`IOCS.txt`](IOCS.txt). Summary:

**File**

```
%LOCALAPPDATA%\Microsoft\EdgeWebView\msedgeview.dll
```

- 34,816 bytes, attributes `Hidden` (`Hidden, Archive`)
- Folder contains **only** this file (a real WebView2 runtime installs many files under `...\EdgeWebView\Application\<version>\`)
- Unsigned, with **fabricated Microsoft Edge WebView2 version resources** (`Microsoft Edge WebView2 Loader`, `Microsoft Edge WebView2 Runtime Helper`, © Microsoft Corporation)
- SHA-256: `397f3ca8e8b3f8498e319e645eb8331478ed495f47ebb41d3d1faa9a5c30eec5`
- VirusTotal submission: <https://www.virustotal.com/gui/file/397f3ca8e8b3f8498e319e645eb8331478ed495f47ebb41d3d1faa9a5c30eec5>

**Registry**

```
HKCU\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32
  (default) = C:\Users\<user>\AppData\Local\Microsoft\EdgeWebView\msedgeview.dll
```

Legitimate value lives only in `HKLM` and points at `C:\WINDOWS\system32\wpdshserviceobj.dll`.

**Runtime**

- Hidden message-only window class `MsEdgeWV` (impersonates WebView2) owned by `explorer.exe`
- `explorer.exe` loading `msedgeview.dll` from `%LOCALAPPDATA%`

## Detection

Read-only checks — nothing is modified:

```powershell
# 1) Does the fake DLL exist?
Test-Path "$env:LOCALAPPDATA\Microsoft\EdgeWebView\msedgeview.dll"

# 2) Is the WPDShServiceObj class hijacked in HKCU?
Get-ItemProperty 'HKCU:\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32' -ErrorAction SilentlyContinue

# 3) Is the fake loader mapped into Explorer?
(Get-Process explorer).Modules | Where-Object { $_.FileName -match 'msedgeview|EdgeWebView' }
```

Included scripts (PowerShell 5.1+, run as your normal user):

| Script | Purpose |
|---|---|
| [`scripts/Check-WebView2Hijack.ps1`](scripts/Check-WebView2Hijack.ps1) | Checks all known IOCs of this hijacker (registry, file, hash, loaded modules, other HKCU CLSID overrides) |
| [`scripts/Test-ClipboardHijack.ps1`](scripts/Test-ClipboardHijack.ps1) | Canary test: places known test addresses on the clipboard and watches for silent replacement (this is how the malware was caught) |
| [`scripts/Scan-ClipboardMalware.ps1`](scripts/Scan-ClipboardMalware.ps1) | Broad triage: suspicious processes/autostarts/tasks/services/COM/WMI/browser and editor extensions/clipboard history |
| [`scripts/Remove-WebView2Hijack.ps1`](scripts/Remove-WebView2Hijack.ps1) | Targeted removal of this hijacker (hash-verified), restarts Explorer and re-tests the clipboard |

> Note: `Test-ClipboardHijack.ps1` modifies your clipboard during the test (it restores the previous text at the end).

## Removal

Manual steps (verify the IOCs first):

```powershell
# 1) Remove the COM hijack so Explorer cannot reload the payload
Remove-Item 'HKCU:\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}' -Recurse -Force

# 2) Restart Explorer (auto-restarts)
Stop-Process -Name explorer -Force

# 3) Delete the fake runtime folder (only exists if infected)
Remove-Item "$env:LOCALAPPDATA\Microsoft\EdgeWebView" -Recurse -Force

# 4) Confirm the hijack is gone (should print nothing)
Get-ItemProperty 'HKCU:\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32' -ErrorAction SilentlyContinue
```

Then re-run `Test-ClipboardHijack.ps1` — all canaries must stay unchanged. After cleanup:

1. Run a full antivirus scan (and a second-opinion scanner such as Malwarebytes; this sample was missed by Bitdefender).
2. Change important passwords and 2FA secrets from a **different, clean device**.
3. Treat anything copied on the machine before cleanup as compromised (addresses, tokens, credentials).
4. Consider a clean Windows reinstall if you cannot identify what installed it (the dropper was never found on the affected host).

## How this was discovered (methodology)

1. A canary test was built: known public test-vector wallet addresses were placed on the clipboard and polled for silent replacement. All five coin types were swapped instantly.
2. Clipboard owner tracing (`GetClipboardOwner` + window class/PID) showed the writes came from a hidden `MsEdgeWV` window in `explorer.exe`.
3. Suspending/vetting user apps (Discord client, emulator software, download manager, all third-party apps, clipboard service) did not stop the swap; restarting Explorer stopped it until the payload reloaded.
4. Registry auditing of `HKCU\Software\Classes\CLSID` found a user-space `InprocServer32` override of `WPDShServiceObj` pointing to the planted `msedgeview.dll`.
5. The DLL's strings and manifest confirmed WebView2 impersonation (including an embedded fake Microsoft assembly manifest and version info) and the `MsEdgeWV` class string.

## Timeline

- **2026-08-19 01:07** — malware folder and DLL created in `%LOCALAPPDATA%\Microsoft\EdgeWebView`
- **2026-10-03** — clipboard theft observed on the affected host (funds lost); canary test, owner tracing and COM audit identified the payload; registry hijack + DLL removed; clipboard verified clean, including after reboot

## Prevention

- Always verify a crypto address **on the receiving device/wallet screen**, not from the clipboard.
- Be suspicious of software that only ever appears in `%LOCALAPPDATA%` and of unsolicited "loaders"/"mods"/cracks — this class of malware is commonly bundled with them.
- Audit `HKCU\Software\Classes\CLSID` for `InprocServer32`/`LocalServer32` values pointing at user-writable paths (Autoruns does this well).
- A quick canary test after any risky download takes 30 seconds and catches this whole malware family.
- Keep an antivirus enabled and add a second-opinion scan periodically; no single engine caught this sample.

## Disclaimer

This repository is published for **defensive security research and victim awareness**. It contains **no malware sample** — only hashes, indicators and detection/removal scripts. The scripts are provided as-is; review them before running. `Remove-WebView2Hijack.ps1` only deletes the specific registry key and file documented above (hash-verified) and restarts Explorer.

## License

[MIT](LICENSE)
