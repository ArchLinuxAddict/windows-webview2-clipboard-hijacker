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
- The replacement addresses are stored **encrypted inside the DLL itself** — the sample has no network capability at all (no C2). The full **23-address, 23-chain pool** was recovered during reverse engineering: see [`iocs/attacker-address-pool.txt`](iocs/attacker-address-pool.txt).

## Execution chain

1. `explorer.exe` starts and instantiates the `WPDShServiceObj` shell service object (Windows Portable Devices shell integration).
2. COM class resolution checks `HKCU\Software\Classes\CLSID\...` **before** `HKLM\...`. The hijacked key points `InprocServer32` at the attacker DLL, so Windows loads it instead of `wpdshserviceobj.dll`.
3. The malicious DLL runs in-process inside `explorer.exe`, registers the hidden message-only class `MsEdgeWV` and begins monitoring `WM_CLIPBOARDUPDATE`.
4. When the clipboard contains a wallet address, the payload writes the attacker's per-coin address back to the clipboard using its hidden window as owner — so the clipboard appears to be owned by a legitimate-looking WebView2 component in Explorer.

## Reverse engineering summary

The recovered DLL was analyzed statically (no execution). Key findings:

- **Type:** x64 COM DLL (linker 14.0), **PE timestamp zeroed** and no Rich header (anti-forensics), exports `DllGetClassObject` plus an unnamed ordinal that simply loops on `Sleep` forever when called (decoy).
- **API resolution:** the import table contains only decoys. All real APIs are resolved manually from `kernelbase` / `user32` / `ntdll` / `rpcrt4` exports using a **custom 32-bit name-hash**:

  ```
  h = 0xDbbc8e2d
  for each byte c of the export name:
      h = (h ^ c) * 0x23FA97F3
  h ^= h >> 15;  h *= 0x93DC8BD1
  h ^= h >> 13;  h *= 0xAC5DF4E3
  h ^= h >> 16
  ```

  All **43** hash constants were cracked. They cover the complete clipboard pipeline (`RegisterClassExA`, `CreateWindowExA`, `AddClipboardFormatListener`, `PeekMessageA`, `DispatchMessageA`, `MsgWaitForMultipleObjects`, `GetClipboardSequenceNumber`, `IsClipboardFormatAvailable`, `OpenClipboard`, `GetClipboardData`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`, `GlobalAlloc/GlobalLock/GlobalUnlock/GlobalFree`), plus registry writes (`NtCreateKey`, `NtSetValueKey`), loading (`LoadLibraryA`, `GetModuleFileNameA`, `GetSystemDirectoryA`, `LdrAddRefDll`), threading (`CreateThread`, `CreateMutexA`), anti-debug (`IsDebuggerPresent`) and fingerprinting APIs.
- **String encryption:** XOR `0x93` (helper at RVA `0x4EA0`). Decrypts to `wpdshserviceobj.dll`, `Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32`, `ThreadingModel`, `Both`, and the fake WebView2 log strings.
- **Config encryption:** two xorshift32-keystream decryptors (RVA `0x3B30` and `0x4DF0`). The first decrypts the single-instance mutex `Local\{8F6E2A14-C9D1-4bdd-B8CF-92F04E6B3E9F}`; the second decrypts a **1088-byte blob** containing the attacker's **23-address multi-chain replacement pool** (BTC, ETH/EVM, LTC, BCH, Dash, Doge, DigiByte, Cardano, Cosmos, MultiversX, Zcash, Ravencoin, Qtum, XRP, Algorand, Monero, TRON, Stellar, Solana, Tezos, Zilliqa, Polkadot, Kusama). The pool is split using the malware's own embedded lengths table (sum = 1088 exactly).
- **Self-install:** the payload writes its own COM hijack key (`Software\Classes\CLSID\{AAA288BA-...}\InprocServer32`, `ThreadingModel = Both`) through `NtCreateKey`/`NtSetValueKey` — it re-creates its persistence whenever it runs.
- **COM camouflage:** `DllGetClassObject` loads the genuine `C:\Windows\System32\wpdshserviceobj.dll` and forwards to `rpcrt4!DllGetClassObject`, so Explorer's COM call behaves normally while the malicious worker thread is spawned from `DllMain`.
- **No C2:** there are no networking APIs anywhere in the sample; the entire address pool is static. The campaign relies purely on replacement, not on remote control.

No public family name was found for this sample: the mutex GUID, hash constants and decryptor constants produced no threat-intel matches, so it currently appears to be a private/custom build. The strongest tracking leads are the address pool (on-chain) and the unique fingerprints above (for finding related samples).

## On-chain footprint (as of 2026-10-03)

Both collector wallets are self-custody addresses reused across all victims of this sample, so every victim's evidence links into the same trace.

**BTC collector** `bc1q00h2kl4uvwcvzp7zdl80yx97f0p8jv450qdzwc`

- 88 incoming payments since 2026-02-05, ~0.0851 BTC (≈ $9k) received; only one spend so far
- The single cash-out (2026-03-12, tx [`0c79c43e...23a6a0b4`](https://mempool.space/tx/0c79c43ec2a64ca4e6c75153439222958b322348c13e0218eb60555d23a6a0b4)) sent 28,951 sats to `bc1q6pttrr6ezjgg423tuz5xdgy2nnnvxfcujqqe9z`, whose UTXO was later merged as input #850 of a large batched consolidation transaction [`c5fbfe0d...809e26`](https://mempool.space/tx/c5fbfe0d80015f8e6c8bb31bd345f003add00154923d4c17a29332e48f809e26) - the pattern of an exchange/service hot-wallet sweep, and the strongest KYC lead for law enforcement
- Remaining balance: ~0.0819 BTC

**ETH collector** `0xcEBDCBA0a42B2dE9Be38c48d648471C672C007C1`

- 349 transactions / 341 deposits since 2026-02-05; current balance ≈ 1.29 ETH; only 8 spends
- Explorer: <https://etherscan.io/address/0xcEBDCBA0a42B2dE9Be38c48d648471C672C007C1>

Reporting these addresses to exchanges and to Chainabuse gets them flagged, so that any later cash-out into a KYC venue can be traced or frozen if a police report is on file.

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
