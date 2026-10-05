# Qoder Privacy Hardening Tool v2.0

Production-grade privacy auditing, telemetry neutralization, and hardening tools for the **[Qoder](https://qoder.com)** AI workbench (Windows & Linux / Ubuntu).

---

## Overview

By default, Qoder's worker runtime (`qoder-worker-runtime.obf.mjs`) transmits prompt metadata, code metrics, Git remote URLs, and session information to remote tracking endpoints.

This tool surgically neutralizes known telemetry sinks at the JavaScript runtime level before packets are constructed or dispatched, while keeping core AI coding and local agent capabilities completely functional.

### Neutralized Telemetry Vectors

| # | Signature / Vector | Target Endpoint | Description |
| :---: | :--- | :--- | :--- |
| **1** | `businessFinish.report` (`vLi`) | `https://api2.qoder.sh/algo/api/v2/service/business/finish` | Neutralizes session business reports and prompt leak pathways. |
| **2** | `codeStatistics.track` (`MTt`) | `https://center.qoder.sh/api/v1/tracking` | Disables code metrics, character generation counts, and token tracking. |
| **3** | `G$` Dispatcher | `https://center.qoder.sh/api/v1/tracking` | Blocks telemetry payloads transmitting local **Git remote URLs** and turn metadata. |
| **4** | `tvl` Transport Sink | `https://center.qoder.sh/api/v1/tracking` | Neutralizes the central network sink for `aiCodeTracking.report`. |

---

## Safety & Engineering Guarantees

Modifying minified runtime code carries risks if done naively. This tool was engineered with strict production safety constraints:

- **Exact Uniqueness Constraint (`count === 1`)**: Every signature to be replaced must match **exactly once** in the runtime file. If a signature matches zero times or multiple times, the tool immediately **fails closed** without touching the disk.
- **Cryptographic SHA-256 Verification**: Calculates SHA-256 hashes before and after every state transition to guarantee integrity.
- **Pre-Patch Rollback Backups**: Before modifying any bytes, an exact pre-patch backup (`*.bak.<timestamp>`) is created and verified by hash comparison.
- **Atomic File Swapping**: Patches are written to an isolated temporary file and swapped atomically (`os.replace` / atomic move) to prevent corrupted states during unexpected interruptions.
- **Post-Patch Verification with Auto-Rollback**: After swapping, the runtime state is re-evaluated. If the state is not 100% `HARDENED`, the original file is restored immediately.
- **Pre-Restore Safety Snapshots**: Restoring from a backup creates a `.safety.<timestamp>` snapshot of the current state before rolling back.

---

## Tested Environments

- **Qoder Versions**: `v0.4.3` (Stable)
- **Linux**: Ubuntu 22.04 / 24.04 LTS (x86_64, `/opt/Qoder`)
- **Windows**: Windows 10 / 11 (x64, `%LOCALAPPDATA%\Programs\Qoder`)

---

## Usage

### Linux / Ubuntu (`apply-qoder-privacy-patch.sh`)

The Linux script is a polyglot Bash/Python 3 launcher and works with standard Python 3.

#### 1. Interactive Menu
Run without arguments to access the interactive CLI:
```bash
sudo ./apply-qoder-privacy-patch.sh
```
Options available:
```
Choose an action:
  [1] Test / Verify privacy hardening status (read-only audit)
  [2] Dry-run simulation (validate patches & backup logic without modifying files)
  [3] Apply privacy hardening patches (auto-backup)
  [4] Restore from latest backup (with pre-restore safety snapshot)
  [5] Exit
```

#### 2. Command-Line Flags
- **Audit current status (read-only, no root needed)**:
  ```bash
  ./apply-qoder-privacy-patch.sh --test
  ```
- **Simulate patch & verify backup logic (zero disk writes)**:
  ```bash
  ./apply-qoder-privacy-patch.sh --dry-run
  ```
- **Apply hardening patch (requires root / sudo)**:
  ```bash
  sudo ./apply-qoder-privacy-patch.sh --apply
  ```
- **Restore original file from latest backup**:
  ```bash
  sudo ./apply-qoder-privacy-patch.sh --restore
  ```

---

### Windows (`apply-qoder-privacy-patch.bat`)

The Windows script is a self-elevating batch script that runs natively in PowerShell.

#### 1. Interactive Menu
Double-click `apply-qoder-privacy-patch.bat` or run in Command Prompt / PowerShell:
```cmd
apply-qoder-privacy-patch.bat
```

#### 2. Command-Line Flags
- **Audit current status**:
  ```cmd
  apply-qoder-privacy-patch.bat --test
  ```
- **Apply hardening patch**:
  ```cmd
  apply-qoder-privacy-patch.bat --apply
  ```
- **Restore from latest backup**:
  ```cmd
  apply-qoder-privacy-patch.bat --restore
  ```

---

## Verification Audit Output Example

When running `--test` (or option `1`), the tool reports the cryptographic status of each telemetry vector:

```text
================================================================================
                     QODER PRIVACY HARDENING TOOL v2.0                          
================================================================================
Qoder Root  : /opt/Qoder
Qoder Ver   : 0.4.3
Target File : /opt/Qoder/resources/app.asar.unpacked/node_modules/@qoder-ai/qoder-agent-sdk/dist/_worker/qoder-worker-runtime.obf.mjs

--- RUNNING PRIVACY VERIFICATION AUDIT ---

Qoder Version : 0.4.3
Runtime SHA256: 7B8392513FD3EEB0173DE2506FEC8FDD426CA1A6E97A0965F21D74256E1EEF9D
File Size     : 33191719 bytes
Runtime State : PRISTINE

Telemetry Vector Signatures:
--------------------------------------------------------------------------------
1. businessFinish.report (Prompt Leak)       : [EXPOSED / UNPATCHED]
   Endpoint: POST https://api2.qoder.sh/algo/api/v2/service/business/finish
2. codeStatistics.track (Code Metrics)       : [EXPOSED / UNPATCHED]
   Endpoint: POST https://center.qoder.sh/api/v1/tracking (code metrics)
3. G$ Dispatcher (Git Remote & Metadata)     : [EXPOSED / UNPATCHED]
   Endpoint: POST https://center.qoder.sh/api/v1/tracking (git_remote + turn metadata)
4. tvl Transport (Network Sink)              : [EXPOSED / UNPATCHED]
   Endpoint: POST https://center.qoder.sh/api/v1/tracking (transport sink)
--------------------------------------------------------------------------------

Backups Available: 0 (0 rollback point(s), 0 safety backup(s))

Summary & Assessment:
[AUDIT] Runtime is in PRISTINE original state. All telemetry code paths are active.
        Run with --apply (or option 3) to apply privacy hardening.
```

---

## Important Notes

1. **Restart Qoder After Patching**: After applying or restoring patches, restart Qoder or run `Developer: Reload Window` in Qoder for the changes to take effect.
2. **Application Updates**: When Qoder automatically or manually updates to a newer release, Electron replaces the `resources/app.asar.unpacked` folder. Run `--test` after any Qoder update to check if re-patching is necessary.

---

## Disclaimer

This project is an independent privacy hardening utility and is not affiliated with, endorsed by, or sponsored by Qoder or its developers. Use at your own discretion in compliance with your organization's privacy and software policies.

## License

MIT License. See [LICENSE](LICENSE) for details.
