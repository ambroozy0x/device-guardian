# Device Guardian — Recovery & Backup Guide

This document describes the atomic persistence model, disaster recovery mechanisms, installation validation, and manual backup/restore procedures for Device Guardian.

---

## 1. Atomic Persistence Architecture

Device Guardian writes state and transaction records non-destructively to prevent corruption during sudden power loss or process interruption:

- **Implementation**: [`device_guardian.recovery.persistence.AtomicPersistence`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/recovery/persistence.py)

### Write Protocol
1. **Staging File**: Data is first serialized to a unique temporary file (`<target>.tmp.<uuid>`) in the same filesystem directory to guarantee same-volume operations.
2. **Flush & Sync**: The temporary file descriptor is explicitly flushed and synced (`os.fsync`) to physical disk.
3. **Atomic Replace**: The file is atomically renamed to the final destination name (`os.replace`).
4. **Retry Loop with Windows Fallback**: On Windows platforms where file locks or antivirus scans may briefly hold open handles, the rename operation executes within an exponential-backoff retry loop.

---

## 2. Automatic State Repair & Integrity

### Corrupted State Repair (`--repair-state`)
If an unexpected operating system failure corrupts `runtime_status.json` or `update_transaction.json`:
- Device Guardian **never silently discards data**.
- The corrupted file is preserved alongside as `<filename>.corrupt.<YYYYMMDD_HHMMSS>`.
- A valid, clean baseline JSON structure is created atomically.

### Installation Integrity Verification (`--verify-installation`)
Verifies that:
1. The executable artifact exists and is readable.
2. If running as a frozen distribution (`dist/DeviceGuardian.exe`), the SHA-256 hash of the binary is compared against `release-manifest.json`.
3. Required runtime and user data directories exist with appropriate read/write permissions.

---

## 3. Recovery CLI Commands

Operators can query health and invoke repair utilities directly:

```powershell
# Inspect overall recovery subsystem and file health
python -m device_guardian.main --recovery-status

# Non-destructively repair corrupted state files
python -m device_guardian.main --repair-state

# Verify physical binary and filesystem integrity
python -m device_guardian.main --verify-installation

# Repair installation paths and recreate directory structure
python -m device_guardian.main --repair-installation
```

---

## 4. Operator Backup Procedures

Device Guardian strictly separates application code from user configuration and state:

- **Installation Directory**: Read-only source code or binary (`dist/`).
- **User Data Directory**: `%LOCALAPPDATA%\DeviceGuardian` (Windows) or `~/.local/share/device-guardian` (Linux/macOS).

### Files to Back Up
To preserve an existing setup across machine migrations or operating system upgrades, back up the following files from the user data directory:
- `.env`: Application configuration (Telegram tokens, thresholds, cooldowns).
- `secret_store.enc`: DPAPI or encrypted credential vault (if enabled).
- `runtime_status.json`: Last known health and state metadata.

### Manual Backup Script (PowerShell)
```powershell
$SourceDir = "$env:LOCALAPPDATA\DeviceGuardian"
$BackupDir = "C:\Backups\DeviceGuardian_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

Copy-Item "$SourceDir\.env" -Destination $BackupDir -ErrorAction SilentlyContinue
Copy-Item "$SourceDir\runtime_status.json" -Destination $BackupDir -ErrorAction SilentlyContinue
Copy-Item "$SourceDir\secret_store.enc" -Destination $BackupDir -ErrorAction SilentlyContinue

Write-Host "Device Guardian state backed up to: $BackupDir"
```

---

## 5. Migration & Disaster Recovery

### Moving to a New Machine
1. Install Device Guardian on the target host following [`installation.md`](file:///C:/Users/Nibras/device-guardian/docs/installation.md).
2. Restore `.env` into `%LOCALAPPDATA%\DeviceGuardian` on the new host.
3. Because Windows DPAPI keys are tied to the local user account, credentials encrypted via DPAPI must be re-entered on the new host:
   ```powershell
   python -m device_guardian.main --setup
   ```
4. Check migration readiness:
   ```powershell
   python -m device_guardian.main --migration-status
   ```
5. Apply migration if transitioning from older schema layouts:
   ```powershell
   python -m device_guardian.main --migrate
   ```
6. Verify operation:
   ```powershell
   python -m device_guardian.main --check-config
   python -m device_guardian.main --test-alert
   ```
