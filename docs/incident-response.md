# Device Guardian — Security Incident Response Playbook

This document defines standard incident response procedures for operators encountering security events, credential exposures, alert storms, or tampering involving Device Guardian.

---

## 1. Seven-Step Incident Response Lifecycle

```
[ 1. DETECT ] ──► [ 2. CONTAIN ] ──► [ 3. PRESERVE ] ──► [ 4. RECOVER ]
                                                               │
[ 7. ESCALATE / POST-MORTEM ] ◄── [ 6. DOCUMENT ] ◄── [ 5. VERIFY ] ◄┘
```

### Step 1: Detect
- **Telegram Security Alert**: High-priority alert notification received containing webcam photo and approximate coordinates.
- **Log Anomaly**: Review `device_guardian.log` for bursts of `AuthenticationFailureEvent` or `BoundedAlertQueue dropped alert` warnings.
- **System Warning**: Local voice warning deterrence triggered or tray status glyph transitions to `[▲ DEGRADED]` or `[✖ ERROR]`.

### Step 2: Contain
- **Physical Device Access**: If unauthorized physical presence is detected, immediately lock or disconnect the machine from the corporate network.
- **Halt Background Daemon**:
  ```powershell
  python -m device_guardian.main --stop
  ```
- **Revoke Exposed Bot Token**: If `TELEGRAM_BOT_TOKEN` is suspected compromised, open Telegram and revoke the token immediately via `@BotFather` (`/revoke`).

### Step 3: Preserve Evidence
- **Do not delete logs or state files**:
  ```powershell
  $EvidenceDir = "C:\Evidence\DeviceGuardian_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  New-Item -ItemType Directory -Path $EvidenceDir -Force

  # Copy Device Guardian logs and state
  Copy-Item "$env:LOCALAPPDATA\DeviceGuardian\device_guardian.log" -Destination $EvidenceDir
  Copy-Item "$env:LOCALAPPDATA\DeviceGuardian\runtime_status.json*" -Destination $EvidenceDir

  # Export Windows Security Event Log (Logon events)
  wevtutil epl Security "$EvidenceDir\SecurityLog.evtx" /q:"*[System[(EventID=4625)]]"
  ```
- **Preserve Memory**: If active tampering is suspected, acquire a process memory dump before stopping.

### Step 4: Recover
- **Regenerate Credentials**:
  1. Generate a new bot token via `@BotFather`.
  2. Launch setup wizard to store new credentials in DPAPI:
     ```powershell
     python -m device_guardian.main --setup
     ```
- **Repair State**: If state corruption or tampering occurred:
  ```powershell
  python -m device_guardian.main --repair-state
  ```

### Step 5: Verify
- Validate configuration and credentials:
  ```powershell
  python -m device_guardian.main --check-config
  python -m device_guardian.main --credentials-status
  ```
- Run diagnostic tests and send a test alert:
  ```powershell
  python -m device_guardian.main --diagnostics
  python -m device_guardian.main --test-alert
  ```
- Restart daemon and confirm healthy PID status:
  ```powershell
  python -m device_guardian.main --start
  python -m device_guardian.main --status
  ```

### Step 6: Document
Record the incident details in a standard post-incident report:
- **Timestamp of Initial Alert**:
- **Trigger Reason & Failure Count**:
- **Physical Location / Photo Context**:
- **User Account Targeted**:
- **Containment Action Taken**:
- **Credentials Revoked / Rotated**:

### Step 7: Escalate
- Notify information security team / CISO.
- If corporate domain accounts were targeted, reset Active Directory / Okta credentials immediately.

---

## 2. Threat Scenarios & Specific Playbooks

### Scenario A: Repeated Physical Brute-Force
- **Indicators**: Rapid succession of Event ID 4625 logs; Telegram alerts showing unknown person at console.
- **Action**: Lock console (`Win + L`); report physical security breach to facility security; preserve webcam snapshot.

### Scenario B: Alert Storm / Log Flooding
- **Indicators**: `BoundedAlertQueue` reports high watermark or dropped alerts; circuit breaker trips to `OPEN`.
- **Root Cause**: Scripted attack or misconfigured automated service attempting rapid logins.
- **Action**: Check `ATTEMPTS_COOLDOWN_SECONDS` in `.env`; identify offending source username in logs; verify circuit breaker prevented external API exhaustion.

### Scenario C: Configuration or State Tampering
- **Indicators**: File hash mismatch reported by `--verify-installation`, or malformed JSON error in logs.
- **Action**: Run `python -m device_guardian.main --verify-installation`. The system automatically isolates corrupted files to `.corrupt.<timestamp>` and restores a clean baseline.
