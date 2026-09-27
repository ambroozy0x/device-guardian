# Device Guardian — Production Deployment Checklist

This document provides a comprehensive operational checklist for deploying Device Guardian in a production environment.

---

## Pre-Deployment Verification

- [ ] **Host Operating System Compatibility**: Windows 10/11 (x64), Linux (Debian/Ubuntu x86_64), or macOS 12+ (x86_64 / ARM64).
- [ ] **Python Runtime**: Python 3.11 or 3.12 installed and accessible on PATH (`python --version`).
- [ ] **Camera Hardware**: Integrated or USB webcam connected and not in exclusive use by other applications.
- [ ] **Camera OS Permissions**:
  - Windows: **Settings > Privacy & security > Camera > Allow desktop apps** enabled.
  - macOS: Terminal/Python authorized under Camera privacy settings.
- [ ] **Network Connectivity**: Outbound HTTPS (port 443) access to `api.telegram.org` and IP geolocation service (`ipapi.co`).
- [ ] **Audit Policy (Windows)**: Run `auditpol /get /subcategory:"Logon"` to confirm Failure auditing is enabled.
- [ ] **Log Access (Linux)**: Verify user is in `adm` group or has read access to `/var/log/auth.log`.
- [ ] **Telegram Bot Provisioned**: Bot created with `@BotFather` and operator numeric chat ID obtained from `@userinfobot`.

---

## Configuration & Credentials

- [ ] **Configuration Initialization**: Ran `python -m device_guardian.main --setup` or prepared sanitized `.env`.
- [ ] **Strict Boolean Validation**: All boolean values in `.env` are strictly lowercase `true` or `false` (no `1`, `yes`, or mixed case).
- [ ] **Credential Security**:
  - Windows: Verified DPAPI encryption via `python -m device_guardian.main --credentials-status`.
  - Stored tokens are absent from plain-text logging and environment inspection.
- [ ] **Configuration Audit**: Executed `python -m device_guardian.main --check-config` and received zero errors.

---

## Filesystem & Directory Hardening

- [ ] **Directory Separation**:
  - Source code / binary placed in dedicated install root.
  - Runtime state configured for `%LOCALAPPDATA%\DeviceGuardian` (Windows) or `~/.local/share/device-guardian` (Linux/macOS).
- [ ] **Filesystem Access Control**:
  - Windows: Only local user and SYSTEM have Full Control on `%LOCALAPPDATA%\DeviceGuardian`.
  - Linux/macOS: Permissions on user data directory set to `700` (`chmod 700 ~/.local/share/device-guardian`).
- [ ] **Log Directory Verified**: `device_guardian.log` created and writable.

---

## Subsystem Functional Verification

- [ ] **Camera Test**:
  ```powershell
  python -m device_guardian.main --test-camera
  ```
  *Verified output image captured without exception.*
- [ ] **Location Test**:
  ```powershell
  python -m device_guardian.main --test-location
  ```
  *Verified approximate city, region, and coordinates resolved.*
- [ ] **Telegram End-to-End Test Alert**:
  ```powershell
  python -m device_guardian.main --test-alert
  ```
  *Verified alert with photo, location, and objective message arrived in Telegram chat.*
- [ ] **Full Diagnostic Audit**:
  ```powershell
  python -m device_guardian.main --diagnostics
  ```
  *Verified all core subsystems return healthy status.*

---

## Background Daemon & Auto-Start Configuration

- [ ] **Auto-Start Configured**:
  - Windows: Shortcut created in `shell:startup` or Scheduled Task configured.
  - Linux: Systemd user service installed and enabled (`systemctl --user enable device-guardian`).
  - macOS: LaunchAgent plist registered in `~/Library/LaunchAgents/`.
- [ ] **Single-Instance Enforcement**: Launched daemon, verified PID lock file created, attempted second launch to verify rejection.
- [ ] **Status Verification**: Checked `python -m device_guardian.main --status` returns `[● HEALTHY]` with active PID.

---

## Rollback & Disaster Recovery Readiness

- [ ] **Configuration Backup**: `.env` and `secret_store.enc` backed up to secure off-machine storage.
- [ ] **Verification Command Tested**: Ran `python -m device_guardian.main --verify-installation`.
- [ ] **Recovery Status Checked**: Ran `python -m device_guardian.main --recovery-status`.
- [ ] **Rollback Procedure Documented**: Operators informed of `python -m device_guardian.main --rollback` procedure.
