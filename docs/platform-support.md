# Device Guardian — Platform Support & Compatibility Matrix

This document defines the cross-platform architecture, operating system support tiers, subsystem implementations, and verified capabilities of Device Guardian.

---

## 1. Platform Support Tiers

Device Guardian classifies platform support into distinct, rigorously verified tiers based on actual host execution and CI test coverage:

| Support Tier | Target Operating Systems | Architectures | Status |
| :--- | :--- | :---: | :--- |
| **Tier 1 (Host Verified)** | Windows 10, Windows 11 | `x64` | **Fully Verified & Tested Locally** |
| **Tier 2 (Compatible)** | Linux (Ubuntu, Debian, Fedora, RHEL) | `x64`, `arm64` | **Architecture Implemented & Unit Tested** |
| **Tier 2 (Compatible)** | macOS 12 (Monterey), 13 (Ventura), 14 (Sonoma) | `x64`, `arm64` | **Architecture Implemented & Unit Tested** |
| **Unsupported** | 32-bit OS, BSD, Solaris, Mobile (iOS/Android) | `x86`, other | **Unsupported & Blocked at Startup** |

---

## 2. Subsystem Implementation Matrix

| Subsystem | Windows (Tier 1) | Linux (Tier 2) | macOS (Tier 2) |
| :--- | :--- | :--- | :--- |
| **Detection Monitor** | `WindowsSecurityLogMonitor`<br>Native Event ID 4625 via `win32evtlog` | `LinuxAuthLogMonitor`<br>`/var/log/auth.log` or `/var/log/secure` | `MacOSAuthLogMonitor`<br>Unified Logging (`log stream`) |
| **Credential Security** | Windows DPAPI<br>`CryptProtectData` | Encrypted Secret Vault<br>PBKDF2-HMAC-SHA256 + AES-GCM | Encrypted Secret Vault<br>PBKDF2-HMAC-SHA256 + AES-GCM |
| **Single-Instance Lock** | File lock with Windows PID handle verification | POSIX `fcntl` / `flock` with PID verification | POSIX `fcntl` / `flock` with PID verification |
| **Camera Capture** | OpenCV DirectShow (`CAP_DSHOW`) | OpenCV V4L2 (`CAP_V4L2`) | OpenCV AVFoundation (`CAP_AVFOUNDATION`) |
| **Approximate Geolocation** | `ipapi.co` JSON over HTTPS | `ipapi.co` JSON over HTTPS | `ipapi.co` JSON over HTTPS |
| **System Tray** | `pystray` with Win32 message loop | `pystray` with AppIndicator / GTK | `pystray` with Cocoa NSApplication |
| **Paths & Data Roots** | `%LOCALAPPDATA%\DeviceGuardian` | `~/.local/share/device-guardian` | `~/Library/Application Support/DeviceGuardian` |
| **Local Voice Deterrence** | `pyttsx3` (SAPI5 backend) | `pyttsx3` (eSpeak backend) | `pyttsx3` (NSSpeechSynthesizer) |
| **Update Verification** | Ed25519 + SHA-256 (Streaming) | Ed25519 + SHA-256 (Streaming) | Ed25519 + SHA-256 (Streaming) |

---

## 3. Detailed Operating System Requirements

### Windows (Tier 1 Primary)
- **Minimum OS**: Windows 10 Version 1809 or Windows 11 (64-bit).
- **Audit Policy Requirement**: Logon failure auditing must be enabled (`auditpol /set /subcategory:"Logon" /failure:enable`) for Event ID 4625 to be written to the Security event log.
- **Privileges**: Standard user permissions for background tray operation. Administrative privileges only required if changing system-wide audit policies or writing to `%ProgramFiles%`.

### Linux (Tier 2 Compatible)
- **Kernel & Distros**: Linux Kernel 4.18+, systemd-based distributions (Ubuntu 20.04+, Debian 11+, Fedora 36+).
- **Log Permissions**: The running user must belong to group `adm` or `systemd-journal` to read authentication logs without root:
  ```bash
  sudo usermod -aG adm $USER
  ```
- **Dependencies**: `libgl1` (OpenCV runtime), `v4l-utils` (video4linux), `espeak` (for voice warning).

### macOS (Tier 2 Compatible)
- **Minimum OS**: macOS 12 (Monterey) or newer on Intel (`x64`) or Apple Silicon (`arm64`).
- **Privacy Permissions (TCC)**: macOS requires explicit user authorization under **System Settings > Privacy & Security > Camera** for Terminal or Python.
- **Log Streaming**: Monitors authentication failures via system `log stream --style ndjson --predicate 'eventMessage CONTAINS "Failed to authenticate"'`.

---

## 4. Querying Platform Capabilities

Inspect the current platform compatibility and capability profile at any time:

```powershell
# Display active platform metadata and support tier
python -m device_guardian.main --platform-info
```

### Sample Output
```json
{
  "os": "Windows",
  "os_name": "Windows",
  "release": "11",
  "version": "10.0.22631",
  "arch": "x64",
  "machine": "AMD64",
  "python_version": "3.12.6",
  "is_frozen": false,
  "is_windows": true,
  "is_linux": false,
  "is_macos": false,
  "is_supported": true,
  "executable_name": "device-guardian.exe",
  "support_tier": "Tier 1 (Host Verified: Windows 11 x64)"
}
```
