# Installation Guide — Device Guardian

This guide details the complete installation procedure for Device Guardian across development environments and production standalone deployments.

---

## 1. Supported Environments & Requirements

| Dimension | Specification | Notes |
| :--- | :--- | :--- |
| **Python Version** | `>= 3.11` | Tested extensively on Python `3.12.6`. |
| **Operating Systems** | Windows 10/11 (x64)<br>Linux (x86_64, aarch64)<br>macOS 12+ (x86_64, arm64) | Full platform parity across detection adapters. |
| **Privilege Level** | **Standard User** (Non-Admin / Non-Root) | Device Guardian intentionally requires **no administrative elevation**. |
| **Hardware** | USB / Integrated Webcam (Optional)<br>Audio Speaker (Optional) | For photo capture and offline text-to-speech warnings. |
| **Network** | HTTPS Outbound Port 443 (Optional) | Required only if Telegram alerts or IP geolocation are enabled. |

---

## 2. Dependencies Matrix

All core dependencies are declared in [`pyproject.toml`](../pyproject.toml):

| Package | Minimum Version | Purpose |
| :--- | :--- | :--- |
| `opencv-python` | `>= 4.8.0.76` | Single-frame webcam photograph capture. |
| `requests` | `>= 2.31.0` | Outbound HTTPS delivery to Telegram Bot API & IP geolocation. |
| `python-dotenv` | `>= 1.0.0` | Environment variable parsing from `.env` files. |
| `Pillow` | `>= 10.0.0` | Image handling and system tray icon rasterization. |
| `pystray` | `>= 0.19.5` | Dynamic cross-platform system tray icon management. |
| `pytest` *(optional `[dev]`)* | `>= 7.4.0` | Automated test suite execution. |

*Note: Cryptography (Ed25519) and streaming checksums (SHA-256) are implemented entirely using Python standard library primitives (`hashlib`, `os`, `hmac`), requiring zero external cryptographic binary wheels.*

---

## 3. Python Source Installation

### Step 1: Create Virtual Environment
Always install Device Guardian in an isolated virtual environment to prevent package conflicts.

**Windows**:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS**:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Package

**Production Installation (Core only)**:
```bash
python -m pip install --upgrade pip
pip install -e .
```

**Development Installation (Includes test runner)**:
```bash
pip install -e ".[dev]"
```

---

## 4. Standalone Packaged Binary Deployment (Windows)

For operators who prefer running a single self-contained executable without maintaining a local Python installation, pre-built standalone binaries are generated via PyInstaller.

### Architectural Directory Separation
Device Guardian strictly enforces architectural separation between immutable binaries and mutable operator data:

1. **`INSTALL_ROOT`** (Application Executables):
   - Path: Directory containing `device-guardian.exe`.
   - Permissions: Read-only for standard runtime operations.
   - Contents: Application executable, release manifest, and build metadata.
2. **`USER_DATA`** (Mutable Application State):
   - Path: `%LOCALAPPDATA%\DeviceGuardian` (Windows) or `~/.local/share/device-guardian` (Linux/macOS).
   - Permissions: Read/Write for the active user.
   - Contents: `.env` configuration, encrypted secret stores, logs, update transactions, and backups.

### Installation Lifecycle Commands

* **Inspect Installation Paths & Metadata**:
  ```powershell
  .\dist\device-guardian.exe --install-info
  ```
* **Verify Health of Installed Files & Directories**:
  ```powershell
  .\dist\device-guardian.exe --installation-status
  ```
* **Safely Repair Missing Runtime Directories & Metadata**:
  ```powershell
  .\dist\device-guardian.exe --repair-installation
  ```
* **Uninstall Application**:
  ```powershell
  # Uninstalls binaries, preserving user data and configuration:
  .\dist\device-guardian.exe --uninstall

  # Uninstalls binaries AND purges user data with explicit confirmation:
  .\dist\device-guardian.exe --uninstall --remove-data
  ```

---

## 5. Platform-Specific Prerequisites

### Windows
* **Windows Event Log Access**: `WindowsSecurityLogMonitor` uses the standard Windows command-line utility `wevtutil.exe` to read event 4625 (Failed Logon). Ensure `wevtutil.exe` is accessible on your system `PATH` (default: `C:\Windows\System32\wevtutil.exe`).
* **Webcam Access**: Ensure Windows Privacy Settings permit desktop applications to access the camera (`Settings > Privacy & Security > Camera`).

### Linux
* **Authentication Log Permissions**: `LinuxAuthLogMonitor` reads `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS). Standard Linux distributions require membership in the `adm` or `systemd-journal` group to read these logs without root elevation:
  ```bash
  sudo usermod -aG adm $USER
  ```
  *(Log out and log back in for group membership to take effect).*
* **Text-to-Speech (Optional)**: If offline voice alerts are enabled, install `espeak-ng` or `spd-say`:
  ```bash
  sudo apt-get install espeak-ng   # Debian / Ubuntu
  sudo dnf install espeak-ng       # Fedora / RHEL
  ```

### macOS
* **Unified Log Access**: `MacOSAuthLogMonitor` queries the macOS Unified Logging System via `/usr/bin/log show`.
* **Camera Privacy Permissions**: macOS Gatekeeper and TCC require camera authorization for the terminal or binary executing the capture (`System Settings > Privacy & Security > Camera`).
* **Text-to-Speech**: Built-in `/usr/bin/say` is utilized natively without additional software.

---

## 6. Verifying Installation

Verify that the installation was successful by checking the version and platform compatibility:

```bash
python -m device_guardian.main --version
python -m device_guardian.main --platform-info
```

Expected output:
```text
Device Guardian v1.0.0 (Phase 8: Resilience, Phase 9: Security, Phase 10: Operator UX, Phase 11: Integration, Phase 12: Lifecycle & Phase 13: Cross-Platform)
Host Platform: Windows (x64)
Python: 3.12.6
Detection Monitor: WindowsSecurityLogMonitor (Ready)
Single-Instance Mutex: Operational
```
