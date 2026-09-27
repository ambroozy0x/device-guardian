# Quick Start Guide — Device Guardian

This guide provides the shortest accurate path from a clean checkout to a configured, validated, and running Device Guardian instance.

---

## 1. Prerequisites

* **Operating System**: Windows 10/11, Linux (Debian, Ubuntu, RHEL, CentOS), or macOS 12+ (Darwin).
* **Python**: Python 3.11 or higher (Python 3.12.x recommended).
* **Hardware (Optional)**: Standard USB or integrated webcam (for photo capture).
* **Network (Optional)**: Outbound HTTPS connectivity to `api.telegram.org` (for Telegram alerts) and `ipapi.co` (for IP geolocation). If offline, local monitoring and voice warnings remain fully operational.

---

## 2. Clone & Environment Setup

### Windows (PowerShell)

```powershell
# Clone the repository
git clone https://github.com/ambroozy0x/device-guardian.git
cd device-guardian

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install package
python -m pip install --upgrade pip
pip install -e .
```

### Linux / macOS (Bash / Zsh)

```bash
# Clone the repository
git clone https://github.com/ambroozy0x/device-guardian.git
cd device-guardian

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install package
python -m pip install --upgrade pip
pip install -e .
```

---

## 3. Initial Configuration

Device Guardian supports two configuration paths: the interactive setup wizard or manual `.env` creation.

### Option A: Interactive Setup Wizard (Recommended)

Run the built-in setup wizard to guide you through Telegram bot pairing, chat ID detection, and hardware testing:

```bash
python -m device_guardian.main --setup
```

The wizard will:
1. Prompt for your Telegram Bot Token (obtained from [@BotFather](https://t.me/BotFather)).
2. Automatically detect your Telegram Chat ID by listening for `/start` in your bot chat.
3. Test camera hardware and take a single test photograph.
4. Test IP geolocation lookup.
5. Save configuration safely to `.env` or the platform secure secret store.

### Option B: Manual Configuration (`.env`)

Create a `.env` file in the project root:

```ini
# Core Notification Credentials (Optional: if empty, runs in local-only mode)
TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID

# Subsystem Toggles
CAMERA_ALERT_ENABLED=true
LOCATION_ALERT_ENABLED=true
TELEGRAM_ALERT_ENABLED=true
VOICE_WARNING_ENABLED=true

# Detection Thresholds
AUTH_FAILURE_THRESHOLD=3
AUTH_FAILURE_WINDOW_SECONDS=60
AUTH_ALERT_COOLDOWN_SECONDS=300
```

---

## 4. Validate Configuration

Before launching the monitoring runtime, verify that configuration and credentials are valid:

```bash
python -m device_guardian.main --check-config
```

Expected output:
```text
Device Guardian - Configuration Readiness Audit
============================================================
[PASS] Config File: Resolved (.env)
[PASS] Telegram Bot: Credentials formatted and valid
[PASS] Detection Engine: OS monitor ready
[PASS] Persistence: Storage directory accessible
```

To run a safe end-to-end alert pipeline test without waiting for failed logins:

```bash
python -m device_guardian.main --test-alert
```

---

## 5. Starting Device Guardian

### Foreground Interactive Mode
To run with live terminal output:

```bash
python -m device_guardian.main --monitor-auth
```

### Background Daemon Mode
To start the background monitoring runtime with single-instance protection:

```bash
python -m device_guardian.main --start
```

### System Tray Mode (GUI)
To start with a dynamic system tray icon in the taskbar:

```bash
python -m device_guardian.main --tray
```

---

## 6. Verifying Operation

Check the live status of the running background service at any time:

```bash
python -m device_guardian.main --status
```

The unified status dashboard will display:
* Service operational state (`RUNNING`, `STOPPED`, `DEGRADED`)
* Process ID (PID) and uptime
* Sensor statuses (Camera, Geolocation, Voice)
* Detection metrics (Events processed, alerts triggered, cooldown state)

---

## 7. Stopping Device Guardian

To gracefully shut down the background runtime:

```bash
python -m device_guardian.main --stop
```

This sends a secure IPC signal (`STOP`) to the running process, flushes pending state files, and releases the single-instance mutex. If running in the foreground, press `Ctrl+C`.
