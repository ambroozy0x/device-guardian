# Operator Handbook — Device Guardian

The Operator Handbook is the authoritative operational guide for running, monitoring, diagnosing, and maintaining Device Guardian in day-to-day production environments.

---

## 1. Purpose

Device Guardian is designed to protect unattended desktop workstations from unauthorized physical access by monitoring operating system authentication events, evaluating failed logon attempts against deterministic thresholds, capturing situational context (camera photograph and approximate IP location), and dispatching real-time alerts to the device owner's personal Telegram chat.

This handbook equips operators with clear procedures for service lifecycle, health evaluation, error recovery, maintenance, and emergency response.

---

## 2. System Overview

Device Guardian runs as an unprivileged user process composed of four synchronized subsystems:

1. **Detection Engine**: Continuously polls native platform authentication failure logs (Windows Event Log 4625, Linux `/var/log/auth.log` or PAM, macOS Unified Log).
2. **Threshold & Filter Engine**: Accumulates events in a sliding time window (default: 3 failures in 60s) and evaluates deterministic rules (trusted users, trusted networks, environmental state).
3. **Alert Pipeline**: Acquires context (webcam frame capture and IP geolocation) and packages alerts for dispatch.
4. **Reliability & Dispatch Manager**: Manages priority alert queues (`BoundedAlertQueue`), enforces cooldown rate-limiting, handles network outages via circuit breaker (`CircuitBreaker`), and delivers HTTPS payloads to Telegram.

---

## 3. Before Starting

Verify that the following conditions are met prior to launching:

* **Configuration**: A valid `.env` file or encrypted secret store exists.
* **Camera Access**: The camera is plugged in and accessible by the operating system (not locked exclusively by another application like Zoom or Teams).
* **Network Connectivity**: Outbound access to `api.telegram.org:443` is available (or offline local mode is acceptable).
* **Permissions**: Running under a standard user account with read access to the system event log or authentication log file.

Perform a fast pre-flight check:
```bash
python -m device_guardian.main --config-check
```

---

## 4. Starting Device Guardian

Depending on the operational context, choose one of the following launch methods:

### Standard Background Service
Recommended for normal daily protection:
```bash
python -m device_guardian.main --start
```
The command spawns the background worker process, creates the single-instance mutex lock, and exits with code `0`.

### Foreground Monitoring (Terminal Console)
Recommended during initial setup, testing, or debugging:
```bash
python -m device_guardian.main --monitor-auth
```
Streams log records and evaluation results directly to the terminal stdout.

### System Tray Desktop Mode
Recommended for interactive workstations:
```bash
python -m device_guardian.main --tray
```
Places a dynamic shield icon in the operating system taskbar/notification area, allowing quick status inspection and manual alert testing.

---

## 5. Verifying Healthy Operation

The primary operational diagnostic tool is the unified status surface:

```bash
python -m device_guardian.main --status
```

### Understanding the Status Output

```text
================================================================================
                    DEVICE GUARDIAN - RUNTIME STATUS
================================================================================
  Service Status        : [● HEALTHY] RUNNING (PID: 14220)
  Uptime                : 04h 12m 30s
  Single Instance Lock  : HELD (Process Validated)
--------------------------------------------------------------------------------
  Configuration State   : [● HEALTHY] Loaded (.env)
  Telegram Channel      : [● HEALTHY] Connected (Bot: @DeviceGuardianBot)
  Camera Sensor         : [● HEALTHY] Available (Index: 0)
  Geolocation Sensor    : [● HEALTHY] Available (https://ipapi.co/json/)
  Offline Voice Alert   : [● HEALTHY] Enabled (System TTS Ready)
--------------------------------------------------------------------------------
  Total Events Polled   : 142
  Alerts Triggered      : 0
  Alerts In Cooldown    : 0
  Queue Watermark       : 0 / 100
  Circuit Breaker       : CLOSED (Normal Operation)
================================================================================
```

### Color-Independent Status Glyphs
Device Guardian adheres strictly to accessibility standards using geometric glyphs:
* `[● HEALTHY]`: Subsystem fully operational without faults.
* `[▲ DEGRADED]`: Subsystem operational in fallback mode (e.g. camera missing, alert sent as text).
* `[■ FAILED]`: Subsystem encountered unrecoverable fault; intervention required.
* `[? UNKNOWN]`: Subsystem status cannot be determined deterministically.
* `[- NOT_CONFIG]`: Subsystem explicitly disabled in configuration.

---

## 6. Understanding Detection

Detection is triggered exclusively by operating system failed logon events:
* **Windows**: Security Event Log ID `4625` (An account failed to log on).
* **Linux**: PAM authentication failure, `sshd` failed password, or `sudo` incorrect password.
* **macOS**: Unified log show entries matching `loginwindow` or `sshd` failure streams.

**Key Rule**: Raw passwords, secret keys, and pin numbers are **never** captured, extracted, or stored by Device Guardian.

When multiple failures occur within `AUTH_FAILURE_WINDOW_SECONDS` (default: 60s), the sliding-window engine trips once `AUTH_FAILURE_THRESHOLD` (default: 3) is reached.

---

## 7. Understanding Alerts

When the threshold is tripped:
1. **Smart Filtering Evaluation**: The event is evaluated against configured trusted rules (`TRUSTED_USERS`, `TRUSTED_NETWORKS`). If a condition matches, the alert is suppressed benignly with an audit log.
2. **Cooldown Check**: If a previous alert occurred within `AUTH_ALERT_COOLDOWN_SECONDS` (default: 300s), the alert is suppressed to prevent notification flooding.
3. **Voice Warning**: If enabled, the local text-to-speech engine speaks the warning text aloud through workstation speakers.
4. **Context Capture**: The camera snaps a single photograph, and an IP geolocation query resolves the public IP, city, region, and ISP.
5. **Alert Packaging**: The alert is enqueued into the priority queue and dispatched to Telegram.

---

## 8. Notification Behavior

* **Primary Delivery**: Telegram Bot API via outbound HTTPS `POST https://api.telegram.org/bot<token>/sendPhoto`.
* **Fallback on Camera Error**: If the camera is disconnected, occupied, or fails, the pipeline degrades gracefully to `sendMessage` containing text metadata, location, and reason.
* **Fallback on Geolocation Error**: If network is down or geolocation times out, location fields are marked as `"Unavailable"`.
* **Zero Cloud Telemetry**: Alert payloads are transmitted **only** to the user's configured Telegram chat ID. No telemetry or analytics are ever dispatched to any other server.

---

## 9. Camera / Location / Voice Components

* **Camera Capture**: Takes a single warm-up frame and a capture frame, resizing image to JPEG in memory. The camera device is immediately released; Device Guardian **never** keeps the webcam handle open continuously.
* **Geolocation**: Issues an unauthenticated HTTP GET request to `LOCATION_API_URL` with a bounded timeout (`[0.5, 60.0]s`).
* **Offline Voice Warning**: Invokes native platform TTS (`SAPI` on Windows, `espeak`/`spd-say` on Linux, `/usr/bin/say` on macOS). Completely offline; requires zero network connectivity.

---

## 10. Runtime State

Runtime state is tracked in `%LOCALAPPDATA%\DeviceGuardian\runtime_status.json`:
* `state`: `IDLE`, `RUNNING`, `DEGRADED`, `STOPPING`, `STOPPED`.
* `pid`: Active process ID.
* `started_at`: UTC ISO timestamp of daemon launch.
* `last_heartbeat`: UTC ISO timestamp updated every polling cycle.
* `health_summary`: Subsystem statuses.

State persistence uses atomic file replacement (`.tmp` -> replace) with `.bak` backups to prevent corruption during unexpected power loss.

---

## 11. Logs

* **Location**: `%LOCALAPPDATA%\DeviceGuardian\device_guardian.log` (or `./device_guardian.log`).
* **Rotation**: 10 MB per file, up to 5 rotated backup files (maximum 50 MB total disk usage).
* **Sanitization**: All log messages pass through `RedactingFilter` and `SecretRedactor`. Bot tokens, passwords, and private keys are scrubbed before writing to disk.
* **Log Storm Suppression**: Identical warning or error messages repeated rapidly are rate-limited by `DuplicateLogFilter`. Critical security audit events (`CRITICAL` or `security.*`) bypass suppression to guarantee full audit integrity.

---

## 12. Reliability Monitoring

Device Guardian incorporates an internal operational reliability tracker:
* **RSS Memory**: Periodically checks physical memory usage. Normal baseline is 30–65 MB.
* **Thread Count**: Normal operating count is 3–5 threads (main runtime, detector loop, alert worker).
* **Queue Watermark**: Shows peak depth of pending alerts. Should remain near 0.
* **Circuit Breaker Status**: If Telegram API fails 5 consecutive times, circuit trips to `OPEN` and fast-fails further attempts for 60 seconds, preventing CPU spinning and socket exhaustion.

Inspect reliability metrics directly:
```bash
python -m device_guardian.main --diagnostics
```

---

## 13. Graceful Shutdown

To stop the running background daemon:
```bash
python -m device_guardian.main --stop
```

### What Happens During Graceful Shutdown:
1. `STOP` command is written to `guardian.control`.
2. Running daemon detects control signal.
3. Polling loops terminate cleanly.
4. Active alert dispatchers finish delivering current item.
5. In-memory state and metrics are flushed to disk.
6. Mutex lock file `guardian.lock` is unlinked.
7. Process terminates cleanly with exit code `0`.

---

## 14. Restart Procedure

To perform a clean restart:
```bash
python -m device_guardian.main --restart
```
This issues a graceful `STOP`, polls for full process release (up to 10 seconds), and immediately launches a new instance.

---

## 15. Maintenance Mode

During workstation maintenance, software updates, or IT troubleshooting where repeated failed logons or reboots are anticipated, place Device Guardian in maintenance:

1. **Stop the Background Service**:
   ```bash
   python -m device_guardian.main --stop
   ```
2. **Temporarily Disable Autostart** (if configured):
   ```bash
   python -m device_guardian.main --remove-startup
   ```
3. **Perform Maintenance Tasks**.
4. **Re-enable Service and Startup**:
   ```bash
   python -m device_guardian.main --install-startup
   python -m device_guardian.main --start
   ```

---

## 16. Failure Recovery

### Corrupted State Files
If runtime state files are damaged by abrupt power failure:
```bash
python -m device_guardian.main --repair-state
```
This preserves the corrupted file as `.corrupt.<timestamp>`, restores a valid default state, and guarantees `.env` and credential stores are never modified or deleted.

### Stale Lock File
If the host workstation crashed while Device Guardian was running, a stale `guardian.lock` may remain:
* Running `--start` automatically inspects the PID and process creation time. If the PID is dead or belongs to an unrelated process, the stale lock is purged automatically.
* To force manual inspection:
  ```bash
  python -m device_guardian.main --status
  ```

---

## 17. Security Operations

* **Rotate Telegram Bot Token**:
  1. Generate a new token via [@BotFather](https://t.me/BotFather).
  2. Update `.env` with the new token.
  3. Run `python -m device_guardian.main --restart`.
  4. Run `python -m device_guardian.main --test-notification` to verify.
* **Inspect Safe Configuration Without Secrets**:
  ```bash
  python -m device_guardian.main --config-show
  ```
* **Verify Physical Binary Integrity Against Release Manifest**:
  ```bash
  python -m device_guardian.main --verify-installation
  ```

---

## 18. Updating

To stage and install an update package (`.zip`):
```bash
python -m device_guardian.main --install-update update_package.zip
```

### Safety Protections During Update:
* Package signature is verified using the official Ed25519 public key.
* Streaming SHA-256 digests verify all binaries.
* Safe extractor rejects path traversals (`..`), casing collisions, and executable scripts.
* Running daemon is coordinated cleanly via IPC; no binaries are swapped while in use.
* Automatic rollback is created before file replacement.

To roll back to the previous release:
```bash
python -m device_guardian.main --rollback
```

---

## 19. Emergency Procedures

### Scenario: High-Volume Alert Storm
If an external script or automated tool is causing runaway alerts:
1. Stop the daemon immediately:
   ```bash
   python -m device_guardian.main --stop
   ```
2. Disable alerts in `.env`:
   ```ini
   TELEGRAM_ALERT_ENABLED=false
   ```
3. Restart daemon to resume local-only logging:
   ```bash
   python -m device_guardian.main --start
   ```

### Scenario: Suspected Compromised Telegram Token
1. Revoke the bot token immediately in Telegram via [@BotFather](https://t.me/BotFather) (`/revoke`).
2. Stop the application:
   ```bash
   python -m device_guardian.main --stop
   ```
3. Update `.env` with the newly issued token.
4. Restart the application:
   ```bash
   python -m device_guardian.main --start
   ```

---

## 20. Daily Operator Checklist

* [ ] Run `python -m device_guardian.main --status` — confirm `[● HEALTHY]` status.
* [ ] Verify Process ID is active and uptime is accumulating steadily.
* [ ] Check `device_guardian.log` for any `[ERROR]` or `[WARNING]` entries.
* [ ] Ensure camera lens is clean and unobstructed.
* [ ] Confirm test notification receipt if periodic audit is scheduled.

---

## 21. Shutdown Checklist

* [ ] Run `python -m device_guardian.main --stop`.
* [ ] Verify exit code `0` is returned.
* [ ] Confirm `guardian.lock` is cleared from `%LOCALAPPDATA%\DeviceGuardian`.
* [ ] Inspect final log entries confirming graceful shutdown sequence.

---

## 22. Escalation Guidance

| Condition | Diagnostic Command | Escalation Action |
| :--- | :--- | :--- |
| **Daemon repeatedly exits with code 1** | `--diagnostics` | Review exception traceback in `device_guardian.log`; check camera driver or event log permissions. |
| **Repeated `[403 Forbidden]` from Telegram** | `--check-config` | Token revoked or bot blocked by user; re-pair with setup wizard. |
| **Circuit breaker permanently `OPEN`** | `--test-notification` | Outbound firewall blocking port 443 or Telegram service outage; check DNS resolution. |
| **Corrupted installation files** | `--verify-installation` | Release manifest mismatch; re-run installer or execute `--repair-installation`. |
