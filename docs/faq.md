# Device Guardian — Frequently Asked Questions (FAQ)

This document provides answers to common operational, architectural, and security questions regarding Device Guardian.

---

### Q1: How does Device Guardian detect unauthorized access attempts?
Device Guardian monitors native operating system authentication logs in real time. On Windows, it hooks the Security Event Log for Event ID 4625 (Logon Failure). On Linux, it monitors `/var/log/auth.log` or PAM logs. On macOS, it streams security events via system logging APIs. When consecutive failures exceed the configured threshold within the sliding window (e.g., 3 failures in 60 seconds), an alert is triggered.

---

### Q2: Does Device Guardian require Administrator or Root privileges?
**No.** Device Guardian is architected to run within a standard user security context.
- **Windows**: Reading the Security Event Log and accessing DPAPI requires only standard user rights (assuming the system audit policy is enabled by an administrator).
- **Linux**: The user only needs membership in the `adm` or `systemd-journal` group to read `/var/log/auth.log`.
- **macOS**: Runs in user space; requires camera permission under System Settings.

---

### Q3: Where and how are my Telegram credentials stored?
On Windows, tokens configured through `python -m device_guardian.main --setup` are encrypted using Windows Data Protection API (DPAPI) via `CryptProtectData` and stored in an encrypted vault (`secret_store.enc`). DPAPI keys are tied to the local user account and cannot be decrypted by other users or across machines. If `.env` is used directly, tokens are loaded into memory and protected by runtime secret redaction.

---

### Q4: What happens if the internet connection is down when an alert triggers?
Device Guardian places the alert into the `BoundedAlertQueue` (capacity: 100 items). The circuit breaker trips to `OPEN` after 5 failed network attempts, preventing socket exhaustion or CPU spinning. When connectivity is restored, the circuit breaker enters `HALF_OPEN`, verifies delivery, resets to `CLOSED`, and dispatches pending alerts in priority order.

---

### Q5: What happens if my webcam is busy or disconnected?
Device Guardian handles camera errors gracefully. If another application (like Zoom or Teams) holds exclusive access to the webcam, or if no camera is connected, camera capture is skipped. Device Guardian immediately sends a text-only Telegram alert with location and timestamp, explicitly noting `Camera: Unavailable`.

---

### Q6: Does Device Guardian permanently store captured webcam photos on disk?
**No.** Privacy is a core invariant of Device Guardian. Captured webcam photos are saved to a temporary staging file, transmitted over TLS directly to Telegram, and immediately deleted (`unlinked`) from the filesystem upon successful transmission.

---

### Q7: How does Device Guardian prevent alert spam during legitimate typos?
Device Guardian employs three layers of noise reduction:
1. **Sliding-Window Correlation**: Requires multiple failures (default: 3) within a time window (default: 60s) before alerting.
2. **Cooldown Windows**: After an alert triggers, an alert cooldown (default: 300s) suppresses duplicate alerts from the same source.
3. **Smart Filters**: High-priority filters suppress alerts during maintenance windows or for designated service accounts.

---

### Q8: Can Device Guardian run multiple instances simultaneously?
**No.** Device Guardian enforces a strict single-instance policy using a filesystem PID lock (`guardian.lock`). Attempting to launch a second instance while one is active will report that another instance is running and terminate immediately.

---

### Q9: Why does Device Guardian use Ed25519 signatures instead of Windows Authenticode?
Release manifests and update packages are signed using Ed25519 public-key cryptography and verified with streaming SHA-256 chunking. Windows Authenticode digital code signing requires an Extended Validation (EV) certificate backed by a physical hardware cryptotoken (HSM) from a public Certificate Authority, which cannot be automated without proprietary CA infrastructure. Ed25519 provides mathematically equivalent or superior cryptographic integrity guarantees.

---

### Q10: How do I test the alerting pipeline without locking myself out?
Run the built-in test alert command:
```powershell
python -m device_guardian.main --test-alert
```
This triggers the complete pipeline (camera capture, geolocation query, message assembly, and Telegram dispatch) safely.

---

### Q11: How do I cleanly uninstall Device Guardian and remove all data?
Run the built-in uninstall utility:
```powershell
# Remove background services and installation
python -m device_guardian.main --uninstall

# Remove all user configuration, logs, and state files
python -m device_guardian.main --remove-data
```
