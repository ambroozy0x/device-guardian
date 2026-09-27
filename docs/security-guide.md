# Security Guide — Device Guardian

Device Guardian is designed from the ground up as a **zero-trust, privacy-preserving, local-first** desktop security system. This guide explains the security controls, cryptographic invariants, and privilege boundaries enforced across the application.

For formal threat modeling and the vulnerability register, refer directly to [`SECURITY.md`](../SECURITY.md).

---

## 1. Core Security Invariants

Device Guardian adheres to 12 immutable security invariants:

1. **Deterministic Logic (Zero AI/ML)**: All detection and filtering logic uses deterministic boolean rules. There are zero heuristic threat scores, machine-learning models, or LLM dependencies.
2. **Zero Telemetry**: The application contains absolutely no third-party telemetry, crash reporters, usage analytics, or cloud tracking beacons.
3. **No Inbound Remote Control**: Device Guardian operates purely as a local client. It never binds to or listens on any network port (TCP, UDP, HTTP, WebSocket).
4. **Credential Non-Collection Invariant**: Passwords, PINs, and credentials attempted during login are **never** captured, extracted, normalized, or stored.
5. **Universal Secret Redaction**: All API tokens and Chat IDs are masked in terminal displays, logs, exceptions, and `__repr__` strings.
6. **Strict Configuration Bounding**: Numerical settings have hard upper and lower bounds; boolean settings reject ambiguous values.
7. **Filesystem Traversal Rejection**: Strict safe path validation rejects directory traversal (`..`), percent-encoding (`%2e%2e`), UNC paths, NTFS Alternate Data Streams, and symlink reparse points.
8. **Atomic Persistence**: State files are written atomically using temporary files and physical fsync to prevent partial write corruption.
9. **Single-Instance Process Identity**: Single-instance mutex validation checks both PID and process creation timestamp to defeat PID reuse attacks.
10. **Command Whitelisting for IPC**: The local control channel strictly permits only `START`, `STOP`, and `RESTART` commands. Arbitrary command execution is impossible.
11. **Cryptographic Release Verification**: Update packages require valid pure-Python RFC 8032 Ed25519 digital signatures and streaming SHA-256 digests.
12. **Non-Destructive Operations**: Repair and uninstallation procedures strictly preserve user configuration files and credential stores by default.

---

## 2. Authentication & Credential Protection

### Password Non-Collection Invariant
Operating system authentication failure monitors strictly extract only non-sensitive metadata:
* Timestamp
* Target username (e.g. `john_doe`)
* Remote IP address (or `"Local Console"`)
* Service / source name (e.g. `sshd`, `wevtutil(4625)`, `loginwindow`)

Attempted passwords, hashes, and PIN codes are stripped at the log ingestion boundary. In macOS and Linux log parsers, an active credential scrubber (`_scrub_entry`) sanitizes raw message snippets before storage.

### Credential Storage Backends
1. **Windows DPAPI**: On Windows, Telegram credentials can be encrypted using the Windows Data Protection API (`CryptProtectData`), binding decryption keys directly to the logged-in Windows user account.
2. **Encrypted Secret Store**: On platforms where DPAPI is unavailable, credentials reside in AES-encrypted local secret stores or permission-restricted `.env` files.
3. **`SecretValue` Wrapper**: In Python memory, tokens are wrapped in `SecretValue` containers that override `__repr__` and `__str__` to output `***REDACTED***`.

### Centralized Redaction Engine
The [`SecretRedactor`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/security/redactor.py#L35) engine actively intercepts and scrubs registered credentials and token patterns (`bot\d{6,12}:[A-Za-z0-9_-]{30,}`) from:
* Rotating log files (`device_guardian.log`)
* Uncaught exception tracebacks
* Status inspection surfaces (`--config-show`, `--status`)
* Dynamic alert reason strings before transmission to Telegram

---

## 3. Filesystem & Path Traversal Protections

All filesystem operations pass through [`validate_safe_path()`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/security/filesystem.py#L29):

```text
Input Path
    │
    ├── Null Byte Check (\0) ───────────────► REJECT (SecurityPathError)
    ├── Encoded Traversal (%2e%2e, %00) ────► REJECT (SecurityPathError)
    ├── UNC Network Path Check (\\server) ──► REJECT (SecurityPathError)
    ├── Alternate Data Stream (file:stream) ─► REJECT (SecurityPathError)
    ├── Drive-Relative Check (C:file) ──────► REJECT (SecurityPathError)
    ├── Symlink / Reparse Point Check ──────► REJECT (SecurityPathError)
    └── Directory Containment (Resolve) ────► PASS
```

---

## 4. Local IPC & Single-Instance Mutex Security

To prevent malicious local processes from interfering with Device Guardian:

### 1. Whitelisted Command Schema
The control file `guardian.control` accepts only structured JSON control messages conforming to [`ControlMessage`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/security/ipc.py#L78):
* Permitted commands: `START`, `STOP`, `RESTART`.
* Unwhitelisted commands (`EXEC`, `CMD`, `POWERSHELL`, `SHELL`) are rejected with a security audit event.

### 2. Anti-Replay & Expiry Controls
* **UUID Request IDs**: Every message has a unique `request_id`. An in-memory cache rejects duplicate or replayed IDs.
* **TTL Expiration**: Messages carry a default 30-second TTL (`expires_at`). Expired messages are unlinked without execution.
* **Clock Skew Defense**: Messages with creation timestamps more than 60 seconds into the future are rejected.

### 3. Single-Instance Mutex Hardening
To prevent denial-of-service via PID reuse or spoofing:
* On Windows, [`SingleInstanceLock`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/runtime/single_instance.py) queries `QueryFullProcessImageNameW` and `GetProcessTimes` to verify that the locking process is genuinely python/device-guardian and matches the lock creation timestamp.

---

## 5. Cryptography & Update Verification

All release packages and update archives are verified using a dual cryptographic gate before staging or execution:

### 1. Streaming SHA-256 Integrity
Files are read in 64 KB streaming chunks to calculate SHA-256 digests. This prevents memory exhaustion and detects any single-byte corruption or file truncation.

### 2. RFC 8032 Ed25519 Authenticity
Release manifests (`release-manifest.json`) are canonicalized into deterministic JSON (sorted keys, compact separators) and verified against the official Ed25519 public key.
* The implementation uses pure-Python RFC 8032 elliptic curve arithmetic, requiring zero C extensions or external binary wheels.
* If signature verification fails, the package is immediately discarded.

### 3. Safe Archive Extraction (`SafeZipExtractor`)
Update `.zip` files are unpacked under strict constraints:
* **Directory Traversal**: Rejects members with `..`, absolute paths, or drive letters.
* **File Size Caps**: Rejects single files exceeding 250 MB or total uncompressed archives exceeding 500 MB.
* **Member Count Limits**: Rejects archives containing more than 50 files.
* **Prohibited File Extensions**: Rejects shell scripts and batch files (`.bat`, `.cmd`, `.sh`, `.ps1`, `.vbs`).
* **Casing Collisions**: Rejects case-insensitive name collisions (e.g. `binary.exe` vs `BINARY.EXE`) to prevent NTFS extraction hijacking.

---

## 6. Network Perimeter & Isolation

| Boundary | Behavior |
| :--- | :--- |
| **Inbound Sockets** | **Zero**. No listening TCP/UDP ports, HTTP servers, or socket listeners. |
| **Outbound Telegram** | Strict HTTPS outbound to `api.telegram.org:443`. Only invoked if credentials are configured. |
| **Outbound Geolocation** | Strict HTTPS outbound to `ipapi.co:443`. Bounded timeout (`[0.5, 60.0]s`). |
| **Telemetry / Tracking** | **Zero**. No usage analytics, tracking pixels, crash beacons, or remote logging. |
| **Offline Operation** | Monitoring, event evaluation, and voice alerts continue uninterrupted when network is down. |

---

## 7. Logging & Terminal Security

* **Log Injection Defense**: Carriage returns (`\r`) and newlines (`\n`) in log arguments are sanitized to `\n` to prevent log forging attacks.
* **ANSI Escape Stripping**: Terminal control sequences are stripped from log messages to prevent terminal hijacking.
* **Length Limits**: Individual log records are capped at 65,536 characters.
* **Audit Trail Protection**: `DuplicateLogFilter` never suppresses `CRITICAL` records or events from `security.*` loggers, preventing attackers from blinding operators through log-flooding.

---

## 8. Release Verification & Authenticode Status

* **Application-Level Verification**: **IMPLEMENTED & VERIFIED**. Standalone release executables and update packages are verified via SHA-256 hashes and Ed25519 digital signatures documented in `release-manifest.json`.
* **Windows Authenticode Signing**: **NOT VERIFIED / NOT IMPLEMENTED**. Commercial EV/OV Authenticode signing requires an active commercial CA subscription and hardware HSM token, which is not applied in local development builds.
