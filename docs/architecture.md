# Device Guardian — Technical Architecture Specification

This document provides a comprehensive architectural specification of the Device Guardian system, covering component relationships, execution lifecycles, security boundaries, and data flows.

---

## 1. High-Level Component Architecture

```
                          ┌────────────────────────┐
                          │   OPERATOR INTERFACE   │
                          │ CLI / System Tray Menu │
                          └───────────┬────────────┘
                                      │ IPC (Commands / Signals)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             GUARDIAN RUNTIME                                │
│                                                                             │
│   ┌────────────────────────┐                   ┌────────────────────────┐   │
│   │ Single-Instance Lock   │                   │ Reliability Engine     │   │
│   │ (PID & File Semaphore) │                   │ (Metrics / Watchdog)   │   │
│   └────────────────────────┘                   └────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         DETECTION ENGINE                            │   │
│   │                                                                     │   │
│   │   [ Windows Security Log ] [ Linux auth.log ] [ macOS Unified Log ] │   │
│   │                 │                  │                  │             │   │
│   │                 └──────────────────┼──────────────────┘             │   │
│   │                                    ▼                                │   │
│   │                      [ Normalizer & Sliding Window ]                │   │
│   │                                    ▼                                │   │
│   │                   [ Priority & Smart Filter Engine ]                │   │
│   └────────────────────────────────────┬────────────────────────────────┘   │
│                                        │ Trigger Alert Event                │
│                                        ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                          ALERT SUBSYSTEM                            │   │
│   │                                                                     │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │       BoundedAlertQueue (Capacity: 100, Priority-Aware)     │   │   │
│   │   └──────────────────────────────┬──────────────────────────────┘   │   │
│   │                                  ▼ Worker Thread                    │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │                     Sensor Enrichment                       │   │   │
│   │   │        [ OpenCV Webcam ]     [ IP Geolocation API ]         │   │   │
│   │   └──────────────────────────────┬──────────────────────────────┘   │   │
│   │                                  ▼                                  │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │                     Secret Redactor                         │   │   │
│   │   │   (Strips Tokens, Passwords, Session IDs from Message)      │   │   │
│   │   └──────────────────────────────┬──────────────────────────────┘   │   │
│   │                                  ▼                                  │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │          Telegram Dispatcher (Protected by CircuitBreaker)  │   │   │
│   │   └─────────────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                 RECOVERY & TRANSACTION SUBSYSTEM                    │   │
│   │                                                                     │   │
│   │   [ Atomic Persistence ]  [ State Repair Engine ]  [ Update Txn ]   │   │
│   │   (Write -> Sync -> Rename)  (.bak & .corrupt fallback)  (Ed25519)  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Subsystem Descriptions

### Detection Subsystem
- **Adapters**: OS-specific event pollers (`WindowsSecurityLogMonitor`, `LinuxAuthLogMonitor`, `MacOSAuthLogMonitor`) that run on background threads and stream raw events to the normalizer.
- **Normalization**: Maps raw system events (e.g. Windows Event ID 4625, Linux PAM failure) into a standardized `AuthenticationFailureEvent` containing timestamp, username, IP address, and logon type.
- **Sliding-Window Correlation**: Evaluates count of failures within `ATTEMPTS_WINDOW_SECONDS` (default: 60). Expired events are automatically pruned to prevent memory growth.
- **Smart Filtering**: Applies a strict priority hierarchy (Priorities 10 to 70) to suppress maintenance periods, known service accounts, and cooldown windows before triggering alarms.

### Alerting & Sensor Subsystem
- **Priority-Aware Queue (`BoundedAlertQueue`)**: Enforces a strict 100-item ceiling. If saturated, higher-priority intrusion events deterministically evict lower-priority informational items.
- **Sensor Enrichment**:
  - `Camera`: Captures a single image via OpenCV using OS-optimized backends (`CAP_DSHOW` on Windows).
  - `Geolocation`: Resolves approximate location via HTTPS (`ipapi.co`) with circuit-breaker protection.
- **Telegram Dispatcher**: Packages sanitized event metadata and optional photo into Telegram Bot API requests. Wrapped in a `CircuitBreaker` (trips after 5 failures, 30s recovery).

### Security & Cryptography Subsystem
- **Credential Protection**: Implements DPAPI on Windows (`CryptProtectData`) to lock secrets to the interactive user. On non-Windows, uses PBKDF2-HMAC-SHA256 with AES-GCM authenticated encryption.
- **Secret Redaction**: High-throughput regex engine (`SecretRedactor`) filters logs and outbound messages to prevent accidental exposure of tokens, authorization headers, private keys, or passwords.
- **Path Traversal Defense**: `validate_safe_path` ensures all file I/O resolves within authorized base roots.
- **Update Verification**: Release manifests verified using Ed25519 public keys and streaming SHA-256 chunking.

### Reliability & Recovery Subsystem
- **Metrics Tracker**: Records RSS memory, thread counts, queue high watermarks, and error counts in real-time.
- **Atomic Persistence**: Serializes state files using an isolated staging file (`.tmp`), calls `os.fsync`, and atomically replaces the target (`os.replace`) with Windows-specific retry handling.
- **Self-Healing State**: If `runtime_status.json` is corrupted, preserves the corrupted file as `.corrupt.<timestamp>` and restores a clean baseline.

---

## 3. Directory Layout & Filesystem Boundaries

Device Guardian enforces strict physical separation between application binaries and runtime data:

```
Installation Root (Read-Only)
└── C:\Program Files\Device Guardian\ (or repo root during dev)
    ├── DeviceGuardian.exe (or src/device_guardian/)
    ├── release-manifest.json
    └── LICENSE / README.md

User Data Directory (Read/Write, Protected ACLs)
└── %LOCALAPPDATA%\DeviceGuardian\ (or ~/.local/share/device-guardian)
    ├── .env                         <- Local operator configuration
    ├── secret_store.enc             <- DPAPI / AES encrypted credential vault
    ├── guardian.lock                <- Single-instance PID lock file
    ├── guardian.control             <- IPC control socket / named pipe
    ├── runtime_status.json          <- Active daemon health state
    ├── update_transaction.json      <- Persistent update state machine
    └── logs\
        └── device_guardian.log      <- Rolling application logs
```

---

## 4. Threat & Privilege Boundaries

1. **Standard User Privilege Model**: Device Guardian runs entirely within standard user context. It does not require continuous administrator or `root` execution.
2. **IPC Command Whitelist**: The IPC socket (`guardian.control`) strictly accepts whitelisted commands (`PING`, `STATUS`, `STOP`, `PAUSE`, `RESUME`). Arbitrary execution strings are rejected.
3. **No Database Dependencies**: The architecture deliberately avoids embedded database engines (SQLite, BerkeleyDB) to eliminate memory corruption vectors and lock contention issues.
