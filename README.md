# Device Guardian

> **A zero-cost, personal-use anti-theft & intrusion alert system for PC and Android.**

---

## 1. Overview

**Device Guardian** is an open-source, consent-based security and anti-theft tool created for device owners. When security events occur, Device Guardian swiftly captures physical and situational context (such as an approximate location and a single camera photograph) and dispatches an alert to the user's personal Telegram chat.

### Architecture

Device Guardian is built in progressive, disciplined phases:
- **Phase 1: PC Core Alert Pipeline**: Foundational alerting engine combining single-frame webcam capture, approximate IP-based geolocation, and HTTPS Telegram Bot API delivery.
- **Phase 2: Setup Wizard & First-Run Configuration**: Guided interactive CLI setup wizard enabling device owners to pair their Telegram bot, detect their Chat ID automatically, test camera hardware and geolocation, and persist settings safely.
- **Phase 3: Detection Triggers & Offline Voice Warning**: First automatic security detection layer monitoring repeated OS-level authentication failures (Windows Event Log, Linux PAM/SSH, macOS Unified Log), normalized event evaluation with sliding-window thresholds, cooldown debouncing, and local offline text-to-speech voice warnings.
- **Phase 4: Smart Filtering & Environmental Triggers**: Deterministic, rule-based filtering (no AI, ML, or behavioral profiling), non-invasive environmental context (device state: active/idle/locked/unknown, network state: connected/disconnected/unknown), explicit trusted context (users, networks, auth types), threshold verification, and safety-gated alert dispatch.
- **Phase 5: Packaging, Background Services & System Tray Integration**: Portable standalone binary packaging with PyInstaller, GuardianRuntime background worker lifecycle, dynamic system tray integration, single-instance execution protection, OS startup configuration, and crash recovery.
- **Phase 6: Secure Configuration, Credential Management & Production Secrets Hardening**: Secure loading, masking, rotating, testing, and diagnosing configuration and notification credentials. `SecretValue` encapsulation, Windows DPAPI / filesystem encrypted credential storage, centralized secret redaction filter, structured subsystem readiness auditing, and actionable configuration workflows without secret leakage.
- **Phase 7: Secure Updates, Versioning & Release Integrity**: Authoritative semantic versioning (RFC 2.0.0), deterministic cryptographic integrity verification (streaming SHA-256), cryptographic authenticity verification (pure-Python RFC 8032 Ed25519 digital signatures), canonical release manifest schema (`release-manifest.json`), safe archive unpacking (`SafeZipExtractor`) with path traversal and zip bomb defenses, atomic staging, crash recovery state machine, reliable user-controlled installation, and rollback restoration preserving user configuration and secrets.
- **Phase 8: Disaster Recovery, Resilience & Failure-Injection Hardening**: Operational survivability and disaster recovery layer. Robust `AtomicPersistence` with thread-safe temporary files, `.bak` backup-on-write, physical fsync, and atomic replace retry loops; comprehensive subsystem health assessment engine (`SystemHealthReport`); safe state file repair and reset without overwriting secrets; installation integrity verification against release manifests; and hardened bounded retries with notification/detection decoupling to prevent alert storms under network failures.
- **Phase 9: Production Security, Threat Modeling & Local Attack-Surface Hardening**: Production security, deterministic threat modeling, and local attack-surface hardening. Strict filesystem security validating against path traversal (`..`), UNC paths, NTFS Alternate Data Streams (ADS), drive-relative paths, and symlink/junction reparse points; hardened local IPC control channel with whitelisted commands (`START`, `STOP`, `RESTART`), UUID request IDs, TTL expiry, and replay protection; single-instance lock hardening with process image verification and creation timestamp checks to defeat PID reuse; update serialization locks eliminating race conditions; hardened ZIP extraction preventing case-insensitive collisions and duplicate members; log injection defenses sanitizing `\r\n` log arguments, bounding record lengths, and stripping ANSI escape sequences; strict configuration bounds; and formal threat modeling documented in `SECURITY.md`.
- **Phase 10: Production UX, Operator Experience & Accessibility Hardening**: Comprehensive accessibility and operational ergonomics. Color-independent state model with geometric glyphs (`[● HEALTHY]`, `[▲ DEGRADED]`, `[■ FAILED]`, `[? UNKNOWN]`, `[- NOT_CONFIG]`), 15-point operator status surface (`--status`), non-destructive operation confirmation contracts (`--yes` bypass), deterministic CLI exit code matrix (0-3), and strict uncertainty invariants (`UNKNOWN != SAFE`, `NOT_CONFIGURED != PROTECTED`).
- **Phase 11: Production Integration, End-to-End Validation & Release Readiness**: System-wide integration and release-readiness verification. Comprehensive end-to-end integration test suites across alert pipeline, notifications, runtime lifecycle, configuration/secret recovery, updates/rollback, and operator journeys (428 passed, 1 skipped). Static security reviews, privacy boundary validation, zero-telemetry enforcement, release artifact secret scans, and verified standalone executable packaging (`dist/device-guardian.exe`).
- **Phase 12: Production Distribution, Installer Engineering & Application Lifecycle Management**: Production distribution and application lifecycle management. Architectural separation between read-only application binaries (`INSTALL_ROOT`) and mutable configuration/logs/credentials (`USER_DATA`); transactional fresh install, upgrade, repair, and uninstallation workflows; authoritative SemVer 2.0.0 comparison and downgrade defense; versioned persistent schema migration framework with pre-migration snapshot backups and automatic rollback; release artifact secret scanning; reproducible build metadata (`build-metadata.json`); and non-destructive data preservation guarantees (476 passed, 1 skipped).


```text
                 DEVICE GUARDIAN
                       │
                       ▼
             ┌───────────────────┐
             │ Detection Manager │
             └─────────┬─────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
      OS Login Monitor     Future Triggers
     (Win / Linux / Mac)
             │
             ▼
      Event Normalization (No Passwords / Credentials)
             │
             ▼
     ┌───────────────────────────────────┐
     │     Sliding-Window Threshold      │ (e.g. 3 in 60s)
     └─────────────────┬─────────────────┘
                       │
                       ▼
     ┌───────────────────────────────────┐
     │        Smart Filter Engine        │
     │  - Safety & Disabled Rules        │
     │  - Synthetic Test Bypass          │
     │  - Explicit Trusted Context       │ (Users / Networks / Auth)
     │  - Environmental Context Check    │ (Active/Locked/Connected)
     │  - Threshold Confirmation         │
     │  - Alert Eligibility Rule         │
     └─────────────────┬─────────────────┘
                       │ (ALLOW / ALERT_ELIGIBLE)
                       ▼
          Alert Cooldown Manager (e.g. 300s window)
                       │
                ┌──────┴──────┐
                ▼             ▼
          Offline Voice  trigger_alert()
             Warning          │
                          ┌───┴───┐
                          ▼       ▼
                       Camera  Telegram
                       (Safety Gated)
```

---

## 2. What Device Guardian Does

### Phase 1: Core Alert Pipeline
- **Single-Frame Camera Capture**: Activates the configured webcam, captures a single still photograph for visual verification, and immediately releases hardware resources in a guaranteed `finally` block.
- **Approximate Geolocation**: Queries an external IP-based geolocation service to estimate city, region, country, and coordinates. Generates a clickable Google Maps link when coordinates are available (strictly IP-based, no GPS hardware collection).
- **Telegram Notification Delivery**: Dispatches alert information directly to the owner's private Telegram chat over HTTPS via the official Telegram Bot API.
- **Safe Resource Cleanup**: Temporary capture photographs are stored in a dedicated temporary folder and deleted immediately upon successful Telegram delivery.
- **Robust Error Handling**: Never crashes on network timeouts, missing webcams, or location failures; gracefully falls back to text-only alerts if the camera is unavailable.
- **Privacy Protections & Secret Redaction**: Bot tokens and secrets are strictly redacted from logs, representations, and exception messages.

### Phase 2: Setup Wizard & First-Run Configuration
- **Interactive First-Run Setup Wizard (`--setup`)**:
  - Transparent Privacy & Permissions disclosure with explicit user consent.
  - Step-by-step guidance for creating a personal Telegram bot via `@BotFather`.
  - Immediate bot token validation via the Telegram Bot API (`getMe`).
  - Automatic, bounded Chat ID detection from incoming Telegram messages with data minimization.
  - Conservative camera enumeration and single-frame lifecycle capture testing.
  - Live approximate IP geolocation verification.
  - Complete configuration review before saving.
  - Atomic configuration writing with automatic `.env.bak` backup and rollback on failure.
  - Safe reconfiguration without destroying previously working settings.

### Phase 3: Detection Triggers & Offline Voice Warning
- **OS Authentication Failure Monitoring**:
  - **Windows**: Queries the Windows Security Event Log for Event ID 4625 (Logon Failure) via `wevtutil`, distinguishing between local console failures (LogonType 2, 7, 11) and remote connection failures (LogonType 3, 8, 10). Handles non-elevated user permissions gracefully without crashing.
  - **Linux**: Tails standard authentication logs (`/var/log/auth.log` or `/var/log/secure`), normalizing PAM authentication failures, local console logins, and SSH failed passwords.
  - **macOS**: Queries the macOS Unified Logging System (`log show`) for authentication failure events from `loginwindow`, `authorizationhost`, and `sshd`.
- **Event Normalization & Privacy Guarantee**: Normalizes all platform log entries into a common `AuthenticationFailureEvent` containing only timestamp, platform, source, sanitized username, and remote address. **Never captures, intercepts, or stores passwords or raw credentials**.
- **Sliding-Window Threshold Engine**: Tracks failure timestamps in memory using a sliding time window (configurable, default: 3 failures within 60 seconds). Automatically evicts expired failures to prevent false alarms from spaced-out normal user typos.
- **Alert Cooldown & Storm Prevention**: A state machine (`READY`, `THRESHOLD_REACHED`, `ALERT_SENT`, `COOLDOWN`, `ERROR`) enforces a minimum cooldown period (configurable, default: 300 seconds) between dispatched alerts, while background monitoring continues uninterrupted.
- **Offline Text-to-Speech Voice Warning**: Locally synthesizes an audible security warning upon threshold breach without internet access or third-party cloud services:
  - **Windows**: Uses native `System.Speech` via PowerShell.
  - **macOS**: Uses native `/usr/bin/say`.
  - **Linux**: Uses local speech dispatchers (`spd-say`, `espeak-ng`, `espeak`).

### Phase 4: Smart Filtering & Environmental Triggers
- **Deterministic Rule-Based Filtering**:
  - Evaluates security events against a priority-ordered rule pipeline without AI, machine learning, heuristic scoring, or behavioral profiling.
  - Every filter decision produces an explainable, auditable reason logged cleanly for transparency.
  - Rules evaluate strictly in descending priority: Safety/Emergency (10) -> Disabled Bypass (20) -> Synthetic Test Bypass (30) -> Explicit Trusted Context (40) -> Environmental Context (50) -> Threshold Evaluation (60) -> Alert Eligibility (70).
- **Non-Invasive Environmental Detection**:
  - **Device Session State**: Inspects local desktop lock state without capturing user activity or screen content. On Windows, uses native `OpenInputDesktop` API via `ctypes`; on Linux, queries `loginctl`; on macOS, queries Quartz framework; falls back safely to `UNKNOWN` on any error.
  - **Network Connectivity State**: Detects primary routable interface and local IP address using local routing table lookups (`192.0.2.1` test socket) without transmitting network packets or performing LAN port scanning.
  - **Safe Fallback**: Recognizes that `UNKNOWN != THREAT`. If environmental detection fails or is inconclusive, events are safely suppressed if strict context is required, rather than triggering false-positive alerts.
- **Explicit Trusted Context**:
  - Device owners can declare trusted usernames (`DEVICE_GUARDIAN_TRUSTED_USERS`), trusted subnets/IPs (`DEVICE_GUARDIAN_TRUSTED_NETWORKS`), and trusted authentication types (`DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES`).
  - Matches are evaluated case-insensitively and normalized.
  - If a failure event matches trusted context, it is suppressed (`Decision: FILTER`) without initiating alerts or camera capture.
- **Safety Gates**:
  - Alert pipeline incorporates explicit gate switches: `CAMERA_ALERT_ENABLED`, `LOCATION_ALERT_ENABLED`, and `TELEGRAM_ALERT_ENABLED`.
  - Disabling any gate skips that specific step while allowing the rest of the alert pipeline to proceed safely.

### Phase 5: Packaging, Background Services & System Tray Integration
- **GuardianRuntime Background Lifecycle**:
  - Independent background worker process coordinating continuous detection monitoring, thread safety, and graceful shutdown.
  - Robust runtime finite-state machine (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `STOPPING`, `FAILED`).
  - Single-instance process coordination via native OS Named Mutex (`Global\DeviceGuardian_SingleInstance_Mutex`) on Windows and flock on POSIX with stale PID cleanup.
  - IPC control signaling (`guardian.control`) allowing external CLI and tray commands to signal running workers.
- **Dynamic System Tray Desktop Interface**:
  - Standalone desktop notification icon powered by `pystray` and `Pillow`.
  - Real-time dynamic visual shield state indicators (Green: Running, Gray: Stopped, Blue: Starting, Amber: Stopping, Red: Error).
  - Background context menu allowing runtime start/stop/restart, manual test alerts, startup launch toggle, and clean exit.
  - Headless degradation: safely degrades to terminal mode in headless environments without errors.
- **Cross-Platform OS Startup Integration**:
  - Configurable auto-launch on user session login requiring only standard user permissions (`HKCU\...\Run` on Windows, XDG Autostart on Linux, user LaunchAgent on macOS).
- **Standalone Portable PyInstaller Packaging**:
  - Zero-dependency desktop executable packaging with runtime path resolution (`ApplicationPaths`) ensuring read-only bundles never mutate application assets.

### Phase 6: Secure Configuration & Credential Hardening
- **SecretValue Encapsulation & Masking**:
  - Sensitive credentials (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) are wrapped in `SecretValue` containers.
  - Default string (`str()`) and representation (`repr()`) representations strictly output masked redactions (e.g., `123***...***XYZ`), eliminating inadvertent leakages in logs, traces, or debug outputs.
- **Platform-Secured Credential Storage**:
  - **Windows DPAPI Storage**: Uses Win32 `CryptProtectData` and `CryptUnprotectData` to bind secrets cryptographically to the logged-in user account.
  - **Restrictive Filesystem Storage**: POSIX-compliant file storage enforcing `0600` user-only permissions.
- **Centralized Secrets Redaction Filter**:
  - Log handler stream filter scrubs bot tokens, authorization bearer headers, and private Telegram URLs before disk persistence.
- **Subsystem Readiness Validation (`--config-check`)**:
  - Comprehensive, non-leaking configuration audit assessing readiness across all subsystems.

### Phase 7: Secure Updates, Versioning & Release Integrity
- **Authoritative Semantic Versioning & Downgrade Prevention**:
  - Single source of truth for version definitions (`0.1.0`) strictly adhering to Semantic Versioning 2.0.0 (RFC 2.0.0).
  - Automated downgrade detection prevents rollbacks to older, vulnerable releases unless explicitly authorized by the user via `--allow-downgrade`.
- **Dual-Layer Integrity & Authenticity Verification**:
  - **Integrity**: Streaming SHA-256 chunked calculation over binaries and packages ensures artifacts are not damaged, truncated, or corrupted.
  - **Authenticity**: Pure-Python RFC 8032 Ed25519 digital signature verification guarantees releases originate strictly from the authentic project release key, with zero external C-extensions or network calls.
- **Strict Canonical Release Manifest (`release-manifest.json`)**:
  - Cryptographically signed release manifests define artifact filenames, exact byte lengths, SHA-256 digests, target OS platform, and architecture.
  - Canonical JSON normalization ensures deterministic byte-for-byte signature verification.
- **Safe Archive Unpacking (`SafeZipExtractor`)**:
  - Multi-layer defense-in-depth zip extractor rejecting path traversal attempts (`..`, absolute paths, drive letters).
  - Enforces individual file size limits (250 MB) and total uncompressed archive limits (500 MB) against zip bomb attacks.
  - Blocks executable shell scripts (`.bat`, `.cmd`, `.sh`, `.vbs`, etc.) and symlink redirection attacks.
- **Multi-Gate Verification Pipeline (`verify_update_package`)**:
  - Candidate packages pass seven sequential gates before staging: existence, archive security, manifest schema, digital signature authenticity, platform compatibility, version progression, and binary SHA-256 verification.
- **Transactional Deployment & Crash Recovery FSM**:
  - Full transactional lifecycle (`IDLE` -> `VERIFYING` -> `VERIFIED` -> `BACKING_UP` -> `STAGING` -> `INSTALLING` -> `VALIDATING` -> `COMPLETED`).
  - Startup crash recovery (`check_and_recover_interrupted_transaction`) automatically detects interrupted installations and flags rollback without leaving broken binaries.
- **Safe Rollback & User State Preservation**:
  - Backups of the previous verified binary are safely stored in `%LOCALAPPDATA%\DeviceGuardian\updates\backup\`.
  - Rollback restoration swaps binaries while guaranteeing that user configuration (`.env`), secret stores (`secrets.dat`), and runtime logs are never overwritten or deleted.
- **Absolute User Control (Zero-Trust Release Architecture)**:
  - **Zero silent updates, zero background network fetching, zero hidden downloads, zero remote code replacement, and zero cloud telemetry**. All updates require explicit user CLI or dashboard commands.

### Phase 8: Disaster Recovery, Resilience & Failure-Injection Hardening
- **Universal Thread-Safe Atomic Persistence (`AtomicPersistence`)**:
  - Replaces all brittle direct file writes across runtime status, update transactions, and credential storage.
  - Generates unique temporary files with process ID, thread identity, and monotonic nanosecond timestamps (`{filename}.tmp.{pid}.{thread_id}.{time_ns}`) to eliminate file collision.
  - Implements automatic `.bak` backup creation prior to file modification.
  - Enforces physical disk synchronization (`flush()` and `os.fsync()`) before file movement.
  - Provides atomic replacement via `os.replace` wrapped in a Windows-tuned retry loop with exponential backoff to handle transient antivirus locks and file contention (`[WinError 32]` / `[WinError 5]`).
  - Thread-safe recovery automatically restores from `.bak` backup if the primary JSON file is corrupted or truncated.
- **Deterministic Multi-Subsystem Health Engine (`assess_system_health`)**:
  - Structured, non-AI health assessment inspecting 8 core subsystems: Configuration, Secret Storage, Intrusion Detection Monitor, Camera Sensor, Geolocation Sensor, Telegram Notification Channel, Update Subsystem, and Single-Instance Lock.
  - Produces an explainable, strongly-typed `SystemHealthReport` with categorical health statuses (`HEALTHY`, `DEGRADED`, `FAILED`, `UNKNOWN`, `NOT_CONFIGURED`).
  - Audits presence and integrity of all state and backup files.
- **Non-Destructive State Repair & Safe Reset (`repair_state_files`)**:
  - Safely detects corrupted, malformed, or zero-byte state files (`runtime_status.json`, `update_transaction.json`).
  - Preserves corrupted data for forensic inspection by backing it up to `.corrupt.<timestamp>` before applying clean default state.
  - **Zero Data Loss Guarantee**: Under no circumstances resets, truncates, or overwrites user `.env` configurations or encrypted credential stores (`secrets.dat` / `secrets.json`).
- **Binary & Installation Integrity Verification (`verify_installation_integrity`)**:
  - Verifies presence, read/write permissions, and disk integrity of the application installation and local data directory.
  - In packaged frozen mode, cross-checks running executable byte length and streaming SHA-256 against the embedded release manifest.
- **Decoupled Detection & Hardened Bounded Retries**:
  - Bounded exponential retries (up to 2 retries, 3 total attempts) for transient Telegram network failures (HTTP 429 rate-limiting, 5xx server errors, socket timeouts). Immediate failure without retries for permanent client errors (HTTP 400, 401, 403).
  - Complete token redaction across all exception strings, traceback entries, and network log records.
  - Decouples local intrusion detection state from notification delivery: sliding-window thresholds and cooldown timers are properly registered upon trigger even if network delivery fails, preventing continuous 2-second alert storms during network outages.

### Phase 9: Production Security, Threat Modeling & Local Attack-Surface Hardening
- **Local Filesystem & Reparse-Point Defense (`validate_safe_path`, `is_symlink_or_reparse_point`)**:
  - Rejects null bytes, path traversal (`..`), UNC network paths (`\\server\share`, `//server/share`), NTFS Alternate Data Streams (`file:stream`), and drive-relative paths (`C:file.txt`).
  - Defends against directory junctions and symbolic links using native Windows `FILE_ATTRIBUTE_REPARSE_POINT` (0x0400) inspections and POSIX `lstat`.
  - Enforces strict directory containment policies (no jailbreaking from app or updates staging directories).
  - Creates collision-resistant temporary files via `secure_create_temp_file` using `os.O_EXCL | os.O_CREAT` flags.
- **Hardened Local IPC / Control Channel (`ControlChannel`, `ControlMessage`)**:
  - Whitelists only explicit local lifecycle commands (`START`, `STOP`, `RESTART`); strictly rejects arbitrary command injection strings (`EXEC`, `SHELL`, `CMD`, `POWERSHELL`, `SCRIPT`, `RUN`).
  - Enforces strict JSON schema validation, UUID request IDs, and 30-second TTL limits.
  - Prevents replay attacks via in-memory request cache and detects future clock skew (> 60 seconds).
  - Uses atomic file operations avoiding symlinks; operates with zero listening network ports or sockets.
- **Single-Instance Lock Hardening with PID Reuse Defense**:
  - Queries Windows `QueryFullProcessImageNameW` and verifies the running executable matches `python` or `device-guardian`.
  - Inspects process creation timestamps via `GetProcessTimes` to defeat PID recycling attacks.
  - Requires only unprivileged `PROCESS_QUERY_LIMITED_INFORMATION` permissions (no UAC elevation).
  - Purges negative, zero, non-integer, or malformed PIDs safely.
- **Safe ZIP Archive Hardening (`SafeZipExtractor`)**:
  - Rejects duplicate member entries and case-insensitive filename collisions (`file.exe` vs `FILE.EXE`).
  - Scans ZIP header external attributes for Windows reparse points (`0x0400`) and POSIX symlinks.
  - Enforces uncompressed file size caps (250 MB single, 500 MB total) and member limits (50 files).
- **Update Concurrency & Replacement Hardening**:
  - `_UpdateLockContext` exclusively serializes all update and rollback operations via `updates/update.lock`.
  - Pre-replacement security validation verifies `target_exe`, `.exe.old`, and destination paths are free of symlinks and reparse points before file swaps.
- **Log Injection & Secret Scrubbing (`RedactingFilter`, `SecretRedactor`)**:
  - Sanitizes log arguments by converting unescaped carriage returns and newlines (`\r\n`, `\n`) into `\n` to prevent log line forging and fake log level injection.
  - Bounds log record lengths to 65,536 characters.
  - Automatically scrubs URL query parameters (`?token=...`, `&apiKey=...`), Basic auth headers, ANSI escape sequences (`\x1b[...]`), and non-printable control characters.
  - Configures `RotatingFileHandler` with 10 MB limit and 5 backups.
- **Strict Configuration Bounds & Boolean Parsing**:
  - Rejects ambiguous boolean strings with actionable `ConfigurationError` messages.
  - Bounds all numerical settings (`camera_index`, `request_timeout_seconds`, `auth_failure_threshold`, `auth_failure_window_seconds`, cooldowns).
  - Masks `telegram_chat_id` in `AppConfig.__repr__`.
- **Formal Threat Model & Invariants**:
  - Full threat model and trust boundaries documented in [SECURITY.md](file:///C:/Users/Nibras/device-guardian/SECURITY.md).

---

## 3. What Device Guardian Does NOT Do

To maintain safety, privacy, and development discipline, Device Guardian strictly excludes:

- ❌ No credential collection, password dumping, or keylogging
- ❌ No continuous camera recording or covert surveillance
- ❌ No hidden persistence, auto-start, stealth mode, or process disguising
- ❌ No antivirus evasion or anti-analysis techniques
- ❌ No remote command execution or remote shell through Telegram
- ❌ No Bluetooth, Wi-Fi packet sniffing, or network connection monitoring
- ❌ No screen recording or arbitrary file uploads
- ❌ No Android or SMS functionality (reserved for Android phase)
- ❌ No silent auto-updates, background downloads, or unexpected binary replacement
- ❌ No cloud telemetry, phone-home beacons, or external version tracking
- ❌ No unverified or unsigned update staging or installation
- ❌ No destructive rollback or configuration wiping

---

## 4. Project Structure

```text
device-guardian/
│
├── README.md                     # Documentation and architecture guide
├── LICENSE                       # MIT License
├── .gitignore                    # Excludes .env, logs, pycache, temp files
├── requirements.txt              # Minimal project dependencies
├── pyproject.toml                # Project metadata & pytest configuration
├── .env.example                  # Environment configuration template
│
├── src/
│   └── device_guardian/
│       ├── __init__.py           # Package version definition
│       ├── main.py               # CLI entrypoint & commands
│       ├── config.py             # Secure configuration loading & validation
│       ├── logger.py             # Redacting logger setup
│       │
│       ├── camera/
│       │   ├── __init__.py
│       │   └── capture.py        # Single-frame webcam capture & resource cleanup
│       │
│       ├── location/
│       │   ├── __init__.py
│       │   └── geolocation.py    # Approximate IP geolocation & map URL generation
│       │
│       ├── telegram/
│       │   ├── __init__.py
│       │   └── bot.py            # Telegram Bot API client (HTTPS only)
│       │
│       ├── alerts/
│       │   ├── __init__.py
│       │   ├── models.py         # AlertEvent data model & message formatter
│       │   └── pipeline.py       # Core reusable alert pipeline
│       │
│       ├── setup/
│       │   ├── __init__.py       # Setup package exports
│       │   ├── status.py         # SetupStatus determination (NOT_CONFIGURED, etc.)
│       │   ├── storage.py        # Atomic configuration saving & rollback
│       │   ├── chat_detector.py  # Bounded Telegram chat ID detection
│       │   ├── camera_detector.py# Conservative camera enumeration & test
│       │   └── wizard.py         # Interactive CLI Setup Wizard
│       │
│       ├── detection/
│       │   ├── __init__.py       # Detection package exports
│       │   ├── models.py         # AuthenticationFailureEvent & detection states
│       │   ├── base.py           # BaseAuthenticationMonitor abstract base class
│       │   ├── windows.py        # Windows Security Event Log (Event 4625) monitor
│       │   ├── linux.py          # Linux auth.log / secure / PAM / SSH monitor
│       │   ├── macos.py          # macOS unified logging system monitor
│       │   ├── threshold.py      # SlidingWindowThresholdEngine
│       │   ├── cooldown.py       # AlertCooldownManager
│       │   ├── voice.py          # OfflineVoiceWarning (local TTS)
│       │   └── manager.py        # DetectionManager coordinating detection pipeline
│       │
│       ├── environment/
│       │   ├── __init__.py       # Environment package exports
│       │   ├── models.py         # DeviceState, NetworkState, EnvironmentalContext
│       │   ├── network.py        # NetworkDetector (interface & route inspection)
│       │   ├── session.py        # DeviceStateDetector (desktop lock detection)
│       │   └── detector.py       # EnvironmentalDetector (transition tracking)
│       │
│       ├── filtering/
│       │   ├── __init__.py       # Filtering package exports
│       │   ├── models.py         # FilterDecision, FilterResult, FilterContext
│       │   ├── trusted.py        # TrustedContext (users, networks, auth types)
│       │   ├── rules.py          # Deterministic priority-ordered filtering rules
│       │   └── engine.py         # SmartFilterEngine evaluation orchestrator
│       │
│       ├── runtime/
│       │   ├── __init__.py       # Runtime package exports
│       │   ├── paths.py          # ApplicationPaths (frozen vs development path resolution)
│       │   ├── single_instance.py# SingleInstanceLock (Windows Named Mutex / PID file)
│       │   ├── models.py         # RuntimeState, GuardianRuntimeStatus, IPC commands
│       │   ├── controller.py     # GuardianRuntime background worker lifecycle & FSM
│       │   ├── tray.py           # TrayManager (dynamic Pillow system tray icon)
│       │   └── startup.py        # OS startup persistence (Registry / Desktop / LaunchAgent)
│       │
│       ├── security/
│       │   ├── __init__.py       # Security package exports
│       │   ├── secret.py         # SecretValue (immutable secret masking)
│       │   ├── redactor.py       # SecretRedactor (regex token scrubbers)
│       │   ├── store.py          # SecretStore, FileSecretStore, WindowsDPAPISecretStore
│       │   ├── validation.py     # Configuration readiness validator & report
│       │   └── manager.py        # SecurityManager credential orchestrator
│       │
│       ├── updates/
│       │   ├── __init__.py       # Updates package exports
│       │   ├── version.py        # SemanticVersion RFC 2.0.0 parsing & comparison
│       │   ├── crypto.py         # Pure-Python RFC 8032 Ed25519 digital signatures
│       │   ├── manifest.py       # ReleaseManifest canonical JSON signing & verification
│       │   ├── archive.py        # SafeZipExtractor (path traversal & zip bomb defense)
│       │   ├── verifier.py       # 7-gate release verification pipeline
│       │   ├── transaction.py    # UpdateTransaction FSM & crash recovery
│       │   ├── installer.py      # Transactional installer & atomic binary swap
│       │   └── manager.py        # ReleaseManager update workflow orchestrator
│       │
│       ├── recovery/
│       │   ├── __init__.py       # Recovery package exports
│       │   ├── persistence.py    # AtomicPersistence (thread-safe, .bak backup, fsync, retry)
│       │   ├── health.py         # Subsystem health evaluator & SystemHealthReport
│       │   └── repair.py         # Safe state repair, reset, and installation verification
│       │
│       └── packaging/
│           ├── __init__.py
│           ├── build.py          # Standalone PyInstaller build script
│           ├── generate_icon.py  # Standalone icon generation utility
│           └── device_guardian.spec # PyInstaller build specification
│
└── tests/
    ├── __init__.py
    ├── conftest.py               # Test isolation fixtures
    ├── failure_injection.py      # Phase 8 test failure-injection harness
    ├── test_camera.py            # Camera capture error handling tests
    ├── test_camera_detector.py   # Camera discovery & lifecycle verification tests
    ├── test_chat_detector.py     # Chat detection & data minimization tests
    ├── test_config.py            # Configuration & token redaction tests
    ├── test_config_phase4.py     # Phase 4 config parsing & defaults tests
    ├── test_config_save.py       # Atomic config saving & rollback tests
    ├── test_cooldown.py          # Alert cooldown suppression & reset tests
    ├── test_detection_manager.py # DetectionManager coordination & synthetic tests
    ├── test_detection_models.py  # Normalized failure event & state tests
    ├── test_diagnostics.py       # Diagnostics subsystem verification tests
    ├── test_environment_detector.py # Desktop lock & network detection tests
    ├── test_environment_models.py# Device & network state data model tests
    ├── test_filtering_engine.py  # SmartFilterEngine pipeline & priority tests
    ├── test_filtering_models.py  # FilterDecision & FilterResult model tests
    ├── test_filtering_rules.py   # Individual filter rule evaluation tests
    ├── test_linux_monitor.py     # Linux PAM / SSH / sudo log parsing tests
    ├── test_location.py          # Geolocation response parsing tests
    ├── test_macos_monitor.py     # macOS unified log NDJSON parsing tests
    ├── test_packaging_spec.py    # PyInstaller spec syntax & configuration tests
    ├── test_phase10_cli.py       # Phase 10 CLI help, disclosure & contract tests
    ├── test_phase10_confirmations.py # Destructive action confirmation guard tests
    ├── test_phase10_events.py    # Activity stream and factual rationale tests
    ├── test_phase10_operator.py  # 15-point operator status dashboard tests
    ├── test_phase10_security.py  # UX security invariants (1-18) tests
    ├── test_phase10_status.py    # Color-independent glyph & health model tests
    ├── test_phase10_tray.py      # Tray icon accessibility shape tests
    ├── test_phase11_config_recovery_e2e.py # Config, secrets & atomic persistence E2E tests
    ├── test_phase11_lifecycle_e2e.py # Runtime, IPC & single-instance E2E tests
    ├── test_phase11_notification_e2e.py # Telegram dispatch & failure recovery E2E tests
    ├── test_phase11_operator_journeys_e2e.py # Operator journeys & accessibility E2E tests
    ├── test_phase11_pipeline_e2e.py # Detection-to-alert pipeline E2E tests
    ├── test_phase11_updates_rollback_e2e.py # Update verification & rollback E2E tests
    ├── test_phase4_integration.py# Phase 4 end-to-end detection integration tests
    ├── test_pipeline.py          # End-to-end alert pipeline tests
    ├── test_recovery_cli.py      # Phase 8 recovery CLI command tests
    ├── test_recovery_health.py   # Subsystem health assessment engine tests
    ├── test_recovery_persistence.py # AtomicPersistence & .bak recovery tests
    ├── test_recovery_repair.py   # Safe state repair & installation integrity tests
    ├── test_resilience_notifications.py # Telegram retry & token redaction resilience tests
    ├── test_resilience_runtime.py# Runtime crash & corrupt state recovery tests
    ├── test_resilience_sensors.py# Camera & geolocation sensor failure tests
    ├── test_resilience_updates.py# Update transaction crash & recovery tests
    ├── test_runtime_controller.py# GuardianRuntime worker lifecycle tests
    ├── test_runtime_paths.py     # ApplicationPaths resolution tests
    ├── test_security_cli.py      # Phase 6 security CLI commands tests
    ├── test_security_filesystem.py # Strict filesystem & path traversal defense tests
    ├── test_security_ipc.py      # Hardened local IPC schema & replay tests
    ├── test_security_locking.py  # Single-instance lock & PID reuse defense tests
    ├── test_security_logging_hardening.py # Log injection & ANSI stripping tests
    ├── test_security_redactor.py # Secret redactor regex filter tests
    ├── test_security_secret.py   # SecretValue encapsulation & masking tests
    ├── test_security_store.py    # DPAPI & file secret store tests
    ├── test_security_threat_model.py # Security Invariants 1-12 validation tests
    ├── test_security_update_hardening.py # Update lock & SafeZip hardening tests
    ├── test_security_validation.py# Subsystem configuration validator tests
    ├── test_setup_status.py      # SetupStatus lifecycle tests
    ├── test_single_instance.py   # Single-instance mutex lock tests
    ├── test_startup.py           # OS autostart persistence tests
    ├── test_telegram.py          # Telegram client & error handling tests
    ├── test_threshold.py         # Sliding window threshold accumulation tests
    ├── test_tray.py              # System tray icon & menu tests
    ├── test_trusted.py           # TrustedContext matching & normalization tests
    ├── test_updates_archive.py   # SafeZipExtractor path traversal defense tests
    ├── test_updates_cli.py       # Phase 7 update CLI command tests
    ├── test_updates_crypto.py    # Pure-Python Ed25519 signing tests
    ├── test_updates_installer.py # Transactional installer & rollback tests
    ├── test_updates_keys.py      # Key management & serialization tests
    ├── test_updates_manifest.py  # Release manifest canonical JSON tests
    ├── test_updates_transaction.py # UpdateTransaction FSM & persistence tests
    ├── test_updates_verifier.py  # 7-gate release verification tests
    ├── test_updates_version.py   # SemanticVersion parsing & comparison tests
    ├── test_voice.py             # Offline voice warning dispatch tests
    ├── test_windows_monitor.py   # Windows Event 4625 XML parsing tests
    └── test_wizard.py            # Setup Wizard interactive workflow tests
```

---

## 5. Installation

### Prerequisites

- **Python 3.11+** installed
- A webcam connected to your computer (optional, text alerts continue if absent)
- Active internet connection for Telegram and geolocation queries

### Setup Instructions

1. **Clone or navigate to the repository:**
   ```bash
   cd device-guardian
   ```

2. **Create a Python virtual environment:**
   - **Windows:**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

---

## 6. Configuration & Setup Wizard

### Option A: Interactive Setup Wizard (Recommended)

Run the Setup Wizard:
```bash
python -m device_guardian.main --setup
```

The wizard guides you through privacy disclosure, Telegram Bot token verification, chat ID detection, hardware testing, and configuration saving.

### Option B: Manual Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env     # macOS / Linux
copy .env.example .env   # Windows
```

Configure settings in `.env`:
```env
# Phase 1 & 2: Telegram & Alert Pipeline
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
TELEGRAM_CHAT_ID=987654321
LOCATION_API_URL=https://ipapi.co/json/
CAMERA_INDEX=0
REQUEST_TIMEOUT_SECONDS=10
LOG_LEVEL=INFO

# Phase 3: Detection Triggers & Offline Voice Warning
AUTH_FAILURE_THRESHOLD=3
AUTH_FAILURE_WINDOW_SECONDS=60
AUTH_ALERT_COOLDOWN_SECONDS=300
VOICE_WARNING_ENABLED=true
VOICE_WARNING_TEXT="Warning. Multiple failed authentication attempts have been detected on this device."
VOICE_WARNING_COOLDOWN_SECONDS=300

# Phase 4: Smart Filtering & Environmental Triggers
SMART_FILTERING_ENABLED=true
DEVICE_GUARDIAN_TRUSTED_USERS=
DEVICE_GUARDIAN_TRUSTED_NETWORKS=
DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES=
ENVIRONMENTAL_TRIGGERS_ENABLED=true
NETWORK_CONTEXT_ENABLED=true
DEVICE_STATE_CONTEXT_ENABLED=true
REQUIRE_CONTEXT_FOR_ALERT=false

# Phase 4: Safety Gates
CAMERA_ALERT_ENABLED=true
LOCATION_ALERT_ENABLED=true
TELEGRAM_ALERT_ENABLED=true
```

> [!WARNING]
> Never commit your `.env` file to version control. It is excluded by `.gitignore`.

---

## 7. Usage & CLI Commands

### 1. Launch Setup Wizard
```bash
python -m device_guardian.main --setup
```

### 2. Check Configuration & Credentials
```bash
python -m device_guardian.main --check-config
```

### 3. Check Authentication Monitor Readiness
Verify OS log accessibility and local offline voice synthesizer:
```bash
python -m device_guardian.main --check-auth-monitor
```

### 4. Test Offline Voice Warning
Directly synthesize the audible warning locally:
```bash
python -m device_guardian.main --test-voice-warning
```

### 5. Run Synthetic Authentication Failure Test
Safely test threshold triggering, voice warning, and alert delivery using synthetic events without needing live log privileges:
```bash
python -m device_guardian.main --test-auth-monitor
```

### 6. Start Live Authentication Monitor
Continuously monitor the operating system for repeated failed logons:
```bash
python -m device_guardian.main --monitor-auth
```
*(Press `Ctrl+C` to terminate cleanly.)*

### 7. Check Smart Filtering Configuration
Inspect trusted context and verify active filter rules:
```bash
python -m device_guardian.main --check-filtering
```

### 8. Check Environmental Context
Inspect current device lock state, network connectivity, and IP address:
```bash
python -m device_guardian.main --check-environment
```

### 9. Test Smart Filtering Rules
Simulate filtering decisions across benign, trusted, and untrusted failure scenarios:
```bash
python -m device_guardian.main --test-filtering
```

### 10. Test Environmental State Transitions
Sample live device and network states and track context transitions:
```bash
python -m device_guardian.main --test-environment
```

### 11. Test Context Correlation
Evaluate how environmental context correlates with authentication failure bursts:
```bash
python -m device_guardian.main --test-context-correlation
```

### 12. Send Manual Test Alert
```bash
python -m device_guardian.main --test-alert
```

### 13. Background Monitoring Service (Phase 5)
Start Device Guardian as a managed background monitoring service:
```bash
python -m device_guardian.main --start
# Or using compiled binary:
./dist/device-guardian.exe --start
```

Stop the background service cleanly:
```bash
python -m device_guardian.main --stop
```

Inspect live runtime status, PID, uptime, and telemetry:
```bash
python -m device_guardian.main --status
```

Restart background monitoring:
```bash
python -m device_guardian.main --restart
```

### 14. System Tray Integration (Phase 5)
Launch Device Guardian with a dynamic system tray icon and interactive menu:
```bash
python -m device_guardian.main --tray
```
- **Icon States**:
  - Green Shield: `RUNNING`
  - Gray Shield: `STOPPED`
  - Azure Blue: `STARTING`
  - Amber: `STOPPING`
  - Red: `FAILED`
- **Menu Features**: Start/Stop/Restart, Trigger Test Alert, Toggle Launch at Startup, Graceful Exit.
- **Headless Fallback**: Automatically degrades to console runtime if no graphical display is present.

### 15. OS Startup Integration (Phase 5)
Configure Device Guardian to start automatically on user login (reversible, standard user privileges):
```bash
# Enable startup launch
python -m device_guardian.main --install-startup

# Disable startup launch
python -m device_guardian.main --remove-startup
```
- **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (no admin elevation required).
- **Linux**: `~/.config/autostart/device-guardian.desktop` (XDG autostart standard).
- **macOS**: `~/Library/LaunchAgents/com.deviceguardian.app.plist` (LaunchAgent standard).

### 16. Comprehensive System Diagnostics (Phase 5)
Execute an end-to-end diagnostic verification across all subsystems:
```bash
python -m device_guardian.main --diagnostics
```

### 17. Packaging & Standalone Binary (Phase 5)
Compile Device Guardian into a standalone, portable desktop binary:
```bash
python -m device_guardian.packaging.build
```
Produces `dist/device-guardian.exe` (or `dist/device-guardian` on Linux/macOS) ready for distribution.

### 18. Interactive CLI Dashboard
Run without arguments for an interactive dashboard with diagnostic checks and full menu options [1-34]:
```bash
python -m device_guardian.main
```

### Phase 6 CLI Commands (Secure Configuration & Secrets Hardening)

```bash
# Audit configuration readiness with structured subsystem reporting
python -m device_guardian.main --config-check

# Display sanitized configuration overview with masked secrets
python -m device_guardian.main --config-show

# Display resolved filesystem and secrets storage paths
python -m device_guardian.main --config-path

# Inspect credential configuration status safely
python -m device_guardian.main --credentials-status

# Send an explicit test notification to Telegram verifying delivery
python -m device_guardian.main --test-notification
```

### Phase 7 CLI Commands (Secure Updates, Versioning & Release Integrity)

```bash
# Display application release version, build metadata, and binary integrity
python -m device_guardian.main --release-info

# Display update subsystem status, active transactions, and available rollbacks
python -m device_guardian.main --update-status

# Verify an update package against digital signature and release manifest
python -m device_guardian.main --verify-update /path/to/update_v0.2.0.zip

# Stage and install a verified update package with rollback protection
python -m device_guardian.main --install-update /path/to/update_v0.2.0.zip

# Roll back to the previous verified release backup
python -m device_guardian.main --rollback

# Roll back to a specific previous release version
python -m device_guardian.main --rollback --rollback-version 0.1.0

# Explicitly permit installing an older version
python -m device_guardian.main --install-update /path/to/update.zip --allow-downgrade
```

### Phase 8 CLI Commands (Disaster Recovery, Resilience & Subsystem Health)

```bash
# Assess complete system health across all subsystems, state files, and sensors
python -m device_guardian.main --recovery-status

# Safely repair or reset corrupted state files without losing user configurations or credentials
python -m device_guardian.main --repair-state

# Verify application binary and directory integrity against release manifest SHA-256
python -m device_guardian.main --verify-installation
```

### Phase 12 CLI Commands (Application Lifecycle, Installation, Migration & Uninstallation)

```bash
# Display persistent installation metadata and execution mode
python -m device_guardian.main --install-info

# Evaluate installation integrity, directory presence, and component readiness
python -m device_guardian.main --installation-status

# Safely repair missing runtime directories, metadata, and prune stale lock files
python -m device_guardian.main --repair-installation

# Check persistent state schema version and pending migration steps
python -m device_guardian.main --migration-status

# Apply pending schema migrations with pre-migration snapshot backup and automatic rollback
python -m device_guardian.main --migrate

# Uninstall application binaries, preserving user data (.env, secrets, logs)
python -m device_guardian.main --uninstall

# Uninstall application and permanently erase user data (explicit confirmation required)
python -m device_guardian.main --uninstall --remove-data

# Non-interactive confirmation for scripts/automation
python -m device_guardian.main --uninstall --yes

# Verify candidate update archive against digital signature and release manifest
python -m device_guardian.main --verify-package /path/to/candidate.zip
```


---

## 8. Operating System Permissions

| OS | Mechanism | Permissions Required |
|---|---|---|
| **Windows** | Windows Security Event Log (Event ID 4625) via `wevtutil` | Standard users cannot read the Security log. Run Device Guardian from an elevated terminal (*"Run as Administrator"*) or add the user account to the local **Event Log Readers** group. Device Guardian detects access denial and provides clear guidance without crashing. Startup integration requires only standard user permissions (`HKCU`). Windows DPAPI credentials encryption is strictly user-bound and requires no elevation. |
| **Linux** | `/var/log/auth.log` or `/var/log/secure` | User must belong to the `adm` or `wheel` group, or run with read privileges to the authentication log. Autostart uses standard `~/.config/autostart`. Secrets file stored with `0600` permissions. |
| **macOS** | Unified Logging System (`/usr/bin/log`) | May require Terminal Full Disk Access or administrative privileges depending on macOS version and privacy policies. Autostart uses user LaunchAgent. |

---

## 9. Automated Tests

The test suite contains **476 automated tests passing (477 collected, 1 skipped)** covering:
- Configuration validation, token redaction, and Phase 3, 5 & 6 settings
- Geolocation parsing and timeout resilience
- Telegram Bot API client and HTTPS error handling
- Single-frame camera capture and hardware release
- Alert pipeline end-to-end flow and resource cleanup
- Setup status determination (`NOT_CONFIGURED`, `PARTIALLY_CONFIGURED`, `CONFIGURED`)
- Atomic configuration saving and automatic rollback
- Chat ID extraction, data minimization, and bounded polling
- Camera device enumeration and lifecycle verification
- Setup Wizard interactive workflow tests
- Normalized failure event sanitization and objective summaries
- Sliding-window threshold accumulation, burst detection, and expiry
- Alert cooldown suppression and reset logic
- Offline voice warning command dispatch across Windows, macOS, and Linux
- Windows Security Log XML parsing, record ID baseline tracking, and deduplication
- Linux auth.log, PAM, and SSH log parsing
- macOS Unified Log NDJSON parsing
- DetectionManager coordination, polling loop lifecycle, and synthetic test dispatch
- Device & network state models and serialization
- Non-invasive desktop lock detection and network interface resolution
- FilterDecision, FilterResult, and FilterContext evaluation models
- TrustedContext case-insensitivity, normalization, and prefix matching
- Priority-ordered rule evaluation: Disabled, Synthetic, Trusted, Environmental, Threshold, Alert Eligibility
- SmartFilterEngine fallback handling and explainable decision audit logging
- Safety gate enforcement in AlertPipeline (Camera, Location, Telegram)
- End-to-end integration: burst suppression on trusted user/network and untrusted dispatch
- ApplicationPaths resource and bundle discovery (Source vs PyInstaller frozen `sys._MEIPASS`)
- User data directory `%LOCALAPPDATA%\DeviceGuardian` mutable state protection
- SingleInstanceLock process coordination, Windows Named Mutex, and stale PID lock pruning
- IPC stop signaling (`guardian.control`)
- GuardianRuntime worker lifecycle, explicit state machine, and status JSON persistence
- Bounded auto-restart crash recovery (exponential backoff up to max attempts)
- OS startup managers for Windows (`winreg`), Linux (XDG desktop entry), and macOS (`LaunchAgents`)
- Dynamic Pillow system tray icon generation for all runtime states
- TrayManager menu callbacks and headless environment degradation
- System diagnostics verification across all subsystems
- PyInstaller specification file syntax and build orchestration
- SecretValue encapsulation, masking (`str` and `repr`), immutability, and string equality
- SecretRedactor regex pattern scrubbing for Telegram tokens, URLs, and Bearer authentication
- SecretStore abstract interface and FileSecretStore with restrictive 0600 permissions and atomic writes
- WindowsDPAPISecretStore user-bound DPAPI encryption and decryption via native Win32 `CryptProtectData`
- Subsystem configuration validation engine and ConfigValidationReport formatting
- Phase 6 CLI command handlers: `--config-check`, `--config-show`, `--config-path`, `--credentials-status`, `--test-notification`
- SemanticVersion 2.0.0 parsing, precedence ordering, equality, and downgrade detection
- Pure-Python RFC 8032 Ed25519 keypair generation, digital signing, and signature verification
- Canonical JSON serialization for deterministic signature payloads
- ReleaseArtifact schema validation, size bounds, and SHA-256 formatting
- ReleaseManifest digital signing, tampering detection, and atomic persistence
- SafeZipExtractor path traversal defenses (`..`, absolute paths, drive letters) and zip bomb defense
- ReleaseVerificationResult multi-gate verification pipeline (7 sequential security gates)
- UpdateTransaction FSM lifecycle, atomic persistence, and startup crash recovery
- UpdateInstaller transactional deployment, rollback backup creation, Windows file replacement, and post-validation
- Rollback restoration preserving user `.env` configuration and encrypted `SecretStore` credentials
- Phase 7 CLI command handlers: `--release-info`, `--update-status`, `--verify-update`, `--install-update`, `--rollback`, `--allow-downgrade`
- Thread-safe `AtomicPersistence` with nanosecond temporary files, backup `.bak` creation, fsync, and atomic `os.replace` retry loops
- Corrupted and malformed JSON recovery with automatic `.bak` fallback
- Deterministic multi-subsystem health evaluation (`assess_system_health`) returning `SystemHealthReport`
- Installation integrity verification (`verify_installation_integrity`) across development and frozen environments
- Non-destructive state file repair and reset (`repair_state_files`) preserving corrupted files as `.corrupt.<timestamp>`
- Telegram client bounded retry mechanism (up to 2 retries, 3 total attempts) with exponential backoff for transient failures (HTTP 429, 5xx, timeouts)
- Permanent HTTP error handling (HTTP 400, 401, 403) failing immediately without wasteful retries
- Complete token redaction in all exception messages and log strings during network operations
- Decoupling of local detection threshold state and alert cooldown from notification delivery to prevent alert storms during outages
- Sensor failure resilience (camera missing, geolocation offline) falling back safely without unhandled exceptions
- Update transaction recovery and rollback resilience under simulated crashes
- Phase 8 CLI command handlers: `--recovery-status`, `--repair-state`, `--verify-installation`
- Phase 9 Security Invariants 1–12 test verification (no AI/ML, zero telemetry, no remote control, credential confidentiality, etc.)
- Strict path traversal, UNC, NTFS Alternate Data Stream, and symlink/junction rejection tests
- Collision-resistant exclusive temporary file creation (`secure_create_temp_file`)
- Local IPC schema validation, UUID request IDs, TTL expiry, clock drift, and replay attack rejection
- Single-instance lock hardening, process identity verification, PID reuse simulation, and stale lock pruning
- Update serialization mutual exclusion lock (`_UpdateLockContext`) and symlink target rejection
- Safe ZIP extraction defense against duplicate members, case collisions, and zip bombs
- Log injection defense against `\r\n` log argument forging, length bounding, ANSI stripping, and rotating handler verification
- Strict configuration bounds and boolean validation tests
- Phase 10 UX Security Invariants 1–18 test verification
- Color-independent state model with bracketed geometric glyphs
- 15-point operator status dashboard and activeActivity stream verification
- Destructive action confirmation prompts with explicit Action, Effect, Preserved, and Changed contracts
- Non-interactive `--yes` / `-y` prompt bypass validation
- System tray accessibility icon shapes (circle, square, triangle, pause, cross)
- Deterministic CLI exit code contract (0, 1, 2, 3) matrix tests
- Phase 11 Detection-to-Alert Pipeline E2E Integration (full pipeline, trusted suppression, cooldown, auth failure context, unknown sensor state propagation, strict redaction, notification failure local alert preservation)
- Phase 11 Notification E2E Integration (Telegram dispatch success, timeout retries, HTTP 429 backoff, HTTP 5xx retry, HTTP 401 fast-fail, unconfigured credentials safe degradation, offline mode)
- Phase 11 Runtime Lifecycle E2E Integration (FSM lifecycle, single-instance mutual exclusion, stale lock reclamation, IPC dispatch, forbidden verb rejection, replay attack rejection, tray sync, stress rapid restart cycles)
- Phase 11 Configuration & Recovery E2E Integration (boundary validation, DPAPI & file fallback, atomic persistence & .bak, corruption recovery, state repair preserving credentials, UTC skew defense, objective health assessment)
- Phase 11 Updates & Rollback E2E Integration (full update lifecycle, rollback restoration, bad hash rejection, bad signature rejection, crash recovery FSM, SafeZip traversal/extension/size rejections)
- Phase 11 Operator Journeys E2E Integration (first-launch unconfigured guidance, status dashboard color-independence, audit trail structured logging, diagnostic reporting, exit code contract, release info, concurrency stress)
- Phase 12 Application Lifecycle Fresh Installation (`test_phase12_installer.py`: clean separation of INSTALL_ROOT and USER_DATA, directory generation, default .env creation, path traversal rejection, re-install overwrite, startup registration)
- Phase 12 Transactional Upgrades & Rollback (`test_phase12_upgrade.py`: atomic binary replacement, backup-on-upgrade, downgrade defense, downgrade override with flag, validation failure rollback, update.lock mutual exclusion, running process IPC stop coordination)
- Phase 12 Versioned Persistent Schema Migration (`test_phase12_migration.py`: schema version tracking, pre-migration snapshot backup creation, step handler execution, atomic commit, automatic rollback on error, downgrade rejection)
- Phase 12 Safe Non-Destructive Repair (`test_phase12_repair.py`: missing directory creation, install_metadata regeneration, stale lock pruning, absolute user config and secret preservation)
- Phase 12 Application Uninstallation & Data Decisions (`test_phase12_uninstall.py`: app removal preserving user data, authorized user data purge, confirmation prompting, --yes non-interactive automation, startup unregistration)
- Phase 12 Security, Versioning & CLI Integration (`test_phase12_lifecycle_security.py`: SemVer 2.0.0 parser/compare, release artifact secret scanner, package verification CLI against valid and malicious archives, CLI commands)

Run the test suite:
```bash
pytest -v
```

All external network endpoints (Telegram API, Geolocation API) and hardware devices (Webcam) are fully mocked in unit tests, allowing tests to run offline in any environment.

---

## 10. Project Status & Roadmap

- **Phase 1: PC Core Alert Pipeline** — Completed & Verified
- **Phase 2: Setup Wizard & First-Run Configuration** — Completed & Verified
- **Phase 3: Detection Triggers & Offline Voice Warning** — Completed & Verified
- **Phase 4: Smart Filtering & Environmental Triggers** — Completed & Verified
- **Phase 4.1: Final Audit, Verification & Hardening Gate** — Completed & Verified
- **Phase 5: Packaging, Background Services & System Tray Integration** — Completed & Verified
- **Phase 6: Secure Configuration, Credential Management & Production Secrets Hardening** — Completed & Verified
- **Phase 7: Secure Updates, Versioning & Release Integrity** — Completed & Verified
- **Phase 8: Disaster Recovery, Resilience & Failure-Injection Hardening** — Completed & Verified
- **Phase 9: Production Security, Threat Modeling & Local Attack-Surface Hardening** — Completed & Verified
- **Phase 10: Production UX, Operator Experience & Accessibility Hardening** — Completed & Verified
- **Phase 11: Production Integration, End-to-End Validation & Release Readiness** — Completed & Verified
- **Phase 12: Production Distribution, Installer Engineering & Application Lifecycle Management** — Completed & Verified

---

## 11. Phase 10 — Production UX & Accessibility Architecture

### Unified Operator Status Surface (`--status`)
The primary status command answers all 15 operational inquiries across 5 distinct dimensions:
1. **Running Status**: Active PID, running state, uptime, and single-instance lock status.
2. **Configuration Readiness**: Status of config files and Telegram channel readiness.
3. **Security Engine Health**: Subsystem health assessments across all sensors and storage backends.
4. **Degraded Subsystem Identification**: Explicit list of subsystems operating in degraded or fallback mode.
5. **Recent Activity**: Count of evaluated events and dispatched alerts (or explicit empty state).
6. **Alert Generation Rationale**: Factual thresholds that led to alert generation.
7. **Alert Suppression Rationale**: Explicit counts of suppressed alerts (smart filtering or cooldown).
8. **Telegram Status**: Clear indication of whether Telegram is configured or inactive.
9. **Sensor Readiness**: Hardware and API sensor status (camera, geolocation, voice warning).
10. **Pending Updates**: Active or interrupted update transaction status.
11. **Recovery Status**: Whether state file corruption requires repair.
12. **Safe Next Action**: Contextual recommendation for operator next steps.
13. **Destructive Action Guards**: Notification that destructive operations require confirmation.
14. **Local Data Disclosure**: Pointer to local storage disclosures.
15. **Remote Transfer**: Clear statement that zero data leaves the machine unless Telegram is configured.

### Color-Independent State Model & Glyphs
To ensure full accessibility for color-blind operators and monochrome displays, all health and runtime states combine a unique geometric glyph, uppercase label, and bracketed format:
- `[● HEALTHY     ]`: Subsystem operational and behaving within expected parameters
- `[▲ DEGRADED    ]`: Subsystem operational with degraded capabilities or fallback active
- `[■ FAILED      ]`: Subsystem unavailable, corrupted, or experiencing operational faults
- `[? UNKNOWN     ]`: Subsystem status cannot be determined deterministically
- `[- NOT_CONFIG  ]`: Subsystem has not been configured by operator
- `[▶ RUNNING     ]`: Background monitoring service active and running
- `[■ STOPPED     ]`: Background monitoring service halted
- `[⟳ STARTING    ]`: Background monitoring service initializing subsystems
- `[⏏ STOPPING    ]`: Background monitoring service terminating gracefully

### System Tray Accessibility
The system tray icon dynamically renders distinct geometric shapes inside the shield emblem:
- **RUNNING**: Solid Circle
- **STOPPED**: Solid Square
- **STARTING**: Upward Triangle
- **STOPPING**: Parallel Pause Bars
- **FAILED**: Bold Diagonal Cross (X)

### Strict Uncertainty Model
- **Rule 1**: State `UNKNOWN` is never represented or interpreted as `SAFE`, `SECURE`, or `HEALTHY`. Absence of evidence is not absence of risk.
- **Rule 2**: State `NOT_CONFIGURED` is never represented or interpreted as `PROTECTED` or `OPERATIONAL`.
- Both invariants are validated programmatically and enforced across all surfaces.

### Destructive Action Confirmation Contract
Potentially destructive actions (`--rollback`, `--repair-state`, `--remove-startup`) require explicit confirmation displaying:
- **Action**: Exact action being executed
- **Effect**: Concrete description of what will occur
- **Preserved**: State, credentials, and configurations that remain intact
- **Changed**: Items that will be modified or restored
- **Cancel Option**: Default option is always Cancel (`[N]` or Enter).
- **Non-Interactive Bypass**: The `--yes` / `-y` flag allows scripted or automated workflows to bypass prompts safely.

### CLI Deterministic Exit Code Contract
- `0`: SUCCESS / HEALTHY / VALID
- `1`: OPERATIONAL_FAILURE / DEGRADED / CONFIG_ERROR
- `2`: CLI_USAGE_ERROR (invalid arguments or syntax)
- `3`: SECURITY_REJECTION / TAMPERING / INTEGRITY_FAILURE

---

## 12. Phase 11 — Production Integration, End-to-End Validation & Release Readiness

Phase 11 validates the entire Device Guardian application as a unified, coherent, and resilient production release candidate.

### Comprehensive E2E Test Suites (47 New Tests, 428 Total Passing)
1. **Pipeline Integration (`test_phase11_pipeline_e2e.py`)**:
   - Validates the complete flow: OS authentication failure -> sliding-window threshold evaluation -> smart filtering -> offline voice warning -> camera capture & IP geolocation -> HTTPS Telegram dispatch -> local audit logging.
   - Enforces trusted context suppression, cooldown storm debouncing, unknown state propagation (`UNKNOWN != THREAT`), and multi-layer secret redaction.
   - Confirms local alert state and cooldowns persist even under total network failure.
2. **Notification Integration (`test_phase11_notification_e2e.py`)**:
   - Tests successful Telegram transmission, network timeouts with bounded exponential backoff (2 retries, 3 total attempts), HTTP 429 rate-limiting backoff, HTTP 5xx server error recovery, and HTTP 401 fast failure.
   - Verifies safe degradation when credentials are unconfigured and 100% offline operation where zero network requests are attempted.
3. **Runtime Lifecycle & IPC Integration (`test_phase11_lifecycle_e2e.py`)**:
   - Verifies the full `GuardianRuntime` finite-state machine (`STOPPED` -> `STARTING` -> `RUNNING` -> `STOPPING` -> `STOPPED`).
   - Hardens single-instance mutual exclusion and verifies stale lock reclamation.
   - Tests local IPC control channel command dispatch, strict schema validation, rejection of forbidden verbs (`EXEC`, `CMD`), TTL expiration, and replay attack prevention.
   - Validates dynamic system tray state synchronization and rapid restart stress cycles.
4. **Configuration, Secrets & Disaster Recovery Integration (`test_phase11_config_recovery_e2e.py`)**:
   - Validates configuration boundaries, DPAPI credential encryption with encrypted filesystem fallback, and atomic persistence with `.bak` safety backups.
   - Tests corruption recovery and safe state file repair, guaranteeing that user configurations (`.env`) and credential stores (`secrets.dat` / `secrets.json`) are never truncated, overwritten, or reset.
   - Verifies UTC timestamp normalization, clock skew defenses (> 60s future drift rejection), and objective subsystem health assessments.
5. **Updates, Archive Security & Rollback Integration (`test_phase11_updates_rollback_e2e.py`)**:
   - Exercises the complete transactional update lifecycle: download verification -> staging -> atomic binary replacement -> post-validation -> clean completion.
   - Validates rollback restoration preserving user state and credentials.
   - Verifies rejection of corrupted packages (SHA-256 hash mismatch), forged packages (Ed25519 signature verification failure), and interrupted update recovery.
   - Enforces `SafeZipExtractor` path traversal protection (`..`, drive-relative), prohibited executable scripts (`.bat`, `.vbs`, `.sh`), and archive size limits (250 MB single file, 500 MB total).
6. **Operator Journeys & Production Accessibility (`test_phase11_operator_journeys_e2e.py`)**:
   - Validates Journey A (first launch unconfigured guidance), Journey B (15-point operator status dashboard), Journey C (audit trail structured logging), Journey D (diagnostics), Journey E (deterministic exit code contract), Journey F (release metadata & update status), Journey G (confirmation prompts and `--yes` automation), and concurrent multi-reader access.

### Packaged Standalone Release Candidate
- **Binary**: `dist/device-guardian.exe` (Windows 11 x64 standalone executable)
- **Size**: 69.81 MB (73,202,759 bytes)
- **SHA-256 Digest**: `bfa400f4d294de71f7da50fb45de77f7d2f10c58657c3ceb8c19a4c2735385d3`
- **Release Manifest**: `dist/release-manifest.json` containing canonical metadata and Ed25519 signature payload
- **Reproducible Build Metadata**: `dist/build-metadata.json` recording environment and build hashes
- **Integrity Verification**: `device-guardian.exe --verify-installation` returns `HEALTHY` / `DEGRADED` (Exit Code 0).
- **Zero Secret Leakage**: Verified zero bundled `.env` files, private keys, or API tokens inside release archives or packaged builds.

---

## 13. Phase 12 — Production Distribution, Installer Engineering & Application Lifecycle Management

Phase 12 delivers complete, operator-controlled desktop lifecycle management for Device Guardian:

### 1. Architectural Separation
- **`INSTALL_ROOT`**: Application executables and read-only binaries (`%LOCALAPPDATA%\Programs\DeviceGuardian` or custom).
- **`USER_DATA`**: Mutable user state, `.env` configuration, `secrets.dat` (Windows DPAPI) / `secrets.json`, logs, audit history, and update backups (`%LOCALAPPDATA%\DeviceGuardian`).

### 2. Application Lifecycle Framework (`LifecycleInstaller`)
- **Fresh Install (`--install-info`)**:
  - Atomic executable placement with disk fsync.
  - Safe path traversal validation blocking null bytes, directory traversal, UNC paths, and reparse points.
  - Default `.env` generation if no configuration exists.
  - Non-destructive handling: never overwrites pre-existing configurations or credentials.
  - Optional OS autostart registration.
- **Transactional Upgrades**:
  - Atomic binary swap via staging files.
  - Pre-upgrade backup to `updates/backup/v_<version>_<timestamp>/`.
  - Downgrade defense: blocks accidental or unauthorized downgrades unless `--allow-downgrade` is explicitly passed.
  - Runtime coordination: writes `STOP` to `guardian.control` and awaits clean shutdown without forceful termination.
  - Automatic rollback: restores previous binary from backup if new binary fails post-swap validation.
  - Data preservation: 100% preservation of `.env`, `SecretStore`, and audit logs.
- **Safe Non-Destructive Repair (`--repair-installation`)**:
  - Recreates missing directories (`logs`, `updates`, `updates/staging`, `updates/verified`, `updates/backup`).
  - Regenerates `install_metadata.json` if missing or corrupted.
  - Prunes stale or malformed `guardian.lock` files.
  - Strict preservation guarantee: never modifies, resets, or erases `.env` or credential stores.
- **Application Uninstallation (`--uninstall`)**:
  - Distinguishes application binaries from user data.
  - Default uninstallation removes binaries and startup registrations while leaving user configuration, credentials, and logs intact.
  - Optional `--remove-data` requires explicit operator confirmation or `--yes` to authorize permanent data erasure.

### 3. Persistent Schema Migration Engine (`MigrationManager`)
- **Schema Versioning**: Authoritative `CURRENT_STATE_SCHEMA_VERSION = 1` recorded in `install_metadata.json`.
- **Pre-Migration Snapshot**: Full copy of critical state files to `migration_backups/snapshot_<timestamp>/` prior to schema modifications.
- **Atomic Migrations**: Sequentially applies step handlers with atomic replacement.
- **Automatic Rollback**: Any validation error or unexpected exception restores the pre-migration snapshot immediately and leaves previous state and version intact.
- **Downgrade Defense**: Schema downgrades are prohibited.

### 4. Release Engineering & Cryptographic Verification
- **Artifact Secret Scanner (`scan_artifacts_for_secrets`)**: Scans distribution directories to ensure no `.env`, DPAPI files, API tokens, or private key headers are bundled into release artifacts.
- **Reproducible Build Metadata (`dist/build-metadata.json`)**: Machine-readable JSON tracking version, release ID, build timestamp, Python version, platform, architecture, executable hash, executable size, and manifest hash.
- **Package Verification CLI (`--verify-package`)**: Evaluates candidate zip archives against digital signatures, manifests, and `SafeZipExtractor` traversal defenses before staging or installation.





