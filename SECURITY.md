# Security Policy & Threat Model — Device Guardian

Device Guardian is an open-source, local-first, privacy-preserving desktop security and anti-theft application designed to protect personal workstations from unauthorized physical access.

---

## 1. Core Security Philosophy

1. **Local-First & Non-Cloud**: All evaluation, filtering, state tracking, and alert triggers occur exclusively on the local machine.
2. **Deterministic Security (Zero AI/ML)**: No machine-learning models, LLM heuristics, statistical scoring, or non-deterministic decision engines are used anywhere in the codebase.
3. **Zero Telemetry**: No third-party analytics, crash reporting, telemetry pings, tracking beacons, or cloud callbacks exist in the application.
4. **Zero Remote Execution**: Device Guardian has absolutely no inbound listening TCP/UDP sockets, HTTP servers, RPC endpoints, or remote execution capabilities.
5. **Least Privilege**: The application operates entirely under unprivileged standard user permissions (no administrator elevation, root, or UAC prompts).
6. **Defense in Depth**: Every input, whether filesystem path, IPC message, update package, or environment variable, is validated, sanitized, and bounded before processing.

---

## 2. Threat Model & Trust Boundaries

### 2.1 Threat Actor Profile
* **Opportunistic Local Intruder**: An unauthorized individual physically sitting at the victim's device attempting credential guessing or login bypass.
* **Malicious Local Process (Same User Context)**: An unprivileged script or process attempting to tamper with Device Guardian's locks, inject false control signals, read sensitive credentials, or hijack update binaries.
* **Network Observer / Passive Eavesdropper**: An adversary monitoring local Wi-Fi or transit networks.
* **Malicious Update Source / Man-in-the-Middle**: An attacker attempting to supply modified update archives or unauthorized application releases.

### 2.2 Trust Boundaries & Defenses

| Boundary | Threat | Mitigation & Defense |
| :--- | :--- | :--- |
| **Local IPC & Control Signaling** | Unauthorized process signaling `STOP`/`RESTART` or injecting shell commands (`EXEC`, `CMD`). | **Strict Whitelist & Schema Validation**: Only `START`, `STOP`, and `RESTART` are permitted; command strings like `EXEC`, `CMD`, `POWERSHELL` are strictly rejected. Commands contain UUID request IDs, creation timestamps, and 30-second TTLs. Replay cache prevents duplicate command replay. Control files avoid symlinks and are atomically written. |
| **Process Identity & Mutex Lock** | Attacker tampering with PID lock file or exploiting PID reuse to cause denial-of-service. | **Process Identity & Timestamp Verification**: Windows `QueryFullProcessImageNameW` verifies process image is python/device-guardian. `GetProcessTimes` verifies creation time to eliminate PID reuse attacks without requiring elevation. Negative or malformed PIDs are safely purged. |
| **Filesystem & Reparse Points** | Directory traversal, NTFS junctions, symlink hijacking, NTFS Alternate Data Streams (ADS). | **Filesystem Security Gate**: `validate_safe_path()` rejects null bytes, path traversal (`..`), UNC network paths (`\\server\share`), NTFS Alternate Data Streams (`file:stream`), drive-relative paths (`C:file`), and symlinks/reparse points. Directory containment is strictly enforced. |
| **Update Archives (ZIP Packages)** | Zip bombs, path traversal, case collisions, archive tampering. | **SafeZipExtractor**: Enforces strict single file (250 MB) and total archive (500 MB) uncompressed limits. Member count capped at 50. Rejects duplicate members, case-insensitive filename collisions (`file.exe` vs `FILE.EXE`), absolute paths, and NTFS reparse point flags. |
| **Update Serialization & Cryptography** | Concurrent update race conditions, unauthorized updates. | **Cryptographic Verification & Update Lock**: All releases require Ed25519 digital signatures and SHA-256 digests. `_UpdateLockContext` serializes updates and rollbacks, eliminating file replacement race conditions. Pre-replacement symlink check blocks hijacking. |
| **Configuration & Credential Storage** | Plaintext credential theft, token leaks in logs, malformed configurations. | **DPAPI / Hardware-Backed Secret Storage**: Telegram bot tokens and chat IDs are stored in Windows DPAPI or encrypted secret stores. `SecretValue` and `SecretRedactor` scrub tokens from logs, exceptions, and `__repr__`. Bounded integers/floats and strict boolean parsers reject corrupted configs. |
| **Logging & Terminal Output** | Log forging via carriage-return/newline injection, ANSI escape attacks. | **Sanitized Logging**: `RedactingFilter` escapes `\r\n` and `\n` in log arguments into `\n`, truncates records longer than 65,536 characters, strips ANSI terminal control sequences, and rotates logs (10 MB, 5 backups). |
| **OS Startup Integration** | Persistence abuse, hijacking autostart entries. | **Autostart Validation**: Validates executable paths against symlinks and verifies command strings contain no shell chaining metacharacters (`&`, `|`, `;`, `>`, `<`, `$`). |

---

## 3. The 12 Security Invariants

1. **No AI/ML Dependencies**: No neural networks, LLMs, or heuristic inference libraries.
2. **Zero Telemetry & Third-Party Analytics**: No telemetry libraries or metrics collection.
3. **No Inbound Remote Control**: No open network listening ports (TCP, UDP, HTTP, WebSocket).
4. **Deterministic Evaluation**: Pure rule-based, deterministic Boolean logic for all detection.
5. **Strict Configuration Boundaries**: Every numerical configuration parameter has bounded ranges.
6. **Strict Boolean Parsing**: Only unambiguous truthy (`true`, `1`, `yes`, `on`) and falsy (`false`, `0`, `no`, `off`) values are accepted.
7. **Credential Confidentiality**: Bot tokens and Chat IDs are never displayed in plaintext in `__repr__`, CLI displays, or crash traces.
8. **Filesystem Traversal Rejection**: Paths with `..`, UNC paths, ADS syntax, or symlinks are rejected.
9. **Atomic Persistence**: State and control files are written atomically using exclusive creation flags.
10. **Archive Traversal & Collision Defense**: Update archives containing path escapes or casing collisions are aborted.
11. **Signature-Verified Releases**: All update artifacts require valid Ed25519 digital signatures and SHA-256 hashes.
12. **Non-Destructive Operations**: Recovery procedures never wipe `.env` files or delete secure credential stores.

---

## 4. Privilege Boundaries

Device Guardian intentionally runs under the **standard user context**:
* **No Administrative Elevation**: Device Guardian does not require `Administrator` (Windows) or `root` (Linux/macOS) privileges.
* **No System Service Registration**: Autostart uses user-level registration (HKCU Run registry key on Windows, XDG autostart on Linux, user LaunchAgents on macOS).
* **Isolation**: All operational directories reside within the user's local application data directory (`%LOCALAPPDATA%\DeviceGuardian` on Windows).

---

## 5. Residual Risks & Out-of-Scope Threats

1. **Compromised Host Kernel / Rootkit**: An attacker with kernel or administrative access can read memory, tamper with running binaries, or disable detection.
2. **Volatile Memory Inspection**: While credentials are encrypted on disk and redacted from logs, they must temporarily reside in process RAM when sending HTTPS requests.
3. **Hardware-Level Interference**: Hardware attacks, camera lens obstruction, or disabling network hardware are physical limitations of any software-based solution.
4. **Denial of Service via Hardware Lock**: If another application locks the webcam device exclusively, Device Guardian gracefully falls back to sending text-only intrusion alerts.

---

## 6. Vulnerability Reporting

If you discover a security vulnerability in Device Guardian, please report it responsibly:

* **Email**: `security@deviceguardian.local` (or file a private security advisory on GitHub).
* **Please Include**:
  * Description of the vulnerability and attack vector.
  * Step-by-step reproduction instructions or proof-of-concept.
  * Affected versions and platforms.
* **Commitment**: We will acknowledge reports within 48 hours and work toward timely verification and remediation.

---

## 7. Phase 10 — UX Security Invariants & Operator Boundaries

Device Guardian enforces 18 strict UX and operational security invariants:

1. **Confidentiality in UI**: No secrets or credential tokens are ever displayed in terminal dashboards or user interfaces.
2. **Confidentiality in CLI**: CLI outputs mask all API tokens, chat IDs, and private keys.
3. **Log Sanitization**: All log emitters pass arguments through `SecretRedactor` to strip credentials from log files.
4. **Uncertainty Rule 1 (`UNKNOWN != SAFE`)**: Absence of evidence is never equated with safety. If a sensor or check cannot be evaluated deterministically, it is labeled `UNKNOWN`, never `SAFE` or `HEALTHY`.
5. **Uncertainty Rule 2 (`NOT_CONFIGURED != PROTECTED`)**: Unconfigured subsystems are explicitly identified as `NOT_CONFIGURED` and never claimed to be `PROTECTED` or `OPERATIONAL`.
6. **No Risk Scoring**: The application uses strictly deterministic rule evaluations and contains zero probabilistic threat scores, danger levels, or risk percentages.
7. **No AI/ML Inference**: Zero artificial intelligence, machine learning models, neural networks, or LLM integrations exist.
8. **No Covert Surveillance**: No hidden audio recording, background screen scraping, or unauthorized camera activation.
9. **No Remote Administration**: No reverse shells, remote procedure calls, or remote control backdoors exist.
10. **No Arbitrary Command Execution**: The application executes only fixed, internal, deterministic code paths; no user input is ever passed to shell interpreters.
11. **Zero Cloud Telemetry**: No analytics SDKs, tracking pixels, crash reporting telemetry, or cloud usage metrics.
12. **No Network Listeners**: Device Guardian operates entirely as a local client and never binds to or listens on network ports or sockets.
13. **Mandatory Update Cryptography**: Updates require valid Ed25519 digital signatures and SHA-256 integrity verification.
14. **Rollback Availability**: Any installed update preserves verified restore points for single-command rollback.
15. **Audit Log Integrity**: Event records and state files maintain strict audit trails with atomic file persistence.
16. **Privilege Boundary Integrity**: The application executes within user-space without requesting administrative elevation.
17. **Destructive Action Confirmation**: High-impact or destructive operations (`--rollback`, `--repair-state`, `--remove-startup`) require explicit confirmation outlining Action, Effect, Preserved State, and Changed State, with cancellation as the default.
18. **Autonomous Local Resilience**: Local security monitoring, event evaluation, and offline voice alerts remain fully functional regardless of Telegram connectivity or network availability.

---

## 8. Phase 11 — Release Verification, Code Signing & Privacy Disclosures

### 8.1 Dual-Layer Release Verification
Every release package must satisfy both layers of verification before execution or update staging:
1. **Integrity (SHA-256)**: Streaming SHA-256 checksums verify the byte-for-byte fidelity of all release artifacts against `release-manifest.json`.
2. **Authenticity (Ed25519)**: The canonical JSON release manifest is signed with the project's official Ed25519 private key and verified using pure-Python RFC 8032 cryptography without external binary dependencies.

### 8.2 Windows Authenticode Code Signing Status (Workstream 54)
* **Status**: `NOT IMPLEMENTED / NOT VERIFIED`
* **Technical Rationale**: While application-level and update-level cryptographic authenticity (Ed25519 digital signatures) and integrity (SHA-256) are fully implemented and verified across all test suites, Windows PE Authenticode certificate signing (`signtool.exe` with a commercial Extended Validation or Organization Validation hardware certificate) is not applied. This requires a commercial certificate authority subscription and hardware cryptographic token unsuitable for local unprivileged development builds.
* **Operator Guidance**: When launching `dist/device-guardian.exe` for the first time, Windows SmartScreen may present an unknown publisher prompt. Operators can verify binary integrity directly by running:
  ```powershell
  Get-FileHash -Algorithm SHA256 .\dist\device-guardian.exe
  .\dist\device-guardian.exe --verify-installation
  ```
  and confirming the digest matches `release-manifest.json`.

### 8.3 Privacy & Network Boundary Verification
* **Zero Telemetry**: Audited across all 72 source files. Zero crash reporters, zero analytics SDKs, zero usage metrics.
* **Zero Inbound Sockets**: Device Guardian never listens on any TCP, UDP, or Unix socket.
* **Controlled Outbound Communication**:
  - `https://api.telegram.org`: Only invoked when Telegram credentials are explicitly supplied by the operator.
  - `https://ipapi.co`: Only invoked when geolocation is enabled (`LOCATION_ALERT_ENABLED=true`).
  - No background polling or update checking occurs over the network.
* **Secret Redaction Across Layers**: `SecretValue` containers, `SecretRedactor` regex scrubbers, and `RedactingFilter` ensure credentials never appear in plain text in logs, traceback exceptions, or terminal displays.

---

## 9. Phase 12 — Production Distribution, Lifecycle Security & Data Preservation Guarantees

### 9.1 Application Lifecycle Threat Model
Phase 12 introduces application lifecycle management (fresh install, upgrade, repair, migration, and uninstallation). The following threats and defenses are formally evaluated:

| Threat | Attack Vector | Mitigation & Defense |
| :--- | :--- | :--- |
| **Malicious Package Injection** | Attacker delivers tampered archive to update/install commands. | **Dual Cryptographic Verification**: Releases verified with Ed25519 signatures and streaming SHA-256 digests. `SafeZipExtractor` blocks traversal, zip bombs, and case collisions. |
| **Version Downgrade Attack** | Adversary forces rollback to older vulnerable version with known defects. | **Semantic Version Downgrade Defense**: `compare_versions()` detects any downgrade attempt and blocks operation unless `--allow-downgrade` is explicitly passed by the operator. |
| **Race Conditions During Upgrades** | Concurrent executions corrupting binary or state during replacement. | **Transactional Update Lock**: `_UpdateLockContext` enforces single-writer mutual exclusion during binary swaps and lifecycle state transitions. |
| **Runtime Interruption During Upgrade** | Upgrading a running executable causing binary locking or file corruption. | **Graceful IPC Coordination**: Upgrader issues `STOP` to `guardian.control` and polls `guardian.lock` for clean shutdown before touching binaries. Never force-kills the host process. |
| **Schema Migration Corruption** | Abrupt crash or validation failure corrupting persistent JSON state files. | **Pre-Migration Snapshot & Rollback**: `MigrationManager` creates full snapshot before executing migration steps; automatically rolls back all files if any step fails. |
| **Accidental User Data Erasure** | Uninstallation or repair wiping configuration, secrets, or logs. | **Architectural Isolation & Confirmation**: `INSTALL_ROOT` is strictly separated from `USER_DATA`. Repair and uninstallation preserve user data by default. Destructive deletion requires explicit operator confirmation or `--yes`. |

### 9.2 Data Preservation Guarantee
Device Guardian enforces an absolute data preservation contract across all lifecycle workflows:
- **Fresh Install**: If a user `.env` or `SecretStore` already exists in `USER_DATA`, it is preserved byte-for-byte.
- **Transactional Upgrade**: User configuration, DPAPI encrypted secrets, audit logs, and update backups remain untouched.
- **Lifecycle Repair**: Recreates missing directories and repairs corrupted metadata, but NEVER modifies, clears, or regenerates `.env` or credential files.
- **Application Uninstallation**: By default, uninstalls only application binaries and OS autostart entries. User configuration and credentials at `USER_DATA` are preserved unless `--remove-data` is authorized with explicit confirmation.

### 9.3 Windows Authenticode Status
- **Status**: `NOT IMPLEMENTED / NOT VERIFIED`
- **Integrity Baseline**: Standalone binaries and release packages are verified using SHA-256 integrity digests and Ed25519 digital signatures documented in `release-manifest.json` and `build-metadata.json`. Commercial EV Authenticode signing is not applied.

---

## 10. Phase 14 — Reliability Engineering, Alert Backpressure & Soak Safety Guarantees

### 10.1 Reliability Threat Model & Protections

| Concern | Operational Risk | Reliability Mitigation & Security Defense |
| :--- | :--- | :--- |
| **Alert Storm / Notification DoS** | Attacker repeatedly triggering failures causing Telegram rate limits, CPU spinning, or memory exhaustion. | **Cooldown Manager & Bounded Queue**: `AlertCooldownManager` suppresses duplicate triggers within window; `BoundedAlertQueue` limits pending queue to 100 items with priority preservation (Critical/High alerts evict lower-priority items). Drops are auditable. |
| **Network Outage / Socket Exhaustion** | Extended internet disconnect causing unbounded retry loops, thread blocking, and log inflation. | **Circuit Breaker Pattern**: `CircuitBreaker` fast-fails calls in `OPEN` state after 5 consecutive failures, avoiding socket exhaustion. Automatically probes for recovery (`HALF_OPEN`) without blocking local monitoring. |
| **Runaway Logging / Disk Exhaustion** | Infinite loop or recurring failure filling disk space with identical error traces. | **Bounded Rotation & Duplicate Suppression**: `RotatingFileHandler` bounds logs to 10 MB with 5 backups (max 50 MB total); `DuplicateLogFilter` suppresses identical log spam exceeding 5 repeats within 10s using an LRU-pruned cache. |
| **Resource Leakage Under 24h Soak** | Long-running daemon accumulating threads, unclosed file handles, or unbounded memory. | **Deterministic Lifecycle & Leak Acceptance**: `GuardianRuntime` ensures idempotent worker join; soak testing strictly validates zero permanent thread growth and bounded RSS memory growth against `SoakAcceptanceCriteria`. |
| **Accidental Real Notification During Soak** | Synthetic load testing accidentally contacting real Telegram chats or leaking secrets. | **Complete Soak Isolation**: `SoakTestRunner` uses isolated temporary test directories, mock in-memory dispatchers, disabled credentials, and never transmits network alerts or touches production user configuration. |
