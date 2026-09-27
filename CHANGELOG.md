# Changelog — Device Guardian

All notable changes to the Device Guardian project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-27

### Phase 17 — Final v1.0.0 Release & Final Hardening
#### Added
- **Official v1.0.0 Release**: Certified controlled v1.0.0 production baseline with unified version metadata across `device_guardian.version`, `pyproject.toml`, and runtime models.
- **Dynamic Application Versioning**: Integrated dynamic `__version__` into geolocation User-Agent headers, lifecycle records, and installation metadata, eliminating hardcoded version drift.
- **Multi-Photo Burst Security Alerts**: Added rapid multi-photo burst capture (default: 3 photos at 0.35s intervals) and sequential Telegram delivery, configurable via `--burst <count>` and `CAMERA_PHOTO_COUNT`.
- **Exact GPS Pinpoint Configuration**: Added support for exact home/office GPS coordinates via `--set-location <lat> <lon> [place_name]` or `.env` (`EXACT_LATITUDE`, `EXACT_LONGITUDE`), overriding approximate IP geolocation with exact map pin accuracy.
- **Resilient Geolocation Fallback**: Added automatic fallback to `http://ip-api.com/json/` when primary geolocation providers encounter carrier rate-limits or Cloudflare blocks.
- **Clean Standalone Windows Release**: Compiled and verified clean PyInstaller binary (`dist/device-guardian.exe`, 69.85 MB) with matching streaming SHA-256 digest (`e660963a8bbe709d3a76e859b8af01c1fa638812d9fe0f91d5d308531c0ffd90`).
- **Release Manifest & Reproducible Metadata**: Generated authoritative `dist/release-manifest.json` and machine-readable `dist/build-metadata.json`.
- **Zero-Secret Artifact Verification**: Executed automated release secret scan confirming zero sensitive files, bot tokens, or private keys in compiled outputs.
- **Installation Integrity Validation**: Verified physical frozen execution and manifest hash matching via `--verify-installation`.

#### Security & Operational Disclosures
- **Windows Authenticode Code Signing**: Maintained explicit disclosure: **NOT VERIFIED / NOT IMPLEMENTED** (Ed25519 signature verification and streaming SHA-256 integrity digests are verified; commercial EV certificate requires physical CA hardware cryptotoken).
- **24-Hour Production Soak**: Maintained explicit disclosure: **FRAMEWORK VERIFIED / 24H SOAK NOT RUN** (framework verified; short soak verified; 24-hour soak must be executed on dedicated hardware in target production environment).

---

## [0.1.0] — 2026-09-27

### Phase 16 — Production Documentation & Operator Handbook
#### Added
- **Production Documentation System (`docs/`)**: Authored 18 operator-ready documentation guides grounded in the verified codebase:
  - `docs/README.md`: Central documentation hub, navigation matrix, and persona paths.
  - `docs/quick-start.md`: Fast-path setup for Windows PowerShell and Linux/macOS Bash.
  - `docs/installation.md`: System requirements, dependencies, and clean directory isolation (`INSTALL_ROOT` vs `USER_DATA`).
  - `docs/configuration.md`: Complete table of all 30 configuration parameters, validation bounds, strict boolean rules, and sanitized `.env` example.
  - `docs/operator-handbook.md`: Comprehensive 22-section operational handbook covering CLI commands, exit codes, health glyphs, maintenance mode, and emergency actions.
  - `docs/security-guide.md`: Threat model, DPAPI / encrypted store credentials, secret redactor, safe path traversal, IPC whitelisting, and Authenticode disclosure.
  - `docs/detection-guide.md`: Detection adapters, event normalization, sliding-window thresholding, and smart filter hierarchy.
  - `docs/alerts-and-notifications.md`: Alert lifecycle, bounded queue (`BoundedAlertQueue`), circuit breaker (`CircuitBreaker`), Telegram delivery, and sensor fallbacks.
  - `docs/reliability-and-soak.md`: Leak prevention, real-time metrics engine, soak runner CLI, acceptance criteria, and explicit 24h soak disclosure.
  - `docs/troubleshooting.md`: Symptom-based troubleshooting for startup, PID locks, cameras, geolocation, Telegram errors, and log ingestion.
  - `docs/recovery-and-backup.md`: Atomic persistence, corrupted state repair (`--repair-state`), installation verification, and manual backup scripts.
  - `docs/updates-and-release.md`: Update lifecycle, Ed25519 signature verification, streaming SHA-256 chunking, update transactions, and rollback.
  - `docs/deployment-checklist.md`: 6-phase deployment and verification checklist for production readiness.
  - `docs/incident-response.md`: 7-step incident response playbook (Detect, Contain, Preserve, Recover, Verify, Document, Escalate) and threat scenarios.
  - `docs/platform-support.md`: Realistic cross-platform matrix for Windows, Linux, and macOS with explicit support tiers.
  - `docs/architecture.md`: Component diagram, subsystem interactions, directory boundaries, and privilege separation.
  - `docs/faq.md`: Grounded Q&A answering 11 operator and security questions accurately based on implementation.
  - `docs/known-limitations.md`: Transparent disclosures on 24h soak status, Authenticode, camera exclusivity, and OS log permissions.
- **Automated Documentation Test Suite**: Added `tests/test_phase16_documentation.py` asserting file presence, non-emptiness, cross-link validity, required operational caveats (24h soak status, Authenticode), and zero secret leaks.

### Phase 15 — Final Security Audit & Release Certification
#### Added
- **Adversarial Security Regression Test Suite**: 55 automated adversarial regression tests (`tests/test_phase15_security_*.py`) covering Authentication sanitization, RBAC operator contracts, Input injection/boundary defense, Filesystem traversal defenses, Secrets storage & recovery isolation, Cryptographic Ed25519/SHA-256 integrity, Network perimeter isolation, IPC replay defense & clock skew, Update package validation, Audit log sanitization & retention, Configuration parsing boundaries, and Atomic persistence safety.
- **Critical Security Audit Trail Preservation**: Hardened `DuplicateLogFilter` in `src/device_guardian/logger.py` so that log records with level `CRITICAL` or from `security.*` loggers bypass duplicate suppression, guaranteeing zero audit loss during high-frequency security events.
- **Percent-Encoded Path Traversal Protection**: Hardened `validate_safe_path` in `src/device_guardian/security/filesystem.py` against URL/percent-encoded traversal sequences (`%2e%2e`, `%00`).
- **Dynamic Alert Reason Redaction**: Integrated `SecretRedactor` into `AlertEvent.format_telegram_message` in `src/device_guardian/alerts/models.py` to scrub secrets from dynamic event reasoning strings before network transmission.
- **Geolocation URL Scheme & Timeout Validation**: Hardened `get_approximate_location` in `src/device_guardian/location/geolocation.py` with URL scheme validation (`https://` enforcement, rejection of dangerous schemes) and bounded timeouts (`[0.5, 60.0]s`).
- **Platform Authentication Log Credential Scrubbing**: Hardened `parse_log_stream` in `src/device_guardian/detection/macos.py` with `_scrub_entry` to strip credentials and passwords from raw event snippets before storing in event details.
- **Modularized Configuration Parsers**: Promoted `_parse_bool` and `_parse_csv` in `src/device_guardian/config.py` to module level for robust testing and direct validation.
- **Release Manifest & Crypto Compatibility Aliases**: Added `save = save_to_file` on `ReleaseManifest` and exported `generate_keypair`, `ed25519_sign`, and `ed25519_verify` in `src/device_guardian/updates/crypto.py`.
- **Formal Security Audit & Certification Report**: Documented vulnerability classifications, attack surface reviews, privilege boundaries, and release certification verdicts in `SECURITY.md`.

### Phase 14 — Performance, 24-Hour Soak & Reliability Engineering
#### Added
- **Operational Reliability Metrics Engine**: Added `ReliabilityMetricsTracker` and `ReliabilityMetrics` in `src/device_guardian/reliability/metrics.py` tracking uptime, events processed, alert counts, queue watermarks, RSS memory baselines/peaks, thread counts, and subsystem failures/recoveries.
- **Bounded Alert Queue & Backpressure**: Implemented `BoundedAlertQueue` in `src/device_guardian/alerts/queue.py` providing thread-safe queueing with auditable priority preservation (Critical/High over Standard/Low) and capacity drop tracking.
- **Network Resilience & Circuit Breaker**: Implemented `CircuitBreaker` in `src/device_guardian/reliability/circuit_breaker.py` with states `CLOSED`, `OPEN`, and `HALF_OPEN`. Integrated into `TelegramClient` to fast-fail during network outages and prevent CPU spinning or socket exhaustion.
- **Log Storm Suppression Filter**: Implemented `DuplicateLogFilter` in `src/device_guardian/logger.py` with sliding window deduplication and strictly bounded cache size to suppress runaway identical log records.
- **Continuous Soak-Testing Framework**: Built dedicated runner in `src/device_guardian/reliability/soak.py` with configurable modes (`smoke`, `short`, `extended`, `production`), checkpoint durability in JSONL, comprehensive diagnostic summaries, and strict acceptance criteria evaluations (`SoakAcceptanceCriteria`).
- **Comprehensive Failure Injection & Reliability Test Suite**: Added 36 targeted Phase 14 unit and integration tests across resource lifecycle, alert storm suppression, network recovery, persistence safety, failure injection, performance baselines, and soak acceptance.

### Phase 12 — Production Distribution, Installer Engineering & Application Lifecycle Management
#### Added
- **Authoritative Version Source**: Added `current_version()`, `parse_version()`, and `compare_versions()` conforming strictly to Semantic Versioning 2.0.0.
- **Architectural Separation**: Clean separation between read-only application binary directory (`INSTALL_ROOT`) and mutable state (`USER_DATA`).
- **Application Lifecycle Framework**:
  - `LifecycleInstaller.fresh_install()`: Atomic binary placement with physical fsync, metadata creation, default `.env` initialization, and optional OS autostart integration.
  - `LifecycleInstaller.upgrade()`: Safe transactional binary swap with backup-on-upgrade, rollback on validation failure, update lock concurrency protection, and graceful running runtime coordination.
  - `LifecycleInstaller.repair()`: Safe non-destructive repair of missing directories and corrupted metadata, stale lock pruning, and strict preservation of user configurations and secrets.
  - `LifecycleInstaller.uninstall()`: Transparent uninstallation distinguishing application binaries from user data, requiring explicit operator confirmation before data deletion.
- **Versioned Schema Migration Framework**:
  - `MigrationManager` managing persistent state schema versions (`CURRENT_STATE_SCHEMA_VERSION = 1`).
  - Automated pre-migration snapshot backups in `migration_backups/snapshot_<ts>/`.
  - Step-by-step migration handlers with atomic commit and automatic rollback on failure.
  - Strict prohibition of schema downgrades.
- **CLI Commands & Operator UX**:
  - `--install-info`: Display installed version, installation root, user data path, and schema version.
  - `--installation-status`: Color-independent health assessment of executable, metadata, directories, and configurations.
  - `--repair-installation`: Trigger non-destructive repair workflow with operator confirmation.
  - `--migration-status`: Inspect current vs target state schemas and pending migrations.
  - `--migrate`: Apply pending persistent schema migrations with automated rollback guarantees.
  - `--uninstall`: Uninstall application binaries with optional `--remove-data` and `--yes` automation.
  - `--verify-package`: Cryptographic and path safety validation of candidate update archives.
- **Security & Build Pipeline**:
  - `scan_artifacts_for_secrets()`: Release artifact scanner rejecting bundled `.env`, secret stores, and private key headers.
  - `build-metadata.json`: Machine-readable reproducible build metadata tracking commit, Python version, platform, architecture, executable hash, and size.
  - 16 new lifecycle security audit events logged through `SecurityEventType`.
  - 48 automated Phase 12 unit and integration tests (bringing test baseline to 476 passed, 1 skipped).

### Phase 11 — Production Integration, End-to-End Validation & Release Readiness
#### Added
- End-to-end integration test suites across detection-to-alert pipeline, notifications, runtime lifecycle, configuration/secret recovery, updates/rollback, and operator journeys.
- Release candidate standalone binary packaging and reproducibility audits.

### Phase 10 — Production UX, Operator Experience & Accessibility Hardening
#### Added
- Color-independent state model with geometric status glyphs (`[● HEALTHY]`, `[▲ DEGRADED]`, `[■ FAILED]`, `[? UNKNOWN]`, `[- NOT_CONFIG]`).
- 15-point operator status dashboard (`--status`).
- Structured confirmation dialogs (`confirm_action`) for high-impact operations.
- Uncertainty invariants (`UNKNOWN != SAFE`, `NOT_CONFIGURED != PROTECTED`).

### Phase 9 — Production Security, Threat Modeling & Local Attack-Surface Hardening
#### Added
- Filesystem traversal defenses, UNC path blocking, NTFS Alternate Data Streams (ADS) protection, and reparse-point/symlink detection.
- Hardened IPC channel with whitelisted verbs (`START`, `STOP`, `RESTART`), UUID request IDs, and 30-second TTL expiry.
- Process identity and creation timestamp checks defeating PID reuse attacks.

### Phase 8 — Disaster Recovery, Resilience & Failure-Injection Hardening
#### Added
- `AtomicPersistence` engine with thread-safe atomic writes, fsync, and automatic `.bak` fallback.
- Health assessment subsystem and failure-resilient alert decoupling.

### Phase 7 — Secure Updates, Versioning & Release Integrity
#### Added
- Pure-Python RFC 8032 Ed25519 digital signature verification and streaming SHA-256 integrity digests.
- `SafeZipExtractor` with zip bomb defenses, directory traversal checks, and case-collision protection.
- Transactional update state machine and verified rollback.

### Phases 1–6 — Core Foundations
- Phase 1: Camera capture, approximate IP geolocation, and HTTPS Telegram delivery.
- Phase 2: Interactive setup wizard and configuration persistence.
- Phase 3: OS authentication failure monitoring (Event ID 4625 / PAM / Unified Log) and offline voice warning.
- Phase 4: Deterministic rule-based smart filtering and environmental context.
- Phase 5: PyInstaller packaging, `GuardianRuntime`, system tray, and OS autostart integration.
- Phase 6: Windows DPAPI and file-based fallback secret storage, `SecretValue` containers, and centralized secret redactor.
