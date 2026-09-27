# Changelog — Device Guardian

All notable changes to the Device Guardian project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-09-27

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
