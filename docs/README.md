# Device Guardian — Documentation System

Welcome to the **Device Guardian** documentation. This documentation system provides comprehensive operational guidance, architectural specifications, security guarantees, and troubleshooting procedures for operators, administrators, developers, and security auditors.

---

## Documentation Navigation

| Document | Purpose & Target Audience | Key Topics |
| :--- | :--- | :--- |
| [**Quick Start Guide**](quick-start.md) | Fast-path setup for new operators | Clone, virtual environment, initial config, startup, health check |
| [**Installation Guide**](installation.md) | Comprehensive installation manual | Prerequisites, dependencies, packaging, permissions, system service |
| [**Configuration Reference**](configuration.md) | Authoritative reference for all settings | Environment variables, `.env` file, default values, bounds, security impact |
| [**Operator Handbook**](operator-handbook.md) | Central daily operational guide | Starting, stopping, monitoring health, runtime state, logs, maintenance |
| [**Security Guide**](security-guide.md) | Security architecture & defensive controls | Zero-cloud invariant, DPAPI/encrypted secrets, safe paths, IPC, crypto |
| [**Detection Guide**](detection-guide.md) | Authentication failure detection engine | Platform log monitors (Win/Linux/Mac), threshold engine, smart filtering |
| [**Alerts & Notifications**](alerts-and-notifications.md) | Notification pipeline & backpressure | Bounded queue, priority preservation, circuit breaker, Telegram, fallback |
| [**Reliability & Soak Guide**](reliability-and-soak.md) | Long-running stability & soak runner | Metrics engine, leak prevention, soak modes, acceptance criteria, 24h status |
| [**Troubleshooting Guide**](troubleshooting.md) | Symptom-organized problem resolution | Startup issues, single-instance lock, sensor faults, network drops |
| [**Recovery & Backup Guide**](recovery-and-backup.md) | Disaster recovery & data resilience | Atomic persistence, `.bak` recovery, state file repair, installation audit |
| [**Updates & Release Guide**](updates-and-release.md) | Release verification & update lifecycle | Ed25519 signatures, SHA-256 chunking, manifest schema, rollbacks, Authenticode |
| [**Deployment Checklist**](deployment-checklist.md) | Practical release & staging checklist | Pre-deployment, deployment, post-deployment, security, rollback steps |
| [**Incident Response Playbook**](incident-response.md) | Security incident operational playbook | Detection, containment, evidence preservation, remediation, recovery |
| [**Platform Support Matrix**](platform-support.md) | Cross-platform compatibility reality | Windows, Linux, macOS support status, limitations, platform-specific traits |
| [**Architecture Overview**](architecture.md) | System design & subsystem flows | Component interaction, pipeline flowcharts, privilege boundaries |
| [**Frequently Asked Questions**](faq.md) | Answers to common practical questions | Internet requirements, password safety, multi-instance, camera behavior |
| [**Known Limitations**](known-limitations.md) | Explicitly labeled project constraints | 24-hour soak status, Authenticode signing, hardware dependency bounds |

---

## Audience Paths

### For Operators & Administrators
1. Start with the [**Quick Start Guide**](quick-start.md) to set up and verify the application.
2. Read the [**Operator Handbook**](operator-handbook.md) for day-to-day operations and health verification.
3. Keep the [**Troubleshooting Guide**](troubleshooting.md) and [**Incident Response Playbook**](incident-response.md) accessible for operational anomalies.

### For Security Auditors
1. Inspect the [**Security Guide**](security-guide.md) and [**Architecture Overview**](architecture.md).
2. Review the [**Configuration Reference**](configuration.md) and [**Platform Support Matrix**](platform-support.md).
3. Review [`SECURITY.md`](../SECURITY.md) at the repository root for formal threat models and vulnerability registers.

### For Developers & Maintainers
1. Follow the [**Installation Guide**](installation.md) for development environment setup.
2. Review the [**Detection Guide**](detection-guide.md) and [**Alerts & Notifications**](alerts-and-notifications.md) for subsystem implementation details.
3. Consult the [**Reliability & Soak Guide**](reliability-and-soak.md) and [**Updates & Release Guide**](updates-and-release.md) before cutting new releases.

---

## Documentation Principles & Caveats

* **Document What Exists**: All documentation directly reflects the actual codebase implementation. Speculative or unverified capabilities are explicitly labeled `NOT VERIFIED` or `REQUIRES PRODUCTION ENVIRONMENT`.
* **Zero Secret Exposure**: All configuration examples use clear placeholders (e.g. `YOUR_TELEGRAM_BOT_TOKEN`). Never paste real tokens or private keys into documentation.
* **Deterministic Behavior**: Device Guardian uses strictly deterministic rule-based evaluation. There are zero AI, machine-learning, or heuristic scoring components.
