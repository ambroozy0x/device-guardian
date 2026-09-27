# Device Guardian — Updates & Release Management Guide

This document describes the update lifecycle, cryptographic verification model, transactional rollback engine, downgrade protections, and current signing status for Device Guardian releases.

---

## 1. Update Architecture & Lifecycle

Device Guardian provides a resilient, non-destructive release updater designed to deploy validated binaries without data loss or partial installation corruptions:

```
[ Update Package (.zip) ]
         │
         ▼
[ Canonical Manifest & Integrity Verification ]
         │ (Ed25519 Signature + SHA-256 Digest)
         ▼
[ Semantic Version Compatibility Check ]
         │ (Rejects downgrades unless --allow-downgrade)
         ▼
[ Transaction: BACKING_UP ]
         │ (Preserves existing executable as .bak)
         ▼
[ Transaction: STAGING ]
         │ (Extracts and validates candidate binary in temporary location)
         ▼
[ Transaction: INSTALLING ]
         │ (Atomic file replacement via os.replace)
         ▼
[ Transaction: VALIDATING ]
         │ (Integrity health check on installed artifact)
         ▼
[ Transaction: COMPLETED ]
   (If any step fails -> Automatic ROLLBACK to .bak)
```

---

## 2. Cryptographic Integrity & Authenticity

Candidate updates must pass strict cryptographic verification gates before staging:

### Canonical Manifest Validation
- The update manifest (`release-manifest.json`) defines application metadata, target semantic version, release ID, and artifact digests.
- **Canonical Serialization**: Uses deterministic JSON serialization (lexicographically sorted keys, no whitespace padding) to eliminate signature malleability.

### Ed25519 Signature Verification
- Release manifests are signed with an Ed25519 private key by the build system.
- The Device Guardian client verifies the signature against the embedded trusted Ed25519 public key before reading or unpacking any archive files.
- Untrusted, unsigned, or tampered manifests are immediately rejected (`VerificationStatus.UNTRUSTED` / `VerificationStatus.INVALID`).

### Streaming SHA-256 Digest Verification
- Package archives and extracted binaries are verified using streaming SHA-256 chunking (64 KB buffers).
- Prevents reading entire multi-megabyte archives into system memory.
- If the computed digest fails to match the manifest hash, the update is rejected as corrupted.

---

## 3. Transaction State Machine & Crash Recovery

Update deployments are governed by a persistent transactional state machine:

- **Implementation**: [`device_guardian.updates.transaction.UpdateTransaction`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/updates/transaction.py)
- **Persisted State File**: `%LOCALAPPDATA%\DeviceGuardian\update_transaction.json`

### Transaction States
- `IDLE`: No update active.
- `VERIFYING`: Manifest signature and package digests being evaluated.
- `VERIFIED`: Package validated successfully.
- `BACKING_UP`: Current binary is being copied to `<binary>.bak`.
- `STAGING`: Candidate executable staged into an isolated temporary folder.
- `INSTALLING`: Candidate executable atomically moved into installation destination.
- `VALIDATING`: Post-install verification running.
- `COMPLETED`: Update successfully finalized.
- `ROLLBACK_REQUIRED` / `ROLLED_BACK`: If any error occurs or power is interrupted mid-install, the startup supervisor inspects the transaction log and automatically restores the `.bak` binary.

---

## 4. Downgrade Protection

To defend against replay attacks where an attacker might attempt to force-downgrade Device Guardian to a previous version containing known vulnerabilities:
- The update verifier compares the candidate version against `device_guardian.version.get_current_semantic_version()`.
- If `candidate_version < current_version`, verification fails with `INCOMPATIBLE: Downgrade not permitted`.
- Operators wishing to intentionally perform a rollback must explicitly provide the `--allow-downgrade` flag.

---

## 5. Release & Update CLI Commands

```powershell
# Show active application version and build metadata
python -m device_guardian.main --release-info

# Check active update transaction state
python -m device_guardian.main --update-status

# Verify candidate package integrity and signature without installing
python -m device_guardian.main --verify-update ./DeviceGuardian-0.1.1-windows-x64.zip

# Verify and atomically install update package
python -m device_guardian.main --install-update ./DeviceGuardian-0.1.1-windows-x64.zip

# Manually rollback to previous binary (.bak)
python -m device_guardian.main --rollback

# Allow intentional downgrade if reverting an unstable release
python -m device_guardian.main --install-update ./DeviceGuardian-0.0.9.zip --allow-downgrade
```

---

## 6. Code Signing Status & Disclosure

> [!WARNING] **WINDOWS AUTHENTICODE SIGNING STATUS: NOT VERIFIED / NOT IMPLEMENTED**
> - **Ed25519 & SHA-256 Verification**: **Fully implemented and verified**. Every release manifest and archive is cryptographically verified against trusted Ed25519 public keys.
> - **Windows Authenticode Digital Signing**: **NOT VERIFIED / NOT IMPLEMENTED**. Device Guardian binaries in `dist/` do not currently have embedded Windows Authenticode signatures.
> - **Rationale**: Commercial Windows Authenticode signing requires an Extended Validation (EV) certificate backed by a certified physical hardware security module (HSM) or USB cryptotoken issued by a public Certificate Authority (e.g. DigiCert, Sectigo). These cannot be automated in CI/CD without dedicated enterprise key management infrastructure. Windows SmartScreen may present an untrusted publisher prompt when executing unsigned `.exe` binaries until Authenticode signing is configured.
