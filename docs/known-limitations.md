# Device Guardian — Known Limitations & Operational Constraints

This document provides transparent, exhaustive disclosure of verified boundaries, design constraints, and unverified production scenarios in Device Guardian.

---

## 1. Production Verification Disclosures

### 24-Hour Production Soak Status: NOT RUN
- **Framework Status**: The dedicated soak testing framework ([`device_guardian.reliability.soak`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/reliability/soak.py)) is fully implemented, isolated in temp files, and verified via automated test suites.
- **Short Soak Status**: The 30-second `smoke` mode and 5-minute `short` mode have been executed and confirmed to meet all 8 strict acceptance criteria (zero unexpected errors, bounded memory growth, zero thread leaks).
- **Production 24-Hour Status**: **NOT RUN**. A full continuous 24-hour soak test (`--mode production`) has not been executed on continuous production hardware. Operators deploying to mission-critical infrastructure must execute an extended soak test in their target staging environment prior to final release signoff.

### Windows Authenticode Code Signing: NOT VERIFIED / NOT IMPLEMENTED
- **Cryptographic Release Verification**: Fully implemented and verified. Release manifests are signed with Ed25519 private keys and verified against trusted public keys, while archive artifacts are validated via streaming SHA-256 digests.
- **Windows Authenticode Digital Signing**: **NOT VERIFIED / NOT IMPLEMENTED**. Standalone binaries in `dist/` do not include commercial Windows Authenticode signatures.
- **Impact**: Windows SmartScreen or Defender may display a warning ("Windows protected your PC — Unknown publisher") when running packaged `.exe` binaries until a commercial Extended Validation (EV) certificate backed by a physical HSM token is applied.

---

## 2. Hardware & Operating System Constraints

### Hardware Camera Exclusivity
- Desktop operating system webcam drivers (DirectShow on Windows, V4L2 on Linux) typically enforce single-client exclusive hardware access.
- If an active video conferencing application (e.g., Zoom, Microsoft Teams, Webex) holds an open handle to the camera device, Device Guardian will fail to acquire the camera frame.
- **Mitigation**: Device Guardian detects this condition gracefully and automatically falls back to sending an alert with text metadata and `Camera: Unavailable`.

### Single-User Session Scope
- Device Guardian is designed primarily as an endpoint defense service for an interactive desktop user.
- In multi-user environments with Windows Fast User Switching or multi-seat Linux terminals, system tray controls and DPAPI secrets are isolated to the specific logged-in user profile running the process.

### IP-Based Geolocation Precision
- Geolocation enrichment relies on external IP address lookups (`ipapi.co`).
- **Precision**: Geolocation is accurate only to the city, regional, or ISP routing level. It is **not** GPS-precise satellite positioning.
- **VPN / Proxy Impact**: If the protected device routes traffic through a corporate VPN, Tor, or proxy, the reported geolocation will reflect the VPN egress gateway rather than the physical location of the machine.

---

## 3. System Permission Dependencies

### Windows Event Auditing Policy
- Device Guardian relies on Windows Security Event ID 4625 to detect failed logons.
- If the Windows Local Security Policy has "Audit Logon Events" set to "No Auditing", Windows will not write Event ID 4625 to the event log, and Device Guardian cannot detect authentication failures.
- **Mitigation**: The `--diagnostics` command checks this policy and advises the operator if failure auditing is disabled.

### Linux Log Read Permissions
- On standard Linux installations, `/var/log/auth.log` is readable only by `root` and members of group `adm`.
- Running Device Guardian under an unprivileged user without `adm` group membership prevents the log monitor from tailing authentication failures.
