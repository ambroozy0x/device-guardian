# Detection Guide — Device Guardian

This guide explains the architecture, platform adapters, event normalization pipeline, sliding-window threshold evaluation, and deterministic smart filtering rules of the Device Guardian detection engine.

---

## 1. Detection Architecture Overview

The detection engine continuously monitors native operating system authentication logs to identify repeated failed logon attempts.

```text
       Native Operating System
       (Windows / Linux / macOS)
                   │
                   ▼
       Platform Detection Adapter
       - Windows: wevtutil (Event 4625)
       - Linux: auth.log / secure (PAM/SSH/sudo)
       - macOS: log show (Unified Log)
                   │
                   ▼
       Event Normalization
       - Password Stripping
       - Sanitized Username & IP
       - Auth Type Classification (Local vs Remote)
                   │
                   ▼
       Sliding-Window Threshold Engine
       - Accumulate events in rolling window (e.g. 60s)
       - Evaluate failure count against threshold (e.g. 3)
                   │
                   ▼
       Smart Filtering Engine (Deterministic Rules)
       - Safety rule checks
       - Synthetic test handling
       - Trusted users / networks / auth types
       - Environmental context (Active / Locked / Connected)
                   │
                   ▼
       Cooldown Manager (Rate-Limiting)
                   │
                   ▼
       Alert Dispatch Pipeline
```

---

## 2. Platform Detection Adapters

Device Guardian incorporates platform-native detection adapters adhering to the [`BaseAuthenticationMonitor`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/detection/base.py#L18) interface:

### 1. Windows: `WindowsSecurityLogMonitor`
* **Mechanism**: Executes `wevtutil.exe qe Security "/q:*[System[(EventID=4625)]]" /f:xml /rd:true` to query the Windows Security Event Log.
* **Target Event**: Windows Event ID `4625` (An account failed to log on).
* **Bookmark Tracking**: Maintains `_last_record_id` and `_seen_record_ids` to ensure historical events logged before daemon launch are never re-evaluated.
* **Fields Extracted**: `TargetUserName`, `LogonType` (Local console: 2, 7, 11; Remote network: 3, 8, 10), `IpAddress`, `Status`, `SubStatus`, `WorkstationName`.

### 2. Linux: `LinuxAuthLogMonitor`
* **Mechanism**: Tails standard system authentication logs (`/var/log/auth.log` on Debian/Ubuntu; `/var/log/secure` on RHEL/CentOS).
* **Bookmark Tracking**: Seeks to the end of file (`seek(0, os.SEEK_END)`) at startup to ignore historical log lines.
* **Log Signatures Parsed**:
  - `sshd`: `sshd[<pid>]: Failed password for <user> from <ip> port <port>`
  - `PAM`: `pam_unix(<service>:auth): authentication failure; ... user=<user>`
  - `sudo`: `sudo: <user> : <n> incorrect password attempts`

### 3. macOS: `MacOSAuthLogMonitor`
* **Mechanism**: Queries the macOS Unified Logging System using `/usr/bin/log show --style ndjson --predicate 'process == "loginwindow" || process == "sshd"'`.
* **Bookmark Tracking**: Tracks the latest event ISO timestamp (`_last_timestamp`) to filter duplicate historic events across polling iterations.
* **Credential Scrubbing**: Intercepts and scrubs attempted passwords from raw log snippets using `_scrub_entry`.

### 4. Fallback: `NullAuthenticationMonitor`
* **Behavior**: Activated automatically on unsupported operating systems (e.g. BSD, Solaris).
* **Safe Degradation**: Reports `is_available() -> (False, reason)` and returns empty event lists (`poll() -> []`) without crashing.

---

## 3. Event Normalization

Regardless of the host operating system, all detected events are normalized into an immutable [`AuthenticationFailureEvent`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/detection/models.py#L38) structure:

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | `datetime` | Exact UTC timestamp of the failed authentication event. |
| `platform` | `str` | Host operating system (`Windows`, `Linux`, `macOS`). |
| `source` | `str` | Subsystem source (e.g. `Security Event Log (4625)`, `sshd`, `pam_unix(login)`). |
| `username` | `str` | Target username attempted (defaults to `"Unavailable"` if unparseable). |
| `remote_address` | `str` | IP address for network logons, or `"Local Console"` for physical console logons. |
| `authentication_type` | `str` | Categorization: `"local"`, `"remote"`, or `"unknown"`. |
| `details` | `dict[str, Any]` | Platform-specific non-sensitive diagnostic metadata. |

### The Password Invariant
The `AuthenticationFailureEvent` dataclass contains **zero** password or credential fields. Any password text present in raw log streams is scrubbed at the ingest boundary.

---

## 4. Sliding-Window Threshold Engine

The [`SlidingWindowThresholdEngine`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/detection/threshold.py#L18) manages temporal failure aggregation:

1. **Window Duration** (`AUTH_FAILURE_WINDOW_SECONDS`, default: 60s): Events older than `now - window_seconds` are pruned automatically from the sliding buffer.
2. **Threshold Count** (`AUTH_FAILURE_THRESHOLD`, default: 3): Once the count of unexpired events reaches the threshold, the engine returns `threshold_reached=True`.
3. **Thread Safety**: Event ingestion and evaluation are protected by an internal reentrant lock (`threading.RLock`).

---

## 5. Smart Filtering & Rule Priority

When the threshold is tripped, the [`SmartFilterEngine`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/filtering/engine.py#L19) evaluates the event context against deterministic rules in strict priority order (lowest priority number evaluates first):

```text
Priority 10: Safety & Configuration Check
             (If TELEGRAM_ALERT_ENABLED=false, route to local sink)
     ↓
Priority 20: Disabled Filtering Bypass
             (If SMART_FILTERING_ENABLED=false, bypass all filters)
     ↓
Priority 30: Synthetic Test Context
             (Synthetic test events bypass trusted context for testing)
     ↓
Priority 40: Explicit Trusted Context Match
             (Filter event if username, network, or auth type is trusted)
     ↓
Priority 50: Environmental Context Requirements
             (If REQUIRE_CONTEXT_FOR_ALERT=true and state is UNKNOWN, filter)
     ↓
Priority 60: Threshold State Confirmation
             (Verify that threshold was genuinely reached)
     ↓
Priority 70: Final Alert Eligibility
             (Mark event as ALERT_ELIGIBLE)
```

### Configurable Trusted Contexts
* **`TRUSTED_USERS`**: Whitelist of trusted local accounts (e.g. `alice,bob`). Failed logons for these accounts are benignly suppressed.
* **`TRUSTED_NETWORKS`**: Whitelist of trusted IP subnets (e.g. `192.168.1.0/24`). Failed remote SSH attempts from these subnets are suppressed.
* **`TRUSTED_AUTH_TYPES`**: Whitelist of authentication types (e.g. `local`).

---

## 6. Cooldown & Debouncing

To prevent notification storms during brute-force attacks:
* [`AlertCooldownManager`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/detection/cooldown.py#L18) enforces a mandatory quiet period (`AUTH_ALERT_COOLDOWN_SECONDS`, default: 300s) between successive alerts.
* During the cooldown window, subsequent threshold trips are recorded in metrics as `alerts_suppressed_by_cooldown` and logged, but no duplicate notifications are transmitted.

---

## 7. What Device Guardian Does NOT Do

To maintain strict privacy and predictability:
* **NO AI/ML Scoring**: No machine-learning models, LLMs, or heuristic risk scores are used.
* **NO Behavioral Profiling**: The application does not monitor user typing speed, mouse movements, or behavioral patterns.
* **NO Keylogging**: Device Guardian does not record keystrokes or input devices.
* **NO Screen Recording**: The application never captures desktop screenshots or video streams.
* **NO Inbound Network Sniffing**: Device Guardian does not inspect general network traffic; it inspects only operating system authentication logs.
