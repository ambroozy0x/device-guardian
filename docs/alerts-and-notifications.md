# Device Guardian — Alerts & Notifications Guide

This document describes the alerting pipeline, dispatch architecture, queuing behavior, circuit breakers, and delivery fallbacks implemented in Device Guardian.

---

## 1. Alert Lifecycle Architecture

Device Guardian processes security alerts through a bounded, fail-safe pipeline that coordinates detection events, sensor captures, priority management, and external notifications.

```
[ Detection Event ]
         │
         ▼
[ Correlation Engine (Sliding Window) ]
         │ (Threshold Exceeded)
         ▼
[ Priority Determination (0=Critical .. 3=Low) ]
         │
         ▼
[ BoundedAlertQueue (Capacity: 100) ]
         │
         ├── [ Worker Thread Dequeues ]
         ▼
[ Sensor Enrichment (Camera Capture + IP Geolocation) ]
         │ (Resilient: failures fall back gracefully)
         ▼
[ Telegram Dispatcher (Protected by CircuitBreaker) ]
         │
         ├── Success: Delete local photo (Privacy Invariant)
         └── Failure: Retry / Circuit Open / Metrics Increment
```

### End-to-End Workflow Steps
1. **Trigger Reception**: Detection adapters (e.g. Windows Security Event Log, Linux auth.log, macOS Unified Log) generate normalized `AuthenticationFailureEvent` instances.
2. **Correlation & Filtering**: The sliding-window engine evaluates failure counts against `FAILED_ATTEMPTS_THRESHOLD` (default: 3) within `ATTEMPTS_WINDOW_SECONDS` (default: 60). Smart filters suppress maintenance, known service accounts, and cooldown windows.
3. **Enqueuing**: The resulting alert event is wrapped in a `PrioritizedAlertItem` and placed into `BoundedAlertQueue`.
4. **Sensor Enrichment**:
   - **Camera**: Captures a single frame from the webcam (OpenCV/DirectShow on Windows, V4L2 on Linux, AVFoundation on macOS).
   - **Location**: Queries approximate IP geolocation via external provider (default: ipapi.co) with timeout bounds.
5. **Redaction**: All alert messages and reasons are sanitized through `get_redactor()` to mask usernames, IP addresses, tokens, and session identifiers before formatting.
6. **Delivery**: The message is formatted for Telegram (`sendPhoto` with photo attachment, or `sendMessage` if camera unavailable).
7. **Privacy Cleanup**: If photo capture succeeded, the local temporary image file is immediately unlinked after delivery.

---

## 2. Bounded Alert Queue (`BoundedAlertQueue`)

To prevent unbounded memory growth and memory leak vulnerabilities during alert storms, Device Guardian uses a thread-safe priority queue with strict bounds.

- **Implementation**: [`device_guardian.alerts.queue.BoundedAlertQueue`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/alerts/queue.py)
- **Default Maximum Capacity**: 100 items (`maxsize=100`).
- **Thread Safety**: Backed by `threading.Lock` and condition variables (`_not_empty`, `_not_full`).

### Priority Tiers

| Priority Value | Name | Description | Drop / Eviction Behavior |
| :---: | :--- | :--- | :--- |
| `0` | **CRITICAL** | Confirmed intrusion, tamper attempt | Never dropped if lower priority items exist |
| `1` | **HIGH** | Rapid brute-force, threshold exceeded | Prioritized over Standard/Low alerts |
| `2` | **STANDARD** | Single threshold breach, test alert | Subject to eviction if queue is saturated |
| `3` | **LOW** | Informational warning, health degraded | First to be evicted under backpressure |

### Backpressure & Eviction Policy
When `push()` is called on a saturated queue:
1. If space is available, the alert is enqueued immediately.
2. If the queue is full and a `timeout` is specified, it waits up to the timeout for space.
3. If still full:
   - If the incoming alert has **higher priority** (lower numeric value) than the lowest-priority item currently in the queue, the lowest-priority item is evicted to make room.
   - If the incoming alert has equal or lower priority than the items in the queue, the incoming alert is rejected.
   - **Audit Guarantee**: Every drop or eviction is logged with `logger.warning()` and recorded in `ReliabilityMetrics` (`queue_dropped_count`). Alerts are never silently discarded.

---

## 3. Circuit Breaker (`CircuitBreaker`)

External API calls (Telegram Bot API, Geolocation API) are wrapped by dedicated circuit breakers to prevent thread starvation, socket exhaustion, and log flooding during network outages.

- **Implementation**: [`device_guardian.reliability.circuit_breaker.CircuitBreaker`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/reliability/circuit_breaker.py)

### States & Transitions

```
    ┌──────────────────────────────────────────────┐
    │                                              │
    ▼                                              │
[ CLOSED ] ──(5 consecutive failures)──► [ OPEN ]  │
    ▲                                       │      │
    │ (2 consecutive successes)             │ (30s cooldown)
    │                                       ▼      │
    └──────────────────────────────── [ HALF_OPEN ] ┘
                                            │
                                            │ (1 failure)
                                            └──────┘
```

- **`CLOSED`**: Normal operation. All requests pass through. Failures increment `_consecutive_failures`.
- **`OPEN`**: Tripped when `failure_threshold` (default: 5) is reached. All calls immediately raise `CircuitBreakerOpenError` without attempting network I/O.
- **`HALF_OPEN`**: After `recovery_timeout` (default: 30.0s), the circuit enters trial state. If the next 2 requests succeed, it resets to `CLOSED`. If any trial request fails, it immediately returns to `OPEN`.

---

## 4. Telegram Notification Delivery

Device Guardian delivers real-time notifications to the operator's designated Telegram chat.

### Required Configuration
- `TELEGRAM_BOT_TOKEN`: Bot authentication token issued by @BotFather.
- `TELEGRAM_CHAT_ID`: Target numeric chat ID of the operator.

### Notification Payload Content
In accordance with Device Guardian's Privacy and Transparency guidelines:
- **Objective Language**: Uses neutral descriptions (e.g. `"Authentication Failure Threshold Exceeded"`). Never uses speculative terms like `"hacker"`, `"attacker"`, or `"criminal"`.
- **Timestamp**: Formatted local timestamp (`YYYY-MM-DD HH:MM:SS`).
- **Location**: Approximate city, region, country, and latitude/longitude coordinates (with OpenStreetMap link) when available.
- **Photo**: Webcam image attached directly to the message if camera capture was successful.

### Fallback Matrix

| Condition | Fallback Action | Status Reported in Alert |
| :--- | :--- | :--- |
| **Webcam Busy / Denied** | Skip photo upload; send text-only Telegram message | `Camera: Unavailable` |
| **Location Timeout / Offline** | Skip geolocation; omit map links | `Coordinates: Unavailable` |
| **Telegram Network Down** | Enqueue in `BoundedAlertQueue`; circuit trips to `OPEN` | Logged to `device_guardian.log` |
| **All Sensors Failed** | Send minimal text alert with timestamp and reason | Core alert delivered safely |

---

## 5. Voice Warnings (Local Deterrence)

Device Guardian can optionally deliver local audible warnings through the system speech synthesizer when a breach threshold is met.

- **Setting**: `VOICE_WARNING_ENABLED=true` (default: `false`).
- **Synthesizer**: Uses local text-to-speech engine (`pyttsx3`) without external cloud dependencies.
- **Message**: Objective audible notice informing the user that an authentication failure alert has been recorded.
- **Timeout**: Speech synthesis runs with a strict 5-second execution bound to prevent worker blocking.

---

## 6. Testing & Manual Verification

Operators can verify the alerting subsystem using built-in CLI test commands:

```powershell
# Send an end-to-end test alert (camera + location + telegram)
python -m device_guardian.main --test-alert

# Test camera capture in isolation
python -m device_guardian.main --test-camera

# Test IP geolocation acquisition in isolation
python -m device_guardian.main --test-location

# Test voice warning synthesizer
python -m device_guardian.main --test-voice-warning
```
