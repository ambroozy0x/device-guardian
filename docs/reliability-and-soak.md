# Device Guardian — Reliability & Soak Testing Guide

This guide details the reliability engineering architecture, leak prevention mechanisms, resource tracking, and the dedicated soak-testing framework in Device Guardian.

---

## 1. Reliability & Leak Prevention Architecture

Device Guardian is engineered to operate continuously as an unattended background service. To prevent resource degradation over extended runtimes, the system enforces strict resource isolation and cleanup policies:

### Memory Leak Prevention
- **Bounded Queues**: All internal queues (`BoundedAlertQueue`) have hard limits (default: 100 items). Under load, deterministic priority eviction prevents memory leaks.
- **Sliding-Window Eviction**: Authentication failure histories in `DetectionManager` automatically evict expired timestamps outside `ATTEMPTS_WINDOW_SECONDS` (default: 60s).
- **Temporary Image Cleanup**: Captured webcam images are unlinked immediately after transmission or on failure.
- **Circuit Breakers**: External HTTP calls fast-fail when unhealthy, preventing request queue buildup and associated buffering.

### Thread & Process Management
- **Controlled Lifecycles**: All worker threads are marked `daemon=True` and reference cooperative shutdown events (`threading.Event`).
- **Bounded Concurrency**: Background tasks run within fixed pools or dedicated single-worker dispatchers; threads are never spawned unboundedly per event.
- **Graceful Termination**: Shutdown handles disconnects in topological order (Monitor -> Controller -> Queue -> Sensors -> Persistence).

### Persistence & File Handles
- **Atomic Operations**: State writes use atomic staging files (`.tmp`) and atomic rename operations with retry fallbacks.
- **Deterministic File Closure**: All file I/O operations strictly use context managers (`with open(...)`) to ensure file descriptors are closed immediately.

---

## 2. Real-Time Reliability Metrics

The reliability engine continuously monitors system health and resource consumption:

- **Implementation**: [`device_guardian.reliability.metrics.ReliabilityMetricsTracker`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/reliability/metrics.py)
- **Global Access**: `get_reliability_metrics()`

### Monitored Metrics
- `rss_bytes`: Current resident set size (RSS) memory consumption in bytes.
- `thread_count`: Active thread count of the Device Guardian process.
- `events_processed`: Total count of authentication failure events processed.
- `alerts_triggered`: Count of high-severity alerts dispatched.
- `alerts_suppressed`: Count of alerts filtered by rate limiting, maintenance, or cooldown rules.
- `queue_dropped_count`: Count of low-priority alerts dropped due to queue saturation.
- `retry_count`: Total network and persistence retries executed.
- `sensor_failures` & `sensor_recoveries`: Tracking transient hardware/driver faults.
- `persistence_failures`: Count of filesystem I/O exceptions.

---

## 3. Dedicated Soak-Testing Framework

Device Guardian includes a dedicated soak testing runner to validate long-running stability under synthetic workloads:

- **Implementation**: [`device_guardian.reliability.soak.SoakTestRunner`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/reliability/soak.py)
- **Module Invocation**: `python -m device_guardian.reliability.soak`

### Safety Guarantees
1. **Isolated Data Path**: Executes in a temporary directory (`tempfile.mkdtemp`); never alters `%LOCALAPPDATA%` or production `.env`.
2. **Local Notification Sinks**: Mocks Telegram and external APIs; never transmits real network traffic or requires real credentials.
3. **Synthetic Injection**: Periodically generates controlled authentication failure bursts to exercise the full pipeline.
4. **Checkpoint Logging**: Emits periodic JSON checkpoints logging RSS memory, threads, queues, and errors.
5. **Clean Signal Handling**: Intercepts `SIGINT` (Ctrl+C) and `SIGTERM` to perform a controlled shutdown and flush final evaluation reports.

---

## 4. Soak Modes & Acceptance Criteria

### Execution Modes

| Mode | Target Duration | Intended Use |
| :--- | :---: | :--- |
| **`smoke`** | 30 seconds | Fast CI smoke test and sanity verification |
| **`short`** | 5 minutes (300s) | Local developer reliability regression check |
| **`extended`**| 30–60 minutes | Pre-deployment staging validation |
| **`production`**| 24 hours (86,400s) | Final 24-hour soak certification before deployment |

### Acceptance Criteria Thresholds (`SoakAcceptanceCriteria`)

For a soak test to receive a `PASSED` acceptance verdict, it must satisfy all 8 criteria simultaneously:

| Acceptance Criterion | Default Threshold | Description |
| :--- | :---: | :--- |
| `max_unexpected_exceptions` | `0` | Zero unhandled exceptions permitted |
| `max_thread_growth` | `1` | Max permanent thread leakage vs initial baseline |
| `max_rss_growth_mb` | `80.0 MB` | Absolute RSS memory growth limit |
| `max_rss_growth_ratio` | `2.0` | Relative RSS memory growth limit (`final / initial`) |
| `max_retry_count` | `10` | Max total retry attempts permitted during soak |
| `max_queue_high_watermark` | `50` | Maximum alert queue depth permitted |
| `max_persistence_failures` | `0` | Zero persistence write/read failures permitted |
| `max_unrecovered_sensor_failures` | `0` | Zero unrecovered sensor faults |

---

## 5. Running the Soak Runner

Execute the runner via the command line:

```powershell
# Run a quick 30-second smoke test
python -m device_guardian.reliability.soak --mode smoke

# Run a 5-minute reliability verification
python -m device_guardian.reliability.soak --mode short

# Run with custom parameters and output directory
python -m device_guardian.reliability.soak --mode short --checkpoint-interval 2.0 --event-interval 1.0 --output-dir ./soak_output
```

### Sample Output Summary
```
=================================================================
         DEVICE GUARDIAN SOAK EXECUTION SUMMARY
=================================================================
Mode                 : short
Execution Status     : COMPLETED
Acceptance Verdict   : PASSED
Reliability Passed   : YES
Duration             : 300.2s (Target: 300.0s)
Checkpoints          : 60
-----------------------------------------------------------------
RSS Memory           : 38.12 MB -> 41.45 MB (Growth: +3.33 MB, Peak: 43.10 MB)
Thread Count         : 3 -> 3 (Growth: 0, Peak: 5)
Events Injected      : 150
Events Processed     : 150
Alerts Triggered     : 50
Alerts Suppressed    : 100
Queue High Watermark : 2
Retries Recorded     : 0
Unexpected Errors    : 0
-----------------------------------------------------------------
CRITERIA EVALUATIONS:
  [PASS]   max_unexpected_exceptions    Target: 0            Actual: 0
  [PASS]   max_thread_growth            Target: 1            Actual: 0
  [PASS]   max_rss_growth_mb            Target: 80.0         Actual: 3.33
  [PASS]   max_rss_growth_ratio         Target: 2.0          Actual: 1.09
  [PASS]   max_retry_count              Target: 10           Actual: 0
  [PASS]   max_queue_high_watermark     Target: 50           Actual: 2
  [PASS]   max_persistence_failures     Target: 0            Actual: 0
  [PASS]   max_unrecovered_sensor_failures Target: 0         Actual: 0
-----------------------------------------------------------------
Output Directory     : C:\Users\Nibras\AppData\Local\Temp\tmp...
=================================================================
```

---

## 6. Current Soak Testing Status

> [!WARNING] **PRODUCTION 24-HOUR SOAK STATUS: NOT RUN**
> - **Framework Implementation**: Fully implemented and validated via automated unit and integration tests (`tests/soak/test_soak_runner.py`).
> - **Smoke & Short Soak Verifications**: Executed and verified locally (`smoke` and `short` modes pass with zero leaks and clean thresholds).
> - **24-Hour Production Soak (`--mode production`)**: **NOT RUN**. A complete 24-hour continuous burn-in must be scheduled and executed on dedicated physical host hardware in the production operating environment prior to mission-critical deployment.
