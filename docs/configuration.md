# Configuration Reference — Device Guardian

Device Guardian is configured via environment variables and optional `.env` files located in the project root or the platform user data directory (`%LOCALAPPDATA%\DeviceGuardian` on Windows).

All configuration settings are strictly parsed and bounded at startup. Invalid values will immediately halt initialization with a clear [`ConfigurationError`](file:///C:/Users/Nibras/device-guardian/src/device_guardian/config.py#L38) explaining the exact constraint violation.

---

## 1. Complete Variable Reference

| Name | Type | Required | Default | Allowed Values / Bounds | Security & Operational Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TELEGRAM_BOT_TOKEN` | `str` | No | `""` | Valid token format (`bot<id>:<secret>`) | Sensitive credential. Scrubbed across all logs, exceptions, and displays via `SecretValue`. |
| `TELEGRAM_CHAT_ID` | `str` | No | `""` | Numeric chat ID or group ID | Sensitive credential. Scrubbed across all logs, exceptions, and displays via `SecretValue`. |
| `LOCATION_API_URL` | `str` | No | `https://ipapi.co/json/` | Valid HTTP/HTTPS URL, max length 2048 | Service used for IP geolocation. HTTPS is strongly recommended; plaintext HTTP logs a warning. |
| `CAMERA_INDEX` | `int` | No | `0` | `0` to `32` | Hardware index of camera device. `0` selects default integrated/primary webcam. |
| `REQUEST_TIMEOUT_SECONDS` | `float` | No | `10.0` | `0.1` to `300.0` | Network timeout for outbound HTTPS requests to Telegram and Geolocation APIs. |
| `LOG_LEVEL` | `str` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | Controls console and rotating log verbosity. Sensitive tokens are scrubbed regardless of level. |
| `AUTH_FAILURE_THRESHOLD` | `int` | No | `3` | `1` to `100` | Number of failed authentication attempts within the detection window required to trigger an alert. |
| `AUTH_FAILURE_WINDOW_SECONDS` | `float` | No | `60.0` | `1.0` to `86400.0` | Rolling sliding window duration (seconds) during which failed authentication attempts accumulate. |
| `AUTH_ALERT_COOLDOWN_SECONDS` | `float` | No | `300.0` | `0.0` to `86400.0` | Minimum duration (seconds) between successive alerts to prevent notification storms. |
| `VOICE_WARNING_ENABLED` | `bool` | No | `true` | `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` | Toggles local offline text-to-speech audio alert through workstation speakers. |
| `VOICE_WARNING_TEXT` | `str` | No | `"Warning. Multiple failed..."` | Any non-empty string | Text synthesized aloud when auth failure threshold is exceeded. |
| `VOICE_WARNING_COOLDOWN_SECONDS` | `float` | No | `300.0` | `0.0` to `86400.0` | Cooldown period between successive offline voice announcements. |
| `SMART_FILTERING_ENABLED` | `bool` | No | `true` | Strict boolean | Master toggle for deterministic filtering rules (bypasses filtering when false). |
| `TRUSTED_USERS` *(or `DEVICE_GUARDIAN_TRUSTED_USERS`)* | `list[str]` | No | `[]` | Comma-separated usernames | Authentication failures from these usernames are benignly suppressed. |
| `TRUSTED_NETWORKS` *(or `DEVICE_GUARDIAN_TRUSTED_NETWORKS`)* | `list[str]` | No | `[]` | Comma-separated IP prefixes | Remote authentication failures originating from these CIDR/IPs are suppressed. |
| `TRUSTED_AUTH_TYPES` *(or `DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES`)* | `list[str]` | No | `[]` | Comma-separated (`local`, `remote`) | Specifies authentication types to treat as trusted when matched. |
| `ENVIRONMENTAL_TRIGGERS_ENABLED` | `bool` | No | `true` | Strict boolean | Enables environmental context checks (network status, workstation lock state). |
| `NETWORK_CONTEXT_ENABLED` | `bool` | No | `true` | Strict boolean | Queries network interface connectivity state during event evaluation. |
| `DEVICE_STATE_CONTEXT_ENABLED` | `bool` | No | `true` | Strict boolean | Queries workstation active/idle/locked state during event evaluation. |
| `REQUIRE_CONTEXT_FOR_ALERT` | `bool` | No | `false` | Strict boolean | When true, enforces uncertainty rule: suppresses alert if state is completely `UNKNOWN`. |
| `CAMERA_ALERT_ENABLED` | `bool` | No | `true` | Strict boolean | Enables webcam frame capture during alert execution. If camera fails, alert still sends text. |
| `LOCATION_ALERT_ENABLED` | `bool` | No | `true` | Strict boolean | Enables IP geolocation lookup during alert execution. If offline, alert marks location as unavailable. |
| `TELEGRAM_ALERT_ENABLED` | `bool` | No | `true` | Strict boolean | Master kill-switch for outbound Telegram messages. When false, pipeline executes without network. |
| `BACKGROUND_MODE_ENABLED` | `bool` | No | `false` | Strict boolean | Configures runtime to run as background worker daemon. |
| `TRAY_ENABLED` | `bool` | No | `true` | Strict boolean | Displays dynamic system tray icon on supported desktop environments. |
| `START_WITH_SYSTEM` | `bool` | No | `false` | Strict boolean | Automatically registers user login autostart entry (HKCU Run on Windows, XDG on Linux). |
| `SINGLE_INSTANCE_ENABLED` | `bool` | No | `true` | Strict boolean | Mutex lock preventing concurrent process execution and port/sensor collisions. |
| `AUTO_RESTART_ENABLED` | `bool` | No | `true` | Strict boolean | Automatically restarts crashed worker threads up to `MAX_RESTART_ATTEMPTS`. |
| `MAX_RESTART_ATTEMPTS` | `int` | No | `3` | `0` to `100` | Maximum automatic recovery restarts allowed before the daemon enters fatal failure state. |
| `RESTART_BACKOFF_SECONDS` | `float` | No | `2.0` | `0.0` to `3600.0` | Exponential backoff delay between worker restart attempts. |
| `CAMERA_PHOTO_COUNT` | `int` | No | `3` | `1` to `10` | Number of rapid burst photos captured per security alert. |
| `EXACT_LATITUDE` | `float` | No | `None` | `-90.0` to `90.0` | Exact fixed GPS latitude coordinate for home/office (overrides IP lookup). |
| `EXACT_LONGITUDE` | `float` | No | `None` | `-180.0` to `180.0` | Exact fixed GPS longitude coordinate for home/office (overrides IP lookup). |
| `EXACT_LOCATION_NAME` | `str` | No | `""` | Any non-empty string | Human-readable place name corresponding to exact GPS coordinates (e.g. "Cherur, Malappuram"). |

---

## 2. Configuration Resolution Order

When `load_config()` is invoked, settings are resolved in the following priority order (highest priority first):

1. **Explicit CLI Flags / Overrides**: Parameters passed directly via CLI flags.
2. **Environment Variables**: Variables exported in the current process shell.
3. **Explicit `.env` Path**: File supplied via `--env-file <path>`.
4. **Current Working Directory `.env`**: `./.env` file in the current working directory.
5. **User Application Data `.env`**: `%LOCALAPPDATA%\DeviceGuardian\.env` (Windows) or `~/.local/share/device-guardian/.env` (Linux/macOS).
6. **Encrypted Secret Store**: Windows DPAPI or encrypted storage backend for `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
7. **Built-in Defaults**: Hardcoded safe defaults declared in `AppConfig`.

---

## 3. Strict Boolean Parsing

Device Guardian strictly rejects ambiguous boolean representations. All boolean settings must resolve to one of the following exact representations (case-insensitive):

* **Truthy**: `true`, `1`, `yes`, `on`
* **Falsy**: `false`, `0`, `no`, `off`

Any other string (e.g. `maybe`, `enable`, `disabled`, `2`) triggers a `ConfigurationError` and aborts execution.

---

## 4. Production Example Configuration File (`.env`)

```ini
# ==============================================================================
# Device Guardian - Production Configuration
# Placeholders used: Replace with actual values
# ==============================================================================

# 1. Telegram Alert Credentials
# Obtain bot token from @BotFather, chat ID from setup wizard or @userinfobot
TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID

# 2. Alert Subsystems
CAMERA_ALERT_ENABLED=true
LOCATION_ALERT_ENABLED=true
TELEGRAM_ALERT_ENABLED=true
VOICE_WARNING_ENABLED=true
CAMERA_INDEX=0
LOCATION_API_URL=https://ipapi.co/json/
REQUEST_TIMEOUT_SECONDS=10.0

# 3. Detection Thresholds
AUTH_FAILURE_THRESHOLD=3
AUTH_FAILURE_WINDOW_SECONDS=60.0
AUTH_ALERT_COOLDOWN_SECONDS=300.0
VOICE_WARNING_COOLDOWN_SECONDS=300.0

# 4. Smart Filtering & Trusted Boundaries
SMART_FILTERING_ENABLED=true
TRUSTED_USERS=alice,bob
TRUSTED_NETWORKS=192.168.1.0/24,10.0.0.0/8
TRUSTED_AUTH_TYPES=local
ENVIRONMENTAL_TRIGGERS_ENABLED=true
REQUIRE_CONTEXT_FOR_ALERT=false

# 5. Service & Reliability
BACKGROUND_MODE_ENABLED=true
TRAY_ENABLED=true
START_WITH_SYSTEM=true
SINGLE_INSTANCE_ENABLED=true
AUTO_RESTART_ENABLED=true
MAX_RESTART_ATTEMPTS=3
RESTART_BACKOFF_SECONDS=2.0
LOG_LEVEL=INFO
```
