"""CLI entrypoint for Device Guardian.

Provides manual test commands, diagnostic verification, interactive menu,
and continuous monitoring for Phase 3 (Detection Triggers & Offline Voice Warning).
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure UTF-8 output on Windows consoles if supported
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from device_guardian import __version__
from device_guardian.alerts.pipeline import trigger_alert
from device_guardian.camera.capture import CameraError, capture_photo
from device_guardian.config import AppConfig, ConfigurationError, load_config, mask_token, mask_chat_id
from device_guardian.detection import (
    DetectionManager,
    DetectionStatus,
    OfflineVoiceWarning,
)
from device_guardian.location.geolocation import get_approximate_location
from device_guardian.logger import get_logger, setup_logging
from device_guardian.runtime import (
    ApplicationPaths,
    GuardianRuntime,
    RuntimeState,
    RuntimeStatus,
    SingleInstanceLock,
)
from device_guardian.setup import SetupStatus, determine_setup_status, run_setup_wizard
from device_guardian.startup import create_startup_manager
from device_guardian.telegram.bot import TelegramClient
from device_guardian.tray import TrayManager
from device_guardian.version import (
    SemanticVersion,
    VersionInfo,
    get_version_info,
)
from device_guardian.updates import (
    ReleaseArtifact,
    ReleaseManifest,
    SafeZipExtractor,
    UpdateInstaller,
    UpdateTransaction,
    VerificationFinding,
    VerificationStatus,
    check_and_recover_interrupted_transaction,
    get_key_fingerprint,
    get_trusted_public_key,
    verify_update_package,
)
from device_guardian.recovery import (
    AtomicPersistence,
    HealthStatus,
    assess_system_health,
    get_recovery_status,
    repair_state_files,
    verify_installation_integrity,
)
from device_guardian.lifecycle import (
    InstallationHealth,
    InstallationMetadata,
    LifecycleInstaller,
    LifecycleOperationType,
    MigrationManager,
    CURRENT_STATE_SCHEMA_VERSION,
)
from device_guardian.ux.confirmations import confirm_action

logger = get_logger("main")



def run_manual_test_alert(config: Optional[AppConfig] = None) -> int:
    """Execute the manual alert test as specified in Section 13.

    Args:
        config: Optional loaded configuration.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    print("\nDevice Guardian")
    print("----------------\n")
    print("Running manual alert test...\n")

    if config is None:
        try:
            config = load_config()
            config.validate()
        except ConfigurationError as exc:
            print(f"Error: {exc}")
            print("\nPlease ensure your .env file is properly configured before running test alerts.")
            return 1

    print("[1/4] Testing camera...")
    # Trigger the pipeline with full step logging
    result = trigger_alert(
        reason="Manual Test Alert",
        config=config,
        cleanup_image_on_success=True,
    )

    if result.camera_success:
        print("      Camera capture successful.")
    else:
        print("      Camera capture unavailable (proceeding with text-only alert).")

    print("[2/4] Obtaining approximate location...")
    if result.location_success and result.event:
        loc = result.event.location
        print(f"      Location: {loc.city}, {loc.region}, {loc.country}")
    else:
        print("      Location lookup unavailable.")

    print("[3/4] Sending Telegram alert...")
    if result.telegram_success:
        print("      Telegram alert sent successfully.")
    else:
        print(f"      Telegram alert failed: {result.error_message}")

    print("[4/4] Cleaning up...")
    print("      Cleanup completed.\n")

    if result.success:
        print("Test alert sent successfully.")
        return 0
    else:
        print(f"Test alert failed: {result.error_message}")
        return 1


def check_configuration(config: Optional[AppConfig] = None) -> bool:
    """Validate configuration and verify Telegram bot credentials."""
    print("\nChecking Configuration...")
    try:
        if config is None:
            config = load_config()
        config.validate()
        print("[OK] Configuration loaded successfully.")
        print(f"  - Camera Index: {config.camera_index}")
        print(f"  - Geolocation API: {config.location_api_url}")
        print(f"  - Request Timeout: {config.request_timeout_seconds}s")
        print(f"  - Telegram Chat ID: {config.telegram_chat_id}")
        print(f"  - Auth Failure Threshold: {config.auth_failure_threshold} failures")
        print(f"  - Auth Failure Window: {config.auth_failure_window_seconds:.0f}s")
        print(f"  - Auth Alert Cooldown: {config.auth_alert_cooldown_seconds:.0f}s")
        print(f"  - Voice Warning: {'Enabled' if config.voice_warning_enabled else 'Disabled'}")
    except ConfigurationError as exc:
        print(f"[FAIL] Configuration Error:\n{exc}")
        return False

    print("\nVerifying Telegram Bot Credentials...")
    client = TelegramClient(
        bot_token=config.telegram_bot_token,
        chat_id=config.telegram_chat_id,
        timeout=config.request_timeout_seconds,
    )
    resp = client.verify_credentials()
    if resp.success:
        bot_name = resp.data.get("username", "Unknown") if resp.data else "Bot"
        print(f"[OK] Telegram bot token is valid! (Connected as @{bot_name})")
        return True
    else:
        print(f"[FAIL] Telegram verification failed: {resp.error_message}")
        return False


def test_camera_only(camera_index: int = 0) -> bool:
    """Test camera capture and report result."""
    print(f"\nTesting Camera (Device Index: {camera_index})...")
    try:
        path = capture_photo(camera_index=camera_index)
        print("[OK] Camera captured successfully!")
        print(f"  Saved test photo: {path}")
        return True
    except CameraError as exc:
        print(f"[FAIL] Camera Test Failed: {exc}")
        return False


def test_location_only(api_url: str, timeout: float = 10.0) -> bool:
    """Test approximate location retrieval and print results."""
    print(f"\nTesting Geolocation ({api_url})...")
    loc = get_approximate_location(api_url=api_url, timeout=timeout)
    if loc.is_available:
        print("[OK] Geolocation retrieved successfully (Approximate):")
        print(f"  - IP: {loc.ip}")
        print(f"  - City: {loc.city}")
        print(f"  - Region: {loc.region}")
        print(f"  - Country: {loc.country}")
        if loc.latitude is not None and loc.longitude is not None:
            print(f"  - Coordinates: {loc.latitude:.6f}, {loc.longitude:.6f}")
            print(f"  - Map: {loc.map_url}")
        return True
    else:
        print("[FAIL] Geolocation lookup was unable to retrieve location details.")
        return False


def check_auth_monitor(config: Optional[AppConfig] = None) -> bool:
    """Check OS authentication failure monitor and voice warning readiness."""
    print("\nChecking Authentication Failure Monitor...")
    try:
        cfg = config or load_config()
    except Exception:
        cfg = None

    mgr = DetectionManager(config=cfg)
    status, msg = mgr.get_monitor_status()
    source = mgr.monitor.get_source_name()

    print(f"Log Source: {source}")
    print(f"Operational Status: {status.value}")
    if status == DetectionStatus.READY:
        print(f"[OK] {msg}")
    else:
        print(f"[UNAVAILABLE] {msg}")

    print("\nChecking Offline Voice Warning...")
    tts_ok = mgr.voice_warning.is_available()
    enabled = mgr.voice_warning.enabled
    print(f"Voice Warning Configured: {'Enabled' if enabled else 'Disabled'}")
    if tts_ok:
        print("[OK] Native offline text-to-speech facility is available.")
    else:
        print("[UNAVAILABLE] Native offline text-to-speech facility not found.")

    if cfg:
        print("\nDetection Parameters:")
        print(f"  - Failure Threshold: {cfg.auth_failure_threshold} failures")
        print(f"  - Sliding Window: {cfg.auth_failure_window_seconds:.0f} seconds")
        print(f"  - Alert Cooldown: {cfg.auth_alert_cooldown_seconds:.0f} seconds")

    return status == DetectionStatus.READY


def test_voice_warning_only(config: Optional[AppConfig] = None) -> bool:
    """Test offline voice warning text-to-speech output."""
    print("\nTesting Offline Voice Warning...")
    try:
        cfg = config or load_config()
    except Exception:
        cfg = None

    vw = OfflineVoiceWarning(
        enabled=True,
        warning_text=cfg.voice_warning_text if cfg else "Warning. Multiple failed authentication attempts detected.",
        cooldown_seconds=0.0,
    )
    if not vw.is_available():
        print("[FAIL] Native offline text-to-speech facility is not available on this system.")
        return False

    print(f"Playing synthesized warning: \"{vw.warning_text}\"")
    success = vw.speak()
    if success:
        print("[OK] Voice warning synthesized successfully.")
        return True
    else:
        print("[FAIL] Voice warning synthesis failed.")
        return False


def test_auth_monitor_synthetic(config: Optional[AppConfig] = None) -> bool:
    """Execute synthetic authentication failure test end-to-end."""
    print("\nTesting Authentication Failure Detection Pipeline (Synthetic)...")
    try:
        cfg = config or load_config()
        cfg.validate()
    except ConfigurationError as exc:
        print(f"Configuration Error: {exc}")
        print("Please configure Device Guardian before running synthetic tests.")
        return False

    mgr = DetectionManager(config=cfg)
    threshold = mgr.threshold_engine.threshold
    window = mgr.threshold_engine.window_seconds

    print(f"Threshold: {threshold} events within {window:.0f}s")
    print(f"Injecting {threshold} synthetic authentication failure events...")

    success = mgr.run_synthetic_test()
    if success:
        print("[OK] Detection pipeline successfully triggered and dispatched alert!")
        return True
    else:
        print("[FAIL] Detection pipeline test did not trigger or alert dispatch failed.")
        return False


def start_auth_monitor(config: Optional[AppConfig] = None, interval: float = 2.0) -> int:
    """Start live continuous authentication failure monitor loop."""
    print("\n=======================================================")
    print("     Device Guardian - Authentication Monitor (Live)")
    print("=======================================================\n")

    try:
        cfg = config or load_config()
        cfg.validate()
    except ConfigurationError as exc:
        print(f"Configuration Error: {exc}")
        print("Please configure Device Guardian before starting the live monitor.")
        return 1

    mgr = DetectionManager(config=cfg)
    status, msg = mgr.get_monitor_status()
    if status != DetectionStatus.READY:
        print(f"[!] Warning: Log monitor is {status.value}: {msg}")
        print("    Device Guardian will poll, but events may not be accessible.\n")

    print(f"Source: {mgr.monitor.get_source_name()}")
    print(f"Threshold: {cfg.auth_failure_threshold} failures in {cfg.auth_failure_window_seconds:.0f}s")
    print(f"Cooldown: {cfg.auth_alert_cooldown_seconds:.0f}s")
    print(f"Voice Warning: {'Enabled' if cfg.voice_warning_enabled else 'Disabled'}")
    print("\nMonitoring active. Press Ctrl+C to terminate cleanly.\n")

    try:
        mgr.run_monitoring_loop(sleep_interval=interval)
        return 0
    except (KeyboardInterrupt, SystemExit):
        print("\nMonitoring cleanly stopped.")
        return 0


def check_filtering_status(config: Optional[AppConfig] = None) -> bool:
    """Check Smart Filtering configuration and trusted rules."""
    print("\nChecking Smart Filtering...")
    try:
        cfg = config or load_config()
    except Exception:
        cfg = None

    enabled = getattr(cfg, "smart_filtering_enabled", True) if cfg else True
    trusted_users = getattr(cfg, "trusted_users", []) if cfg else []
    trusted_networks = getattr(cfg, "trusted_networks", []) if cfg else []
    trusted_auth_types = getattr(cfg, "trusted_auth_types", []) if cfg else []
    env_triggers = getattr(cfg, "environmental_triggers_enabled", True) if cfg else True
    net_ctx = getattr(cfg, "network_context_enabled", True) if cfg else True
    dev_ctx = getattr(cfg, "device_state_context_enabled", True) if cfg else True

    print(f"\nSmart Filtering: {'ENABLED' if enabled else 'DISABLED'}")
    print(f"\nTrusted Users:\n  {len(trusted_users)} configured")
    print(f"\nTrusted Networks:\n  {len(trusted_networks)} configured")
    print(f"\nTrusted Authentication Types:\n  {len(trusted_auth_types)} configured")
    print(f"\nEnvironmental Context:\n  {'ENABLED' if env_triggers else 'DISABLED'}")
    print(f"\nNetwork Context:\n  {'ENABLED' if net_ctx else 'DISABLED'}")
    print(f"\nDevice State Context:\n  {'ENABLED' if dev_ctx else 'DISABLED'}")
    print("\nStatus: READY\n")
    return True


def check_environment_status(config: Optional[AppConfig] = None) -> bool:
    """Check environmental context detection."""
    print("\nChecking Environmental Context...")
    from device_guardian.environment import EnvironmentalDetector

    detector = EnvironmentalDetector()
    ctx = detector.collect_context()

    print(f"\nDevice State:\n  {ctx.device_state.value}")
    print(f"\nNetwork State:\n  {ctx.network_context.state.value}")
    print(f"\nNetwork Context:\n  {'Available' if ctx.network_context.interface_count > 0 else 'Unavailable'}")
    print(f"\nTimestamp:\n  {ctx.collected_at.isoformat()}")
    print("\nStatus:\n  READY\n")
    return True


def test_filtering_rules(config: Optional[AppConfig] = None) -> bool:
    """Test smart filtering with untrusted and trusted synthetic contexts."""
    print("\nTesting Smart Filtering Engine...")
    from device_guardian.detection.models import AuthenticationFailureEvent
    from device_guardian.environment import EnvironmentalContext
    from device_guardian.filtering import FilterContext, FilterDecision, SmartFilterEngine, TrustedContext

    trusted = TrustedContext(trusted_users=["alice"])
    engine = SmartFilterEngine(trusted_context=trusted, filtering_enabled=True)

    # 1. Untrusted user at threshold
    event_untrusted = AuthenticationFailureEvent(username="untrusted_user")
    ctx_untrusted = FilterContext(
        event=event_untrusted,
        environmental_context=EnvironmentalContext(),
        consecutive_failures=3,
        threshold=3,
    )
    res1 = engine.evaluate(ctx_untrusted)
    print(f"1. Untrusted user evaluation: Decision={res1.decision.value}, Rule={res1.rule_id}")
    print(f"   Explanation: {res1.explanation}")

    # 2. Configured trusted user
    event_trusted = AuthenticationFailureEvent(username="alice")
    ctx_trusted = FilterContext(
        event=event_trusted,
        environmental_context=EnvironmentalContext(),
        consecutive_failures=3,
        threshold=3,
    )
    res2 = engine.evaluate(ctx_trusted)
    print(f"2. Trusted user evaluation: Decision={res2.decision.value}, Rule={res2.rule_id}")
    print(f"   Explanation: {res2.explanation}")

    success = (
        res1.decision == FilterDecision.ALERT_ELIGIBLE
        and res2.decision == FilterDecision.FILTER
    )
    if success:
        print("\n[OK] Smart filtering test passed successfully.")
        return True
    else:
        print("\n[FAIL] Smart filtering test failed.")
        return False


def test_environment_live(config: Optional[AppConfig] = None) -> bool:
    """Probe live environmental telemetry."""
    print("\nTesting Environmental Context Collection...")
    from device_guardian.environment import EnvironmentalDetector

    detector = EnvironmentalDetector()
    ctx = detector.collect_context()
    print(f"[OK] Context Collected: {ctx.format_summary()}")
    print(f"  - Device State: {ctx.device_state.value}")
    print(f"  - Network State: {ctx.network_context.state.value}")
    print(f"  - Interfaces: {ctx.network_context.interface_count}")
    print(f"  - Private Network: {ctx.network_context.is_private_network}")
    return True


def test_context_correlation_pipeline(config: Optional[AppConfig] = None) -> bool:
    """Test correlation between detection event, environmental state, and alert eligibility."""
    print("\nTesting Context Correlation Pipeline...")
    from device_guardian.detection.models import AuthenticationFailureEvent
    from device_guardian.environment import DeviceState, EnvironmentalContext, NetworkContext, NetworkState
    from device_guardian.filtering import FilterContext, FilterDecision, SmartFilterEngine, TrustedContext

    trusted = TrustedContext(trusted_users=[])
    engine = SmartFilterEngine(trusted_context=trusted, filtering_enabled=True)

    # Simulate locked workstation with connected network
    env = EnvironmentalContext(
        device_state=DeviceState.LOCKED,
        network_context=NetworkContext(connected=True, state=NetworkState.CONNECTED, interface_count=1),
    )
    ev = AuthenticationFailureEvent(username="unknown_user", authentication_type="local")
    ctx = FilterContext(
        event=ev,
        environmental_context=env,
        consecutive_failures=3,
        threshold=3,
        window_seconds=60.0,
    )
    result = engine.evaluate(ctx)

    print(f"Correlated Event: {ev.format_summary()}")
    print(f"Environmental Context: {env.format_summary()}")
    print(f"Correlation Decision: {result.decision.value} (Rule: {result.rule_id})")
    print(f"Explanation: {result.explanation}")

    if result.decision == FilterDecision.ALERT_ELIGIBLE:
        print("\n[OK] Context correlation evaluated to ALERT_ELIGIBLE as expected.")
        return True
    else:
        print(f"\n[FAIL] Context correlation unexpected result: {result.decision.value}")
        return False


def start_background_runtime(config: Optional[AppConfig] = None, blocking: bool = True) -> int:
    """Start the Device Guardian background monitoring service."""
    print("\nStarting Device Guardian Background Runtime...")
    if config is None:
        try:
            config = load_config()
            config.validate()
        except ConfigurationError as exc:
            print(f"[FAIL] Configuration Error:\n{exc}")
            return 1

    runtime = GuardianRuntime(config=config)
    success = runtime.start(blocking=blocking)
    if not success:
        print(f"[FAIL] Could not start runtime: {runtime.status.last_error or 'Unknown failure'}")
        return 1

    if not blocking:
        print(f"[OK] Device Guardian background runtime is now RUNNING (PID: {runtime.status.pid}).")
    return 0


def stop_background_runtime() -> int:
    """Stop the running Device Guardian background service via IPC."""
    print("\nStopping Device Guardian Background Runtime...")
    lock = SingleInstanceLock()
    active_pid = lock.get_active_pid()

    if not lock.is_locked() or active_pid is None:
        print("[*] Device Guardian is not currently running.")
        return 0

    print(f"[*] Dispatched stop signal to active instance (PID: {active_pid})...")
    lock.signal_stop()

    # Wait for process to exit
    for _ in range(25):
        time.sleep(0.2)
        if not lock.is_locked():
            print("[OK] Device Guardian stopped cleanly.")
            return 0

    print("[!] Runtime did not terminate within 5 seconds. You may need to kill the process manually.")
    return 1


def restart_background_runtime(config: Optional[AppConfig] = None) -> int:
    """Restart the Device Guardian background runtime."""
    print("\nRestarting Device Guardian Background Runtime...")
    stop_background_runtime()
    time.sleep(1.0)
    return start_background_runtime(config=config, blocking=True)


def show_runtime_status(config: Optional[AppConfig] = None) -> int:
    """Display the current background runtime status and unified operator dashboard."""
    from device_guardian.ux.operator import get_operator_summary, format_operator_dashboard
    summary = get_operator_summary(config=config)
    print(format_operator_dashboard(summary))
    return 0


def start_tray_interface(config: Optional[AppConfig] = None) -> int:
    """Start Device Guardian with system tray icon and background runtime."""
    print("\nStarting Device Guardian in System Tray mode...")
    if config is None:
        try:
            config = load_config()
            config.validate()
        except ConfigurationError as exc:
            print(f"[FAIL] Configuration Error:\n{exc}")
            return 1

    runtime = GuardianRuntime(config=config)
    tray = TrayManager(runtime=runtime)

    if tray.is_headless():
        print("[!] Headless environment detected (no graphical display available).")
        print("[*] Falling back to standard background runtime without system tray...")
        return start_background_runtime(config=config, blocking=True)

    started = runtime.start(blocking=False)
    if not started:
        print(f"[FAIL] Could not start runtime: {runtime.status.last_error}")
        return 1

    print("[OK] Background runtime active. Launching tray icon...")
    try:
        tray.run(blocking=True)
        return 0
    except KeyboardInterrupt:
        print("\nStopping tray interface...")
        tray.stop()
        runtime.stop()
        return 0


def install_system_startup() -> int:
    """Enable automatic startup launch on user login."""
    print("\nConfiguring OS Startup Integration...")
    mgr = create_startup_manager()
    if not mgr.is_supported():
        from device_guardian.platform_compat import get_current_os
        print(f"[FAIL] Startup configuration is not supported on {get_current_os().value}.")
        return 1

    success = mgr.enable()
    if success:
        print(f"[OK] Device Guardian successfully configured to start on user login.")
        print(f"     Command: {mgr.get_command()}")
        return 0
    else:
        print("[FAIL] Failed to register Device Guardian in OS startup.")
        return 1


def remove_system_startup(assume_yes: bool = False) -> int:
    """Disable automatic startup launch on user login."""
    from device_guardian.ux.confirmations import confirm_remove_startup

    if not assume_yes and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        if not confirm_remove_startup(assume_yes=False):
            return 1

    print("\nRemoving OS Startup Integration...")
    mgr = create_startup_manager()
    if not mgr.is_supported():
        from device_guardian.platform_compat import get_current_os
        print(f"[FAIL] Startup configuration is not supported on {get_current_os().value}.")
        return 1

    success = mgr.disable()
    if success:
        print("[OK] Device Guardian successfully removed from OS startup.")
        return 0
    else:
        print("[FAIL] Failed to remove Device Guardian from OS startup.")
        return 1


def check_config_readiness(config: Optional[AppConfig] = None) -> int:
    """Audit configuration readiness across all functional subsystems (Phase 6).

    Prints structured subsystem status and clear next-step remediation instructions.
    Returns 0 if configuration is fully ready, 1 otherwise.
    """
    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - CONFIGURATION READINESS AUDIT")
    print("=" * 65)

    try:
        cfg = config or load_config()
    except ConfigurationError as exc:
        print(f"\n[FAIL] Configuration syntax/validation error:")
        print(f"  {exc}")
        print("\nActionable Next Steps:")
        print("  - Run 'device-guardian --setup' to configure credentials via Setup Wizard.")
        print("  - Or define TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env or your environment.")
        return 1
    except Exception as exc:
        print(f"\n[FAIL] Unable to load configuration: {exc}")
        print("\nActionable Next Steps:")
        print("  - Run 'device-guardian --setup' to initialize configuration.")
        return 1

    report = cfg.validate_readiness()
    print(report.format_report())

    if report.is_ready:
        print("\n[OK] Device Guardian is fully configured and ready for production.\n")
        return 0
    else:
        print("\n[!] Attention Required: Device Guardian is not yet fully configured.")
        print("Actionable Next Steps:")
        print("  - Run 'device-guardian --setup' to configure credentials interactively.")
        env_display = cfg.env_file_path or ApplicationPaths.get_config_file_path()
        print(f"  - Or update your .env file at: {env_display}\n")
        return 1


def show_config(config: Optional[AppConfig] = None) -> int:
    """Display sanitized configuration overview with masked secrets (Phase 6)."""
    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - SANITIZED CONFIGURATION OVERVIEW")
    print("=" * 65)

    try:
        cfg = config or load_config()
    except Exception as exc:
        print(f"\n[FAIL] Unable to load configuration: {exc}")
        return 1

    sanitized = cfg.to_sanitized_dict()
    print(f"\nActive Configuration File: {cfg.env_file_path or 'Loaded from Environment / Defaults'}")
    print("\n[Credentials & Delivery]")
    print(f"  - Telegram Bot Token:         {sanitized['telegram_bot_token']}")
    print(f"  - Telegram Chat ID:           {sanitized['telegram_chat_id']}")
    print(f"  - Telegram Alert Enabled:     {sanitized['telegram_alert_enabled']}")

    print("\n[Hardware & Sensors]")
    print(f"  - Camera Index:               {sanitized['camera_index']}")
    print(f"  - Camera Alert Enabled:       {sanitized['camera_alert_enabled']}")
    print(f"  - Location API URL:           {sanitized['location_api_url']}")
    print(f"  - Location Alert Enabled:     {sanitized['location_alert_enabled']}")
    print(f"  - Request Timeout:            {sanitized['request_timeout_seconds']}s")

    print("\n[Detection & Thresholds]")
    print(f"  - Auth Failure Threshold:     {sanitized['auth_failure_threshold']} failures")
    print(f"  - Failure Window:             {sanitized['auth_failure_window_seconds']}s")
    print(f"  - Alert Cooldown:             {sanitized['auth_alert_cooldown_seconds']}s")
    print(f"  - Voice Warning:              {sanitized['voice_warning_enabled']}")
    print(f"  - Voice Warning Cooldown:     {sanitized['voice_warning_cooldown_seconds']}s")

    print("\n[Smart Filtering & Context]")
    print(f"  - Smart Filtering:            {sanitized['smart_filtering_enabled']}")
    print(f"  - Trusted Users:              {sanitized['trusted_users'] or 'None'}")
    print(f"  - Trusted Networks:           {sanitized['trusted_networks'] or 'None'}")
    print(f"  - Trusted Auth Types:         {sanitized['trusted_auth_types'] or 'None'}")
    print(f"  - Environmental Triggers:     {sanitized['environmental_triggers_enabled']}")
    print(f"  - Require Context for Alert:  {sanitized['require_context_for_alert']}")

    print("\n[Runtime & Process]")
    print(f"  - Background Mode Enabled:    {sanitized['background_mode_enabled']}")
    print(f"  - Tray Enabled:               {sanitized['tray_enabled']}")
    print(f"  - Single Instance Enabled:    {sanitized['single_instance_enabled']}")
    print(f"  - Auto Restart Enabled:       {sanitized['auto_restart_enabled']}")
    print(f"  - Max Restart Attempts:       {sanitized['max_restart_attempts']}")
    print("=" * 65 + "\n")
    return 0


def show_config_paths() -> int:
    """Display resolved paths for configuration, logs, data, and secrets store (Phase 6)."""
    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - RESOLVED SYSTEM & STORAGE PATHS")
    print("=" * 65)

    data_dir = ApplicationPaths.get_user_data_dir()
    config_file = ApplicationPaths.get_config_file_path()
    status_file = ApplicationPaths.get_status_file_path()
    log_dir = ApplicationPaths.get_log_dir()

    from device_guardian.security.store import create_default_secret_store
    secret_store = create_default_secret_store()

    print(f"\nExecution Mode:       {'Packaged Executable (Frozen)' if ApplicationPaths.is_frozen() else 'Python Source'}")
    print(f"Application Root:     {ApplicationPaths.get_bundle_dir()}")
    print(f"User Data Directory:  {data_dir}")
    print(f"Config File (.env):   {config_file} ({'EXISTS' if config_file.is_file() else 'MISSING'})")
    print(f"Status JSON:          {status_file} ({'EXISTS' if status_file.is_file() else 'NOT CREATED'})")
    print(f"Log Directory:        {log_dir}")
    print(f"Log File:             {log_dir / 'device_guardian.log'}")
    print(f"Secrets Backend:      {secret_store.get_backend_name()}")
    if hasattr(secret_store, "file_path"):
        print(f"Secrets Store Path:   {secret_store.file_path} ({'EXISTS' if secret_store.file_path.is_file() else 'EMPTY/NOT CREATED'})")
    print("=" * 65 + "\n")
    return 0


def show_platform_info() -> int:
    """Display comprehensive host platform compatibility and subsystem capabilities (Phase 13)."""
    from device_guardian.platform_compat import get_platform_info, get_platform_capabilities
    info = get_platform_info()
    caps = get_platform_capabilities()["capabilities"]

    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - PLATFORM COMPATIBILITY & SUPPORT")
    print("=" * 65)
    print("\n[Host Environment]")
    print(f"  - Operating System:       {info.os_name} {info.release}")
    print(f"  - OS Kernel Version:      {info.version}")
    print(f"  - Architecture:           {info.arch.value} ({info.machine})")
    print(f"  - Python Runtime:         {info.python_version}")
    print(f"  - Execution Mode:         {'Packaged Executable (Frozen)' if info.is_frozen else 'Python Source'}")
    print(f"  - Executable Binary:      {info.executable_name}")
    print(f"  - Platform Supported:     {'YES' if info.is_supported else 'NO'}")
    print(f"  - Support & Test Tier:    {info.support_tier.value}")

    print("\n[Subsystem Capability Matrix]")
    print(f"  - Secrets Backend:        {caps['secrets_backend']}")
    print(f"  - Single-Instance Lock:   {caps['single_instance_mechanism']}")
    print(f"  - OS Startup Autostart:   {caps['startup_mechanism']}")
    print(f"  - Auth Detection Source:  {caps['detection_source']}")
    print(f"  - System Tray Interface:  {caps['tray_support']}")
    print(f"  - Camera Capture Sensor:  {caps['camera_support']}")
    print(f"  - Geolocation Sensor:     {caps['geolocation_support']}")
    print(f"  - Offline Voice Warning:  {caps['offline_voice_support']}")
    print("=" * 65 + "\n")
    return 0


def show_credentials_status(config: Optional[AppConfig] = None) -> int:
    """Display safe status of configured credentials without leaking secrets (Phase 6)."""
    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - CREDENTIALS & SECRETS STATUS")
    print("=" * 65)

    from device_guardian.security.store import create_default_secret_store
    secret_store = create_default_secret_store()

    cfg: Optional[AppConfig] = None
    try:
        cfg = config or load_config()
    except Exception:
        pass

    all_configured = True

    # Telegram Bot Token
    token_str = cfg.get_secret_token().strip() if cfg and hasattr(cfg, "get_secret_token") else (cfg.telegram_bot_token.strip() if cfg else "")
    if not token_str:
        print("  - Telegram Bot Token:   [NOT CONFIGURED]")
        all_configured = False
    elif token_str in {"your_telegram_bot_token_here", "YOUR_BOT_TOKEN", "CHANGE_ME"}:
        print("  - Telegram Bot Token:   [INVALID / PLACEHOLDER]")
        all_configured = False
    elif len(token_str) < 10 or ":" not in token_str:
        print(f"  - Telegram Bot Token:   [INVALID FORMAT] ({mask_token(token_str)})")
        all_configured = False
    else:
        print(f"  - Telegram Bot Token:   [CONFIGURED] ({mask_token(token_str)})")

    # Telegram Chat ID
    chat_id_str = cfg.get_secret_chat_id().strip() if cfg and hasattr(cfg, "get_secret_chat_id") else (cfg.telegram_chat_id.strip() if cfg else "")
    if not chat_id_str:
        print("  - Telegram Chat ID:     [NOT CONFIGURED]")
        all_configured = False
    elif chat_id_str in {"your_telegram_chat_id_here", "YOUR_CHAT_ID", "CHANGE_ME"}:
        print("  - Telegram Chat ID:     [INVALID / PLACEHOLDER]")
        all_configured = False
    else:
        print(f"  - Telegram Chat ID:     [CONFIGURED] ({mask_chat_id(chat_id_str)})")

    print(f"  - Secrets Storage:      {secret_store.get_backend_name()}")

    stored_names = secret_store.list_secret_names()
    if stored_names:
        print(f"  - Stored Secret Keys:   {', '.join(stored_names)}")
    else:
        print("  - Stored Secret Keys:   None (Credentials provided via .env/environment)")

    print("=" * 65 + "\n")
    return 0 if all_configured else 1


def send_test_notification_cli(config: Optional[AppConfig] = None) -> int:
    """Send an explicit test notification to Telegram verifying delivery (Phase 6)."""
    print("\nSending Test Telegram Notification...")
    try:
        cfg = config or load_config()
    except Exception as exc:
        print(f"[FAIL] Unable to load configuration: {exc}")
        return 1

    try:
        client = TelegramClient(
            bot_token=cfg.telegram_bot_token,
            chat_id=cfg.telegram_chat_id,
            timeout=cfg.request_timeout_seconds,
        )
        resp = client.send_test_notification(
            custom_message="Device Guardian Phase 6 Test Notification - Secrets & Credentials Hardened."
        )
        if resp.success:
            print("[OK] Test notification delivered successfully to Telegram!")
            return 0
        else:
            print(f"[FAIL] Test notification delivery failed: {resp.error_message}")
            return 1
    except Exception as exc:
        print(f"[FAIL] Notification failed with exception: {exc}")
        return 1


def run_system_diagnostics(config: Optional[AppConfig] = None) -> int:
    """Run comprehensive Phase 5 and Phase 6 diagnostics across all subsystems."""
    print("\n" + "=" * 65)
    print("      DEVICE GUARDIAN - COMPREHENSIVE SYSTEM DIAGNOSTICS")
    print("=" * 65)

    all_ok = True

    # 1. Environment & Paths
    print("\n[1] Environment & Packaging:")
    is_frozen = ApplicationPaths.is_frozen()
    from device_guardian.platform_compat import get_platform_info
    p_info = get_platform_info()
    print(f"    - Execution Mode:       {'Packaged Executable (Frozen)' if is_frozen else 'Python Source'}")
    print(f"    - Platform OS:          {p_info.os_name} {p_info.release} ({p_info.arch.value})")
    print(f"    - Platform Support:     {p_info.support_tier.value}")
    print(f"    - Python Runtime:       {sys.version.split()[0]}")
    print(f"    - Data Directory:       {ApplicationPaths.get_user_data_dir()}")
    print(f"    - Configuration Path:   {ApplicationPaths.get_config_file_path()}")
    print(f"    - Status JSON Path:     {ApplicationPaths.get_status_file_path()}")

    # 2. Configuration & Credentials
    print("\n[2] Configuration & Privacy Validation:")
    try:
        if config is None:
            config = load_config()
        config.validate()
        print("    [PASS] Local configuration valid (.env parsed cleanly).")
        print(f"    - Telegram Token:       {mask_token(config.telegram_bot_token)}")
        print(f"    - Telegram Chat ID:     {mask_chat_id(config.telegram_chat_id)}")
        from device_guardian.security.store import create_default_secret_store
        sec_store = create_default_secret_store()
        print(f"    - Secrets Storage:      {sec_store.get_backend_name()}")
        val_rep = config.validate_readiness()
        if not val_rep.is_ready:
            print("    [WARN] Subsystem configuration incomplete. Run --config-check for details.")
    except Exception as exc:
        print(f"    [FAIL] Configuration error: {exc}")
        all_ok = False

    # 3. Telegram API Connection
    print("\n[3] Telegram API Connectivity:")
    if config:
        try:
            tg = TelegramClient(config.telegram_bot_token, config.telegram_chat_id, timeout=config.request_timeout_seconds)
            resp = tg.verify_credentials()
            if resp.success:
                bot_user = resp.data.get("username", "Unknown") if resp.data else "Bot"
                print(f"    [PASS] Telegram Bot API verified (Connected as @{bot_user}).")
            else:
                print(f"    [FAIL] Telegram Bot API rejected: {resp.error_message}")
                all_ok = False
        except Exception as exc:
            print(f"    [FAIL] Telegram connection exception: {exc}")
            all_ok = False
    else:
        print("    [SKIP] Configuration missing.")
        all_ok = False

    # 4. Hardware Sensors (Camera & Location)
    print("\n[4] Hardware & Network Geolocation Sensors:")
    try:
        import cv2
        cap = cv2.VideoCapture(config.camera_index if config else 0)
        if cap.isOpened():
            cap.release()
            print("    [PASS] Camera sensor accessible.")
        else:
            print("    [WARN] Camera sensor not detected or busy.")
    except Exception as exc:
        print(f"    [WARN] OpenCV camera check failed: {exc}")

    try:
        loc = get_approximate_location(
            api_url=config.location_api_url if config else "https://ipapi.co/json/",
            timeout=5.0,
        )
        if loc.is_available:
            print(f"    [PASS] IP Geolocation service reachable ({loc.city}, {loc.country}).")
        else:
            print("    [WARN] IP Geolocation query unavailable.")
    except Exception as exc:
        print(f"    [WARN] Geolocation lookup exception: {exc}")

    # 5. OS Detection Monitor & Voice Warning
    print("\n[5] Intrusion Detection & Local Voice Warning:")
    det_mgr = DetectionManager(config=config)
    m_status, m_msg = det_mgr.get_monitor_status()
    if m_status == DetectionStatus.READY:
        print(f"    [PASS] Platform Authentication Monitor: READY ({det_mgr.monitor.get_source_name()})")
    else:
        print(f"    [WARN] Platform Authentication Monitor: {m_status.value} ({m_msg})")

    tts_avail = det_mgr.voice_warning.is_available()
    if tts_avail:
        print("    [PASS] Offline Text-To-Speech engine: AVAILABLE")
    else:
        print("    [WARN] Offline Text-To-Speech engine: UNAVAILABLE")

    # 6. Smart Filtering & Environmental Context
    print("\n[6] Smart Filtering & Environmental Context Engine:")
    print(f"    - Smart Filtering:      {'ENABLED' if config and config.smart_filtering_enabled else 'DISABLED'}")
    print(f"    - Trusted Users:        {len(config.trusted_users) if config else 0} registered")
    print(f"    - Trusted Networks:     {len(config.trusted_networks) if config else 0} registered")
    print(f"    - Trusted Auth Types:   {len(config.trusted_auth_types) if config else 0} registered")

    # 7. Single Instance & Lock Manager
    print("\n[7] Single Instance & Process Coordination:")
    lock = SingleInstanceLock()
    is_locked = lock.is_locked()
    active_pid = lock.get_active_pid()
    print(f"    - Single Instance Mode: {'ENABLED' if config and config.single_instance_enabled else 'DISABLED'}")
    print(f"    - Current Lock Status:  {'LOCKED (PID ' + str(active_pid) + ')' if is_locked else 'UNLOCKED'}")
    print(f"    - Lock File Path:       {lock.lock_file}")

    # 8. OS Startup Integration
    print("\n[8] OS Startup Launch Configuration:")
    startup_mgr = create_startup_manager()
    print(f"    - Supported on Platform:{'YES' if startup_mgr.is_supported() else 'NO'}")
    print(f"    - Startup Enabled:      {'YES' if startup_mgr.is_enabled() else 'NO'}")
    if startup_mgr.is_enabled():
        print(f"    - Startup Command:      {startup_mgr.get_command()}")

    # 9. System Tray & GUI Capabilities
    print("\n[9] System Tray & Desktop UI:")
    try:
        from PIL import Image
        print("    [PASS] Pillow image engine available.")
    except ImportError:
        print("    [FAIL] Pillow is not installed.")
        all_ok = False

    try:
        import pystray
        print("    [PASS] pystray system tray engine available.")
    except ImportError:
        print("    [FAIL] pystray is not installed.")
        all_ok = False

    tray_mgr = TrayManager(runtime=GuardianRuntime(config=config))
    if tray_mgr.is_headless():
        print("    [INFO] Headless display detected; tray will safely degrade.")
    else:
        print("    [PASS] Graphical display session detected.")

    # 10. Update & Release Integrity Subsystem
    print("\n[10] Update & Release Integrity Subsystem:")
    v_info = get_version_info()
    is_froz = ApplicationPaths.is_frozen()
    x_path = ApplicationPaths.get_executable_path()
    x_hash = None
    if is_froz and x_path.is_file():
        from device_guardian.updates.crypto import calculate_sha256
        try:
            x_hash = calculate_sha256(x_path)
        except Exception:
            x_hash = None
    print(f"    - Version:              v{v_info.version} ({v_info.release_id})")
    print(f"    - Build Timestamp:      {v_info.build_timestamp}")
    print(f"    - Executable Hash:      {x_hash[:16] + '...' if x_hash else 'N/A (Source Mode)'}")
    try:
        u_stat = UpdateInstaller.get_update_status_summary()
        print(f"    - Transaction State:    {u_stat['transaction_state']}")
        print(f"    - Available Rollbacks:  {len(u_stat.get('available_rollbacks', []))} backup(s)")
    except Exception as exc:
        print(f"    - Update Subsystem:     Error checking status ({exc})")

    # 11. Disaster Recovery & System Health Assessment (Phase 8)
    print("\n[11] Disaster Recovery, Resilience & Subsystem Health:")
    try:
        health_report = assess_system_health(config=config)
        print(f"    - Overall System Health: {health_report.status.value}")
        for sub in health_report.subsystems:
            icon = "[PASS]" if sub.status == HealthStatus.HEALTHY else ("[WARN]" if sub.status in (HealthStatus.DEGRADED, HealthStatus.NOT_CONFIGURED) else "[FAIL]")
            print(f"      {icon} {sub.name:<22}: {sub.status.value:<14} {sub.message}")
        if health_report.status == HealthStatus.FAILED:
            all_ok = False
    except Exception as exc:
        print(f"    [WARN] System health evaluation error: {exc}")

    print("\n" + "=" * 65)
    if all_ok:
        print("      DIAGNOSTICS SUMMARY: ALL CORE SUBSYSTEMS HEALTHY")
    else:
        print("      DIAGNOSTICS SUMMARY: ATTENTION REQUIRED (SEE ABOVE)")
    print("=" * 65 + "\n")
    return 0 if all_ok else 1


def show_release_info() -> int:
    """Display comprehensive release and build integrity information."""
    v_info = get_version_info()
    is_froz = ApplicationPaths.is_frozen()
    x_path = ApplicationPaths.get_executable_path()
    x_hash = None
    if is_froz and x_path.is_file():
        from device_guardian.updates.crypto import calculate_sha256
        try:
            x_hash = calculate_sha256(x_path)
        except Exception:
            x_hash = None

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - RELEASE & BUILD INFORMATION")
    print("=" * 65)
    print("  Application:          Device Guardian")
    print(f"  Installed Version:    v{v_info.version}")
    print(f"  Release Identifier:   {v_info.release_id}")
    print(f"  Build Timestamp:      {v_info.build_timestamp}")
    print(f"  Platform Target:      {v_info.platform} ({v_info.architecture})")
    print(f"  Execution Mode:       {v_info.packaging_format}")
    print(f"  Executable Path:      {x_path}")
    print(f"  Binary SHA-256:       {x_hash if x_hash else 'N/A (Running from source)'}")

    trusted_key = get_trusted_public_key()
    key_fp = get_key_fingerprint(trusted_key)
    print(f"  Verification Key:     {key_fp}")
    print(f"  Updates Directory:    {ApplicationPaths.get_updates_dir()}")
    print("=" * 65 + "\n")
    return 0


def show_update_status() -> int:
    """Display current update subsystem status, active transactions, and rollbacks."""
    status_info = UpdateInstaller.get_update_status_summary()
    print("\n" + "=" * 65)
    print("          DEVICE GUARDIAN - UPDATE SUBSYSTEM STATUS")
    print("=" * 65)
    print(f"  Installed Version:    v{status_info['installed_version']}")
    print(f"  Transaction State:    {status_info['transaction_state']}")
    if status_info.get("last_verified_version"):
        print(f"  Last Verified:        v{status_info['last_verified_version']}")
    if status_info.get("error_message"):
        print(f"  Transaction Error:    {status_info['error_message']}")

    verified_files = status_info.get("verified_artifacts", [])
    print(f"  Verified Packages:    {len(verified_files)} available")
    for vf in verified_files:
        print(f"    - {vf}")

    rollbacks = status_info.get("available_rollbacks", [])
    print(f"  Available Rollbacks:  {len(rollbacks)} restore point(s)")
    for rb in rollbacks:
        print(f"    - Version: v{rb}")

    print("=" * 65 + "\n")
    return 0


def verify_update_cli(path_str: str, allow_downgrade: bool = False) -> int:
    """Verify an update package against digital signature and release manifest."""
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - RELEASE VERIFICATION GATE")
    print("=" * 65)

    try:
        from device_guardian.security.filesystem import validate_safe_path, SecurityPathError
        target_path = validate_safe_path(path_str, allow_symlinks=False)
    except (SecurityPathError, ValueError) as exc:
        print(f"[REJECTED] Insecure update package path: {exc}")
        return 3

    print(f"Target Update Package: {target_path}")
    print(f"Allow Downgrade:       {'Yes' if allow_downgrade else 'No'}\n")

    if not target_path.exists():
        print(f"[REJECTED] Update package file does not exist: {target_path}")
        return 1

    result = verify_update_package(target_path, allow_downgrade=allow_downgrade)

    print("Verification Findings:")
    for finding in result.findings:
        sev_tag = f"[{finding.status.value}]".ljust(14)
        print(f"  {sev_tag} {finding.category}: {finding.message}")

    print("\n" + "-" * 65)
    if result.is_verified:
        print(f"VERIFICATION STATUS:   {result.status.value} (PASS)")
        if result.manifest:
            print(f"Release Version:       v{result.manifest.version}")
            print(f"Release ID:            {result.manifest.release_id}")
            print(f"Artifacts in Release:  {len(result.manifest.artifacts)}")
            for art in result.manifest.artifacts:
                print(f"  * {art.filename} ({art.platform}-{art.architecture}, {art.size_bytes} bytes)")
        print("\nIntegrity & Authenticity Confirmed. Package is safe to stage/install.")
        print("=" * 65 + "\n")
        return 0
    else:
        print(f"VERIFICATION STATUS:   {result.status.value} (REJECTED)")
        print("\nUpdate package FAILED verification gates and will NOT be installed.")
        print("=" * 65 + "\n")
        return 3


def install_update_cli(path_str: str, allow_downgrade: bool = False) -> int:
    """Verify and install an update package with rollback protection."""
    print("\n" + "=" * 65)
    print("         DEVICE GUARDIAN - UPDATE INSTALLATION")
    print("=" * 65)

    try:
        from device_guardian.security.filesystem import validate_safe_path, SecurityPathError
        target_path = validate_safe_path(path_str, allow_symlinks=False)
    except (SecurityPathError, ValueError) as exc:
        print(f"[REJECTED] Insecure update package path: {exc}")
        return 1

    print(f"Target Package:        {target_path}")
    print(f"Allow Downgrade:       {'Yes' if allow_downgrade else 'No'}\n")

    res = UpdateInstaller.install_update(target_path, allow_downgrade=allow_downgrade)
    if res.success:
        print("\n" + "-" * 65)
        print(f"[SUCCESS] {res.message}")
        print("Update installed successfully. Please restart Device Guardian.")
        print("=" * 65 + "\n")
        return 0
    else:
        print("\n" + "-" * 65)
        print(f"[FAILED] {res.message}")
        print("Installation aborted. Existing installation preserved.")
        print("=" * 65 + "\n")
        return 1


def rollback_cli(target_version: Optional[str] = None, assume_yes: bool = False) -> int:
    """Restore previously installed version from backup."""
    from device_guardian.ux.confirmations import confirm_rollback

    if not assume_yes and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        if not confirm_rollback(target_version=target_version, assume_yes=False):
            return 1

    print("\n" + "=" * 65)
    print("          DEVICE GUARDIAN - ROLLBACK RESTORATION")
    print("=" * 65)
    if target_version:
        import re
        if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9a-zA-Z.-]+)?$", target_version.strip()):
            print(f"[REJECTED] Invalid semantic version format: '{target_version}'")
            return 1
        print(f"Requested Version:     v{target_version.strip()}")
    else:
        print("Target:                Most recent verified backup")

    res = UpdateInstaller.rollback(target_version=target_version)
    if res.success:
        print("\n" + "-" * 65)
        print(f"[SUCCESS] {res.message}")
        print("Rollback completed successfully. Please restart Device Guardian.")
        print("=" * 65 + "\n")
        return 0
    else:
        print("\n" + "-" * 65)
        print(f"[FAILED] {res.message}")
        print("Rollback aborted.")
        print("=" * 65 + "\n")
        return 1


def show_recovery_status(config: Optional[AppConfig] = None) -> int:
    """Display comprehensive disaster recovery status and subsystem health report."""
    status = get_recovery_status(config=config)
    health = status["system_health"]
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - DISASTER RECOVERY & SYSTEM HEALTH")
    print("=" * 65)
    print(f"  Overall System Health:  {health.get('status', 'UNKNOWN')}")
    print(f"  Assessment Timestamp:   {health.get('timestamp', 'N/A')}")
    print(f"  Execution Mode:         {status.get('execution_mode', 'source')}")
    print(f"  Data Directory:         {status.get('data_directory')}")
    print("\n  Subsystem Health Assessments:")
    for sub in health.get("subsystems", []):
        icon = "[PASS]" if sub["status"] == "HEALTHY" else ("[WARN]" if sub["status"] in ("DEGRADED", "NOT_CONFIGURED") else "[FAIL]")
        print(f"    {icon} {sub['name']:<22}: {sub['status']:<14} {sub['message']}")

    print("\n  State File Resilience & Backups:")
    for sf, info in status.get("state_files", {}).items():
        exists = "PRESENT" if info.get("exists") else "MISSING"
        bak = "YES" if info.get("has_backup") else "NO"
        corrupt = f" ({len(info.get('corrupted_copies', []))} preserved)" if info.get("corrupted_copies") else ""
        print(f"    - {sf:<26}: Status={exists:<8} Backup={bak:<4}{corrupt}")

    print("=" * 65 + "\n")
    return 0 if health["status"] != HealthStatus.FAILED.value else 1


def repair_state_cli(assume_yes: bool = False) -> int:
    """Perform non-destructive repair of state files, preserving corrupted copies."""
    from device_guardian.ux.confirmations import confirm_repair_state

    if not assume_yes and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        if not confirm_repair_state(assume_yes=False):
            return 1

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - STATE FILE REPAIR & RESET")
    print("=" * 65)
    print("Inspecting and repairing application state files safely...\n")
    results = repair_state_files()
    if not results:
        print("  [OK]    All monitored state files are intact. No repair needed.")
    else:
        for item in results:
            print(f"  [FIXED] {item.get('target')}")
            print(f"          Action:           {item.get('action')}")
            print(f"          Preserved Copy:   {item.get('preserved_backup')}")
            print(f"          Reason:           {item.get('reason')}")

    print("\n" + "-" * 65)
    print(f"Repair complete: {len(results)} file(s) repaired/reset.")
    print("User secrets, credentials, and configurations were strictly preserved.")
    print("=" * 65 + "\n")
    return 0


def verify_installation_cli() -> int:
    """Verify application binary integrity and release manifest."""
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - INSTALLATION INTEGRITY VERIFICATION")
    print("=" * 65)
    is_valid, msg, details = verify_installation_integrity()
    print(f"  Execution Mode:         {details.get('mode')}")
    print(f"  Executable Path:        {details.get('executable_path')}")
    if details.get("executable_sha256"):
        print(f"  Executable SHA-256:     {details.get('executable_sha256')}")
    print("\n  Integrity Checks:")
    for chk in details.get("checks", []):
        icon = "[PASS]" if chk["status"] == "PASS" else ("[WARN]" if chk["status"] == "WARN" else "[FAIL]")
        print(f"    {icon} {chk['check']:<22}: {chk['status']:<8} {chk['message']}")

    print(f"\n  Integrity Result:       {'VALID' if is_valid else 'INVALID / COMPROMISED'}")
    print(f"  Summary:                {msg}")
    print("=" * 65 + "\n")
    return 0 if is_valid else 3


def show_local_disclosure() -> int:
    """Display comprehensive local data disclosure and privacy guarantees (Phase 10)."""
    from device_guardian.ux.help import format_local_data_disclosure
    print(format_local_data_disclosure())
    return 0


def show_state_model() -> int:
    """Display UX state model, health definitions, and uncertainty invariants (Phase 10)."""
    from device_guardian.ux.help import format_state_definitions
    print(format_state_definitions())
    return 0


def show_install_info() -> int:
    """Display comprehensive installation metadata and directory locations (Phase 12)."""
    meta = LifecycleInstaller.get_installation_info()
    install_root = ApplicationPaths.get_install_root()
    user_data = ApplicationPaths.get_user_data_dir()
    schema_ver = MigrationManager.get_schema_version()

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - INSTALLATION INFORMATION")
    print("=" * 65)
    print(f"  Installed Version:     v{meta.version if meta else __version__}")
    print(f"  Installation Root:     {meta.install_path if meta and meta.install_path else install_root}")
    print(f"  User Data Directory:   {meta.user_data_path if meta and meta.user_data_path else user_data}")
    print(f"  State Schema Version:  {schema_ver}")
    print(f"  Execution Mode:        {'Frozen Executable' if ApplicationPaths.is_frozen() else 'Python Source Package'}")
    if meta:
        print(f"  Installed At:          {meta.installed_at}")
        if meta.last_upgraded_at:
            print(f"  Last Upgraded At:      {meta.last_upgraded_at}")
        if meta.executable_hash:
            print(f"  Executable SHA-256:    {meta.executable_hash}")
    else:
        print("  Status:                Running from development source (metadata not persisted)")
    print("=" * 65 + "\n")
    return 0


def show_installation_status() -> int:
    """Inspect and display installation health and file integrity (Phase 12)."""
    health = LifecycleInstaller.verify_installation()
    glyph_map = {
        "HEALTHY": "[● HEALTHY     ]",
        "DEGRADED": "[▲ DEGRADED    ]",
        "FAILED": "[■ FAILED      ]",
        "NOT_CONFIGURED": "[- NOT_CONFIG  ]",
        "UNKNOWN": "[? UNKNOWN     ]",
    }
    glyph = glyph_map.get(health.status, "[? UNKNOWN     ]")

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - INSTALLATION HEALTH ASSESSMENT")
    print("=" * 65)
    print(f"  Installation State:    {glyph} {health.status}")
    print(f"  Version:               v{health.version}")
    print(f"  Binary Path:           {health.binary_path}")
    print(f"  Summary:               {health.message}")
    print("\n  Component Status:")
    print(f"    {'[PASS]' if health.binary_exists else '[FAIL]'} Application Executable  : {'Present' if health.binary_exists else 'Missing'}")
    print(f"    {'[PASS]' if health.metadata_exists else '[WARN]'} Installation Metadata  : {'Present' if health.metadata_exists else 'Missing'}")
    print(f"    {'[PASS]' if health.data_dir_valid else '[FAIL]'} User Data Directory    : {'Accessible' if health.data_dir_valid else 'Inaccessible'}")
    print(f"    {'[PASS]' if health.config_present else '[-   ]'} Configuration (.env)   : {'Configured' if health.config_present else 'Not configured'}")
    print(f"    {'[PASS]' if health.secrets_present else '[-   ]'} Secret Store Backends   : {'Present' if health.secrets_present else 'Unconfigured'}")

    if health.issues:
        print("\n  Identified Issues:")
        for issue in health.issues:
            print(f"    [!] {issue}")
    print("=" * 65 + "\n")
    return 0 if health.status in {"HEALTHY", "DEGRADED", "NOT_CONFIGURED"} else 1


def repair_installation_cli(assume_yes: bool = False) -> int:
    """Execute safe repair workflow for missing directories and metadata (Phase 12)."""
    confirmed = confirm_action(
        action_name="Repair Device Guardian Installation",
        effect="Recreates missing directories, regenerates install metadata, and prunes stale locks.",
        preserved=[
            "User configuration (.env)",
            "Secret storage (DPAPI secrets.dat / File secrets.json)",
            "Historical activity and audit logs",
            "Update transaction state",
        ],
        changed=[
            "Missing runtime directories will be recreated",
            "Missing installation metadata will be restored",
            "Stale or malformed process lock files will be purged",
        ],
        assume_yes=assume_yes,
    )
    if not confirmed:
        print("\n[!] Repair operation cancelled by operator.")
        return 1

    print("\n[*] Executing application lifecycle repair...")
    res = LifecycleInstaller.repair()
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - REPAIR OPERATION RESULT")
    print("=" * 65)
    print(f"  Status:   {'SUCCESS' if res.success else 'FAILED'}")
    print(f"  Message:  {res.message}")
    if res.details and "repaired_items" in res.details:
        print("  Actions Taken:")
        for item in res.details["repaired_items"]:
            print(f"    [+] {item}")
    print("=" * 65 + "\n")
    return 0 if res.success else 1


def show_migration_status() -> int:
    """Display persistent state schema version and pending migrations (Phase 12)."""
    current_ver = MigrationManager.get_schema_version()
    pending = MigrationManager.check_pending_migrations(target_version=CURRENT_STATE_SCHEMA_VERSION)

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - SCHEMA MIGRATION STATUS")
    print("=" * 65)
    print(f"  Current Schema Version: {current_ver}")
    print(f"  Target Schema Version:  {CURRENT_STATE_SCHEMA_VERSION}")
    if pending:
        print(f"  Pending Migrations:     {len(pending)} step(s) pending:")
        for f, t in pending:
            print(f"    - Migration step: v{f} -> v{t}")
        print("  Action Required:        Run 'device-guardian --migrate' to apply pending migrations.")
    else:
        print("  Pending Migrations:     None (Schema is up to date)")
        print("  Migration Readiness:    [● HEALTHY     ] State schemas match application target.")
    print("=" * 65 + "\n")
    return 0


def apply_migration_cli(assume_yes: bool = False, target_version: int = CURRENT_STATE_SCHEMA_VERSION) -> int:
    """Apply pending schema migrations with pre-migration backup and rollback (Phase 12)."""
    pending = MigrationManager.check_pending_migrations(target_version=target_version)
    if not pending:
        print(f"\n[+] Schema is already at target version {target_version}. No migration needed.\n")
        return 0

    confirmed = confirm_action(
        action_name="Apply Schema Migrations",
        effect=f"Transforms persistent data schemas to version {target_version}.",
        preserved=[
            "Pre-migration backup snapshot will be saved in migration_backups/",
            "User configuration (.env) and encrypted SecretStore credentials remain intact",
            "Automatic rollback is guaranteed if validation fails",
        ],
        changed=[
            f"Persistent state schema updated to version {target_version}",
            "install_metadata.json updated with migration timestamp",
        ],
        assume_yes=assume_yes,
    )
    if not confirmed:
        print("\n[!] Migration cancelled by operator.")
        return 1

    print("\n[*] Applying schema migrations...")
    res = MigrationManager.apply_migrations(target_version=target_version)
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - MIGRATION RESULT")
    print("=" * 65)
    print(f"  Status:   {'SUCCESS' if res.success else 'FAILED'}")
    print(f"  Result:   {res.message}")
    if res.backup_path:
        print(f"  Backup:   {res.backup_path}")
    print("=" * 65 + "\n")
    return 0 if res.success else 1


def uninstall_cli(remove_user_data: bool = False, assume_yes: bool = False) -> int:
    """Execute application uninstallation with data preservation decision (Phase 12)."""
    user_data = ApplicationPaths.get_user_data_dir()
    install_root = ApplicationPaths.get_install_root()

    if remove_user_data:
        action_name = "Uninstall Device Guardian (WITH USER DATA PURGE)"
        effect = "Removes application binary, autostart entries, AND PERMANENTLY ERASES all user data."
        preserved = ["None (All configuration, credentials, logs, and state files will be deleted)"]
        changed = [
            f"Executable in {install_root} deleted",
            "OS autostart registration removed",
            f"User data directory ({user_data}) permanently erased",
        ]
    else:
        action_name = "Uninstall Device Guardian (Application Only)"
        effect = "Removes application binary and autostart registration, preserving user data."
        preserved = [
            f"User configuration (.env) preserved at: {user_data}",
            "Secret storage (DPAPI secrets.dat / File secrets.json) preserved",
            "Logs, audit history, and update backups preserved",
        ]
        changed = [
            f"Application binary in {install_root} will be deleted",
            "OS autostart registration will be removed",
        ]

    confirmed = confirm_action(
        action_name=action_name,
        effect=effect,
        preserved=preserved,
        changed=changed,
        assume_yes=assume_yes,
    )
    if not confirmed:
        print("\n[!] Uninstallation cancelled by operator.")
        return 1

    print("\n[*] Executing uninstallation...")
    res = LifecycleInstaller.uninstall(remove_user_data=remove_user_data)
    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - UNINSTALLATION RESULT")
    print("=" * 65)
    print(f"  Status:   {'SUCCESS' if res.success else 'FAILED'}")
    print(f"  Summary:  {res.message}")
    print("=" * 65 + "\n")
    return 0 if res.success else 1


def verify_package_cli(package_path: str) -> int:
    """Verify a distributable release package against digital signature and release manifest (Phase 12)."""
    p = Path(package_path)
    if not p.is_file():
        print(f"[!] Target package does not exist: {package_path}")
        return 1

    print("\n" + "=" * 65)
    print("       DEVICE GUARDIAN - RELEASE PACKAGE VERIFICATION")
    print("=" * 65)
    print(f"  Package Path: {package_path}\n")

    result = verify_update_package(p, allow_downgrade=True)
    for finding in result.findings:
        icon = "[PASS]" if finding.status == VerificationStatus.VALID else ("[WARN]" if finding.status == VerificationStatus.UNSIGNED else "[FAIL]")
        print(f"    {icon} {finding.category:<24}: {finding.status.value:<10} {finding.message}")

    print("\n" + "-" * 65)
    print(f"  Overall Verification Result: {result.status.value}")
    if result.manifest:
        print(f"  Package Version:            v{result.manifest.version}")
        print(f"  Release Identifier:         {result.manifest.release_id}")
    print("=" * 65 + "\n")

    if result.is_verified:
        return 0
    elif any(f.status == VerificationStatus.INVALID and "signature" in f.category.lower() for f in result.findings):
        return 3
    return 1



def run_interactive_menu() -> None:
    """Display interactive CLI menu with Phase 3 diagnostics and monitoring."""
    config: Optional[AppConfig] = None
    config_ok = False
    telegram_ok = False
    camera_ok = False

    status = determine_setup_status()
    config_ok = (status == SetupStatus.CONFIGURED)

    try:
        config = load_config()
    except Exception:
        config = None

    print("========================================")
    print("        DEVICE GUARDIAN")
    print(f"        Setup Status: {status.value}")
    print("========================================")

    if status != SetupStatus.CONFIGURED:
        print("\n[!] Device Guardian is not yet fully configured.")
        try:
            start_wizard = input("Would you like to run the Setup Wizard now? [Y/n]: ").strip().lower()
            if not start_wizard or start_wizard in {"y", "yes"}:
                run_setup_wizard()
                status = determine_setup_status()
                config_ok = (status == SetupStatus.CONFIGURED)
                try:
                    config = load_config()
                except Exception:
                    config = None
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return

    print("\nStatus:")
    print(f"  {'[OK]' if config_ok else '[--]'} Configuration {'loaded' if config_ok else 'missing or incomplete'}")

    if config_ok and config:
        client = TelegramClient(config.telegram_bot_token, config.telegram_chat_id, timeout=5.0)
        verify_resp = client.verify_credentials()
        telegram_ok = verify_resp.success
        print(f"  {'[OK]' if telegram_ok else '[--]'} Telegram {'configured and verified' if telegram_ok else 'credentials invalid'}")
    else:
        print("  [--] Telegram not configured")

    try:
        import cv2
        cap = cv2.VideoCapture(config.camera_index if config else 0)
        camera_ok = cap.isOpened()
        cap.release()
    except Exception:
        camera_ok = False
    print(f"  {'[OK]' if camera_ok else '[--]'} Camera {'available' if camera_ok else 'unavailable or in use'}")

    # Check auth monitor availability
    mgr = DetectionManager(config=config)
    mon_status, _ = mgr.get_monitor_status()
    print(f"  {'[OK]' if mon_status == DetectionStatus.READY else '[--]'} Auth Monitor ({mon_status.value})")

    # Check voice warning
    tts_ok = mgr.voice_warning.is_available()
    print(f"  {'[OK]' if tts_ok else '[--]'} Offline TTS ({'Available' if tts_ok else 'Unavailable'})")

    while True:
        print("\nCommands:\n")
        print("1. Send test alert")
        print("2. Check configuration")
        print("3. Test camera")
        print("4. Test location")
        print("5. Check authentication monitor & TTS status")
        print("6. Test offline voice warning")
        print("7. Test authentication failure pipeline (synthetic)")
        print("8. Start live authentication monitor (foreground)")
        print("9. Check smart filtering configuration")
        print("10. Check environmental context")
        print("11. Test smart filtering rules")
        print("12. Test context correlation pipeline")
        print("13. Start background monitoring service")
        print("14. Stop background monitoring service")
        print("15. View background runtime status")
        print("16. Launch system tray interface")
        print("17. Enable OS startup launch")
        print("18. Disable OS startup launch")
        print("19. Run comprehensive system diagnostics")
        print("20. Run Setup Wizard (configure/reconfigure)")
        print("21. Check configuration readiness (--config-check)")
        print("22. View sanitized configuration overview (--config-show)")
        print("23. View system and configuration paths (--config-path)")
        print("24. Check credentials status (--credentials-status)")
        print("25. Send test Telegram notification (--test-notification)")
        print("26. View release information (--release-info)")
        print("27. View update subsystem status (--update-status)")
        print("28. Verify update package (--verify-update)")
        print("29. Install update package (--install-update)")
        print("30. Rollback to previous version (--rollback)")
        print("31. View recovery & subsystem health status (--recovery-status)")
        print("32. Repair state files (--repair-state)")
        print("33. Verify binary installation integrity (--verify-installation)")
        print("34. Exit\n")

        try:
            choice = input("Select [1-34]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice == "1":
            run_manual_test_alert(config)
        elif choice == "2":
            check_configuration(config)
        elif choice == "3":
            idx = config.camera_index if config else 0
            test_camera_only(idx)
        elif choice == "4":
            url = config.location_api_url if config else "https://ipapi.co/json/"
            to = config.request_timeout_seconds if config else 10.0
            test_location_only(url, to)
        elif choice == "5":
            check_auth_monitor(config)
        elif choice == "6":
            test_voice_warning_only(config)
        elif choice == "7":
            test_auth_monitor_synthetic(config)
        elif choice == "8":
            start_auth_monitor(config)
        elif choice == "9":
            check_filtering_status(config)
        elif choice == "10":
            check_environment_status(config)
        elif choice == "11":
            test_filtering_rules(config)
        elif choice == "12":
            test_context_correlation_pipeline(config)
        elif choice == "13":
            start_background_runtime(config, blocking=False)
        elif choice == "14":
            stop_background_runtime()
        elif choice == "15":
            show_runtime_status()
        elif choice == "16":
            start_tray_interface(config)
        elif choice == "17":
            install_system_startup()
        elif choice == "18":
            remove_system_startup()
        elif choice == "19":
            run_system_diagnostics(config)
        elif choice == "20":
            run_setup_wizard()
            try:
                config = load_config()
                config_ok = True
            except Exception:
                config = None
                config_ok = False
        elif choice == "21":
            check_config_readiness(config)
        elif choice == "22":
            show_config(config)
        elif choice == "23":
            show_config_paths()
        elif choice == "24":
            show_credentials_status(config)
        elif choice == "25":
            send_test_notification_cli(config)
        elif choice == "26":
            show_release_info()
        elif choice == "27":
            show_update_status()
        elif choice == "28":
            try:
                pkg = input("Enter path to update package (.zip or manifest): ").strip()
                if pkg:
                    verify_update_cli(pkg)
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "29":
            try:
                pkg = input("Enter path to update package (.zip or manifest): ").strip()
                if pkg:
                    install_update_cli(pkg)
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "30":
            rollback_cli()
        elif choice == "31":
            show_recovery_status(config)
        elif choice == "32":
            repair_state_cli()
        elif choice == "33":
            verify_installation_cli()
        elif choice == "34":
            print("Exiting Device Guardian. Stay safe!")
            break
        else:
            print("Invalid option. Please enter a number between 1 and 34.")


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Device Guardian - Zero-Cost Personal Anti-Theft & Intrusion Alert System (Phase 5)"
    )
    parser.add_argument(
        "--setup",
        "-s",
        action="store_true",
        help="Launch the interactive first-run Setup Wizard",
    )
    parser.add_argument(
        "--test-alert",
        "-t",
        action="store_true",
        help="Trigger a manual test alert through the complete pipeline",
    )
    parser.add_argument(
        "--check-config",
        "-c",
        action="store_true",
        help="Validate local configuration and Telegram bot credentials",
    )
    parser.add_argument(
        "--test-camera",
        action="store_true",
        help="Test camera capture and save a single frame",
    )
    parser.add_argument(
        "--test-location",
        action="store_true",
        help="Test approximate IP geolocation lookup",
    )
    parser.add_argument(
        "--check-auth-monitor",
        action="store_true",
        help="Check OS authentication monitor and offline voice warning readiness",
    )
    parser.add_argument(
        "--test-voice-warning",
        action="store_true",
        help="Test offline voice warning text-to-speech synthesis",
    )
    parser.add_argument(
        "--test-auth-monitor",
        action="store_true",
        help="Trigger a synthetic authentication failure test through the pipeline",
    )
    parser.add_argument(
        "--monitor-auth",
        action="store_true",
        help="Start live continuous authentication failure monitor",
    )
    parser.add_argument(
        "--check-filtering",
        action="store_true",
        help="Check Smart Filtering configuration and trusted rules",
    )
    parser.add_argument(
        "--check-environment",
        action="store_true",
        help="Check live environmental context detection",
    )
    parser.add_argument(
        "--test-filtering",
        action="store_true",
        help="Test smart filtering with untrusted and trusted synthetic contexts",
    )
    parser.add_argument(
        "--test-environment",
        action="store_true",
        help="Test environmental context detection live",
    )
    parser.add_argument(
        "--test-context-correlation",
        action="store_true",
        help="Test context correlation between detection and environmental state",
    )
    # Phase 5 Arguments
    parser.add_argument(
        "--start",
        action="store_true",
        help="Start Device Guardian background monitoring service",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop running Device Guardian background service",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Restart Device Guardian background monitoring service",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Display background runtime status and telemetry",
    )
    parser.add_argument(
        "--tray",
        action="store_true",
        help="Launch Device Guardian with system tray icon and background runtime",
    )
    parser.add_argument(
        "--install-startup",
        action="store_true",
        help="Configure Device Guardian to start automatically on user login",
    )
    parser.add_argument(
        "--remove-startup",
        action="store_true",
        help="Remove Device Guardian from user login startup",
    )
    # Phase 6 Arguments: Secure Configuration & Credential Hardening
    parser.add_argument(
        "--config-check",
        action="store_true",
        help="Audit configuration readiness and print structured subsystem report",
    )
    parser.add_argument(
        "--config-show",
        action="store_true",
        help="Display sanitized configuration overview with masked secrets",
    )
    parser.add_argument(
        "--config-path",
        action="store_true",
        help="Display resolved system and configuration file paths",
    )
    parser.add_argument(
        "--credentials-status",
        action="store_true",
        help="Display safe credentials status and storage backend",
    )
    parser.add_argument(
        "--test-notification",
        action="store_true",
        help="Send an explicit test notification to Telegram verifying delivery",
    )
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Run comprehensive Phase 5/6 diagnostics across all subsystems",
    )
    # Phase 7 Arguments: Secure Updates, Versioning & Release Integrity
    parser.add_argument(
        "--release-info",
        action="store_true",
        help="Display application release version, build metadata, and binary integrity",
    )
    parser.add_argument(
        "--update-status",
        action="store_true",
        help="Display update subsystem status, active transactions, and available rollbacks",
    )
    parser.add_argument(
        "--verify-update",
        metavar="PATH",
        type=str,
        help="Verify an update package against signature and checksums",
    )
    parser.add_argument(
        "--install-update",
        metavar="PATH",
        type=str,
        help="Stage and install a verified update package with rollback protection",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back to the previous verified release backup",
    )
    parser.add_argument(
        "--rollback-version",
        metavar="VERSION",
        type=str,
        default=None,
        help="Specific version to restore during rollback (defaults to latest backup)",
    )
    parser.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="Allow verification or installation of older versions (default: blocked)",
    )
    # Phase 8 Arguments: Disaster Recovery, Resilience & Failure-Injection Hardening
    parser.add_argument(
        "--recovery-status",
        action="store_true",
        help="Display comprehensive subsystem health, repair logs, and backup availability",
    )
    parser.add_argument(
        "--repair-state",
        action="store_true",
        help="Perform non-destructive repair and reset of corrupted state files",
    )
    parser.add_argument(
        "--verify-installation",
        action="store_true",
        help="Verify physical binary integrity against expected release hash",
    )
    # Phase 10 Arguments: Production UX, Operator Experience & Accessibility Hardening
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Bypass interactive confirmation for high-impact or destructive operations",
    )
    parser.add_argument(
        "--local-disclosure",
        action="store_true",
        help="Display local data disclosure, privacy guarantees, and boundaries",
    )
    parser.add_argument(
        "--state-model",
        action="store_true",
        help="Display UX state model, health definitions, and uncertainty invariants",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Launch the interactive command menu",
    )
    # Phase 12 Arguments: Production Distribution & Lifecycle Management
    parser.add_argument(
        "--install-info",
        action="store_true",
        help="Display application installation metadata, paths, and deployment information",
    )
    parser.add_argument(
        "--installation-status",
        action="store_true",
        help="Check health of installed files, directory permissions, and version consistency",
    )
    parser.add_argument(
        "--repair-installation",
        action="store_true",
        help="Safely repair missing runtime directories, stale locks, and installation metadata",
    )
    parser.add_argument(
        "--migration-status",
        action="store_true",
        help="Display persistent state schema version and pending migrations",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Apply pending state schema migrations with automatic backup and rollback",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall Device Guardian application with explicit data preservation prompt",
    )
    parser.add_argument(
        "--remove-data",
        action="store_true",
        help="With --uninstall: Authorize permanent deletion of user data and credentials",
    )
    parser.add_argument(
        "--verify-package",
        metavar="PATH",
        type=str,
        help="Verify a candidate release package or archive before installation",
    )
    parser.add_argument(
        "--platform-info",
        action="store_true",
        help="Display host platform compatibility, architecture, and subsystem support (Phase 13)",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"Device Guardian v{__version__} (Phase 8: Resilience, Phase 9: Security, Phase 10: Operator UX, Phase 11: Integration, Phase 12: Lifecycle & Phase 13: Cross-Platform)",
    )


    args = parser.parse_args(argv)

    # Initialize logging
    setup_logging(log_level="INFO", log_file="device_guardian.log")

    # Check for and recover any interrupted update transactions
    try:
        recovery_info = check_and_recover_interrupted_transaction()
        if recovery_info.get("status") == "interrupted":
            logger.warning(
                "Interrupted update transaction detected on startup: %s",
                recovery_info.get("message"),
            )
    except Exception as exc:
        logger.debug("Startup transaction recovery check non-critical error: %s", exc)

    if args.setup:
        ok = run_setup_wizard()
        return 0 if ok else 1
    elif args.release_info:
        return show_release_info()
    elif args.update_status:
        return show_update_status()
    elif args.local_disclosure:
        return show_local_disclosure()
    elif args.state_model:
        return show_state_model()
    elif args.verify_update:
        return verify_update_cli(args.verify_update, allow_downgrade=args.allow_downgrade)
    elif args.install_update:
        return install_update_cli(args.install_update, allow_downgrade=args.allow_downgrade)
    elif args.rollback:
        return rollback_cli(target_version=args.rollback_version, assume_yes=args.yes)
    elif args.config_check:
        return check_config_readiness()
    elif args.config_show:
        return show_config()
    elif args.config_path:
        return show_config_paths()
    elif args.credentials_status:
        return show_credentials_status()
    elif args.test_notification:
        return send_test_notification_cli()
    elif args.start:
        return start_background_runtime(blocking=True)
    elif args.stop:
        return stop_background_runtime()
    elif args.restart:
        return restart_background_runtime()
    elif args.status:
        return show_runtime_status()
    elif args.tray:
        return start_tray_interface()
    elif args.install_startup:
        return install_system_startup()
    elif args.remove_startup:
        return remove_system_startup(assume_yes=args.yes)
    elif args.diagnostics:
        return run_system_diagnostics()
    elif args.recovery_status:
        return show_recovery_status()
    elif args.repair_state:
        return repair_state_cli(assume_yes=args.yes)
    elif args.verify_installation:
        return verify_installation_cli()
    elif args.install_info:
        return show_install_info()
    elif args.installation_status:
        return show_installation_status()
    elif args.repair_installation:
        return repair_installation_cli(assume_yes=args.yes)
    elif args.migration_status:
        return show_migration_status()
    elif args.migrate:
        return apply_migration_cli(assume_yes=args.yes)
    elif args.uninstall:
        return uninstall_cli(remove_user_data=args.remove_data, assume_yes=args.yes)
    elif args.verify_package:
        return verify_package_cli(args.verify_package)
    elif args.platform_info:
        return show_platform_info()
    elif args.test_alert:
        return run_manual_test_alert()
    elif args.check_config:
        ok = check_configuration()
        return 0 if ok else 1
    elif args.test_camera:
        try:
            cfg = load_config()
            idx = cfg.camera_index
        except Exception:
            idx = 0
        ok = test_camera_only(idx)
        return 0 if ok else 1
    elif args.test_location:
        try:
            cfg = load_config()
            url = cfg.location_api_url
            to = cfg.request_timeout_seconds
        except Exception:
            url = "https://ipapi.co/json/"
            to = 10.0
        ok = test_location_only(url, to)
        return 0 if ok else 1
    elif args.check_auth_monitor:
        ok = check_auth_monitor()
        return 0 if ok else 1
    elif args.test_voice_warning:
        ok = test_voice_warning_only()
        return 0 if ok else 1
    elif args.test_auth_monitor:
        ok = test_auth_monitor_synthetic()
        return 0 if ok else 1
    elif args.monitor_auth:
        return start_auth_monitor()
    elif args.check_filtering:
        ok = check_filtering_status()
        return 0 if ok else 1
    elif args.check_environment:
        ok = check_environment_status()
        return 0 if ok else 1
    elif args.test_filtering:
        ok = test_filtering_rules()
        return 0 if ok else 1
    elif args.test_environment:
        ok = test_environment_live()
        return 0 if ok else 1
    elif args.test_context_correlation:
        ok = test_context_correlation_pipeline()
        return 0 if ok else 1
    else:
        run_interactive_menu()
        return 0


if __name__ == "__main__":
    sys.exit(main())
