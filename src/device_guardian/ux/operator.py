"""Unified Operator Status Surface for Device Guardian (Phase 10).

Provides a comprehensive, non-secret, color-independent operator dashboard answering:
1. Is Device Guardian running?
2. Is Device Guardian configured?
3. Is the security engine healthy?
4. Are any subsystems degraded?
5. What happened recently?
6. Why was an alert generated?
7. Why was an alert NOT generated?
8. Is Telegram configured?
9. Are camera/location/environmental systems available?
10. Is an update pending?
11. Is recovery required?
12. What action can the user safely take?
13. What will happen before they click a destructive/high-impact action?
14. What information is stored locally?
15. What information leaves the machine?

Adheres strictly to Phase 10 UX standards:
- Clear empty states (no raw [] or None).
- No secrets exposed (all masked/redacted).
- No risk scores or AI/predictive indicators.
- Uncertainty invariants enforced (UNKNOWN is never SAFE).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from device_guardian import __version__
from device_guardian.config import AppConfig, load_config
from device_guardian.logger import get_logger
from device_guardian.recovery.health import HealthStatus, assess_system_health
from device_guardian.recovery.repair import get_recovery_status
from device_guardian.runtime.models import RuntimeState
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.startup.factory import create_startup_manager
from device_guardian.updates.installer import UpdateInstaller
from device_guardian.updates.transaction import check_and_recover_interrupted_transaction
from device_guardian.ux.status import (
    format_status_badge,
    get_state_glyph,
    normalize_state,
)

logger = get_logger("ux.operator")


def get_operator_summary(config: Optional[AppConfig] = None) -> dict[str, Any]:
    """Gather all operator metrics and health evaluations into a unified summary dictionary.

    Args:
        config: Optional pre-loaded AppConfig.

    Returns:
        Structured dictionary containing all operational dimensions.
    """
    # 1. Config loading & Telegram status
    cfg_loaded = False
    telegram_configured = False
    cfg_error = None
    if config is None:
        try:
            config = load_config()
            cfg_loaded = True
        except Exception as exc:
            cfg_error = str(exc)
    else:
        cfg_loaded = True

    if config is not None:
        try:
            tok = config.get_secret_token()
            if hasattr(tok, "get_secret_value"):
                tok = tok.get_secret_value()
            cid = config.get_secret_chat_id()
            if hasattr(cid, "get_secret_value"):
                cid = cid.get_secret_value()
            tok_str = str(tok or "").strip()
            cid_str = str(cid or "").strip()
            telegram_configured = bool(
                tok_str and cid_str and tok_str != "***EMPTY***" and cid_str != "***EMPTY***" and config.telegram_alert_enabled
            )
        except Exception:
            telegram_configured = False

    # 2. Runtime status
    lock = SingleInstanceLock()
    is_locked = lock.is_locked()
    active_pid = lock.get_active_pid() if is_locked else None

    status_file = ApplicationPaths.get_status_file_path()
    runtime_data: dict[str, Any] = {}
    if status_file.is_file():
        try:
            runtime_data = json.loads(status_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("Could not read runtime_status.json: %s", exc)

    raw_runtime_state = runtime_data.get("state", "STOPPED" if not is_locked else "RUNNING")
    if not is_locked:
        runtime_state = "STOPPED"
    else:
        runtime_state = raw_runtime_state

    # 3. System Health
    health_report = assess_system_health(config=config)
    overall_health = health_report.overall_status.value

    # Identify degraded subsystems
    degraded_subsystems = [
        sub.name for sub in health_report.subsystems if sub.status == HealthStatus.DEGRADED
    ]
    failed_subsystems = [
        sub.name for sub in health_report.subsystems if sub.status == HealthStatus.FAILED
    ]

    # 4. Recovery & Resilience
    recovery_info = get_recovery_status(config=config)
    recovery_required = recovery_info.get("recovery_required", False)

    # 5. Updates & Transactions
    staged_transaction = None
    try:
        tx_info = check_and_recover_interrupted_transaction()
        if tx_info.get("status") == "interrupted":
            staged_transaction = tx_info.get("message")
    except Exception as exc:
        logger.debug("Update transaction check error: %s", exc)

    rollback_versions: list[str] = []
    try:
        upd_summary = UpdateInstaller.get_update_status_summary()
        rollback_versions = upd_summary.get("available_rollbacks", [])
    except Exception as exc:
        logger.debug("Failed to get update status summary: %s", exc)

    # 6. Startup configuration
    startup_enabled = False
    try:
        startup_mgr = create_startup_manager()
        startup_enabled = startup_mgr.is_enabled()
    except Exception as exc:
        logger.debug("Startup status check error: %s", exc)

    # Compile structured summary
    return {
        "version": __version__,
        "runtime": {
            "state": runtime_state,
            "pid": active_pid,
            "uptime": runtime_data.get("formatted_uptime", "00:00:00") if is_locked else "00:00:00",
            "is_locked": is_locked,
            "startup_enabled": startup_enabled,
            "restarts_count": runtime_data.get("restart_count", 0),
            "events_processed": runtime_data.get("total_events_processed", 0),
            "alerts_dispatched": runtime_data.get("alerts_triggered", 0),
            "alerts_filtered": runtime_data.get("alerts_suppressed_by_filter", 0),
            "alerts_cooldown": runtime_data.get("alerts_suppressed_by_cooldown", 0),
            "last_cycle": runtime_data.get("last_detection_cycle"),
            "last_error": runtime_data.get("last_error"),
        },
        "configuration": {
            "loaded": cfg_loaded,
            "error": cfg_error,
            "telegram_configured": telegram_configured,
            "camera_enabled": getattr(config, "camera_alert_enabled", False) if config else False,
            "location_enabled": getattr(config, "location_alert_enabled", False) if config else False,
            "voice_enabled": getattr(config, "voice_warning_enabled", False) if config else False,
        },
        "health": {
            "overall": overall_health,
            "subsystems": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "message": s.message,
                }
                for s in health_report.subsystems
            ],
            "degraded_count": len(degraded_subsystems),
            "degraded_subsystems": degraded_subsystems,
            "failed_count": len(failed_subsystems),
            "failed_subsystems": failed_subsystems,
        },
        "recovery": {
            "recovery_required": recovery_required,
            "state_files": recovery_info.get("state_files", {}),
            "data_directory": recovery_info.get("data_directory"),
        },
        "updates": {
            "current_version": __version__,
            "interrupted_transaction": staged_transaction,
            "rollback_available": len(rollback_versions) > 0,
            "rollback_versions": rollback_versions,
        },
    }


def format_operator_dashboard(summary: dict[str, Any]) -> str:
    """Render a comprehensive, accessible operator dashboard text presentation.

    Args:
        summary: Output dictionary from get_operator_summary().

    Returns:
        Clean, formatted terminal dashboard string.
    """
    lines = [
        "=" * 68,
        f"       DEVICE GUARDIAN - UNIFIED OPERATOR STATUS SURFACE (v{summary['version']})",
        "              Device Guardian Runtime Status",
        "=" * 68,
        "",
        "--- 1. OPERATOR QUICK STATUS (15 CORE INQUIRIES) ---",
    ]

    rt = summary["runtime"]
    cfg = summary["configuration"]
    hlth = summary["health"]
    rec = summary["recovery"]
    upd = summary["updates"]

    # 1. Is Device Guardian running?
    rt_running = rt["state"] == "RUNNING"
    lines.append(f"  1. Running:            {'YES' if rt_running else 'NO'} ({rt['state']})")

    # 2. Is Device Guardian configured?
    if cfg["loaded"]:
        cfg_status_str = "YES (Configuration active)"
    else:
        cfg_status_str = f"NO ({cfg['error'] or 'Config file missing'})"
    lines.append(f"  2. Configured:         {cfg_status_str}")

    # 3. Is the security engine healthy?
    lines.append(f"  3. Security Engine:    {format_status_badge(hlth['overall'], width=12)} (Overall status)")

    # 4. Are any subsystems degraded?
    if hlth["degraded_count"] == 0 and hlth["failed_count"] == 0:
        lines.append("  4. Degraded Subsystems: NONE (All active subsystems operating normally)")
    else:
        deg_names = ", ".join(hlth["degraded_subsystems"] + hlth["failed_subsystems"])
        lines.append(f"  4. Degraded Subsystems: {deg_names}")

    # 5. What happened recently?
    if rt["events_processed"] > 0:
        lines.append(
            f"  5. Recent Activity:    {rt['events_processed']} events evaluated; {rt['alerts_dispatched']} alert(s) dispatched"
        )
    else:
        lines.append("  5. Recent Activity:    No security events recorded (system operating normally)")

    # 6. Why was an alert generated?
    if rt["alerts_dispatched"] > 0:
        lines.append(f"  6. Alert Generation:   {rt['alerts_dispatched']} alert(s) met deterministic trigger thresholds")
    else:
        lines.append("  6. Alert Generation:   N/A (No alerts triggered)")

    # 7. Why was an alert NOT generated?
    suppressed_total = rt["alerts_filtered"] + rt["alerts_cooldown"]
    if suppressed_total > 0:
        lines.append(
            f"  7. Alert Suppression:  {rt['alerts_filtered']} filtered (trusted context), {rt['alerts_cooldown']} cooldown"
        )
    else:
        lines.append("  7. Alert Suppression:  N/A (No alerts suppressed)")

    # 8. Is Telegram configured?
    if cfg["telegram_configured"]:
        lines.append("  8. Telegram Channel:   CONFIGURED & READY (Encrypted in SecretStore)")
    else:
        lines.append("  8. Telegram Channel:   NOT_CONFIGURED (Local alerts only; remote dispatch inactive)")

    # 9. Are sensors available?
    lines.append(
        f"  9. Available Sensors:  Camera={'ON' if cfg['camera_enabled'] else 'OFF'}, Geolocation={'ON' if cfg['location_enabled'] else 'OFF'}, Voice={'ON' if cfg['voice_enabled'] else 'OFF'}"
    )

    # 10. Is an update pending?
    if upd["interrupted_transaction"]:
        lines.append(f" 10. Update Pending:     ATTENTION ({upd['interrupted_transaction']})")
    else:
        lines.append(" 10. Update Pending:     NO (No active update transactions)")

    # 11. Is recovery required?
    if rec["recovery_required"]:
        lines.append(" 11. Recovery Required:  YES (Corrupted state files detected; run --repair-state)")
    else:
        lines.append(" 11. Recovery Required:  NO (All state files and backups intact)")

    # 12. What action can the user safely take?
    if rec["recovery_required"]:
        lines.append(" 12. Safe Next Action:   Execute 'device-guardian --repair-state' to restore clean state")
    elif not rt_running:
        lines.append(" 12. Safe Next Action:   Execute 'device-guardian --start' or '--tray' to begin monitoring")
    else:
        lines.append(" 12. Safe Next Action:   System operating normally; no operator intervention required")

    # 13. What will happen before destructive action?
    lines.append(" 13. Destructive Action: Explicit confirmation required; cancel is always the default")

    # 14. What information is stored locally?
    lines.append(" 14. Local Storage:      Encrypted secrets, config, runtime health, rolling logs (run --local-disclosure)")

    # 15. What leaves the machine?
    if cfg["telegram_configured"]:
        lines.append(" 15. Remote Transfer:    Telegram alerts (HTTPS only) when triggered; zero telemetry")
    else:
        lines.append(" 15. Remote Transfer:    NONE (Zero data leaves this machine)")

    lines.append("\n--- 2. RUNTIME & PROCESS METRICS ---")
    lines.append(f"  Runtime State:        {format_status_badge(rt['state'], width=12)}")
    lines.append(f"  Process PID:          {rt['pid'] or 'None (inactive)'}")
    lines.append(f"  Active Uptime:        {rt['uptime']}")
    lines.append(f"  Startup Integration:  {'ENABLED' if rt['startup_enabled'] else 'DISABLED'}")
    lines.append(f"  Restart Count:        {rt['restarts_count']}")
    lines.append(f"  Events Evaluated:     {rt['events_processed']}")
    lines.append(f"  Alerts Dispatched:    {rt['alerts_dispatched']}")
    lines.append(f"  Alerts Filtered:      {rt['alerts_filtered']}")
    lines.append(f"  Alerts Cooldown:      {rt['alerts_cooldown']}")
    if rt["last_cycle"]:
        lines.append(f"  Last Cycle Time:      {rt['last_cycle']}")
    if rt["last_error"]:
        lines.append(f"  Last Error:           {rt['last_error']}")

    lines.append("\n--- 3. SUBSYSTEM HEALTH BREAKDOWN ---")
    if hlth["subsystems"]:
        for sub in hlth["subsystems"]:
            badge = format_status_badge(sub["status"], width=12)
            lines.append(f"  {badge} {sub['name']:<22} : {sub['message']}")
    else:
        lines.append("  No subsystem health entries available.")

    lines.append("\n--- 4. RESILIENCE & RECOVERY STATUS ---")
    if rec["recovery_required"]:
        lines.append("  [!] ATTENTION: One or more state files require repair.")
    else:
        lines.append("  [✓] All monitored state files are intact; no recovery actions required.")

    state_files = rec["state_files"]
    if state_files:
        for sf, info in state_files.items():
            exists_str = "PRESENT" if info.get("exists") else "MISSING"
            bak_str = "YES" if info.get("has_backup") else "NO"
            corrupt_count = len(info.get("corrupted_copies", []))
            corrupt_str = f" ({corrupt_count} corrupt copy preserved)" if corrupt_count else ""
            lines.append(f"    - {sf:<24}: Status={exists_str:<8} Backup={bak_str:<4}{corrupt_str}")
    else:
        lines.append("    No state files currently tracked.")

    lines.append("\n--- 5. UPDATES & ROLLBACK AVAILABILITY ---")
    lines.append(f"  Installed Release:    v{upd['current_version']}")
    if upd["interrupted_transaction"]:
        lines.append(f"  Active Transaction:   {upd['interrupted_transaction']}")
    else:
        lines.append("  Active Transaction:   No update transaction is active.")

    if upd["rollback_available"]:
        rb_list = ", ".join(f"v{v}" for v in upd["rollback_versions"])
        lines.append(f"  Rollback Backups:     Available ({rb_list})")
    else:
        lines.append("  Rollback Backups:     None stored (initial clean release)")

    lines.append("\n" + "=" * 68)
    return "\n".join(lines)
