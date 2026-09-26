"""Local data disclosure, transparency guide, and state definitions for Device Guardian (Phase 10).

Adheres strictly to Phase 10 UX standards:
- Comprehensive, precise disclosure of what is stored locally, what remains local, and what leaves the machine.
- Factual guarantees and limitations: No false claims of '100% secure' or 'impossible to hack'.
- Explicit definitions of the UX state model and runtime states.
"""

from __future__ import annotations


LOCAL_DATA_DISCLOSURE = {
    "what_is_stored_locally": [
        "Configuration settings (.env or device_guardian.json) in user app data directory.",
        "Encrypted Telegram bot tokens and chat IDs stored in Windows DPAPI or user-restricted keyfile.",
        "Local runtime health and metric files (runtime_status.json).",
        "Local application audit logs (device_guardian.log) with automatic secret redaction.",
        "Temporary camera capture JPEG files (automatically deleted after dispatch unless local archiving is explicitly enabled).",
        "Backup copies of previous application binaries and configuration files during verified updates.",
    ],
    "what_remains_strictly_local": [
        "Authentication failure monitoring and event analysis (Windows Event Log / Linux auditd / macOS log stream).",
        "Offline voice warnings synthesized via OS native text-to-speech without network access.",
        "Sliding-window threshold calculations and smart filtering rules.",
        "Single-instance lock management and IPC mutual exclusion.",
        "Cryptographic public keys for update verification.",
    ],
    "what_information_can_leave_the_machine": [
        "Telegram notifications: Alert text and captured photos are sent over TLS/HTTPS directly to the Telegram Bot API ONLY if the operator configures a valid Telegram bot token and chat ID.",
        "Approximate Geolocation: An HTTPS GET request is sent to the configured geolocation provider (e.g., ipapi.co) to determine city/region coordinates ONLY during triggered alerts if geolocation is enabled.",
        "Update manifest verification: An HTTPS request to check for new release manifests ONLY when explicitly requested by operator via update commands.",
    ],
    "what_is_never_collected": [
        "No keystrokes, passwords, or credential harvesting.",
        "No browser history, cookies, or session tokens.",
        "No continuous screen recording or ambient microphone surveillance.",
        "No personal files, documents, or private directory scanning.",
        "No telemetry, cloud usage analytics, tracking pixels, or diagnostic reporting.",
        "No remote administration backdoors, reverse shells, or listening network sockets.",
        "No AI/ML profiling, facial recognition, or probabilistic threat scoring.",
    ],
    "guarantees_and_limitations": [
        "Guarantee: All operations are local-first, auditable, and deterministic.",
        "Guarantee: Sensitive tokens and credentials are encrypted at rest and redacted from logs/CLI output.",
        "Limitation: Device Guardian cannot prevent physical theft; it alerts the owner upon unauthorized access attempts.",
        "Limitation: Geolocation accuracy is approximate and depends on external IP-based geolocation services.",
        "Limitation: Notification delivery requires active network connectivity at the time of the event.",
        "Limitation: Unprivileged users on shared machines cannot monitor other users' authentication failures without administrator privileges.",
    ],
}


UX_STATE_DEFINITIONS = {
    "HEALTHY": "Subsystem is operational, responsive, and operating within expected security and performance parameters.",
    "DEGRADED": "Subsystem is operational but utilizing fallback mechanisms or operating with limited capabilities (e.g. FileSecretStore instead of DPAPI). DEGRADED does NOT indicate system compromise.",
    "FAILED": "Subsystem is unavailable, corrupted, or experiencing unrecoverable errors. Requires operator inspection or repair.",
    "UNKNOWN": "Subsystem status cannot be determined deterministically (e.g. sensor unqueried or offline). UNKNOWN is NEVER represented as SAFE.",
    "NOT_CONFIGURED": "Subsystem is intentionally unconfigured by operator (e.g. Telegram token not set). NOT_CONFIGURED is NEVER represented as PROTECTED.",
    "RUNNING": "Background monitoring service is active and processing events.",
    "STOPPED": "Background monitoring service is not running.",
    "STARTING": "Service is actively initializing subsystems.",
    "STOPPING": "Service is actively performing graceful shutdown.",
}


def format_local_data_disclosure() -> str:
    """Format the local data disclosure document as a clean terminal text presentation."""
    lines = [
        "=" * 65,
        "       DEVICE GUARDIAN - LOCAL DATA DISCLOSURE & PRIVACY GUIDE",
        "=" * 65,
        "",
        "1. What Device Guardian Stores Locally:",
    ]
    for item in LOCAL_DATA_DISCLOSURE["what_is_stored_locally"]:
        lines.append(f"   * {item}")

    lines.append("\n2. What Remains Strictly Local:")
    for item in LOCAL_DATA_DISCLOSURE["what_remains_strictly_local"]:
        lines.append(f"   * {item}")

    lines.append("\n3. What Information Can Leave The Machine:")
    for item in LOCAL_DATA_DISCLOSURE["what_information_can_leave_the_machine"]:
        lines.append(f"   * {item}")

    lines.append("\n4. What Is NEVER Collected (Absolute Boundaries):")
    for item in LOCAL_DATA_DISCLOSURE["what_is_never_collected"]:
        lines.append(f"   * {item}")

    lines.append("\n5. Guarantees & Limitations:")
    for item in LOCAL_DATA_DISCLOSURE["guarantees_and_limitations"]:
        lines.append(f"   * {item}")

    lines.append("\n" + "=" * 65)
    return "\n".join(lines)


def format_state_definitions() -> str:
    """Format explanation of all health and runtime states."""
    lines = [
        "=" * 65,
        "              DEVICE GUARDIAN - UX STATE MODEL",
        "=" * 65,
        "",
        "Subsystem Health States:",
    ]
    for state in ["HEALTHY", "DEGRADED", "FAILED", "UNKNOWN", "NOT_CONFIGURED"]:
        desc = UX_STATE_DEFINITIONS[state]
        lines.append(f"  [{state:<14}] : {desc}")

    lines.append("\nRuntime Lifecycle States:")
    for state in ["RUNNING", "STOPPED", "STARTING", "STOPPING"]:
        desc = UX_STATE_DEFINITIONS[state]
        lines.append(f"  [{state:<14}] : {desc}")

    lines.append("\nUncertainty Rules:")
    lines.append("  - UNKNOWN is NEVER interpreted or shown as SAFE.")
    lines.append("  - NOT_CONFIGURED is NEVER interpreted or shown as PROTECTED.")
    lines.append("=" * 65)
    return "\n".join(lines)
