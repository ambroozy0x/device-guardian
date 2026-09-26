"""Explicit destructive action confirmation workflows for Device Guardian (Phase 10).

Adheres strictly to Phase 10 UX standards:
- Requires unambiguous confirmation explaining:
  ACTION, EFFECT, WHAT IS PRESERVED, WHAT MAY CHANGE, CANCEL OPTION.
- No dark patterns: Cancellation is the default option.
- No ambiguous prompts like 'Are you sure?'.
- Supports non-interactive bypass via explicit '--yes' flag.
"""

from __future__ import annotations

import sys
from typing import Callable, Optional, Sequence

from device_guardian.logger import get_logger

logger = get_logger("ux.confirmations")


def confirm_action(
    action_name: str,
    effect: str,
    preserved: Sequence[str],
    changed: Sequence[str],
    assume_yes: bool = False,
    input_fn: Optional[Callable[[str], str]] = None,
) -> bool:
    """Prompt user for explicit confirmation before executing a high-impact or destructive action.

    Args:
        action_name: Short name of the action (e.g. 'Rollback Device Guardian').
        effect: Clear description of what the action does.
        preserved: List of items/state files that will remain intact.
        changed: List of items/state files that will be modified or restored.
        assume_yes: If True, bypasses prompt and automatically confirms.
        input_fn: Custom input function for testability (defaults to built-in input).

    Returns:
        True if action was explicitly confirmed, False if cancelled.
    """
    if assume_yes:
        logger.info("High-impact action '%s' auto-confirmed via --yes flag.", action_name)
        return True

    print("\n" + "=" * 65)
    print("      ATTENTION: HIGH-IMPACT / DESTRUCTIVE ACTION CONFIRMATION")
    print("=" * 65)
    print(f"Action:    {action_name}")
    print(f"Effect:    {effect}\n")

    print("Preserved (Will NOT be deleted or modified):")
    for item in preserved:
        print(f"  [✓] {item}")

    print("\nWhat May Change:")
    for item in changed:
        print(f"  [!] {item}")

    print("\nCancel Option: Press [N] or Enter to cancel safely without making changes.")
    print("-" * 65)

    prompt = f"Proceed with {action_name}? [y/N]: "
    actual_input = input_fn or input

    try:
        response = actual_input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[CANCELLED] Operation cancelled by operator.")
        logger.info("High-impact action '%s' cancelled via input interrupt.", action_name)
        return False

    confirmed = response in ("y", "yes")
    if confirmed:
        logger.info("High-impact action '%s' confirmed by operator.", action_name)
        return True
    else:
        print("\n[CANCELLED] Operation cancelled safely. No changes were made.\n")
        logger.info("High-impact action '%s' cancelled by operator response '%s'.", action_name, response)
        return False


def confirm_rollback(target_version: Optional[str] = None, assume_yes: bool = False) -> bool:
    """Confirm restoration of previous application version."""
    target_desc = f"version v{target_version}" if target_version else "the previously installed backup version"
    return confirm_action(
        action_name="Rollback Executable Binary",
        effect=f"Replaces the current executable with {target_desc}.",
        preserved=[
            "Encrypted credentials and secrets in SecretStore",
            "Configuration files (.env, device_guardian.json)",
            "Local event logs and audit history",
            "Operating system startup registrations",
        ],
        changed=[
            "Active application binary executable",
            "Runtime version reported by --version",
        ],
        assume_yes=assume_yes,
    )


def confirm_repair_state(assume_yes: bool = False) -> bool:
    """Confirm state file repair and reset."""
    return confirm_action(
        action_name="Repair State Files",
        effect="Resets corrupted state files to initial known-good defaults while archiving damaged copies.",
        preserved=[
            "Corrupted files are safely preserved with timestamped .corrupt.* extensions",
            "Encrypted credentials in SecretStore",
            "Configuration files (.env, device_guardian.json)",
            "System logs and audit trails",
        ],
        changed=[
            "Damaged state files (e.g. runtime_status.json) reset to clean defaults",
            "Current runtime session metrics reset",
        ],
        assume_yes=assume_yes,
    )


def confirm_remove_startup(assume_yes: bool = False) -> bool:
    """Confirm removal of automatic user login startup."""
    return confirm_action(
        action_name="Disable Login Startup",
        effect="Removes Device Guardian from automatic startup upon user login.",
        preserved=[
            "All configuration, secrets, and state files remain intact",
            "Manual CLI and tray execution remain fully functional",
        ],
        changed=[
            "Operating system login startup registry/service entry removed",
            "Device Guardian will not start automatically on device reboot",
        ],
        assume_yes=assume_yes,
    )
