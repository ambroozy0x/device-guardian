"""Local IPC and Control Channel Security for Device Guardian (Phase 9).

Provides local-only, authenticated, spoof-resistant cross-process control signaling:
- Bounded, explicit control commands enum (START, STOP, RESTART).
- Strictly blocks command execution injection (EXEC, SHELL, CMD, etc.).
- Strict JSON schema validation with UUID request IDs and bounded TTL expiry.
- In-memory replay protection for processed request IDs.
- Symlink and junction avoidance on control signaling files.
- Atomic control message dispatch.
- Absolutely NO listening TCP/UDP network ports or sockets.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import os
from pathlib import Path
import time
from typing import Any, Optional, Set
import uuid

from device_guardian.logger import get_logger
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point, validate_safe_path

logger = get_logger("security.ipc")

# Forbidden command names that must be immediately rejected
FORBIDDEN_COMMAND_NAMES = {
    "EXEC",
    "SHELL",
    "POWERSHELL",
    "CMD",
    "RUN",
    "COMMAND",
    "SCRIPT",
    "EVAL",
    "SYSTEM",
    "SPAWN",
}


class ControlCommand(str, Enum):
    """Explicit whitelisted lifecycle commands for local IPC."""

    START = "START"
    STOP = "STOP"
    RESTART = "RESTART"


class ControlChannelError(Exception):
    """Raised when an IPC control message violates security or schema rules."""
    pass


# Backwards compatibility alias
IPCError = ControlChannelError


@dataclass(frozen=True)
class ControlMessage:
    """Strict schema for cross-process control messages."""

    command: ControlCommand
    request_id: str
    created_at: str
    expires_at: str
    sender_pid: int

    @classmethod
    def create(
        cls,
        command: ControlCommand | str,
        ttl_seconds: float = 30.0,
        sender_pid: Optional[int] = None,
    ) -> ControlMessage:
        """Create a new control message with guaranteed timestamp and expiry."""
        if isinstance(command, ControlCommand):
            valid_cmd = command
            cmd_str = command.value
        else:
            raw_s = str(command).strip()
            if "." in raw_s:
                raw_s = raw_s.split(".")[-1]
            cmd_str = raw_s.upper()

        if cmd_str in FORBIDDEN_COMMAND_NAMES:
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message=f"Attempted forbidden control command: '{cmd_str}'",
                details={"command": cmd_str},
            )
            raise ControlChannelError(f"Forbidden command name: '{cmd_str}'")

        try:
            valid_cmd = ControlCommand(cmd_str)
        except ValueError:
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message=f"Unknown control command rejected: '{cmd_str}'",
                details={"command": cmd_str},
            )
            raise ControlChannelError(f"Unknown control command: '{cmd_str}'")

        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=max(1.0, min(ttl_seconds, 300.0)))

        return cls(
            command=valid_cmd,
            request_id=str(uuid.uuid4()),
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            sender_pid=sender_pid if sender_pid is not None else os.getpid(),
        )

    def to_json(self) -> str:
        """Serialize to compact JSON string."""
        return json.dumps({
            "command": self.command.value,
            "request_id": self.request_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "sender_pid": self.sender_pid,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ControlMessage:
        """Parse and strictly validate a dictionary against control schema."""
        if not isinstance(data, dict):
            raise ControlChannelError("Control payload must be a JSON object.")

        # Strict field validation: Reject unknown fields
        expected_fields = {"command", "request_id", "created_at", "expires_at", "sender_pid"}
        extra_fields = set(data.keys()) - expected_fields
        if extra_fields:
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message="Control payload contained unexpected fields.",
                details={"extra_fields": list(extra_fields)},
            )
            raise ControlChannelError(f"Unexpected fields in control message: {extra_fields}")

        cmd_raw = str(data.get("command", "")).upper().strip()
        if cmd_raw in FORBIDDEN_COMMAND_NAMES:
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message=f"Forbidden command rejected: '{cmd_raw}'",
                details={"command": cmd_raw},
            )
            raise ControlChannelError(f"Forbidden command: '{cmd_raw}'")

        try:
            cmd = ControlCommand(cmd_raw)
        except ValueError:
            raise ControlChannelError(f"Invalid command: '{cmd_raw}'")

        req_id = str(data.get("request_id", "")).strip()
        if not req_id or len(req_id) < 8 or len(req_id) > 64:
            raise ControlChannelError(f"Invalid request_id format: '{req_id}'")

        sender_pid = data.get("sender_pid")
        if not isinstance(sender_pid, int) or sender_pid <= 0:
            raise ControlChannelError(f"Invalid sender_pid: {sender_pid}")

        created_str = str(data.get("created_at", ""))
        expires_str = str(data.get("expires_at", ""))
        try:
            created_dt = datetime.fromisoformat(created_str)
            expires_dt = datetime.fromisoformat(expires_str)
        except Exception as exc:
            raise ControlChannelError(f"Malformed timestamp in control message: {exc}")

        # Check future timestamp drift (clock skew > 60 seconds)
        now_utc = datetime.now(timezone.utc)
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        if created_dt > now_utc + timedelta(seconds=60):
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message="Control message from the future detected (clock skew > 60s).",
                details={"request_id": req_id, "created_at": created_str},
            )
            raise ControlChannelError(f"Control message '{req_id}' timestamp is too far in the future: {created_str}")

        # Check expiration
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if now_utc > expires_dt:
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message="Control message has expired.",
                details={"request_id": req_id, "expired_at": expires_str},
            )
            raise ControlChannelError(f"Control message '{req_id}' expired at {expires_str}")

        return cls(
            command=cmd,
            request_id=req_id,
            created_at=created_str,
            expires_at=expires_str,
            sender_pid=sender_pid,
        )


class ControlChannel:
    """Manages secure reading, writing, and replay prevention of control signals."""

    _processed_request_ids: Set[str] = set()

    @classmethod
    def send_command(
        cls,
        control_file: Path | str,
        command: ControlCommand | str,
        ttl_seconds: float = 30.0,
    ) -> bool:
        """Dispatch a control command securely using atomic persistence.

        Args:
            control_file: Target file path for the control signal.
            command: ControlCommand (START, STOP, RESTART).
            ttl_seconds: Maximum command validity period.

        Returns:
            True if dispatched successfully.
        """
        try:
            path = Path(control_file).resolve()
            if is_symlink_or_reparse_point(path):
                log_security_event(
                    SecurityEventType.SECURITY_CONTROL_REJECTED,
                    subsystem="ipc",
                    message="Control file destination is a symlink or reparse point.",
                    details={"path": str(path)},
                )
                return False

            msg = ControlMessage.create(command=command, ttl_seconds=ttl_seconds)

            from device_guardian.recovery.persistence import AtomicPersistence
            AtomicPersistence.atomic_write(
                file_path=path,
                content=msg.to_json(),
                backup=False,
            )
            logger.info("Secure control signal dispatched: %s (ID: %s)", msg.command.value, msg.request_id)
            return True
        except Exception as exc:
            logger.error("Failed to send control command: %s", exc)
            return False

    @classmethod
    def read_command(cls, control_file: Path | str) -> Optional[ControlMessage]:
        """Read and validate a pending control signal.

        Args:
            control_file: Target control file path.

        Returns:
            Validated ControlMessage if a valid, unexpired, non-replayed command exists,
            or None otherwise.
        """
        path = Path(control_file)
        if not path.is_file():
            return None

        # Reparse point check
        if is_symlink_or_reparse_point(path):
            log_security_event(
                SecurityEventType.SECURITY_CONTROL_REJECTED,
                subsystem="ipc",
                message="Blocked read of control file via symlink/reparse point.",
                details={"path": str(path)},
            )
            cls.clear(path)
            return None

        try:
            content = path.read_text(encoding="utf-8").strip()
            if not content:
                return None

            # Handle backward-compatible raw string "STOP"
            if content == "STOP":
                return ControlMessage.create(ControlCommand.STOP)

            data = json.loads(content)
            msg = ControlMessage.from_dict(data)

            # Replay protection
            if msg.request_id in cls._processed_request_ids:
                log_security_event(
                    SecurityEventType.SECURITY_CONTROL_REJECTED,
                    subsystem="ipc",
                    message="Duplicate / replayed control request rejected.",
                    details={"request_id": msg.request_id},
                )
                cls.clear(path)
                return None

            cls._processed_request_ids.add(msg.request_id)
            # Bound in-memory cache
            if len(cls._processed_request_ids) > 1000:
                cls._processed_request_ids.pop()

            return msg
        except ControlChannelError as cce:
            logger.warning("Rejected invalid control message: %s", cce)
            cls.clear(path)
            return None
        except Exception as exc:
            logger.warning("Failed to parse control signal: %s", exc)
            cls.clear(path)
            return None

    @classmethod
    def clear(cls, control_file: Path | str) -> None:
        """Safely delete any existing control file."""
        try:
            path = Path(control_file)
            if path.is_file() or is_symlink_or_reparse_point(path):
                path.unlink()
        except Exception:
            pass

    @classmethod
    def reset_replay_cache(cls) -> None:
        """Reset the replay cache (primarily for tests)."""
        cls._processed_request_ids.clear()
