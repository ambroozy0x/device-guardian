"""Device Guardian security and credential hardening package (Phase 6).

Provides SecretValue encapsulation, DPAPI/file secret storage,
centralized secret redaction, and structured subsystem configuration validation.
"""

from device_guardian.security.events import (
    SecurityAuditEvent,
    SecurityAuditLogger,
    SecurityEventType,
    log_security_event,
)
from device_guardian.security.filesystem import (
    SecurityPathError,
    is_symlink_or_reparse_point,
    secure_create_temp_file,
    validate_safe_path,
)
from device_guardian.security.ipc import (
    ControlChannel,
    ControlChannelError,
    ControlCommand,
    ControlMessage,
)
from device_guardian.security.redactor import SecretRedactor, get_redactor, redact_string
from device_guardian.security.secret import SecretValue, mask_secret
from device_guardian.security.store import (
    FileSecretStore,
    SecretStore,
    WindowsDPAPISecretStore,
    create_default_secret_store,
)
from device_guardian.security.validation import (
    ConfigValidationReport,
    SubsystemValidation,
    ValidationState,
    validate_subsystems,
)

__all__ = [
    "ConfigValidationReport",
    "ControlChannel",
    "ControlChannelError",
    "ControlCommand",
    "ControlMessage",
    "FileSecretStore",
    "SecretAuditEvent",
    "SecurityAuditLogger",
    "SecurityEventType",
    "SecurityPathError",
    "SecretRedactor",
    "SecretStore",
    "SecretValue",
    "SubsystemValidation",
    "ValidationState",
    "WindowsDPAPISecretStore",
    "create_default_secret_store",
    "get_redactor",
    "is_symlink_or_reparse_point",
    "log_security_event",
    "mask_secret",
    "redact_string",
    "secure_create_temp_file",
    "validate_safe_path",
    "validate_subsystems",
]
