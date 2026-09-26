"""User Experience, Operator Ergonomics, and Accessibility Hardening Package for Device Guardian (Phase 10)."""

from device_guardian.ux.confirmations import (
    confirm_action,
    confirm_remove_startup,
    confirm_repair_state,
    confirm_rollback,
)
from device_guardian.ux.events import (
    HumanReadableEvent,
    format_alert_explanation,
    format_empty_event_state,
    format_security_event_block,
)
from device_guardian.ux.help import (
    LOCAL_DATA_DISCLOSURE,
    UX_STATE_DEFINITIONS,
    format_local_data_disclosure,
    format_state_definitions,
)
from device_guardian.ux.operator import (
    format_operator_dashboard,
    get_operator_summary,
)
from device_guardian.ux.status import (
    GLYPH_MAP,
    STATE_DESCRIPTIONS,
    UXGlyph,
    assert_uncertainty_invariants,
    format_state_with_description,
    format_status_badge,
    get_state_glyph,
    is_deterministic_healthy,
    normalize_state,
)

__all__ = [
    "UXGlyph",
    "GLYPH_MAP",
    "STATE_DESCRIPTIONS",
    "normalize_state",
    "get_state_glyph",
    "format_status_badge",
    "format_state_with_description",
    "assert_uncertainty_invariants",
    "is_deterministic_healthy",
    "HumanReadableEvent",
    "format_security_event_block",
    "format_alert_explanation",
    "format_empty_event_state",
    "confirm_action",
    "confirm_rollback",
    "confirm_repair_state",
    "confirm_remove_startup",
    "LOCAL_DATA_DISCLOSURE",
    "UX_STATE_DEFINITIONS",
    "format_local_data_disclosure",
    "format_state_definitions",
    "get_operator_summary",
    "format_operator_dashboard",
]
