"""Select only known KIM diagnostic fields before the inventory privacy sanitizer."""
from __future__ import annotations
import math
import re
from typing import Any

MODULE = {"module": None, "state": None, "evidence": None, "checked_at": None}
INCIDENT = {k: None for k in (
    "id", "severity", "title", "evidence", "next_check", "first_seen", "last_seen",
    "occurrences", "state", "resolved_at", "resolution",
)}
COMMON = {"reported_at": None, "source": None}
SCHEMAS = {
    "status": {"app_version": None, "entities": None, "anomalies": None,
               "important_anomalies": None, "details": [{"entity_or_module": None, "evidence": None, "next_check": None}]},
    "memory": {"confirmed_preferences": None},
    "learning": {"enabled": None, "kind": None},
    "wake": {"enabled": None, "checked_at": None, "foreground_only": None},
    "last_action": {"entity_id": None, "detail": None},
    "update": {"installed_version": None},
    "identity": {"motion_is_identity": None, "local_face_recognition": None},
    "diagnostics": {"important_count": None},
    "voice": {"turn_id": None, "timings_ms": {k: None for k in (
        "prepare_ms", "listen_ms", "stt_ms", "brain_ms", "ai_ms", "actions_ms", "tts_ms", "total_ms")},
        "providers": {"stt": None, "tts": None}, "failure_stage": None, "first_audio_or_failure": None},
    "health": {"report_id": None, "checked_at_ms": None, "modules": [MODULE],
               "tests_are_synthetic": None, "offline_watchdog": None, "reset_at_ms": None, "reset_count": None},
    "incidents": {"report_id": None, "active_count": None, "resolved_count": None, "pages": None,
                  "dropped_history": None, "capacity": None, "reported_at_ms": None, "complete": None,
                  "reset_at_ms": None, "reset_count": None},
}
PAGE = {"report_id": None, "page": None, "records": [INCIDENT]}


def _project(value: Any, schema: Any) -> Any:
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            return None
        return {key: _project(item, schema[key]) for key, item in value.items() if key in schema}
    if isinstance(schema, list):
        if not isinstance(value, (list, tuple)):
            return None
        # Known reports contain 32 records/page. Oversized fields are omitted visibly, never silently truncated.
        if len(value) > 128:
            return {"export_error": "diagnostic list exceeds 128 items"}
        return [_project(item, schema[0]) for item in value]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value if len(value) <= 2000 else "[DIAGNOSTIC_TEXT_TOO_LONG]"
    return None


def select_kim_attributes(entity_id: str, attrs: dict[str, Any]) -> dict[str, Any]:
    match = re.fullmatch(r"sensor\.kim_([a-z_]+|incidents_(?:0[0-9]|1[0-5]))", entity_id)
    if not match:
        return {}
    name = match.group(1)
    schema = PAGE if name.startswith("incidents_") else SCHEMAS.get(name)
    if schema is None:
        return {}
    return _project(attrs, {**COMMON, **schema})
