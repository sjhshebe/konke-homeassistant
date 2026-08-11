"""Persistent forensic event recording for Konke Smart."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from homeassistant.core import Context, HomeAssistant
from homeassistant.helpers.storage import Store

from .const import DOMAIN

STORAGE_VERSION = 1
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_EVENTS = 20_000
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
SAVE_DELAY_SECONDS = 60
STORE_OVERHEAD_RESERVE = 16 * 1024

REDACTED = "**REDACTED**"

_SENSITIVE_KEYS = {
    "authorization",
    "accesstoken",
    "refreshtoken",
    "token",
    "tokenexpiresat",
    "password",
    "userpassword",
    "username",
    "mobile",
    "mobilenumber",
    "phone",
    "phonenumber",
    "telephone",
}
_URL_SECRET_RE = re.compile(
    r"([?&](?:authorization|access[_-]?token|refresh[_-]?token|token|password|"
    r"mobile(?:[_-]?number)?|phone(?:[_-]?number)?|telephone)=)[^&\s]+",
    re.IGNORECASE,
)
_STRING_SECRET_KEY = (
    r"(?:authorization|access[_-]?token|refresh[_-]?token|token|password|"
    r"user[_-]?password|mobile(?:[_-]?number)?|phone(?:[_-]?number)?|telephone)"
)
_QUOTED_STRING_SECRET_RE = re.compile(
    rf"(?P<prefix>[\"']?{_STRING_SECRET_KEY}[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"'])(?P<secret>.*?)(?P=quote)",
    re.IGNORECASE,
)
_STRING_SECRET_RE = re.compile(
    rf"(?P<prefix>[\"']?{_STRING_SECRET_KEY}[\"']?\s*[:=]\s*+)"
    r"(?P<secret>(?![\"'])(?:Bearer\s+)?[^,;}&\r\n]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~-]+", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+){1,2}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")


def utcnow_iso() -> str:
    """Return a millisecond-resolution UTC timestamp."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def context_data(context: Context | None) -> dict[str, str | None] | None:
    """Return the useful, JSON-safe parts of a Home Assistant context."""
    if context is None:
        return None
    return {
        "id": context.id,
        "parent_id": context.parent_id,
        "user_id": context.user_id,
    }


def _is_sensitive_key(normalized_key: str) -> bool:
    """Return whether a normalized mapping key identifies secret data."""
    return (
        normalized_key in _SENSITIVE_KEYS
        or normalized_key.endswith("token")
        or normalized_key.endswith("password")
    )


def _stable_json_sort_key(value: Any) -> str:
    """Return a deterministic ordering key for an already sanitized value."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sanitize_forensics(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact secrets and normalize values for JSON storage."""
    if _depth > 30:
        return "**MAX_DEPTH**"
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, Enum):
        return sanitize_forensics(value.value, _depth=_depth + 1)
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            key = str(raw_key)
            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            sanitized[key] = (
                REDACTED
                if _is_sensitive_key(normalized_key)
                else sanitize_forensics(item, _depth=_depth + 1)
            )
        return sanitized
    if isinstance(value, (set, frozenset)):
        sanitized_items = [
            sanitize_forensics(item, _depth=_depth + 1) for item in value
        ]
        return sorted(sanitized_items, key=_stable_json_sort_key)
    if isinstance(value, (list, tuple, deque)):
        return [sanitize_forensics(item, _depth=_depth + 1) for item in value]
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=UTC)
        return normalized.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {
            "binary": True,
            "length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, str):
        value = _BEARER_RE.sub(f"Bearer {REDACTED}", value)
        value = _QUOTED_STRING_SECRET_RE.sub(
            lambda match: (
                f"{match.group('prefix')}{match.group('quote')}"
                f"{REDACTED}{match.group('quote')}"
            ),
            value,
        )
        value = _STRING_SECRET_RE.sub(
            lambda match: f"{match.group('prefix')}{REDACTED}", value
        )
        value = _URL_SECRET_RE.sub(r"\1" + REDACTED, value)
        value = _JWT_RE.sub(REDACTED, value)
        return _PHONE_RE.sub(REDACTED, value)
    return sanitize_forensics(repr(value), _depth=_depth + 1)


def json_diff(before: Any, after: Any, path: str = "") -> list[dict[str, Any]]:
    """Return stable JSON-pointer changes between two sanitized snapshots."""
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        changes: list[dict[str, Any]] = []
        keys = sorted(set(before) | set(after), key=str)
        for key in keys:
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            child_path = f"{path}/{escaped}"
            if key not in before:
                changes.append(
                    {"path": child_path, "before": None, "after": after[key]}
                )
            elif key not in after:
                changes.append(
                    {"path": child_path, "before": before[key], "after": None}
                )
            else:
                changes.extend(json_diff(before[key], after[key], child_path))
        return changes
    if isinstance(before, list) and isinstance(after, list):
        if before == after:
            return []
        # Array positions returned by the cloud are not treated as event ordering.
        return [{"path": path or "/", "before": before, "after": after}]
    if before == after:
        return []
    return [{"path": path or "/", "before": before, "after": after}]


def _event_size(event: Mapping[str, Any]) -> int:
    return len(json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode())


def _error_summary(error: Exception | str) -> str:
    """Return a bounded sanitized error string for status and event metadata."""
    value = sanitize_forensics(str(error))
    return (value if isinstance(value, str) else type(error).__name__)[:500]


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _power_transition(changes: Any) -> bool:
    if not isinstance(changes, list):
        return False
    power_suffixes = (
        "/on",
        "/power",
        "/power_on",
        "/powerstate",
        "/switch",
        "/turnonoff",
    )
    return any(
        isinstance(change, Mapping)
        and str(change.get("path", "")).casefold().endswith(power_suffixes)
        and change.get("before") != change.get("after")
        for change in changes
    )


def _event_target_ids(data: Mapping[str, Any]) -> list[str | None]:
    """Return deterministic per-device targets without implying frame order."""
    target_ids: set[str] = set()
    target_id = data.get("user_device_id")
    if target_id is not None and str(target_id):
        target_ids.add(str(target_id))
    plural_targets = data.get("user_device_ids")
    if isinstance(plural_targets, (list, tuple, set, frozenset)):
        target_ids.update(
            str(item) for item in plural_targets if item is not None and str(item)
        )
    if not target_ids:
        return [None]
    return sorted(target_ids)


def _named_scalar_values(value: Any, normalized_keys: set[str]) -> set[str]:
    """Collect matching scalar values without assigning traversal order."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if (
                normalized in normalized_keys
                and item is not None
                and not isinstance(item, (Mapping, list, tuple, set, frozenset))
            ):
                found.add(str(item))
            found.update(_named_scalar_values(item, normalized_keys))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            found.update(_named_scalar_values(item, normalized_keys))
    return found


def _latest_scene_snapshot(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the most recently recorded structured scene snapshot."""
    snapshot: dict[str, Any] = {}
    for event in events:
        if event.get("kind") != "scene_snapshot_changed":
            continue
        data = event.get("data")
        candidate = data.get("snapshot") if isinstance(data, Mapping) else None
        if isinstance(candidate, Mapping):
            snapshot = {str(key): value for key, value in candidate.items()}
    return snapshot


def _multi_control_topology(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return read-only MultiControl membership hints from a scene snapshot."""
    topology: list[dict[str, Any]] = []
    for scene_id, scene in sorted(snapshot.items(), key=lambda item: str(item[0])):
        scene_types = {
            value.lower() for value in _named_scalar_values(scene, {"scenetype"})
        }
        if "multicontrol" not in scene_types:
            continue
        scene_names = sorted(_named_scalar_values(scene, {"scenename", "name"}))
        topology.append(
            {
                "scene_id": str(scene_id),
                "scene_name": scene_names[0] if scene_names else None,
                "user_device_ids": sorted(
                    _named_scalar_values(
                        scene,
                        {
                            "deviceid",
                            "targetdeviceid",
                            "userdeviceid",
                        },
                    )
                ),
                "configuration_only": True,
            }
        )
    return topology


def _timing_changes(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return timer-related state diffs as configuration evidence only."""
    changes = data.get("changes")
    if not isinstance(changes, list):
        return []
    timing_terms = ("/times", "/timingoffenable", "/timingofftime")
    return [
        deepcopy(change)
        for change in changes
        if isinstance(change, Mapping)
        and any(term in str(change.get("path", "")).lower() for term in timing_terms)
    ]


def _timing_configuration(value: Any, path: str = "") -> list[dict[str, Any]]:
    """Extract current timer fields without interpreting them as triggers."""
    fields: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            child_path = f"{path}/{escaped}"
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in {"times", "timingoffenable", "timingofftime"}:
                fields.append({"path": child_path, "value": deepcopy(item)})
                continue
            fields.extend(_timing_configuration(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            fields.extend(_timing_configuration(item, f"{path}/{index}"))
    return fields


def analyze_forensic_events(
    events: list[dict[str, Any]],
    *,
    stats: Mapping[str, Any] | None = None,
    recording_enabled: bool = True,
    scene_snapshot: Mapping[str, Any] | None = None,
    recording_breaks: list[Mapping[str, Any]] | None = None,
    recording_disabled_since: str | None = None,
) -> dict[str, Any]:
    """Build conservative attribution hints from retained events."""
    write_operations: dict[str, dict[str, Any]] = {}
    writes_by_message_id: dict[str, dict[str, Any]] = {}
    coverage_gap_reasons: set[str] = set()
    active_gap_reasons: set[str] = set()
    transitions: list[dict[str, Any]] = []

    if not recording_enabled:
        coverage_gap_reasons.add("recording_disabled")
        active_gap_reasons.add("recording_disabled")
    if recording_disabled_since:
        coverage_gap_reasons.add("recording_disabled_interval")
    for item in recording_breaks or []:
        coverage_gap_reasons.add(
            str(
                item.get("reason")
                if isinstance(item, Mapping) and item.get("reason")
                else "recording_disabled_interval"
            )
        )
    for counter in (
        "dropped_by_age",
        "dropped_by_count",
        "dropped_by_size",
        "dropped_baselines_by_size",
        "dropped_scene_snapshots_by_size",
        "oversize_events",
        "storage_errors",
    ):
        try:
            value = int((stats or {}).get(counter, 0))
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            coverage_gap_reasons.add(counter)
            if counter == "storage_errors":
                active_gap_reasons.add(counter)

    for event in events:
        kind = event.get("kind")
        if kind in {"coverage_gap", "history_cleared", "storage_error"}:
            coverage_gap_reasons.add(str(kind))
        if kind not in {"outbound_attempt", "outbound_result"}:
            continue
        raw_data = event.get("data")
        data = raw_data if isinstance(raw_data, Mapping) else {}
        operation_id = str(event.get("operation_id") or f"event:{event.get('seq')}")
        operation = write_operations.setdefault(
            operation_id,
            {
                "operation_id": event.get("operation_id"),
                "recorded_at": event.get("recorded_at"),
                "data": {},
                "result_recorded_at": None,
                "result_success": None,
            },
        )
        operation["data"].update(data)
        if kind == "outbound_attempt":
            operation["recorded_at"] = event.get("recorded_at")
        else:
            operation["result_recorded_at"] = event.get("recorded_at")
            operation["result_success"] = data.get("success")
        message_id = data.get("message_id")
        if message_id is not None:
            writes_by_message_id[str(message_id)] = operation

    observed_writes = sorted(
        write_operations.values(),
        key=lambda item: (
            str(item.get("recorded_at") or ""),
            str(item.get("operation_id") or ""),
        ),
    )
    if any(write.get("result_recorded_at") is None for write in observed_writes):
        coverage_gap_reasons.add("incomplete_outbound_operation")
        active_gap_reasons.add("incomplete_outbound_operation")

    topology = _multi_control_topology(
        scene_snapshot
        if isinstance(scene_snapshot, Mapping)
        else _latest_scene_snapshot(events)
    )

    for event in events:
        if event.get("kind") not in {"state_change", "websocket_report"}:
            continue
        raw_data = event.get("data")
        data = raw_data if isinstance(raw_data, Mapping) else {}
        event_gap_reasons = set(active_gap_reasons)
        raw_event_gaps = data.get("coverage_gap_reasons")
        if isinstance(raw_event_gaps, (list, tuple, set, frozenset)):
            event_gap_reasons.update(str(item) for item in raw_event_gaps)
        is_power_transition = event.get("kind") == "state_change" and _power_transition(
            data.get("changes")
        )

        message_id = data.get("message_id")
        exact = (
            writes_by_message_id.get(str(message_id))
            if message_id is not None
            else None
        )
        frame_target_ids = _event_target_ids(data)
        for target_id in frame_target_ids:
            observed_at = _parse_timestamp(event.get("recorded_at"))
            candidates: list[dict[str, Any]] = []
            if observed_at is not None:
                for write in observed_writes:
                    write_time = _parse_timestamp(write.get("recorded_at"))
                    raw_write_data = write.get("data")
                    write_data = (
                        raw_write_data if isinstance(raw_write_data, Mapping) else {}
                    )
                    if write_time is None or write_time > observed_at:
                        continue
                    if observed_at - write_time > timedelta(minutes=15):
                        continue
                    write_target = str(write_data.get("user_device_id") or "")
                    if target_id and write_target and target_id != write_target:
                        continue
                    candidates.append(
                        {
                            "operation_id": write.get("operation_id"),
                            "recorded_at": write.get("recorded_at"),
                            "result_recorded_at": write.get("result_recorded_at"),
                            "result_success": write.get("result_success"),
                            "action_name": write_data.get("action_name"),
                            "scene_id": write_data.get("scene_id"),
                        }
                    )

            if exact is not None:
                verdict = "ha_message_id_match"
                confidence = "strong"
            elif candidates:
                verdict = "ha_write_time_target_candidate"
                confidence = "candidate"
            elif event_gap_reasons:
                verdict = "insufficient_coverage"
                confidence = "unknown"
            elif event.get("channel") == "poll":
                verdict = "poll_window_only"
                confidence = "unknown"
            else:
                verdict = "no_plugin_write_observed"
                confidence = "limited"

            transitions.append(
                {
                    "event_seq": event.get("seq"),
                    "recorded_at": event.get("recorded_at"),
                    "user_device_id": target_id,
                    "frame_user_device_ids": frame_target_ids,
                    "same_frame_order_is_causal": False,
                    "is_power_transition": is_power_transition,
                    "verdict": verdict,
                    "confidence": confidence,
                    "coverage_gap_reasons": sorted(event_gap_reasons),
                    "matching_operation_id": (
                        exact.get("operation_id") if exact else None
                    ),
                    "candidates": candidates,
                    "timing_configuration": deepcopy(
                        data.get("timing_configuration") or []
                    ),
                    "timing_configuration_changes": _timing_changes(data),
                    "matching_multi_control_scene_ids": [
                        item["scene_id"]
                        for item in topology
                        if target_id is not None
                        and target_id in item["user_device_ids"]
                    ],
                    "configuration_evidence_is_trigger_evidence": False,
                    "caveat": (
                        "Absence of a plugin write does not identify an app, cloud, "
                        "automation, or hardware source."
                    ),
                }
            )

    return {
        "analysis_version": 2,
        "coverage_gap_present": bool(coverage_gap_reasons),
        "coverage_gap_reasons": sorted(coverage_gap_reasons),
        "observed_outbound_operations": len(observed_writes),
        "multi_control_topology": topology,
        "transition_count": len(transitions),
        "transitions": transitions,
    }


class _ForensicStore(Store[dict[str, Any]]):
    """Expose Store write failures that Home Assistant normally logs and swallows."""

    def __init__(
        self,
        hass: HomeAssistant,
        version: int,
        key: str,
        *,
        on_write_error: Callable[[Exception], None],
    ) -> None:
        super().__init__(
            hass,
            version,
            key,
            private=True,
            atomic_writes=True,
        )
        self._on_write_error = on_write_error
        self.write_error_count = 0

    async def _async_write_data(self, data: dict[str, Any]) -> None:
        try:
            await super()._async_write_data(data)
        except Exception as err:
            self.write_error_count += 1
            self._on_write_error(err)
            raise


class KonkeForensicRecorder:
    """Keep bounded, persistent evidence for one config entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        *,
        enabled: bool = True,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        """Initialize the recorder."""
        self.hass = hass
        self.entry_id = entry_id
        self.enabled = enabled
        self.retention_days = retention_days
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._store = _ForensicStore(
            hass,
            STORAGE_VERSION,
            f"{DOMAIN}.forensics.{entry_id}",
            on_write_error=self._record_storage_error,
        )
        self._lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._events: deque[dict[str, Any]] = deque()
        self._event_sizes: deque[int] = deque()
        self._event_bytes = 0
        self._next_seq = 1
        self._device_baselines: dict[str, dict[str, Any]] = {}
        self._scene_snapshot: dict[str, Any] = {}
        self._stats: dict[str, int] = {
            "dropped_by_age": 0,
            "dropped_by_count": 0,
            "dropped_by_size": 0,
            "dropped_baselines_by_size": 0,
            "dropped_scene_snapshots_by_size": 0,
            "oversize_events": 0,
            "storage_errors": 0,
        }
        self._status: dict[str, Any] = {
            "listener_state": "disabled" if not enabled else "stopped",
            "last_listener_event": None,
            "poll_state": "not_started",
            "failed_area_ids": [],
            "scene_snapshot_state": "not_started",
            "failed_scene_room_ids": [],
            "last_poll_started": None,
            "last_poll_success": None,
            "last_event": None,
            "last_error": None,
            "last_cleared_at": None,
            "last_storage_error_at": None,
            "recording_state": "enabled" if enabled else "disabled",
            "recording_disabled_since": None,
            "recording_breaks": [],
            "recorder_stopped_at": None,
            "pending_coverage_gap_reasons": [],
            "failed_scene_ids": [],
        }
        self._listeners: set[Callable[[], None]] = set()

    def _record_storage_error(self, error: Exception | str) -> None:
        """Record a persistence failure without attempting recursive persistence."""
        self._stats["storage_errors"] = self._stats.get("storage_errors", 0) + 1
        self._status["last_storage_error_at"] = utcnow_iso()
        self._status["last_error"] = _error_summary(error)
        self._mark_coverage_gap("storage_errors")
        self._notify_listeners()

    def _mark_coverage_gap(self, reason: str) -> None:
        """Keep a bounded in-memory/persisted marker for the next observed event."""
        reasons = self._status.setdefault("pending_coverage_gap_reasons", [])
        if not isinstance(reasons, list):
            reasons = []
            self._status["pending_coverage_gap_reasons"] = reasons
        if reason not in reasons:
            reasons.append(reason)

    async def async_update_recording_state(self) -> None:
        """Persist enable/disable intervals without creating forensic events."""
        async with self._lock:
            now = utcnow_iso()
            disabled_since = self._status.get("recording_disabled_since")
            stopped_at = self._status.get("recorder_stopped_at")
            breaks = self._status.get("recording_breaks")
            breaks = list(breaks) if isinstance(breaks, list) else []
            if self.enabled:
                if stopped_at and not disabled_since:
                    breaks.append(
                        {
                            "reason": "recorder_stopped_interval",
                            "started_at": stopped_at,
                            "ended_at": now,
                        }
                    )
                    self._mark_coverage_gap("recorder_stopped_interval")
                if disabled_since:
                    breaks.append(
                        {
                            "reason": "recording_disabled_interval",
                            "started_at": disabled_since,
                            "ended_at": now,
                        }
                    )
                    self._mark_coverage_gap("recording_disabled_interval")
                    self._status["recording_disabled_since"] = None
                self._status["recording_state"] = "enabled"
            else:
                if not disabled_since:
                    self._status["recording_disabled_since"] = now
                self._status["recording_state"] = "disabled"
            self._status["recording_breaks"] = breaks[-100:]
            self._status["recorder_stopped_at"] = None
            await self._async_save_locked()

    async def async_mark_runtime_stopped(self) -> None:
        """Persist the beginning of a runtime coverage gap without an event."""
        async with self._lock:
            self._status["recorder_stopped_at"] = utcnow_iso()
            await self._async_save_locked()

    async def async_load(self) -> None:
        """Load retained evidence and baselines."""
        store_path = Path(self._store.path)
        store_existed = await self.hass.async_add_executor_job(store_path.is_file)
        try:
            stored = await self._store.async_load()
        except Exception as err:  # Store failures must never block the integration.
            self._record_storage_error(err)
            return
        if not isinstance(stored, Mapping):
            if store_existed:
                self._record_storage_error("Forensic Store data was unavailable")
                if self.enabled:
                    await self.async_record(
                        "storage_error",
                        "storage",
                        {"error": "forensic_store_unavailable"},
                        immediate=True,
                    )
            return
        stored_stats = stored.get("stats")
        for key in (
            "storage_errors",
            "dropped_by_age",
            "dropped_by_count",
            "dropped_by_size",
            "dropped_baselines_by_size",
            "dropped_scene_snapshots_by_size",
            "oversize_events",
        ):
            try:
                self._stats[key] = int(
                    stored_stats.get(key, 0) if isinstance(stored_stats, Mapping) else 0
                )
            except (TypeError, ValueError):
                self._stats[key] = 0
                self._stats["storage_errors"] += 1
                self._mark_coverage_gap("storage_errors")
        if stored_stats is not None and not isinstance(stored_stats, Mapping):
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")
        try:
            self._next_seq = max(1, int(stored.get("next_seq", 1)))
        except (TypeError, ValueError):
            self._next_seq = 1
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")

        baselines = sanitize_forensics(stored.get("device_baselines") or {})
        if isinstance(baselines, Mapping):
            self._device_baselines = {
                str(key): dict(value)
                for key, value in baselines.items()
                if isinstance(value, Mapping)
            }
            if len(self._device_baselines) != len(baselines):
                self._stats["storage_errors"] += 1
                self._mark_coverage_gap("storage_errors")
        else:
            self._device_baselines = {}
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")

        scene_snapshot = sanitize_forensics(stored.get("scene_snapshot") or {})
        if isinstance(scene_snapshot, Mapping):
            self._scene_snapshot = dict(scene_snapshot)
        else:
            self._scene_snapshot = {}
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")

        stored_status = sanitize_forensics(stored.get("status") or {})
        if isinstance(stored_status, Mapping):
            pending_before_status = self._status.get("pending_coverage_gap_reasons")
            pending_before_status = (
                set(pending_before_status)
                if isinstance(pending_before_status, list)
                else set()
            )
            self._status.update(stored_status)
            stored_pending = self._status.get("pending_coverage_gap_reasons")
            pending_before_status.update(
                stored_pending if isinstance(stored_pending, list) else []
            )
            self._status["pending_coverage_gap_reasons"] = sorted(
                str(item) for item in pending_before_status
            )
        else:
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")
        if not self.enabled:
            self._status["listener_state"] = "disabled"
        stored_events = stored.get("events") or []
        if not isinstance(stored_events, list):
            stored_events = []
            self._stats["storage_errors"] += 1
            self._mark_coverage_gap("storage_errors")
        maximum_seq = 0
        for raw_event in stored_events:
            if not isinstance(raw_event, Mapping):
                self._stats["storage_errors"] += 1
                self._mark_coverage_gap("storage_errors")
                continue
            event = sanitize_forensics(raw_event)
            if not isinstance(event, Mapping):
                self._stats["storage_errors"] += 1
                self._mark_coverage_gap("storage_errors")
                continue
            event = dict(event)
            try:
                maximum_seq = max(maximum_seq, int(event.get("seq", 0)))
            except (TypeError, ValueError):
                self._stats["storage_errors"] += 1
                self._mark_coverage_gap("storage_errors")
            size = _event_size(event)
            self._events.append(event)
            self._event_sizes.append(size)
            self._event_bytes += size
        self._next_seq = max(self._next_seq, maximum_seq + 1)
        self._prune()

    def _serialize(self) -> dict[str, Any]:
        return {
            "next_seq": self._next_seq,
            "events": list(self._events),
            "device_baselines": self._device_baselines,
            "scene_snapshot": self._scene_snapshot,
            "stats": self._stats,
            "status": self._status,
        }

    def _prune(self) -> None:
        self._bound_auxiliary_data()
        cutoff = datetime.now(UTC) - timedelta(days=self.retention_days)
        recording_breaks = self._status.get("recording_breaks")
        if isinstance(recording_breaks, list):
            self._status["recording_breaks"] = [
                item
                for item in recording_breaks
                if isinstance(item, Mapping)
                and (
                    (timestamp := _parse_timestamp(item.get("ended_at"))) is None
                    or timestamp >= cutoff
                )
            ]
        while self._events:
            timestamp = _parse_timestamp(self._events[0].get("recorded_at"))
            if timestamp is None:
                self._drop_left("storage_errors")
                continue
            if timestamp >= cutoff:
                break
            self._drop_left("dropped_by_age")
        while len(self._events) > self.max_events:
            self._drop_left("dropped_by_count")
        event_budget = max(
            0,
            self.max_bytes - STORE_OVERHEAD_RESERVE - self._auxiliary_data_size(),
        )
        while self._events and self._event_bytes > event_budget:
            self._drop_left("dropped_by_size")

    def _auxiliary_data_size(self) -> int:
        """Return the serialized size of baselines and scene configuration."""
        return _event_size(
            {
                "device_baselines": self._device_baselines,
                "scene_snapshot": self._scene_snapshot,
            }
        )

    def _bound_auxiliary_data(self) -> None:
        """Keep non-event evidence inside the same total storage budget."""
        auxiliary_budget = max(0, self.max_bytes - STORE_OVERHEAD_RESERVE)
        if self._auxiliary_data_size() <= auxiliary_budget:
            return

        if self._scene_snapshot and not self._scene_snapshot.get("_truncated"):
            encoded = json.dumps(
                self._scene_snapshot,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            self._scene_snapshot = {
                "_truncated": True,
                "original_length": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
            self._stats["dropped_scene_snapshots_by_size"] += 1

        if self._auxiliary_data_size() <= auxiliary_budget:
            return

        retained: dict[str, dict[str, Any]] = {}
        for device_id, snapshot in sorted(self._device_baselines.items()):
            retained[device_id] = snapshot
            candidate_size = _event_size(
                {
                    "device_baselines": retained,
                    "scene_snapshot": self._scene_snapshot,
                }
            )
            if candidate_size > auxiliary_budget:
                retained.pop(device_id)
        dropped = len(self._device_baselines) - len(retained)
        if dropped:
            self._device_baselines = retained
            self._stats["dropped_baselines_by_size"] += dropped

    def _drop_left(self, counter: str) -> None:
        self._events.popleft()
        self._event_bytes -= self._event_sizes.popleft()
        self._stats[counter] += 1
        self._mark_coverage_gap(counter)

    async def _async_save_locked(self) -> None:
        error_count = self._store.write_error_count
        try:
            await self._store.async_save(self._serialize())
        except Exception as err:  # Persistence must not break device control.
            if self._store.write_error_count == error_count:
                self._record_storage_error(err)

    async def async_record(
        self,
        kind: str,
        channel: str,
        data: Mapping[str, Any] | None = None,
        *,
        operation_id: str | None = None,
        context: Context | None = None,
        recorded_at: str | None = None,
        immediate: bool = False,
    ) -> dict[str, Any] | None:
        """Append one event when recording is enabled."""
        if not self.enabled:
            return None
        async with self._lock:
            event_data = sanitize_forensics(data or {})
            pending_gaps = self._status.get("pending_coverage_gap_reasons")
            if (
                isinstance(event_data, dict)
                and kind in {"state_change", "websocket_report"}
                and isinstance(pending_gaps, list)
                and pending_gaps
            ):
                event_data.setdefault("coverage_gap_reasons", list(pending_gaps))
            event = {
                "seq": self._next_seq,
                "recorded_at": recorded_at or utcnow_iso(),
                "kind": str(kind),
                "channel": str(channel),
                "entry_id": self.entry_id,
                "operation_id": operation_id,
                "context": context_data(context),
                "data": event_data,
            }
            self._next_seq += 1
            size = _event_size(event)
            if size > MAX_EVENT_BYTES:
                original = json.dumps(
                    event["data"], ensure_ascii=False, separators=(",", ":")
                ).encode()
                event["data"] = {
                    "truncated": True,
                    "original_length": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                }
                if isinstance(pending_gaps, list) and pending_gaps:
                    event["data"]["coverage_gap_reasons"] = list(pending_gaps)
                self._stats["oversize_events"] += 1
                size = _event_size(event)
            self._events.append(event)
            self._event_sizes.append(size)
            self._event_bytes += size
            self._status["last_event"] = event["recorded_at"]
            self._prune()
            if kind in {"state_change", "websocket_report"}:
                current_gaps = self._status.get("pending_coverage_gap_reasons")
                if (
                    self._events
                    and self._events[-1] is event
                    and isinstance(current_gaps, list)
                    and current_gaps
                ):
                    existing_gaps = event["data"].get("coverage_gap_reasons") or []
                    merged_gaps = sorted(
                        {str(item) for item in [*existing_gaps, *current_gaps]}
                    )
                    if merged_gaps != existing_gaps:
                        old_size = self._event_sizes[-1]
                        event["data"]["coverage_gap_reasons"] = merged_gaps
                        new_size = _event_size(event)
                        self._event_sizes[-1] = new_size
                        self._event_bytes += new_size - old_size
                        self._prune()
            if immediate:
                await self._async_save_locked()
            else:
                self._store.async_delay_save(self._serialize, SAVE_DELAY_SECONDS)
            self._notify_listeners()
            return deepcopy(event)

    async def async_record_poll(
        self,
        data: Mapping[str, Any] | None,
        metadata: Mapping[str, Any],
        *,
        success: bool,
        error: Exception | str | None = None,
    ) -> None:
        """Record poll coverage and device changes, preserving the baseline."""
        async with self._operation_lock:
            await self._async_record_poll_serialized(
                data,
                metadata,
                success=success,
                error=error,
            )

    async def _async_record_poll_serialized(
        self,
        data: Mapping[str, Any] | None,
        metadata: Mapping[str, Any],
        *,
        success: bool,
        error: Exception | str | None = None,
    ) -> None:
        """Record one poll while clear/snapshot mutations are excluded."""
        if not self.enabled:
            return
        metadata = sanitize_forensics(metadata)
        self._status["last_poll_started"] = metadata.get("started_at")
        failed_areas = sorted(
            {str(item) for item in metadata.get("failed_area_ids") or []}
        )
        failed_scene_rooms = sorted(
            {str(item) for item in metadata.get("failed_scene_room_ids") or []}
        )
        self._status["failed_area_ids"] = failed_areas
        self._status["failed_scene_room_ids"] = failed_scene_rooms
        pending_gaps = self._status.get("pending_coverage_gap_reasons")
        pending_gaps = list(pending_gaps) if isinstance(pending_gaps, list) else []
        if success:
            self._status["last_poll_success"] = (
                metadata.get("completed_at") or utcnow_iso()
            )
            self._status["poll_state"] = "partial" if failed_areas else "complete"
            self._status["scene_snapshot_state"] = (
                "partial"
                if failed_scene_rooms or self._status.get("failed_scene_ids")
                else "complete"
            )
        else:
            self._status["poll_state"] = "failed"
            self._status["scene_snapshot_state"] = "unknown"
        await self.async_record(
            "poll_cycle",
            "poll",
            {
                **metadata,
                "success": success,
                "error": _error_summary(error) if error else None,
                "coverage_gap_reasons": pending_gaps,
            },
            immediate=not success or not isinstance(data, Mapping),
        )
        if not success or not isinstance(data, Mapping):
            return

        failed_areas = set(failed_areas)
        current: dict[str, dict[str, Any]] = {}
        raw_devices = data.get("forensic_devices")
        if not isinstance(raw_devices, list):
            raw_devices = data.get("devices") or []
        for index, raw in enumerate(raw_devices):
            if not isinstance(raw, Mapping) or raw.get("userDeviceId") is None:
                continue
            device_id = str(raw["userDeviceId"])
            # Preserve every recursively sanitized cloud field so newly observed
            # timing and vendor-specific state remains available for later diffing.
            snapshot = sanitize_forensics(raw)
            before = self._device_baselines.get(device_id)
            area_id = str(
                snapshot.get("areaId")
                if snapshot.get("areaId") is not None
                else (before or {}).get("areaId")
            )
            if area_id in failed_areas:
                if before is not None:
                    current[device_id] = before
                continue
            current[device_id] = snapshot
            if before is None:
                continue
            changes = json_diff(before, snapshot)
            if changes:
                await self.async_record(
                    "state_change",
                    "poll",
                    {
                        "user_device_id": device_id,
                        "device_name": snapshot.get("deviceName"),
                        "area_id": snapshot.get("areaId"),
                        "cache_index": index,
                        "cache_index_is_causal_order": False,
                        "changes": changes,
                        "timing_configuration": _timing_configuration(snapshot),
                        "remote_times": sorted(
                            _named_scalar_values(
                                snapshot,
                                {"eventtime", "timestamp", "updatetime"},
                            )
                        ),
                        "poll_started_at": metadata.get("started_at"),
                        "poll_completed_at": metadata.get("completed_at"),
                    },
                )

        for device_id, before in self._device_baselines.items():
            if device_id in current:
                continue
            area_id = str(before.get("areaId"))
            if area_id in failed_areas:
                current[device_id] = before
                continue
            await self.async_record(
                "device_missing",
                "poll",
                {
                    "user_device_id": device_id,
                    "device_name": before.get("deviceName"),
                    "area_id": before.get("areaId"),
                },
            )
        self._device_baselines = current
        async with self._lock:
            if not failed_areas:
                self._status["pending_coverage_gap_reasons"] = []
            self._prune()
            await self._async_save_locked()

    async def async_record_scene_snapshot(self, scenes: Mapping[str, Any]) -> None:
        """Record a changed, read-only scene and MultiControl snapshot."""
        async with self._operation_lock:
            await self._async_record_scene_snapshot_serialized(scenes)

    async def _async_record_scene_snapshot_serialized(
        self, scenes: Mapping[str, Any]
    ) -> None:
        """Record one configuration snapshot while clear/poll is excluded."""
        if not self.enabled:
            return
        snapshot = sanitize_forensics(scenes)
        encoded_snapshot = json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if (
            self._scene_snapshot.get("_truncated") is True
            and self._scene_snapshot.get("sha256")
            == hashlib.sha256(encoded_snapshot).hexdigest()
        ):
            return
        changes = json_diff(self._scene_snapshot, snapshot)
        if not changes:
            return
        await self.async_record(
            "scene_snapshot_changed",
            "scene_snapshot",
            {
                "changes": changes,
                "scene_count": len(snapshot),
                "snapshot": snapshot,
            },
        )
        async with self._lock:
            self._scene_snapshot = snapshot
            self._prune()
            self._store.async_delay_save(self._serialize, SAVE_DELAY_SECONDS)

    async def async_set_listener_status(
        self,
        state: str,
        *,
        error: Exception | str | None = None,
        retry_seconds: float | None = None,
    ) -> None:
        """Update and record WebSocket listener coverage."""
        if not self.enabled:
            self._status["listener_state"] = "disabled"
            return
        self._status["listener_state"] = state
        self._status["last_listener_event"] = utcnow_iso()
        if error is not None:
            self._status["last_error"] = _error_summary(error)
        await self.async_record(
            "listener_status",
            "websocket",
            {
                "state": state,
                "error": _error_summary(error) if error else None,
                "retry_seconds": retry_seconds,
            },
        )

    async def async_set_scene_snapshot_state(
        self,
        state: str,
        *,
        failed_scene_ids: list[str],
        failed_scene_room_ids: list[str],
    ) -> None:
        """Persist scene-summary/detail coverage independently from polling."""
        if not self.enabled:
            return
        async with self._lock:
            self._status["scene_snapshot_state"] = state
            self._status["failed_scene_ids"] = sorted(set(failed_scene_ids))
            self._status["failed_scene_room_ids"] = sorted(set(failed_scene_room_ids))
            self._store.async_delay_save(self._serialize, SAVE_DELAY_SECONDS)
            self._notify_listeners()

    async def async_export(self) -> dict[str, Any]:
        """Return the complete bounded evidence bundle for diagnostics."""
        async with self._lock:
            self._prune()
            events = deepcopy(list(self._events))
            status = deepcopy(self._status)
            status["current_coverage_gaps"] = self._current_coverage_gaps()
            return {
                "settings": {
                    "enabled": self.enabled,
                    "retention_days": self.retention_days,
                    "max_events": self.max_events,
                    "max_bytes": self.max_bytes,
                },
                "status": status,
                "stats": {**self._stats, "retained_events": len(events)},
                "latest_scene_snapshot": deepcopy(self._scene_snapshot),
                "events": events,
                "analysis": analyze_forensic_events(
                    events,
                    stats=self._stats,
                    recording_enabled=self.enabled,
                    scene_snapshot=self._scene_snapshot,
                    recording_breaks=(
                        self._status.get("recording_breaks")
                        if isinstance(self._status.get("recording_breaks"), list)
                        else None
                    ),
                    recording_disabled_since=self._status.get(
                        "recording_disabled_since"
                    ),
                ),
            }

    async def async_clear(self, context: Context | None = None) -> dict[str, int]:
        """Clear retained evidence while keeping an explicit coverage marker."""
        async with self._operation_lock:
            return await self._async_clear_serialized(context)

    async def _async_clear_serialized(
        self, context: Context | None = None
    ) -> dict[str, int]:
        """Clear evidence while poll and snapshot mutations are excluded."""
        async with self._lock:
            deleted = {
                "events": len(self._events),
                "device_baselines": len(self._device_baselines),
                "scenes": len(self._scene_snapshot),
            }
            self._events.clear()
            self._event_sizes.clear()
            self._event_bytes = 0
            self._device_baselines = {}
            self._scene_snapshot = {}
            cleared_at = utcnow_iso()
            self._status["last_cleared_at"] = cleared_at
            self._status["last_event"] = cleared_at
            self._status["poll_state"] = "baseline_cleared"
            self._status["failed_area_ids"] = []
            self._status["scene_snapshot_state"] = "cleared"
            self._status["failed_scene_room_ids"] = []
            self._status["failed_scene_ids"] = []
            self._status["recording_breaks"] = []
            self._status["pending_coverage_gap_reasons"] = ["history_cleared"]
            event = {
                "seq": self._next_seq,
                "recorded_at": cleared_at,
                "kind": "history_cleared",
                "channel": "service",
                "entry_id": self.entry_id,
                "operation_id": str(uuid.uuid4()),
                "context": context_data(context),
                "data": deleted,
            }
            self._next_seq += 1
            size = _event_size(event)
            self._events.append(event)
            self._event_sizes.append(size)
            self._event_bytes = size
            await self._async_save_locked()
            self._notify_listeners()
            return deleted

    async def async_shutdown(self) -> None:
        """Flush pending evidence during config-entry unload."""
        async with self._operation_lock, self._lock:
            await self._async_save_locked()

    async def async_remove(self) -> None:
        """Remove all storage for a deleted config entry."""
        await self._store.async_remove()

    @property
    def status(self) -> dict[str, Any]:
        """Return compact status for the diagnostic sensor."""
        return {
            **deepcopy(self._status),
            "current_coverage_gaps": self._current_coverage_gaps(),
            **self._stats,
            "retained_events": len(self._events),
            "enabled": self.enabled,
        }

    def _current_coverage_gaps(self) -> list[str]:
        """Return current recorder, polling, and listener coverage gaps."""
        gaps: list[str] = []
        if not self.enabled:
            gaps.append("recording_disabled")
        pending = self._status.get("pending_coverage_gap_reasons")
        if isinstance(pending, list):
            gaps.extend(str(item) for item in pending)
        poll_state = str(self._status.get("poll_state") or "not_started")
        if poll_state != "complete":
            gaps.append(f"poll_{poll_state}")
        scene_state = str(self._status.get("scene_snapshot_state") or "not_started")
        if scene_state != "complete":
            gaps.append(f"scene_snapshot_{scene_state}")
        listener_state = str(self._status.get("listener_state") or "stopped")
        if listener_state != "connected":
            gaps.append(f"websocket_{listener_state}")
        return sorted(set(gaps))

    def async_add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        """Subscribe a diagnostic entity to recorder status updates."""
        self._listeners.add(listener)

        def remove_listener() -> None:
            self._listeners.discard(listener)

        return remove_listener

    def _notify_listeners(self) -> None:
        for listener in tuple(self._listeners):
            listener()
