"""Focused tests for the persistent Konke forensic recorder."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from custom_components.konke.forensics import (
    REDACTED,
    KonkeForensicRecorder,
    analyze_forensic_events,
    sanitize_forensics,
)
from homeassistant.util.file import WriteError


def _event(
    seq: int,
    kind: str,
    channel: str,
    recorded_at: str,
    data: dict,
    *,
    operation_id: str | None = None,
) -> dict:
    return {
        "seq": seq,
        "recorded_at": recorded_at,
        "kind": kind,
        "channel": channel,
        "entry_id": "entry",
        "operation_id": operation_id,
        "context": None,
        "data": data,
    }


def _poll_metadata(
    minute: int,
    *,
    failed_area_ids: list[str] | None = None,
) -> dict:
    return {
        "started_at": f"2026-08-11T00:{minute:02d}:00+00:00",
        "completed_at": f"2026-08-11T00:{minute:02d}:01+00:00",
        "failed_area_ids": failed_area_ids or [],
        "area_requests": [],
    }


def _device(*, power: int, update_time: int, timing_enabled: bool) -> dict:
    return {
        "userDeviceId": "device-1",
        "deviceName": "Living room AC",
        "areaId": "area-1",
        "updateTime": update_time,
        "timingOffEnable": timing_enabled,
        "timingOffTime": 30 if timing_enabled else 0,
        "cache": {
            "extension": {
                "current": {
                    "turnOnOff": power,
                    "times": [
                        {
                            "enabled": timing_enabled,
                            "time": "14:00",
                        }
                    ],
                }
            }
        },
    }


def test_recursive_redaction_and_deterministic_nested_values() -> None:
    """Secrets are removed at every depth and unordered values are stable."""
    jwt = f"eyJ{'a' * 24}.{'b' * 12}.{'c' * 12}"
    value = {
        "Authorization": "Bearer top-secret",
        "nested": {
            "Access_Token": "access-secret",
            "apiTOKEN": "api-secret",
            "mobile-number": "13800138000",
            "Pass-word": "password-secret",
            "PhoneNumber": "13900139000",
            "url": (
                "https://example.test/list?access-token=query-secret"
                "&mobile_number=13700137000"
            ),
            "jwt": jwt,
        },
        "unordered": {"z", "a", "m"},
        "free_text": (
            "Authorization: opaque-secret password=plain-secret "
            'token: "json-secret" {"password": "two word secret"} '
            "owner 13600136000"
        ),
    }

    sanitized = sanitize_forensics(value)
    encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)

    assert sanitized["Authorization"] == REDACTED
    assert sanitized["nested"]["Access_Token"] == REDACTED
    assert sanitized["nested"]["apiTOKEN"] == REDACTED
    assert sanitized["nested"]["mobile-number"] == REDACTED
    assert sanitized["nested"]["Pass-word"] == REDACTED
    assert sanitized["nested"]["PhoneNumber"] == REDACTED
    assert sanitized["unordered"] == ["a", "m", "z"]
    assert sanitized == sanitize_forensics(value)
    for secret in (
        "top-secret",
        "access-secret",
        "api-secret",
        "password-secret",
        "13800138000",
        "13900139000",
        "query-secret",
        "13700137000",
        "13600136000",
        "opaque-secret",
        "plain-secret",
        "json-secret",
        "two word secret",
        jwt,
    ):
        assert secret not in encoded


@pytest.mark.asyncio
async def test_pruning_counts_each_evidence_loss_reason(hass) -> None:
    """Age, count, and byte caps retain explicit evidence-loss counters."""
    count_recorder = KonkeForensicRecorder(
        hass,
        "forensic-count",
        max_events=2,
    )
    for index in range(3):
        await count_recorder.async_record(
            "sample",
            "test",
            {"index": index},
            immediate=True,
        )
    count_export = await count_recorder.async_export()
    assert count_export["stats"]["retained_events"] == 2
    assert count_export["stats"]["dropped_by_count"] == 1
    assert count_export["analysis"]["coverage_gap_present"] is True
    assert "dropped_by_count" in count_export["analysis"]["coverage_gap_reasons"]

    old = (datetime.now(UTC) - timedelta(days=31)).isoformat()
    age_recorder = KonkeForensicRecorder(hass, "forensic-age")
    await age_recorder.async_record(
        "old_sample",
        "test",
        recorded_at=old,
        immediate=True,
    )
    age_export = await age_recorder.async_export()
    assert age_export["stats"]["retained_events"] == 0
    assert age_export["stats"]["dropped_by_age"] == 1

    size_recorder = KonkeForensicRecorder(
        hass,
        "forensic-size",
        max_bytes=1,
    )
    await size_recorder.async_record(
        "large_sample",
        "test",
        {"payload": "large enough to exceed one byte"},
        immediate=True,
    )
    size_export = await size_recorder.async_export()
    assert size_export["stats"]["retained_events"] == 0
    assert size_export["stats"]["dropped_by_size"] == 1


@pytest.mark.asyncio
async def test_transition_that_causes_pruning_keeps_the_gap_reason(hass) -> None:
    """A just-pruned write cannot become a false no-write conclusion."""
    recorder = KonkeForensicRecorder(hass, "forensic-prune-transition", max_events=1)
    await recorder.async_record(
        "outbound_attempt",
        "ha_write",
        {"user_device_id": "device-1", "action_name": "TurnOff"},
        operation_id="operation-1",
        immediate=True,
    )
    await recorder.async_record(
        "websocket_report",
        "websocket",
        {"user_device_ids": ["device-1"]},
        immediate=True,
    )

    exported = await recorder.async_export()
    transition = exported["analysis"]["transitions"][0]
    assert transition["verdict"] == "insufficient_coverage"
    assert "dropped_by_count" in transition["coverage_gap_reasons"]


@pytest.mark.asyncio
async def test_poll_baseline_survives_restart_and_failed_area(hass) -> None:
    """A failed area cannot replace its persisted baseline with an empty result."""
    initial = KonkeForensicRecorder(hass, "forensic-baseline")
    await initial.async_load()
    await initial.async_record_poll(
        {"devices": [_device(power=1, update_time=1, timing_enabled=True)]},
        _poll_metadata(0),
        success=True,
    )
    await initial.async_shutdown()

    restarted = KonkeForensicRecorder(hass, "forensic-baseline")
    await restarted.async_load()
    await restarted.async_record_poll(
        {"devices": [_device(power=0, update_time=999, timing_enabled=False)]},
        _poll_metadata(1, failed_area_ids=["area-1"]),
        success=True,
    )
    await restarted.async_record_poll(
        {"devices": [_device(power=0, update_time=2, timing_enabled=False)]},
        _poll_metadata(2),
        success=True,
    )

    exported = await restarted.async_export()
    assert not [
        event for event in exported["events"] if event["kind"] == "device_missing"
    ]
    changes = [event for event in exported["events"] if event["kind"] == "state_change"]
    assert len(changes) == 1
    assert changes[0]["data"]["user_device_id"] == "device-1"
    paths = {change["path"] for change in changes[0]["data"]["changes"]}
    assert paths >= {
        "/cache/extension/current/times",
        "/cache/extension/current/turnOnOff",
        "/timingOffEnable",
        "/timingOffTime",
        "/updateTime",
    }
    timing_paths = {item["path"] for item in changes[0]["data"]["timing_configuration"]}
    assert timing_paths == {
        "/cache/extension/current/times",
        "/timingOffEnable",
        "/timingOffTime",
    }
    assert exported["analysis"]["transitions"][0]["verdict"] == "poll_window_only"


@pytest.mark.asyncio
async def test_cache_only_devices_are_diffed_and_can_disappear(hass) -> None:
    """The forensic-only collection participates in diffs without HA entities."""
    recorder = KonkeForensicRecorder(hass, "forensic-cache-only")
    initial = _device(power=1, update_time=1, timing_enabled=False)
    initial["_forensicCacheOnly"] = True
    changed = _device(power=0, update_time=2, timing_enabled=False)
    changed["_forensicCacheOnly"] = True

    await recorder.async_record_poll(
        {"devices": [], "forensic_devices": [initial]},
        _poll_metadata(0),
        success=True,
    )
    await recorder.async_record_poll(
        {"devices": [], "forensic_devices": [changed]},
        _poll_metadata(1),
        success=True,
    )
    await recorder.async_record_poll(
        {"devices": [], "forensic_devices": []},
        _poll_metadata(2),
        success=True,
    )

    exported = await recorder.async_export()
    assert any(event["kind"] == "state_change" for event in exported["events"])
    missing = [
        event for event in exported["events"] if event["kind"] == "device_missing"
    ]
    assert missing[-1]["data"]["user_device_id"] == "device-1"


def test_analysis_expands_websocket_targets_and_stays_conservative() -> None:
    """Frame members are deterministic and missing evidence prevents absolutes."""
    events = [
        _event(
            1,
            "outbound_result",
            "device_control",
            "2026-08-11T00:00:00+00:00",
            {
                "success": True,
                "message_id": "message-1",
                "user_device_id": "device-2",
                "action_name": "TurnOff",
            },
            operation_id="operation-1",
        ),
        _event(
            2,
            "websocket_report",
            "websocket",
            "2026-08-11T00:00:01+00:00",
            {
                "message_id": "message-1",
                "user_device_ids": ["device-2", "device-1", "device-2"],
            },
        ),
        _event(
            3,
            "websocket_report",
            "websocket",
            "2026-08-11T00:20:00+00:00",
            {"user_device_ids": ["device-3"]},
        ),
    ]

    complete = analyze_forensic_events(events)
    assert complete["transition_count"] == 3
    first_frame = complete["transitions"][:2]
    assert [item["user_device_id"] for item in first_frame] == [
        "device-1",
        "device-2",
    ]
    assert {item["verdict"] for item in first_frame} == {"ha_message_id_match"}
    assert all(item["same_frame_order_is_causal"] is False for item in first_frame)
    assert complete["transitions"][2]["verdict"] == "no_plugin_write_observed"

    incomplete = analyze_forensic_events(
        [events[2]],
        stats={"storage_errors": 1, "dropped_by_count": 2},
    )
    assert incomplete["coverage_gap_present"] is True
    assert incomplete["coverage_gap_reasons"] == [
        "dropped_by_count",
        "storage_errors",
    ]
    assert incomplete["transitions"][0]["verdict"] == "insufficient_coverage"

    retention_gap = analyze_forensic_events(
        [events[2]],
        stats={"dropped_by_age": 1},
    )
    assert retention_gap["transitions"][0]["verdict"] == "no_plugin_write_observed"


@pytest.mark.asyncio
async def test_disabled_recorder_retains_history_without_appending(hass) -> None:
    """Loading disabled preserves old evidence but forces a disabled listener."""
    enabled = KonkeForensicRecorder(hass, "forensic-disabled")
    await enabled.async_load()
    await enabled.async_record(
        "websocket_report",
        "websocket",
        {"user_device_ids": ["device-1"]},
        immediate=True,
    )
    await enabled.async_set_listener_status("connected")
    await enabled.async_shutdown()

    disabled = KonkeForensicRecorder(hass, "forensic-disabled", enabled=False)
    await disabled.async_load()
    before = await disabled.async_export()
    assert before["status"]["listener_state"] == "disabled"
    assert before["stats"]["retained_events"] == 2

    assert await disabled.async_record("ignored", "test", immediate=True) is None
    await disabled.async_record_poll(
        {"devices": [_device(power=0, update_time=2, timing_enabled=False)]},
        _poll_metadata(3),
        success=True,
    )
    await disabled.async_set_listener_status("connected")

    after = await disabled.async_export()
    assert after["status"]["listener_state"] == "disabled"
    assert after["stats"]["retained_events"] == 2
    assert after["analysis"]["coverage_gap_reasons"] == ["recording_disabled"]
    assert after["analysis"]["transitions"][0]["verdict"] == ("insufficient_coverage")


@pytest.mark.asyncio
async def test_reenabled_recorder_marks_first_diff_after_disabled_interval(
    hass,
) -> None:
    """A disabled interval remains a boundary for the first later baseline diff."""
    initial = KonkeForensicRecorder(hass, "forensic-disabled-gap")
    await initial.async_load()
    await initial.async_update_recording_state()
    await initial.async_record_poll(
        {"devices": [_device(power=1, update_time=1, timing_enabled=False)]},
        _poll_metadata(0),
        success=True,
    )
    await initial.async_shutdown()

    disabled = KonkeForensicRecorder(hass, "forensic-disabled-gap", enabled=False)
    await disabled.async_load()
    await disabled.async_update_recording_state()
    await disabled.async_shutdown()

    resumed = KonkeForensicRecorder(hass, "forensic-disabled-gap")
    await resumed.async_load()
    await resumed.async_update_recording_state()
    await resumed.async_record_poll(
        {"devices": [_device(power=0, update_time=2, timing_enabled=False)]},
        _poll_metadata(1),
        success=True,
    )
    await resumed.async_record_poll(
        {"devices": [_device(power=1, update_time=3, timing_enabled=False)]},
        _poll_metadata(2),
        success=True,
    )

    exported = await resumed.async_export()
    transitions = exported["analysis"]["transitions"]
    assert transitions[0]["verdict"] == "insufficient_coverage"
    assert "recording_disabled_interval" in transitions[0]["coverage_gap_reasons"]
    assert transitions[1]["verdict"] == "poll_window_only"
    assert exported["status"]["recording_breaks"]


@pytest.mark.asyncio
async def test_runtime_restart_marks_first_diff_as_coverage_gap(hass) -> None:
    """A clean HA stop/start cannot be mistaken for continuous observation."""
    initial = KonkeForensicRecorder(hass, "forensic-runtime-gap")
    await initial.async_load()
    await initial.async_update_recording_state()
    await initial.async_record_poll(
        {"devices": [_device(power=1, update_time=1, timing_enabled=False)]},
        _poll_metadata(0),
        success=True,
    )
    await initial.async_mark_runtime_stopped()

    resumed = KonkeForensicRecorder(hass, "forensic-runtime-gap")
    await resumed.async_load()
    await resumed.async_update_recording_state()
    await resumed.async_record_poll(
        {"devices": [_device(power=0, update_time=2, timing_enabled=False)]},
        _poll_metadata(1),
        success=True,
    )

    transition = (await resumed.async_export())["analysis"]["transitions"][0]
    assert transition["verdict"] == "insufficient_coverage"
    assert "recorder_stopped_interval" in transition["coverage_gap_reasons"]


@pytest.mark.asyncio
async def test_store_write_and_corrupt_file_failures_are_visible(hass) -> None:
    """Store failures increment counters instead of looking like no evidence."""
    recorder = KonkeForensicRecorder(hass, "forensic-storage-errors")
    with patch(
        "homeassistant.helpers.storage.Store._async_write_data",
        side_effect=WriteError("disk full"),
    ):
        await recorder.async_record("write_failure", "test", immediate=True)
    failed = await recorder.async_export()
    assert failed["stats"]["storage_errors"] == 1
    assert "storage_errors" in failed["status"]["current_coverage_gaps"]

    corrupt = KonkeForensicRecorder(hass, "forensic-corrupt-json")
    path = Path(corrupt._store.path)  # noqa: SLF001 - corruption fixture
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    loaded = KonkeForensicRecorder(hass, "forensic-corrupt-json")
    await loaded.async_load()
    recovered = await loaded.async_export()
    assert recovered["stats"]["storage_errors"] > 0
    assert any(event["kind"] == "storage_error" for event in recovered["events"])


def test_failed_outbound_result_remains_an_attribution_candidate() -> None:
    """An exception after send cannot be treated as proof no write occurred."""
    events = [
        _event(
            1,
            "outbound_attempt",
            "ha_write",
            "2026-08-11T00:00:00+00:00",
            {"user_device_id": "device-1", "action_name": "TurnOff"},
            operation_id="operation-1",
        ),
        _event(
            2,
            "outbound_result",
            "ha_write",
            "2026-08-11T00:00:01+00:00",
            {
                "user_device_id": "device-1",
                "action_name": "TurnOff",
                "success": False,
                "error_type": "TimeoutError",
            },
            operation_id="operation-1",
        ),
        _event(
            3,
            "websocket_report",
            "websocket",
            "2026-08-11T00:00:02+00:00",
            {"user_device_ids": ["device-1"]},
        ),
    ]

    analysis = analyze_forensic_events(events)
    transition = analysis["transitions"][0]
    assert transition["verdict"] == "ha_write_time_target_candidate"
    assert transition["candidates"][0]["result_success"] is False


def test_analysis_attaches_timer_and_multicontrol_configuration_only() -> None:
    """Configuration evidence is exposed without calling it a trigger."""
    events = [
        _event(
            1,
            "scene_snapshot_changed",
            "scene_snapshot",
            "2026-08-11T00:00:00+00:00",
            {
                "snapshot": {
                    "scene-1": {
                        "sceneType": "MultiControl",
                        "sceneName": "Living room AC group",
                        "actionSimpleV2List": [
                            {"userDeviceId": "device-1"},
                            {"userDeviceId": "device-2"},
                        ],
                    }
                }
            },
        ),
        _event(
            2,
            "state_change",
            "poll",
            "2026-08-11T00:01:00+00:00",
            {
                "user_device_id": "device-1",
                "changes": [
                    {"path": "/cache/on", "before": 1, "after": 0},
                    {
                        "path": "/cache/timingOffEnable",
                        "before": False,
                        "after": True,
                    },
                ],
            },
        ),
    ]

    analysis = analyze_forensic_events(events)
    transition = analysis["transitions"][0]
    assert transition["matching_multi_control_scene_ids"] == ["scene-1"]
    assert transition["timing_configuration_changes"] == [
        {
            "path": "/cache/timingOffEnable",
            "before": False,
            "after": True,
        }
    ]
    assert transition["configuration_evidence_is_trigger_evidence"] is False
    assert analysis["multi_control_topology"][0]["configuration_only"] is True


@pytest.mark.asyncio
async def test_malformed_stored_fields_recover_without_reusing_sequence(hass) -> None:
    """Partially malformed Store data is discarded without blocking startup."""
    recorder = KonkeForensicRecorder(hass, "forensic-corrupt")
    await recorder._store.async_save(  # noqa: SLF001 - intentional corruption fixture
        {
            "next_seq": "invalid",
            "events": [
                {
                    "seq": 9,
                    "recorded_at": datetime.now(UTC).isoformat(),
                    "kind": "sample",
                    "channel": "test",
                    "data": {},
                },
                {"seq": "broken"},
                "not-an-event",
            ],
            "device_baselines": ["invalid"],
            "scene_snapshot": "invalid",
            "status": ["invalid"],
            "stats": {"storage_errors": 0},
        }
    )

    loaded = KonkeForensicRecorder(hass, "forensic-corrupt")
    await loaded.async_load()
    event = await loaded.async_record("after_recovery", "test", immediate=True)
    exported = await loaded.async_export()

    assert event is not None
    assert event["seq"] == 10
    assert exported["stats"]["storage_errors"] > 0


@pytest.mark.asyncio
async def test_total_size_budget_includes_baselines_and_scene_snapshots(hass) -> None:
    """Large auxiliary snapshots cannot bypass the total Store size guard."""
    recorder = KonkeForensicRecorder(
        hass,
        "forensic-total-size",
        max_bytes=24 * 1024,
    )
    device = _device(power=1, update_time=1, timing_enabled=False)
    device["large_vendor_field"] = "x" * 12_000
    await recorder.async_record_poll(
        {"devices": [device]},
        _poll_metadata(0),
        success=True,
    )
    await recorder.async_record_scene_snapshot(
        {
            "scene-1": {
                "sceneType": "MultiControl",
                "large_vendor_field": "y" * 12_000,
            }
        }
    )

    exported = await recorder.async_export()
    serialized_size = len(
        json.dumps(recorder._serialize(), ensure_ascii=False).encode()  # noqa: SLF001
    )
    assert serialized_size <= recorder.max_bytes
    assert exported["stats"]["dropped_baselines_by_size"] == 1
    assert exported["stats"]["dropped_scene_snapshots_by_size"] == 1
    assert exported["analysis"]["coverage_gap_present"] is True
