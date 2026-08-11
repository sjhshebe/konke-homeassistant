"""Tests for coordinator-owned Konke write auditing."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from custom_components.konke.api import KonkeApiExchange
from custom_components.konke.const import CONF_ACCESS_TOKEN, DOMAIN
from custom_components.konke.coordinator import KonkeDataUpdateCoordinator
from custom_components.konke.exceptions import KonkeApiError, KonkeAuthError
from homeassistant.core import Context
from pytest_homeassistant_custom_component.common import MockConfigEntry


def _exchange(message_id: str) -> KonkeApiExchange:
    return KonkeApiExchange(
        payload={
            "code": 200,
            "info": "SUCCESS",
            "messageId": message_id,
        },
        http_status=200,
        started_at="2026-08-11T00:00:00+00:00",
        completed_at="2026-08-11T00:00:01+00:00",
        response_date="Tue, 11 Aug 2026 00:00:01 GMT",
    )


def _coordinator(hass) -> tuple[KonkeDataUpdateCoordinator, object]:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={CONF_ACCESS_TOKEN: "access-secret"},
        entry_id="forensic-write-entry",
    )
    entry.add_to_hass(hass)

    class Client:
        access_token = "access-secret"
        refresh_token = "refresh-secret"

        control_device_exchange = AsyncMock(return_value=_exchange("device-message"))
        execute_scene_exchange = AsyncMock(return_value=_exchange("scene-message"))

    client = Client()
    return KonkeDataUpdateCoordinator(hass, entry, client), client


@pytest.mark.asyncio
async def test_device_and_scene_success_are_audited_with_context(hass) -> None:
    """Successful writes retain request/result linkage without credentials."""
    coordinator, _client = _coordinator(hass)
    context = Context(user_id="admin-user")

    await coordinator.async_control_device(
        home_id="home-1",
        user_device_id="device-1",
        action_name="TurnOff",
        extension={
            "Authorization": "Bearer nested-secret",
            "owner": "13800138000",
        },
        context=context,
        source_entity_id="climate.living_room",
    )
    await coordinator.async_execute_scene(
        home_id="home-1",
        scene_id="scene-1",
        context=context,
        source_entity_id="scene.leave_home",
    )

    exported = await coordinator.forensics.async_export()
    writes = [
        event
        for event in exported["events"]
        if event["kind"] in {"outbound_attempt", "outbound_result"}
    ]
    assert len(writes) == 4
    assert len({event["operation_id"] for event in writes[:2]}) == 1
    assert len({event["operation_id"] for event in writes[2:]}) == 1
    assert all(event["context"]["id"] == context.id for event in writes)
    assert all(event["context"]["user_id"] == "admin-user" for event in writes)

    results = [event["data"] for event in writes if event["kind"] == "outbound_result"]
    assert [result["message_id"] for result in results] == [
        "device-message",
        "scene-message",
    ]
    assert all(result["success"] is True for result in results)
    assert all(result["duration_ms"] >= 0 for result in results)
    encoded = json.dumps(exported, ensure_ascii=False)
    assert "nested-secret" not in encoded
    assert "13800138000" not in encoded
    assert "access-secret" not in encoded


@pytest.mark.asyncio
async def test_device_auth_retry_records_both_attempts(hass) -> None:
    """An authentication retry keeps one operation and the first error metadata."""
    coordinator, client = _coordinator(hass)
    client.control_device_exchange = AsyncMock(
        side_effect=[
            KonkeAuthError(
                "expired",
                http_status=401,
                business_code=10001,
                business_info="token expired",
                message_id="auth-message",
            ),
            _exchange("retry-message"),
        ]
    )
    coordinator.async_refresh_auth = AsyncMock(return_value=True)

    await coordinator.async_control_device(
        home_id="home-1",
        user_device_id="device-1",
        action_name="TurnOn",
    )

    exported = await coordinator.forensics.async_export()
    retry = next(
        event for event in exported["events"] if event["kind"] == "outbound_auth_retry"
    )
    result = [
        event for event in exported["events"] if event["kind"] == "outbound_result"
    ][-1]
    assert retry["operation_id"] == result["operation_id"]
    assert retry["data"]["http_status"] == 401
    assert retry["data"]["business_code"] == 10001
    assert retry["data"]["message_id"] == "auth-message"
    assert result["data"]["attempts"] == 2
    assert result["data"]["message_id"] == "retry-message"
    assert client.control_device_exchange.await_count == 2


@pytest.mark.asyncio
async def test_scene_failure_is_saved_before_being_raised(hass) -> None:
    """Failed writes keep structured business metadata and remain observable."""
    coordinator, client = _coordinator(hass)
    client.execute_scene_exchange = AsyncMock(
        side_effect=KonkeApiError(
            "scene failed",
            http_status=503,
            business_code="E_DOWNSTREAM",
            business_info="temporarily unavailable",
            message_id="failed-message",
            started_at="2026-08-11T00:00:00+00:00",
            completed_at="2026-08-11T00:00:02+00:00",
        )
    )

    with pytest.raises(KonkeApiError, match="scene failed"):
        await coordinator.async_execute_scene(home_id="home-1", scene_id="scene-1")

    exported = await coordinator.forensics.async_export()
    result = [
        event for event in exported["events"] if event["kind"] == "outbound_result"
    ][-1]["data"]
    assert result["success"] is False
    assert result["http_status"] == 503
    assert result["business_code"] == "E_DOWNSTREAM"
    assert result["business_info"] == "temporarily unavailable"
    assert result["message_id"] == "failed-message"
    assert result["request_started_at"] == "2026-08-11T00:00:00+00:00"


@pytest.mark.asyncio
async def test_partial_scene_poll_preserves_last_complete_snapshot(hass) -> None:
    """A failed room request cannot look like a scene or MultiControl deletion."""
    coordinator, _client = _coordinator(hass)
    complete = {
        "forensic_scenes_by_id": {
            "scene-1": {
                "sceneId": "scene-1",
                "sceneType": "MultiControl",
                "sceneName": "Living room group",
            }
        },
        "forensic_poll_metadata": {
            "failed_scene_room_ids": [],
            "scene_requests": [],
        },
    }
    await coordinator._async_update_scene_snapshot(complete)
    before = await coordinator.forensics.async_export()

    await coordinator._async_update_scene_snapshot(
        {
            "forensic_scenes_by_id": {},
            "forensic_poll_metadata": {
                "failed_scene_room_ids": ["room-1"],
                "scene_requests": [
                    {"room_id": "room-1", "success": False, "http_status": 503}
                ],
            },
        }
    )
    after = await coordinator.forensics.async_export()

    assert after["latest_scene_snapshot"] == before["latest_scene_snapshot"]
    incomplete = [
        event
        for event in after["events"]
        if event["kind"] == "scene_snapshot_incomplete"
    ]
    assert incomplete[-1]["data"]["failed_room_ids"] == ["room-1"]
    assert incomplete[-1]["data"]["preserved_previous_snapshot"] is True


@pytest.mark.asyncio
async def test_scene_detail_failure_is_partial_and_throttled(hass) -> None:
    """Detail failures remain visible and are retried at most daily."""
    coordinator, client = _coordinator(hass)
    client.fetch_scene_detail = AsyncMock(side_effect=KonkeApiError("detail down"))
    data = {
        "forensic_scenes_by_id": {
            "scene-1": {
                "sceneId": "scene-1",
                "sceneType": "MultiControl",
                "sceneName": "Living room group",
            }
        },
        "forensic_poll_metadata": {
            "failed_scene_room_ids": [],
            "scene_requests": [],
        },
    }

    await coordinator._async_update_scene_snapshot(data)
    await coordinator._async_update_scene_snapshot(data)

    assert client.fetch_scene_detail.await_count == 1
    status = coordinator.forensics.status
    assert status["scene_snapshot_state"] == "partial"
    assert status["failed_scene_ids"] == ["scene-1"]
