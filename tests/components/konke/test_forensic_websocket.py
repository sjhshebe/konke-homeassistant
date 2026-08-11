"""Tests for the read-only Konke forensic WebSocket listener."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.konke.api import (
    WEBSOCKET_MESSAGE_BINARY,
    WEBSOCKET_MESSAGE_TEXT,
)
from custom_components.konke.const import CONF_ACCESS_TOKEN, DOMAIN
from custom_components.konke.coordinator import (
    KonkeDataUpdateCoordinator,
    _next_listener_retry,
)
from custom_components.konke.exceptions import KonkeAuthError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry


def _coordinator(hass, client) -> KonkeDataUpdateCoordinator:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={CONF_ACCESS_TOKEN: "access-secret"},
        entry_id="forensic-websocket-entry",
    )
    entry.add_to_hass(hass)
    return KonkeDataUpdateCoordinator(hass, entry, client)


@pytest.mark.asyncio
async def test_websocket_messages_are_classified_bounded_and_sanitized(hass) -> None:
    """DeviceReport stays structured while unsafe and opaque frames are bounded."""
    client = SimpleNamespace(
        access_token="access-secret", refresh_token="refresh-secret"
    )
    coordinator = _coordinator(hass, client)
    report = {
        "messageType": "DeviceReport",
        "messageId": "message-1",
        "data": {
            "userDevice": {
                "userDeviceId": "device-1",
                "updateTime": 1786400000000,
                "Authorization": "Bearer embedded-secret",
                "owner": "13800138000",
            }
        },
    }

    await coordinator._async_record_websocket_message(
        SimpleNamespace(type=WEBSOCKET_MESSAGE_TEXT, data=json.dumps(report))
    )
    await coordinator._async_record_websocket_message(
        SimpleNamespace(
            type=WEBSOCKET_MESSAGE_TEXT,
            data=json.dumps({"event": "unknown", "blob": "x" * 10_000}),
        )
    )
    await coordinator._async_record_websocket_message(
        SimpleNamespace(type=WEBSOCKET_MESSAGE_TEXT, data="not-json")
    )
    await coordinator._async_record_websocket_message(
        SimpleNamespace(type=WEBSOCKET_MESSAGE_BINARY, data=b"binary-secret")
    )
    exported = await coordinator.forensics.async_export()

    report_event = next(
        event for event in exported["events"] if event["kind"] == "websocket_report"
    )
    assert report_event["data"]["event_type"] == "DeviceReport"
    assert report_event["data"]["message_id"] == "message-1"
    assert report_event["data"]["user_device_id"] == "device-1"
    assert report_event["data"]["user_device_ids"] == ["device-1"]
    assert report_event["data"]["remote_time"] == "1786400000000"
    assert report_event["data"]["same_frame_order_is_causal"] is False

    unknown = next(
        event for event in exported["events"] if event["kind"] == "websocket_message"
    )
    assert unknown["data"]["payload"]["truncated"] is True
    unparsed = next(
        event for event in exported["events"] if event["kind"] == "websocket_unparsed"
    )
    assert set(unparsed["data"]) == {"length", "sha256"}
    binary = next(
        event for event in exported["events"] if event["kind"] == "websocket_binary"
    )
    assert set(binary["data"]) == {"length", "sha256"}

    encoded = json.dumps(exported, ensure_ascii=False)
    assert "embedded-secret" not in encoded
    assert "13800138000" not in encoded
    assert "binary-secret" not in encoded
    assert "access-secret" not in encoded


class _BlockingWebSocket:
    """Async iterator that remains connected until cancelled."""

    def __init__(self) -> None:
        self.receiving = asyncio.Event()
        self.close = AsyncMock()
        self.close_code = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.receiving.set()
        await asyncio.Event().wait()
        raise StopAsyncIteration


class _FiniteWebSocket:
    """Async iterator that emits fixed messages and then disconnects."""

    def __init__(self, *messages) -> None:
        self._messages = iter(messages)
        self.close = AsyncMock()
        self.close_code = 1006

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._messages)
        except StopIteration:
            raise StopAsyncIteration from None


@pytest.mark.asyncio
async def test_listener_unload_cancels_receive_and_closes_socket(hass) -> None:
    """Unload leaves no listener task and always closes the active socket."""
    websocket = _BlockingWebSocket()
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
        websocket_connect=AsyncMock(return_value=websocket),
    )
    coordinator = _coordinator(hass, client)

    coordinator.async_start_listener()
    await asyncio.wait_for(websocket.receiving.wait(), timeout=1)
    await coordinator.async_shutdown()

    assert coordinator._listener_task is None
    websocket.close.assert_awaited_once()
    assert coordinator.forensics.status["listener_state"] == "stopped"


@pytest.mark.asyncio
async def test_listener_auth_failure_is_isolated_from_rest_polling(hass) -> None:
    """An endpoint-specific listener rejection does not alter account auth."""
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
        websocket_connect=AsyncMock(side_effect=KonkeAuthError("expired")),
        fetch_data=AsyncMock(
            return_value={
                "devices": [],
                "forensic_scenes_by_id": {},
                "forensic_poll_metadata": {
                    "started_at": "2026-08-11T00:00:00+00:00",
                    "completed_at": "2026-08-11T00:00:01+00:00",
                    "failed_area_ids": [],
                    "failed_scene_room_ids": [],
                },
            }
        ),
    )
    coordinator = _coordinator(hass, client)
    coordinator.async_refresh_auth = AsyncMock()

    with patch.object(coordinator.config_entry, "async_start_reauth") as start_reauth:
        await coordinator._async_listener_loop()
        data = await coordinator._async_update_data()

    assert data["devices"] == []
    start_reauth.assert_not_called()
    coordinator.async_refresh_auth.assert_not_awaited()
    client.websocket_connect.assert_awaited_once()
    client.fetch_data.assert_awaited_once()
    assert coordinator.forensics.status["listener_state"] == "auth_error"


@pytest.mark.asyncio
async def test_access_token_rotation_reconnects_active_listener(hass) -> None:
    """A rotated REST token closes the old socket and opens a fresh listener."""
    first_websocket = _BlockingWebSocket()
    second_websocket = _BlockingWebSocket()
    websockets = iter((first_websocket, second_websocket))
    observed_tokens: list[str] = []
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
    )

    async def websocket_connect():
        observed_tokens.append(client.access_token)
        return next(websockets)

    client.websocket_connect = AsyncMock(side_effect=websocket_connect)
    coordinator = _coordinator(hass, client)

    coordinator.async_start_listener()
    await asyncio.wait_for(first_websocket.receiving.wait(), timeout=1)
    client.access_token = "rotated-secret"
    coordinator._update_entry_tokens(access_token="rotated-secret")
    await asyncio.wait_for(second_websocket.receiving.wait(), timeout=1)

    assert observed_tokens == ["access-secret", "rotated-secret"]
    first_websocket.close.assert_awaited_once()

    await coordinator.async_shutdown()

    assert coordinator._listener_task is None
    second_websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_access_token_rotation_restarts_auth_paused_listener(hass) -> None:
    """A REST-side token refresh resumes a listener paused by WS auth failure."""
    second_websocket = _BlockingWebSocket()
    first_attempted = asyncio.Event()
    observed_tokens: list[str] = []
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
    )

    async def websocket_connect():
        observed_tokens.append(client.access_token)
        if len(observed_tokens) == 1:
            first_attempted.set()
            raise KonkeAuthError("expired")
        return second_websocket

    client.websocket_connect = AsyncMock(side_effect=websocket_connect)
    coordinator = _coordinator(hass, client)

    coordinator.async_start_listener()
    await asyncio.wait_for(first_attempted.wait(), timeout=1)
    for _ in range(10):
        if coordinator._listener_task is None:
            break
        await asyncio.sleep(0)

    assert coordinator._listener_task is None
    assert coordinator.forensics.status["listener_state"] == "auth_error"

    client.access_token = "rotated-secret"
    coordinator._update_entry_tokens(access_token="rotated-secret")
    await asyncio.wait_for(second_websocket.receiving.wait(), timeout=1)

    assert observed_tokens == ["access-secret", "rotated-secret"]

    await coordinator.async_shutdown()

    second_websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_listener_task_does_not_prevent_shutdown_flush(hass) -> None:
    """A completed task exception is consumed before recorder shutdown."""
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
        websocket_connect=AsyncMock(),
    )
    coordinator = _coordinator(hass, client)
    coordinator._async_listener_loop = AsyncMock(
        side_effect=RuntimeError("listener failed")
    )
    recorder_shutdown = AsyncMock(wraps=coordinator.forensics.async_shutdown)
    coordinator.forensics.async_shutdown = recorder_shutdown

    coordinator.async_start_listener()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await coordinator.async_shutdown()

    assert coordinator._listener_task is None
    recorder_shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_is_idempotent_and_calls_coordinator_base_once(hass) -> None:
    """HA and integration unload hooks share one complete shutdown pass."""
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
    )
    coordinator = _coordinator(hass, client)
    recorder_shutdown = AsyncMock(wraps=coordinator.forensics.async_shutdown)
    coordinator.forensics.async_shutdown = recorder_shutdown

    with patch.object(
        DataUpdateCoordinator, "async_shutdown", new_callable=AsyncMock
    ) as base_shutdown:
        await coordinator.async_shutdown()
        await coordinator.async_shutdown()

    base_shutdown.assert_awaited_once()
    recorder_shutdown.assert_awaited_once()
    exported = await coordinator.forensics.async_export()
    assert sum(event["kind"] == "recorder_stopped" for event in exported["events"]) == 1


@pytest.mark.asyncio
async def test_messages_do_not_reset_listener_backoff(hass) -> None:
    """Short welcome frames followed by disconnects keep escalating retries."""
    welcome = SimpleNamespace(
        type=WEBSOCKET_MESSAGE_TEXT,
        data=json.dumps({"event": "welcome"}),
    )
    websockets = (_FiniteWebSocket(welcome), _FiniteWebSocket(welcome))
    client = SimpleNamespace(
        access_token="access-secret",
        refresh_token="refresh-secret",
        websocket_connect=AsyncMock(side_effect=websockets),
    )
    coordinator = _coordinator(hass, client)
    observed_indexes: list[int] = []

    def next_retry(index: int, _connected_duration: float) -> tuple[int, float]:
        observed_indexes.append(index)
        if len(observed_indexes) == 2:
            coordinator._listener_stop.set()
        return index + 1, 0

    with patch(
        "custom_components.konke.coordinator._next_listener_retry",
        side_effect=next_retry,
    ):
        await coordinator._async_listener_loop()

    assert observed_indexes == [0, 1]
    assert client.websocket_connect.await_count == 2
    assert all(websocket.close.await_count == 1 for websocket in websockets)


def test_stable_connection_resets_listener_backoff() -> None:
    """Only a sufficiently long-lived connection resets retry escalation."""
    with patch("custom_components.konke.coordinator.random.uniform", return_value=1.0):
        assert _next_listener_retry(4, 59) == (5, 30)
        assert _next_listener_retry(4, 60) == (1, 1)
