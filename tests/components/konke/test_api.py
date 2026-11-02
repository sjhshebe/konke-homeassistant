"""Tests for Konke cloud API request constants."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.konke.api import (
    _SCENE_TYPES_FOR_FORENSICS,
    _SCENE_TYPES_FOR_SYNC,
    KonkeApiClient,
    KonkeApiExchange,
)
from custom_components.konke.exceptions import (
    KonkeApiError,
    KonkeCannotConnect,
)


def test_scene_sync_does_not_request_internal_multi_control() -> None:
    """Scene sync should only request user-facing scene types."""
    assert _SCENE_TYPES_FOR_SYNC == "Normal,ExternalScene"
    assert "MultiControl" not in _SCENE_TYPES_FOR_SYNC
    assert _SCENE_TYPES_FOR_FORENSICS == "Normal,ExternalScene,MultiControl"


@pytest.mark.asyncio
async def test_websocket_connect_uses_structured_timeouts() -> None:
    """The listener separates handshake, receive, and close timeouts."""
    websocket = object()
    session = SimpleNamespace(ws_connect=AsyncMock(return_value=websocket))
    client = KonkeApiClient(session, access_token="access-token")

    assert await client.websocket_connect() is websocket

    kwargs = session.ws_connect.await_args.kwargs
    assert kwargs["params"] == {"authorization": "access-token"}
    assert kwargs["autoping"] is True
    assert kwargs["heartbeat"] == 30
    assert "receive_timeout" not in kwargs
    assert type(kwargs["timeout"]).__name__ == "ClientWSTimeout"
    assert kwargs["timeout"].ws_receive == 90
    assert kwargs["timeout"].ws_close == 5


@pytest.mark.asyncio
async def test_websocket_handshake_has_independent_timeout() -> None:
    """A stalled HTTP upgrade is bounded separately from WebSocket I/O."""

    async def never_connect(*_args, **_kwargs):
        await asyncio.Event().wait()

    session = SimpleNamespace(ws_connect=AsyncMock(side_effect=never_connect))
    client = KonkeApiClient(session, access_token="access-token")

    with (
        patch(
            "custom_components.konke.api._WEBSOCKET_HANDSHAKE_TIMEOUT",
            0.01,
        ),
        pytest.raises(KonkeCannotConnect, match="timed out"),
    ):
        await client.websocket_connect()

    session.ws_connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_websocket_timeout_falls_back_for_older_runtime() -> None:
    """Older supported HA releases still import and connect."""
    session = SimpleNamespace(ws_connect=AsyncMock(return_value=object()))
    client = KonkeApiClient(session, access_token="access-token")

    with patch("custom_components.konke.api.ClientWSTimeout", None):
        await client.websocket_connect()

    kwargs = session.ws_connect.await_args.kwargs
    assert kwargs["timeout"] == 5
    assert kwargs["receive_timeout"] == 90


@pytest.mark.asyncio
async def test_fetch_devices_reads_every_reported_page() -> None:
    """Visible-device collection cannot silently stop at the first 100 items."""
    client = KonkeApiClient(object(), access_token="test-token")
    first_page = [{"userDeviceId": str(index)} for index in range(100)]
    client._request_exchange = AsyncMock(  # noqa: SLF001 - API boundary fixture
        side_effect=[
            KonkeApiExchange(
                {"data": {"pagePojo": {"list": first_page, "totalPage": 2}}},
                200,
                "2026-08-11T00:00:00+00:00",
                "2026-08-11T00:00:01+00:00",
                None,
            ),
            KonkeApiExchange(
                {
                    "data": {
                        "pagePojo": {
                            "list": [{"userDeviceId": "100"}],
                            "totalPage": 2,
                        }
                    }
                },
                200,
                "2026-08-11T00:00:01+00:00",
                "2026-08-11T00:00:02+00:00",
                None,
            ),
        ]
    )

    devices, metadata = await client.fetch_devices_exchange(
        home_id="home-1", area_id="area-1"
    )

    assert len(devices) == 101
    assert metadata["page_count"] == 2
    assert metadata["coverage_complete"] is True
    assert [
        call.kwargs["params"]["page"]
        for call in client._request_exchange.await_args_list
    ] == [  # noqa: SLF001
        1,
        2,
    ]


def _client_with_home() -> KonkeApiClient:
    client = KonkeApiClient(object(), access_token="test-token")
    client.fetch_home_index = AsyncMock(
        return_value={
            "data": {
                "home": {
                    "homeId": "home-1",
                    "homeName": "Test home",
                    "areaList": [
                        {
                            "areaId": "area-1",
                            "areaName": "Downstairs",
                            "roomList": [
                                {"roomId": "room-1", "roomName": "Living room"}
                            ],
                        }
                    ],
                }
            }
        }
    )
    return client


@pytest.mark.asyncio
async def test_fetch_data_records_area_and_scene_request_coverage() -> None:
    """Every room/area request contributes safe timing and coverage metadata."""
    client = _client_with_home()
    client.fetch_scenes_exchange = AsyncMock(
        return_value=(
            [
                {"sceneId": "10", "sceneType": "Normal"},
                {"sceneId": "20", "sceneType": "MultiControl"},
            ],
            {
                "started_at": "2026-08-11T00:00:00+00:00",
                "completed_at": "2026-08-11T00:00:01+00:00",
                "http_status": 200,
            },
        )
    )
    client.fetch_devices_exchange = AsyncMock(
        return_value=(
            [],
            {
                "started_at": "2026-08-11T00:00:01+00:00",
                "completed_at": "2026-08-11T00:00:02+00:00",
                "http_status": 200,
            },
        )
    )
    client.fetch_device_cache_exchange = AsyncMock(
        return_value=(
            [],
            {
                "started_at": "2026-08-11T00:00:02+00:00",
                "completed_at": "2026-08-11T00:00:03+00:00",
                "http_status": 200,
            },
        )
    )

    data = await client.fetch_data(include_forensic_scenes=True)

    assert set(data["scenes_by_id"]) == {"10"}
    assert set(data["forensic_scenes_by_id"]) == {"10", "20"}
    metadata = data["forensic_poll_metadata"]
    assert metadata["failed_area_ids"] == []
    assert metadata["failed_scene_room_ids"] == []
    assert [item["endpoint"] for item in metadata["area_requests"]] == [
        "/user/device",
        "/user/device/cache",
    ]
    assert metadata["scene_requests"][0]["endpoint"] == "/v2/scene"
    assert metadata["scene_requests"][0]["scene_count"] == 2
    assert metadata["scene_requests"][0]["success"] is True


@pytest.mark.asyncio
async def test_fetch_data_keeps_cache_only_devices_for_forensics() -> None:
    """Hidden/cache-only devices extend the baseline without becoming HA devices."""
    client = _client_with_home()
    client.fetch_scenes_exchange = AsyncMock(return_value=([], {}))
    client.fetch_devices_exchange = AsyncMock(
        return_value=(
            [{"userDeviceId": "visible-1", "areaId": "area-1"}],
            {"coverage_complete": True},
        )
    )
    client.fetch_device_cache_exchange = AsyncMock(
        return_value=(
            [
                {"userDeviceId": "visible-1", "updateTime": 1, "on": 1},
                {"userDeviceId": "hidden-1", "updateTime": 2, "on": 0},
            ],
            {},
        )
    )

    data = await client.fetch_data(include_forensic_scenes=True)

    assert [item["userDeviceId"] for item in data["devices"]] == ["visible-1"]
    assert {str(item["userDeviceId"]) for item in data["forensic_devices"]} == {
        "hidden-1",
        "visible-1",
    }
    hidden = next(
        item for item in data["forensic_devices"] if item["userDeviceId"] == "hidden-1"
    )
    assert hidden["_forensicCacheOnly"] is True
    assert hidden["cache"]["extension"]["on"] == 0


@pytest.mark.asyncio
async def test_fetch_data_marks_partial_area_and_scene_failures() -> None:
    """Partial failures keep their request timings and explicit coverage gaps."""
    client = _client_with_home()
    client.fetch_scenes_exchange = AsyncMock(
        side_effect=KonkeApiError(
            "scene unavailable",
            http_status=503,
            started_at="2026-08-11T00:00:00+00:00",
            completed_at="2026-08-11T00:00:01+00:00",
        )
    )
    client.fetch_devices_exchange = AsyncMock(
        return_value=(
            [],
            {
                "started_at": "2026-08-11T00:00:01+00:00",
                "completed_at": "2026-08-11T00:00:02+00:00",
                "http_status": 200,
            },
        )
    )
    client.fetch_device_cache_exchange = AsyncMock(
        side_effect=KonkeApiError(
            "cache unavailable",
            http_status=504,
            business_code="TIMEOUT",
            started_at="2026-08-11T00:00:02+00:00",
            completed_at="2026-08-11T00:00:05+00:00",
        )
    )

    data = await client.fetch_data(include_forensic_scenes=True)

    metadata = data["forensic_poll_metadata"]
    assert metadata["failed_area_ids"] == ["area-1"]
    assert metadata["failed_scene_room_ids"] == ["room-1"]
    cache_request = metadata["area_requests"][-1]
    assert cache_request["success"] is False
    assert cache_request["http_status"] == 504
    assert cache_request["business_code"] == "TIMEOUT"
    assert cache_request["started_at"] == "2026-08-11T00:00:02+00:00"
    assert metadata["scene_requests"][0]["success"] is False
    assert metadata["scene_requests"][0]["http_status"] == 503


@pytest.mark.asyncio
async def test_fetch_data_uses_configured_home_when_it_is_not_the_default() -> None:
    """The configured home drives areas/devices even when it is not the default."""
    client = KonkeApiClient(object(), access_token="test-token")
    default_index = {
        "data": {
            "home": {
                "homeId": "255027",
                "homeName": "自己的家",
                "areaList": [{"areaId": "own-area", "roomList": []}],
            }
        }
    }
    shared_index = {
        "data": {
            "home": {
                "homeId": "214716",
                "homeName": "共享的家",
                "areaList": [
                    {
                        "areaId": "shared-area",
                        "roomList": [
                            {"roomId": "room-1", "roomName": "客厅"}
                        ],
                    }
                ],
            }
        }
    }

    async def fetch_home_index(*, home_id: str = "0") -> dict:
        return default_index if str(home_id) == "0" else shared_index

    client.fetch_home_index = AsyncMock(side_effect=fetch_home_index)
    client.fetch_scenes_exchange = AsyncMock(return_value=([], {}))
    client.fetch_devices_exchange = AsyncMock(
        return_value=([{"userDeviceId": "device-1"}], {"coverage_complete": True})
    )
    client.fetch_device_cache_exchange = AsyncMock(return_value=([], {}))

    data = await client.fetch_data(configured_home_id="214716")

    assert data["home"]["homeId"] == "214716"
    assert [room["roomName"] for room in data["rooms"]] == ["客厅"]
    client.fetch_devices_exchange.assert_awaited_with(
        home_id="214716",
        area_id="shared-area",
    )
