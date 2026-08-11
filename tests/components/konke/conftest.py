"""Shared pytest fixtures for Konke Home Assistant tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.konke.const import (
    AUTH_METHOD_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_AUTH_METHOD,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)

pytest_plugins = "pytest_homeassistant_custom_component"

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Allow Home Assistant to load this custom integration in tests."""
    yield


def load_devices() -> list[dict[str, Any]]:
    """Load sanitized fixture devices."""
    return json.loads((FIXTURES / "devices.json").read_text())


def home_payload() -> dict[str, Any]:
    """Return a minimal Konke home payload."""
    return {
        "homeId": "home-1",
        "homeName": "测试家庭",
    }


class FakeKonkeClient:
    """Fake Konke client used by HA integration tests."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.access_token = "fake-access-token"
        self.refresh_token = "fake-refresh-token"
        self.commands: list[dict[str, Any]] = []
        self.scene_calls: list[dict[str, Any]] = []
        self.devices = load_devices()
        self.refresh_access_token = AsyncMock(return_value={})
        self.login = AsyncMock(return_value={})

    async def fetch_data(
        self,
        configured_home_id: str | None = None,
        include_forensic_scenes: bool = False,
    ) -> dict[str, Any]:
        """Return normalized coordinator data."""
        from custom_components.konke.models import build_device_indexes

        indexes = build_device_indexes(self.devices)
        return {
            "home": home_payload() | {"homeId": configured_home_id or "home-1"},
            "rooms": [],
            "scenes": [
                {
                    "sceneId": "10",
                    "sceneName": "回家模式",
                    "sceneType": "Normal",
                    "roomName": "客厅",
                },
                {
                    "sceneId": "20",
                    "sceneName": "空调多控",
                    "sceneType": "MultiControl",
                    "roomName": "客厅",
                },
            ],
            "scenes_by_id": {
                "10": {
                    "sceneId": "10",
                    "sceneName": "回家模式",
                    "sceneType": "Normal",
                    "roomName": "客厅",
                },
                "20": {
                    "sceneId": "20",
                    "sceneName": "空调多控",
                    "sceneType": "MultiControl",
                    "roomName": "客厅",
                },
            },
            **indexes,
            "devices": self.devices,
            "normalized_devices": indexes["devices"],
            "normalized_devices_by_id": indexes["devices_by_id"],
            "forensic_scenes_by_id": {
                key: value
                for key, value in {
                    "10": {
                        "sceneId": "10",
                        "sceneName": "回家模式",
                        "sceneType": "Normal",
                        "roomName": "客厅",
                        "homeId": configured_home_id or "home-1",
                    },
                    "20": {
                        "sceneId": "20",
                        "sceneName": "空调多控",
                        "sceneType": "MultiControl",
                        "roomName": "客厅",
                        "homeId": configured_home_id or "home-1",
                    },
                }.items()
                if include_forensic_scenes or value["sceneType"] != "MultiControl"
            },
            "forensic_poll_metadata": {
                "started_at": "2026-08-11T00:00:00+00:00",
                "completed_at": "2026-08-11T00:00:01+00:00",
                "failed_area_ids": [],
                "area_requests": [],
            },
        }

    async def fetch_scene_detail(
        self, *, home_id: str | int, scene_id: str | int
    ) -> dict[str, Any]:
        """Return a stable read-only scene detail."""
        return {
            "sceneId": str(scene_id),
            "homeId": str(home_id),
            "sceneType": "MultiControl" if str(scene_id) == "20" else "Normal",
            "actionSimpleV2List": [],
        }

    async def execute_scene(self, *, home_id: str | int, scene_id: str | int) -> dict:
        """Record scene execution."""
        self.scene_calls.append({"home_id": str(home_id), "scene_id": str(scene_id)})
        return {"code": 200, "info": "SUCCESS", "data": {}}

    async def control_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        action_name: str,
        extension: dict[str, Any] | str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict:
        """Record a device command."""
        command = {
            "home_id": str(home_id),
            "user_device_id": str(user_device_id),
            "action_name": action_name,
            "extension": extension,
            "extra": extra,
        }
        self.commands.append(command)
        self._apply_device_action(user_device_id, action_name)
        return {"code": 200, "info": "SUCCESS", "data": {}}

    def _apply_device_action(
        self,
        user_device_id: str | int,
        action_name: str,
    ) -> None:
        """Apply state changes that tests need to observe after refresh."""
        device = next(
            (
                item
                for item in self.devices
                if str(item.get("userDeviceId")) == str(user_device_id)
            ),
            None,
        )
        if device is None:
            return
        state = device.setdefault("cache", {}).setdefault("extension", {})
        current = state.setdefault("current", {})
        if action_name == "AdjustDownWindSpeed":
            speed = max(1, int(current.get("windSpeed", state.get("windSpeed", 1))) - 1)
            state["windSpeed"] = speed
            current["windSpeed"] = speed
        elif action_name == "AdjustUpWindSpeed":
            speed = min(3, int(current.get("windSpeed", state.get("windSpeed", 1))) + 1)
            state["windSpeed"] = speed
            current["windSpeed"] = speed

    def extract_token_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return token fields from a fake payload."""
        token = payload.get("data", {}).get("userToken", {})
        return {
            "access_token": token.get("accessToken"),
            "refresh_token": token.get("refreshToken"),
        }

    def expires_at_from_payload(self, _payload: dict[str, Any]) -> str | None:
        """Return no expiry for fake tokens."""
        return None


@pytest.fixture(name="fake_client")
def fake_client_fixture() -> FakeKonkeClient:
    """Return a fake Konke client."""
    return FakeKonkeClient()


@pytest.fixture(name="konke_client_patch")
def konke_client_patch_fixture(fake_client: FakeKonkeClient):
    """Patch the integration API client constructor."""
    with patch("custom_components.konke.KonkeApiClient", return_value=fake_client):
        yield fake_client


@pytest.fixture(name="config_entry")
def config_entry_fixture():
    """Return a configured Konke config entry."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    return MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={
            CONF_AUTH_METHOD: AUTH_METHOD_TOKEN,
            CONF_ACCESS_TOKEN: "fake-access-token",
            CONF_REFRESH_TOKEN: "fake-refresh-token",
            CONF_HOME_ID: "home-1",
        },
        options={},
        entry_id="konke-test-entry",
    )


@pytest.fixture(name="entity_id_lookup")
def entity_id_lookup_fixture(hass):
    """Return entity ids from stable integration unique ids."""
    from homeassistant.helpers import entity_registry as er

    def lookup(platform: str, unique_id: str) -> str | None:
        return er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)

    return lookup
