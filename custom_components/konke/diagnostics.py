"""Diagnostics support for Konke Smart."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, CONF_TOKEN_EXPIRES_AT, DOMAIN
from .forensics import sanitize_forensics
from .models import summarize_device

TO_REDACT = {
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_TOKEN_EXPIRES_AT,
    CONF_PASSWORD,
    CONF_USERNAME,
    "Authorization",
    "accessToken",
    "refreshToken",
    "mobile",
    "phone",
    "username",
    "userPassword",
    "authorization",
    "access_token",
    "refresh_token",
    "password",
}


def _diagnostic_data(data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a JSON-friendly diagnostic view of coordinator data."""
    if data is None:
        return None

    normalized_devices = data.get("normalized_devices", [])
    devices_by_id = data.get("normalized_devices_by_id", {})
    return {
        "home": data.get("home"),
        "rooms": data.get("rooms", []),
        "scene_count": len(data.get("scenes_by_id", {})),
        "device_count": len(data.get("devices", [])),
        "devices": [summarize_device(device) for device in normalized_devices],
        "entities": data.get("entities", []),
        "entity_mapping": _entity_mapping(data),
        "device_ids_by_room_id": data.get("device_ids_by_room_id", {}),
        "child_device_ids_by_parent_id": data.get("child_device_ids_by_parent_id", {}),
        "device_ids_by_capability": data.get("device_ids_by_capability", {}),
        "skipped_devices": data.get("skipped_devices", []),
        "normalized_device_ids": sorted(devices_by_id),
    }


def _entity_mapping(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a compact diagnostic view of generated entity descriptors."""
    return [
        {
            "unique_id": entity.get("unique_id"),
            "device_id": entity.get("device_id"),
            "capability": entity.get("capability"),
            "platform": entity.get("platform"),
            "room_name": entity.get("room_name"),
        }
        for entity in data.get("entities", [])
        if isinstance(entity, dict)
    ]


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = hass.data[DOMAIN].get(config_entry.entry_id)
    forensics = (
        await coordinator.forensics.async_export() if coordinator is not None else None
    )
    return async_redact_data(
        sanitize_forensics(
            {
                "entry": {
                    "title": config_entry.title,
                    "data": dict(config_entry.data),
                    "options": dict(config_entry.options),
                },
                "coordinator": {
                    "last_update_success": (
                        coordinator.last_update_success if coordinator else None
                    ),
                    "last_exception": (
                        str(coordinator.last_exception)
                        if coordinator and coordinator.last_exception
                        else None
                    ),
                },
                "data": _diagnostic_data(coordinator.data if coordinator else None),
                "forensics": forensics,
            }
        ),
        TO_REDACT,
    )
