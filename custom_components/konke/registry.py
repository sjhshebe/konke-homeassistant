"""Device registry helpers for the Konke Smart integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import CONF_HOME_ID, DOMAIN
from .coordinator import KonkeDataUpdateCoordinator
from .models import KonkeDevice
from .options import options_from_entry

MANUFACTURER = "Konke"


def home_identifier(home_id: str | int) -> tuple[str, str]:
    """Return the Home Assistant device identifier for a Konke home."""
    return (DOMAIN, str(home_id))


def device_identifier(device_id: str | int) -> tuple[str, str]:
    """Return the Home Assistant device identifier for a Konke device."""
    return (DOMAIN, str(device_id))


def home_device_info(
    *,
    home: Mapping[str, Any],
    home_id: str | int | None,
    entry_title: str,
) -> dict[str, Any]:
    """Return HA device info for the Konke home hub."""
    resolved_home_id = str(home.get("homeId") or home_id)
    return {
        "identifiers": {home_identifier(resolved_home_id)},
        "manufacturer": MANUFACTURER,
        "name": home.get("homeName") or entry_title,
        "model": "Konke Smart Cloud",
    }


def konke_device_info(
    device: KonkeDevice,
    *,
    via_device_id: str | None = None,
) -> dict[str, Any]:
    """Return HA device info for a normalized Konke device.

    The parent relationship is resolved by the caller into a device registry
    id (``via_device_id``) because HA 2027.8 removes the deprecated
    identifier based ``via_device`` argument.
    """
    info: dict[str, Any] = {
        "identifiers": {device_identifier(device.user_device_id)},
        "manufacturer": MANUFACTURER,
        "name": device_registry_name(device),
    }

    model = device_model(device)
    if model:
        info["model"] = model
    if device.suggested_area:
        info["suggested_area"] = device.suggested_area

    sw_version = firmware_version(device)
    if sw_version:
        info["sw_version"] = sw_version

    if via_device_id:
        info["via_device_id"] = via_device_id

    return info


def device_registry_name(device: KonkeDevice) -> str:
    """Return the device name shown on the HA device page."""
    return device.name or device.user_device_id


def device_model(device: KonkeDevice) -> str | None:
    """Return a stable model string for a Konke device."""
    if device.type_name and device.product_id and device.type_name != device.product_id:
        return f"{device.type_name} ({device.product_id})"
    return device.model or device.type_name or device.product_id or device.cate_type


def firmware_version(device: KonkeDevice) -> str | None:
    """Return firmware/software version from known raw fields."""
    for key in ("currentVersion", "firmwareVersion", "softwareVersion", "version"):
        value = device.raw.get(key)
        if value:
            return str(value)
    return None


def async_register_konke_devices(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: KonkeDataUpdateCoordinator,
) -> None:
    """Register known Konke devices in the HA device registry."""
    registry = dr.async_get(hass)
    data = coordinator.data or {}
    home = data.get("home", {})
    home_id = home.get("homeId") or entry.data.get(CONF_HOME_ID)
    if home_id:
        registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            **home_device_info(
                home=home,
                home_id=home_id,
                entry_title=entry.title,
            ),
        )

    devices_by_id: Mapping[str, KonkeDevice] = data.get("normalized_devices_by_id", {})
    create_offline = options_from_entry(entry).create_offline_device_entities
    for device in sorted(
        devices_by_id.values(),
        key=lambda item: (
            item.parent_user_device_id is not None,
            _numeric_sort_key(item.user_device_id),
        ),
    ):
        if not create_offline and device.online is False:
            continue
        registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            **konke_device_info(
                device,
                via_device_id=parent_device_registry_id(registry, device, devices_by_id),
            ),
        )


def parent_device_registry_id(
    registry: dr.DeviceRegistry,
    device: KonkeDevice,
    devices_by_id: Mapping[str, KonkeDevice],
) -> str | None:
    """Return the HA device registry id of the parent device, when known."""
    parent_id = device.parent_key
    if (
        not parent_id
        or parent_id == device.user_device_id
        or parent_id not in devices_by_id
    ):
        return None
    parent_entry = registry.async_get_device(
        identifiers={device_identifier(parent_id)}
    )
    return parent_entry.id if parent_entry is not None else None


def async_prune_konke_registry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    data: Mapping[str, Any],
) -> tuple[int, int]:
    """Remove registry entries for devices/scenes no longer reported by cloud.

    Returns the number of removed scene entities and devices. Callers must only
    pass a complete device listing: pruning is skipped when the poll reported
    failed areas or did not contain any device, so a partial cloud response can
    never wipe the registry.
    """
    metadata = data.get("forensic_poll_metadata") or {}
    if metadata.get("failed_area_ids"):
        return (0, 0)

    devices_by_id = data.get("normalized_devices_by_id") or {}
    if not devices_by_id:
        return (0, 0)

    home = data.get("home") or {}
    home_id = home.get("homeId") or entry.data.get(CONF_HOME_ID)
    cloud_home_id = "" if home_id is None else str(home_id)
    configured_home_id = str(entry.data.get(CONF_HOME_ID) or "")
    home_ids = {value for value in (cloud_home_id, configured_home_id) if value}
    expected_device_ids = {str(device_id) for device_id in devices_by_id}

    device_registry = dr.async_get(hass)
    removed_devices = 0
    for device_entry in dr.async_entries_for_config_entry(
        device_registry, entry.entry_id
    ):
        konke_ids = {
            identifier[1]
            for identifier in device_entry.identifiers
            if identifier and identifier[0] == DOMAIN
        }
        if not konke_ids:
            continue
        if konke_ids & home_ids or konke_ids & expected_device_ids:
            continue
        device_registry.async_remove_device(device_entry.id)
        removed_devices += 1

    scenes_by_id = data.get("scenes_by_id") or {}
    expected_scene_unique_ids = {
        f"{DOMAIN}_{home_id}_scene_{scene_id}"
        for home_id in home_ids
        for scene_id in scenes_by_id
    }
    entity_registry = er.async_get(hass)
    removed_entities = 0
    for entity_entry in er.async_entries_for_config_entry(
        entity_registry, entry.entry_id
    ):
        if entity_entry.domain != "scene":
            continue
        if entity_entry.unique_id in expected_scene_unique_ids:
            continue
        entity_registry.async_remove(entity_entry.entity_id)
        removed_entities += 1

    return (removed_entities, removed_devices)


def reset_konke_registry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove entities and devices that were created for this config entry.

    Used when a config entry is repointed at another Konke account (family
    shared account, or a repaired login). Clearing the registry entries first
    avoids duplicate entities/devices with stale ``unique_id`` values after
    the account switch.
    """
    entity_registry = er.async_get(hass)
    for entity_entry in er.async_entries_for_config_entry(
        entity_registry, entry.entry_id
    ):
        entity_registry.async_remove(entity_entry.entity_id)

    device_registry = dr.async_get(hass)
    for device_entry in dr.async_entries_for_config_entry(
        device_registry, entry.entry_id
    ):
        device_registry.async_remove_device(device_entry.id)


def _numeric_sort_key(value: str) -> tuple[int, str]:
    """Sort numeric ids naturally."""
    try:
        return (0, f"{int(value):020d}")
    except (TypeError, ValueError):
        return (1, str(value))
