"""Tests for Home Assistant registry metadata."""

from __future__ import annotations

import pytest
from custom_components.konke.models import KonkeDevice
from custom_components.konke.registry import (
    async_prune_konke_registry,
    device_registry_name,
    konke_device_info,
    reset_konke_registry,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from .conftest import load_devices


def test_device_name_does_not_duplicate_suggested_area() -> None:
    """Device registry name should not include the room prefix."""
    device = KonkeDevice.from_raw(load_devices()[0])

    assert device.room_name == "客厅"
    assert device_registry_name(device) == "空调左"


def test_device_info_keeps_room_as_suggested_area() -> None:
    """Room information should remain available through HA area metadata."""
    device = KonkeDevice.from_raw(load_devices()[0])

    assert konke_device_info(device) == {
        "identifiers": {("konke", "1001")},
        "manufacturer": "Konke",
        "name": "空调左",
        "model": "空调 (kk-ac)",
        "suggested_area": "客厅",
    }


def test_device_info_uses_via_device_id_instead_of_deprecated_via_device() -> None:
    """Parent devices are linked with the non-deprecated via_device_id field."""
    device = KonkeDevice.from_raw(load_devices()[0])

    info = konke_device_info(device, via_device_id="parent-device-id")

    assert info["via_device_id"] == "parent-device-id"
    assert "via_device" not in info


@pytest.mark.asyncio
async def test_reset_konke_registry_removes_entities_and_devices(hass) -> None:
    """Resetting the registry clears entries created for the config entry."""
    entry = MockConfigEntry(
        domain="konke",
        title="Konke Smart",
        data={},
        entry_id="konke-registry-reset-entry",
    )
    entry.add_to_hass(hass)

    device_registry = dr.async_get(hass)
    device = device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={("konke", "1001")},
        manufacturer="Konke",
        name="空调左",
    )
    entity_registry = er.async_get(hass)
    entity_registry.async_get_or_create(
        "climate",
        "konke",
        "konke-unique-1",
        config_entry=entry,
        device_id=device.id,
        suggested_object_id="konke_test_ac",
    )

    reset_konke_registry(hass, entry)

    assert device_registry.async_get(device.id) is None
    assert entity_registry.async_get_entity_id("climate", "konke", "konke-unique-1") is None


def _prune_data() -> dict:
    """Return a complete cloud snapshot with a single visible device."""
    return {
        "home": {"homeId": "home-1"},
        "normalized_devices_by_id": {"1001": object()},
        "scenes_by_id": {"10": {"sceneId": "10"}},
        "forensic_poll_metadata": {"failed_area_ids": []},
    }


def _registry_with_stale_entries(hass, entry):
    """Create a live and a stale device plus scene entities for pruning."""
    device_registry = dr.async_get(hass)
    for device_id, name in (("home-1", "我的家"), ("1001", "空调左"), ("2002", "旧设备")):
        device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={("konke", device_id)},
            manufacturer="Konke",
            name=name,
        )
    entity_registry = er.async_get(hass)
    for scene_id in ("10", "99"):
        entity_registry.async_get_or_create(
            "scene",
            "konke",
            f"konke_home-1_scene_{scene_id}",
            config_entry=entry,
            suggested_object_id=f"konke_scene_{scene_id}",
        )
    return device_registry, entity_registry


@pytest.mark.asyncio
async def test_prune_removes_devices_and_scenes_missing_from_cloud(hass) -> None:
    """A complete snapshot prunes devices and scenes no longer reported."""
    entry = MockConfigEntry(
        domain="konke",
        title="Konke Smart",
        data={"home_id": "home-1"},
        entry_id="konke-prune-entry",
    )
    entry.add_to_hass(hass)
    device_registry, entity_registry = _registry_with_stale_entries(hass, entry)

    removed_entities, removed_devices = async_prune_konke_registry(
        hass, entry, _prune_data()
    )

    assert removed_devices == 1
    assert removed_entities == 1
    assert device_registry.async_get_device(identifiers={("konke", "2002")}) is None
    assert device_registry.async_get_device(identifiers={("konke", "1001")}) is not None
    assert device_registry.async_get_device(identifiers={("konke", "home-1")}) is not None
    assert (
        entity_registry.async_get_entity_id("scene", "konke", "konke_home-1_scene_99")
        is None
    )
    assert (
        entity_registry.async_get_entity_id("scene", "konke", "konke_home-1_scene_10")
        is not None
    )


@pytest.mark.asyncio
async def test_prune_skips_incomplete_polls(hass) -> None:
    """Partial or empty polls must never prune registry entries."""
    entry = MockConfigEntry(
        domain="konke",
        title="Konke Smart",
        data={"home_id": "home-1"},
        entry_id="konke-prune-incomplete-entry",
    )
    entry.add_to_hass(hass)
    device_registry, _ = _registry_with_stale_entries(hass, entry)

    failed = _prune_data()
    failed["forensic_poll_metadata"] = {"failed_area_ids": ["256094"]}
    assert async_prune_konke_registry(hass, entry, failed) == (0, 0)

    empty = _prune_data()
    empty["normalized_devices_by_id"] = {}
    assert async_prune_konke_registry(hass, entry, empty) == (0, 0)
    assert device_registry.async_get_device(identifiers={("konke", "2002")}) is not None
