"""Tests for Konke integration setup and services."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from custom_components.konke import async_migrate_entry, async_remove_entry
from custom_components.konke.const import (
    CONF_FORENSIC_LOGGING,
    CONF_FORENSIC_RETENTION_DAYS,
    CONF_FORENSIC_WEBSOCKET,
    DOMAIN,
)
from custom_components.konke.forensics import KonkeForensicRecorder
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler
from pytest_homeassistant_custom_component.common import MockConfigEntry


@pytest.mark.asyncio
async def test_setup_entry_creates_entities(
    hass,
    config_entry,
    konke_client_patch,
    entity_id_lookup,
) -> None:
    """The integration creates standard HA entities from fixture devices."""
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    entity_ids = [
        entity_id_lookup("climate", "konke_home-1_climate_1001"),
        entity_id_lookup("climate", "konke_home-1_heating_3001"),
        entity_id_lookup("cover", "konke_home-1_cover_4001"),
        entity_id_lookup("fan", "konke_home-1_fan_5001"),
        entity_id_lookup("scene", "konke_home-1_scene_10"),
    ]
    assert None not in entity_ids
    states = set(hass.states.async_entity_ids())
    assert set(entity_ids) <= states
    assert entity_id_lookup("scene", "konke_home-1_scene_20") is None
    assert DOMAIN in hass.data
    assert config_entry.entry_id in hass.data[DOMAIN]


@pytest.mark.asyncio
async def test_unload_entry_removes_coordinator(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """Unloading the integration removes the coordinator."""
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    assert config_entry.entry_id in hass.data[DOMAIN]

    assert await hass.config_entries.async_unload(config_entry.entry_id)
    await hass.async_block_till_done()
    assert config_entry.entry_id not in hass.data[DOMAIN]


@pytest.mark.asyncio
async def test_services_registered_without_removed_air_conditioner_services(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """Only supported Konke domain services are registered."""
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert hass.services.has_service(DOMAIN, "execute_scene")
    assert hass.services.has_service(DOMAIN, "refresh")
    assert hass.services.has_service(DOMAIN, "clear_forensic_history")
    assert not hass.services.has_service(DOMAIN, "raw_command")
    assert not hass.services.has_service(DOMAIN, "list_air_conditioners")
    assert not hass.services.has_service(DOMAIN, "turn_off_air_conditioners")


@pytest.mark.asyncio
async def test_execute_scene_service_uses_client(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """The execute_scene service calls the Konke client."""
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    await hass.services.async_call(
        DOMAIN,
        "execute_scene",
        {"scene_id": 10},
        blocking=True,
    )

    assert konke_client_patch.scene_calls == [{"home_id": "home-1", "scene_id": "10"}]


@pytest.mark.asyncio
async def test_refresh_service_supports_optional_response(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """Refresh remains callable from YAML and can optionally return status."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert (
        await hass.services.async_call(
            DOMAIN,
            "refresh",
            {},
            blocking=True,
        )
        is None
    )
    response = await hass.services.async_call(
        DOMAIN,
        "refresh",
        {},
        blocking=True,
        return_response=True,
    )
    assert response == {
        "entry_id": config_entry.entry_id,
        "last_update_success": True,
    }


@pytest.mark.asyncio
async def test_forensic_sensor_is_registered_disabled_by_default(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """The compact status sensor exists without recording payloads in HA state."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id(
        "sensor",
        DOMAIN,
        f"{config_entry.entry_id}_forensic_status",
    )
    assert entity_id == "sensor.konke_forensic_status"
    entry = registry.async_get(entity_id)
    assert entry is not None
    assert entry.disabled_by is RegistryEntryDisabler.INTEGRATION
    assert hass.states.get(entity_id) is None


@pytest.mark.asyncio
async def test_migration_removes_raw_command_and_enables_forensics(hass) -> None:
    """Version 1 options lose the arbitrary-write switch during migration."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={},
        options={"debug_raw_command": True},
        version=1,
        entry_id="konke-migration-entry",
    )
    entry.add_to_hass(hass)

    assert await async_migrate_entry(hass, entry)
    assert entry.version == 2
    assert "debug_raw_command" not in entry.options
    assert entry.options[CONF_FORENSIC_LOGGING] is True
    assert entry.options[CONF_FORENSIC_WEBSOCKET] is True
    assert entry.options[CONF_FORENSIC_RETENTION_DAYS] == 30


@pytest.mark.asyncio
async def test_remove_entry_deletes_persistent_forensic_store(hass) -> None:
    """Deleting a config entry removes events, baselines, and scene history."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={},
        entry_id="konke-remove-entry",
    )
    recorder = KonkeForensicRecorder(hass, entry.entry_id)
    await recorder.async_record("sample", "test", {"value": 1}, immediate=True)
    await recorder.async_shutdown()

    await async_remove_entry(hass, entry)

    reloaded = KonkeForensicRecorder(hass, entry.entry_id)
    await reloaded.async_load()
    exported = await reloaded.async_export()
    assert exported["events"] == []
    assert exported["latest_scene_snapshot"] == {}


@pytest.mark.asyncio
async def test_remove_entry_stops_loaded_coordinator_before_removing_store(
    hass,
) -> None:
    """A failed platform unload cannot leave a deleted entry listener running."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={},
        entry_id="konke-loaded-remove-entry",
    )
    calls: list[str] = []

    async def shutdown() -> None:
        calls.append("shutdown")

    async def remove() -> None:
        calls.append("remove")

    coordinator = SimpleNamespace(
        async_shutdown=AsyncMock(side_effect=shutdown),
        forensics=SimpleNamespace(async_remove=AsyncMock(side_effect=remove)),
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await async_remove_entry(hass, entry)

    assert calls == ["shutdown", "remove"]
    assert entry.entry_id not in hass.data[DOMAIN]
