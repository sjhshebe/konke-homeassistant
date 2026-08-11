"""Diagnostic sensors for Konke Smart."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import KonkeDataUpdateCoordinator
from .entity import KonkeEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the disabled-by-default forensic status sensor."""
    coordinator: KonkeDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([KonkeForensicStatusSensor(coordinator, entry)])


class KonkeForensicStatusSensor(KonkeEntity, SensorEntity):
    """Expose recorder coverage without placing evidence in HA state history."""

    _attr_translation_key = "forensic_status"
    _attr_icon = "mdi:shield-search"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self.entity_id = f"sensor.{DOMAIN}_forensic_status"
        self._attr_unique_id = f"{entry.entry_id}_forensic_status"

    async def async_added_to_hass(self) -> None:
        """Subscribe to recorder-only status updates."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self.coordinator.forensics.async_add_listener(self.async_write_ha_state)
        )

    @property
    def native_value(self) -> str:
        """Return the current listener state."""
        status = self.coordinator.forensics.status
        if not status["enabled"]:
            return "disabled"
        return str(status.get("listener_state") or "stopped")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return compact coverage and storage counters."""
        status = self.coordinator.forensics.status
        return {
            key: status.get(key)
            for key in (
                "last_listener_event",
                "poll_state",
                "failed_area_ids",
                "scene_snapshot_state",
                "failed_scene_room_ids",
                "failed_scene_ids",
                "last_poll_started",
                "last_poll_success",
                "last_event",
                "last_error",
                "last_cleared_at",
                "last_storage_error_at",
                "recording_state",
                "recording_disabled_since",
                "recorder_stopped_at",
                "retained_events",
                "dropped_by_age",
                "dropped_by_count",
                "dropped_by_size",
                "dropped_baselines_by_size",
                "dropped_scene_snapshots_by_size",
                "oversize_events",
                "storage_errors",
                "current_coverage_gaps",
            )
        }
