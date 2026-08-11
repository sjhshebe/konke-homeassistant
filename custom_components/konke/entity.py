"""Shared entity helpers for the Konke Smart integration."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_HOME_ID
from .coordinator import KonkeDataUpdateCoordinator
from .models import KonkeDevice
from .registry import home_device_info, konke_device_info


class KonkeEntity(CoordinatorEntity[KonkeDataUpdateCoordinator]):
    """Base class for Konke entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._entry = entry

    @property
    def konke_home_id(self) -> str:
        """Return the configured or discovered Konke home id."""
        home = self.coordinator.data.get("home", {})
        home_id = home.get("homeId") or self._entry.data.get(CONF_HOME_ID)
        return "" if home_id is None else str(home_id)

    @property
    def device_info(self) -> dict[str, Any]:
        """Return HA device info for the Konke home."""
        home = self.coordinator.data.get("home", {})
        return home_device_info(
            home=home,
            home_id=self.konke_home_id,
            entry_title=self._entry.title,
        )


class KonkeDeviceEntity(KonkeEntity):
    """Base class for Konke entities backed by a single device."""

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
    ) -> None:
        """Initialize the device entity."""
        super().__init__(coordinator, entry)
        self._device_id = str(device_id)

    @property
    def konke_device(self) -> KonkeDevice | None:
        """Return the latest normalized Konke device."""
        return self.coordinator.data.get("normalized_devices_by_id", {}).get(
            self._device_id
        )

    @property
    def available(self) -> bool:
        """Return if the entity is available."""
        device = self.konke_device
        return super().available and device is not None and device.online is not False

    @property
    def device_info(self) -> dict[str, Any]:
        """Return HA device info for a Konke device."""
        device = self.konke_device
        if device is None:
            return super().device_info
        return konke_device_info(
            device,
            devices_by_id=self.coordinator.data.get("normalized_devices_by_id", {}),
        )

    async def async_control_device(
        self,
        action_name: str,
        *,
        extension: dict[str, Any] | str | None = None,
        extra: dict[str, Any] | None = None,
        refresh: bool = True,
    ) -> dict[str, Any]:
        """Send a control command for this entity's Konke device."""
        device = self.konke_device
        if device is None:
            raise HomeAssistantError(f"Konke device not found: {self._device_id}")
        home_id = self.konke_home_id
        if not home_id:
            raise HomeAssistantError("Konke home_id not found")

        result = await self.coordinator.async_control_device(
            home_id=home_id,
            user_device_id=device.user_device_id,
            action_name=action_name,
            extension=extension,
            extra=extra,
            context=self._context,
            source_entity_id=self.entity_id,
        )

        if refresh:
            await self.coordinator.async_request_refresh()
        return result
