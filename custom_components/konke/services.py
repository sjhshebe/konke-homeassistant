"""Service registration for the Konke Smart integration."""

from __future__ import annotations

import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .const import (
    ATTR_ENTRY_ID,
    ATTR_SCENE_ID,
    CONF_HOME_ID,
    DOMAIN,
    SERVICE_CLEAR_FORENSIC_HISTORY,
    SERVICE_EXECUTE_SCENE,
    SERVICE_REFRESH,
)
from .coordinator import KonkeDataUpdateCoordinator

SERVICE_EXECUTE_SCENE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_SCENE_ID): cv.positive_int,
        vol.Optional(ATTR_ENTRY_ID): cv.string,
    }
)

SERVICE_REFRESH_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_ENTRY_ID): cv.string,
    }
)


def _get_coordinator(
    hass: HomeAssistant,
    entry_id: str | None,
) -> KonkeDataUpdateCoordinator:
    """Return the requested Konke coordinator."""
    coordinators: dict[str, KonkeDataUpdateCoordinator] = hass.data.get(DOMAIN, {})
    if entry_id:
        coordinator = coordinators.get(entry_id)
        if coordinator is None:
            raise HomeAssistantError(f"Konke entry_id not found: {entry_id}")
        return coordinator

    if len(coordinators) != 1:
        raise HomeAssistantError(
            "More than one Konke entry exists; pass entry_id to select one"
        )
    return next(iter(coordinators.values()))


def _home_id_from_coordinator(coordinator: KonkeDataUpdateCoordinator) -> str | int:
    """Return configured or discovered home id."""
    home_id = coordinator.config_entry.data.get(CONF_HOME_ID)
    if not home_id:
        home_id = coordinator.data.get("home", {}).get("homeId")
    if not home_id:
        raise HomeAssistantError("Konke home_id not found")
    return home_id


async def _async_execute_scene(hass: HomeAssistant, call: ServiceCall) -> None:
    """Execute a Konke scene by ID."""
    entry_id = call.data.get(ATTR_ENTRY_ID)
    scene_id = call.data[ATTR_SCENE_ID]
    coordinator = _get_coordinator(hass, entry_id)

    home_id = _home_id_from_coordinator(coordinator)
    await coordinator.async_execute_scene(
        home_id=home_id,
        scene_id=scene_id,
        context=call.context,
        source_entity_id=f"{DOMAIN}.{SERVICE_EXECUTE_SCENE}",
    )


async def _async_refresh(hass: HomeAssistant, call: ServiceCall) -> dict:
    """Refresh a Konke config entry on demand."""
    coordinator = _get_coordinator(hass, call.data.get(ATTR_ENTRY_ID))
    await coordinator.async_request_refresh()
    return {
        "entry_id": coordinator.config_entry.entry_id,
        "last_update_success": coordinator.last_update_success,
    }


async def _async_clear_forensic_history(
    hass: HomeAssistant, call: ServiceCall
) -> dict[str, object]:
    """Clear retained forensic history for an administrator."""
    user_id = call.context.user_id
    user = await hass.auth.async_get_user(user_id) if user_id else None
    if user is None or not user.is_admin:
        raise HomeAssistantError(
            "Only a Home Assistant administrator can clear forensics"
        )
    coordinator = _get_coordinator(hass, call.data.get(ATTR_ENTRY_ID))
    return {
        "entry_id": coordinator.config_entry.entry_id,
        "deleted": await coordinator.forensics.async_clear(call.context),
    }


def async_register_services(hass: HomeAssistant) -> None:
    """Register Konke domain services."""

    async def async_execute_scene(call: ServiceCall) -> None:
        """Execute a Konke scene by ID."""
        await _async_execute_scene(hass, call)

    async def async_refresh(call: ServiceCall) -> dict:
        """Refresh Konke data."""
        return await _async_refresh(hass, call)

    async def async_clear_forensic_history(call: ServiceCall) -> dict[str, object]:
        """Clear retained forensic evidence."""
        return await _async_clear_forensic_history(hass, call)

    if not hass.services.has_service(DOMAIN, SERVICE_EXECUTE_SCENE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_EXECUTE_SCENE,
            async_execute_scene,
            schema=SERVICE_EXECUTE_SCENE_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH,
            async_refresh,
            schema=SERVICE_REFRESH_SCHEMA,
            supports_response=SupportsResponse.OPTIONAL,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_CLEAR_FORENSIC_HISTORY):
        hass.services.async_register(
            DOMAIN,
            SERVICE_CLEAR_FORENSIC_HISTORY,
            async_clear_forensic_history,
            schema=SERVICE_REFRESH_SCHEMA,
            supports_response=SupportsResponse.OPTIONAL,
        )
