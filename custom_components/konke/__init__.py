"""Konke Smart integration."""

from __future__ import annotations

import homeassistant.helpers.config_validation as cv
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import KonkeApiClient
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY_CODE,
    CONF_FORENSIC_LOGGING,
    CONF_FORENSIC_RETENTION_DAYS,
    CONF_FORENSIC_WEBSOCKET,
    CONF_REFRESH_TOKEN,
    CONF_REGION_ID,
    CONF_VERSION_HEADER,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import KonkeDataUpdateCoordinator
from .forensics import KonkeForensicRecorder
from .options import (
    DEFAULT_FORENSIC_LOGGING,
    DEFAULT_FORENSIC_RETENTION_DAYS,
    DEFAULT_FORENSIC_WEBSOCKET,
)
from .profile import (
    DEFAULT_COUNTRY_CODE,
    DEFAULT_REGION_ID,
    DEFAULT_VERSION_HEADER,
)
from .registry import async_register_konke_devices
from .services import async_register_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Konke Smart integration."""
    hass.data.setdefault(DOMAIN, {})
    async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Konke Smart from a config entry."""
    session = async_get_clientsession(hass)
    client = KonkeApiClient(
        session,
        access_token=entry.data.get(CONF_ACCESS_TOKEN),
        refresh_token=entry.data.get(CONF_REFRESH_TOKEN),
        country_code=entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
        region_id=entry.data.get(CONF_REGION_ID, DEFAULT_REGION_ID),
        version_header=entry.data.get(CONF_VERSION_HEADER, DEFAULT_VERSION_HEADER),
    )
    coordinator = KonkeDataUpdateCoordinator(hass, entry, client)
    setup_complete = False
    try:
        await coordinator.async_initialize()
        await coordinator.async_config_entry_first_refresh()

        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
        async_register_konke_devices(hass, entry, coordinator)
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        entry.async_on_unload(entry.add_update_listener(_async_update_listener))
        coordinator.async_start_listener()
        setup_complete = True
        return True
    finally:
        if not setup_complete:
            hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
            await coordinator.async_shutdown()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Konke Smart config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        if coordinator is not None:
            await coordinator.async_shutdown()
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove forensic storage when a config entry is deleted."""
    coordinator = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if coordinator is not None:
        await coordinator.async_shutdown()
        await coordinator.forensics.async_remove()
        return
    recorder = KonkeForensicRecorder(hass, entry.entry_id, enabled=False)
    await recorder.async_remove()


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate legacy raw-command options to forensic recording."""
    if entry.version > 2:
        return False
    if entry.version < 2:
        options = dict(entry.options)
        options.pop("debug_raw_command", None)
        options.setdefault(CONF_FORENSIC_LOGGING, DEFAULT_FORENSIC_LOGGING)
        options.setdefault(CONF_FORENSIC_WEBSOCKET, DEFAULT_FORENSIC_WEBSOCKET)
        options.setdefault(
            CONF_FORENSIC_RETENTION_DAYS,
            DEFAULT_FORENSIC_RETENTION_DAYS,
        )
        hass.config_entries.async_update_entry(entry, options=options, version=2)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload Konke when options change."""
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if coordinator is not None and coordinator.loaded_options == dict(entry.options):
        return
    await hass.config_entries.async_reload(entry.entry_id)
