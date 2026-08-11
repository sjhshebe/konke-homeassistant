"""Runtime option helpers for Konke Smart config entries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import (
    AUTH_METHOD_PASSWORD,
    CONF_ALLOW_PASSWORD_REAUTH,
    CONF_AUTH_METHOD,
    CONF_CREATE_OFFLINE_DEVICE_ENTITIES,
    CONF_CREATE_SCENE_ENTITIES,
    CONF_FORENSIC_LOGGING,
    CONF_FORENSIC_RETENTION_DAYS,
    CONF_FORENSIC_WEBSOCKET,
    CONF_SCAN_INTERVAL,
)

DEFAULT_SCAN_INTERVAL_MINUTES = 10
DEFAULT_SCAN_INTERVAL = timedelta(minutes=DEFAULT_SCAN_INTERVAL_MINUTES)
DEFAULT_CREATE_SCENE_ENTITIES = True
DEFAULT_CREATE_OFFLINE_DEVICE_ENTITIES = True
DEFAULT_ALLOW_PASSWORD_REAUTH = False
DEFAULT_FORENSIC_LOGGING = True
DEFAULT_FORENSIC_WEBSOCKET = True
DEFAULT_FORENSIC_RETENTION_DAYS = 30


@dataclass(frozen=True)
class KonkeOptions:
    """Normalized runtime options stored on a Home Assistant config entry."""

    scan_interval_minutes: int
    create_scene_entities: bool
    create_offline_device_entities: bool
    allow_password_reauth: bool
    forensic_logging: bool
    forensic_websocket: bool
    forensic_retention_days: int

    @property
    def scan_interval(self) -> timedelta:
        """Return the polling interval as a timedelta."""
        return timedelta(minutes=self.scan_interval_minutes)


def options_from_entry(config_entry: ConfigEntry) -> KonkeOptions:
    """Return normalized options for a config entry."""
    return options_from_mapping(config_entry.options)


def allow_password_reauth_from_entry(config_entry: ConfigEntry) -> bool:
    """Return whether background password reauthentication is allowed."""
    if CONF_ALLOW_PASSWORD_REAUTH in config_entry.options:
        return _bool_option(
            config_entry.options.get(CONF_ALLOW_PASSWORD_REAUTH),
            False,
        )

    return (
        config_entry.data.get(CONF_AUTH_METHOD) == AUTH_METHOD_PASSWORD
        and bool(config_entry.data.get(CONF_USERNAME))
        and bool(config_entry.data.get(CONF_PASSWORD))
    )


def options_from_mapping(options: Mapping[str, Any]) -> KonkeOptions:
    """Return normalized options from an options mapping."""
    return KonkeOptions(
        scan_interval_minutes=_positive_int(
            options.get(CONF_SCAN_INTERVAL),
            DEFAULT_SCAN_INTERVAL_MINUTES,
        ),
        create_scene_entities=_bool_option(
            options.get(CONF_CREATE_SCENE_ENTITIES),
            DEFAULT_CREATE_SCENE_ENTITIES,
        ),
        create_offline_device_entities=_bool_option(
            options.get(CONF_CREATE_OFFLINE_DEVICE_ENTITIES),
            DEFAULT_CREATE_OFFLINE_DEVICE_ENTITIES,
        ),
        allow_password_reauth=_bool_option(
            options.get(CONF_ALLOW_PASSWORD_REAUTH),
            DEFAULT_ALLOW_PASSWORD_REAUTH,
        ),
        forensic_logging=_bool_option(
            options.get(CONF_FORENSIC_LOGGING),
            DEFAULT_FORENSIC_LOGGING,
        ),
        forensic_websocket=_bool_option(
            options.get(CONF_FORENSIC_WEBSOCKET),
            DEFAULT_FORENSIC_WEBSOCKET,
        ),
        forensic_retention_days=_positive_int(
            options.get(CONF_FORENSIC_RETENTION_DAYS),
            DEFAULT_FORENSIC_RETENTION_DAYS,
        ),
    )


def _positive_int(value: Any, default: int) -> int:
    """Return a positive integer option, falling back to default."""
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return default
    return normalized if normalized > 0 else default


def _bool_option(value: Any, default: bool) -> bool:
    """Return a boolean option, falling back to default when unset."""
    if value is None:
        return default
    return bool(value)
