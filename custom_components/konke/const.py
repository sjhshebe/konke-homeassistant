"""Constants for the Konke Smart integration."""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "konke"

PLATFORMS: list[Platform] = [
    Platform.SCENE,
    Platform.CLIMATE,
    Platform.COVER,
    Platform.FAN,
    Platform.SENSOR,
]

AUTH_METHOD_TOKEN = "token"
AUTH_METHOD_PASSWORD = "password"

CONF_AUTH_METHOD = "auth_method"
CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_TOKEN_EXPIRES_AT = "token_expires_at"
CONF_COUNTRY_CODE = "country_code"
CONF_REGION_ID = "region_id"
CONF_HOME_ID = "home_id"
CONF_HOME_NAME = "home_name"
CONF_USER_ID = "user_id"
CONF_VERSION_HEADER = "version_header"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_CREATE_SCENE_ENTITIES = "create_scene_entities"
CONF_CREATE_OFFLINE_DEVICE_ENTITIES = "create_offline_device_entities"
CONF_ALLOW_PASSWORD_REAUTH = "allow_password_reauth"
CONF_FORENSIC_LOGGING = "forensic_logging"
CONF_FORENSIC_WEBSOCKET = "forensic_websocket"
CONF_FORENSIC_RETENTION_DAYS = "forensic_retention_days"

SERVICE_EXECUTE_SCENE = "execute_scene"
SERVICE_REFRESH = "refresh"
SERVICE_CLEAR_FORENSIC_HISTORY = "clear_forensic_history"
ATTR_SCENE_ID = "scene_id"
ATTR_ENTRY_ID = "entry_id"
