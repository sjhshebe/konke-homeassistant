"""Konke cloud/API profile constants.

These values describe the Android client profile observed in captures. They
are not user secrets and should not contain account-specific data.
"""

from __future__ import annotations

APP_KEY = "1592290148"
APP_TYPE = "ANDROID"
APP_VERSION = "2.9.5"

DEFAULT_COUNTRY_CODE = "86"
DEFAULT_REGION_ID = "CN"
DEFAULT_LANGUAGE = "zh"
DEFAULT_TIME_ZONE = "Asia/Shanghai"
DEFAULT_VERSION_HEADER = "Android-2.9.5-OnePlus ONEPLUS A5000-7.1.1"

ACCOUNT_BASE_URL = "https://kapp.ikonke.com/account"
API_BASE_URL = "https://kapp.ikonke.com/api"
WEBSOCKET_LISTENER_URL = "wss://kapp.ikonke.com/ws/listener"
