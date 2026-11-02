"""Client for the Konke Smart cloud API."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aiohttp import (
    ClientError,
    ClientResponse,
    ClientSession,
    ClientWebSocketResponse,
    WSMsgType,
)

try:
    from aiohttp import ClientWSTimeout
except ImportError:  # aiohttp < 3.12 (used by older supported HA releases)
    ClientWSTimeout = None  # type: ignore[assignment,misc]

from .command import (
    ACTION_PAUSE,
    ACTION_SET_MODE,
    ACTION_SET_TEMPERATURE,
    ACTION_SET_WIND_SPEED,
    ACTION_TURN_OFF,
    ACTION_TURN_ON,
    build_device_action_body,
)
from .exceptions import KonkeApiError, KonkeAuthError, KonkeCannotConnect
from .models import build_device_indexes, summarize_device
from .profile import (
    ACCOUNT_BASE_URL,
    API_BASE_URL,
    APP_KEY,
    APP_TYPE,
    APP_VERSION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_LANGUAGE,
    DEFAULT_REGION_ID,
    DEFAULT_TIME_ZONE,
    DEFAULT_VERSION_HEADER,
    WEBSOCKET_LISTENER_URL,
)

_LOGGER = logging.getLogger(__name__)

_SCENE_TYPES_FOR_SYNC = "Normal,ExternalScene"
_SCENE_TYPES_FOR_FORENSICS = "Normal,ExternalScene,MultiControl"
_WEBSOCKET_CLOSE_TIMEOUT = 5
_WEBSOCKET_HANDSHAKE_TIMEOUT = 20
_WEBSOCKET_RECEIVE_TIMEOUT = 90
_DEVICE_PAGE_SIZE = 100
_MAX_DEVICE_PAGES = 100
WEBSOCKET_MESSAGE_BINARY = WSMsgType.BINARY
WEBSOCKET_MESSAGE_ERROR = WSMsgType.ERROR
WEBSOCKET_MESSAGE_PING = WSMsgType.PING
WEBSOCKET_MESSAGE_PONG = WSMsgType.PONG
WEBSOCKET_MESSAGE_TEXT = WSMsgType.TEXT


def _websocket_timeout_kwargs() -> dict[str, Any]:
    """Return a structured timeout when the installed aiohttp supports it."""
    if ClientWSTimeout is None:
        return {
            "timeout": _WEBSOCKET_CLOSE_TIMEOUT,
            "receive_timeout": _WEBSOCKET_RECEIVE_TIMEOUT,
        }
    return {
        "timeout": ClientWSTimeout(
            ws_receive=_WEBSOCKET_RECEIVE_TIMEOUT,
            ws_close=_WEBSOCKET_CLOSE_TIMEOUT,
        )
    }


@dataclass(frozen=True)
class KonkeApiExchange:
    """Successful HTTP response plus timing metadata."""

    payload: dict[str, Any]
    http_status: int
    started_at: str
    completed_at: str
    response_date: str | None

    @property
    def metadata(self) -> dict[str, Any]:
        """Return JSON-safe exchange metadata."""
        return {
            "http_status": self.http_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "response_date": self.response_date,
            "business_code": self.payload.get("code"),
            "business_info": self.payload.get("info") or self.payload.get("message"),
            "message_id": self.payload.get("messageId"),
        }


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _error_metadata(error: KonkeApiError) -> dict[str, Any]:
    """Return structured request metadata without transport exception text."""
    return {
        "http_status": error.http_status,
        "business_code": error.business_code,
        "business_info": error.business_info,
        "message_id": error.message_id,
        "response_date": error.response_date,
        "started_at": error.started_at,
        "completed_at": error.completed_at,
    }


class KonkeApiClient:
    """Small async client for the Konke Smart cloud API."""

    def __init__(
        self,
        session: ClientSession,
        *,
        access_token: str | None = None,
        refresh_token: str | None = None,
        country_code: str = DEFAULT_COUNTRY_CODE,
        region_id: str = DEFAULT_REGION_ID,
        language: str = DEFAULT_LANGUAGE,
        time_zone: str = DEFAULT_TIME_ZONE,
        version_header: str = DEFAULT_VERSION_HEADER,
    ) -> None:
        """Initialize the client."""
        self._session = session
        self.access_token = access_token or ""
        self.refresh_token = refresh_token or ""
        self.country_code = country_code
        self.region_id = region_id
        self.language = language
        self.time_zone = time_zone
        self.version_header = version_header

    @staticmethod
    def extract_token_payload(payload: dict[str, Any]) -> dict[str, Any]:
        """Extract token fields from a login or refresh response."""
        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        user_token = data.get("userToken")
        user_token = user_token if isinstance(user_token, dict) else {}
        return {
            "access_token": (
                user_token.get("accessToken")
                or data.get("accessToken")
                or payload.get("accessToken")
            ),
            "refresh_token": (
                user_token.get("refreshToken")
                or data.get("refreshToken")
                or payload.get("refreshToken")
            ),
            "expires_in": (
                user_token.get("expirIn")
                or user_token.get("expiresIn")
                or user_token.get("expireIn")
                or data.get("expirIn")
                or data.get("expiresIn")
                or payload.get("expiresIn")
                or payload.get("expires_in")
            ),
        }

    @staticmethod
    def expires_at_from_payload(payload: dict[str, Any]) -> str | None:
        """Return an ISO expiry timestamp from a token response."""
        expires_in = KonkeApiClient.extract_token_payload(payload).get("expires_in")
        try:
            seconds = int(expires_in)
        except (TypeError, ValueError):
            return None
        if seconds <= 0:
            return None
        return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()

    @property
    def masked_token(self) -> str:
        """Return a redacted token for logs."""
        token = self.access_token
        if len(token) <= 8:
            return "***"
        return f"{token[:4]}...{token[-4:]}"

    def _headers(
        self,
        *,
        home_id: str | int | None = None,
        json_content: bool = False,
        include_token: bool = True,
    ) -> dict[str, str]:
        """Build headers used by the Android app."""
        headers = {
            "appKey": APP_KEY,
            "language": self.language,
            "timeZone": self.time_zone,
            "version": self.version_header,
            "User-Agent": "okhttp/4.2.2",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json"
            if json_content
            else "application/x-www-form-urlencoded",
        }
        if home_id is not None:
            headers["homeId"] = str(home_id)
        if include_token:
            headers["Authorization"] = self.access_token
        return headers

    async def _json_or_error(self, response: ClientResponse) -> dict[str, Any]:
        """Parse a Konke JSON response."""
        text = (await response.read()).decode("utf-8", "replace")
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            error_class = (
                KonkeAuthError if response.status in (401, 403) else KonkeApiError
            )
            message = (
                f"HTTP {response.status}"
                if response.status >= 400
                else "Invalid JSON response"
            )
            raise error_class(
                message,
                http_status=response.status,
                response_date=response.headers.get("Date"),
            ) from None

        if not isinstance(decoded, dict):
            error_class = (
                KonkeAuthError if response.status in (401, 403) else KonkeApiError
            )
            raise error_class(
                "Konke response was not a JSON object",
                http_status=response.status,
                response_date=response.headers.get("Date"),
            )
        payload: dict[str, Any] = decoded

        code = payload.get("code")
        info = payload.get("info") or payload.get("message") or ""
        metadata = {
            "http_status": response.status,
            "business_code": code,
            "business_info": info or None,
            "message_id": payload.get("messageId"),
            "response_date": response.headers.get("Date"),
        }
        if response.status in (401, 403):
            raise KonkeAuthError(f"HTTP {response.status}", **metadata)
        if response.status >= 400:
            raise KonkeApiError(f"HTTP {response.status}", **metadata)
        if code not in (None, 0, 200):
            if (
                code in (401, 403, 4010, 10001, 10002, 10003)
                or "token" in str(info).lower()
            ):
                raise KonkeAuthError(f"Konke authentication failed: {code}", **metadata)
            raise KonkeApiError(f"Konke API failed: {code}", **metadata)
        return payload

    async def _request(
        self,
        method: str,
        url: str,
        *,
        home_id: str | int | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        include_token: bool = True,
        account_api: bool = False,
    ) -> dict[str, Any]:
        """Send a request to Konke cloud."""
        return (
            await self._request_exchange(
                method,
                url,
                home_id=home_id,
                params=params,
                json_body=json_body,
                include_token=include_token,
                account_api=account_api,
            )
        ).payload

    async def _request_exchange(
        self,
        method: str,
        url: str,
        *,
        home_id: str | int | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        include_token: bool = True,
        account_api: bool = False,
    ) -> KonkeApiExchange:
        """Send a request and retain safe transport metadata."""
        base_url = ACCOUNT_BASE_URL if account_api else API_BASE_URL
        full_url = f"{base_url}{url}"
        headers = self._headers(
            home_id=home_id,
            json_content=json_body is not None,
            include_token=include_token,
        )
        started_at = _utcnow_iso()
        try:
            async with self._session.request(
                method,
                full_url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=20,
            ) as response:
                payload = await self._json_or_error(response)
                return KonkeApiExchange(
                    payload=payload,
                    http_status=response.status,
                    started_at=started_at,
                    completed_at=_utcnow_iso(),
                    response_date=response.headers.get("Date"),
                )
        except KonkeApiError as err:
            err.started_at = err.started_at or started_at
            err.completed_at = err.completed_at or _utcnow_iso()
            raise
        except ClientError:
            raise KonkeCannotConnect(
                "Unable to connect to Konke cloud",
                started_at=started_at,
                completed_at=_utcnow_iso(),
            ) from None
        except TimeoutError:
            raise KonkeCannotConnect(
                "Konke request timed out",
                started_at=started_at,
                completed_at=_utcnow_iso(),
            ) from None

    async def websocket_connect(self) -> ClientWebSocketResponse:
        """Open the captured read-only Konke event listener."""
        if not self.access_token:
            raise KonkeAuthError("Missing access token")
        try:
            async with asyncio.timeout(_WEBSOCKET_HANDSHAKE_TIMEOUT):
                return await self._session.ws_connect(
                    WEBSOCKET_LISTENER_URL,
                    params={"authorization": self.access_token},
                    headers={
                        "appKey": APP_KEY,
                        "language": self.language,
                        "timeZone": self.time_zone,
                        "version": self.version_header,
                        "User-Agent": "okhttp/4.2.2",
                    },
                    autoping=True,
                    heartbeat=30,
                    **_websocket_timeout_kwargs(),
                )
        except ClientError as err:
            status = getattr(err, "status", None)
            if status in (401, 403):
                raise KonkeAuthError(
                    f"WebSocket authentication failed: HTTP {status}",
                    http_status=status,
                ) from None
            raise KonkeCannotConnect(
                "WebSocket connection failed",
                http_status=status if isinstance(status, int) else None,
            ) from None
        except TimeoutError:
            raise KonkeCannotConnect("WebSocket connection timed out") from None

    async def login(
        self,
        username: str,
        password: str,
        *,
        country_code: str = DEFAULT_COUNTRY_CODE,
        region_id: str = DEFAULT_REGION_ID,
    ) -> dict[str, Any]:
        """Login with phone/username and password."""
        self.country_code = country_code
        self.region_id = region_id
        payload = await self._request(
            "POST",
            "/login",
            account_api=True,
            include_token=True,
            json_body={
                "username": username,
                "userPassword": password,
                "appType": APP_TYPE,
                "appVersion": APP_VERSION,
                "countryCode": country_code,
                "regionId": region_id,
            },
        )
        token_payload = self.extract_token_payload(payload)
        token = token_payload.get("access_token")
        if not token:
            raise KonkeAuthError("Login response did not contain accessToken")
        self.access_token = token
        self.refresh_token = token_payload.get("refresh_token") or self.refresh_token
        return payload

    async def refresh_access_token(self) -> dict[str, Any]:
        """Refresh access token when Konke exposes a refresh endpoint.

        The current Android app returns refreshToken on login, but the tested
        public account/API endpoints do not expose a working refresh route. This
        method keeps the client ready for endpoint-compatible responses and
        lets callers fall back to username/password login when it fails.
        """
        if not self.refresh_token:
            raise KonkeAuthError("Missing refresh token")

        candidates = (
            (ACCOUNT_BASE_URL, "/refreshToken", {"refreshToken": self.refresh_token}),
            (ACCOUNT_BASE_URL, "/token/refresh", {"refreshToken": self.refresh_token}),
            (
                ACCOUNT_BASE_URL,
                "/token/refreshToken",
                {"refreshToken": self.refresh_token},
            ),
            (
                API_BASE_URL,
                "/token",
                {"grantType": "refresh_token", "refreshToken": self.refresh_token},
            ),
        )
        last_error: KonkeApiError | None = None
        for base_url, path, body in candidates:
            full_url = f"{base_url}{path}"
            headers = self._headers(home_id="0", json_content=True, include_token=False)
            try:
                async with self._session.post(
                    full_url,
                    headers=headers,
                    json=body,
                    timeout=20,
                ) as response:
                    payload = await self._json_or_error(response)
            except KonkeApiError as err:
                last_error = err
                continue
            except ClientError:
                last_error = KonkeCannotConnect("Unable to connect to Konke cloud")
                continue
            except TimeoutError:
                last_error = KonkeCannotConnect("Konke request timed out")
                continue

            token_payload = self.extract_token_payload(payload)
            token = token_payload.get("access_token")
            if not token:
                last_error = KonkeAuthError(
                    "Refresh response did not contain accessToken"
                )
                continue
            self.access_token = token
            self.refresh_token = (
                token_payload.get("refresh_token") or self.refresh_token
            )
            return payload

        raise last_error or KonkeAuthError("Unable to refresh Konke token")

    async def validate_token(self) -> dict[str, Any]:
        """Validate the current access token and return the home index."""
        if not self.access_token:
            raise KonkeAuthError("Missing access token")
        return await self.fetch_home_index(home_id="0")

    async def fetch_home_index(self, *, home_id: str | int = "0") -> dict[str, Any]:
        """Fetch the app home index."""
        return await self._request(
            "GET",
            "/v2/page/index",
            home_id=home_id,
            params={"synUserHostList": "true"},
        )

    async def fetch_device_total(self, *, home_id: str | int) -> int:
        """Return the number of visible devices in a home.

        Used when an account can see several homes (for example a family
        member account that owns an empty home plus the shared family home),
        so the integration can pick the home that actually contains devices.
        """
        payload = await self._request(
            "GET",
            "/user/device",
            home_id=home_id,
            params={"page": 1, "pageSize": 1},
        )
        data = payload.get("data")
        page = data.get("pagePojo") if isinstance(data, dict) else None
        try:
            return int((page or {}).get("dataTotal") or 0)
        except (TypeError, ValueError):
            return 0

    async def fetch_scenes(
        self,
        *,
        home_id: str | int,
        room_id: str | int,
        scene_types: str = _SCENE_TYPES_FOR_SYNC,
    ) -> list[dict[str, Any]]:
        """Fetch scenes for a room."""
        scenes, _metadata = await self.fetch_scenes_exchange(
            home_id=home_id,
            room_id=room_id,
            scene_types=scene_types,
        )
        return scenes

    async def fetch_scenes_exchange(
        self,
        *,
        home_id: str | int,
        room_id: str | int,
        scene_types: str = _SCENE_TYPES_FOR_SYNC,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Fetch room scenes plus safe request metadata."""
        exchange = await self._request_exchange(
            "GET",
            "/v2/scene",
            home_id=home_id,
            params={
                "orderByField": "sort",
                "orderByType": "asc",
                "roomId": room_id,
                "sceneTypes": scene_types,
            },
        )
        payload = exchange.payload
        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        page = data.get("pagePojo")
        page = page if isinstance(page, dict) else {}
        scenes = page.get("list") or []
        if not isinstance(scenes, list):
            return [], exchange.metadata
        return (
            [scene for scene in scenes if isinstance(scene, dict)],
            exchange.metadata,
        )

    async def fetch_scene_detail(
        self,
        *,
        home_id: str | int,
        scene_id: str | int,
    ) -> dict[str, Any]:
        """Fetch scene detail."""
        payload = await self._request(
            "GET",
            f"/scene/{scene_id}",
            home_id=home_id,
            params={"timeZone": self.time_zone},
        )
        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        scene = data.get("scene")
        if not isinstance(scene, dict):
            raise KonkeApiError(f"Scene detail missing scene object: {scene_id}")
        return scene

    async def execute_scene(
        self,
        *,
        home_id: str | int,
        scene_id: str | int,
    ) -> dict[str, Any]:
        """Execute a Konke scene."""
        return (
            await self.execute_scene_exchange(home_id=home_id, scene_id=scene_id)
        ).payload

    async def execute_scene_exchange(
        self,
        *,
        home_id: str | int,
        scene_id: str | int,
    ) -> KonkeApiExchange:
        """Execute a scene and return transport metadata."""
        return await self._request_exchange(
            "POST",
            "/scene/action",
            home_id=home_id,
            json_body={"sceneId": int(scene_id)},
        )

    async def control_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        action_name: str,
        extension: dict[str, Any] | str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Control a Konke device action."""
        return (
            await self.control_device_exchange(
                home_id=home_id,
                user_device_id=user_device_id,
                action_name=action_name,
                extension=extension,
                extra=extra,
            )
        ).payload

    async def control_device_exchange(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        action_name: str,
        extension: dict[str, Any] | str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> KonkeApiExchange:
        """Control a device and return transport metadata."""
        body = build_device_action_body(
            user_device_id=user_device_id,
            action_name=action_name,
            extension=extension,
            extra=extra,
        )
        return await self._request_exchange(
            "POST",
            "/device/action/control",
            home_id=home_id,
            json_body=body,
        )

    async def turn_on_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
    ) -> dict[str, Any]:
        """Turn on a Konke device."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_TURN_ON,
        )

    async def turn_off_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
    ) -> dict[str, Any]:
        """Turn off a Konke device."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_TURN_OFF,
        )

    async def pause_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
    ) -> dict[str, Any]:
        """Pause a Konke device."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_PAUSE,
        )

    async def set_device_temperature(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        temperature: float,
    ) -> dict[str, Any]:
        """Set target temperature for a Konke climate device."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_SET_TEMPERATURE,
            extension={"value": float(temperature)},
        )

    async def set_device_mode(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        mode: str | int,
    ) -> dict[str, Any]:
        """Set mode for a Konke climate device."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_SET_MODE,
            extension={"mode": mode},
        )

    async def set_air_conditioner_fan_speed(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        speed: str,
    ) -> dict[str, Any]:
        """Set fan speed for a Konke air conditioner."""
        return await self.control_device(
            home_id=home_id,
            user_device_id=user_device_id,
            action_name=ACTION_SET_WIND_SPEED,
            extension={"speed": speed},
        )

    async def fetch_devices(
        self,
        *,
        home_id: str | int,
        area_id: str | int,
    ) -> list[dict[str, Any]]:
        """Fetch visible devices in an area."""
        devices, _metadata = await self.fetch_devices_exchange(
            home_id=home_id,
            area_id=area_id,
        )
        return devices

    async def fetch_devices_exchange(
        self,
        *,
        home_id: str | int,
        area_id: str | int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Fetch visible devices plus safe request metadata."""
        devices: list[dict[str, Any]] = []
        page_requests: list[dict[str, Any]] = []
        first_metadata: dict[str, Any] | None = None
        last_metadata: dict[str, Any] = {}
        coverage_complete = True

        for page_number in range(1, _MAX_DEVICE_PAGES + 1):
            exchange = await self._request_exchange(
                "GET",
                "/user/device",
                home_id=home_id,
                params={
                    "areaId": area_id,
                    "isVisible": "true",
                    "orderByField": "sort",
                    "page": page_number,
                    "orderByType": "desc",
                    "pageSize": _DEVICE_PAGE_SIZE,
                },
            )
            first_metadata = first_metadata or exchange.metadata
            last_metadata = exchange.metadata
            payload = exchange.payload
            data = payload.get("data")
            data = data if isinstance(data, dict) else {}
            page = data.get("pagePojo")
            page = page if isinstance(page, dict) else {}
            raw_items = page.get("list") or []
            raw_items = raw_items if isinstance(raw_items, list) else []
            items = [item for item in raw_items if isinstance(item, dict)]
            devices.extend(items)
            page_requests.append(
                {
                    **exchange.metadata,
                    "page": page_number,
                    "page_size": _DEVICE_PAGE_SIZE,
                    "device_count": len(items),
                }
            )
            if not _device_page_has_more(page, page_number, len(raw_items)):
                break
        else:
            coverage_complete = False

        metadata = {
            **(first_metadata or {}),
            "completed_at": last_metadata.get("completed_at"),
            "response_date": last_metadata.get("response_date"),
            "page_count": len(page_requests),
            "pages": page_requests,
            "coverage_complete": coverage_complete,
        }
        return devices, metadata

    async def fetch_device_cache(
        self,
        *,
        home_id: str | int,
        area_id: str | int,
    ) -> list[dict[str, Any]]:
        """Fetch current device cache snapshots for an area."""
        cache, _metadata = await self.fetch_device_cache_exchange(
            home_id=home_id,
            area_id=area_id,
        )
        return cache

    async def fetch_device_cache_exchange(
        self,
        *,
        home_id: str | int,
        area_id: str | int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Fetch cache snapshots plus safe request metadata."""
        exchange = await self._request_exchange(
            "GET",
            "/user/device/cache",
            home_id=home_id,
            params={"areaId": area_id},
        )
        payload = exchange.payload
        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        cache_list = data.get("cacheList") or []
        if not isinstance(cache_list, list):
            return [], exchange.metadata
        return (
            [item for item in cache_list if isinstance(item, dict)],
            exchange.metadata,
        )

    @staticmethod
    def extract_home(home_index: dict[str, Any]) -> dict[str, Any]:
        """Extract current home from home index payload."""
        data = home_index.get("data")
        data = data if isinstance(data, dict) else {}
        home = data.get("home")
        if isinstance(home, dict) and home.get("homeId"):
            return home

        home_list = data.get("homeList") or []
        home_list = home_list if isinstance(home_list, list) else []
        for item in home_list:
            if isinstance(item, dict) and item.get("isDefault"):
                return item
        if home_list and isinstance(home_list[0], dict):
            return home_list[0]
        raise KonkeApiError("No home found in Konke account")

    @staticmethod
    def extract_rooms(home: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract rooms from a home object."""
        rooms: list[dict[str, Any]] = []
        for area in home.get("areaList") or []:
            if not isinstance(area, dict):
                continue
            area_id = area.get("areaId")
            area_name = area.get("areaName")
            for room in area.get("roomList") or []:
                if not isinstance(room, dict) or not room.get("roomId"):
                    continue
                item = dict(room)
                item.setdefault("areaId", area_id)
                item.setdefault("areaName", area_name)
                rooms.append(item)
        return rooms

    async def fetch_data(
        self,
        *,
        configured_home_id: str | None = None,
        include_forensic_scenes: bool = False,
    ) -> dict[str, Any]:
        """Fetch all data used by the integration."""
        poll_started_at = _utcnow_iso()
        poll_requests: list[dict[str, Any]] = []
        scene_requests: list[dict[str, Any]] = []
        failed_area_ids: list[str] = []
        failed_scene_room_ids: list[str] = []
        home_index = await self.fetch_home_index(home_id="0")
        home = self.extract_home(home_index)
        home_id = str(configured_home_id or home["homeId"])
        rooms = self.extract_rooms(home)

        scenes_by_id: dict[str, dict[str, Any]] = {}
        forensic_scenes_by_id: dict[str, dict[str, Any]] = {}
        requested_scene_types = (
            _SCENE_TYPES_FOR_FORENSICS
            if include_forensic_scenes
            else _SCENE_TYPES_FOR_SYNC
        )
        for room in rooms:
            room_id = room.get("roomId")
            if not room_id:
                continue
            try:
                room_scenes, scenes_metadata = await self.fetch_scenes_exchange(
                    home_id=home_id,
                    room_id=room_id,
                    scene_types=requested_scene_types,
                )
                scene_requests.append(
                    {
                        **scenes_metadata,
                        "area_id": str(room.get("areaId") or ""),
                        "room_id": str(room_id),
                        "endpoint": "/v2/scene",
                        "scene_types": requested_scene_types,
                        "success": True,
                        "scene_count": len(room_scenes),
                    }
                )
            except KonkeApiError as err:
                _LOGGER.debug("Failed fetching scenes for room %s: %s", room_id, err)
                failed_scene_room_ids.append(str(room_id))
                scene_requests.append(
                    {
                        **_error_metadata(err),
                        "area_id": str(room.get("areaId") or ""),
                        "room_id": str(room_id),
                        "endpoint": "/v2/scene",
                        "scene_types": requested_scene_types,
                        "success": False,
                        "error": str(err),
                    }
                )
                continue
            for scene in room_scenes:
                scene_id = scene.get("sceneId")
                if scene_id is None:
                    continue
                item = dict(scene)
                item.setdefault(
                    "homeId", int(home_id) if home_id.isdigit() else home_id
                )
                item.setdefault("roomId", room_id)
                item.setdefault("roomName", room.get("roomName"))
                item.setdefault("areaId", room.get("areaId"))
                item.setdefault("areaName", room.get("areaName"))
                forensic_scenes_by_id[str(scene_id)] = item
                if str(item.get("sceneType") or "").lower() != "multicontrol":
                    scenes_by_id[str(scene_id)] = item

        devices: list[dict[str, Any]] = []
        forensic_devices: list[dict[str, Any]] = []
        for area in home.get("areaList") or []:
            area_id = area.get("areaId") if isinstance(area, dict) else None
            if not area_id:
                continue
            try:
                area_devices, devices_metadata = await self.fetch_devices_exchange(
                    home_id=home_id, area_id=area_id
                )
                poll_requests.append(
                    {
                        **devices_metadata,
                        "area_id": str(area_id),
                        "endpoint": "/user/device",
                        "success": True,
                        "device_count": len(area_devices),
                    }
                )
                if devices_metadata.get("coverage_complete") is False:
                    failed_area_ids.append(str(area_id))
            except KonkeApiError as err:
                _LOGGER.debug("Failed fetching devices for area %s: %s", area_id, err)
                failed_area_ids.append(str(area_id))
                poll_requests.append(
                    {
                        **_error_metadata(err),
                        "area_id": str(area_id),
                        "endpoint": "/user/device",
                        "success": False,
                        "error": str(err),
                    }
                )
                continue
            try:
                area_cache, cache_metadata = await self.fetch_device_cache_exchange(
                    home_id=home_id,
                    area_id=area_id,
                )
                poll_requests.append(
                    {
                        **cache_metadata,
                        "area_id": str(area_id),
                        "endpoint": "/user/device/cache",
                        "success": True,
                        "device_count": len(area_cache),
                    }
                )
            except KonkeApiError as err:
                _LOGGER.debug(
                    "Failed fetching device cache for area %s: %s", area_id, err
                )
                failed_area_ids.append(str(area_id))
                poll_requests.append(
                    {
                        **_error_metadata(err),
                        "area_id": str(area_id),
                        "endpoint": "/user/device/cache",
                        "success": False,
                        "error": str(err),
                    }
                )
                area_cache = []
            devices.extend(_merge_device_cache(area_devices, area_cache))
            forensic_devices.extend(
                _merge_device_cache(
                    area_devices,
                    area_cache,
                    include_cache_only=True,
                    area_id=area_id,
                )
            )

        device_indexes = build_device_indexes(devices)
        normalized_devices = device_indexes["devices"]
        return {
            "home": home,
            "rooms": rooms,
            "scenes_by_id": scenes_by_id,
            "forensic_scenes_by_id": forensic_scenes_by_id,
            "devices": devices,
            "forensic_devices": forensic_devices,
            "normalized_devices": normalized_devices,
            "normalized_devices_by_id": device_indexes["devices_by_id"],
            "entities": device_indexes["entities"],
            "device_ids_by_room_id": device_indexes["device_ids_by_room_id"],
            "child_device_ids_by_parent_id": device_indexes[
                "child_device_ids_by_parent_id"
            ],
            "device_ids_by_capability": device_indexes["device_ids_by_capability"],
            "device_summaries": [
                summarize_device(device) for device in normalized_devices
            ],
            "skipped_devices": device_indexes["skipped_devices"],
            "forensic_poll_metadata": {
                "started_at": poll_started_at,
                "completed_at": _utcnow_iso(),
                "failed_area_ids": sorted(set(failed_area_ids)),
                "failed_scene_room_ids": sorted(set(failed_scene_room_ids)),
                "area_requests": poll_requests,
                "scene_requests": scene_requests,
            },
        }


def _page_int(page: dict[str, Any], *keys: str) -> int | None:
    """Return the first positive pagination value exposed by the cloud."""
    for key in keys:
        try:
            value = int(page.get(key))
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return None


def _device_page_has_more(
    page: dict[str, Any], page_number: int, raw_item_count: int
) -> bool:
    """Return whether another visible-device page should be requested."""
    total_pages = _page_int(
        page,
        "totalPage",
        "totalPages",
        "pageCount",
        "pages",
    )
    if total_pages is not None:
        return page_number < total_pages
    total_items = _page_int(page, "total", "totalCount", "recordCount")
    if total_items is not None:
        return page_number * _DEVICE_PAGE_SIZE < total_items
    return raw_item_count >= _DEVICE_PAGE_SIZE


def _merge_device_cache(
    devices: list[dict[str, Any]],
    cache_list: list[dict[str, Any]],
    *,
    include_cache_only: bool = False,
    area_id: str | int | None = None,
) -> list[dict[str, Any]]:
    """Merge area cache snapshots, optionally retaining cache-only devices."""
    cache_by_id = {
        str(item["userDeviceId"]): item
        for item in cache_list
        if item.get("userDeviceId") is not None
    }
    if not cache_by_id:
        return devices

    merged: list[dict[str, Any]] = []
    visible_ids: set[str] = set()
    for device in devices:
        device_id = device.get("userDeviceId")
        if device_id is not None:
            visible_ids.add(str(device_id))
        cache = cache_by_id.get(str(device_id)) if device_id is not None else None
        if cache is None:
            merged.append(device)
            continue
        merged.append(_merge_single_device_cache(device, cache))

    if include_cache_only:
        for device_id, cache in sorted(cache_by_id.items()):
            if device_id in visible_ids:
                continue
            shell: dict[str, Any] = {
                "userDeviceId": cache.get("userDeviceId", device_id),
                "areaId": area_id,
                "_forensicCacheOnly": True,
            }
            if cache.get("roomId") is not None:
                shell["roomId"] = cache["roomId"]
            merged.append(_merge_single_device_cache(shell, cache))
    return merged


def _merge_single_device_cache(
    device: dict[str, Any],
    cache: dict[str, Any],
) -> dict[str, Any]:
    """Return a device payload with cache-list state merged into cache.extension."""
    merged = dict(device)
    device_cache = merged.get("cache")
    device_cache = {} if not isinstance(device_cache, dict) else dict(device_cache)

    extension = device_cache.get("extension")
    extension = {} if not isinstance(extension, dict) else dict(extension)

    for key, value in cache.items():
        if key in {"userDeviceId", "roomId"}:
            continue
        extension[key] = value

    if "isOnline" in cache:
        device_cache["isOnline"] = cache["isOnline"]
    if "updateTime" in cache:
        device_cache["updateTime"] = cache["updateTime"]

    device_cache["extension"] = extension
    merged["cache"] = device_cache
    return merged
