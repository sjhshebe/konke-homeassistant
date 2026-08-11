"""Data coordinator for the Konke Smart integration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import Context, HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    WEBSOCKET_MESSAGE_BINARY,
    WEBSOCKET_MESSAGE_ERROR,
    WEBSOCKET_MESSAGE_PING,
    WEBSOCKET_MESSAGE_PONG,
    WEBSOCKET_MESSAGE_TEXT,
    KonkeApiClient,
    KonkeApiExchange,
)
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY_CODE,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    CONF_REGION_ID,
    CONF_TOKEN_EXPIRES_AT,
    DOMAIN,
)
from .exceptions import KonkeApiError, KonkeAuthError
from .forensics import KonkeForensicRecorder, sanitize_forensics, utcnow_iso
from .options import allow_password_reauth_from_entry, options_from_entry
from .profile import (
    DEFAULT_COUNTRY_CODE,
    DEFAULT_REGION_ID,
)

_LOGGER = logging.getLogger(__name__)

_LISTENER_BACKOFF_SECONDS = (1, 2, 5, 10, 30, 60, 300)
_SCENE_DETAIL_REFRESH = timedelta(days=1)
_DEVICE_REPORT_PAYLOAD_BYTES = 48 * 1024
_UNKNOWN_WEBSOCKET_SAMPLE_BYTES = 4 * 1024
_WEBSOCKET_AUTH_CLOSE_CODES = {4001, 4003, 4401, 4403}
_WEBSOCKET_CLOSE_TIMEOUT = 5
_WEBSOCKET_STABLE_CONNECTION_SECONDS = 60


class KonkeDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinate Konke Smart data."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        client: KonkeApiClient,
    ) -> None:
        """Initialize coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=config_entry,
            update_interval=options_from_entry(config_entry).scan_interval,
        )
        self.client = client
        options = options_from_entry(config_entry)
        self.loaded_options = dict(config_entry.options)
        self.forensics = KonkeForensicRecorder(
            hass,
            config_entry.entry_id,
            enabled=options.forensic_logging,
            retention_days=options.forensic_retention_days,
        )
        self._forensic_websocket = options.forensic_websocket
        self._auth_lock = asyncio.Lock()
        self._shutdown_lock = asyncio.Lock()
        self._shutdown_complete = False
        self._listener_task: asyncio.Task[None] | None = None
        self._listener_restart_task: asyncio.Task[None] | None = None
        self._listener_stop = asyncio.Event()
        self._listener_should_run = False
        self._scene_fingerprint: str | None = None
        self._scene_details: dict[str, Any] = {}
        self._scene_details_attempted_at: datetime | None = None
        self._scene_details_refreshed_at: datetime | None = None

    async def async_initialize(self) -> None:
        """Load persisted evidence before the first cloud refresh."""
        await self.forensics.async_load()
        await self.forensics.async_update_recording_state()
        await self.forensics.async_record(
            "recorder_started",
            "lifecycle",
            {"recording_enabled": self.forensics.enabled},
            immediate=True,
        )
        if not self.forensics.enabled or not self._forensic_websocket:
            await self.forensics.async_set_listener_status("disabled")

    def async_start_listener(self) -> None:
        """Start the optional read-only event listener."""
        if self._listener_stop.is_set():
            return
        self._listener_should_run = True
        if (
            not self.forensics.enabled
            or not self._forensic_websocket
            or self._listener_task is not None
        ):
            return
        if not callable(getattr(self.client, "websocket_connect", None)):
            _LOGGER.debug("Konke client has no WebSocket listener implementation")
            return
        task = self.hass.async_create_background_task(
            self._async_listener_loop(),
            f"{DOMAIN} forensic listener {self.config_entry.entry_id}",
        )
        self._listener_task = task
        task.add_done_callback(self._listener_task_done)

    def _listener_task_done(self, task: asyncio.Task[None]) -> None:
        """Consume listener failures and release the owned task reference."""
        if self._listener_task is task:
            self._listener_task = None
        if task.cancelled():
            return
        try:
            task.result()
        except Exception as err:
            _LOGGER.error(
                "Konke forensic listener stopped unexpectedly: %s",
                self._safe_error_summary(err),
            )

    async def _async_cancel_task(
        self, task: asyncio.Task[Any], description: str
    ) -> None:
        """Cancel an owned task without letting its prior failure escape."""
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as err:
            _LOGGER.debug(
                "Ignoring failure from %s during cleanup: %s",
                description,
                self._safe_error_summary(err),
            )

    async def async_shutdown(self) -> None:
        """Stop background work and flush retained evidence."""
        async with self._shutdown_lock:
            if self._shutdown_complete:
                return
            self._shutdown_complete = True
            self._listener_should_run = False
            self._listener_stop.set()
            try:
                try:
                    await super().async_shutdown()
                finally:
                    restart_task = self._listener_restart_task
                    if restart_task is not None:
                        await self._async_cancel_task(
                            restart_task, "Konke forensic listener restart task"
                        )
                        if self._listener_restart_task is restart_task:
                            self._listener_restart_task = None
                    listener_task = self._listener_task
                    if listener_task is not None:
                        await self._async_cancel_task(
                            listener_task, "Konke forensic listener task"
                        )
                        if self._listener_task is listener_task:
                            self._listener_task = None
                    listener_state = (
                        "stopped"
                        if self.forensics.enabled and self._forensic_websocket
                        else "disabled"
                    )
                    try:
                        await self.forensics.async_set_listener_status(listener_state)
                    finally:
                        await self.forensics.async_record(
                            "recorder_stopped", "lifecycle", {}, immediate=True
                        )
                        await self.forensics.async_mark_runtime_stopped()
            finally:
                await self.forensics.async_shutdown()

    def _update_entry_tokens(
        self,
        *,
        access_token: str | None = None,
        refresh_token: str | None = None,
        token_expires_at: str | None = None,
    ) -> None:
        """Persist new tokens on the config entry."""
        updates: dict[str, Any] = {}
        if access_token and access_token != self.config_entry.data.get(
            CONF_ACCESS_TOKEN
        ):
            updates[CONF_ACCESS_TOKEN] = access_token
        if refresh_token and refresh_token != self.config_entry.data.get(
            CONF_REFRESH_TOKEN
        ):
            updates[CONF_REFRESH_TOKEN] = refresh_token
        if token_expires_at and token_expires_at != self.config_entry.data.get(
            CONF_TOKEN_EXPIRES_AT
        ):
            updates[CONF_TOKEN_EXPIRES_AT] = token_expires_at
        if updates:
            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data={**self.config_entry.data, **updates},
            )
            if CONF_ACCESS_TOKEN in updates:
                self._schedule_listener_restart()

    def _schedule_listener_restart(self) -> None:
        """Coalesce reconnect requests caused by access-token rotation."""
        if (
            not self._listener_should_run
            or self._listener_restart_task is not None
            or self._listener_stop.is_set()
        ):
            return
        if self._listener_task is None:
            self.async_start_listener()
            return
        self._listener_restart_task = self.hass.async_create_background_task(
            self._async_restart_listener(),
            f"{DOMAIN} restart forensic listener {self.config_entry.entry_id}",
        )

    async def _async_restart_listener(self) -> None:
        """Reconnect the listener with a refreshed access token."""
        restart_task = asyncio.current_task()
        try:
            task = self._listener_task
            if task is not None and task is not restart_task:
                await self._async_cancel_task(
                    task, "Konke forensic listener task during restart"
                )
                if self._listener_task is task:
                    self._listener_task = None
            if self._listener_should_run and not self._listener_stop.is_set():
                self.async_start_listener()
        finally:
            if self._listener_restart_task is restart_task:
                self._listener_restart_task = None

    def _token_expires_soon(self) -> bool:
        """Return true when the stored token should be renewed proactively."""
        expires_at = self.config_entry.data.get(CONF_TOKEN_EXPIRES_AT)
        if not expires_at:
            return False
        try:
            expires = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError):
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return datetime.now(UTC) + timedelta(days=7) >= expires.astimezone(UTC)

    async def async_refresh_auth(
        self, *, failed_access_token: str | None = None
    ) -> bool:
        """Refresh authorization using refresh token or stored credentials."""
        async with self._auth_lock:
            if (
                failed_access_token is not None
                and self.client.access_token
                and self.client.access_token != failed_access_token
            ):
                return True
            return await self._async_refresh_auth_locked()

    async def _async_refresh_auth_locked(self) -> bool:
        """Refresh authorization while serializing concurrent callers."""
        try:
            if self.config_entry.data.get(CONF_REFRESH_TOKEN):
                payload = await self.client.refresh_access_token()
                self._update_entry_tokens(
                    access_token=self.client.access_token,
                    refresh_token=self.client.refresh_token,
                    token_expires_at=self.client.expires_at_from_payload(payload),
                )
                return True
        except KonkeApiError:
            _LOGGER.debug("Konke refreshToken flow failed")

        if not allow_password_reauth_from_entry(self.config_entry):
            _LOGGER.debug(
                "Konke password reauth is disabled; waiting for explicit reauthentication"
            )
            return False

        return await self._async_login_from_entry()

    async def _async_login_from_entry(self) -> bool:
        """Login again using stored username/password, if available."""
        username = self.config_entry.data.get(CONF_USERNAME)
        password = self.config_entry.data.get(CONF_PASSWORD)
        if not username or not password:
            return False

        payload = await self.client.login(
            username,
            password,
            country_code=self.config_entry.data.get(
                CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE
            ),
            region_id=self.config_entry.data.get(CONF_REGION_ID, DEFAULT_REGION_ID),
        )
        token_payload = self.client.extract_token_payload(payload)
        self._update_entry_tokens(
            access_token=token_payload.get("access_token"),
            refresh_token=token_payload.get("refresh_token"),
            token_expires_at=self.client.expires_at_from_payload(payload),
        )
        return True

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Konke cloud."""
        poll_started_at = utcnow_iso()
        request_access_token = self.client.access_token
        try:
            if not self.client.access_token or self._token_expires_soon():
                await self.async_refresh_auth(failed_access_token=request_access_token)
            request_access_token = self.client.access_token
            data = await self.client.fetch_data(
                configured_home_id=self.config_entry.data.get(CONF_HOME_ID),
                include_forensic_scenes=self.forensics.enabled,
            )
            await self._async_record_successful_poll(data, poll_started_at)
            return data
        except KonkeAuthError as err:
            try:
                if await self.async_refresh_auth(
                    failed_access_token=request_access_token
                ):
                    data = await self.client.fetch_data(
                        configured_home_id=self.config_entry.data.get(CONF_HOME_ID),
                        include_forensic_scenes=self.forensics.enabled,
                    )
                    await self._async_record_successful_poll(data, poll_started_at)
                    return data
            except KonkeApiError as login_err:
                await self._async_record_failed_poll(poll_started_at, login_err)
                raise ConfigEntryAuthFailed from login_err
            await self._async_record_failed_poll(poll_started_at, err)
            raise ConfigEntryAuthFailed from err
        except KonkeApiError as err:
            await self._async_record_failed_poll(poll_started_at, err)
            raise UpdateFailed(self._safe_error_summary(err)) from err

    async def _async_record_successful_poll(
        self, data: dict[str, Any], fallback_started_at: str
    ) -> None:
        metadata = dict(data.get("forensic_poll_metadata") or {})
        metadata.setdefault("started_at", fallback_started_at)
        metadata.setdefault("completed_at", utcnow_iso())
        await self.forensics.async_record_poll(data, metadata, success=True)
        if self.forensics.enabled:
            await self._async_update_scene_snapshot(data)

    async def _async_record_failed_poll(
        self, started_at: str, error: Exception
    ) -> None:
        business_info = getattr(error, "business_info", None)
        await self.forensics.async_record_poll(
            None,
            {
                "started_at": started_at,
                "completed_at": utcnow_iso(),
                "request_started_at": getattr(error, "started_at", None),
                "request_completed_at": getattr(error, "completed_at", None),
                "http_status": getattr(error, "http_status", None),
                "business_code": getattr(error, "business_code", None),
                "business_info": sanitize_forensics(business_info),
                "message_id": getattr(error, "message_id", None),
                "response_date": getattr(error, "response_date", None),
            },
            success=False,
            error=self._safe_error_summary(error),
        )

    async def _async_update_scene_snapshot(self, data: dict[str, Any]) -> None:
        poll_metadata = data.get("forensic_poll_metadata")
        poll_metadata = poll_metadata if isinstance(poll_metadata, dict) else {}
        failed_scene_rooms = sorted(
            {str(item) for item in poll_metadata.get("failed_scene_room_ids") or []}
        )
        if failed_scene_rooms:
            await self.forensics.async_set_scene_snapshot_state(
                "partial", failed_scene_ids=[], failed_scene_room_ids=failed_scene_rooms
            )
            await self.forensics.async_record(
                "scene_snapshot_incomplete",
                "scene_snapshot",
                {
                    "failed_room_ids": failed_scene_rooms,
                    "scene_requests": poll_metadata.get("scene_requests") or [],
                    "preserved_previous_snapshot": True,
                },
            )
            return

        summaries = data.get("forensic_scenes_by_id") or data.get("scenes_by_id") or {}
        summaries = summaries if isinstance(summaries, dict) else {}
        canonical = json.dumps(
            sanitize_forensics(summaries),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        fingerprint = hashlib.sha256(canonical).hexdigest()
        now = datetime.now(UTC)
        due = (
            self._scene_details_attempted_at is None
            or now - self._scene_details_attempted_at >= _SCENE_DETAIL_REFRESH
        )
        if fingerprint != self._scene_fingerprint or due:
            details: dict[str, Any] = {}
            detail_requests: list[dict[str, Any]] = []
            detail_failed = False
            failed_scene_ids: list[str] = []
            self._scene_details_attempted_at = now
            for scene_id, summary in summaries.items():
                if not isinstance(summary, dict):
                    continue
                fetch_detail = getattr(self.client, "fetch_scene_detail", None)
                if not callable(fetch_detail):
                    details[str(scene_id)] = summary
                    continue
                home_id = summary.get("homeId") or self.config_entry.data.get(
                    CONF_HOME_ID
                )
                started_at = utcnow_iso()
                try:
                    details[str(scene_id)] = await fetch_detail(
                        home_id=home_id,
                        scene_id=scene_id,
                    )
                    detail_requests.append(
                        {
                            "scene_id": str(scene_id),
                            "started_at": started_at,
                            "completed_at": utcnow_iso(),
                            "success": True,
                        }
                    )
                except Exception as err:
                    detail_failed = True
                    failed_scene_ids.append(str(scene_id))
                    previous = self._scene_details.get(str(scene_id))
                    if (
                        isinstance(previous, dict)
                        and previous.get("_forensic_detail_status") == "stale"
                    ):
                        previous = previous.get("last_known_detail")
                    details[str(scene_id)] = {
                        "summary": summary,
                        "last_known_detail": previous,
                        "_forensic_detail_status": "stale",
                    }
                    detail_requests.append(
                        {
                            "scene_id": str(scene_id),
                            "started_at": started_at,
                            "completed_at": utcnow_iso(),
                            "success": False,
                            **self._error_audit_metadata(err),
                        }
                    )
            self._scene_details = details
            self._scene_details_refreshed_at = now if not detail_failed else None
            self._scene_fingerprint = fingerprint
            await self.forensics.async_set_scene_snapshot_state(
                "partial" if detail_failed else "complete",
                failed_scene_ids=failed_scene_ids,
                failed_scene_room_ids=[],
            )
            await self.forensics.async_record(
                "scene_snapshot_refreshed",
                "scene_snapshot",
                {
                    "summary_fingerprint": fingerprint,
                    "scene_count": len(summaries),
                    "detail_requests": detail_requests,
                },
            )
        await self.forensics.async_record_scene_snapshot(
            self._scene_details or summaries
        )

    async def async_control_device(
        self,
        *,
        home_id: str | int,
        user_device_id: str | int,
        action_name: str,
        extension: dict[str, Any] | str | None = None,
        extra: dict[str, Any] | None = None,
        context: Context | None = None,
        source_entity_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute and audit one device command."""
        operation_id = str(uuid.uuid4())
        request_data = {
            "endpoint": "/device/action/control",
            "home_id": home_id,
            "user_device_id": user_device_id,
            "action_name": action_name,
            "extension": extension,
            "extra": extra,
            "source_entity_id": source_entity_id,
        }
        await self.forensics.async_record(
            "outbound_attempt",
            "ha_write",
            request_data,
            operation_id=operation_id,
            context=context,
            immediate=True,
        )
        started = time.monotonic()
        attempts = 0
        request_access_token = self.client.access_token
        try:
            attempts += 1
            exchange = await self._async_control_exchange(
                home_id=home_id,
                user_device_id=user_device_id,
                action_name=action_name,
                extension=extension,
                extra=extra,
            )
        except KonkeAuthError as auth_error:
            await self.forensics.async_record(
                "outbound_auth_retry",
                "ha_write",
                {
                    **request_data,
                    **self._error_audit_metadata(auth_error),
                    "attempt": attempts,
                },
                operation_id=operation_id,
                context=context,
                immediate=True,
            )
            try:
                auth_refreshed = await self.async_refresh_auth(
                    failed_access_token=request_access_token
                )
            except Exception as err:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    err,
                    attempts,
                    started,
                )
                raise
            if not auth_refreshed:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    auth_error,
                    attempts,
                    started,
                )
                raise
            attempts += 1
            try:
                exchange = await self._async_control_exchange(
                    home_id=home_id,
                    user_device_id=user_device_id,
                    action_name=action_name,
                    extension=extension,
                    extra=extra,
                )
            except Exception as err:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    err,
                    attempts,
                    started,
                )
                raise
        except Exception as err:
            await self._async_record_write_error(
                operation_id,
                request_data,
                context,
                err,
                attempts,
                started,
            )
            raise
        await self._async_record_write_result(
            operation_id,
            request_data,
            context,
            exchange,
            attempts,
            started,
        )
        return exchange.payload

    async def async_execute_scene(
        self,
        *,
        home_id: str | int,
        scene_id: str | int,
        context: Context | None = None,
        source_entity_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute and audit one Konke scene."""
        operation_id = str(uuid.uuid4())
        request_data = {
            "endpoint": "/scene/action",
            "home_id": home_id,
            "scene_id": scene_id,
            "source_entity_id": source_entity_id,
        }
        await self.forensics.async_record(
            "outbound_attempt",
            "ha_write",
            request_data,
            operation_id=operation_id,
            context=context,
            immediate=True,
        )
        started = time.monotonic()
        attempts = 0
        request_access_token = self.client.access_token
        try:
            attempts += 1
            exchange = await self._async_scene_exchange(home_id, scene_id)
        except KonkeAuthError as auth_error:
            await self.forensics.async_record(
                "outbound_auth_retry",
                "ha_write",
                {
                    **request_data,
                    **self._error_audit_metadata(auth_error),
                    "attempt": attempts,
                },
                operation_id=operation_id,
                context=context,
                immediate=True,
            )
            try:
                auth_refreshed = await self.async_refresh_auth(
                    failed_access_token=request_access_token
                )
            except Exception as err:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    err,
                    attempts,
                    started,
                )
                raise
            if not auth_refreshed:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    auth_error,
                    attempts,
                    started,
                )
                raise
            attempts += 1
            try:
                exchange = await self._async_scene_exchange(home_id, scene_id)
            except Exception as err:
                await self._async_record_write_error(
                    operation_id,
                    request_data,
                    context,
                    err,
                    attempts,
                    started,
                )
                raise
        except Exception as err:
            await self._async_record_write_error(
                operation_id,
                request_data,
                context,
                err,
                attempts,
                started,
            )
            raise
        await self._async_record_write_result(
            operation_id,
            request_data,
            context,
            exchange,
            attempts,
            started,
        )
        return exchange.payload

    async def _async_control_exchange(self, **kwargs: Any) -> KonkeApiExchange:
        exchange_method = getattr(self.client, "control_device_exchange", None)
        if callable(exchange_method):
            return await exchange_method(**kwargs)
        payload = await self.client.control_device(**kwargs)
        now = utcnow_iso()
        return KonkeApiExchange(payload, 200, now, now, None)

    async def _async_scene_exchange(
        self, home_id: str | int, scene_id: str | int
    ) -> KonkeApiExchange:
        exchange_method = getattr(self.client, "execute_scene_exchange", None)
        if callable(exchange_method):
            return await exchange_method(home_id=home_id, scene_id=scene_id)
        payload = await self.client.execute_scene(home_id=home_id, scene_id=scene_id)
        now = utcnow_iso()
        return KonkeApiExchange(payload, 200, now, now, None)

    async def _async_record_write_result(
        self,
        operation_id: str,
        request_data: dict[str, Any],
        context: Context | None,
        exchange: KonkeApiExchange,
        attempts: int,
        started: float,
    ) -> None:
        await self.forensics.async_record(
            "outbound_result",
            "ha_write",
            {
                **request_data,
                **exchange.metadata,
                "success": True,
                "attempts": attempts,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
            },
            operation_id=operation_id,
            context=context,
            immediate=True,
        )

    async def _async_record_write_error(
        self,
        operation_id: str,
        request_data: dict[str, Any],
        context: Context | None,
        error: Exception,
        attempts: int,
        started: float,
    ) -> None:
        await self.forensics.async_record(
            "outbound_result",
            "ha_write",
            {
                **request_data,
                "success": False,
                "attempts": attempts,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
                **self._error_audit_metadata(error),
            },
            operation_id=operation_id,
            context=context,
            immediate=True,
        )

    def _error_audit_metadata(self, error: Exception) -> dict[str, Any]:
        """Return safe, structured metadata for a failed API attempt."""
        business_info = getattr(error, "business_info", None)
        return {
            "error_type": type(error).__name__,
            "error": self._safe_error_summary(error),
            "http_status": getattr(error, "http_status", None),
            "business_code": getattr(error, "business_code", None),
            "business_info": (
                sanitize_forensics(business_info) if business_info is not None else None
            ),
            "message_id": getattr(error, "message_id", None),
            "response_date": getattr(error, "response_date", None),
            "request_started_at": getattr(error, "started_at", None),
            "request_completed_at": getattr(error, "completed_at", None),
        }

    def _safe_error_summary(self, error: Exception | str) -> str:
        """Return a bounded error summary without known account secrets."""
        value = sanitize_forensics(str(error))
        text = value if isinstance(value, str) else type(error).__name__
        for secret in (
            getattr(self.client, "access_token", None),
            getattr(self.client, "refresh_token", None),
        ):
            if secret:
                text = text.replace(secret, "**REDACTED**")
        return text[:500]

    async def _async_listener_loop(self) -> None:
        backoff_index = 0
        while not self._listener_stop.is_set():
            websocket: Any = None
            connected_at: float | None = None
            connected_duration = 0.0
            disconnect_error: str | None = None
            try:
                await self.forensics.async_set_listener_status("connecting")
                websocket = await self.client.websocket_connect()
                connected_at = time.monotonic()
                await self.forensics.async_set_listener_status("connected")
                async for message in websocket:
                    await self._async_record_websocket_message(message)
                if self._listener_stop.is_set():
                    break
                close_code = getattr(websocket, "close_code", None)
                if close_code in _WEBSOCKET_AUTH_CLOSE_CODES:
                    raise KonkeAuthError(
                        f"WebSocket authorization was rejected: close code {close_code}",
                        business_code=close_code,
                    )
                raise KonkeApiError(
                    f"WebSocket listener closed: close code {close_code}",
                    business_code=close_code,
                )
            except asyncio.CancelledError:
                raise
            except KonkeAuthError as err:
                disconnect_error = self._safe_error_summary(err)
                await self.forensics.async_set_listener_status(
                    "auth_error", error=disconnect_error
                )
                return
            except Exception as err:
                disconnect_error = self._safe_error_summary(err)
                _LOGGER.debug(
                    "Konke forensic listener disconnected: %s",
                    disconnect_error,
                )
            finally:
                if connected_at is not None:
                    connected_duration = time.monotonic() - connected_at
                if websocket is not None:
                    with suppress(Exception):
                        await asyncio.wait_for(
                            websocket.close(), timeout=_WEBSOCKET_CLOSE_TIMEOUT
                        )

            await self.forensics.async_set_listener_status(
                "disconnected", error=disconnect_error
            )
            backoff_index, retry = _next_listener_retry(
                backoff_index, connected_duration
            )
            await self.forensics.async_set_listener_status(
                "reconnecting", retry_seconds=round(retry, 3)
            )
            with suppress(TimeoutError):
                await asyncio.wait_for(self._listener_stop.wait(), timeout=retry)

    async def _async_record_websocket_message(self, message: Any) -> None:
        received_at = utcnow_iso()
        if message.type in (WEBSOCKET_MESSAGE_PING, WEBSOCKET_MESSAGE_PONG):
            return
        if message.type == WEBSOCKET_MESSAGE_TEXT:
            try:
                payload = json.loads(message.data)
            except (json.JSONDecodeError, TypeError):
                encoded = str(message.data).encode()
                await self.forensics.async_record(
                    "websocket_unparsed",
                    "websocket",
                    {
                        "length": len(encoded),
                        "sha256": hashlib.sha256(encoded).hexdigest(),
                    },
                    recorded_at=received_at,
                )
                return
            event_type = _message_type(payload)
            user_device_ids = sorted(_nested_values(payload, ("userdeviceid",)))
            remote_times = sorted(
                _nested_values(payload, ("updatetime", "timestamp", "eventtime"))
            )
            is_device_report = event_type.casefold() == "devicereport"
            safe_payload = sanitize_forensics(payload)
            data = {
                "event_type": event_type,
                "message_id": _first_nested_value(payload, ("messageid",)),
                "user_device_id": (
                    user_device_ids[0] if len(user_device_ids) == 1 else None
                ),
                "user_device_ids": user_device_ids,
                "remote_time": remote_times[0] if len(remote_times) == 1 else None,
                "remote_times": remote_times,
                "same_frame_order_is_causal": False,
                "payload": (
                    _bounded_websocket_sample(
                        safe_payload, max_bytes=_DEVICE_REPORT_PAYLOAD_BYTES
                    )
                    if is_device_report
                    else _bounded_websocket_sample(safe_payload)
                ),
            }
            await self.forensics.async_record(
                "websocket_report" if is_device_report else "websocket_message",
                "websocket",
                data,
                recorded_at=received_at,
            )
            return
        if message.type == WEBSOCKET_MESSAGE_BINARY:
            payload = bytes(message.data)
            await self.forensics.async_record(
                "websocket_binary",
                "websocket",
                {
                    "length": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                recorded_at=received_at,
            )
            return
        if message.type == WEBSOCKET_MESSAGE_ERROR:
            raise KonkeApiError("WebSocket transport error")


def _next_listener_retry(
    backoff_index: int, connected_duration: float
) -> tuple[int, float]:
    """Return the next bounded retry index and jittered delay."""
    if connected_duration >= _WEBSOCKET_STABLE_CONNECTION_SECONDS:
        backoff_index = 0
    delay = _LISTENER_BACKOFF_SECONDS[
        min(backoff_index, len(_LISTENER_BACKOFF_SECONDS) - 1)
    ]
    next_index = min(backoff_index + 1, len(_LISTENER_BACKOFF_SECONDS) - 1)
    return next_index, delay * random.uniform(0.8, 1.0)


def _message_type(payload: Any) -> str:
    value = _first_nested_value(
        payload,
        ("messagetype", "msgtype", "eventtype", "event", "type", "cmd", "name"),
    )
    return "unknown" if value is None else str(value)


def _first_nested_value(payload: Any, keys: tuple[str, ...]) -> str | None:
    values = _nested_values(payload, keys)
    return values[0] if values else None


def _nested_values(payload: Any, keys: tuple[str, ...]) -> list[str]:
    """Collect unique scalar values in deterministic document order."""
    found: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        normalized = str(value)
        if normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    pending = [payload]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            normalized_items = [
                (
                    "".join(
                        character
                        for character in str(key).casefold()
                        if character.isalnum()
                    ),
                    value,
                )
                for key, value in current.items()
            ]
            for wanted_key in keys:
                for normalized_key, value in normalized_items:
                    if (
                        normalized_key == wanted_key
                        and value is not None
                        and not isinstance(value, (dict, list))
                    ):
                        add(value)
            pending.extend(reversed(current.values()))
        elif isinstance(current, list):
            pending.extend(reversed(current))
    return found


def _bounded_websocket_sample(
    payload: Any, *, max_bytes: int = _UNKNOWN_WEBSOCKET_SAMPLE_BYTES
) -> Any:
    """Limit unknown JSON samples while retaining a stable hash."""
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if len(encoded) <= max_bytes:
        return payload
    sample_bytes = min(max_bytes, _UNKNOWN_WEBSOCKET_SAMPLE_BYTES)
    return {
        "truncated": True,
        "original_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sample": encoded[:sample_bytes].decode("utf-8", "ignore"),
    }
