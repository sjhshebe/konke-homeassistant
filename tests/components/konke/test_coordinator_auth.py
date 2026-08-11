"""Tests for Konke coordinator authentication policy."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from custom_components.konke.const import (
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_ALLOW_PASSWORD_REAUTH,
    CONF_AUTH_METHOD,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)
from custom_components.konke.coordinator import KonkeDataUpdateCoordinator
from custom_components.konke.exceptions import KonkeAuthError
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from pytest_homeassistant_custom_component.common import MockConfigEntry


@pytest.mark.asyncio
async def test_password_reauth_enabled_by_default_for_password_entries(hass) -> None:
    """Password entries recover with stored credentials by default."""
    coordinator = _coordinator(hass, auth_method=AUTH_METHOD_PASSWORD, options={})
    coordinator.client.refresh_access_token = AsyncMock(
        side_effect=KonkeAuthError("bad token")
    )
    coordinator.client.login = AsyncMock(
        return_value={
            "data": {
                "userToken": {
                    "accessToken": "new-access",
                    "refreshToken": "new-refresh",
                }
            }
        }
    )

    assert await coordinator.async_refresh_auth()
    coordinator.client.login.assert_awaited_once()


@pytest.mark.asyncio
async def test_password_reauth_can_be_disabled_explicitly(hass) -> None:
    """Stored passwords are not used when the option is explicitly disabled."""
    coordinator = _coordinator(
        hass,
        auth_method=AUTH_METHOD_PASSWORD,
        options={CONF_ALLOW_PASSWORD_REAUTH: False},
    )
    coordinator.client.refresh_access_token = AsyncMock(
        side_effect=KonkeAuthError("bad token")
    )
    coordinator.client.login = AsyncMock()

    assert not await coordinator.async_refresh_auth()
    coordinator.client.login.assert_not_called()


@pytest.mark.asyncio
async def test_token_entries_do_not_password_reauth_by_default(hass) -> None:
    """Token entries do not use stored passwords unless explicitly enabled."""
    coordinator = _coordinator(hass, auth_method=AUTH_METHOD_TOKEN, options={})
    coordinator.client.refresh_access_token = AsyncMock(
        side_effect=KonkeAuthError("bad token")
    )
    coordinator.client.login = AsyncMock()

    assert not await coordinator.async_refresh_auth()
    coordinator.client.login.assert_not_called()


@pytest.mark.asyncio
async def test_password_reauth_can_be_enabled_explicitly(hass) -> None:
    """Stored passwords can still be enabled explicitly for compatible entries."""
    coordinator = _coordinator(
        hass,
        auth_method=AUTH_METHOD_TOKEN,
        options={CONF_ALLOW_PASSWORD_REAUTH: True},
    )
    coordinator.client.refresh_access_token = AsyncMock(
        side_effect=KonkeAuthError("bad token")
    )
    coordinator.client.login = AsyncMock(
        return_value={
            "data": {
                "userToken": {
                    "accessToken": "new-access",
                    "refreshToken": "new-refresh",
                }
            }
        }
    )

    assert await coordinator.async_refresh_auth()
    coordinator.client.login.assert_awaited_once()


@pytest.mark.asyncio
async def test_concurrent_failures_refresh_the_same_token_once(hass) -> None:
    """Waiters reuse a token already replaced by the first refresh."""
    coordinator = _coordinator(hass, auth_method=AUTH_METHOD_TOKEN, options={})
    refresh_started = asyncio.Event()
    finish_refresh = asyncio.Event()

    async def refresh_access_token() -> dict:
        refresh_started.set()
        await finish_refresh.wait()
        coordinator.client.access_token = "new-access"
        coordinator.client.refresh_token = "new-refresh"
        return {}

    coordinator.client.refresh_access_token = AsyncMock(
        side_effect=refresh_access_token
    )
    first = asyncio.create_task(
        coordinator.async_refresh_auth(failed_access_token="old-access")
    )
    await refresh_started.wait()
    second = asyncio.create_task(
        coordinator.async_refresh_auth(failed_access_token="old-access")
    )
    await asyncio.sleep(0)

    finish_refresh.set()

    assert await asyncio.gather(first, second) == [True, True]
    coordinator.client.refresh_access_token.assert_awaited_once()


def _coordinator(
    hass,
    *,
    auth_method: str,
    options: dict,
) -> KonkeDataUpdateCoordinator:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        data={
            CONF_USERNAME: "user",
            CONF_PASSWORD: "password",
            CONF_AUTH_METHOD: auth_method,
            CONF_ACCESS_TOKEN: "old-access",
            CONF_REFRESH_TOKEN: "refresh-token",
        },
        options=options,
        entry_id=f"konke-auth-{auth_method}",
    )
    entry.add_to_hass(hass)
    client = _FakeAuthClient(
        access_token="old-access",
        refresh_token="refresh-token",
    )
    return KonkeDataUpdateCoordinator(hass, entry, client)


class _FakeAuthClient:
    """Small fake client for coordinator auth tests."""

    def __init__(self, *, access_token: str, refresh_token: str) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token

    @staticmethod
    def extract_token_payload(payload: dict) -> dict:
        """Extract token fields from fake auth payloads."""
        return {
            "access_token": payload["data"]["userToken"]["accessToken"],
            "refresh_token": payload["data"]["userToken"]["refreshToken"],
        }

    @staticmethod
    def expires_at_from_payload(_payload: dict) -> None:
        """Return no expiry for fake auth payloads."""
        return None
