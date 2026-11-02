"""Tests for Konke config and reauthentication flows."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from custom_components.konke.config_flow import _select_home
from custom_components.konke.const import (
    AUTH_METHOD_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_AUTH_METHOD,
    CONF_COUNTRY_CODE,
    CONF_HOME_ID,
    CONF_HOME_NAME,
    CONF_REFRESH_TOKEN,
    CONF_REGION_ID,
    CONF_USER_ID,
    CONF_VERSION_HEADER,
    DOMAIN,
)
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_RECONFIGURE
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry


def _reauth_entry() -> MockConfigEntry:
    """Return a token entry with non-default connection profile fields."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        unique_id="konke_user-1_home-1",
        data={
            CONF_AUTH_METHOD: AUTH_METHOD_TOKEN,
            CONF_ACCESS_TOKEN: "old-access",
            CONF_REFRESH_TOKEN: "old-refresh",
            CONF_COUNTRY_CODE: "+99",
            CONF_REGION_ID: "custom-region",
            CONF_HOME_ID: "home-1",
            CONF_HOME_NAME: "Original home",
            CONF_USER_ID: "user-1",
            CONF_VERSION_HEADER: "custom-version",
        },
        entry_id="konke-reauth-entry",
    )


@pytest.mark.asyncio
async def test_token_reauth_preserves_profile_and_refresh_token(hass) -> None:
    """A token replacement keeps omitted refresh and connection profile data."""
    entry = _reauth_entry()
    entry.add_to_hass(hass)
    validated = {
        CONF_ACCESS_TOKEN: "new-access",
        CONF_REFRESH_TOKEN: "old-refresh",
        CONF_COUNTRY_CODE: "+99",
        CONF_REGION_ID: "custom-region",
        CONF_HOME_ID: "home-1",
        CONF_HOME_NAME: "Original home",
        CONF_USER_ID: "user-1",
        CONF_VERSION_HEADER: "ignored-default-version",
    }

    with patch(
        "custom_components.konke.config_flow._validate_token",
        AsyncMock(return_value=validated),
    ) as validate:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
            data=entry.data,
        )
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "reauth_confirm"

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_ACCESS_TOKEN: "new-access"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    validate.assert_awaited_once_with(
        hass,
        "new-access",
        "old-refresh",
        "+99",
        "custom-region",
        preferred_home_id="home-1",
    )
    assert entry.data[CONF_ACCESS_TOKEN] == "new-access"
    assert entry.data[CONF_REFRESH_TOKEN] == "old-refresh"
    assert entry.data[CONF_VERSION_HEADER] == "custom-version"


@pytest.mark.asyncio
async def test_token_reauth_rejects_a_different_account_or_home(hass) -> None:
    """Credentials for another identity cannot replace an existing entry."""
    entry = _reauth_entry()
    entry.add_to_hass(hass)
    original_data = dict(entry.data)
    validated = {
        CONF_ACCESS_TOKEN: "other-access",
        CONF_REFRESH_TOKEN: "other-refresh",
        CONF_COUNTRY_CODE: "+99",
        CONF_REGION_ID: "custom-region",
        CONF_HOME_ID: "other-home",
        CONF_HOME_NAME: "Other home",
        CONF_USER_ID: "other-user",
        CONF_VERSION_HEADER: "ignored-default-version",
    }

    with patch(
        "custom_components.konke.config_flow._validate_token",
        AsyncMock(return_value=validated),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
            data=entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_ACCESS_TOKEN: "other-access"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "wrong_account"
    assert entry.data == original_data


@pytest.mark.asyncio
async def test_password_reauth_form_preserves_profile_defaults(hass) -> None:
    """Password reauth renders the existing country and region values."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Konke Smart",
        unique_id="konke_user-1_home-1",
        data={
            CONF_AUTH_METHOD: "password",
            CONF_USERNAME: "user@example.test",
            CONF_PASSWORD: "old-password",
            CONF_COUNTRY_CODE: "+99",
            CONF_REGION_ID: "custom-region",
            CONF_HOME_ID: "home-1",
            CONF_USER_ID: "user-1",
        },
        entry_id="konke-password-reauth-entry",
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    schema = result["data_schema"]
    validated = schema({CONF_USERNAME: "new-user", CONF_PASSWORD: "new-password"})

    assert validated[CONF_COUNTRY_CODE] == "+99"
    assert validated[CONF_REGION_ID] == "custom-region"


def _password_entry(entry_id: str = "konke-reconfigure-entry") -> MockConfigEntry:
    """Return a password authenticated entry used by reconfigure tests."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="我的家",
        unique_id="konke_user-1_home-1",
        data={
            CONF_AUTH_METHOD: "password",
            CONF_USERNAME: "13800138000",
            CONF_PASSWORD: "old-password",
            CONF_ACCESS_TOKEN: "old-access",
            CONF_REFRESH_TOKEN: "old-refresh",
            CONF_COUNTRY_CODE: "86",
            CONF_REGION_ID: "CN",
            CONF_HOME_ID: "home-1",
            CONF_HOME_NAME: "我的家",
            CONF_USER_ID: "user-1",
            CONF_VERSION_HEADER: "custom-version",
        },
        entry_id=entry_id,
    )


def _validated_password_account(
    *,
    user_id: str,
    home_id: str,
    home_name: str,
    username: str = "13900139000",
    password: str = "new-password",
) -> dict:
    """Return the data dict produced by a successful password validation."""
    return {
        CONF_USERNAME: username,
        CONF_PASSWORD: password,
        CONF_ACCESS_TOKEN: "new-access",
        CONF_REFRESH_TOKEN: "new-refresh",
        CONF_COUNTRY_CODE: "86",
        CONF_REGION_ID: "CN",
        CONF_HOME_ID: home_id,
        CONF_HOME_NAME: home_name,
        CONF_USER_ID: user_id,
    }


@pytest.mark.asyncio
async def test_reconfigure_moves_entry_to_another_account(hass) -> None:
    """Reconfigure repoints the entry at a shared family account."""
    entry = _password_entry()
    entry.add_to_hass(hass)
    validated = _validated_password_account(
        user_id="user-2",
        home_id="home-1",
        home_name="家庭成员家",
    )

    with (
        patch(
            "custom_components.konke.config_flow._validate_password",
            AsyncMock(return_value=validated),
        ),
        patch(
            "custom_components.konke.config_flow.reset_konke_registry"
        ) as reset_registry,
        patch(
            "homeassistant.config_entries.ConfigEntries.async_reload",
            AsyncMock(return_value=True),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
        )
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "reconfigure"
        assert result["data_schema"]({})[CONF_AUTH_METHOD] == "password"

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_AUTH_METHOD: "password"},
        )
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "reconfigure_confirm"

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "13900139000", CONF_PASSWORD: "new-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    reset_registry.assert_called_once()
    assert entry.unique_id == "konke_user-2_home-1"
    assert entry.title == "家庭成员家"
    assert entry.data[CONF_USER_ID] == "user-2"
    assert entry.data[CONF_USERNAME] == "13900139000"
    assert entry.data[CONF_VERSION_HEADER] == "custom-version"


@pytest.mark.asyncio
async def test_reconfigure_same_account_keeps_registry_entries(hass) -> None:
    """Changing only the password keeps devices and entity customizations."""
    entry = _password_entry()
    entry.add_to_hass(hass)
    validated = _validated_password_account(
        user_id="user-1",
        home_id="home-1",
        home_name="我的家",
    )

    with (
        patch(
            "custom_components.konke.config_flow._validate_password",
            AsyncMock(return_value=validated),
        ),
        patch(
            "custom_components.konke.config_flow.reset_konke_registry"
        ) as reset_registry,
        patch(
            "homeassistant.config_entries.ConfigEntries.async_reload",
            AsyncMock(return_value=True),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_AUTH_METHOD: "password"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "13800138000", CONF_PASSWORD: "new-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    reset_registry.assert_not_called()
    assert entry.unique_id == "konke_user-1_home-1"
    assert entry.data[CONF_PASSWORD] == "new-password"


@pytest.mark.asyncio
async def test_reconfigure_rejects_an_account_configured_elsewhere(hass) -> None:
    """A shared account already configured in another entry is rejected."""
    entry = _password_entry()
    entry.add_to_hass(hass)
    other_entry = MockConfigEntry(
        domain=DOMAIN,
        title="Other",
        unique_id="konke_user-9_home-9",
        data={CONF_AUTH_METHOD: "password"},
        entry_id="konke-other-entry",
    )
    other_entry.add_to_hass(hass)
    validated = _validated_password_account(
        user_id="user-9",
        home_id="home-9",
        home_name="Other",
    )

    with (
        patch(
            "custom_components.konke.config_flow._validate_password",
            AsyncMock(return_value=validated),
        ),
        patch(
            "custom_components.konke.config_flow.reset_konke_registry"
        ) as reset_registry,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_AUTH_METHOD: "password"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "13900139000", CONF_PASSWORD: "new-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    reset_registry.assert_not_called()
    assert entry.unique_id == "konke_user-1_home-1"


def _token_entry(entry_id: str = "konke-token-reconfigure-entry") -> MockConfigEntry:
    """Return a token authenticated entry used by method switch tests."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="我的家",
        unique_id="konke_user-1_home-1",
        data={
            CONF_AUTH_METHOD: AUTH_METHOD_TOKEN,
            CONF_ACCESS_TOKEN: "old-access",
            CONF_REFRESH_TOKEN: "old-refresh",
            CONF_COUNTRY_CODE: "86",
            CONF_REGION_ID: "CN",
            CONF_HOME_ID: "home-1",
            CONF_HOME_NAME: "我的家",
            CONF_USER_ID: "user-1",
            CONF_VERSION_HEADER: "custom-version",
        },
        entry_id=entry_id,
    )


@pytest.mark.asyncio
async def test_reconfigure_can_switch_from_token_to_password(hass) -> None:
    """Reconfigure can move a token entry to password authentication."""
    entry = _token_entry()
    entry.add_to_hass(hass)
    validated = _validated_password_account(
        user_id="user-1",
        home_id="home-1",
        home_name="我的家",
        username="13800138000",
        password="new-password",
    )

    with (
        patch(
            "custom_components.konke.config_flow._validate_password",
            AsyncMock(return_value=validated),
        ),
        patch(
            "custom_components.konke.config_flow.reset_konke_registry"
        ) as reset_registry,
        patch(
            "homeassistant.config_entries.ConfigEntries.async_reload",
            AsyncMock(return_value=True),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
        )
        assert result["step_id"] == "reconfigure"
        assert result["data_schema"]({})[CONF_AUTH_METHOD] == AUTH_METHOD_TOKEN

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_AUTH_METHOD: "password"},
        )
        assert result["step_id"] == "reconfigure_confirm"

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "13800138000", CONF_PASSWORD: "new-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    reset_registry.assert_not_called()
    assert entry.data[CONF_AUTH_METHOD] == "password"
    assert entry.data[CONF_USERNAME] == "13800138000"
    assert entry.data[CONF_PASSWORD] == "new-password"


class _FakeHomeClient:
    """Minimal client for home selection tests."""

    def __init__(self, index: dict, totals: dict) -> None:
        self._index = index
        self._totals = totals
        self.device_total_calls: list[str] = []

    async def fetch_home_index(self, *, home_id: str = "0") -> dict:
        return self._index.get(str(home_id), self._index["0"])

    def extract_home(self, payload: dict) -> dict:
        return payload["data"]["home"]

    async def fetch_device_total(self, *, home_id: str) -> int:
        self.device_total_calls.append(str(home_id))
        return self._totals.get(str(home_id), 0)


def _multi_home_index() -> dict:
    """Return a home index for an account with an own and a shared home."""
    return {
        "0": {
            "data": {
                "home": {"homeId": 255027, "homeName": "我的家", "areaList": [1]},
                "homeList": [{"homeId": 255027}, {"homeId": 214716}],
            }
        },
        "255027": {
            "data": {"home": {"homeId": 255027, "homeName": "我的家", "areaList": [1]}}
        },
        "214716": {
            "data": {
                "home": {"homeId": 214716, "homeName": "我的家", "areaList": [1]}
            }
        },
    }


@pytest.mark.asyncio
async def test_select_home_prefers_default_home_with_devices() -> None:
    """The account's default home wins when it contains devices."""
    client = _FakeHomeClient(_multi_home_index(), {"255027": 5, "214716": 35})

    home = await _select_home(client)

    assert home["homeId"] == 255027
    assert client.device_total_calls == ["255027"]


@pytest.mark.asyncio
async def test_select_home_falls_back_to_home_with_devices() -> None:
    """An empty default home falls back to the shared home with devices."""
    client = _FakeHomeClient(_multi_home_index(), {"255027": 0, "214716": 35})

    home = await _select_home(client)

    assert home["homeId"] == 214716


@pytest.mark.asyncio
async def test_select_home_keeps_preferred_home() -> None:
    """Reauthentication and account switching keep the configured home."""
    client = _FakeHomeClient(_multi_home_index(), {"255027": 5, "214716": 35})

    home = await _select_home(client, preferred_home_id="214716")

    assert home["homeId"] == 214716
    assert client.device_total_calls == []
