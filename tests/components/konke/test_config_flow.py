"""Tests for Konke config and reauthentication flows."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
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
from homeassistant.config_entries import SOURCE_REAUTH
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
