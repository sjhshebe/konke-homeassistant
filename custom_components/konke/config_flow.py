"""Config flow for Konke Smart."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import KonkeApiClient
from .const import (
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_ALLOW_PASSWORD_REAUTH,
    CONF_AUTH_METHOD,
    CONF_COUNTRY_CODE,
    CONF_CREATE_OFFLINE_DEVICE_ENTITIES,
    CONF_CREATE_SCENE_ENTITIES,
    CONF_FORENSIC_LOGGING,
    CONF_FORENSIC_RETENTION_DAYS,
    CONF_FORENSIC_WEBSOCKET,
    CONF_HOME_ID,
    CONF_HOME_NAME,
    CONF_REFRESH_TOKEN,
    CONF_REGION_ID,
    CONF_SCAN_INTERVAL,
    CONF_TOKEN_EXPIRES_AT,
    CONF_USER_ID,
    CONF_VERSION_HEADER,
    DOMAIN,
)
from .exceptions import KonkeApiError, KonkeAuthError, KonkeCannotConnect
from .options import (
    options_from_mapping,
)
from .profile import (
    DEFAULT_COUNTRY_CODE,
    DEFAULT_REGION_ID,
    DEFAULT_VERSION_HEADER,
)


async def _validate_token(
    hass: HomeAssistant,
    token: str,
    refresh_token: str,
    country_code: str,
    region_id: str,
) -> dict[str, Any]:
    """Validate access token and return config data."""
    client = KonkeApiClient(
        async_get_clientsession(hass),
        access_token=token,
        country_code=country_code,
        region_id=region_id,
    )
    home_index = await client.validate_token()
    home = client.extract_home(home_index)
    user_id = home_index.get("data", {}).get("user", {}).get("userId")
    return {
        CONF_ACCESS_TOKEN: token,
        CONF_REFRESH_TOKEN: refresh_token,
        CONF_COUNTRY_CODE: country_code,
        CONF_REGION_ID: region_id,
        CONF_HOME_ID: str(home["homeId"]),
        CONF_HOME_NAME: home.get("homeName") or "Konke Home",
        CONF_USER_ID: str(user_id or home["homeId"]),
        CONF_VERSION_HEADER: DEFAULT_VERSION_HEADER,
    }


async def _validate_password(
    hass: HomeAssistant,
    username: str,
    password: str,
    country_code: str,
    region_id: str,
) -> dict[str, Any]:
    """Validate username/password and return config data."""
    client = KonkeApiClient(
        async_get_clientsession(hass),
        country_code=country_code,
        region_id=region_id,
    )
    login_payload = await client.login(
        username,
        password,
        country_code=country_code,
        region_id=region_id,
    )
    home_index = await client.validate_token()
    home = client.extract_home(home_index)
    user_token = login_payload.get("data", {}).get("userToken", {})
    user_id = user_token.get("userId") or home_index.get("data", {}).get(
        "user", {}
    ).get("userId")
    token_expires_at = client.expires_at_from_payload(login_payload)
    return {
        CONF_USERNAME: username,
        CONF_PASSWORD: password,
        CONF_ACCESS_TOKEN: client.access_token,
        CONF_REFRESH_TOKEN: client.refresh_token,
        CONF_TOKEN_EXPIRES_AT: token_expires_at,
        CONF_COUNTRY_CODE: country_code,
        CONF_REGION_ID: region_id,
        CONF_HOME_ID: str(home["homeId"]),
        CONF_HOME_NAME: home.get("homeName") or "Konke Home",
        CONF_USER_ID: str(user_id or home["homeId"]),
        CONF_VERSION_HEADER: DEFAULT_VERSION_HEADER,
    }


def _auth_method_schema() -> vol.Schema:
    """Return auth method schema."""
    return vol.Schema(
        {
            vol.Required(
                CONF_AUTH_METHOD, default=AUTH_METHOD_TOKEN
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        {"value": AUTH_METHOD_TOKEN, "label": "Access Token"},
                        {"value": AUTH_METHOD_PASSWORD, "label": "手机号和密码"},
                    ],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            )
        }
    )


def _token_schema(defaults: Mapping[str, Any] | None = None) -> vol.Schema:
    """Return token form schema."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_ACCESS_TOKEN): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(CONF_REFRESH_TOKEN): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(
                CONF_COUNTRY_CODE,
                default=str(defaults.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)),
            ): str,
            vol.Optional(
                CONF_REGION_ID,
                default=str(defaults.get(CONF_REGION_ID, DEFAULT_REGION_ID)),
            ): str,
        }
    )


def _password_schema(defaults: Mapping[str, Any] | None = None) -> vol.Schema:
    """Return username/password form schema."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(
                CONF_USERNAME,
                default=str(defaults.get(CONF_USERNAME, "")),
            ): str,
            vol.Required(CONF_PASSWORD): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(
                CONF_COUNTRY_CODE,
                default=str(defaults.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)),
            ): str,
            vol.Optional(
                CONF_REGION_ID,
                default=str(defaults.get(CONF_REGION_ID, DEFAULT_REGION_ID)),
            ): str,
        }
    )


def _options_schema(config_entry: config_entries.ConfigEntry) -> vol.Schema:
    """Return options flow schema."""
    options = options_from_mapping(config_entry.options)
    return vol.Schema(
        {
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=options.scan_interval_minutes,
            ): vol.All(vol.Coerce(int), vol.Range(min=1, max=1440)),
            vol.Optional(
                CONF_CREATE_SCENE_ENTITIES,
                default=options.create_scene_entities,
            ): bool,
            vol.Optional(
                CONF_CREATE_OFFLINE_DEVICE_ENTITIES,
                default=options.create_offline_device_entities,
            ): bool,
            vol.Optional(
                CONF_FORENSIC_LOGGING,
                default=options.forensic_logging,
            ): bool,
            vol.Optional(
                CONF_FORENSIC_WEBSOCKET,
                default=options.forensic_websocket,
            ): bool,
            vol.Optional(
                CONF_FORENSIC_RETENTION_DAYS,
                default=options.forensic_retention_days,
            ): vol.All(vol.Coerce(int), vol.Range(min=1, max=90)),
            vol.Optional(
                CONF_ALLOW_PASSWORD_REAUTH,
                default=options.allow_password_reauth,
            ): bool,
        }
    )


class KonkeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Konke Smart."""

    VERSION = 2

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Select auth method."""
        if user_input is not None:
            auth_method = user_input[CONF_AUTH_METHOD]
            if auth_method == AUTH_METHOD_PASSWORD:
                return await self.async_step_password()
            return await self.async_step_token()

        return self.async_show_form(
            step_id="user",
            data_schema=_auth_method_schema(),
        )

    async def async_step_token(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Configure with access token."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await _validate_token(
                    self.hass,
                    user_input[CONF_ACCESS_TOKEN].strip(),
                    user_input.get(CONF_REFRESH_TOKEN, "").strip(),
                    user_input.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE).strip(),
                    user_input.get(CONF_REGION_ID, DEFAULT_REGION_ID).strip(),
                )
            except KonkeAuthError:
                errors["base"] = "invalid_auth"
            except KonkeCannotConnect:
                errors["base"] = "cannot_connect"
            except KonkeApiError:
                errors["base"] = "unknown"
            else:
                data[CONF_AUTH_METHOD] = AUTH_METHOD_TOKEN
                await self.async_set_unique_id(
                    f"{DOMAIN}_{data[CONF_USER_ID]}_{data[CONF_HOME_ID]}"
                )
                self._abort_if_unique_id_configured(updates=data)
                return self.async_create_entry(title=data[CONF_HOME_NAME], data=data)

        return self.async_show_form(
            step_id="token",
            data_schema=_token_schema(),
            errors=errors,
        )

    async def async_step_password(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Configure with username/password."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await _validate_password(
                    self.hass,
                    user_input[CONF_USERNAME].strip(),
                    user_input[CONF_PASSWORD],
                    user_input.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE).strip(),
                    user_input.get(CONF_REGION_ID, DEFAULT_REGION_ID).strip(),
                )
            except KonkeAuthError:
                errors["base"] = "invalid_auth"
            except KonkeCannotConnect:
                errors["base"] = "cannot_connect"
            except KonkeApiError:
                errors["base"] = "unknown"
            else:
                data[CONF_AUTH_METHOD] = AUTH_METHOD_PASSWORD
                await self.async_set_unique_id(
                    f"{DOMAIN}_{data[CONF_USER_ID]}_{data[CONF_HOME_ID]}"
                )
                self._abort_if_unique_id_configured(updates=data)
                return self.async_create_entry(title=data[CONF_HOME_NAME], data=data)

        return self.async_show_form(
            step_id="password",
            data_schema=_password_schema(),
            errors=errors,
        )

    async def async_step_reauth(
        self,
        entry_data: dict[str, Any],
    ) -> config_entries.ConfigFlowResult:
        """Handle reauthentication."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Ask for credentials again during reauth."""
        if self._reauth_entry is None:
            return self.async_abort(reason="reauth_entry_missing")

        auth_method = self._reauth_entry.data.get(
            CONF_AUTH_METHOD,
            AUTH_METHOD_PASSWORD
            if self._reauth_entry.data.get(CONF_USERNAME)
            else AUTH_METHOD_TOKEN,
        )
        errors: dict[str, str] = {}
        if user_input is not None:
            existing_data = self._reauth_entry.data
            country_code = str(
                user_input.get(
                    CONF_COUNTRY_CODE,
                    existing_data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
                )
            ).strip()
            region_id = str(
                user_input.get(
                    CONF_REGION_ID,
                    existing_data.get(CONF_REGION_ID, DEFAULT_REGION_ID),
                )
            ).strip()
            try:
                if auth_method == AUTH_METHOD_TOKEN:
                    data = await _validate_token(
                        self.hass,
                        user_input[CONF_ACCESS_TOKEN].strip(),
                        str(
                            user_input.get(
                                CONF_REFRESH_TOKEN,
                                existing_data.get(CONF_REFRESH_TOKEN, ""),
                            )
                        ).strip(),
                        country_code,
                        region_id,
                    )
                else:
                    data = await _validate_password(
                        self.hass,
                        user_input[CONF_USERNAME].strip(),
                        user_input[CONF_PASSWORD],
                        country_code,
                        region_id,
                    )
            except KonkeAuthError:
                errors["base"] = "invalid_auth"
            except KonkeCannotConnect:
                errors["base"] = "cannot_connect"
            except KonkeApiError:
                errors["base"] = "unknown"
            else:
                data[CONF_AUTH_METHOD] = auth_method
                data[CONF_VERSION_HEADER] = existing_data.get(
                    CONF_VERSION_HEADER, DEFAULT_VERSION_HEADER
                )
                await self.async_set_unique_id(
                    f"{DOMAIN}_{data[CONF_USER_ID]}_{data[CONF_HOME_ID]}"
                )
                self._abort_if_unique_id_mismatch(reason="wrong_account")
                return self.async_update_reload_and_abort(
                    self._reauth_entry,
                    data_updates=data,
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=(
                _token_schema(self._reauth_entry.data)
                if auth_method == AUTH_METHOD_TOKEN
                else _password_schema(self._reauth_entry.data)
            ),
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Return options flow handler."""
        return KonkeOptionsFlow(config_entry)


class KonkeOptionsFlow(config_entries.OptionsFlow):
    """Handle Konke options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Manage options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(self._config_entry),
        )
