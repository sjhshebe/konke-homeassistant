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
from .registry import reset_konke_registry


async def _select_home(
    client: KonkeApiClient,
    *,
    preferred_home_id: str | None = None,
) -> dict[str, Any]:
    """Return the home to configure for this account.

    An account can see several homes. Selection order:

    1. the previously configured home when it is still visible (reauthentication
       and account switching keep pointing at the same home);
    2. the account's default home (what the mobile app opens) when it contains
       devices;
    3. otherwise the home that actually contains devices, for example the
       shared family home when the account's own default home is empty.
    """
    home_index = await client.fetch_home_index(home_id="0")
    data = home_index.get("data")
    data = data if isinstance(data, dict) else {}
    current_home = data.get("home")
    current_home = current_home if isinstance(current_home, dict) else {}
    default_home_id = (
        str(current_home["homeId"]) if current_home.get("homeId") is not None else None
    )

    candidates: list[str] = []
    if default_home_id is not None:
        candidates.append(default_home_id)
    for item in data.get("homeList") or []:
        if not isinstance(item, dict) or item.get("homeId") is None:
            continue
        home_id = str(item["homeId"])
        if home_id not in candidates:
            candidates.append(home_id)
    if not candidates:
        raise KonkeApiError("No home found in Konke account")

    async def _device_total(home_id: str) -> int:
        try:
            return await client.fetch_device_total(home_id=home_id)
        except KonkeApiError:
            return 0

    preferred = str(preferred_home_id) if preferred_home_id else None
    chosen: str | None = None
    if preferred and preferred in candidates:
        chosen = preferred
    elif len(candidates) == 1:
        chosen = candidates[0]
    else:
        default_total = (
            await _device_total(default_home_id) if default_home_id else 0
        )
        if default_home_id and default_total > 0:
            chosen = default_home_id
        else:
            best_total = 0
            for candidate in candidates:
                total = await _device_total(candidate)
                if total > best_total:
                    chosen = candidate
                    best_total = total
            if chosen is None:
                chosen = candidates[0]

    if current_home and str(current_home.get("homeId")) == chosen:
        return current_home
    chosen_index = await client.fetch_home_index(home_id=chosen)
    home = client.extract_home(chosen_index)
    if str(home.get("homeId")) == chosen:
        return home
    for item in chosen_index.get("data", {}).get("homeList", []) or []:
        if isinstance(item, dict) and str(item.get("homeId")) == chosen:
            return item
    raise KonkeApiError("Selected home is not accessible")


async def _validate_token(
    hass: HomeAssistant,
    token: str,
    refresh_token: str,
    country_code: str,
    region_id: str,
    *,
    preferred_home_id: str | None = None,
) -> dict[str, Any]:
    """Validate access token and return config data."""
    client = KonkeApiClient(
        async_get_clientsession(hass),
        access_token=token,
        country_code=country_code,
        region_id=region_id,
    )
    await client.validate_token()
    home = await _select_home(client, preferred_home_id=preferred_home_id)
    home_index = await client.fetch_home_index(home_id=home["homeId"])
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
    *,
    preferred_home_id: str | None = None,
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
    await client.validate_token()
    home = await _select_home(client, preferred_home_id=preferred_home_id)
    home_index = await client.fetch_home_index(home_id=home["homeId"])
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


def _entry_auth_method(entry: config_entries.ConfigEntry) -> str:
    """Return the authentication method stored on a config entry."""
    auth_method = entry.data.get(CONF_AUTH_METHOD)
    if auth_method in (AUTH_METHOD_PASSWORD, AUTH_METHOD_TOKEN):
        return auth_method
    return (
        AUTH_METHOD_PASSWORD
        if entry.data.get(CONF_USERNAME)
        else AUTH_METHOD_TOKEN
    )


def _auth_method_schema(
    default: str = AUTH_METHOD_TOKEN,
) -> vol.Schema:
    """Return auth method schema."""
    return vol.Schema(
        {
            vol.Required(
                CONF_AUTH_METHOD, default=default
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

    _reconfigure_auth_method: str = AUTH_METHOD_TOKEN

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
                        preferred_home_id=existing_data.get(CONF_HOME_ID),
                    )
                else:
                    data = await _validate_password(
                        self.hass,
                        user_input[CONF_USERNAME].strip(),
                        user_input[CONF_PASSWORD],
                        country_code,
                        region_id,
                        preferred_home_id=existing_data.get(CONF_HOME_ID),
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

    async def async_step_reconfigure(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Point this config entry at another Konke account.

        Reauthentication only accepts credentials of the account the entry
        already belongs to, because it is triggered by an expired login.
        Reconfiguration is the explicit user action used to move the entry to
        another account, for example a family member account that shares the
        same home. Konke allows only one active cloud session per account, so
        a separate shared account is the supported way to keep the phone app
        and Home Assistant online at the same time.

        The first step selects the authentication method, so an entry can be
        moved between password and token authentication as well. When the
        account or home changes, registry entries created for the previous
        account are removed before the entry reloads, so entities are
        recreated from the new account's device data instead of leaving
        duplicates behind.
        """
        if user_input is not None:
            auth_method = user_input[CONF_AUTH_METHOD]
            if auth_method not in (AUTH_METHOD_PASSWORD, AUTH_METHOD_TOKEN):
                auth_method = _entry_auth_method(self._get_reconfigure_entry())
            self._reconfigure_auth_method = auth_method
            return await self.async_step_reconfigure_confirm()

        entry = self._get_reconfigure_entry()
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_auth_method_schema(_entry_auth_method(entry)),
        )

    async def async_step_reconfigure_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Validate the new account credentials during reconfiguration."""
        entry = self._get_reconfigure_entry()
        auth_method = self._reconfigure_auth_method
        errors: dict[str, str] = {}
        if user_input is not None:
            country_code = str(
                user_input.get(
                    CONF_COUNTRY_CODE,
                    entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
                )
            ).strip()
            region_id = str(
                user_input.get(
                    CONF_REGION_ID,
                    entry.data.get(CONF_REGION_ID, DEFAULT_REGION_ID),
                )
            ).strip()
            try:
                if auth_method == AUTH_METHOD_TOKEN:
                    data = await _validate_token(
                        self.hass,
                        user_input[CONF_ACCESS_TOKEN].strip(),
                        str(user_input.get(CONF_REFRESH_TOKEN, "")).strip(),
                        country_code,
                        region_id,
                        preferred_home_id=entry.data.get(CONF_HOME_ID),
                    )
                else:
                    data = await _validate_password(
                        self.hass,
                        user_input[CONF_USERNAME].strip(),
                        user_input[CONF_PASSWORD],
                        country_code,
                        region_id,
                        preferred_home_id=entry.data.get(CONF_HOME_ID),
                    )
            except KonkeAuthError:
                errors["base"] = "invalid_auth"
            except KonkeCannotConnect:
                errors["base"] = "cannot_connect"
            except KonkeApiError:
                errors["base"] = "unknown"
            else:
                data[CONF_AUTH_METHOD] = auth_method
                data[CONF_VERSION_HEADER] = entry.data.get(
                    CONF_VERSION_HEADER, DEFAULT_VERSION_HEADER
                )
                new_unique_id = f"{DOMAIN}_{data[CONF_USER_ID]}_{data[CONF_HOME_ID]}"
                existing = (
                    self.hass.config_entries.async_entry_for_domain_unique_id(
                        DOMAIN, new_unique_id
                    )
                )
                if existing is not None and existing.entry_id != entry.entry_id:
                    return self.async_abort(reason="already_configured")

                identity_changed = (
                    str(entry.data.get(CONF_USER_ID)) != data[CONF_USER_ID]
                    or str(entry.data.get(CONF_HOME_ID)) != data[CONF_HOME_ID]
                )
                if identity_changed:
                    reset_konke_registry(self.hass, entry)

                self.hass.config_entries.async_update_entry(
                    entry,
                    unique_id=new_unique_id,
                    title=data.get(CONF_HOME_NAME) or entry.title,
                    data={**entry.data, **data},
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure_confirm",
            data_schema=(
                _token_schema(entry.data)
                if auth_method == AUTH_METHOD_TOKEN
                else _password_schema(entry.data)
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
