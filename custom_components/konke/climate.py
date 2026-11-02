"""Climate platform for Konke Smart."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import (
    FAN_AUTO,
    FAN_HIGH,
    FAN_LOW,
    FAN_MEDIUM,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .capabilities import KonkeCapability
from .command import (
    ACTION_SET_MODE,
    ACTION_SET_TEMPERATURE,
    ACTION_SET_WIND_SPEED,
    ACTION_TURN_OFF,
    ACTION_TURN_ON,
)
from .const import DOMAIN
from .coordinator import KonkeDataUpdateCoordinator
from .device_profiles import (
    AIR_CONDITIONER_FAN_ALIASES,
    AIR_CONDITIONER_FAN_KEY_TO_KONKE,
    AIR_CONDITIONER_HVAC_KEY_TO_MODE,
    AIR_CONDITIONER_MODE_TO_HVAC_KEY,
    AIR_CONDITIONER_WORK_MODE_TO_HVAC_KEY,
    FLOOR_HEATING_HVAC_KEY_TO_MODE,
    FLOOR_HEATING_WORK_MODE_TO_HVAC_KEY,
)
from .entity import KonkeDeviceEntity
from .platform_helpers import (
    device_base_attributes,
    device_ids_for_capability,
    device_name_or_id,
    device_state,
    float_from_state,
    int_from_state,
    power_from_state,
)

_AIR_CONDITIONER_FAN_MODES = [FAN_AUTO, FAN_LOW, FAN_MEDIUM, FAN_HIGH]
_HVAC_BY_KEY = {
    "auto": HVACMode.AUTO,
    "cool": HVACMode.COOL,
    "dry": HVACMode.DRY,
    "fan_only": HVACMode.FAN_ONLY,
    "heat": HVACMode.HEAT,
}
_HVAC_KEY_BY_MODE = {
    value: key
    for key, value in _HVAC_BY_KEY.items()
}
_FAN_BY_KEY = {
    "auto": FAN_AUTO,
    "high": FAN_HIGH,
    "low": FAN_LOW,
    "medium": FAN_MEDIUM,
}
_FAN_KEY_BY_MODE = {value: key for key, value in _FAN_BY_KEY.items()}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Konke climate devices from a config entry."""
    coordinator: KonkeDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            KonkeAirConditionerClimate(coordinator, entry, device_id)
            for device_id in device_ids_for_capability(
                coordinator, entry, KonkeCapability.AIR_CONDITIONER
            )
        ]
        + [
            KonkeFloorHeatingClimate(coordinator, entry, device_id)
            for device_id in device_ids_for_capability(
                coordinator, entry, KonkeCapability.FLOOR_HEATING
            )
        ]
    )


class KonkeClimateBase(KonkeDeviceEntity, ClimateEntity):
    """Shared behavior for Konke climate entities."""

    _attr_precision = 0.5
    _attr_target_temperature_step = 0.5
    _enable_turn_on_off_backwards_compatibility = False

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
        *,
        unique_id_suffix: str,
    ) -> None:
        """Initialize the climate entity."""
        super().__init__(coordinator, entry, device_id)
        self._attr_unique_id = (
            f"{DOMAIN}_{self.konke_home_id}_{unique_id_suffix}_{device_id}"
        )

    @property
    def name(self) -> str | None:
        """Return the entity name."""
        return device_name_or_id(self.konke_device, self._device_id)

    @property
    def temperature_unit(self) -> str:
        """Return the unit of measurement."""
        return UnitOfTemperature.CELSIUS

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        device = self.konke_device
        if device is None:
            return None
        return float_from_state(
            device_state(device),
            "curTemp",
            "currentTemperature",
        )

    @property
    def target_temperature(self) -> float | None:
        """Return the target temperature."""
        device = self.konke_device
        if device is None:
            return None
        return float_from_state(
            device_state(device),
            "setTemp",
            "temperature",
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return debug attributes for the mapped Konke device."""
        device = self.konke_device
        if device is None:
            return {}
        state = device_state(device)
        return {
            **device_base_attributes(device),
            "konke_mode": state.get("mode"),
            "konke_work_mode": state.get("workMode"),
            "konke_fan_speed": state.get("speed") or state.get("windSpeed"),
        }

    async def async_turn_on(self) -> None:
        """Turn the climate device on."""
        await self.async_control_device(ACTION_TURN_ON)

    async def async_turn_off(self) -> None:
        """Turn the climate device off."""
        await self.async_control_device(ACTION_TURN_OFF)

    async def _async_set_temperature_value(self, temperature: Any) -> None:
        """Set a numeric target temperature."""
        if temperature is None:
            return
        try:
            value = float(temperature)
        except (TypeError, ValueError) as err:
            raise HomeAssistantError("Konke temperature must be numeric") from err
        await self.async_control_device(
            ACTION_SET_TEMPERATURE,
            extension={"value": value},
        )


class KonkeAirConditionerClimate(KonkeClimateBase):
    """Representation of a Konke air conditioner."""

    _attr_icon = "mdi:air-conditioner"
    _attr_supported_features = (
        ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
        | ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
    )

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
    ) -> None:
        """Initialize the air-conditioner entity."""
        super().__init__(
            coordinator,
            entry,
            device_id,
            unique_id_suffix="climate",
        )

    @property
    def min_temp(self) -> float:
        """Return the minimum supported target temperature."""
        return 16.0

    @property
    def max_temp(self) -> float:
        """Return the maximum supported target temperature."""
        return 30.0

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return supported HVAC modes."""
        return [
            HVACMode.OFF,
            HVACMode.COOL,
            HVACMode.HEAT,
            HVACMode.FAN_ONLY,
            HVACMode.DRY,
        ]

    @property
    def hvac_mode(self) -> HVACMode | None:
        """Return the current HVAC mode."""
        device = self.konke_device
        if device is None:
            return HVACMode.OFF
        if device.power_on is False:
            return HVACMode.OFF

        state = device_state(device)
        mode = _air_conditioner_hvac_mode(state)
        if mode is not None:
            return mode

        if device.power_on is True:
            return HVACMode.COOL
        return HVACMode.OFF

    @property
    def hvac_action(self) -> HVACAction | None:
        """Return the current HVAC action."""
        return _hvac_action_from_mode(self.hvac_mode)

    @property
    def fan_modes(self) -> list[str]:
        """Return supported fan modes."""
        return list(_AIR_CONDITIONER_FAN_MODES)

    @property
    def fan_mode(self) -> str | None:
        """Return the current fan mode."""
        device = self.konke_device
        if device is None:
            return None
        state = device_state(device)
        raw_speed = state.get("speed") or state.get("windSpeed")
        if raw_speed is None:
            return None
        fan_key = AIR_CONDITIONER_FAN_ALIASES.get(str(raw_speed).upper())
        if fan_key is None:
            return None
        return _FAN_BY_KEY.get(fan_key)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set target temperature."""
        await self._async_set_temperature_value(kwargs.get(ATTR_TEMPERATURE))

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set HVAC mode."""
        if hvac_mode == HVACMode.OFF:
            await self.async_turn_off()
            return

        hvac_key = _HVAC_KEY_BY_MODE.get(hvac_mode)
        konke_mode = AIR_CONDITIONER_HVAC_KEY_TO_MODE.get(hvac_key or "")
        if hvac_key is None or konke_mode is None:
            raise HomeAssistantError(
                f"Konke air conditioner does not support HVAC mode: {hvac_mode}"
            )

        if self.hvac_mode == HVACMode.OFF:
            await self.async_control_device(ACTION_TURN_ON, refresh=False)
        await self.async_control_device(
            ACTION_SET_MODE,
            extension={"mode": konke_mode},
        )

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """Set fan mode."""
        fan_key = _FAN_KEY_BY_MODE.get(str(fan_mode))
        fan_key = AIR_CONDITIONER_FAN_ALIASES.get(str(fan_mode).upper(), fan_key)
        normalized = _FAN_BY_KEY.get(fan_key or "")
        if normalized not in _AIR_CONDITIONER_FAN_MODES:
            raise HomeAssistantError(
                f"Konke air conditioner does not support fan mode: {fan_mode}"
            )
        normalized_key = _FAN_KEY_BY_MODE[normalized]
        await self.async_control_device(
            ACTION_SET_WIND_SPEED,
            extension={"speed": AIR_CONDITIONER_FAN_KEY_TO_KONKE[normalized_key]},
        )


class KonkeFloorHeatingClimate(KonkeClimateBase):
    """Representation of a Konke floor-heating controller."""

    _attr_icon = "mdi:heating-coil"
    _attr_supported_features = (
        ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
        | ClimateEntityFeature.TARGET_TEMPERATURE
    )

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
    ) -> None:
        """Initialize the floor-heating entity."""
        super().__init__(
            coordinator,
            entry,
            device_id,
            unique_id_suffix="heating",
        )

    @property
    def min_temp(self) -> float:
        """Return the minimum supported target temperature."""
        return 5.0

    @property
    def max_temp(self) -> float:
        """Return the maximum supported target temperature."""
        return 40.0

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return supported HVAC modes."""
        return [HVACMode.OFF, HVACMode.HEAT, HVACMode.AUTO]

    @property
    def hvac_mode(self) -> HVACMode | None:
        """Return the current HVAC mode."""
        device = self.konke_device
        if device is None:
            return HVACMode.OFF
        if device.power_on is False:
            return HVACMode.OFF

        state = device_state(device)
        power = power_from_state(state)
        if power is False:
            return HVACMode.OFF

        mode = _floor_heating_hvac_mode(state)
        if mode is not None:
            return mode

        if device.power_on is True:
            return HVACMode.HEAT
        return HVACMode.OFF

    @property
    def hvac_action(self) -> HVACAction | None:
        """Return the current HVAC action."""
        mode = self.hvac_mode
        if mode == HVACMode.OFF:
            return HVACAction.OFF
        if mode == HVACMode.HEAT:
            return HVACAction.HEATING
        if mode == HVACMode.AUTO:
            return HVACAction.IDLE
        return None

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set target temperature."""
        await self._async_set_temperature_value(kwargs.get(ATTR_TEMPERATURE))

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set floor-heating mode."""
        if hvac_mode == HVACMode.OFF:
            await self.async_turn_off()
            return

        hvac_key = _HVAC_KEY_BY_MODE.get(hvac_mode)
        konke_mode = FLOOR_HEATING_HVAC_KEY_TO_MODE.get(hvac_key or "")
        if hvac_key is None or konke_mode is None:
            raise HomeAssistantError(
                f"Konke floor heating does not support HVAC mode: {hvac_mode}"
            )

        if self.hvac_mode == HVACMode.OFF:
            await self.async_control_device(ACTION_TURN_ON, refresh=False)
        await self.async_control_device(
            ACTION_SET_MODE,
            extension={"mode": konke_mode},
        )


def _air_conditioner_hvac_mode(state: dict[str, Any]) -> HVACMode | None:
    """Return a HA HVAC mode from a Konke air-conditioner state payload."""
    if power_from_state(state) is False:
        return HVACMode.OFF

    raw_mode = state.get("mode")
    if raw_mode is not None:
        key = AIR_CONDITIONER_MODE_TO_HVAC_KEY.get(str(raw_mode).upper())
        if key is not None:
            return _HVAC_BY_KEY.get(key)

    work_mode = int_from_state(state, "workMode")
    if work_mode is None:
        return None
    key = AIR_CONDITIONER_WORK_MODE_TO_HVAC_KEY.get(work_mode)
    if key is None:
        return None
    return _HVAC_BY_KEY.get(key)


def _floor_heating_hvac_mode(state: dict[str, Any]) -> HVACMode | None:
    """Return a HA HVAC mode from a Konke floor-heating state payload."""
    work_mode = int_from_state(state, "workMode")
    if work_mode is None:
        return None
    key = FLOOR_HEATING_WORK_MODE_TO_HVAC_KEY.get(work_mode)
    if key is None:
        return None
    return _HVAC_BY_KEY.get(key)


def _hvac_action_from_mode(mode: HVACMode | None) -> HVACAction | None:
    """Return a generic HA HVAC action from an HVAC mode."""
    if mode == HVACMode.OFF:
        return HVACAction.OFF
    if mode == HVACMode.HEAT:
        return HVACAction.HEATING
    if mode == HVACMode.COOL:
        return HVACAction.COOLING
    if mode == HVACMode.DRY:
        return HVACAction.DRYING
    if mode == HVACMode.FAN_ONLY:
        return HVACAction.FAN
    if mode == HVACMode.AUTO:
        return HVACAction.IDLE
    return None
