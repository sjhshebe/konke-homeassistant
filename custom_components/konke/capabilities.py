"""Konke device capability inference rules."""

from __future__ import annotations

from enum import StrEnum


class KonkeCapability(StrEnum):
    """Normalized capabilities exposed by Konke devices."""

    AIR_CONDITIONER = "air_conditioner"
    AIR_FRESHER = "air_fresher"
    COVER = "cover"
    FLOOR_HEATING = "floor_heating"
    HVAC_MANAGER = "hvac_manager"
    LIGHT = "light"
    SENSOR = "sensor"
    SWITCH = "switch"
    UNKNOWN = "unknown"


POWER_ACTIONS = frozenset({"TurnOn", "TurnOff"})
POWER_ACTION_CAPABILITY_PRIORITY: tuple[KonkeCapability, ...] = (
    KonkeCapability.AIR_CONDITIONER,
    KonkeCapability.FLOOR_HEATING,
    KonkeCapability.AIR_FRESHER,
    KonkeCapability.COVER,
    KonkeCapability.LIGHT,
    KonkeCapability.SWITCH,
)


def capabilities_from_device_profile(
    *,
    cate_type: str | None,
    inner_type: str | None,
    product_id: str | None,
    icon: str | None,
    device_name: str | None,
    action_names: set[str],
) -> set[KonkeCapability]:
    """Infer normalized capabilities from stable device profile fields."""
    from .device_profiles import capabilities_from_profile

    capabilities = {
        KonkeCapability(capability)
        for capability in capabilities_from_profile(
            cate_type=cate_type,
            inner_type=inner_type,
            product_id=product_id,
            icon=icon,
            device_name=device_name,
        )
    }

    if POWER_ACTIONS.issubset(action_names) and not capabilities:
        capabilities.add(KonkeCapability.SWITCH)

    if not capabilities:
        capabilities.add(KonkeCapability.UNKNOWN)
    return capabilities


def capability_for_action(
    action_name: str,
    capabilities: set[KonkeCapability],
) -> KonkeCapability | None:
    """Return the best capability owner for a command name."""
    if len(capabilities) == 1:
        return next(iter(capabilities))
    if action_name in POWER_ACTIONS:
        for capability in POWER_ACTION_CAPABILITY_PRIORITY:
            if capability in capabilities:
                return capability
    return None


def platform_for_capability(capability: KonkeCapability) -> str | None:
    """Return the intended Home Assistant platform for a capability."""
    from .device_profiles import PLATFORM_BY_CAPABILITY

    return PLATFORM_BY_CAPABILITY.get(capability.value)


def capability_matches_device_type(
    capability: KonkeCapability,
    *,
    cate_type: str | None,
    inner_type: str | None,
    product_id: str | None,
    icon: str | None,
    device_name: str | None,
) -> bool:
    """Return true when a raw device profile matches a capability."""
    return capability in capabilities_from_device_profile(
        cate_type=cate_type,
        inner_type=inner_type,
        product_id=product_id,
        icon=icon,
        device_name=device_name,
        action_names=set(),
    )
