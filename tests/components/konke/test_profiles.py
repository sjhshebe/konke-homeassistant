"""Tests for verified Konke device profiles."""

from __future__ import annotations

from custom_components.konke.capabilities import KonkeCapability
from custom_components.konke.device_profiles import capabilities_from_profile

from .conftest import load_devices


def test_profiles_recognize_verified_fixture_devices() -> None:
    """Verified profiles identify fixture device capabilities."""
    expected = [
        KonkeCapability.AIR_CONDITIONER,
        KonkeCapability.SWITCH,
        KonkeCapability.FLOOR_HEATING,
        KonkeCapability.COVER,
        KonkeCapability.AIR_FRESHER,
    ]

    for raw, capability in zip(load_devices(), expected, strict=True):
        device_type = raw.get("device", {}).get("deviceType", {})
        capabilities = capabilities_from_profile(
            cate_type=raw.get("device", {}).get("cateType") or device_type.get("cateType"),
            inner_type=device_type.get("innerType"),
            product_id=device_type.get("productId"),
            icon=raw.get("icon"),
            device_name=raw.get("deviceName"),
        )
        if capability is KonkeCapability.SWITCH:
            assert capabilities == set()
        else:
            assert capability.value in capabilities
