"""Internal models for Konke Smart data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .capabilities import (
    KonkeCapability,
    capabilities_from_device_profile,
    capability_for_action,
    platform_for_capability,
)


def nested(data: Mapping[str, Any], *keys: str) -> Any:
    """Return a nested value from a mapping."""
    value: Any = data
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def maybe_str(value: Any) -> str | None:
    """Return a non-empty string value."""
    if value is None:
        return None
    normalized = str(value)
    return normalized or None


def maybe_bool(value: Any) -> bool | None:
    """Return a normalized boolean value."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"true", "1", "on", "online"}:
            return True
        if lowered in {"false", "0", "off", "offline"}:
            return False
    return None


def current_state_for_raw(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Return a merged scalar state snapshot from known cache payloads."""
    state: dict[str, Any] = {}
    extension = nested(raw, "cache", "extension")
    current: Any = None

    if isinstance(extension, Mapping):
        current = extension.get("current")
        for key, value in extension.items():
            if key == "current" or isinstance(value, (Mapping, list)):
                continue
            state[str(key)] = value

    if isinstance(current, Mapping):
        for key, value in current.items():
            if isinstance(value, (Mapping, list)):
                continue
            state[str(key)] = value

    return state


def as_str_list(value: Any) -> list[str]:
    """Return a list of strings from an arbitrary list-like value."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


@dataclass(frozen=True)
class KonkeHome:
    """Normalized Konke home data."""

    home_id: str
    name: str | None
    raw: Mapping[str, Any]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> KonkeHome:
        """Build a normalized home from raw API data."""
        home_id = maybe_str(raw.get("homeId"))
        if home_id is None:
            raise ValueError("Konke home is missing homeId")
        return cls(
            home_id=home_id,
            name=maybe_str(raw.get("homeName")),
            raw=raw,
        )


@dataclass(frozen=True)
class KonkeProperty:
    """Normalized property snapshot exposed by a Konke device."""

    key: str
    value: Any
    source: str | None = None
    unit: str | None = None


@dataclass(frozen=True)
class KonkeCommand:
    """Normalized command advertised by a Konke device."""

    action_name: str
    capability: KonkeCapability | None = None
    raw: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class KonkeRoom:
    """Normalized Konke room data."""

    room_id: str
    name: str | None
    area_id: str | None
    area_name: str | None
    raw: Mapping[str, Any]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> KonkeRoom:
        """Build a normalized room from raw API data."""
        room_id = maybe_str(raw.get("roomId"))
        if room_id is None:
            raise ValueError("Konke room is missing roomId")
        return cls(
            room_id=room_id,
            name=maybe_str(raw.get("roomName")),
            area_id=maybe_str(raw.get("areaId")),
            area_name=maybe_str(raw.get("areaName")),
            raw=raw,
        )


@dataclass(frozen=True)
class KonkeDevice:
    """Normalized Konke device data."""

    user_device_id: str
    name: str | None
    room_id: str | None
    room_name: str | None
    area_id: str | None
    area_name: str | None
    node_id: str | None
    parent_user_device_id: str | None
    cate_type: str | None
    inner_type: str | None
    product_id: str | None
    type_name: str | None
    model: str | None
    icon: str | None
    online: bool | None
    power_on: bool | None
    action_names: tuple[str, ...]
    properties: tuple[KonkeProperty, ...]
    commands: tuple[KonkeCommand, ...]
    capabilities: tuple[KonkeCapability, ...]
    raw: Mapping[str, Any]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> KonkeDevice:
        """Build a normalized device from raw API data."""
        user_device_id = maybe_str(raw.get("userDeviceId"))
        if user_device_id is None:
            raise ValueError("Konke device is missing userDeviceId")
        return cls(
            user_device_id=user_device_id,
            name=maybe_str(raw.get("deviceName")),
            room_id=maybe_str(raw.get("roomId")),
            room_name=maybe_str(raw.get("roomName")),
            area_id=maybe_str(raw.get("areaId")),
            area_name=maybe_str(raw.get("areaName")),
            node_id=maybe_str(raw.get("nodeId")),
            parent_user_device_id=maybe_str(raw.get("parentUserDeviceId")),
            cate_type=maybe_str(
                nested(raw, "device", "cateType")
                or nested(raw, "device", "deviceType", "cateType")
            ),
            inner_type=maybe_str(nested(raw, "device", "deviceType", "innerType")),
            product_id=maybe_str(nested(raw, "device", "deviceType", "productId")),
            type_name=maybe_str(nested(raw, "device", "deviceType", "typeName")),
            model=maybe_str(
                nested(raw, "device", "deviceType", "productId")
                or nested(raw, "device", "deviceType", "typeName")
            ),
            icon=maybe_str(raw.get("icon")),
            online=_device_online(raw),
            power_on=_device_power_on(raw),
            action_names=tuple(as_str_list(nested(raw, "device", "deviceType", "actionList"))),
            properties=tuple(properties_for_raw_device(raw)),
            commands=tuple(commands_for_raw_device(raw)),
            capabilities=tuple(
                sorted(capabilities_for_raw_device(raw), key=lambda item: item.value)
            ),
            raw=raw,
        )

    @property
    def stable_key(self) -> str:
        """Return the stable device key used by this integration."""
        return self.user_device_id

    @property
    def parent_key(self) -> str | None:
        """Return the parent device key, if this is a child node."""
        return self.parent_user_device_id

    @property
    def suggested_area(self) -> str | None:
        """Return the suggested Home Assistant area name."""
        return self.room_name or self.area_name


def _device_online(raw: Mapping[str, Any]) -> bool | None:
    """Return cached online state, if present."""
    for path in (
        ("cache", "isOnline"),
        ("cache", "extension", "online"),
        ("cache", "extension", "current", "online"),
        ("cache", "extension", "onlineState"),
        ("cache", "extension", "current", "onlineState"),
    ):
        value = maybe_bool(nested(raw, *path))
        if value is not None:
            return value
    return None


def _device_power_on(raw: Mapping[str, Any]) -> bool | None:
    """Return cached power state, if present."""
    for path in (
        ("cache", "extension", "current", "on"),
        ("cache", "extension", "on"),
        ("cache", "extension", "current", "turnOnOff"),
        ("cache", "extension", "turnOnOff"),
    ):
        value = maybe_bool(nested(raw, *path))
        if value is not None:
            return value
    return None


def capabilities_for_raw_device(raw: Mapping[str, Any]) -> set[KonkeCapability]:
    """Infer normalized capabilities from raw Konke device data."""
    cate_type = maybe_str(
        nested(raw, "device", "cateType")
        or nested(raw, "device", "deviceType", "cateType")
    )
    inner_type = maybe_str(nested(raw, "device", "deviceType", "innerType"))
    product_id = maybe_str(nested(raw, "device", "deviceType", "productId"))
    icon = maybe_str(raw.get("icon"))
    action_names = set(as_str_list(nested(raw, "device", "deviceType", "actionList")))
    return capabilities_from_device_profile(
        cate_type=cate_type,
        inner_type=inner_type,
        product_id=product_id,
        icon=icon,
        device_name=maybe_str(raw.get("deviceName")),
        action_names=action_names,
    )


def properties_for_raw_device(raw: Mapping[str, Any]) -> list[KonkeProperty]:
    """Extract a stable property snapshot from known cache payloads."""
    properties_by_key: dict[str, KonkeProperty] = {}
    extension = nested(raw, "cache", "extension")
    current: Any = None

    if isinstance(extension, Mapping):
        current = extension.get("current")
        for key, item in extension.items():
            if key == "current" or isinstance(item, (Mapping, list)):
                continue
            normalized_key = str(key)
            properties_by_key[normalized_key] = KonkeProperty(
                key=normalized_key,
                value=item,
                source="cache.extension",
            )

    if isinstance(current, Mapping):
        for key, item in current.items():
            if isinstance(item, (Mapping, list)):
                continue
            normalized_key = str(key)
            properties_by_key[normalized_key] = KonkeProperty(
                key=normalized_key,
                value=item,
                source="cache.extension.current",
            )

    return list(properties_by_key.values())


def commands_for_raw_device(raw: Mapping[str, Any]) -> list[KonkeCommand]:
    """Extract advertised commands from the Konke device type payload."""
    capabilities = capabilities_for_raw_device(raw)
    return [
        KonkeCommand(
            action_name=action_name,
            capability=capability_for_action(action_name, capabilities),
        )
        for action_name in as_str_list(nested(raw, "device", "deviceType", "actionList"))
    ]


def build_entity_descriptors(devices: list[KonkeDevice]) -> list[dict[str, Any]]:
    """Build stable entity descriptors from normalized devices."""
    descriptors: list[dict[str, Any]] = []
    for device in devices:
        for capability in sorted(device.capabilities, key=lambda item: item.value):
            if capability is KonkeCapability.UNKNOWN:
                continue
            platform = platform_for_capability(capability)
            if platform is None:
                continue
            descriptors.append(
                {
                    "unique_id": f"{device.user_device_id}_{capability.value}",
                    "device_id": device.user_device_id,
                    "capability": capability.value,
                    "platform": platform,
                    "name": device.name,
                    "room_id": device.room_id,
                    "room_name": device.room_name,
                }
            )
    return descriptors


def build_device_indexes(devices: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Build normalized device indexes while preserving raw API payloads."""
    normalized: list[KonkeDevice] = []
    skipped: list[dict[str, Any]] = []

    for raw in devices:
        try:
            normalized.append(KonkeDevice.from_raw(raw))
        except ValueError as err:
            skipped.append(
                {
                    "reason": str(err),
                    "deviceName": raw.get("deviceName"),
                    "userDeviceId": raw.get("userDeviceId"),
                }
            )

    by_id = {device.user_device_id: device for device in normalized}
    by_room: dict[str, list[str]] = {}
    children_by_parent: dict[str, list[str]] = {}
    by_capability: dict[str, list[str]] = {}

    for device in normalized:
        if device.room_id:
            by_room.setdefault(device.room_id, []).append(device.user_device_id)
        if device.parent_user_device_id:
            children_by_parent.setdefault(device.parent_user_device_id, []).append(
                device.user_device_id
            )
        for capability in device.capabilities:
            by_capability.setdefault(capability.value, []).append(device.user_device_id)

    return {
        "devices": normalized,
        "devices_by_id": by_id,
        "entities": build_entity_descriptors(normalized),
        "device_ids_by_room_id": by_room,
        "child_device_ids_by_parent_id": children_by_parent,
        "device_ids_by_capability": by_capability,
        "skipped_devices": skipped,
    }


def summarize_device(device: KonkeDevice) -> dict[str, Any]:
    """Return a JSON-serializable summary of a normalized device."""
    return {
        "user_device_id": device.user_device_id,
        "name": device.name,
        "room_id": device.room_id,
        "room_name": device.room_name,
        "area_id": device.area_id,
        "area_name": device.area_name,
        "node_id": device.node_id,
        "parent_user_device_id": device.parent_user_device_id,
        "cate_type": device.cate_type,
        "inner_type": device.inner_type,
        "product_id": device.product_id,
        "type_name": device.type_name,
        "model": device.model,
        "icon": device.icon,
        "online": device.online,
        "power_on": device.power_on,
        "action_names": list(device.action_names),
        "properties": [
            {
                "key": prop.key,
                "value": prop.value,
                "source": prop.source,
                "unit": prop.unit,
            }
            for prop in device.properties
        ],
        "commands": [
            {
                "action_name": command.action_name,
                "capability": command.capability.value if command.capability else None,
            }
            for command in device.commands
        ],
        "capabilities": [capability.value for capability in device.capabilities],
        "suggested_area": device.suggested_area,
    }
