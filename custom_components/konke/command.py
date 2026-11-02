"""Command helpers for Konke Smart devices."""

from __future__ import annotations

from typing import Any

from .exceptions import KonkeCommandError

ACTION_PAUSE = "Pause"
ACTION_SET_MODE = "SetMode"
ACTION_SET_TEMPERATURE = "SetTemperature"
ACTION_SET_WIND_SPEED = "SetWindSpeed"
ACTION_TURN_OFF = "TurnOff"
ACTION_TURN_ON = "TurnOn"


def build_device_action_body(
    *,
    user_device_id: str | int,
    action_name: str,
    extension: dict[str, Any] | str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a request body for the Konke device action endpoint."""
    try:
        normalized_user_device_id = int(user_device_id)
    except (TypeError, ValueError) as err:
        raise KonkeCommandError("Device action requires a numeric userDeviceId") from err

    body: dict[str, Any] = {
        "userDeviceId": normalized_user_device_id,
        "name": action_name,
    }
    if extension is not None:
        body["extension"] = extension
    if extra:
        body.update(extra)
    return body
