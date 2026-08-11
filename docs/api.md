# Konke API Notes

This document records protocol conclusions that are safe to use in code.
Do not paste raw captures, tokens, phone numbers, passwords, or home addresses here.

## Confirmed

- Base API: `https://kapp.ikonke.com/api/`
- Account API: `https://kapp.ikonke.com/account/`
- Android app key: `1592290148`
- Login: `POST /account/login`
  - response `data` contains `userToken` and `user`.
  - tokens/passwords must remain redacted in docs, diagnostics, and fixtures.
- Account profile: `GET /account/user`
- App version: `GET /api/app/version`
- YS token: `POST /api/ys/token`
- Home index: `GET /api/v2/page/index`
  - query: `synUserHostList`
  - response `data` contains `hostDevice`, `otherHosts`, `homeList`, and `home`.
- Room scenes: `GET /api/v2/scene`
  - normal entity sync uses `Normal,ExternalScene`.
  - forensic recording may additionally request `MultiControl`; it is retained
    only as a read-only topology snapshot and is never exposed as an HA scene.
- Scene detail: `GET /api/scene/{scene_id}`
- Scene execution: `POST /api/scene/action`
- Visible devices: `GET /api/user/device`
  - area device list query keys observed: `areaId`, `isVisible`, `orderByField`, `orderByType`, `page`, `pageSize`.
  - room device list query keys observed: `roomId`, `isVisible`, `orderByField`, `orderByType`, `page`, `pageSize`.
  - device detail query keys observed: `userDeviceId`.
  - response `data.pagePojo` is used for paged lists.
  - forensic polling follows every reported page instead of stopping after the first 100 devices.
  - response `data.userDeviceList` is used for a single `userDeviceId` detail query.
- Device cache: `GET /api/user/device/cache`
  - area cache query keys observed: `areaId`, optional `cateTypes`.
  - detail cache query keys observed: `userDeviceId`.
  - response `data.cacheList` contains cached state.
  - cache-only device IDs are retained in the forensic baseline but do not create HA entities.
- Device action endpoint: `POST /api/device/action/control`
- Air-conditioner actions for `virtual_AC_3in1` indoor units:
  - endpoint: `POST /api/device/action/control`
  - power on body shape: `{"userDeviceId": <int>, "name": "TurnOn"}`
  - power off body shape: `{"userDeviceId": <int>, "name": "TurnOff"}`
  - target temperature body shape:
    `{"userDeviceId": <int>, "name": "SetTemperature", "extension": {"value": <float>}}`
  - HVAC mode body shape:
    `{"userDeviceId": <int>, "name": "SetMode", "extension": {"mode": "<mode>"}}`
  - fan speed body shape:
    `{"userDeviceId": <int>, "name": "SetWindSpeed", "extension": {"speed": "<speed>"}}`
  - observed modes: `COLD`, `HOT`, `WIND`, `DEHUM`
  - observed fan speeds: `AUTO`, `LOW`, `MEDIUM`, `HIGH`
  - successful response shape: `{"code": 200, "info": "SUCCESS", "data": {}, "messageId": "..."}`
  - implemented by `command.py`, `api.py`, and the HA `climate` platform.
- Authentication behavior:
  - The Android app and HA integration can both obtain access tokens through
    `POST /account/login`.
  - It is not yet proven whether Konke invalidates older sessions on every new
    login, but the integration must assume this is possible.
  - Password-based HA config entries default to background password
    reauthentication so expired cloud tokens can recover without manual HA
    reauth. Disable `allow_password_reauth` in options during packet-capture
    sessions when preserving a phone app or emulator session is more important.
- Air-conditioner read-only detail/cache shape:
  - detail fields observed: `userDeviceId`, `deviceName`, `icon`, `state`, `nodeId`, `master`, `parentUserDeviceId`, `gwId`, `device`, `childDevice`, `homeId`, `areaId`, `roomId`, `homeName`, `roomName`, `areaName`, `cache`, `originProductId`, `UDID`.
  - cache fields observed: `productId`, `setTemp`, `curTemp`, `isOnline`, `userDeviceId`, `type`, `speed`, `roomId`, `mode`, `current`, `times`, `cateType`, `innerType`, `online`, `nodeId`, `on`, `onlineState`.
  - `current` contains `mode`, `setTemp`, `online`, `curTemp`, `updateTime`, `nodeId`, `speed`, `epType`, `on`, `onlineState`.
- WebSocket listener: `GET /ws/listener`
  - query contains `authorization`; keep it redacted.
  - the integration uses it only for forensic observation. Messages never
    update entities, trigger refreshes, execute scenes, or control devices.
  - `DeviceReport` and unknown JSON objects are recursively sanitized before
    bounded persistence. Non-JSON data is retained only as length and SHA-256.
- Curtain motor actions:
  - state cache endpoint: `GET /api/user/device/cache?areaId=<area_id>`
  - endpoint: `POST /api/device/action/control`
  - device type validated: `3215` / `curtain_motor` / `CurtainsMotor`
  - open body shape: `{"userDeviceId": <int>, "name": "TurnOn"}`
  - close body shape: `{"userDeviceId": <int>, "name": "TurnOff"}`
  - pause body shape: `{"userDeviceId": <int>, "name": "Pause"}`
  - cache fields observed: `operationMode`, `workMode`, `routeState`,
    `position`, `innerType`, `cateType`, `userExtension`, `isOnline`.
  - Some cloud payloads return sparse `cache.extension.current` objects, so
    `cache.extension` and `cache.extension.current` must be merged before entity
    state is derived. This keeps `position` available for HA `cover` state.
  - implemented by `command.py`, `api.py`, and the HA `cover` platform.
- Floor-heating actions for `virtual_FH_3in1_mix` nodes:
  - endpoint: `POST /api/device/action/control`
  - device type validated: `virtual_FH_3in1_mix` / `floor_heating` /
    `FloorHeating`
  - power on body shape: `{"userDeviceId": <int>, "name": "TurnOn"}`
  - power off body shape: `{"userDeviceId": <int>, "name": "TurnOff"}`
  - target temperature body shape:
    `{"userDeviceId": <int>, "name": "SetTemperature", "extension": {"value": <float>}}`
  - mode body shape:
    `{"userDeviceId": <int>, "name": "SetMode", "extension": {"mode": <int>}}`
  - observed mode values: `0` = `Auto`, `1` = `Manual`
  - observed temperature step: `0.5`
  - cache fields observed: `turnOnOff`, `currentTemperature`, `workMode`,
    `temperature`, `timingOffTime`, `nodeId`, `innerType`, `cateType`,
    `userExtension`, `isOnline`.
  - implemented by `command.py`, `api.py`, and the HA `climate` platform.
- Fresh-air actions for `virtual_AF_3in1_mix` nodes:
  - endpoint: `POST /api/device/action/control`
  - device type validated: `virtual_AF_3in1_mix` / `air_fresher_panel` /
    `AirFresher`
  - power on body shape: `{"userDeviceId": <int>, "name": "TurnOn"}`
  - power off body shape: `{"userDeviceId": <int>, "name": "TurnOff"}`
  - mode body shape:
    `{"userDeviceId": <int>, "name": "SetMode", "extension": {"mode": <int>}}`
  - observed mode values: `0` = `Auto`, `1` = `Manual`
  - direct wind-speed body shape observed but not effective:
    `{"userDeviceId": <int>, "name": "SetWindSpeed", "extension": {"speed": <int>}}`
  - direct `SetWindSpeed` returned `SUCCESS` during validation but did not
    change the cached `windSpeed`, so it must not be used for HA speed setting.
  - wind speed is controlled with relative actions:
    `{"userDeviceId": <int>, "name": "AdjustDownWindSpeed"}` and
    `{"userDeviceId": <int>, "name": "AdjustUpWindSpeed"}`.
  - observed wind-speed values: `1`, `2`, `3`.
  - cache fields observed: `turnOnOff`, `currentTemperature`, `workMode`,
    `timingOffTime`, `windSpeed`, `strainerWorkTime`, `strainerAlarmTime`,
    `nodeId`, `innerType`, `cateType`, `userExtension`, `isOnline`.
  - implemented by `command.py`, `api.py`, and the HA `fan` platform.

## Not Yet Confirmed

These items must not be exposed as Home Assistant supported features until captured,
documented, and tested:

- Air-conditioner actions for `virtual_AC_3in1_mix#2` wire-controller devices.
- Curtain position-set payloads.
- Light brightness, color temperature, and RGB payloads.
- Generic switch payloads beyond advertised `TurnOn`/`TurnOff`.
- A reliable refresh-token endpoint.

## Capture Sessions

### 2026-06-01 Frida + mitmproxy

- Raw capture: retained locally outside this repository.
- Sanitized summary: retained locally outside this repository.
- Captured safely:
  - login flow
  - home index
  - account profile
  - all-devices list
  - room device list
  - area and device cache
  - one air-conditioner detail page load
  - WebSocket listener handshake/messages
- Not captured:
  - air-conditioner `TurnOn`
  - target temperature changes
  - mode changes
  - fan speed changes
  - floor-heating/fresh-air/cover control actions

Reason: those actions change real device state and need an explicit test window.

### 2026-06-01 Frida + mitmproxy Air-Conditioner Control

- Raw capture: retained locally outside this repository.
- Sanitized summary: retained locally outside this repository.
- Device type validated: `virtual_AC_3in1` / `fan_coil`.
- Test device was online and originally `off`, `WIND`, `24`, `HIGH`.
- Captured and validated:
  - `TurnOn`
  - `SetMode` to `COLD`
  - `SetTemperature` to `25.0`
  - `SetTemperature` back to `24.0`
  - `SetWindSpeed` to `LOW`
  - `SetWindSpeed` back to `HIGH`
  - `SetMode` back to `WIND`
  - `TurnOff`
- Post-test state was verified back at `off`, `WIND`, `24`, `HIGH`.

### 2026-06-01 Frida + mitmproxy Curtain Control

- Raw capture: retained locally outside this repository.
- Sanitized summary: retained locally outside this repository.
- Device type validated: `3215` / `curtain_motor` / `CurtainsMotor`.
- Initial cache position was `99`.
- Captured and validated:
  - `TurnOn` from the card `openBtn`
  - `TurnOff` from the card `closeBtn`
  - `Pause` from the card `pauseBtn`
  - `TurnOn` again to restore the curtain near the initial open position.

### 2026-06-01 Frida + mitmproxy Floor-Heating Control

- Raw captures: retained locally outside this repository.
- Sanitized summary: retained locally outside this repository.
- Device type validated: `virtual_FH_3in1_mix` / `floor_heating` /
  `FloorHeating`.
- Captured and validated:
  - `TurnOn`
  - `TurnOff`
  - `SetTemperature` to `26.5`
  - `SetTemperature` back to `26.0`
  - `SetMode` to `0` (`Auto`)
  - `SetMode` back to `1` (`Manual`)
- Post-test state for the main test device was verified back at `off`,
  `Manual`, `26.0`.

### 2026-06-01 Frida + mitmproxy Fresh-Air Attempt

- Raw capture: retained locally outside this repository.
- Sanitized summary: retained locally outside this repository.
- Device type observed: `virtual_AF_3in1_mix` / `air_fresher_panel` /
  `AirFresher`.
- Dynamic UI navigation confirmed the detail title was `新风`.
- Captured:
  - `TurnOn`
- Not confirmed:
  - `TurnOff`
  - `SetWindSpeed`
  - `SetMode`
- Reason: the test device remained reported as `turnOnOff=true` after the
  attempted toggle, so the off path was not validated.

### 2026-06-02 HA-side Fresh-Air Control Validation

- Validation script: retained locally outside this repository.
- Device type validated: `virtual_AF_3in1_mix` / `air_fresher_panel` /
  `AirFresher`.
- Test device was online and originally `on`, `windSpeed=3`, `workMode=1`.
- HA-side validated:
  - `TurnOff`
  - `TurnOn` restore
  - `SetMode` to `0`
  - `SetMode` back to `1`
  - `AdjustDownWindSpeed` from `3` to `2`
  - `AdjustDownWindSpeed` from `2` to `1`
  - `AdjustUpWindSpeed` from `1` to `2`
  - `AdjustUpWindSpeed` from `2` back to `3`
- Also tested but not accepted:
  - `SetWindSpeed` with `{"speed": 2}` returned `SUCCESS` but the cached
    `windSpeed` remained `3`.
- Post-test state was verified back at `on`, `windSpeed=3`, `Manual`.

## Capture Checklist

For every new command, record a sanitized conclusion with:

- endpoint
- request body shape
- response shape
- device type and capability
- whether the command changes real device state
- where it was validated

Original captures belong in the workspace `captures/` directory, not in the
integration source tree. Sanitized fixtures can be added under `tests/fixtures/`.
