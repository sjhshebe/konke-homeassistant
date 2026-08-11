"""Scene platform for Konke Smart."""

from __future__ import annotations

from typing import Any

from homeassistant.components.scene import Scene
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_HOME_ID, DOMAIN
from .coordinator import KonkeDataUpdateCoordinator
from .entity import KonkeEntity
from .options import options_from_entry

_INTERNAL_SCENE_TYPES = {"multicontrol"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Konke scenes from a config entry."""
    if options_from_entry(entry).create_scene_entities is False:
        return
    coordinator: KonkeDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    scenes = coordinator.data.get("scenes_by_id", {})
    _remove_internal_scene_entities(
        hass,
        entry,
        coordinator,
        coordinator.data.get("forensic_scenes_by_id", scenes),
    )
    async_add_entities(
        KonkeScene(coordinator, entry, scene_id)
        for scene_id in _scene_ids_for_entities(scenes)
    )


class KonkeScene(KonkeEntity, Scene):
    """Representation of a Konke scene."""

    def __init__(
        self,
        coordinator: KonkeDataUpdateCoordinator,
        entry: ConfigEntry,
        scene_id: str,
    ) -> None:
        """Initialize the scene."""
        super().__init__(coordinator, entry)
        self._scene_id = str(scene_id)
        self._attr_unique_id = _scene_unique_id(
            _scene_home_id(entry, coordinator),
            self._scene_id,
        )

    @property
    def _scene(self) -> dict[str, Any]:
        """Return latest scene data."""
        return self.coordinator.data.get("scenes_by_id", {}).get(self._scene_id, {})

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return super().available and bool(self._scene)

    @property
    def name(self) -> str:
        """Return the scene name."""
        return self._scene.get("sceneName") or f"Scene {self._scene_id}"

    @property
    def icon(self) -> str | None:
        """Return icon for known scene types."""
        name = self.name
        if "离家" in name:
            return "mdi:home-export-outline"
        if "回家" in name:
            return "mdi:home-import-outline"
        if "空调" in name:
            return "mdi:air-conditioner"
        if "新风" in name:
            return "mdi:fan"
        return "mdi:palette-outline"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return scene attributes."""
        scene = self._scene
        return {
            "scene_id": int(self._scene_id)
            if self._scene_id.isdigit()
            else self._scene_id,
            "scene_type": scene.get("sceneType"),
            "manual": scene.get("manual"),
            "home_id": scene.get("homeId"),
            "area_id": scene.get("areaId"),
            "area_name": scene.get("areaName"),
            "room_id": scene.get("roomId"),
            "room_name": scene.get("roomName"),
            "actions": scene.get("actionSimpleV2List") or scene.get("actionList"),
            "result_id": scene.get("resultId"),
        }

    async def async_activate(self, **kwargs: Any) -> None:
        """Activate the Konke scene."""
        home_id = self._entry.data.get(CONF_HOME_ID)
        await self.coordinator.async_execute_scene(
            home_id=home_id,
            scene_id=self._scene_id,
            context=self._context,
            source_entity_id=self.entity_id,
        )
        await self.coordinator.async_request_refresh()


def _scene_ids_for_entities(scenes: dict[str, dict[str, Any]]) -> list[str]:
    """Return scene ids that should be exposed as Home Assistant entities."""
    return sorted(
        (
            str(scene_id)
            for scene_id, scene in scenes.items()
            if _should_create_scene_entity(scene)
        ),
        key=_sort_scene_id,
    )


def _should_create_scene_entity(scene: dict[str, Any]) -> bool:
    """Return if a Konke scene should be exposed as a HA scene entity."""
    scene_type = str(scene.get("sceneType") or "").lower()
    return scene_type not in _INTERNAL_SCENE_TYPES


def _remove_internal_scene_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: KonkeDataUpdateCoordinator,
    scenes: dict[str, dict[str, Any]],
) -> None:
    """Remove previously registered internal Konke scene entities."""
    registry = er.async_get(hass)
    home_ids = {
        _scene_home_id(entry, coordinator),
        str(entry.data.get(CONF_HOME_ID) or ""),
        "None",
    }
    home_ids.discard("")
    for scene_id, scene in scenes.items():
        if _should_create_scene_entity(scene):
            continue
        for home_id in home_ids:
            entity_id = registry.async_get_entity_id(
                "scene",
                DOMAIN,
                _scene_unique_id(home_id, str(scene_id)),
            )
            if entity_id:
                registry.async_remove(entity_id)


def _scene_home_id(
    entry: ConfigEntry,
    coordinator: KonkeDataUpdateCoordinator,
) -> str:
    """Return the home id used for scene unique ids."""
    home = coordinator.data.get("home", {})
    home_id = entry.data.get(CONF_HOME_ID) or home.get("homeId")
    return "" if home_id is None else str(home_id)


def _scene_unique_id(home_id: str, scene_id: str) -> str:
    """Return a stable scene unique id."""
    return f"{DOMAIN}_{home_id}_scene_{scene_id}"


def _sort_scene_id(scene_id: str) -> tuple[int, str]:
    """Sort numeric scene ids naturally."""
    try:
        return (0, f"{int(scene_id):020d}")
    except (TypeError, ValueError):
        return (1, str(scene_id))
