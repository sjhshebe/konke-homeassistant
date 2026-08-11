"""Tests for administrator-only Konke forensic history clearing."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.konke.const import (
    DOMAIN,
    SERVICE_CLEAR_FORENSIC_HISTORY,
)
from homeassistant.core import Context
from homeassistant.exceptions import HomeAssistantError


@pytest.mark.asyncio
async def test_admin_clear_returns_counts_and_keeps_coverage_marker(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """An administrator can clear evidence without hiding the resulting gap."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    recorder = hass.data[DOMAIN][config_entry.entry_id].forensics
    await recorder.async_record(
        "websocket_report",
        "websocket",
        {"user_device_ids": ["1001"]},
        immediate=True,
    )
    before = await recorder.async_export()
    admin_context = Context(user_id="admin-user")

    with patch.object(
        hass.auth,
        "async_get_user",
        AsyncMock(return_value=SimpleNamespace(is_admin=True)),
    ):
        response = await hass.services.async_call(
            DOMAIN,
            SERVICE_CLEAR_FORENSIC_HISTORY,
            {},
            blocking=True,
            context=admin_context,
            return_response=True,
        )

    deleted = response["deleted"]
    assert response["entry_id"] == config_entry.entry_id
    assert deleted["events"] == before["stats"]["retained_events"]
    assert deleted["device_baselines"] == len(konke_client_patch.devices)
    assert deleted["scenes"] == len(before["latest_scene_snapshot"])

    after = await recorder.async_export()
    assert after["latest_scene_snapshot"] == {}
    assert after["stats"]["retained_events"] == 1
    assert after["events"][0]["kind"] == "history_cleared"
    assert after["events"][0]["data"] == deleted
    assert after["events"][0]["context"] == {
        "id": admin_context.id,
        "parent_id": None,
        "user_id": "admin-user",
    }
    assert after["status"]["last_cleared_at"] is not None
    assert after["status"]["last_event"] == after["status"]["last_cleared_at"]
    assert "poll_baseline_cleared" in after["status"]["current_coverage_gaps"]
    assert "scene_snapshot_cleared" in after["status"]["current_coverage_gaps"]
    assert after["analysis"]["coverage_gap_present"] is True
    assert "history_cleared" in after["analysis"]["coverage_gap_reasons"]


@pytest.mark.asyncio
@pytest.mark.parametrize("user", [None, SimpleNamespace(is_admin=False)])
async def test_clear_rejects_missing_or_non_admin_user_without_data_loss(
    hass,
    config_entry,
    konke_client_patch,
    user,
) -> None:
    """Anonymous and non-admin calls cannot clear retained evidence."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    recorder = hass.data[DOMAIN][config_entry.entry_id].forensics
    await recorder.async_record("sample", "test", {"value": 1}, immediate=True)
    before = await recorder.async_export()
    context = Context(user_id="regular-user" if user is not None else None)

    with (
        patch.object(
            hass.auth,
            "async_get_user",
            AsyncMock(return_value=user),
        ) as get_user,
        pytest.raises(
            HomeAssistantError,
            match="Only a Home Assistant administrator can clear forensics",
        ),
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_CLEAR_FORENSIC_HISTORY,
            {},
            blocking=True,
            context=context,
            return_response=True,
        )

    if user is None:
        get_user.assert_not_awaited()
    else:
        get_user.assert_awaited_once_with("regular-user")
    after = await recorder.async_export()
    assert after["events"] == before["events"]
    assert after["latest_scene_snapshot"] == before["latest_scene_snapshot"]
