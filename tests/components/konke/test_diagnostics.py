"""Tests for Konke diagnostics."""

from __future__ import annotations

import json

import pytest
from custom_components.konke.diagnostics import async_get_config_entry_diagnostics


@pytest.mark.asyncio
async def test_diagnostics_redacts_credentials(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """Diagnostics redact sensitive entry data."""
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    diagnostics = await async_get_config_entry_diagnostics(hass, config_entry)
    encoded = json.dumps(diagnostics, ensure_ascii=False)

    assert "fake-access-token" not in encoded
    assert "fake-refresh-token" not in encoded
    assert diagnostics["entry"]["data"]["access_token"] == "**REDACTED**"
    assert diagnostics["entry"]["data"]["refresh_token"] == "**REDACTED**"
    assert diagnostics["forensics"]["events"]
    assert "analysis" in diagnostics["forensics"]
    assert diagnostics["forensics"]["settings"]["max_events"] == 20_000
    assert diagnostics["forensics"]["settings"]["max_bytes"] == 10 * 1024 * 1024


@pytest.mark.asyncio
async def test_diagnostics_sanitize_nested_payload_and_phone_values(
    hass,
    config_entry,
    konke_client_patch,
) -> None:
    """No nested credential or phone value can escape through diagnostics."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    coordinator = hass.data["konke"][config_entry.entry_id]
    await coordinator.forensics.async_record(
        "sample",
        "test",
        {
            "nested": {
                "Authorization": "Bearer diagnostics-secret",
                "owner": "13900139000",
                "accessToken": "nested-token",
            }
        },
        immediate=True,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, config_entry)
    encoded = json.dumps(diagnostics, ensure_ascii=False)

    assert "diagnostics-secret" not in encoded
    assert "13900139000" not in encoded
    assert "nested-token" not in encoded
