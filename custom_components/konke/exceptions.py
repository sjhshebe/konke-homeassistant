"""Exceptions for the Konke Smart integration."""

from __future__ import annotations

from typing import Any


class KonkeApiError(Exception):
    """Base Konke API error with safe transport metadata."""

    def __init__(
        self,
        message: str,
        *,
        http_status: int | None = None,
        business_code: int | str | None = None,
        business_info: Any = None,
        message_id: str | None = None,
        response_date: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        """Initialize an API error."""
        super().__init__(message)
        self.http_status = http_status
        self.business_code = business_code
        self.business_info = business_info
        self.message_id = message_id
        self.response_date = response_date
        self.started_at = started_at
        self.completed_at = completed_at


class KonkeAuthError(KonkeApiError):
    """Authentication failed or expired."""


class KonkeCannotConnect(KonkeApiError):
    """Unable to connect to Konke cloud."""


class KonkeUnsupportedDeviceError(KonkeApiError):
    """Device or capability is not supported by this integration."""


class KonkeCommandError(KonkeApiError):
    """A device command could not be built or executed."""
