"""Incident persistence is implemented by the shared SecurityRepository.

This module is kept as the extension point for a future split repository.
"""

from .event_repository import SecurityRepository

__all__ = ["SecurityRepository"]
