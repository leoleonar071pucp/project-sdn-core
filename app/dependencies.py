from app.common.database import get_db_session
from app.config import settings
from app.modules.m6_translator.onos_client import ONOSClient


def get_onos_client() -> ONOSClient:
    return ONOSClient(
        base_url=settings.onos_base_url,
        username=settings.onos_username,
        password=settings.onos_password,
    )


__all__ = ["get_db_session", "get_onos_client"]
