from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "m4-security"
    app_env: str = "development"
    security_token: str = "change-me"

    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "radius"
    mysql_password: str = "radius_pass"
    mysql_database: str = "radius_db"
    mysql_persistence_enabled: bool = False

    m6_base_url: str = "http://127.0.0.1:8080"
    m2_base_url: str = "http://127.0.0.1:8182"
    telemetry_manager_url: str = "http://127.0.0.1:8090"

    network_actions_enabled: bool = False
    onos_writes_enabled: bool = False
    ovsdb_actions_enabled: bool = False
    m4_automatic_actions_enabled: bool = False
    suricata_ingestion_enabled: bool = False
    flow_telemetry_ingestion_enabled: bool = False

    event_window_seconds: int = 60
    temporary_block_seconds: int = 600
    long_block_seconds: int = 3600
    http_timeout_seconds: float = 3.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
