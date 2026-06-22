from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    security_token: str = "change-me"
    ovsdb_actions_enabled: bool = False
    inventory_path: Path = Path("./inventory/critical-assets.yaml")
    mysql_persistence_enabled: bool = False
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "radius"
    mysql_password: str = "radius_pass"
    mysql_database: str = "radius_db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
