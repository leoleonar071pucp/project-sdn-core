from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "sdn-core"
    app_env: str = "development"
    database_url: str = "postgresql://postgres:postgres@db:5432/sdn_core"
    onos_base_url: str = "http://onos:8181/onos/v1"
    onos_username: str = "onos"
    onos_password: str = "rocks"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
