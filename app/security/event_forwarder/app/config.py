from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    eve_path: Path = Path("/var/log/suricata/eve.json")
    state_path: Path = Path("./state/offset.json")
    queue_path: Path = Path("./state/pending.jsonl")
    dry_run_output: Path = Path("./state/dry-run-events.jsonl")
    critical_assets_path: Path = Path("/etc/suricata/critical-assets.yaml")
    m4_url: str = "http://m4:8084"
    security_token: str = "change-me"
    dry_run: bool = True
    allowed_event_types: str = "alert,anomaly,http,tls,flow"
    max_queue_size: int = 10000
    http_timeout_seconds: float = 3.0

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_types(self) -> set[str]:
        return {item.strip() for item in self.allowed_event_types.split(",") if item}
