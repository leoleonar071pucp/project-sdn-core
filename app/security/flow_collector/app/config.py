import os
from pathlib import Path


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.lower() in {"1", "true", "yes", "on"}


class Settings:
    dry_run = env_bool("DRY_RUN", True)
    m4_url = os.getenv("M4_URL", "http://m4:8084")
    security_token = os.getenv("SECURITY_TOKEN", "change-me")
    output_path = Path(os.getenv("DRY_RUN_OUTPUT", "./state/telemetry-events.jsonl"))
    max_datagram_size = int(os.getenv("MAX_DATAGRAM_SIZE", "65535"))
    sflow_port = int(os.getenv("SFLOW_PORT", "6343"))
    netflow_port = int(os.getenv("NETFLOW_PORT", "2055"))
