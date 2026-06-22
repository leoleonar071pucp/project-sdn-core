from pathlib import Path

import yaml


REQUIRED_MARKER = "REQUIRED"


class Inventory:
    def __init__(self, path: Path):
        self.path = path
        self.assets = {}
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            self.assets = {
                item["id"]: item for item in data.get("assets", []) if item.get("id")
            }

    def resolve(self, asset_id: str | None, explicit: dict) -> dict:
        asset = self.assets.get(asset_id or "", {})
        values = {
            "bridge": explicit.get("bridge") or asset.get("bridge"),
            "source_port": explicit.get("source_port") or asset.get("source_port"),
            "output_tunnel_port": explicit.get("output_tunnel_port")
            or asset.get("output_tunnel_port"),
        }
        missing = [
            key
            for key, value in values.items()
            if not value or str(value).upper() == REQUIRED_MARKER
        ]
        if missing:
            raise ValueError(
                "unresolved mirror inventory fields: " + ", ".join(missing)
            )
        return {key: str(value) for key, value in values.items()}

    def unresolved_assets(self) -> dict[str, list[str]]:
        result = {}
        for asset_id, asset in self.assets.items():
            missing = [
                key
                for key in ("bridge", "source_port", "output_tunnel_port")
                if not asset.get(key)
                or str(asset.get(key)).upper() == REQUIRED_MARKER
            ]
            if missing:
                result[asset_id] = missing
        return result
