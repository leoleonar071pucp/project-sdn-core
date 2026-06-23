from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Callable

import httpx
import yaml

from .config import Settings


class EveForwarder:
    def __init__(
        self,
        settings: Settings,
        sender: Callable[[dict], None] | None = None,
    ):
        self.settings = settings
        self.sender = sender or self._send_http
        self._seen: set[str] = set()
        self._critical_assets = self._load_critical_assets()

    def _load_critical_assets(self) -> dict[str, str]:
        try:
            data = yaml.safe_load(
                self.settings.critical_assets_path.read_text(encoding="utf-8")
            ) or {}
        except OSError:
            return {}
        return {
            item["destination_ip"]: item["id"]
            for item in data.get("assets", [])
            if item.get("destination_ip")
            and str(item["destination_ip"]).upper() != "REQUIRED"
        }

    def _load_offset(self) -> int:
        try:
            return int(json.loads(self.settings.state_path.read_text())["offset"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return 0

    def _save_offset(self, offset: int) -> None:
        self.settings.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings.state_path.write_text(
            json.dumps({"offset": offset}), encoding="utf-8"
        )

    @staticmethod
    def _dedupe_key(event: dict) -> str:
        alert = event.get("alert", {})
        raw = "|".join(
            str(value or "")
            for value in (
                event.get("event_id"),
                event.get("flow_id"),
                event.get("timestamp"),
                alert.get("signature_id"),
                alert.get("signature"),
                event.get("src_ip"),
                event.get("dest_ip"),
            )
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def normalize(self, event: dict) -> dict | None:
        event_type = event.get("event_type")
        if event_type not in self.settings.allowed_types:
            return None
        key = self._dedupe_key(event)
        if key in self._seen:
            return None
        self._seen.add(key)
        event = dict(event)
        event["event_id"] = event.get("event_id") or key
        event["sensor_id"] = event.get("host") or "suricata-offline"
        asset_id = self._critical_assets.get(event.get("dest_ip"))
        if asset_id:
            event["mirror_scope"] = "permanent"
            event["asset_id"] = asset_id
        return event

    def process_file(self, path: Path | None = None, resume: bool = True) -> dict:
        path = path or self.settings.eve_path
        offset = self._load_offset() if resume and path == self.settings.eve_path else 0
        stats = {"processed": 0, "forwarded": 0, "duplicates_or_filtered": 0, "invalid": 0}
        with path.open("r", encoding="utf-8") as stream:
            stream.seek(offset)
            while line := stream.readline():
                stats["processed"] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats["invalid"] += 1
                    continue
                normalized = self.normalize(event)
                if normalized is None:
                    stats["duplicates_or_filtered"] += 1
                    continue
                try:
                    self.sender(normalized)
                    stats["forwarded"] += 1
                except Exception:
                    self._enqueue(normalized)
            if resume and path == self.settings.eve_path:
                self._save_offset(stream.tell())
        return stats

    def _enqueue(self, event: dict) -> None:
        self.settings.queue_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if self.settings.queue_path.exists():
            lines = self.settings.queue_path.read_text(encoding="utf-8").splitlines()
        lines = lines[-(self.settings.max_queue_size - 1):] + [json.dumps(event)]
        self.settings.queue_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def retry_queue(self, attempts: int = 3) -> int:
        if not self.settings.queue_path.exists():
            return 0
        pending = [
            json.loads(line)
            for line in self.settings.queue_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        remaining, sent = [], 0
        for event in pending:
            delivered = False
            for attempt in range(attempts):
                try:
                    self.sender(event)
                    delivered = True
                    sent += 1
                    break
                except Exception:
                    if attempt + 1 < attempts:
                        time.sleep(2**attempt)
            if not delivered:
                remaining.append(event)
        self.settings.queue_path.write_text(
            "".join(json.dumps(event) + "\n" for event in remaining),
            encoding="utf-8",
        )
        return sent

    def _send_http(self, event: dict) -> None:
        if self.settings.dry_run:
            self.settings.dry_run_output.parent.mkdir(parents=True, exist_ok=True)
            with self.settings.dry_run_output.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event) + "\n")
            return
        response = httpx.post(
            f"{self.settings.m4_url}/m4/events/suricata",
            json=event,
            headers={"X-Security-Token": self.settings.security_token},
            timeout=self.settings.http_timeout_seconds,
        )
        response.raise_for_status()
