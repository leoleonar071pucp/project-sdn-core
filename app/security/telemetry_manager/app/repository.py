from __future__ import annotations

from threading import Lock

from .config import Settings
from .models import MirrorRecord

try:
    import pymysql
except ImportError:  # pragma: no cover
    pymysql = None


class MemoryMirrorRepository:
    def __init__(self):
        self._lock = Lock()
        self._by_incident: dict[str, MirrorRecord] = {}

    def get(self, incident_id: str) -> MirrorRecord | None:
        return self._by_incident.get(incident_id)

    def save(self, record: MirrorRecord) -> None:
        with self._lock:
            self._by_incident[record.incident_id] = record

    def list(self) -> list[MirrorRecord]:
        return list(self._by_incident.values())


class MySQLMirrorRepository:
    def __init__(self, settings: Settings):
        if pymysql is None:
            raise RuntimeError("pymysql is required")
        self.settings = settings

    def _connection(self):
        return pymysql.connect(
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            user=self.settings.mysql_user,
            password=self.settings.mysql_password,
            database=self.settings.mysql_database,
            autocommit=True,
        )

    def save(self, record: MirrorRecord) -> None:
        with self._connection() as conn, conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO active_mirrors
                    (mirror_id, incident_id, asset_id, permanent, switch_dpid,
                     bridge_name, in_port, src_mac, status, expires_at, payload_json)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    status=VALUES(status), expires_at=VALUES(expires_at),
                    payload_json=VALUES(payload_json)
                """,
                (
                    record.mirror_id,
                    record.incident_id,
                    record.asset_id,
                    int(record.permanent),
                    record.switch_dpid,
                    record.bridge,
                    record.in_port,
                    record.src_mac,
                    record.status.value,
                    record.expires_at.replace(tzinfo=None) if record.expires_at else None,
                    record.model_dump_json(),
                ),
            )

    def get(self, incident_id: str) -> MirrorRecord | None:
        with self._connection() as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT payload_json FROM active_mirrors WHERE incident_id=%s",
                (incident_id,),
            )
            row = cursor.fetchone()
        return MirrorRecord.model_validate_json(row[0]) if row else None

    def list(self) -> list[MirrorRecord]:
        with self._connection() as conn, conn.cursor() as cursor:
            cursor.execute("SELECT payload_json FROM active_mirrors")
            rows = cursor.fetchall()
        return [MirrorRecord.model_validate_json(row[0]) for row in rows]
