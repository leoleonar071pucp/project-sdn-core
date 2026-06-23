from __future__ import annotations

import json
from threading import Lock
from typing import Protocol

from ..config import Settings
from ..models import ActionResult, SecurityEvent, SecurityIncident

try:
    import pymysql
except ImportError:  # pragma: no cover - only relevant in incomplete deployments
    pymysql = None


class SecurityRepository(Protocol):
    def add_event(self, event: SecurityEvent) -> bool: ...
    def get_incident_by_key(self, key: str) -> SecurityIncident | None: ...
    def save_incident(self, incident: SecurityIncident) -> None: ...
    def save_action(self, result: ActionResult) -> None: ...
    def list_incidents(self) -> list[SecurityIncident]: ...
    def get_incident(self, incident_id: str) -> SecurityIncident | None: ...


class MemorySecurityRepository:
    def __init__(self):
        self._lock = Lock()
        self._event_keys: set[str] = set()
        self._incidents_by_key: dict[str, SecurityIncident] = {}
        self._incidents_by_id: dict[str, SecurityIncident] = {}
        self.actions: list[ActionResult] = []

    def add_event(self, event: SecurityEvent) -> bool:
        with self._lock:
            if event.idempotency_key in self._event_keys:
                return False
            self._event_keys.add(event.idempotency_key)
            return True

    def get_incident_by_key(self, key: str) -> SecurityIncident | None:
        return self._incidents_by_key.get(key)

    def save_incident(self, incident: SecurityIncident) -> None:
        with self._lock:
            self._incidents_by_key[incident.incident_key] = incident
            self._incidents_by_id[incident.incident_id] = incident

    def save_action(self, result: ActionResult) -> None:
        with self._lock:
            self.actions.append(result)

    def list_incidents(self) -> list[SecurityIncident]:
        return sorted(
            self._incidents_by_id.values(),
            key=lambda item: item.updated_at,
            reverse=True,
        )

    def get_incident(self, incident_id: str) -> SecurityIncident | None:
        return self._incidents_by_id.get(incident_id)


class MySQLSecurityRepository:
    """Lazy MySQL repository. It never connects during application startup."""

    def __init__(self, settings: Settings):
        if pymysql is None:
            raise RuntimeError("pymysql is required for MySQL persistence")
        self.settings = settings

    def _connection(self):
        return pymysql.connect(
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            user=self.settings.mysql_user,
            password=self.settings.mysql_password,
            database=self.settings.mysql_database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=3,
            autocommit=True,
        )

    def add_event(self, event: SecurityEvent) -> bool:
        sql = """
            INSERT IGNORE INTO security_events
                (idempotency_key, source, event_type, event_timestamp,
                 src_ip, src_mac, dst_ip, dst_port, protocol,
                 switch_dpid, in_port, username, role_name, severity, metadata_json)
            VALUES
                (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """
        with self._connection() as conn, conn.cursor() as cur:
            affected = cur.execute(
                sql,
                (
                    event.idempotency_key,
                    event.source.value,
                    event.event_type,
                    event.timestamp.replace(tzinfo=None),
                    event.src_ip,
                    event.src_mac,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                    event.switch_dpid,
                    event.in_port,
                    event.username,
                    event.role,
                    event.severity,
                    json.dumps(event.metadata),
                ),
            )
        return bool(affected)

    def get_incident_by_key(self, key: str) -> SecurityIncident | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT payload_json FROM security_incidents WHERE incident_key=%s",
                (key,),
            )
            row = cur.fetchone()
        return SecurityIncident.model_validate_json(row["payload_json"]) if row else None

    def save_incident(self, incident: SecurityIncident) -> None:
        sql = """
            INSERT INTO security_incidents
                (incident_id, incident_key, state, score, threat_type,
                 recommended_action, payload_json, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                state=VALUES(state), score=VALUES(score),
                threat_type=VALUES(threat_type),
                recommended_action=VALUES(recommended_action),
                payload_json=VALUES(payload_json), updated_at=VALUES(updated_at)
        """
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    incident.incident_id,
                    incident.incident_key,
                    incident.state.value,
                    incident.score,
                    incident.threat_type,
                    incident.recommended_action.value,
                    incident.model_dump_json(),
                    incident.created_at.replace(tzinfo=None),
                    incident.updated_at.replace(tzinfo=None),
                ),
            )

    def save_action(self, result: ActionResult) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_actions
                    (action_id, incident_id, action_type, status, payload_json)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (
                    result.action_id,
                    result.incident_id,
                    result.action.value,
                    result.status.value,
                    result.model_dump_json(),
                ),
            )

    def list_incidents(self) -> list[SecurityIncident]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT payload_json FROM security_incidents ORDER BY updated_at DESC"
            )
            rows = cur.fetchall()
        return [SecurityIncident.model_validate_json(row["payload_json"]) for row in rows]

    def get_incident(self, incident_id: str) -> SecurityIncident | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT payload_json FROM security_incidents WHERE incident_id=%s",
                (incident_id,),
            )
            row = cur.fetchone()
        return SecurityIncident.model_validate_json(row["payload_json"]) if row else None
