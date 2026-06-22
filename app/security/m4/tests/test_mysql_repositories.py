from datetime import datetime, timezone

from app.config import Settings
from app.models import (
    ActionResult,
    ActionStatus,
    EventSource,
    SecurityAction,
    SecurityEvent,
    SecurityIncident,
)
from app.repositories.event_repository import MySQLSecurityRepository
from app.repositories.identity_repository import IdentityRepository


class FakeCursor:
    def __init__(self, rows=None, affected=1):
        self.rows = list(rows or [])
        self.affected = affected
        self.executions = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        return self.affected

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self._cursor


def test_mysql_event_insert_is_idempotency_aware(monkeypatch):
    cursor = FakeCursor(affected=0)
    repository = MySQLSecurityRepository(Settings())
    monkeypatch.setattr(repository, "_connection", lambda: FakeConnection(cursor))
    added = repository.add_event(
        SecurityEvent(source=EventSource.M6, event_type="policy_denial")
    )
    assert added is False
    assert "INSERT IGNORE" in cursor.executions[0][0]


def test_mysql_incident_and_action_queries(monkeypatch):
    cursor = FakeCursor()
    repository = MySQLSecurityRepository(Settings())
    monkeypatch.setattr(repository, "_connection", lambda: FakeConnection(cursor))
    incident = SecurityIncident(incident_key="ip|10.0.0.1")
    repository.save_incident(incident)
    repository.save_action(
        ActionResult(
            incident_id=incident.incident_id,
            action=SecurityAction.WATCH,
            status=ActionStatus.SIMULATED,
        )
    )
    assert any("security_incidents" in sql for sql, _ in cursor.executions)
    assert any("security_actions" in sql for sql, _ in cursor.executions)


def test_identity_repository_queries_session_binding_and_auth(monkeypatch):
    cursor = FakeCursor(
        rows=[{"codigo_pucp": "USER", "total": 3, "reply": "Access-Reject"}]
    )
    repository = IdentityRepository(Settings())
    monkeypatch.setattr(repository, "_connection", lambda: FakeConnection(cursor))
    assert repository.get_active_session(ip="10.0.0.1")["codigo_pucp"] == "USER"
    assert repository.validate_binding("10.0.0.1", "aa:bb:cc:dd:ee:ff", "of:1", 2)
    history = repository.get_authentication_history(
        "USER", datetime.now(timezone.utc)
    )
    assert history
    assert repository.get_failed_logins(
        "USER", datetime.now(timezone.utc)
    ) == 3
