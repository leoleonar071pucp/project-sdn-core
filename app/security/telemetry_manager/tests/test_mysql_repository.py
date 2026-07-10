from app.config import Settings
from app.models import MirrorRecord, MirrorStatus
from app.repository import MySQLMirrorRepository


class Cursor:
    def __init__(self):
        self.executions = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.executions.append((sql, params))


class Connection:
    def __init__(self, cursor):
        self.value = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self.value


def test_mysql_mirror_save_uses_upsert_without_connection(monkeypatch):
    cursor = Cursor()
    repository = MySQLMirrorRepository(Settings())
    monkeypatch.setattr(repository, "_connection", lambda: Connection(cursor))
    repository.save(
        MirrorRecord(
            incident_id="inc",
            switch_dpid="of:1",
            bridge="br-test",
            source_port="p2",
            output_tunnel_port="gre",
            status=MirrorStatus.SIMULATED,
        )
    )
    assert "ON DUPLICATE KEY UPDATE" in cursor.executions[0][0]
