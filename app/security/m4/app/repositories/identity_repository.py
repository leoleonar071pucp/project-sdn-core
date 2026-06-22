from __future__ import annotations

from datetime import datetime

from ..config import Settings

try:
    import pymysql
except ImportError:  # pragma: no cover
    pymysql = None


class IdentityRepository:
    """Read-only access to identity and authentication data in radius_db."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def _connection(self):
        if pymysql is None:
            raise RuntimeError("pymysql is required for identity queries")
        return pymysql.connect(
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            user=self.settings.mysql_user,
            password=self.settings.mysql_password,
            database=self.settings.mysql_database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=3,
        )

    def get_active_session(
        self,
        ip: str | None = None,
        mac: str | None = None,
    ) -> dict | None:
        if not ip and not mac:
            return None
        filters, params = ["s.estado='ACTIVA'"], []
        if ip:
            filters.append("s.ip_asignada=%s")
            params.append(ip)
        if mac:
            filters.append("LOWER(s.mac_address)=LOWER(%s)")
            params.append(mac)
        sql = f"""
            SELECT s.*, u.codigo_pucp
            FROM sesiones_activas s
            JOIN usuarios u ON u.id_usuario=s.id_usuario
            WHERE {' AND '.join(filters)}
            LIMIT 1
        """
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return cur.fetchone()

    def get_authentication_history(
        self,
        username: str,
        since: datetime,
    ) -> list[dict]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT username, reply, authdate
                FROM radpostauth
                WHERE username=%s AND authdate >= %s
                ORDER BY authdate DESC
                """,
                (username, since.replace(tzinfo=None)),
            )
            return list(cur.fetchall())

    def get_failed_logins(
        self,
        username: str,
        since: datetime,
    ) -> int:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM radpostauth
                WHERE username=%s AND authdate >= %s
                  AND reply NOT LIKE 'Access-Accept%%'
                """,
                (username, since.replace(tzinfo=None)),
            )
            row = cur.fetchone()
        return int(row["total"]) if row else 0

    def validate_binding(
        self,
        ip: str,
        mac: str,
        switch_dpid: str,
        in_port: int,
    ) -> bool:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM ip_mac_binding b
                JOIN sesiones_activas s ON s.id_sesion=b.id_sesion
                WHERE b.ip_asignada=%s
                  AND LOWER(b.mac_address)=LOWER(%s)
                  AND s.switch_dpid=%s
                  AND s.in_port=%s
                  AND s.estado='ACTIVA'
                LIMIT 1
                """,
                (ip, mac, switch_dpid, in_port),
            )
            return cur.fetchone() is not None
