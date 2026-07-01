#!/usr/bin/env python3
"""
m5_logs.py — Módulo de Auditoría M5 — SDN PUCP
Grupo 2 | TEL354

Responsabilidades:
  - Recibir eventos de M1 via POST /m5/log
  - Persistir eventos en audit_log (MySQL)
  - Exponer endpoints de consulta para Admin_TI

Eventos que registra:
  login_exitoso, login_fallido, cuenta_bloqueada,
  logout, sesion_expirada, visitante_acceso,
  jp_solicitado, jp_aprobado, jp_rechazado, jp_revocado

Severidades:
  INFO    -> login_exitoso, logout, sesion_expirada, visitante_acceso,
             jp_aprobado, jp_rechazado, jp_revocado
  WARNING -> login_fallido, jp_solicitado
  ERROR   -> cuenta_bloqueada
"""
import json
import datetime
from flask import Flask, request, jsonify

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    MYSQL_OK = False
    print("[ADVERTENCIA] mysql-connector-python no instalado.")

app = Flask(__name__)

HOST = "0.0.0.0"
PORT = 5002  # M1 hace POST a http://127.0.0.1:5002/m5/log


# Configuración 
class Config:
    MYSQL_HOST = "localhost"
    MYSQL_USER = "radius"
    MYSQL_PASS = "radius_pass"
    MYSQL_DB   = "radius_db"


# Ejm: Severidad por evento 
SEVERIDAD = {
    "login_exitoso":    "INFO",
    "login_fallido":    "WARNING",
    "cuenta_bloqueada": "ERROR",
    "logout":           "INFO",
    "sesion_expirada":  "INFO",
    "visitante_acceso": "INFO",
    "jp_solicitado":    "WARNING",
    "jp_aprobado":      "INFO",
    "jp_rechazado":     "INFO",
    "jp_revocado":      "INFO",
}


# Conexión MySQL 
def get_connection():
    if not MYSQL_OK:
        return None
    try:
        return mysql.connector.connect(
            host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
            password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
            autocommit=False, use_pure=True, ssl_disabled=True
        )
    except mysql.connector.Error as e:
        print(f"  [M5] Error de conexión DB: {e}")
        return None


# Escritura de evento 
def insertar_evento(evento, usuario=None, rol=None, ip=None, mac=None,
                    duracion_ms=None, detalle=None):
    severidad = SEVERIDAD.get(evento, "INFO")
    conn = get_connection()
    if not conn:
        print(f"  [M5] Sin conexión DB — evento perdido: {evento}")
        return False
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_log
                (evento, severidad, usuario, rol, ip, mac, duracion_ms, detalle)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            evento, severidad, usuario, rol, ip, mac, duracion_ms,
            json.dumps(detalle) if detalle else None
        ))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"  [M5] Error al insertar evento: {e}")
        return False
    finally:
        conn.close()


# Endpoint: recibir evento de M1 
@app.route("/m5/log", methods=["POST"])
def recibir_log():
    """
    POST /m5/log
    Content-Type: application/json
    {
      "evento":      "login_exitoso",
      "usuario":     "20192434",
      "rol":         "Estudiante_Telecom",
      "ip":          "192.168.100.55",
      "mac":         "FA:16:3E:5A:AA:4A",
      "duracion_ms": 45,
      "detalle":     {"vlan_id": 210, "session_timeout": 7200}
    }
    """
    data = request.get_json(silent=True) or {}
    evento = data.get("evento")
    if not evento:
        return jsonify({"ok": False, "motivo": "falta campo: evento"}), 400

    ok = insertar_evento(
        evento      = evento,
        usuario     = data.get("usuario"),
        rol         = data.get("rol"),
        ip          = data.get("ip"),
        mac         = data.get("mac"),
        duracion_ms = data.get("duracion_ms"),
        detalle     = data.get("detalle"),
    )
    return jsonify({"ok": ok}), (200 if ok else 500)


# ── Endpoint: consultar logs (Admin_TI) ──────────────────────
@app.route("/m5/logs", methods=["GET"])
def consultar_logs():
    """
    GET /m5/logs?evento=login_fallido&usuario=20192434&limite=50
    Filtra por evento y/o usuario. Por defecto devuelve los últimos 100.
    """
    evento  = request.args.get("evento")
    usuario = request.args.get("usuario")
    limite  = int(request.args.get("limite", 100))

    conn = get_connection()
    if not conn:
        return jsonify({"ok": False, "motivo": "Error de conexión DB"}), 500
    try:
        cur = conn.cursor(dictionary=True)
        query  = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if evento:
            query += " AND evento = %s"
            params.append(evento)
        if usuario:
            query += " AND usuario = %s"
            params.append(usuario)
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limite)
        cur.execute(query, params)
        rows = cur.fetchall()
        # Serializar timestamps
        for row in rows:
            if isinstance(row.get("timestamp"), datetime.datetime):
                row["timestamp"] = row["timestamp"].isoformat(sep=" ")
            if isinstance(row.get("detalle"), str):
                try:
                    row["detalle"] = json.loads(row["detalle"])
                except Exception:
                    pass
        return jsonify({"ok": True, "total": len(rows), "logs": rows}), 200
    except Exception as e:
        return jsonify({"ok": False, "motivo": str(e)}), 500
    finally:
        conn.close()


# ── Endpoint: métricas (Admin_TI) ────────────────────────────
@app.route("/m5/metricas", methods=["GET"])
def metricas():
    """
    GET /m5/metricas
    Devuelve métricas de auditoría calculadas desde audit_log.
    """
    conn = get_connection()
    if not conn:
        return jsonify({"ok": False, "motivo": "Error de conexión DB"}), 500
    try:
        cur = conn.cursor(dictionary=True)

        # Tasa de bloqueo
        cur.execute("""
            SELECT
                COUNT(CASE WHEN evento IN ('login_fallido','cuenta_bloqueada')
                      THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0)
                AS tasa_bloqueo_pct
            FROM audit_log
            WHERE evento IN ('login_exitoso','login_fallido','cuenta_bloqueada')
        """)
        tasa = cur.fetchone()

        # Latencia promedio
        cur.execute("""
            SELECT
                ROUND(AVG(duracion_ms), 2) AS latencia_promedio_ms,
                MIN(duracion_ms)           AS latencia_min_ms,
                MAX(duracion_ms)           AS latencia_max_ms
            FROM audit_log
            WHERE evento = 'login_exitoso' AND duracion_ms IS NOT NULL
        """)
        latencia = cur.fetchone()

        # Logins por segundo (última hora)
        cur.execute("""
            SELECT
                ROUND(COUNT(*) / NULLIF(
                    TIMESTAMPDIFF(SECOND, MIN(timestamp), MAX(timestamp)), 0
                ), 4) AS logins_por_segundo
            FROM audit_log
            WHERE evento = 'login_exitoso'
              AND timestamp >= NOW() - INTERVAL 1 HOUR
        """)
        throughput = cur.fetchone()

        # Total por evento
        cur.execute("""
            SELECT evento, severidad, COUNT(*) AS total
            FROM audit_log
            GROUP BY evento, severidad
            ORDER BY total DESC
        """)
        por_evento = cur.fetchall()

        # Roles soportados
        cur.execute("SELECT COUNT(*) AS total_roles FROM roles_facultad")
        roles = cur.fetchone()

        return jsonify({
            "ok": True,
            "tasa_bloqueo_pct":     round(tasa["tasa_bloqueo_pct"] or 0, 2),
            "latencia_promedio_ms": latencia["latencia_promedio_ms"],
            "latencia_min_ms":      latencia["latencia_min_ms"],
            "latencia_max_ms":      latencia["latencia_max_ms"],
            "logins_por_segundo":   throughput["logins_por_segundo"],
            "total_roles":          roles["total_roles"],
            "eventos_por_tipo":     por_evento,
        }), 200
    except Exception as e:
        return jsonify({"ok": False, "motivo": str(e)}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    print(f"[M5 Auditoría] http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)