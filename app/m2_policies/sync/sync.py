import os
import time
import pymysql
import requests
from datetime import datetime

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "user": os.getenv("DB_USER", "radius"),
    "password": os.getenv("DB_PASSWORD", "radius_pass"),
    "database": os.getenv("DB_NAME", "radius_db"),
    "charset": "utf8mb4",
    "connect_timeout": 5,
}

OPA_URL = os.getenv("OPA_URL", "http://opa:8182")

RESOURCES_INTERVAL = int(os.getenv("RESOURCES_SYNC_INTERVAL", "300"))  # 5 min
EXCEPTIONS_INTERVAL = int(os.getenv("EXCEPTIONS_SYNC_INTERVAL", "30"))  # 30 seg

session = requests.Session()


def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC] {msg}", flush=True)


def wait_for_db():
    while True:
        try:
            conn = pymysql.connect(**DB_CONFIG)
            conn.close()
            log("MySQL listo")
            return
        except Exception as e:
            log(f"MySQL no disponible: {e}")
            time.sleep(2)


def wait_for_opa():
    while True:
        try:
            r = session.get(f"{OPA_URL}/health", timeout=5)
            if r.status_code == 200:
                log("OPA listo")
                return
        except Exception:
            pass
        log("Esperando OPA...")
        time.sleep(2)


def get_connection():
    return pymysql.connect(**DB_CONFIG)


def fetch_resources():
    conn = get_connection()
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT
                r.id_recurso AS id,
                r.nombre_recurso AS nombre,
                s.ip_servidor AS ip_servidor,
                s.mac_servidor AS mac_servidor,
                r.puerto,
                r.protocolo,
                r.ancho_banda_default
            FROM recursos r
            JOIN servidores s ON r.id_servidor = s.id_servidor
        """)
        recursos_rows = cursor.fetchall()

        cursor.execute("""
            SELECT
                pr.id_recurso,
                pr.group_id,
                pr.tipo_condicion,
                pr.id_rol,
                pr.valor_condicion,
                rf.nombre_rol AS nombre_rol,
                rf.vlan_id AS vlan_rol
            FROM politicas_rbac pr
            LEFT JOIN roles_facultad rf
                ON pr.id_rol = rf.id_rol
            WHERE pr.activo = 1
              AND pr.accion = 'ALLOW'
        """)
        condiciones_rows = cursor.fetchall()

        grupos_por_recurso = {}
        for row in condiciones_rows:
            rid = str(row["id_recurso"])
            group_id = str(row["group_id"])
            tipo = row["tipo_condicion"] or "rol"

            if tipo == "rol":
                valor = row["nombre_rol"] or (str(row["id_rol"]) if row["id_rol"] is not None else None)
            else:
                valor = row["valor_condicion"]

            if valor is None:
                continue

            condicion = {"tipo": tipo, "valor": valor}
            grupos_por_recurso.setdefault(rid, {}).setdefault(group_id, []).append(condicion)

        recursos = {}
        for r in recursos_rows:
            rid = str(r["id"])
            grupos_map = grupos_por_recurso.get(rid, {})
            grupos = [grupos_map[group_id] for group_id in sorted(grupos_map, key=lambda k: int(k))]

            recursos[rid] = {
                "id": r["id"],
                "nombre": r["nombre"],
                "ip_servidor": r["ip_servidor"],
                "mac_servidor": r["mac_servidor"],
                #"ip_dst": r["ip_dst"],
                "puerto": r["puerto"],
                "protocolo": r["protocolo"],
                "grupos": grupos,
                "ancho_banda_default": r["ancho_banda_default"]
            }
        return recursos
    finally:
        conn.close()


def fetch_exceptions():
    conn = get_connection()
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT
                u.codigo_pucp   AS usuario,
                pt.id_recurso,
                r.nombre_recurso AS recurso,
                pt.allow AS allow,
                pt.expiration,
                pt.razon AS razon,
                pt.ancho_banda AS ancho_banda,
                pt.prioridad AS prioridad
            FROM politicas_temporales pt
            JOIN usuarios u ON pt.id_usuario = u.id_usuario
            JOIN recursos r ON pt.id_recurso = r.id_recurso
            WHERE pt.activo = 1
              AND (pt.expiration IS NULL OR pt.expiration > NOW())
        """)
        rows = cursor.fetchall()

        excepciones_por_usuario = {}
        for row in rows:
            usuario  = row["usuario"]
            ex_entry = {
                "recurso_id": str(row["id_recurso"]),
                "recurso":    row["recurso"],
                "allow":      bool(row["allow"]),
            }
            if row["expiration"]:
                ex_entry["expires_at"] = row["expiration"].strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if row["ancho_banda"] is not None:
                ex_entry["ancho_banda"] = row["ancho_banda"]
            excepciones_por_usuario.setdefault(usuario, []).append(ex_entry)

        return excepciones_por_usuario
    finally:
        conn.close()

def push_resources(data):
    r = session.put(f"{OPA_URL}/v1/data/pool/recursos", json=data, timeout=10)
    r.raise_for_status()
    log(f"Recursos sincronizados ({len(data)} recursos)")


def push_exceptions(data):
    r = session.put(f"{OPA_URL}/v1/data/pool/excepciones", json=data, timeout=10)
    r.raise_for_status()
    log(f"Excepciones sincronizadas ({len(data)} excepciones)")


if __name__ == "__main__":
    log("Iniciando sincronizador")

    wait_for_db()
    wait_for_opa()

    last_resources_sync = 0
    last_exceptions_sync = 0

    while True:
        now = time.time()

        try:
            if now - last_resources_sync >= RESOURCES_INTERVAL:
                resources = fetch_resources()
                push_resources(resources)
                last_resources_sync = now
        except Exception as e:
            log(f"Error sincronizando recursos: {e}")

        try:
            if now - last_exceptions_sync >= EXCEPTIONS_INTERVAL:
                exceptions = fetch_exceptions()
                push_exceptions(exceptions)
                last_exceptions_sync = now
        except Exception as e:
            log(f"Error sincronizando excepciones: {e}")

        time.sleep(5)