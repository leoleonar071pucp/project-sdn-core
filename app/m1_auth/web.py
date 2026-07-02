#!/usr/bin/env python3
"""
webYO.py — Portal Cautivo Web (API JSON) — SDN PUCP
Módulo M1 | Grupo 2 - TEL354
- Sheila J 
Ejecutar en VM-Auth: python3 -u web.py

"""
from flask import Flask, request, jsonify, render_template_string

from m1_auth import Config, autenticar, autenticar_visitante, cerrar_sesion, \
    obtener_recursos_permitidos, obtener_sesion_actual, obtener_recursos_sesion, \
    solicitar_jp, historial_jp, listar_solicitudes_jp, resolver_solicitud_jp

app = Flask(__name__)

HOST = "0.0.0.0"
PORT = 8282  # coincide con el ejemplo: 192.168.100.110:8282

# HTML --> si hubiera interfaz grafica, se vería por ahi el formulario de ingreso :'v
PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Portal Cautivo — PUCP SDN</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',Arial,sans-serif;
         background:linear-gradient(135deg,#003366 0%,#0066cc 100%);
         min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#fff;border-radius:12px;padding:40px 36px;width:400px;
          box-shadow:0 20px 60px rgba(0,0,0,.3)}
    .logo{text-align:center;margin-bottom:28px}
    .logo h1{color:#003366;font-size:1.25em;line-height:1.4}
    .logo p{color:#666;font-size:.82em;margin-top:5px}
    label{display:block;font-size:.88em;color:#333;font-weight:600;margin-bottom:5px}
    input[type=text],input[type=password]{
      width:100%;padding:10px 13px;border:1.5px solid #ccc;
      border-radius:6px;font-size:.95em;margin-bottom:18px}
    input:focus{outline:none;border-color:#0066cc}
    button{width:100%;padding:12px;background:#003366;color:#fff;
           border:none;border-radius:6px;font-size:1em;cursor:pointer;font-weight:600}
    button:hover{background:#0052a3}
    .msg{border-radius:6px;padding:11px 14px;margin-bottom:18px;font-size:.88em}
    .error{background:#ffe0e0;color:#c00}
    .ok{background:#e0ffe8;color:#060}
    .info{color:#999;font-size:.78em;text-align:center;margin-top:18px}
    .role-badge{display:inline-block;background:#003366;color:#fff;
                border-radius:20px;padding:3px 12px;font-size:.85em;margin-top:4px}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>&#127979; PUCP — Red SDN Zero Trust</h1>
    <p>TEL354 · Grupo 2 · Autenticación de acceso</p>
  </div>

  <div id="msg"></div>

  <form id="loginForm">
    <label for="u">Código PUCP</label>
    <input type="text" id="u" name="usuario" placeholder="ej. 20192434" required autofocus>
    <label for="p">Contraseña</label>
    <input type="password" id="p" name="password" placeholder="Contraseña PUCP" required>
    <button type="submit">Iniciar sesión</button>
  </form>

  <p class="info">Sistema SDN Zero Trust PUCP</p>
</div>

<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const usuario  = document.getElementById('u').value.trim();
  const password = document.getElementById('p').value.trim();
  const msgDiv   = document.getElementById('msg');

  try {
    const resp = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({usuario, password})
    });
    const data = await resp.json();

    if (data.ok) {
      msgDiv.innerHTML = `
        <div class="msg ok">
          <strong>&#10003; Acceso concedido</strong><br>
          Usuario: <strong>${data.codigo_pucp}</strong><br>
          Rol: <span class="role-badge">${data.nombre_rol}</span><br>
          VLAN asignada: <strong>${data.vlan_id}</strong>
        </div>`;
      document.getElementById('loginForm').style.display = 'none';
    } else {
      msgDiv.innerHTML = `<div class="msg error">&#10007; ${data.motivo}</div>`;
    }
  } catch (err) {
    msgDiv.innerHTML = `<div class="msg error">&#10007; Error de conexión: ${err}</div>`;
  }
});
</script>
</body>
</html>"""

# los ends points necesarios 

@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """
    POST /auth/login
    Content-Type: application/json
    {"usuario": "...", "password": "..."}

    La IP real del cliente se toma de request.remote_addr.

    La respuesta incluye "session_timeout" (segundos) cuando ok=true, tomado del atributo Session-Timeout de FreeRADIUS para ese rol.
    El cliente lo usa para mostrar la cuenta regresiva hasta el cierre automático de sesión.
    """
    data = request.get_json(silent=True) or {}
    usuario  = data.get("usuario", "").strip()
    password = data.get("password", "").strip()

    # IP real del host que hizo el request HTTP 
    ip_asignada = request.remote_addr

    resultado = autenticar(usuario, password, ip_asignada)
    status_code = 200 if resultado["ok"] else 401
    return jsonify(resultado), status_code


@app.route("/auth/visitante", methods=["POST"])
def auth_visitante():
    """
    POST /auth/visitante
    Content-Type: application/json
    {"correo": "...", "password": "..."}

    La respuesta incluye "session_timeout" fijo en 1800s (30 min), regla para visitantes.
    """
    data = request.get_json(silent=True) or {}
    correo   = data.get("correo", "").strip()
    password = data.get("password", "").strip()
    ip_asignada = request.remote_addr

    resultado = autenticar_visitante(correo, password, ip_asignada)
    status_code = 200 if resultado["ok"] else 401
    return jsonify(resultado), status_code


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """
    POST /auth/logout
    Content-Type: application/json
    {"mac": "...", "id_usuario": 0, "codigo_pucp": "...",
     "ip_asignada": "...", "es_visitante": false}
    """
    data = request.get_json(silent=True) or {}
    mac = data.get("mac")
    if not mac:
        return jsonify({"ok": False, "motivo": "falta campo: mac"}), 400

    resultado = cerrar_sesion(
        mac=mac,
        id_usuario=data.get("id_usuario", 0),
        codigo_pucp=data.get("codigo_pucp"),
        ip_asignada=data.get("ip_asignada"),
        es_visitante=data.get("es_visitante", False),
    )
    return jsonify(resultado), (200 if resultado["ok"] else 404)


@app.route("/auth/sesion/actual", methods=["GET"])
def auth_sesion_actual():
    """
    GET /auth/sesion/actual

    Resuelve la MAC del solicitante a partir de su IP (request.remote_addr) y consulta si existe una sesión activa para ese host en sesiones_activas.
    Usado por cli.py al iniciar/reiniciar para resumir sesión sin pedir login otra vez si el host ya estaba autenticado.

    Respuesta:
      {"ok": true, "activa": false}
      {"ok": true, "activa": true, "sesion": {...}}
    """
    resultado = obtener_sesion_actual(request.remote_addr)
    return jsonify(resultado), (200 if resultado.get("ok") else 500)


@app.route("/auth/sesion/recursos", methods=["GET"])
def auth_sesion_recursos():
    """
    GET /auth/sesion/recursos

    Devuelve los recursos permitidos para la sesión activa del solicitante (resuelta por IP), combinando T2 (reglas del rol,
    politicas_rbac) y T3 (excepciones temporales del usuario, politicas_temporales, no expiradas). Si no hay sesión activa para esa IP, responde ok=false.

    Respuesta:
      {"ok": true, "sesion": {...}, "recursos": [...]}
      {"ok": false, "motivo": "No hay sesion activa."}
    """
    resultado = obtener_recursos_sesion(request.remote_addr)
    return jsonify(resultado), (200 if resultado.get("ok") else 404)

# Lgógica para JP / Multi-rol 

@app.route("/jp/solicitar", methods=["POST"])
def jp_solicitar():
    """
    POST /jp/solicitar
    Content-Type: application/json
    {"carrera_jp": "Estudiante_Telecom"}

    El codigo_pucp/id_usuario se resuelve SIEMPRE desde la sesion activa
    (por IP del request), nunca se recibe en el body.
    """
    data = request.get_json(silent=True) or {}
    carrera_jp = (data.get("carrera_jp") or "").strip()
    if not carrera_jp:
        return jsonify({"ok": False, "motivo": "falta campo: carrera_jp"}), 400
    resultado = solicitar_jp(request.remote_addr, carrera_jp)
    return jsonify(resultado), (200 if resultado.get("ok") else 400)


@app.route("/jp/historial", methods=["GET"])
def jp_historial():
    """Historial de postulaciones JP del usuario de la sesion activa."""
    resultado = historial_jp(request.remote_addr)
    return jsonify(resultado), (200 if resultado.get("ok") else 404)


@app.route("/jp/solicitudes", methods=["GET"])
def jp_solicitudes():
    """
    GET /jp/solicitudes?estado=PENDIENTE
    Uso exclusivo de Admin_TI. estado=TODAS lista sin filtro.

    Se valida server-side que la sesion activa del solicitante sea
    Admin_TI — no basta con que cli.py oculte la opcion del menu.
    """
    estado = obtener_sesion_actual(request.remote_addr)
    if not estado.get("activa"):
        return jsonify({"ok": False, "motivo": "No hay sesion activa."}), 401
    if estado["sesion"].get("nombre_rol") != "Admin_TI":
        return jsonify({"ok": False, "motivo": "Solo Admin_TI puede ver las solicitudes JP."}), 403

    filtro = request.args.get("estado", "PENDIENTE")
    if filtro.upper() == "TODAS":
        filtro = None
    resultado = listar_solicitudes_jp(filtro)
    return jsonify(resultado), (200 if resultado.get("ok") else 500)


@app.route("/jp/resolver", methods=["POST"])
def jp_resolver():
    """
    POST /jp/resolver
    Content-Type: application/json
    {"id_solicitud": 3, "accion": "APROBAR", "expiration": "2026-12-31 23:59:59", "motivo": null}

    El id_admin se resuelve desde la sesion activa del que hace el
    request (debe ser Admin_TI). accion: APROBAR | RECHAZAR | REVOCAR
    expiration es obligatorio solo cuando accion='APROBAR'
    (formato 'YYYY-MM-DD HH:MM:SS'); resolver_solicitud_jp valida esto
    internamente y responde FALTA_EXPIRATION si falta.
    """
    data = request.get_json(silent=True) or {}
    id_solicitud = data.get("id_solicitud")
    accion = (data.get("accion") or "").strip().upper()
    expiration = data.get("expiration")
    motivo = data.get("motivo")

    if not id_solicitud or accion not in ("APROBAR", "RECHAZAR", "REVOCAR"):
        return jsonify({"ok": False, "motivo": "faltan campos: id_solicitud, accion valida"}), 400

    estado = obtener_sesion_actual(request.remote_addr)
    if not estado.get("activa"):
        return jsonify({"ok": False, "motivo": "No hay sesion activa."}), 401
    sesion = estado["sesion"]
    if sesion.get("nombre_rol") != "Admin_TI":
        return jsonify({"ok": False, "motivo": "Solo Admin_TI puede resolver solicitudes JP."}), 403

    resultado = resolver_solicitud_jp(
        id_solicitud, sesion.get("id_usuario"), accion,
        expiration=expiration, motivo=motivo,
    )
    return jsonify(resultado), (200 if resultado.get("ok") else 400)


if __name__ == "__main__":
    print(f"[Portal Web] http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)