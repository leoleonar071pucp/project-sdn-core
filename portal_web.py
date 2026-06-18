#!/usr/bin/env python3
# portal_web.py — Portal Cautivo Web (M1)
# VM-Auth: python3 -u /root/portal_web.py

from flask import Flask, request, render_template_string
import pyrad.client, pyrad.packet, pyrad.dictionary
import requests, os

app = Flask(__name__)

RADIUS_HOST   = "127.0.0.1"
RADIUS_PORT   = 1812
RADIUS_SECRET = b"testing123"
M6_URL        = "http://127.0.0.1:8080/m6/token_rol"
ONOS_URL      = "http://192.168.201.200:8181"
ONOS_AUTH     = ("onos", "rocks")

VLANS_POR_ROL = {
    "Visitante":              100,
    "Estudiante_Telecom":     210,
    "Estudiante_Informatica": 220,
    "Estudiante_Electronica": 230,
    "Docente":                300,
    "Admin_TI":               400,
}

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

  {% if error %}
  <div class="msg error">&#10007; {{ error }}</div>
  {% endif %}

  {% if success %}
  <div class="msg ok">
    <strong>&#10003; Acceso concedido</strong><br>
    Usuario: <strong>{{ username }}</strong><br>
    Rol: <span class="role-badge">{{ role }}</span><br>
    VLAN asignada: <strong>{{ vlan }}</strong>
  </div>
  <p class="info">Ya puedes acceder a los recursos académicos autorizados.</p>
  {% else %}
  <form method="POST" action="/auth">
    <label for="u">Código PUCP</label>
    <input type="text" id="u" name="username" placeholder="ej. 20192434" required autofocus>
    <label for="p">Contraseña</label>
    <input type="password" id="p" name="password" placeholder="Contraseña PUCP" required>
    <button type="submit">Iniciar sesión</button>
  </form>
  {% endif %}

  <p class="info">IP cliente: {{ client_ip }} · Sistema SDN Zero Trust PUCP</p>
</div>
</body>
</html>"""


def radius_auth(username, password):
    try:
        dict_path = "/usr/share/freeradius/dictionary"
        d = pyrad.dictionary.Dictionary(dict_path) if os.path.exists(dict_path) \
            else pyrad.dictionary.Dictionary()
        cli = pyrad.client.Client(server=RADIUS_HOST, authport=RADIUS_PORT,
                                  secret=RADIUS_SECRET, dict=d)
        cli.timeout = 5
        req = cli.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                   User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-IP-Address"] = "127.0.0.1"
        req["NAS-Port"] = 0
        reply = cli.SendPacket(req)
        if reply.code == pyrad.packet.AccessAccept:
            fid = reply.get("Filter-Id")
            if fid:
                val = fid[0] if isinstance(fid, (list, tuple)) else fid
                return val.decode() if isinstance(val, bytes) else val
            return "Visitante"
        return None
    except Exception as e:
        print(f"[RADIUS] {e}")
        return None


def get_mac_from_onos(ip):
    try:
        r = requests.get(f"{ONOS_URL}/onos/v1/hosts", auth=ONOS_AUTH, timeout=3)
        for h in r.json().get("hosts", []):
            if ip in h.get("ipAddresses", []):
                return h["mac"]
    except Exception as e:
        print(f"[ONOS] {e}")
    return None


@app.route("/")
def index():
    return render_template_string(PAGE, error=None, success=False,
                                  client_ip=request.remote_addr,
                                  username="", role="", vlan="")


@app.route("/auth", methods=["POST"])
def auth():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = request.remote_addr

    if not username or not password:
        return render_template_string(PAGE, error="Ingrese usuario y contraseña.",
                                      success=False, client_ip=client_ip,
                                      username="", role="", vlan="")

    role = radius_auth(username, password)
    if not role:
        return render_template_string(PAGE, error="Credenciales incorrectas.",
                                      success=False, client_ip=client_ip,
                                      username="", role="", vlan="")

    vlan_id = VLANS_POR_ROL.get(role, 100)
    mac = get_mac_from_onos(client_ip) or "00:00:00:00:00:00"

    print(f"[AUTH] {username} → {role} vlan={vlan_id} ip={client_ip} mac={mac}")

    try:
        resp = requests.post(M6_URL, json={
            "codigo_pucp": username,
            "nombre_rol":  role,
            "vlan_id":     vlan_id,
            "ip_asignada": client_ip,
            "mac_address": mac,
        }, timeout=10)
        print(f"[M6] {resp.status_code} {resp.text[:120]}")
    except Exception as e:
        print(f"[M6] Error: {e}")

    return render_template_string(PAGE, success=True, error=None,
                                  client_ip=client_ip, username=username,
                                  role=role, vlan=vlan_id)


if __name__ == "__main__":
    print("[Portal Web] http://192.168.100.2:80")
    app.run(host="0.0.0.0", port=80, debug=False)
