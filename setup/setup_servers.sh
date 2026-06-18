#!/bin/bash
# setup_servers.sh — HTTP + HTTPS con contenido diferenciado en srv1 y srv2
# DONDE ejecutar: una vez en srv1 (puerto 5821), otra vez en srv2 (puerto 5822)
#   bash setup/setup_servers.sh

# Detectar IP local del servidor (interfaz ens4 o ens3)
MY_IP=$(ip addr show ens4 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$MY_IP" ] && MY_IP=$(ip addr show ens3 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$MY_IP" ] && MY_IP=$(hostname -I | awk '{print $1}')

echo "Servidor: $MY_IP"

# Determinar si es srv1 (192.168.100.101) o srv2 (192.168.100.102)
if echo "$MY_IP" | grep -q "\.101$"; then
    NOMBRE="Cursos Telecomunicaciones"
    COLOR="#003366"
    SERVER="srv1 (recursos_academicos)"
elif echo "$MY_IP" | grep -q "\.102$"; then
    NOMBRE="Sistema de Notas"
    COLOR="#006633"
    SERVER="srv2 (sistema_notas)"
else
    echo "[!] IP no reconocida: $MY_IP — usando defaults"
    NOMBRE="Servidor SDN"
    COLOR="#333333"
    SERVER="desconocido"
fi

echo "Configurando: $SERVER — $NOMBRE"

# ── HTTP (puerto 80) ─────────────────────────────────────────────────────────
mkdir -p /tmp/www
cat > /tmp/www/index.html <<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>$NOMBRE</title>
  <style>
    body { background: $COLOR; color: white; font-family: Arial, sans-serif;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; }
    h1   { font-size: 2em; text-align: center; }
    p    { text-align: center; }
  </style>
</head>
<body>
  <div>
    <h1>$NOMBRE</h1>
    <p>Servidor: $MY_IP | Protocolo: HTTP</p>
    <p>Sistema SDN Zero Trust — PUCP TEL354</p>
  </div>
</body>
</html>
HTML

pkill -f "http.server 80" 2>/dev/null || true
cd /tmp/www && nohup python3 -m http.server 80 > /tmp/http.log 2>&1 &
echo "  HTTP: PID $! — puerto 80"

# ── HTTPS (puerto 443) ────────────────────────────────────────────────────────
mkdir -p /tmp/www-ssl
cat > /tmp/www-ssl/index.html <<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>$NOMBRE — HTTPS</title>
  <style>
    body { background: $COLOR; color: white; font-family: Arial, sans-serif;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; }
    h1   { font-size: 2em; text-align: center; }
    .badge { background: rgba(255,255,255,0.2); padding: 8px 16px;
             border-radius: 4px; margin-top: 12px; display: inline-block; }
    p    { text-align: center; }
  </style>
</head>
<body>
  <div>
    <h1>$NOMBRE</h1>
    <p><span class="badge">Conexión HTTPS activa</span></p>
    <p>Servidor: $MY_IP | Protocolo: HTTPS/TLS</p>
    <p>Sistema SDN Zero Trust — PUCP TEL354</p>
  </div>
</body>
</html>
HTML

# Certificado autofirmado para HTTPS
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
    -days 365 -nodes -subj "/CN=$MY_IP" 2>/dev/null
echo "  Certificado generado para CN=$MY_IP"

# Servidor HTTPS
cat > /tmp/https_server.py <<'PYSSL'
import http.server, ssl, os
os.chdir('/tmp/www-ssl')
httpd = http.server.HTTPServer(('', 443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("HTTPS servidor en puerto 443")
httpd.serve_forever()
PYSSL

pkill -f "https_server.py" 2>/dev/null || true
nohup python3 /tmp/https_server.py > /tmp/https.log 2>&1 &
echo "  HTTPS: PID $! — puerto 443"

echo ""
echo "=== $SERVER listo ==="
echo "  HTTP:  http://$MY_IP/"
echo "  HTTPS: https://$MY_IP/"
echo "  Logs: /tmp/http.log  /tmp/https.log"
