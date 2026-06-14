#!/bin/bash
# install_flows_vnrt.sh
# Instala reglas T1 (cuarentena) y T2 (políticas proactivas) en el slice VNRT.
# Ejecutar en la VM Controller (192.168.200.200) desde el directorio home.
# TEL354 Grupo 2 — M6 Traductor

set -e

# ── PARÁMETROS DEL SLICE ──────────────────────────────────────────────────────
ONOS="http://127.0.0.1:8181"
AUTH="onos:rocks"

SW1="of:00005ec76ec6114c"   # troncal
SW2="of:000072e0807e854c"   # acceso hosts   (H1 en puerto 2)
SW3="of:0000f220f9454c4e"   # acceso servidores (servidor en puerto 2)

# IPs de destino (según CLAUDE_VNRT.md — VNRT real)
SERVER_CURSOS="192.168.100.200"   # H3: servidor cursos (IP fija)
SERVER_NOTAS="192.168.100.201"    # H4: servidor notas  (IP fija)
PORTAL_IP="10.0.0.10"            # Portal cautivo / Auth VM

# Puertos de acceso en SW2 donde se conectan hosts clientes
SW2_ACCESS_PORTS=(2 3)

# Puertos de acceso en SW3 donde se conectan servidores
SW3_ACCESS_PORTS=(2 3)

# ── HELPERS ───────────────────────────────────────────────────────────────────
post_flow() {
    local dpid="$1"
    local body="$2"
    local resp
    resp=$(curl -s -w "\n%{http_code}" -u "$AUTH" -X POST \
         -H "Content-Type: application/json" \
         -d "$body" \
         "$ONOS/onos/v1/flows/$dpid")
    local code
    code=$(echo "$resp" | tail -1)
    local out
    out=$(echo "$resp" | head -1)
    if [[ "$code" == "201" || "$code" == "200" ]]; then
        echo "    ✓ flow instalado (HTTP $code)"
    else
        echo "    ✗ ERROR HTTP $code: $out"
    fi
}

check_onos() {
    echo "Verificando conexión con ONOS..."
    if curl -s -u "$AUTH" "$ONOS/onos/v1/devices" > /dev/null; then
        echo "✓ ONOS responde en $ONOS"
    else
        echo "✗ No se puede conectar a ONOS en $ONOS"
        echo "  Verifica que ONOS esté corriendo: ps aux | grep onos"
        exit 1
    fi
}

# ── T1: REGLAS DE CUARENTENA (VLAN 90) ───────────────────────────────────────
# Instala 3 reglas en cada puerto de acceso de un switch:
#   1. Push VLAN 90 a paquetes sin tag (prio 10)
#   2. Forward DHCP a controller (prio 500)
#   3. DROP todo lo demás en VLAN 90 (prio 5)
# NOTA ONOS: DROP = treatment con instructions vacías (NO "type":"DROP" — da error 400)

install_t1_quarantine() {
    local dpid="$1"
    local port="$2"
    local label="$3"

    echo "  T1 PUSH VLAN 90 — $label puerto $port"
    post_flow "$dpid" '{
      "priority": 10,
      "isPermanent": true,
      "tableId": 1,
      "deviceId": "'"$dpid"'",
      "selector": {"criteria": [
        {"type": "IN_PORT",  "port": '"$port"'},
        {"type": "ETH_TYPE", "ethType": "0x0800"}
      ]},
      "treatment": {"instructions": [
        {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
        {"type": "L2MODIFICATION", "subtype": "VLAN_ID", "vlanId": 90},
        {"type": "OUTPUT", "port": "NORMAL"}
      ]}
    }'

    echo "  T1 DHCP  VLAN 90 → CONTROLLER — $label puerto $port"
    post_flow "$dpid" '{
      "priority": 500,
      "isPermanent": true,
      "tableId": 1,
      "deviceId": "'"$dpid"'",
      "selector": {"criteria": [
        {"type": "VLAN_VID", "vlanId": 90},
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": 17},
        {"type": "UDP_DST",  "udpPort": 67}
      ]},
      "treatment": {"instructions": [
        {"type": "OUTPUT", "port": "CONTROLLER"}
      ]}
    }'

    # Portal cautivo: TCP (sin filtro de puerto — cubre 22/80/443)
    # Solo si el portal es alcanzable en el plano de datos
    echo "  T1 PORTAL VLAN 90 + TCP → portal ($PORTAL_IP) — $label puerto $port"
    post_flow "$dpid" '{
      "priority": 100,
      "isPermanent": true,
      "tableId": 1,
      "deviceId": "'"$dpid"'",
      "selector": {"criteria": [
        {"type": "VLAN_VID",  "vlanId": 90},
        {"type": "ETH_TYPE",  "ethType": "0x0800"},
        {"type": "IP_PROTO",  "protocol": 6},
        {"type": "IPV4_DST",  "ip": "'"$PORTAL_IP"'/32"}
      ]},
      "treatment": {"instructions": [
        {"type": "OUTPUT", "port": "NORMAL"}
      ]}
    }'

    # DROP implícito: VLAN 90 + cualquier otra cosa (prio 5, menor que DHCP y portal)
    echo "  T1 DROP  VLAN 90 resto — $label puerto $port"
    post_flow "$dpid" '{
      "priority": 5,
      "isPermanent": true,
      "tableId": 1,
      "deviceId": "'"$dpid"'",
      "selector": {"criteria": [
        {"type": "VLAN_VID", "vlanId": 90}
      ]},
      "treatment": {"clearDeferred": true, "instructions": []}
    }'
}

# ── T2: REGLAS PROACTIVAS ALLOW POR VLAN → SERVIDOR ─────────────────────────
# ONOS requiere un puerto TCP por regla (no se puede hacer 80,443 en una sola).
# Se instalan en el switch de acceso del cliente (SW2).
# OUTPUT: NORMAL → OVS/ONOS rutea al destino usando forwarding L2.

install_t2_allow() {
    local dpid="$1"
    local vlan="$2"
    local ip_dst="$3"
    local label="$4"

    for tcp_port in 80 443; do
        echo "  T2 ALLOW VLAN $vlan → $ip_dst TCP $tcp_port ($label)"
        post_flow "$dpid" '{
          "priority": 100,
          "isPermanent": true,
          "tableId": 2,
          "deviceId": "'"$dpid"'",
          "selector": {"criteria": [
            {"type": "VLAN_VID",  "vlanId": '"$vlan"'},
            {"type": "ETH_TYPE",  "ethType": "0x0800"},
            {"type": "IP_PROTO",  "protocol": 6},
            {"type": "IPV4_DST",  "ip": "'"$ip_dst"'/32"},
            {"type": "TCP_DST",   "tcpPort": '"$tcp_port"'}
          ]},
          "treatment": {"instructions": [
            {"type": "OUTPUT", "port": "NORMAL"}
          ]}
        }'
    done
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
check_onos

echo ""
echo "══════════════════════════════════════════════════════"
echo "  PASO 1: Reglas T1 cuarentena en SW2 (hosts)"
echo "══════════════════════════════════════════════════════"
for p in "${SW2_ACCESS_PORTS[@]}"; do
    install_t1_quarantine "$SW2" "$p" "SW2"
    echo ""
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "  PASO 2: Reglas T1 cuarentena en SW3 (servidores)"
echo "══════════════════════════════════════════════════════"
for p in "${SW3_ACCESS_PORTS[@]}"; do
    install_t1_quarantine "$SW3" "$p" "SW3"
    echo ""
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "  PASO 3: Reglas T2 proactivas ALLOW por VLAN (en SW2)"
echo "══════════════════════════════════════════════════════"

# Estudiante_Telecom (210) → servidor cursos
install_t2_allow "$SW2" 210 "$SERVER_CURSOS" "Est.Telecom→cursos"
echo ""

# Estudiante_Informatica (220) → servidor cursos
install_t2_allow "$SW2" 220 "$SERVER_CURSOS" "Est.Informatica→cursos"
echo ""

# Estudiante_Electronica (230) → servidor cursos
install_t2_allow "$SW2" 230 "$SERVER_CURSOS" "Est.Electronica→cursos"
echo ""

# Docente (300) → cursos + notas
install_t2_allow "$SW2" 300 "$SERVER_CURSOS" "Docente→cursos"
install_t2_allow "$SW2" 300 "$SERVER_NOTAS"  "Docente→notas"
echo ""

# Admin TI (400) → cursos + notas
install_t2_allow "$SW2" 400 "$SERVER_CURSOS" "AdminTI→cursos"
install_t2_allow "$SW2" 400 "$SERVER_NOTAS"  "AdminTI→notas"
echo ""

# Instalar también en SW3 (servidor recibe del trunk, necesita salida correcta)
install_t2_allow "$SW3" 210 "$SERVER_CURSOS" "SW3 Est.Telecom→cursos"
install_t2_allow "$SW3" 220 "$SERVER_CURSOS" "SW3 Est.Informatica→cursos"
install_t2_allow "$SW3" 230 "$SERVER_CURSOS" "SW3 Est.Electronica→cursos"
install_t2_allow "$SW3" 300 "$SERVER_CURSOS" "SW3 Docente→cursos"
install_t2_allow "$SW3" 300 "$SERVER_NOTAS"  "SW3 Docente→notas"
install_t2_allow "$SW3" 400 "$SERVER_CURSOS" "SW3 AdminTI→cursos"
install_t2_allow "$SW3" 400 "$SERVER_NOTAS"  "SW3 AdminTI→notas"
echo ""

echo ""
echo "══════════════════════════════════════════════════════"
echo "  VERIFICACIÓN"
echo "══════════════════════════════════════════════════════"
for dpid in "$SW1" "$SW2" "$SW3"; do
    count=$(curl -s -u "$AUTH" "$ONOS/onos/v1/flows/$dpid" | \
            python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('flows',[])))" 2>/dev/null || echo "?")
    echo "  $dpid → $count flows"
done

echo ""
echo "✓ Flows instalados. Verificar con:"
echo "  curl -u onos:rocks http://127.0.0.1:8181/onos/v1/flows/$SW2 | python3 -m json.tool"
echo ""
echo "Para borrar todos los flows de un switch (reset):"
echo "  curl -u onos:rocks -X DELETE http://127.0.0.1:8181/onos/v1/flows/$SW2"
