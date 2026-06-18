#!/bin/bash
# setup_onos_dhcp.sh — Configura apps y pool DHCP en ONOS via REST API
# DONDE ejecutar: en VM-Controller (donde ONOS está en 127.0.0.1:8181)
#   bash setup/setup_onos_dhcp.sh
#
# Qué hace:
#   1. Verifica y activa apps necesarias (openflow, dhcp, lldp, hostprovider)
#   2. Configura pool DHCP 192.168.100.10–30 via POST al API de ONOS
#   3. Muestra switches y hosts descubiertos
#   4. Explica cómo agregar mapeos estáticos MAC→IP por Karaf CLI

ONOS="http://127.0.0.1:8181"
AUTH="onos:rocks"

echo "=== Verificando ONOS ==="
curl -sf -u $AUTH $ONOS/onos/v1/devices > /dev/null || {
    echo "[ERROR] ONOS no responde en $ONOS — ¿está ONOS corriendo?"
    exit 1
}
echo "  ONOS accesible"

echo ""
echo "=== Activando apps necesarias ==="
for APP in \
    "org.onosproject.openflow" \
    "org.onosproject.lldpprovider" \
    "org.onosproject.hostprovider" \
    "org.onosproject.dhcp"; do

    STATE=$(curl -sf -u $AUTH "$ONOS/onos/v1/applications/$APP" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('state','?'))" 2>/dev/null \
        || echo "UNKNOWN")

    if [ "$STATE" != "ACTIVE" ]; then
        curl -sf -u $AUTH -X POST "$ONOS/onos/v1/applications/$APP/active" > /dev/null
        echo "  $APP → ACTIVADA"
    else
        echo "  $APP → ya ACTIVE"
    fi
done

echo ""
echo "=== Configurando pool DHCP via REST API ==="
# POST al endpoint de configuración de la app DHCP de ONOS
# ONOS actúa como servidor DHCP: intercepta DHCP Discover via OpenFlow PACKET_IN,
# construye DHCP Offer con esta config, lo inyecta como PACKET_OUT.
# El 'ip' es el IP del servidor DHCP que aparece en el offer.
# El 'mac' es la MAC fuente del DHCP Reply (ficticia, no importa mucho).
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -u $AUTH \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "dhcp": {
            "ip":        "192.168.100.2",
            "mac":       "2A:00:00:00:00:01",
            "subnet":    "255.255.255.0",
            "broadcast": "192.168.100.255",
            "router":    "192.168.100.2",
            "domain":    "sdn.pucp",
            "ttl":       "63",
            "lease":     "600",
            "renew":     "300",
            "rebind":    "500",
            "startip":   "192.168.100.10",
            "endip":     "192.168.100.30"
        }
    }' \
    "$ONOS/onos/v1/network/configuration/apps/org.onosproject.dhcp")
echo "  HTTP $HTTP — pool 192.168.100.10–30 (router: 192.168.100.2)"

echo ""
echo "=== Switches conectados ==="
curl -sf -u $AUTH $ONOS/onos/v1/devices | python3 -c "
import json, sys
for d in json.load(sys.stdin)['devices']:
    print(f'  {d[\"id\"]}  available:{d[\"available\"]}')
"

echo ""
echo "=== Hosts descubiertos ==="
curl -sf -u $AUTH $ONOS/onos/v1/hosts | python3 -c "
import json, sys
hosts = json.load(sys.stdin)['hosts']
if not hosts:
    print('  (ninguno — conectar hosts y esperar DHCP Discover o tráfico ARP)')
for h in hosts:
    loc = h.get('locations', [{}])[0]
    print(f'  {h[\"mac\"]}  IP:{h.get(\"ipAddresses\",[])}  '
          f'sw:{loc.get(\"elementId\",\"?\")[-4:]} port:{loc.get(\"port\",\"?\")}')
"

echo ""
echo "=== Mapeos estáticos (una vez conocidos los MACs) ==="
echo "Karaf CLI: ssh -p 8101 karaf@localhost  (password: karaf)"
echo "  dhcp-set-static-mapping <MAC_H1> 192.168.100.10"
echo "  dhcp-set-static-mapping <MAC_H2> 192.168.100.11"
echo "  dhcp-set-static-mapping <MAC_H3> 192.168.100.12"
