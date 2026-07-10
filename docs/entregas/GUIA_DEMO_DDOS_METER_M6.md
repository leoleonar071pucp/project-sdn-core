# Guia Demo: DDoS/Ruido De Puerto -> Meter Temporal En M6

Objetivo: demostrar que si un host genera demasiado trafico, M6 puede detectar el estres del puerto y aplicar un **meter temporal** en T0 del switch de borde para limitarlo.

Regla de seguridad: **no tocar `ens3`**. La prueba genera trafico desde H1 usando HTTP hacia el recurso Telecom.

## 1. Idea De La Demo

H1 genera muchas conexiones HTTP hacia:

```text
http://192.168.100.101:8001/
```

M6 observa los contadores de ONOS. Si el puerto de H1 supera el umbral, M6 instala una flow con meter en SW4 T0.

Resultado esperado:

```text
H1 genera mucho trafico
M6 detecta PPS alto: mas de 300 paquetes por segundo
SW4 instala flow priority=38900 con meter
El puerto queda limitado temporalmente a 50 pps
```

Valores usados en la demo:

```text
Umbral de deteccion: 300 pps
Accion aplicada: meter a 50 pps
Duracion del castigo: 300 segundos
Switch afectado: SW4
Puerto esperado para H1: port 1
```

## 2. Verificar Que M6 Esta Vivo

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Campos importantes:

```text
status: ok
network_actions_enabled: true
onos_reads_enabled: true
onos_writes_enabled: true
```

Para que esta demo aplique meter automaticamente, el estado ideal es:

```text
self_monitor.running: true
self_monitor.actions_enabled: true
self_monitor.threshold_pps: 300
self_monitor.meter_pps: 50
self_monitor.ttl_seconds: 300
```

Si `actions_enabled` aparece en `false`, M6 puede estar en modo observacion y no instalara el meter automaticamente.

## 3. Ver Que No Hay Meters Activos Antes

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
rate_limits: []
```

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 38900 || true
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4
```

Esperado:

```text
No aparece priority=38900
No hay meters activos
```

## 4. Ejecutar Ataque De Ruido Desde H1

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
```

Si el script existe:

```bash
/home/ubuntu/demo_ddos_curl.sh http://192.168.100.101:8001/ 20 40
```

Si no existe, crearlo:

```bash
cat > /home/ubuntu/demo_ddos_curl.sh <<'EOF'
#!/usr/bin/env bash
TARGET="${1:-http://192.168.100.101:8001/}"
DURATION="${2:-20}"
PARALLEL="${3:-40}"
end=$((SECONDS + DURATION))

while [ "$SECONDS" -lt "$end" ]; do
  for i in $(seq 1 "$PARALLEL"); do
    curl -s -o /dev/null --max-time 1 "$TARGET" &
  done
  wait
done
EOF

chmod +x /home/ubuntu/demo_ddos_curl.sh
/home/ubuntu/demo_ddos_curl.sh http://192.168.100.101:8001/ 20 40
```

Que hace el comando:

```text
Durante 20 segundos lanza lotes de 40 curls en paralelo.
Eso aumenta el PPS observado en el puerto de H1.
Si supera 300 pps, M6 instala un meter temporal.
```

## 5. Ver El Meter En M6

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
status: EXECUTED
device: of:00006a0757adfc4e
port: 1
src_ip: 192.168.100.55
rate_pps: 50
priority: 38900
```

Interpretacion:

```text
device of:00006a0757adfc4e = SW4
port 1 = puerto de H1 en SW4
rate_pps 50 = limite aplicado
priority 38900 = regla T0 de rate-limit
```

## 6. Ver El Meter En SW4

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 38900
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4
```

Esperado:

```text
priority=38900 ... actions=meter:ID,goto_table:1
meter=ID pktps rate=50 burst_size=100
```

Que significa:

```text
La flow T0 matchea el trafico del host ruidoso.
Antes de seguir al pipeline normal, pasa por un meter.
El meter limita la tasa de paquetes.
```

## 7. Quitar El Meter Manualmente

En AAA:

```bash
python3 - <<'PY'
import requests, json
headers = {'X-Security-Token': 'change-me'}
payload = {
    "device": "of:00006a0757adfc4e",
    "port": 1,
    "event": "port_traffic_stress"
}
r = requests.post(
    'http://127.0.0.1:8080/m6/security/rate-limit/remove',
    headers=headers,
    json=payload,
    timeout=8,
)
print(json.dumps(r.json(), indent=2))
PY
```

Confirmar que quedo limpio:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
rate_limits: []
```

En SW4:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 38900 || true
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4
```

Esperado:

```text
No queda priority=38900
No quedan meters activos
```

## 8. Como Funciona Por Detras

Flujo tecnico:

```text
H1 genera mucho trafico
  -> SW4 incrementa contadores de puerto/flows
  -> ONOS expone estadisticas
  -> M6 self-monitor lee estadisticas
  -> M6 detecta PPS alto en SW4 puerto 1
  -> M6 resuelve host/sesion asociada
  -> M6 instala meter OpenFlow en SW4
  -> SW4 limita el trafico antes de seguir al pipeline
```

Modulo principal:

```text
M6
```

Endpoints utiles:

```text
GET  /m6/security/rate-limits?active=1
POST /m6/security/rate-limit/remove
GET  /m6/status
```

Tipo de flow instalada:

```text
table=0
priority=38900
match: puerto/sesion/host ruidoso
action: meter:ID,goto_table:1
timeout: temporal
```

## 9. Frase Para Explicar En La Expo

```text
Esta mitigacion no depende de Suricata. M6 observa contadores de ONOS y, si un puerto de usuario genera demasiado trafico, instala un meter temporal en T0 del switch de borde. Asi reducimos la tasa del host ruidoso sin tumbar toda la red ni bloquear permanentemente al usuario.
```
