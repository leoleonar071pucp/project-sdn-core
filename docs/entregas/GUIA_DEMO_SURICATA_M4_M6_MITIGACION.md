# Guia demo: Suricata -> M4 -> M6 -> mitigacion T0

Esta guia sirve para reproducir la demo frente a profesores y comprobar que la
cadena de deteccion y mitigacion funciona:

```text
H1/H2/H3 -> mirror SW4 -> Suricata/M3 -> event-forwarder -> M4 -> M6 -> ONOS -> T0
```

Estado esperado actual:

- M3/monitoring: Suricata, Evebox, M4 y event-forwarder corriendo.
- AAA/policies: M6 corriendo en `192.168.201.251:8080`.
- M4 corriendo en `192.168.201.252:8084`.
- El event-forwarder lee `eve.json` cada 10 segundos y envia solo `event_type=alert`.
- Las mitigaciones se instalan en T0 con `priority=39000`.

> Importante: usar pruebas pequenas. No ejecutar floods largos, `nmap -p-` ni
> escaneos agresivos durante la demo.

## 1. Prechecks

### 1.1 Ver servicios en monitoring

```bash
ssh -p 5852 ubuntu@10.20.11.32
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -sS --max-time 5 http://127.0.0.1:8084/health | python3 -m json.tool
```

Debe verse:

```text
suricata
evebox
m4-security
event-forwarder
```

En `/health`, M4 debe tener:

```text
status=ok
automatic_actions_enabled=true
```

### 1.2 Ver M6 en AAA

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/mitigations?active=1' | python3 -m json.tool
```

Esperado antes de empezar:

```text
status=ok
sesiones_activas={}
mitigations=[]
```

### 1.3 Ver alertas Suricata en vivo

En monitoring:

```bash
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
tail -f logs/eve.json | grep --line-buffered '"event_type":"alert"'
```

Tambien se puede abrir Evebox desde la PC local:

```bash
ssh -L 8183:192.168.201.252:8181 -p 5852 ubuntu@10.20.11.32
```

Luego abrir:

```text
https://127.0.0.1:8183/
```

## 2. Login de host para pruebas

La demo mas simple usa H1 como Telecom, porque tiene acceso normal a
`192.168.100.101:8001`.

Credenciales disponibles para la demo:

| Usuario | Password | Rol esperado | Uso recomendado |
|---|---|---|---|
| `20192434` | `pass_teleco123` | Telecom | Demo principal con H1 y curso Telecom `8001` |
| `20200101` | `pass_info123` | Informatica | Validar curso Info `8002` |
| `20200202` | `pass_electro123` | Electronica | Validar curso Electro `8003` |
| `DOBLE_TELECO_INFO` | `pass_doble123` | Doble carrera Telecom + Informatica | Validar permiso normal y excepcion |
| `JP_ELECTRO_TELECO` | `pass_jpteleco123` | JP / Electronica + Telecom | Validar excepciones T3 |

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
ip -br addr
curl -sS --max-time 20 -X POST http://192.168.100.110:8282/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"usuario":"20192434","password":"pass_teleco123"}' \
  | tee /tmp/h1_login.json | python3 -m json.tool

curl -sS --max-time 8 -o /dev/null \
  -w 'before=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
ok=true
ip_asignada=192.168.100.55
mac=FA:16:3E:5A:AA:4A
before=200 exit=0
```

## 3. Reglas principales para demo

| SID | Que detecta | Comando que activa la regla desde H1 | Mitigacion que aplica M6 | Que queda bloqueado despues |
|---:|---|---|---|---|
| `9000002` | SQL injection HTTP contra curso Telecom | `curl --path-as-is -m 8 'http://192.168.100.101:8001/?id=2%27%20OR%20%272%27=%272'` | `block_tcp_to_dest_port`, TTL `900s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101`, `tcp_dst=8001` | Cualquier nuevo TCP del host hacia `192.168.100.101:8001` |
| `9000014` | Path traversal HTTP contra curso Telecom | `curl --path-as-is -m 8 'http://192.168.100.101:8001/../../etc/passwd'` | `block_tcp_to_dest_port`, TTL `900s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101`, `tcp_dst=8001` | Cualquier nuevo TCP del host hacia `192.168.100.101:8001` |
| `9000001` | TCP SYN scan | `sudo nmap -sS -Pn --max-retries 0 --host-timeout 20s -p 1-40 192.168.100.101` | `block_tcp_to_dest`, TTL `300s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101` | Todo TCP del host hacia `192.168.100.101`, no solo los puertos escaneados |
| `9000008` | XMAS scan | `sudo nmap -sX -Pn --max-retries 0 --host-timeout 20s -p 81,82,83 192.168.100.101` | `block_tcp_to_dest`, TTL `300s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101` | Todo TCP del host hacia `192.168.100.101` |
| `9000009` | NULL scan | `sudo nmap -sN -Pn --max-retries 0 --host-timeout 20s -p 84,85,86 192.168.100.101` | `block_tcp_to_dest`, TTL `300s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101` | Todo TCP del host hacia `192.168.100.101` |
| `9000010` | FIN scan | `sudo nmap -sF -Pn --max-retries 0 --host-timeout 20s -p 87,88,89 192.168.100.101` | `block_tcp_to_dest`, TTL `300s`: drop T0 `tcp`, `src_ip=host`, `dst_ip=192.168.100.101` | Todo TCP del host hacia `192.168.100.101` |
| `9000027` | Intentos/burst SSH | `sudo hping3 -S -c 6 -i u100000 -p 22 192.168.100.101` | `block_tcp_port`, TTL `600s`: drop T0 `tcp`, `src_ip=host`, `tcp_dst=22` | SSH del host hacia cualquier destino |
| `9000028` | Intentos/burst RDP | `sudo hping3 -S -c 6 -i u100000 -p 3389 192.168.100.101` | `block_tcp_port`, TTL `600s`: drop T0 `tcp`, `src_ip=host`, `tcp_dst=3389` | RDP del host hacia cualquier destino |
| `9000029` | Intentos/burst FTP | `sudo hping3 -S -c 6 -i u100000 -p 21 192.168.100.101` | `block_tcp_port`, TTL `600s`: drop T0 `tcp`, `src_ip=host`, `tcp_dst=21` | FTP del host hacia cualquier destino |
| `9000018` | ICMP con payload grande | `ping -c 6 -s 700 192.168.100.101` | `block_icmp`, TTL `600s`: drop T0 `icmp`, `src_ip=host` | Ping/ICMP saliente del host |

La columna `Login` separa deteccion de mitigacion:

- Sin login, Suricata puede alertar si el paquete llega al mirror, pero M6 no
  castiga porque no puede resolver `src_ip -> MAC/switch/puerto`.
- Con login, M6 encuentra la sesion activa y puede instalar el drop T0.

Para la demo principal se recomienda usar `9000002`, porque ya fue validada de
extremo a extremo con H1.

## 4. Pruebas copiables de mitigacion

Estas pruebas se ejecutan desde H1 despues de iniciar sesion como Telecom. Para
que M6 pueda castigar, debe existir una sesion activa para `192.168.100.55`.

### 4.1 SQL injection HTTP - `sid=9000002`

Descripcion: simula una consulta HTTP con payload SQLi. Se activa porque
Suricata detecta una cadena tipo `' OR '2'='2` en la URL.

Antes del ataque, el curso Telecom debe responder:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'before_sql=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
before_sql=200 exit=0
```

Activar la regla:

```bash
curl --path-as-is -m 8 \
  'http://192.168.100.101:8001/?id=2%27%20OR%20%272%27=%272'
```

Mitigacion esperada:

```text
sid=9000002
mitigation_action=block_tcp_to_dest_port
TTL=900s
drop T0: tcp + src_ip=192.168.100.55 + dst_ip=192.168.100.101 + tcp_dst=8001
```

Comandos que ya no deberian funcionar mientras dure el castigo:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'blocked_sql_same_port=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/ || true
```

Esperado:

```text
blocked_sql_same_port=000 exit=28
```

### 4.2 Path traversal HTTP - `sid=9000014`

Descripcion: simula un intento de leer `/etc/passwd` usando `../`. Aunque nginx
responda `400 Bad Request`, Suricata igual ve la URL y dispara la regla.

Antes del ataque:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'before_traversal=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Activar la regla:

```bash
curl --path-as-is -m 8 \
  'http://192.168.100.101:8001/../../etc/passwd'
```

Mitigacion esperada:

```text
sid=9000014
mitigation_action=block_tcp_to_dest_port
TTL=900s
drop T0: tcp + src_ip=192.168.100.55 + dst_ip=192.168.100.101 + tcp_dst=8001
```

Comandos que ya no deberian funcionar:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'blocked_traversal_same_port=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/ || true
```

Esperado:

```text
blocked_traversal_same_port=000 exit=28
```

### 4.3 TCP SYN scan - `sid=9000001`

Descripcion: simula reconocimiento de puertos. Se activa porque el host genera
SYNs hacia varios puertos de un mismo destino.

Activar la regla:

```bash
sudo nmap -sS -Pn --max-retries 0 --host-timeout 20s \
  -p 1-40 192.168.100.101
```

Mitigacion esperada:

```text
sid=9000001
mitigation_action=block_tcp_to_dest
TTL=300s
drop T0: tcp + src_ip=192.168.100.55 + dst_ip=192.168.100.101
```

Comandos que ya no deberian funcionar:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'blocked_scan_http=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/ || true
```

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'blocked_scan_https=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:1443/ || true
```

Esperado:

```text
blocked_scan_http=000 exit=28
blocked_scan_https=000 exit=28
```

### 4.4 XMAS, NULL y FIN scans - `sid=9000008/9000009/9000010`

Descripcion: variantes de escaneo TCP con flags inusuales. La mitigacion es la
misma que para SYN scan: bloquear TCP hacia el destino completo.

Activar XMAS:

```bash
sudo nmap -sX -Pn --max-retries 0 --host-timeout 20s \
  -p 81,82,83 192.168.100.101
```

Activar NULL:

```bash
sudo nmap -sN -Pn --max-retries 0 --host-timeout 20s \
  -p 84,85,86 192.168.100.101
```

Activar FIN:

```bash
sudo nmap -sF -Pn --max-retries 0 --host-timeout 20s \
  -p 87,88,89 192.168.100.101
```

Mitigacion esperada:

```text
sid=9000008 o 9000009 o 9000010
mitigation_action=block_tcp_to_dest
TTL=300s
drop T0: tcp + src_ip=192.168.100.55 + dst_ip=192.168.100.101
```

Comando que ya no deberia funcionar:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'blocked_tcp_dest=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/ || true
```

Esperado:

```text
blocked_tcp_dest=000 exit=28
```

### 4.5 SSH/RDP/FTP bursts - `sid=9000027/9000028/9000029`

Descripcion: simula intentos repetidos a puertos administrativos o de servicio.
La mitigacion bloquea ese puerto TCP para el host atacante, hacia cualquier
destino.

Activar SSH:

```bash
sudo hping3 -S -c 6 -i u100000 -p 22 192.168.100.101
```

Luego SSH ya no deberia salir desde H1:

```bash
nc -vz -w 3 192.168.100.101 22 || true
```

Activar RDP:

```bash
sudo hping3 -S -c 6 -i u100000 -p 3389 192.168.100.101
```

Luego RDP ya no deberia salir desde H1:

```bash
nc -vz -w 3 192.168.100.101 3389 || true
```

Activar FTP:

```bash
sudo hping3 -S -c 6 -i u100000 -p 21 192.168.100.101
```

Luego FTP ya no deberia salir desde H1:

```bash
nc -vz -w 3 192.168.100.101 21 || true
```

Mitigacion esperada:

```text
sid=9000027 -> block_tcp_port tcp_dst=22
sid=9000028 -> block_tcp_port tcp_dst=3389
sid=9000029 -> block_tcp_port tcp_dst=21
TTL=600s
drop T0: tcp + src_ip=192.168.100.55 + tcp_dst=PUERTO
```

### 4.6 ICMP grande - `sid=9000018`

Descripcion: simula ICMP anomalo con payload grande. La mitigacion bloquea ICMP
saliente del host atacante.

Antes:

```bash
ping -c 2 192.168.100.101
```

Activar la regla:

```bash
ping -c 6 -s 700 192.168.100.101
```

Mitigacion esperada:

```text
sid=9000018
mitigation_action=block_icmp
TTL=600s
drop T0: icmp + src_ip=192.168.100.55
```

Comando que ya no deberia funcionar:

```bash
ping -c 2 192.168.100.101
```

Esperado:

```text
100% packet loss
```

## 5. Ver que la regla se activo

### 5.1 En Suricata

En monitoring:

```bash
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
grep '"event_type":"alert"' logs/eve.json | tail -5
```

Buscar estos campos:

```text
signature_id
signature
src_ip
dest_ip
dest_port
```

Ejemplo esperado para SQLi:

```text
signature_id=9000002
signature="SDN DEMO possible SQL injection"
src_ip="192.168.100.55"
dest_ip="192.168.100.101"
dest_port=8001
```

### 5.2 En el forwarder

En monitoring:

```bash
sudo docker logs --tail 40 event-forwarder
```

Esperado cuando llega una alerta nueva:

```text
{"processed": ..., "forwarded": 1, ...}
```

### 5.3 En M4

En monitoring:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8084/m4/incidents | python3 -m json.tool
```

Buscar:

```text
src_ip=192.168.100.55
threat_type=web_attack
recommended_action=TEMP_BLOCK
action_history.status=EXECUTED
```

### 5.4 En M6

Desde cualquier VM con acceso a `192.168.201.251`:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://192.168.201.251:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Ejemplo esperado:

```text
active=true
sid=9000002
mitigation_action=block_tcp_to_dest_port
switch_dpid=of:00006a0757adfc4e
priority=39000
tableId=0
src_ip=192.168.100.55
dst_ip=192.168.100.101
tcpPort=8001
```

### 5.5 En el switch SW4

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 'priority=39000'
```

Debe aparecer un drop similar a:

```text
priority=39000,tcp,in_port=ens4,dl_src=fa:16:3e:5a:aa:4a,nw_src=192.168.100.55,nw_dst=192.168.100.101,tp_dst=8001 actions=drop
```

## 6. Ver que el castigo funciona

Desde H1, despues de disparar `9000002`:

```bash
curl -sS --max-time 5 -o /dev/null \
  -w 'during=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/ || true
```

Esperado:

```text
during=000 exit=28
```

Eso significa timeout por drop.

## 7. Quitar mitigaciones

### 7.1 Quitar una mitigacion especifica

Primero obtener el `incident_id`:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://192.168.201.251:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Luego ejecutar:

```bash
INCIDENT_ID="PEGAR_INCIDENT_ID_AQUI"

curl -sS --max-time 8 -H 'Content-Type: application/json' \
  -H 'X-Security-Token: change-me' \
  -d "{\"incident_id\":\"$INCIDENT_ID\"}" \
  http://192.168.201.251:8080/m6/security/unmitigate \
  | python3 -m json.tool
```

Esperado:

```text
ok=true
status=EXECUTED
```

Confirmar que ya no hay mitigaciones activas:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://192.168.201.251:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
mitigations=[]
```

### 7.2 Verificar que el recurso vuelve

Desde H1:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'after_unmitigate=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
after_unmitigate=200 exit=0
```

## 8. Logout y limpieza al terminar

Desde H1, usando el JSON guardado del login:

```bash
python3 - <<'PY' >/tmp/h1_logout.json
import json
j=json.load(open('/tmp/h1_login.json'))
print(json.dumps({
  "mac": j["mac"],
  "id_usuario": j["id_usuario"],
  "codigo_pucp": j["codigo_pucp"],
  "ip_asignada": j["ip_asignada"],
  "es_visitante": False,
}))
PY

curl -sS --max-time 12 -X POST http://192.168.100.110:8282/auth/logout \
  -H 'Content-Type: application/json' \
  -d @/tmp/h1_logout.json | python3 -m json.tool
```

Confirmar M6 limpio:

```bash
curl -sS --max-time 8 http://192.168.201.251:8080/m6/status \
  | python3 -m json.tool | grep -E 'status|sesiones_activas'

curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://192.168.201.251:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
status=ok
sesiones_activas={}
mitigations=[]
```

## 9. Reglas que requieren servicios adicionales

Estas reglas estan cargadas, pero para demostrarlas bien se necesita un servicio
real o trafico adicional:

| SID | Regla | Requisito |
|---:|---|---|
| `9000013` | SSH brute force established | Servidor SSH real aceptando TCP/22 |
| `9000012` | RDP brute force established | Servidor RDP real TCP/3389 |
| `9000015` | DNS tunneling | Que UDP/53 sea visible por el mirror |
| `9000026` | SSH client banner puerto no estandar | Listener TCP en puerto no 22 |
| `9000037` | SSH server banner puerto no estandar | Servidor que responda `SSH-` en puerto no 22 |
| `9000024` | HTTP puerto inesperado | Servidor HTTP en puerto no academico, por ejemplo 9090 |
| `9000036` | FTP STOR/exfiltration | Servidor FTP real con subida |
| `9000021` | ARP spoofing | Desactivada; Suricata rechazo la firma ARP en esta configuracion |

## 10. Salud y seguridad durante demo

### Monitoring

```bash
ssh -p 5852 ubuntu@10.20.11.32
free -h
df -h /
ps -eo pid,cmd,%mem,%cpu --sort=-%cpu | head -12
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

Nota: Suricata puede aparecer cerca de `100% CPU` porque corre con DPDK y hace
polling activo de un core. En la ultima validacion la VM tenia 4 cores, RAM
disponible y `drops=0` en Suricata.

### M6 / AAA

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
curl -s -u onos:rocks --max-time 12 \
  http://192.168.201.200:8181/onos/v1/flows | grep -c 'OUTPUT.*NORMAL'
```

Esperado:

```text
OUTPUT NORMAL = 0
```

## 11. Resumen de demo recomendada

1. Mostrar servicios:
   ```bash
   sudo docker ps
   curl http://127.0.0.1:8084/health
   ```
2. Loguear H1 como Telecom.
3. Probar `8001` y ver `200`.
4. Ejecutar SQLi `sid=9000002`.
5. Ver alerta en `eve.json`.
6. Ver incidente en M4.
7. Ver mitigacion activa en M6.
8. Ver drop T0 en SW4.
9. Probar `8001` y ver timeout.
10. Ejecutar `unmitigate`.
11. Probar `8001` y ver `200`.
12. Logout y confirmar `sesiones_activas={}`.


