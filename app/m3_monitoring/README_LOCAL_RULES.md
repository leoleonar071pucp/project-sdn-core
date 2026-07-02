# M3 Suricata Local Rules

Este modulo es de observabilidad. Suricata genera alertas en M3; no reemplaza la politica de M6/ONOS/OVS ni instala flows de bloqueo.

## Estado Actual

- Mirror validado en SW4 hacia `gre_mon`.
- Para HTTP real, SW4 debe copiar ida y vuelta de los puertos de hosts:
  - `select_src_port = ens4, ens5, ens6`
  - `select_dst_port = ens4, ens5, ens6`
- H1 tiene `nmap` y `hping3` instalados para pruebas controladas.
- Evebox puede verse con tunel SSH:

```bash
ssh -L 8183:192.168.201.252:8181 ubuntu@10.20.11.32
```

Luego abrir:

```text
https://127.0.0.1:8183/
```

## Ver Alertas En M3

En la VM M3:

```bash
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
tail -f logs/eve.json | jq 'select(.event_type=="alert") | {timestamp, sid:.alert.signature_id, signature:.alert.signature, src_ip, dest_ip, dest_port}'
```

Si no tienes `jq`, usar:

```bash
grep '"event_type":"alert"' logs/eve.json | tail -20
```

## Reglas Probadas Y Comandos

Ejecutar estas pruebas desde H1 salvo que se indique otra cosa.

### 9000001 - TCP SYN Port Scan

Detecta reconocimiento tipo `nmap -sS`.

```bash
sudo nmap -sS -Pn --max-retries 0 --host-timeout 20s -p 1-40 192.168.100.101
```

Alternativa con `hping3`:

```bash
sudo hping3 -S -c 25 -i u100000 -p 9090 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO TCP SYN port scan
sid=9000001
```

### 9000008 - TCP XMAS Scan

Detecta paquetes TCP con flags `FIN+PSH+URG`.

```bash
sudo nmap -sX -Pn --max-retries 0 --host-timeout 20s -p 81,82,83 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO Nmap XMAS scan
sid=9000008
```

### 9000009 - TCP NULL Scan

Detecta paquetes TCP sin flags.

```bash
sudo nmap -sN -Pn --max-retries 0 --host-timeout 20s -p 84,85,86 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO Nmap NULL scan
sid=9000009
```

### 9000010 - TCP FIN Scan

Detecta paquetes TCP con flag `FIN`.

```bash
sudo nmap -sF -Pn --max-retries 0 --host-timeout 20s -p 87,88,89 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO Nmap FIN scan
sid=9000010
```

### 9000027 - SSH Connection Attempt Burst

Detecta varios intentos SYN hacia puerto `22`, aunque no haya servidor SSH real.

```bash
sudo hping3 -S -c 6 -i u100000 -p 22 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO SSH connection attempt burst
sid=9000027
```

### 9000028 - RDP Connection Attempt Burst

Detecta varios intentos SYN hacia puerto `3389`, aunque no haya servidor RDP real.

```bash
sudo hping3 -S -c 6 -i u100000 -p 3389 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO RDP connection attempt burst
sid=9000028
```

### 9000029 - FTP Connection Attempt Burst

Detecta varios intentos SYN hacia puerto `21`, aunque no haya servidor FTP real.

```bash
sudo hping3 -S -c 6 -i u100000 -p 21 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO FTP connection attempt burst
sid=9000029
```

### 9000018 - ICMP Grande

Detecta echo-request ICMP con payload grande.

```bash
ping -c 6 -s 700 192.168.100.101
```

Resultado esperado:

```text
SDN DEMO possible ICMP tunneling - large payload
sid=9000018
```

### 9000002 - SQL Injection En HTTP

Requiere HTTP real y sesion permitida hacia `192.168.100.101:8001`.

Primero loguear H1 como Telecom:

```bash
python3 cli.py
```

Credenciales:

```text
usuario: 20192434
password: pass_teleco123
```

Verificar que el recurso responde:

```bash
curl -m 5 -s -o /tmp/base_8001.html -w 'http=%{http_code}\n' http://192.168.100.101:8001/
```

Debe devolver:

```text
http=200
```

Disparar la regla:

```bash
curl -m 5 'http://192.168.100.101:8001/?id=1%27%20OR%20%271%27=%271'
```

Resultado esperado:

```text
SDN DEMO possible SQL injection
sid=9000002
url=/?id=1%27%20OR%20%271%27=%271
```

### 9000014 - Path Traversal

Requiere HTTP real y sesion permitida hacia `192.168.100.101:8001`.

Importante: usar `--path-as-is`, porque `curl` normaliza `../../` si no se indica.

```bash
curl --path-as-is -m 5 'http://192.168.100.101:8001/../../etc/passwd'
```

Resultado esperado:

```text
SDN DEMO path traversal attempt
sid=9000014
url=/../../etc/passwd
```

## Reglas Pendientes De Validacion Real

Estas reglas cargan en Suricata, pero requieren servicios reales o trafico que todavia no esta preparado en el laboratorio.

### 9000015 - DNS Tunneling

Detecta consultas DNS con nombres largos.

Comando sugerido cuando UDP/53 sea visible por el mirror:

```bash
python3 - <<'PY'
import socket, random
q = "a" * 60 + ".test.local"
msg = random.randrange(65536).to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for part in q.split("."):
    msg += bytes([len(part)]) + part.encode()
msg += b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg, ("8.8.8.8", 53))
print("dns query sent:", q)
PY
```

Resultado esperado si Suricata ve DNS:

```text
SDN DEMO possible DNS tunneling - long domain
sid=9000015
```

Nota: en pruebas anteriores no aparecio DNS en Suricata. Primero confirmar que UDP/53 pasa por el mirror.

### 9000013 - SSH Brute Force Established

Requiere un servidor SSH real aceptando conexiones en puerto `22`.

Comando sugerido cuando exista ese servicio:

```bash
for i in 1 2 3 4 5 6; do
  timeout 2 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password usuario_invalido@192.168.100.101 true
done
```

Resultado esperado:

```text
SDN DEMO SSH brute force attempt
sid=9000013
```

### 9000012 - RDP Brute Force Established

Requiere un servidor RDP real en puerto `3389`.

Comando orientativo, si existe cliente RDP:

```bash
xfreerdp /v:192.168.100.101 /u:test /p:wrong
```

Resultado esperado:

```text
SDN DEMO RDP brute force attempt
sid=9000012
```

### 9000026 - SSH Client Banner En Puerto No Estandar

Requiere un servicio TCP escuchando en un puerto diferente de `22`.

Ejemplo si existe un listener en `2222`:

```bash
python3 - <<'PY'
import socket
s = socket.create_connection(("192.168.100.101", 2222), timeout=3)
s.sendall(b"SSH-2.0-SDN-test\r\n")
s.close()
PY
```

Resultado esperado:

```text
SDN DEMO SSH on non-standard port
sid=9000026
```

### 9000037 - SSH Server Banner Desde Puerto No Estandar

Requiere un servidor que responda con banner `SSH-` desde un puerto distinto de `22`.

Ejemplo de cliente:

```bash
nc -v 192.168.100.101 2222
```

Resultado esperado:

```text
SDN DEMO SSH server banner from non-standard port
sid=9000037
```

### 9000024 - HTTP En Puerto Inesperado

Requiere un servidor HTTP real en un puerto no academico y no excluido, por ejemplo `9090`.

En la VM destino:

```bash
python3 -m http.server 9090
```

Desde H1:

```bash
curl -m 5 http://192.168.100.101:9090/
```

Resultado esperado:

```text
SDN DEMO HTTP on unexpected non-academic port
sid=9000024
```

### 9000036 - FTP STOR

Requiere un servidor FTP real aceptando conexiones y subida de archivos.

Comando orientativo desde H1:

```bash
ftp 192.168.100.101
```

Dentro del cliente FTP:

```text
put archivo_prueba.txt
```

Resultado esperado:

```text
SDN DEMO possible FTP exfiltration
sid=9000036
```

### 9000021 - ARP Spoofing

Estado: desactivada/comentada.

Motivo: esta version/configuracion de Suricata rechazo la firma ARP usada inicialmente. Para esta deteccion conviene usar checks de M6/ONOS sobre binding MAC/IP/puerto, o crear una regla ARP compatible y validarla aparte.

## Cargar Y Validar Reglas

En M3:

```bash
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
sudo docker exec suricata suricata -T -c /etc/suricata/suricata.yaml
sudo docker restart suricata
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'
```

Resultado esperado del test:

```text
rules successfully loaded
0 rules failed
```

## Seguridad Operativa Para Pruebas

- Probar desde un solo host a la vez.
- Usar pocos paquetes: rangos pequenos y `-c 6`, no floods largos.
- No usar `nmap -p-` ni escaneos agresivos.
- Verificar que no queden procesos:

```bash
ps -eo comm,args | egrep 'nmap|hping3' | grep -v egrep
```

- Verificar recursos:

```bash
df -h /
free -h
```

## Relacion Con M6

- Suricata ve paquetes y payloads.
- M6 conoce sesiones, MAC, IP, puerto fisico, rol y politica.
- Para respuesta automatica futura, lo ideal es correlacionar:
  - Suricata: escaneos, payloads web, tunneling, protocolos raros.
  - M6: `policy_denied`, spoofing MAC/IP, packet-in burst, acceso fuera de rol.
