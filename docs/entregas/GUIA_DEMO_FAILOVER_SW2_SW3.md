# Guia Demo: Failover Si Cae SW2 O SW3

Objetivo: demostrar que si cae un switch intermedio, **SW2 o SW3**, la sesion del usuario no se borra y la red puede seguir funcionando por ruta alternativa si ONOS/M6 ven un camino disponible.

Regla de seguridad: **nunca tocar `ens3`**. `ens3` es gestion/SSH. La prueba solo baja puertos de datos.

## 1. Idea De La Demo

H1 esta autenticado y accede a Telecom:

```text
H1 -> SW4 -> red troncal -> SW5 -> 192.168.100.101:8001
```

Luego se baja temporalmente SW2 o SW3. Como son switches intermedios, la red deberia intentar usar una ruta alternativa.

Resultado esperado:

```text
Antes de la caida: H1 recibe 200.
Durante convergencia: puede haber 1 timeout.
Despues: H1 vuelve a recibir 200 sin reloguearse.
```

## 2. Verificar Estado Base

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Esperado:

```text
status: ok
devices_onos: 5 switches
network_actions_enabled: true
onos_reads_enabled: true
onos_writes_enabled: true
```

Ver topologia/failover:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/failover/topology \
  | python3 -m json.tool
```

## 3. Ver Dashboard M6

Desde tu PC local:

```bash
ssh -L 8080:127.0.0.1:8080 -p 5851 ubuntu@10.20.11.32
```

Abrir:

```text
http://127.0.0.1:8080/m6/dashboard
```

En la vista de failover:

```text
Analizar impacto = dry-run, no tumba switches.
Plan recovery = dry-run, muestra plan sin instalar flows.
```

Para una demo real de caida se usan los comandos de SW2/SW3 de esta guia.

## 4. Verificar Que H1 Funciona Antes

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
```

Si no esta logueado:

```bash
python3 cli.py
```

Credenciales ejemplo:

```text
usuario: 20192434
password: pass_teleco123
```

Probar:

```bash
curl -sS --max-time 5 -o /dev/null \
  -w 'h1_8001_before=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
h1_8001_before=200 exit=0
```

## 5. Dejar H1 Probando Mientras Cae El Switch

En H1 deja corriendo este loop:

```bash
for i in $(seq 1 12); do
  date -Is
  curl -sS --max-time 5 -o /dev/null \
    -w 'h1_8001 http=%{http_code} exit=%{exitcode} time=%{time_total}\n' \
    http://192.168.100.101:8001/ || true
  sleep 5
done
```

Que se debe ver:

```text
http=200 antes de la caida.
Puede aparecer 000/timeout durante reconvergencia.
Luego vuelve a http=200 sin ejecutar login otra vez.
```

## 6. Tumbar SW2 Con Rollback Automatico

En otra terminal, en SW2:

```bash
ssh -p 5802 ubuntu@10.20.11.32
```

Ejecutar:

```bash
cat > /tmp/sw2_failover_safe_test.sh <<'EOF'
#!/usr/bin/env bash
set -u
PORTS='ens4 ens5 ens6 ens7'
{
  echo "$(date -Is) DOWN sw2 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" down; done
  sleep 35
  echo "$(date -Is) UP sw2 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" up; done
  echo "$(date -Is) DONE"
} > /tmp/sw2_failover_safe_test.log 2>&1
EOF

chmod +x /tmp/sw2_failover_safe_test.sh
nohup /tmp/sw2_failover_safe_test.sh >/dev/null 2>&1 &
```

Demostrar que SW2 bajo:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw2 | egrep 'ens4|ens5|ens6|ens7'
```

Ver log:

```bash
cat /tmp/sw2_failover_safe_test.log
```

## 7. Tumbar SW3 Con Rollback Automatico

En otra terminal, en SW3:

```bash
ssh -p 5803 ubuntu@10.20.11.32
```

Ejecutar:

```bash
cat > /tmp/sw3_failover_safe_test.sh <<'EOF'
#!/usr/bin/env bash
set -u
PORTS='ens4 ens5 ens6 ens7'
{
  echo "$(date -Is) DOWN sw3 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" down; done
  sleep 35
  echo "$(date -Is) UP sw3 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" up; done
  echo "$(date -Is) DONE"
} > /tmp/sw3_failover_safe_test.log 2>&1
EOF

chmod +x /tmp/sw3_failover_safe_test.sh
nohup /tmp/sw3_failover_safe_test.sh >/dev/null 2>&1 &
```

Demostrar que SW3 bajo:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw3 | egrep 'ens4|ens5|ens6|ens7'
```

Ver log:

```bash
cat /tmp/sw3_failover_safe_test.log
```

## 8. Confirmar Que Los Puertos Volvieron

En SW2:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw2 | egrep 'ens4|ens5|ens6|ens7'
```

En SW3:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw3 | egrep 'ens4|ens5|ens6|ens7'
```

Si algun puerto queda abajo, restaurar manualmente.

En SW2:

```bash
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" up
done
```

En SW3:

```bash
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" up
done
```

## 9. Ver Logs De M6

En AAA:

```bash
grep -nE 'failover|FAILOVER|recover|reinstall|GRE|gre|SW2|SW3|link|device' \
  /home/ubuntu/logs/m6_*.log /home/ubuntu/m6_traductor.log 2>/dev/null | tail -n 120
```

Tambien puedes consultar estado:

```bash
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

## 10. Reasegurar GRE De Monitoreo

Despues de la prueba, en AAA:

```bash
curl -sS --max-time 10 -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

Esto no tumba nada. Solo asegura que las flows GRE de monitoreo existan.

## 11. Como Funciona Por Detras

Flujo tecnico:

```text
ONOS detecta link/switch down
  -> app topology-events avisa a M6
  -> M6 recibe /m6/failover/event
  -> M6 analiza sesiones activas
  -> M6 calcula si existe ruta alternativa
  -> M6 reinstala flows de sesion/ruta si es recuperable
  -> H1 mantiene sesion activa sin volver a login
```

Modulos involucrados:

```text
ONOS: detecta cambios de topologia.
topology-events: envia eventos a M6.
M6: analiza impacto, recalcula rutas y reinstala flows.
SW4/SW5/troncales: aplican las nuevas flows.
```

Lo importante:

```text
La sesion vive en M1/MySQL y M6, no en SW2/SW3.
Si cae un switch intermedio, no se debe borrar la sesion.
Solo se deben recalcular/reinstalar los caminos de datos.
```

## 12. Frase Para Explicar En La Expo

```text
SW2 y SW3 son switches intermedios. Si uno cae, ONOS detecta el cambio de topologia y M6 puede recalcular una ruta alternativa sin cerrar la sesion del usuario. Por eso H1 puede tener un timeout breve durante la convergencia, pero no necesita volver a autenticarse.
```
