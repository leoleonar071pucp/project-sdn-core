# Guia Breve: Prueba Anti-Spoofing IP/MAC

Objetivo: demostrar que un host no puede copiar la IP/MAC de otro host autenticado para aprovechar sus flows OpenFlow, porque las reglas tambien validan el puerto fisico (`in_port`).

## Datos Usados

| Equipo | SSH | IP academica | MAC academica | Puerto SW4 |
|---|---|---:|---|---:|
| H1 | `ssh -p 5811 ubuntu@10.20.11.32` | `192.168.100.55` | `fa:16:3e:5a:aa:4a` | `1` |
| H2 | `ssh -p 5812 ubuntu@10.20.11.32` | `192.168.100.56` | `fa:16:3e:86:c2:42` | `2` |

Credencial de prueba:

```bash
usuario=20192434
password=pass_teleco123
```

## 1. Login Normal En H1

En H1:

```bash
curl -sS --max-time 20 -X POST http://192.168.100.110:8282/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"usuario":"20192434","password":"pass_teleco123"}' \
  | python3 -m json.tool
```

Esperado:

```text
"ok": true
"ip_asignada": "192.168.100.55"
"mac": "FA:16:3E:5A:AA:4A"
```

Probar que H1 accede a su recurso:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'h1_course_http=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
h1_course_http=200 exit=0
```

## 2. Ver Flow Legitima En SW4

En SW4:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | \
  egrep '39900|192.168.100.55|fa:16:3e:5a:aa:4a'
```

Esperado: la flow de sesion debe apuntar al puerto real de H1:

```text
priority=39900,tcp,in_port=1,dl_src=fa:16:3e:5a:aa:4a,nw_src=192.168.100.55
actions=push_vlan:...,goto_table:2
```

## 3. Spoofing Desde H2

En H2, copiar temporalmente IP/MAC de H1:

```bash
echo ubuntu | sudo -S ip link set ens4 down
echo ubuntu | sudo -S ip link set ens4 address fa:16:3e:5a:aa:4a
echo ubuntu | sudo -S ip addr flush dev ens4
echo ubuntu | sudo -S ip addr add 192.168.100.55/24 dev ens4
echo ubuntu | sudo -S ip link set ens4 up
sleep 2
ip -br addr show ens4
ip link show ens4 | sed -n '1,2p'
```

Que hace ese bloque:

| Comando | Funcion |
|---|---|
| `ip link set ens4 down` | Apaga temporalmente la interfaz academica de H2 para poder cambiarle la MAC. |
| `ip link set ens4 address fa:16:3e:5a:aa:4a` | Cambia la MAC de H2 y la hace igual a la MAC academica de H1. |
| `ip addr flush dev ens4` | Borra la IP academica original de H2 (`192.168.100.56`). |
| `ip addr add 192.168.100.55/24 dev ens4` | Asigna a H2 la IP academica de H1 (`192.168.100.55`). |
| `ip link set ens4 up` | Vuelve a levantar la interfaz academica de H2. |
| `ip -br addr show ens4` | Confirma la IP actual de `ens4`. |
| `ip link show ens4` | Confirma la MAC actual de `ens4`. |

En resumen: durante esta prueba, H2 intenta hacerse pasar por H1 copiando su IP y su MAC. La prueba debe fallar porque H2 sigue entrando por otro puerto fisico del switch.

Esperado: H2 aparece como si fuera H1:

```text
ens4 UP 192.168.100.55/24
link/ether fa:16:3e:5a:aa:4a
```

Intentar usar el recurso de H1 desde H2 spoofeado:

```bash
curl -sS --connect-timeout 4 --max-time 8 -o /tmp/spoof_course.out \
  -w 'spoof_course_http=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
spoof_course_http=000 exit=28
```

Interpretacion: H2 no aprovecha la flow de H1 porque entra por `in_port=2`, mientras la flow valida de H1 exige `in_port=1`.

## 4. Intentar Login Duplicado Desde H2

En H2 spoofeado:

```bash
curl -sS --connect-timeout 4 --max-time 8 -X POST http://192.168.100.110:8282/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"usuario":"20192434","password":"pass_teleco123"}' \
  | python3 -m json.tool
```

Resultado aceptable:

```text
timeout
```

o, si llega al portal:

```text
"ok": false
"codigo_error": "USER_ALREADY_ACTIVE_OTHER_HOST"
```

## 5. Restaurar H2

Muy importante: al terminar, restaurar IP/MAC original de H2.

```bash
echo ubuntu | sudo -S ip link set ens4 down
echo ubuntu | sudo -S ip link set ens4 address fa:16:3e:86:c2:42
echo ubuntu | sudo -S ip addr flush dev ens4
echo ubuntu | sudo -S ip addr add 192.168.100.56/24 dev ens4
echo ubuntu | sudo -S ip link set ens4 up
sleep 2
ip -br addr show ens4
ip link show ens4 | sed -n '1,2p'
```

Esperado:

```text
ens4 UP 192.168.100.56/24
link/ether fa:16:3e:86:c2:42
```

## 6. Logout Y Limpieza

En H1:

```bash
curl -sS --max-time 20 -X POST http://192.168.100.110:8282/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"mac":"FA:16:3E:5A:AA:4A","id_usuario":1,"codigo_pucp":"20192434","ip_asignada":"192.168.100.55","es_visitante":false}' \
  | python3 -m json.tool
```

Verificar en AAA:

```bash
sudo mysql -u root radius_db -e \
  "SELECT id_sesion,id_usuario,mac_address,ip_asignada,estado FROM sesiones_activas;"
```

Esperado: sin filas activas.

## Conclusion Esperada

El ataque falla porque las flows no solo hacen match por IP/MAC. La flow de sesion tambien valida el puerto fisico:

```text
in_port + dl_src + nw_src -> push_vlan -> T2
```

Por eso H2, aunque copie IP/MAC de H1, no entra por el mismo `in_port` y no recibe la VLAN logica autorizada.
