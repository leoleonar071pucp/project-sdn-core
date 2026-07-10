# Guia Demo: Antispoofing IP/MAC En SDN

Objetivo: demostrar que un host no puede copiar la IP/MAC de otro host autenticado para usar sus permisos.

Regla de seguridad: **no tocar `ens3`**. `ens3` es gestion/SSH. La prueba usa solo `ens4`.

## 1. Idea De La Demo

H1 esta autenticado y puede acceder a su recurso academico.

```text
H1 real:
IP  = 192.168.100.55
MAC = fa:16:3e:5a:aa:4a
SW4 puerto = 1
```

Luego H2 intenta hacerse pasar por H1 copiando esa IP y MAC en `ens4`.

Resultado esperado:

```text
H1 accede: 200
H2 spoofeado: timeout
```

## 2. Verificar Que H1 Accede

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
```

Si no esta logueado, iniciar sesion:

```bash
python3 cli.py
```

Credenciales ejemplo:

```text
usuario: 20192434
password: pass_teleco123
```

Probar recurso:

```bash
curl -sS --max-time 5 -o /dev/null \
  -w 'h1_8001=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
h1_8001=200 exit=0
```

## 3. Ver La Flow De Sesion En SW4

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | grep 'priority=39900'
```

Debe verse algo parecido a:

```text
priority=39900,tcp,in_port=1,dl_src=fa:16:3e:5a:aa:4a,nw_src=192.168.100.55
actions=push_vlan:...,goto_table:2
```

Esa es la clave: la sesion no depende solo de IP o MAC. Depende de:

```text
puerto fisico + MAC + IP
```

## 4. Intentar Spoofing Desde H2

En H2:

```bash
ssh -p 5812 ubuntu@10.20.11.32
```

Guardar/mostrar estado original:

```bash
ip -br addr show ens4
ip link show ens4 | sed -n '1,2p'
```

Cambiar H2 para copiar IP/MAC de H1:

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

Probar acceso:

```bash
curl -sS --max-time 7 -o /dev/null \
  -w 'h2_spoof_8001=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
h2_spoof_8001=000 exit=28
```

Eso significa timeout: H2 no pudo usar la sesion de H1.

## 5. Restaurar H2

Muy importante: dejar H2 como estaba.

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

Verificar que H1 sigue funcionando:

```bash
ssh -p 5811 ubuntu@10.20.11.32
curl -sS --max-time 5 -o /dev/null \
  -w 'h1_after_spoof_test_8001=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
h1_after_spoof_test_8001=200 exit=0
```

## 6. Como Funciona Por Detras

Flujo al iniciar sesion:

```text
H1 cli.py
  -> M1 web.py / m1_auth.py
  -> M1 consulta M6 para resolver host
  -> M6/ONOS responde MAC + switch + puerto
  -> M1 valida binding en MySQL
  -> M1 registra sesion en sesiones_activas e ip_mac_binding
  -> M1 pide a M6 instalar flows
  -> M6 instala T1 session gate en SW4
```

Funciones importantes:

```text
M1:
- verify_antispoofing(ip, mac)
- validate_login_binding(id_usuario, ip, mac, switch_dpid, in_port)
- register_session(...)
- create_binding(...)

M6:
- t1_session_gate(...)
- _instalar_session_gate(...)
```

La flow que protege la sesion queda en SW4 T1:

```text
table=1, priority=39900,
tcp,in_port=PUERTO_REAL,
dl_src=MAC_REAL,
nw_src=IP_REAL
actions=push_vlan:VLAN_ROL,goto_table:2
```

Por eso H2 falla aunque copie IP/MAC:

```text
H2 entra por otro puerto fisico.
No matchea in_port=1 de H1.
No recibe la VLAN logica.
No llega a T2/T3 como usuario autorizado.
El trafico termina en drop/timeout.
```

## 7. Frase Para Explicar En La Expo

```text
El permiso no esta atado solo a IP o solo a MAC. Al autenticar, M1 y M6 atan la sesion al binding completo IP + MAC + switch + puerto fisico. Luego SW4 solo marca con VLAN logica si el paquete coincide exactamente con ese binding. Por eso copiar IP/MAC desde otro host no permite robar la sesion.
```
