# Diagnóstico de topología, DPIDs, puertos OpenFlow y migración a modo `secure`

Fecha de verificación: 22 de junio de 2026.

## 1. Objetivo y alcance

Este documento compara tres fuentes:

1. La arquitectura esperada mostrada en el diagrama de red.
2. La configuración codificada actualmente en `app/m6_traductor/m6_traductor.py`.
3. El estado real observado en ONOS, Open vSwitch y las VMs.

Todas las comprobaciones realizadas para elaborar este documento fueron de solo lectura. No se cambiaron interfaces, IPs, flows, procesos ni modos de operación de los switches.

## 2. Conclusión ejecutiva

La red de gestión y la red de control están levantadas, y los cinco switches están conectados a ONOS mediante OpenFlow 1.3. Sin embargo, el pipeline SDN del proyecto todavía no está desplegado.

Estado observado:

- Los cinco switches están conectados a `tcp:192.168.201.200:6653`.
- ONOS reconoce los cinco switches como disponibles y con rol `MASTER`.
- Todos los switches siguen en `fail_mode: standalone`.
- Cada switch tiene solamente cuatro flows básicos en la tabla 0.
- No hay flows del proyecto en las tablas 1, 2 o 3.
- M6 no está escuchando en el puerto 8080 de la VM ONOS.
- OPA/M2 no está escuchando en el puerto 8182 de la VM ONOS.
- La IP prevista para el portal, `192.168.100.1`, no está configurada actualmente.
- Los DPIDs, IPs de servidores y supuestos de puertos codificados en M6 no coinciden con la topología desplegada.

Por ello, no se debe cambiar aún a `secure`. Primero se debe corregir el inventario, desplegar M6 y validar todos los caminos de tráfico.

## 3. Redes indicadas por el diagrama

| Función | Red |
|---|---|
| Gestión OOB | `192.168.201.0/24` |
| Control | `192.168.200.0/24` |
| Usuarios y servidores | `192.168.100.0/24` |

La interpretación funcional esperada es:

```text
Red OOB 192.168.201.0/24
  Administración y acceso SSH a todas las VMs

Red de control 192.168.200.0/24
  ONOS, switches, AAA, monitoreo y señalización de control

Red de usuarios 192.168.100.0/24
  Clientes H1-H3, servidores académicos y gateway/portal
```

## 4. IPs del diagrama comparadas con las IPs reales

| Equipo | IP esperada en el diagrama | IP observada | Resultado |
|---|---|---|---|
| Gateway OOB | `192.168.201.210` | `192.168.201.210` | Coincide |
| Gateway usuarios | `192.168.100.1` | No configurada | Falta |
| AAA-policies OOB | `192.168.201.251` | `192.168.201.251` | Coincide |
| AAA-policies control | `192.168.200.211` | `192.168.200.211` | Coincide |
| ONOS OOB | `192.168.201.200` | `192.168.201.200` | Coincide |
| ONOS control | `192.168.200.200` | `192.168.200.200` | Coincide |
| Monitoreo OOB | `192.168.201.252` | `192.168.201.252` | Coincide |
| Monitoreo control | `192.168.200.212` | `192.168.200.212` | Coincide |
| SW1 control | `192.168.200.201` | `192.168.200.201` | Coincide |
| SW2 control | `192.168.200.202` | `192.168.200.202` | Coincide |
| SW3 control | `192.168.200.203` | `192.168.200.203` | Coincide |
| SW4 control | `192.168.200.204` | `192.168.200.204` | Coincide |
| SW5 control | `192.168.200.205` | `192.168.200.205` | Coincide |
| H1 usuarios | `192.168.100.10` por DHCP | `192.168.100.14` | No coincide |
| H2 usuarios | `192.168.100.11` por DHCP | `192.168.100.13` | No coincide |
| H3 usuarios | `192.168.100.12` por DHCP | `192.168.100.12` | Coincide |
| srv1 académicos | `192.168.100.101` | `.101` y `.10` en la misma interfaz | Configuración duplicada |
| srv2 notas | `192.168.100.102` | `192.168.100.102` | Coincide |

### Hallazgo crítico de direccionamiento

`srv1-academicos` tiene actualmente dos direcciones en `ens4`:

```text
192.168.100.101/24
192.168.100.10/24
```

La segunda dirección fue obtenida por DHCP y coincide con la dirección que el diagrama reserva para H1. Esto puede producir:

- colisiones si H1 vuelve a recibir `.10`;
- resolución ARP ambigua;
- registros incorrectos de hosts en ONOS;
- selección incorrecta de sesión por IP en M1/M6;
- pruebas aparentemente aleatorias.

Antes de desplegar políticas por IP debe existir una única política de direccionamiento:

- clientes mediante DHCP dentro de un rango exclusivo;
- servidores con direcciones fijas fuera del rango DHCP;
- reservas DHCP por MAC si se necesitan direcciones previsibles.

Un ejemplo prudente sería:

```text
Gateway/portal:       192.168.100.1
Clientes DHCP:        192.168.100.10-99
Servidores estáticos: 192.168.100.101-199
```

## 5. Cómo se confirmaron los DPIDs reales

Los DPIDs no se dedujeron únicamente de la imagen. Se verificaron mediante dos fuentes independientes.

### Fuente 1: el propio Open vSwitch

En cada VM switch se ejecutó:

```bash
sudo ovs-ofctl -O OpenFlow13 show NOMBRE_BRIDGE
```

Open vSwitch respondió directamente con:

```text
dpid:XXXXXXXXXXXXXXXX
```

Este valor pertenece al datapath local y es la referencia primaria del switch.

### Fuente 2: inventario de ONOS

En la VM ONOS se consultó:

```bash
curl -u onos:rocks \
  http://127.0.0.1:8181/onos/v1/devices
```

ONOS devolvió el mismo DPID junto con la dirección de gestión de cada switch. La coincidencia entre el valor local de OVS y el inventario del controlador elimina la ambigüedad.

### DPIDs confirmados

| Switch | IP de gestión | DPID local de OVS | DPID visto por ONOS |
|---|---|---|---|
| SW1 | `192.168.201.201` | `00007e3892af7141` | `of:00007e3892af7141` |
| SW2 | `192.168.201.202` | `0000e2ecb0ea0445` | `of:0000e2ecb0ea0445` |
| SW3 | `192.168.201.203` | `0000eadb63449748` | `of:0000eadb63449748` |
| SW4 | `192.168.201.204` | `00006a0757adfc4e` | `of:00006a0757adfc4e` |
| SW5 | `192.168.201.205` | `0000ca126249d546` | `of:0000ca126249d546` |

Estos valores también coinciden con los DPIDs impresos en el diagrama proporcionado.

## 6. Puertos OpenFlow reales

El número de interfaz Linux no es necesariamente el número que debe colocarse en un flow. Los flows usan el número de puerto OpenFlow.

La relación se obtuvo con:

```bash
sudo ovs-ofctl -O OpenFlow13 show NOMBRE_BRIDGE
```

### SW1

| Puerto OpenFlow | Interfaz |
|---:|---|
| 1 | `ens4` |
| 2 | `ens5` |
| 3 | `ens6` |
| 4 | `ens7` |
| 6 | `ens9` |
| 7 | `ens8` |

### SW2

| Puerto OpenFlow | Interfaz |
|---:|---|
| 1 | `ens4` |
| 2 | `ens5` |
| 3 | `ens6` |
| 4 | `ens7` |

### SW3

| Puerto OpenFlow | Interfaz |
|---:|---|
| 1 | `ens4` |
| 2 | `ens5` |
| 3 | `ens6` |
| 4 | `ens7` |

### SW4

| Puerto OpenFlow | Interfaz |
|---:|---|
| 1 | `ens4` |
| 2 | `ens5` |
| 3 | `ens6` |
| 4 | `ens7` |
| 5 | `ens8` |

### SW5

| Puerto OpenFlow | Interfaz |
|---:|---|
| 1 | `ens4` |
| 2 | `ens5` |
| 3 | `ens6` |
| 4 | `ens7` |

## 7. Enlaces descubiertos actualmente por ONOS

ONOS reportó los siguientes enlaces activos mediante `/onos/v1/links`:

| Origen | Puerto/interfaz | Destino | Puerto/interfaz |
|---|---|---|---|
| SW1 | OF 2 / `ens5` | SW2 | OF 4 / `ens7` |
| SW1 | OF 3 / `ens6` | SW3 | OF 4 / `ens7` |
| SW2 | OF 1 / `ens4` | SW4 | OF 5 / `ens8` |
| SW2 | OF 2 / `ens5` | SW5 | OF 3 / `ens6` |
| SW2 | OF 3 / `ens6` | SW3 | OF 3 / `ens6` |
| SW3 | OF 1 / `ens4` | SW4 | OF 4 / `ens7` |
| SW3 | OF 2 / `ens5` | SW5 | OF 4 / `ens7` |

ONOS clasifica estos enlaces como `INDIRECT`, no como `DIRECT`. Esto merece una revisión antes de generar rutas automáticamente. Puede indicar que:

- algunos enlaces atraviesan segmentos L2 compartidos;
- LLDP está viendo switches a través de una red intermedia;
- el diagrama y las conexiones desplegadas no representan enlaces punto a punto idénticos;
- existe conectividad adicional no mostrada claramente en el diagrama.

Por tanto, la API de enlaces de ONOS es evidencia del estado operativo actual, pero se debe contrastar con las redes/puertos conectados en el hipervisor antes de considerarla una representación física definitiva.

## 8. Ubicación real de hosts conocida por ONOS

| Equipo/IP actual | Switch de acceso | Puerto OpenFlow | Interfaz del switch |
|---|---|---:|---|
| H1 `192.168.100.14` | SW4 | 1 | `ens4` |
| H2 `192.168.100.13` | SW4 | 2 | `ens5` |
| H3 `192.168.100.12` | SW4 | 3 | `ens6` |
| srv1 `.101` y `.10` | SW5 | 2 | `ens5` |
| srv2 `.102` | SW5 | 1 | `ens4` |

Este resultado confirma que:

- SW4 es el switch de acceso de clientes.
- SW5 es el switch de acceso de servidores.
- La configuración actual de M6 que trata a SW2 como switch de clientes y a SW3 como switch de servidores está desactualizada.

## 9. Diferencias entre M6 y la topología actual

### 9.1 DPIDs antiguos

M6 tiene:

```python
SW1 = "of:00005ec76ec6114c"
SW2 = "of:000072e0807e854c"
SW3 = "of:0000f220f9454c4e"
```

Ninguno coincide con los cinco DPIDs actuales. M6 puede consultar ONOS, pero varias operaciones comparan los resultados con esos valores antiguos. Como consecuencia:

- no reconoce correctamente SW1, SW2 o SW3;
- omite reglas destinadas a switches concretos;
- no instala cuarentena en el switch real de clientes;
- intenta publicar flows contra identificadores inexistentes.

### 9.2 Solo modela tres switches

El código fue escrito para:

```text
SW1: core
SW2: acceso de clientes
SW3: acceso de servidores
```

La topología actual tiene cinco:

```text
SW1: core/servicios
SW2 y SW3: distribución
SW4: acceso de clientes
SW5: acceso de servidores
```

No basta con sustituir tres cadenas DPID. La lógica de roles de los switches debe reflejar las cinco capas reales.

### 9.3 Puertos codificados directamente

M6 contiene rutas como:

```python
(Config.SW2, 1, "src", PORTAL_IP, "NORMAL", ...)
(Config.SW1, 2, "dst", PORTAL_IP, 1, ...)
(Config.SW1, 1, "src", PORTAL_IP, 2, ...)
```

También asume:

```python
out_port=1
IN_PORT=1
```

en flows de usuario y retorno.

Esto es hardcoding y, en este despliegue, es peligroso porque:

- el puerto 1 de SW4 conduce a H1, no necesariamente hacia el core;
- un puerto puede cambiar después de recrear una VM o una interfaz;
- la ruta depende del origen y destino, no de un único puerto universal;
- la topología actual tiene caminos redundantes por SW2 y SW3;
- los números Linux `ensX` y OpenFlow no son intercambiables.

Hardcodear no siempre es incorrecto en un laboratorio completamente fijo. Puede ser válido para una demo pequeña si existe un inventario único, probado y versionado. La mala señal es tener los valores dispersos dentro de la lógica de negocio y sin validación contra ONOS.

### 9.4 Detección parcial de puertos de acceso

M6 ya contiene una mejora útil:

```python
get_access_ports(device_id)
```

Esta función consulta los puertos del switch y resta aquellos que ONOS detecta como enlaces entre switches.

El problema no es el método en sí, sino que actualmente se invoca sobre `Config.SW2`. En la red real debería aplicarse a SW4 para clientes y a SW5 para servidores.

Además, considerar “puerto de acceso” a todo puerto que no aparezca en LLDP puede clasificar erróneamente:

- puertos hacia AAA;
- puertos hacia ONOS;
- puertos hacia monitoreo;
- puertos hacia gateway/portal;
- enlaces indirectos que LLDP no detecte temporalmente.

### 9.5 IPs de recursos incorrectas

M6 usa:

```python
SERVER_CURSOS = "192.168.100.200"
SERVER_NOTAS  = "192.168.100.201"
```

El diagrama y las VMs actuales usan:

```text
srv1-academicos: 192.168.100.101
srv2-notas:      192.168.100.102
```

Las reglas T2 generadas con `.200` y `.201` no permitirían llegar a los servidores reales.

### 9.6 Fallback de hosts desactualizado

`HOSTS_VNRT` contiene IPs y MACs antiguas como `.23` y `.100`. Actualmente ONOS ve H1-H3 como `.14`, `.13` y `.12`.

El fallback puede asociar una sesión al host equivocado si se utiliza cuando ONOS no encuentra la IP.

### 9.7 Portal sin destino real

M6 espera:

```python
PORTAL_IP = "192.168.100.1"
```

La imagen también ubica `192.168.100.1` en el gateway, pero esa dirección no está configurada actualmente. Instalar flows hacia esa IP no crea el portal ni la dirección; únicamente envía paquetes hacia un destino que debe existir previamente.

### 9.8 M1 y M6 deben compartir una dirección alcanzable

M1 usa:

```python
M6_URL = "http://127.0.0.1:8080/m6/token_rol"
```

Esto solo funciona si M1 y M6 corren en la misma VM. Si M1 corre en AAA y M6 en ONOS, `127.0.0.1` desde AAA apunta a AAA, no a ONOS.

La dirección debe salir de configuración y representar la ubicación real del servicio M6.

### 9.9 No se encontró una variable booleana para activar M6

En la versión local revisada no aparece una variable como:

```text
M6_ENABLED=true
MODO_PRUEBA=false
INSTALL_FLOWS=true
```

El archivo `m6_traductor.py`, al ejecutarse directamente, llama automáticamente a:

```python
m6.instalar_cuarentena_arranque()
```

Si se ejecuta mediante Gunicorn, el bloque `if __name__ == "__main__"` no se ejecuta y el arranque debe invocarse por el endpoint:

```bash
curl -X POST http://127.0.0.1:8080/m6/arranque
```

Si existe una variable nueva en otra copia desplegada o en otra rama, debe compararse con este repositorio antes de realizar el despliegue.

## 10. Propuesta ideal para eliminar el hardcoding

La solución recomendada combina configuración declarativa y descubrimiento dinámico.

### 10.1 Inventario declarativo separado del código

Crear, por ejemplo:

```text
config/topology.yaml
```

Contenido conceptual:

```yaml
networks:
  management: 192.168.201.0/24
  control: 192.168.200.0/24
  users: 192.168.100.0/24

services:
  onos:
    management_ip: 192.168.201.200
    control_ip: 192.168.200.200
    api_port: 8181
  m6:
    control_ip: 192.168.200.200
    port: 8080
  portal:
    user_ip: 192.168.100.1
  courses:
    user_ip: 192.168.100.101
  grades:
    user_ip: 192.168.100.102

switches:
  core:
    management_ip: 192.168.201.201
    dpid: of:00007e3892af7141
  distribution_a:
    management_ip: 192.168.201.202
    dpid: of:0000e2ecb0ea0445
  distribution_b:
    management_ip: 192.168.201.203
    dpid: of:0000eadb63449748
  client_access:
    management_ip: 192.168.201.204
    dpid: of:00006a0757adfc4e
  server_access:
    management_ip: 192.168.201.205
    dpid: of:0000ca126249d546
```

Los valores todavía deben validarse al arrancar. El archivo no debería convertirse en una nueva fuente de hardcoding silencioso.

### 10.2 Descubrimiento y validación al iniciar M6

M6 debería:

1. Consultar `/onos/v1/devices`.
2. Resolver cada switch por `managementAddress`.
3. Confirmar que el DPID configurado coincide.
4. Consultar `/onos/v1/devices/{dpid}/ports`.
5. Consultar `/onos/v1/links`.
6. Confirmar que existen SW1-SW5 y los caminos esperados.
7. Detener la instalación si falta un elemento crítico.

Así, si un DPID cambia, M6 informa claramente:

```text
SW4 esperado por management_ip=192.168.201.204
DPID configurado: X
DPID observado:   Y
Instalación cancelada
```

### 10.3 Roles explícitos de puertos

No se debería depender únicamente de restar puertos LLDP. Lo ideal es etiquetar puertos mediante ONOS Network Configuration o mediante el inventario:

```yaml
ports:
  client_access:
    h1: 1
    h2: 2
    h3: 3
    uplinks: [4, 5]
  server_access:
    srv2: 1
    srv1: 2
    uplinks: [3, 4]
```

M6 puede validar estas etiquetas contra los hosts que ONOS observa. Si H1 aparece en otro puerto, debe rechazar la instalación o generar una alerta, no instalar ciegamente.

### 10.4 Cálculo dinámico del camino

Para enviar tráfico desde H1 hasta srv1, M6 no debería asumir `OUTPUT:1`.

El proceso ideal es:

```text
1. Resolver H1 mediante /hosts
2. Resolver srv1 mediante /hosts
3. Obtener switch y puerto de ambos extremos
4. Consultar caminos entre SW4 y SW5
5. Elegir un camino
6. Instalar reglas salto por salto
7. Instalar también el camino de retorno
```

Opciones:

- utilizar la API de paths/topología de ONOS;
- instalar intents punto a punto;
- calcular el camino en M6 a partir de `/links`.

Para este proyecto, los intents de ONOS o un cálculo explícito de camino son preferibles a números de salida fijos.

### 10.5 Separar política de topología

M2 debería decidir:

```text
Rol Estudiante_Telecom puede acceder a srv1 TCP 80/443
```

M6 debería traducir:

```text
Dónde está el cliente
Dónde está srv1
Qué camino existe
Qué flows debe instalar cada switch
```

M2 no debería conocer puertos físicos. M6 no debería contener políticas de negocio duplicadas salvo un modo de emergencia claramente controlado.

## 11. Significado de `standalone` y `secure`

### `standalone`

Si el controlador no instala una regla útil, OVS puede comportarse como un switch Ethernet tradicional y aprender MACs automáticamente.

Consecuencia:

```text
El tráfico puede funcionar aunque el pipeline SDN esté incompleto.
```

Esto es útil durante montaje y diagnóstico, pero puede ocultar fallos de autorización.

### `secure`

OVS no utiliza el comportamiento autónomo como respaldo. El tráfico depende de los flows instalados por el controlador.

Consecuencia:

```text
Sin flow válido, no hay forwarding.
```

Este es el modo adecuado para hacer obligatorio el control SDN, pero solamente después de disponer de reglas completas.

### Precaución adicional

Aunque el bridge esté en `secure`, un flow explícito con:

```text
actions=NORMAL
```

sigue habilitando el switching tradicional para el tráfico que coincida con esa regla. Por tanto, `secure` no reemplaza una revisión de los treatments `NORMAL` presentes en M6.

## 12. Orden recomendado de corrección

### Fase 1: normalizar direccionamiento

1. Definir dónde residirá realmente `192.168.100.1`.
2. Separar el pool DHCP de las IPs estáticas.
3. Eliminar la superposición conceptual entre H1 `.10` y srv1 `.10`.
4. Confirmar que srv1 sea `.101` y srv2 `.102`.
5. Confirmar que H1-H3 reciben el rango previsto.

### Fase 2: actualizar el modelo de topología

1. Incorporar SW1-SW5.
2. Usar los DPIDs confirmados.
3. Asignar roles: core, distribución, acceso clientes y acceso servidores.
4. Validar los enlaces `INDIRECT` de ONOS contra el hipervisor.
5. Registrar la relación interfaz Linux ↔ puerto OpenFlow.

### Fase 3: eliminar supuestos de puertos

1. Sustituir `out_port=1` por resolución de camino.
2. Sustituir `IN_PORT=1` por el puerto real de retorno.
3. Resolver clientes y servidores con ONOS `/hosts`.
4. Usar paths o intents para los saltos intermedios.
5. Mantener un inventario declarativo únicamente para roles y validación.

### Fase 4: corregir servicios

1. Definir la VM donde ejecutará M6.
2. Configurar la URL M1→M6 con una IP alcanzable.
3. Levantar M6 en 8080.
4. Levantar OPA/M2 en el puerto acordado.
5. Comprobar que M6 alcanza ONOS, OPA y MySQL.
6. Confirmar que el portal/gateway existe en `.1`.

### Fase 5: instalar el pipeline todavía en `standalone`

Instalar y verificar:

- T0: ARP, mitigación y encaminamiento inicial.
- T1: cuarentena y cambio de VLAN por sesión.
- T2: permisos proactivos por rol.
- T3: excepciones y denegaciones por sesión.
- reglas de retorno;
- table-miss explícitos y seguros.

### Fase 6: pruebas

Desde H1-H3:

1. DHCP.
2. ARP hacia gateway/portal.
3. acceso al portal;
4. autenticación válida e inválida;
5. acceso permitido según rol;
6. acceso denegado;
7. cierre y expiración de sesión;
8. caída y recuperación de ONOS;
9. caminos de ida y retorno.

### Fase 7: migración a `secure`

Solo cuando todas las pruebas anteriores funcionen:

```bash
sudo ovs-vsctl set-fail-mode sw1 secure
sudo ovs-vsctl set-fail-mode sw2 secure
sudo ovs-vsctl set-fail-mode sw3 secure
sudo ovs-vsctl set-fail-mode sw4 secure
sudo ovs-vsctl set-fail-mode sw5 secure
```

Después se debe repetir la batería completa de pruebas.

## 13. Lista de verificación previa a `secure`

- [ ] Los cinco DPIDs fueron validados al arrancar M6.
- [ ] ONOS muestra los cinco switches disponibles.
- [ ] La topología de ONOS coincide con la topología del hipervisor.
- [ ] H1-H3 están ubicados en SW4.
- [ ] srv1 y srv2 están ubicados en SW5.
- [ ] No existen IPs duplicadas.
- [ ] `192.168.100.1` existe y responde.
- [ ] M6 escucha en 8080.
- [ ] M1 puede alcanzar M6.
- [ ] M6 puede alcanzar ONOS.
- [ ] M6 puede alcanzar OPA/M2.
- [ ] Existen flows en T0, T1 y T2.
- [ ] T3 se crea al aplicar una excepción/denegación de sesión.
- [ ] Existen flows correctos de retorno.
- [ ] No hay `NORMAL` que permita saltarse las políticas.
- [ ] DHCP y ARP funcionan con el pipeline activo.
- [ ] Las pruebas permitidas y denegadas producen el resultado esperado.

## 14. Comandos de verificación de solo lectura

### DPID y puertos locales

```bash
sudo ovs-ofctl -O OpenFlow13 show sw1
```

### Modo del bridge

```bash
sudo ovs-vsctl get-fail-mode sw1
```

### Controlador configurado

```bash
sudo ovs-vsctl get-controller sw1
```

### Flows por switch

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw1
```

### Dispositivos en ONOS

```bash
curl -u onos:rocks \
  http://127.0.0.1:8181/onos/v1/devices
```

### Enlaces en ONOS

```bash
curl -u onos:rocks \
  http://127.0.0.1:8181/onos/v1/links
```

### Hosts en ONOS

```bash
curl -u onos:rocks \
  http://127.0.0.1:8181/onos/v1/hosts
```

### Estado de M6

```bash
curl http://127.0.0.1:8080/m6/status
```

## 15. Recomendación final

No se recomienda limitar el cambio a sustituir DPIDs y activar `secure`. El cambio mínimo correcto debe:

1. corregir IPs y evitar duplicados;
2. modelar los cinco switches;
3. reconocer SW4 como acceso de clientes y SW5 como acceso de servidores;
4. eliminar puertos de salida universales;
5. calcular los caminos con información de ONOS;
6. desplegar y probar el pipeline;
7. activar `secure` al final.

El hardcoding puede mantenerse temporalmente para una demostración controlada, pero debe centralizarse en un único inventario y validarse automáticamente. Los valores actuales dentro de M6 no deben utilizarse para instalar flows en la topología actual.
