# ONOS Topology Events -> M6 Failover

App ONOS que escucha cambios reales de topologia y avisa a M6:

```text
ONOS DeviceEvent / LinkEvent
        |
        v
pe.edu.pucp.sdn.topology-events
        |
        v
POST /m6/failover/event
```

M6 decide si solo analiza o aplica recovery. Por seguridad, en la maqueta se deja:

```text
FAILOVER_AUTO_REINSTALL_ENABLED=false
```

Con ese flag apagado, la app ONOS puede avisar eventos reales sin reinstalar flows.

## Eventos Soportados

| Evento ONOS | Payload enviado a M6 |
|---|---|
| `DEVICE_REMOVED` | `event_type=device_down`, `device_id=of:...` |
| `DEVICE_AVAILABILITY_CHANGED` hacia unavailable | `event_type=device_down`, `device_id=of:...` |
| `LINK_REMOVED` | `event_type=link_down`, `failed_links=[...]` |
| `LINK_UPDATED` no activo | `event_type=link_down`, `failed_links=[...]` |

## Configuracion

Valores por defecto:

```text
m6Url=http://192.168.201.251:8080/m6/failover/event
securityToken=change-me
timeoutMs=2000
dedupWindowSeconds=15
enabled=true
```

## Build

Requiere JDK 11 y Maven.

```bash
cd app/onos_topology_events
mvn clean package
```

Artefacto esperado:

```text
target/onos-topology-events-1.0.0.oar
```

## Instalar En ONOS

Desde una maquina con acceso al controlador ONOS:

```bash
curl -u onos:rocks -X POST \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @target/onos-topology-events-1.0.0.oar \
  'http://192.168.201.200:8181/onos/v1/applications?activate=true'
```

Verificar:

```bash
curl -sS -u onos:rocks \
  http://192.168.201.200:8181/onos/v1/applications/pe.edu.pucp.sdn.topology-events \
  | python3 -m json.tool
```

## Prueba Segura

1. Confirmar que M6 no aplica recovery automatico:

```bash
curl -sS http://127.0.0.1:8080/m6/status \
  | python3 -m json.tool \
  | grep failover_auto_reinstall_enabled
```

Debe ser:

```text
false
```

2. Probar primero con evento manual:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/event \
  -d '{"event_type":"device_down","device_id":"of:0000e2ecb0ea0445","source":"manual-demo"}' \
  | python3 -m json.tool
```

Esperado:

```text
applied=false
reason=auto_reinstall_disabled
```

3. Luego probar un evento real de ONOS en ventana controlada.

## Seguridad Operativa

- No instala flows.
- No borra flows.
- No usa `OUTPUT:NORMAL`.
- No hace polling.
- No crea un thread por evento; usa un worker unico.
- La cola de eventos hacia M6 esta acotada a 256 items.
- Tiene timeout HTTP corto.
- Deduplica eventos repetidos para evitar bucles.

## Desinstalar

```bash
curl -u onos:rocks -X DELETE \
  http://192.168.201.200:8181/onos/v1/applications/pe.edu.pucp.sdn.topology-events
```
