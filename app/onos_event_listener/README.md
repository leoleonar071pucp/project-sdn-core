# M6 ONOS Events

App ONOS para conectar eventos del controlador con M6 sin activar `fwd` ni usar
`OUTPUT:NORMAL`.

## Que hace

- Escucha `RULE_REMOVED` de flows M6 en `T1` con prioridad `39900`.
- Envia esos eventos a `POST /m6/flow_expired`.
- Opcionalmente recibe Packet-In TCP y envia metadata a `POST /m6/packet-in`.
- No instala flows de datos. M6 sigue siendo el unico escritor de flows.

## Modo seguro por defecto

La app arranca en dry-run:

```bash
-Dm6.dryRun=true
-Dm6.packetIn=false
```

Con eso solo escribe logs en ONOS y no llama a M6.

## Build recomendado para ONOS 2.7.0

En este laboratorio ONOS corre dentro del contenedor `onosproject/onos:2.7.0`.
El metodo probado es empaquetar como `.oar` e instalar por REST. Primero copia
esta carpeta al contenedor, por ejemplo en `/tmp/m6-onos-events-src`, y ejecuta:

```bash
sh /tmp/m6-onos-events-src/build_oar.sh
```

El artefacto queda en:

```bash
/tmp/m6-onos-events.oar
```

Nota: el manifest debe importar explicitamente `org.onosproject.event`; si se
instala solo como `.jar` suelto o con imports incompletos, la app puede aparecer
`ACTIVE` pero el componente DS no arranca.

## Activacion recomendada

1. Instalar la app ONOS por REST:

```bash
curl -u onos:rocks -X POST \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/m6-onos-events.oar \
  "http://127.0.0.1:8181/onos/v1/applications?activate=true"
```

2. Arrancar primero con:

```bash
-Dm6.url=http://192.168.201.251:8080
-Dm6.token=change-me
-Dm6.dryRun=true
-Dm6.packetIn=false
```

3. Confirmar logs y CPU/RAM de ONOS.
4. Luego activar llamadas reales:

```bash
-Dm6.dryRun=false
```

5. Solo despues de validar expiracion T1, activar Packet-In:

```bash
-Dm6.packetIn=true
```

## Flags necesarios en M6

Para solo observar:

```bash
SESSION_EXPIRE_ON_T1_REMOVED=false
REACTIVE_DATA_FLOWS_ENABLED=false
```

Para cerrar sesion por expiracion T1:

```bash
SESSION_EXPIRE_ON_T1_REMOVED=true
SESSION_IDLE_TIMEOUT=600
```

Para flows reactivos bajo demanda:

```bash
REACTIVE_DATA_FLOWS_ENABLED=true
MYSQL_SECURITY_READS_ENABLED=true
POLICY_QUERIES_ENABLED=true
```

Mantener siempre:

```bash
ONOS_READS_ENABLED=true
ONOS_WRITES_ENABLED=true
NETWORK_ACTIONS_ENABLED=true
STARTUP_FLOW_INSTALL_ENABLED=false
```
