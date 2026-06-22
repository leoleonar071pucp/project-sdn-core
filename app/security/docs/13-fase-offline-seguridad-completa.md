# Fase offline de seguridad

## Objetivo

Dejar preparados todos los componentes de seguridad que pueden desarrollarse
sin instalar nada en ONOS, sin desplegar la VM y sin contactar switches.

## Componentes entregados

### Suricata

- Configuración base y salida `eve.json`.
- Reglas locales de demostración.
- Inventario declarativo de recursos críticos con placeholders obligatorios.
- Fixtures para alertas normales, críticas, duplicadas e inválidas.

### Forwarder EVE

- Lectura incremental y persistencia de offset.
- Filtrado de `alert`, `anomaly`, `http`, `tls` y `flow`.
- Deduplicación y cola local.
- Reintentos con backoff.
- Dry-run predeterminado.

### Colector de flujos

- Decodificador sFlow v5 para flow samples con raw packet header
  Ethernet/IPv4/TCP/UDP.
- Decodificador NetFlow v5.
- Ventanas para volumen, paquetes, puertos y destinos.
- Detección de port scan, fan-out, DDoS, picos y posible exfiltración.
- Receptor UDP disponible únicamente al ejecutar explícitamente el servicio.

NetFlow v9 e IPFIX no están incluidos.

### Gestor de mirrors

- API completa de creación, consulta, eliminación y reconciliación.
- Mirrors permanentes y temporales.
- TTL, idempotencia e inventario.
- Generación de operaciones OVSDB como listas de argumentos.
- Ninguna función ejecuta `ovs-vsctl`.
- Si `OVSDB_ACTIONS_ENABLED=true` durante esta fase, la acción se marca
  `FAILED` en vez de ejecutarse.

### M4

- Correlación entre M6, Suricata, sFlow y NetFlow por IP origen.
- Evidencias y acciones incluidas en cada incidente.
- Diferenciación entre mirror permanente y temporal.
- Repositorios MySQL preparados y probados con conexiones simuladas.

## Seguridad offline

Todos los servicios conservan dry-run y flags de red desactivados. El archivo
`app/security/docker-compose.yml` utiliza el profile `deployment`, por lo que una
invocación normal de Compose no inicia los servicios.

No se debe ejecutar:

```text
docker compose --profile deployment up
```

hasta entrar formalmente en la fase de VM.

## Inventario pendiente

Antes de habilitar mirrors reales deben sustituirse todos los valores
`REQUIRED` en:

```text
app/security/telemetry_manager/inventory/critical-assets.yaml
```

Los valores requeridos son bridge OVS, puerto origen y puerto de túnel de
salida.

## Fase posterior

Queda diferido:

- Aplicación Packet-In de ONOS.
- Despliegue en la VM.
- Aplicación del esquema MySQL.
- Apertura de puertos UDP.
- Configuración de exportadores sFlow/NetFlow.
- Ejecución OVSDB.
- Pruebas de tráfico real.
