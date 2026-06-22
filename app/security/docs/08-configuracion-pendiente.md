# Qué falta configurar

El código offline está listo. Antes de levantarlo en la VM deben completarse
estos puntos.

## 1. Inventario real de red

Reemplazar `REQUIRED` en:

```text
app/security/telemetry_manager/inventory/critical-assets.yaml
app/security/suricata/critical-assets.yaml
```

Se necesita conocer:

- DPID de cada switch.
- Nombre del bridge OVS.
- Número OpenFlow y nombre OVS de cada puerto.
- Puerto conectado a cada recurso crítico.
- Nombre del túnel de salida hacia Suricata.

## 2. Archivos `.env`

Crear un `.env` desde cada `.env.example`:

```text
app/security/m4/.env.example
app/security/event_forwarder/.env.example
app/security/flow_collector/.env.example
app/security/telemetry_manager/.env.example
```

Configurar:

- `SECURITY_TOKEN` compartido.
- IP/URL de M4, M6, M2 y MySQL.
- Rutas de logs y estado.
- Puertos UDP.

Mantener inicialmente:

```env
NETWORK_ACTIONS_ENABLED=false
ONOS_WRITES_ENABLED=false
OVSDB_ACTIONS_ENABLED=false
M4_AUTOMATIC_ACTIONS_ENABLED=false
DRY_RUN=true
```

## 3. MySQL

Aplicar manualmente:

```text
app/security/sql/security_schema.sql
```

No aplicarlo hasta respaldar la base y confirmar credenciales.

## 4. Red y firewall

Permitir únicamente las comunicaciones necesarias:

- Forwarder y colector hacia M4.
- M4 hacia M6 y Telemetry Manager.
- M4/Telemetry Manager hacia MySQL.
- UDP 6343 para sFlow.
- UDP 2055 para NetFlow v5.

## 5. Exportadores y captura

- Configurar sFlow/NetFlow en switches.
- Crear túneles GRE/ERSPAN.
- Confirmar la interfaz que Suricata capturará.
- Configurar mirrors permanentes de recursos críticos.

## 6. Pieza de código pendiente

Falta la aplicación Java Packet-In de ONOS:

```text
OVS → Packet-In → ONOS App → M6
```

Sin ella, M6 no recibe automáticamente decisiones reactivas desde ONOS.

## Orden de activación recomendado

1. Levantar servicios con dry-run.
2. Verificar logs y healthchecks.
3. Habilitar ingesta hacia M4.
4. Aplicar persistencia MySQL.
5. Validar telemetría y Suricata en observación.
6. Completar la app ONOS.
7. Habilitar lecturas ONOS.
8. Probar un mirror controlado.
9. Habilitar escrituras y bloqueos únicamente al final.
