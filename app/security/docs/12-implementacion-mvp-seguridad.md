# Implementación del MVP de seguridad

## Estado

El código del circuito `M6 → M4 → M6 → ONOS` está preparado en modo seguro.
Mientras los switches permanezcan standalone, todas las integraciones externas
están desactivadas por defecto.

## Componentes

- `app/security/m4/`: servicio FastAPI de correlación.
- `app/m6_traductor/m6_traductor.py`: endpoints reactivos y de mitigación.
- `app/security/sql/security_schema.sql`: tablas MySQL listas, pero no aplicadas.
- `tests/test_m6_security.py`: pruebas de M6 sin red.
- `app/security/m4/tests/`: pruebas de M4 con repositorios y clientes simulados.

## Endpoints de M4

```text
GET  /health
POST /m4/events
POST /m4/events/m6
POST /m4/events/suricata
POST /m4/events/telemetry
GET  /m4/incidents
GET  /m4/incidents/{incident_id}
```

Suricata y telemetría responden `503` mientras sus flags de ingesta estén
desactivados.

## Endpoints añadidos a M6

```text
POST /m6/packet-in
POST /m6/mitigacion
POST /m6/unblock
GET  /m6/security/host-state
GET  /m6/security/mitigations/<incident_id>
```

Los endpoints de seguridad requieren:

```text
X-Security-Token: <SECURITY_TOKEN>
```

## Modo seguro obligatorio

Mantener:

```env
NETWORK_ACTIONS_ENABLED=false
ONOS_WRITES_ENABLED=false
ONOS_READS_ENABLED=false
OVSDB_ACTIONS_ENABLED=false
M4_AUTOMATIC_ACTIONS_ENABLED=false
M4_EVENTS_ENABLED=false
M5_LOGGING_ENABLED=false
MYSQL_SECURITY_READS_ENABLED=false
POLICY_QUERIES_ENABLED=false
STARTUP_FLOW_INSTALL_ENABLED=false
```

Con esos valores:

- M6 no consulta ni escribe en ONOS.
- M6 no consulta OPA ni MySQL.
- M6 no envía eventos a M4 o logs a M5.
- M4 usa memoria y no conecta a MySQL.
- Los bloqueos y mirrors se registran como `SIMULATED`.
- `/m6/arranque` no instala flows.

## Persistencia futura

Para habilitar persistencia, primero se debe aplicar manualmente:

```text
app/security/sql/security_schema.sql
```

Luego se habilita únicamente:

```env
MYSQL_PERSISTENCE_ENABLED=true
```

Esto no habilita ONOS ni OVSDB.

## Habilitación futura de red

No activar todos los flags simultáneamente. El orden recomendado, una vez
resueltos los problemas de los switches, es:

1. `ONOS_READS_ENABLED=true`
2. Verificar DPIDs, hosts y puertos.
3. `M4_EVENTS_ENABLED=true`
4. Verificar M6 → M4 sin acciones automáticas.
5. `NETWORK_ACTIONS_ENABLED=true`
6. `ONOS_WRITES_ENABLED=true` durante una ventana controlada.
7. Finalmente evaluar `M4_AUTOMATIC_ACTIONS_ENABLED=true`.

OVSDB y mirroring continúan fuera del MVP actual.

## Directriz para la siguiente fase

Suricata permanecerá activo y recibirá dos clases de tráfico:

1. Mirrors permanentes de recursos críticos como autenticación, notas,
   administración y bases de datos.
2. Mirrors temporales activados por M4 para tráfico general sospechoso.

Esta decisión evita depender únicamente de Packet-In o anomalías volumétricas,
que no detectarían necesariamente un único payload malicioso sobre una
conexión permitida.
