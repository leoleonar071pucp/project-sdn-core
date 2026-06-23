# M4: correlador y motor de decisión

## Ubicación

```text
app/security/m4/
```

## Qué hace

M4 es el cerebro de seguridad. Recibe eventos de M6, Suricata, sFlow y NetFlow.

```text
Evento → normalización → correlación → riesgo → incidente → acción
```

Sus piezas principales son:

- `correlator.py`: une evidencias del mismo origen.
- `risk_engine.py`: calcula el riesgo.
- `incident_manager.py`: evita acciones duplicadas y controla estados.
- `service.py`: coordina el proceso.
- `clients/`: consulta M6, M2 y Telemetry Manager.
- `repositories/`: guarda eventos e incidentes.

## Decisiones posibles

```text
LOG → WATCH → MIRROR → TEMP_BLOCK → BLOCK
```

Mientras los flags estén desactivados, la decisión se registra pero la acción
queda como `SIMULATED`.

## Entradas

```text
POST /m4/events/m6
POST /m4/events/suricata
POST /m4/events/telemetry
```

## Salidas

- Solicitudes de mitigación hacia M6.
- Solicitudes de mirror hacia Telemetry Manager.
- Incidentes persistidos en memoria o MySQL.
