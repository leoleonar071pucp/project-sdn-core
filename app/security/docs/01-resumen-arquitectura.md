# Resumen simple de la arquitectura

La VM de seguridad recibe señales desde varias fuentes, las combina en M4 y
decide si solamente registra, vigila, solicita un mirror o pide un bloqueo.

```text
Suricata ───────────────┐
sFlow / NetFlow ────────┼→ M4 → decisión ─┬→ M6 → ONOS → switch
Eventos de M6 ──────────┘                 └→ Telemetry Manager → mirror
```

## Flujo de un ataque a un recurso prohibido

```text
Host → switch → Packet-In → ONOS → M6 → M2
                                      |
                                     DENY
                                      |
                                      v
                                     M4
                                      |
                              riesgo alto/bloqueo
                                      |
                                      v
                                M6 → ONOS → T0
```

La aplicación Packet-In de ONOS todavía está pendiente.

## Flujo de un ataque dentro de una conexión permitida

```text
Recurso crítico → mirror permanente → Suricata → eve.json
                                               → Forwarder → M4
```

Este flujo permite detectar un único payload malicioso aunque no exista
Packet-In ni un volumen alto.

## Flujo de una anomalía volumétrica

```text
Switch → sFlow/NetFlow → Flow Collector → M4
                                         |
                               mirror o bloqueo simulado
```

## Estado actual

Todo funciona en modo offline o `SIMULATED`. Ningún componente modifica
switches, ejecuta OVSDB o instala flows reales.
