# Flow Collector: sFlow y NetFlow

## Ubicación

```text
app/security/flow_collector/
```

## Qué hace

Recibe telemetría de los switches y detecta comportamiento anormal sin
inspeccionar todo el payload.

```text
Switch → UDP 6343 sFlow v5 ─┐
                            ├→ decodificar → ventana → evento → M4
Switch → UDP 2055 NetFlow v5┘
```

## Detecciones

- Muchos puertos: posible port scan.
- Muchos destinos: fan-out.
- Muchos paquetes: posible DDoS.
- Muchos bytes: pico de tráfico.
- Mucha transferencia hacia pocos destinos: posible exfiltración.

## Protocolos incluidos

- sFlow v5 con muestras de encabezado Ethernet/IPv4/TCP/UDP.
- NetFlow v5.

NetFlow v9 e IPFIX quedan pendientes.

## Modo actual

El receptor UDP solo se abre al ejecutar expresamente el servicio. Con
`DRY_RUN=true`, los eventos se guardan localmente y no se envían a M4.
