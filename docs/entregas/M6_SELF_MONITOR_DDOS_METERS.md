# M6 Self-Monitor: deteccion liviana de saturacion y meters

Este modo permite que M6 detecte puertos ruidosos usando contadores de ONOS y aplique un meter temporal en T0. No hace DPI y no reemplaza a M5; es una defensa local de respaldo.

## Modo seguro recomendado

Primero activar solo deteccion, sin castigar:

```bash
export M6_SELF_MONITOR_ENABLED=true
export M6_SELF_MONITOR_ACTIONS=false
export M6_SELF_MONITOR_PORTS='of:00006a0757adfc4e:1,2,3'
export M6_SELF_MONITOR_THRESHOLD_PPS=500
export M6_SELF_MONITOR_METER_PPS=50
export M6_SELF_MONITOR_TTL=300
```

Con `M6_SELF_MONITOR_ACTIONS=false`, M6 registra que habria aplicado un meter, pero no instala flows ni meters.

## Activar mitigacion real

Cuando la deteccion ya fue validada:

```bash
export M6_SELF_MONITOR_ACTIONS=true
```

Si un puerto supera el umbral durante 2 muestras consecutivas, M6 reutiliza la logica de:

```text
POST /m6/security/rate-limit
```

Resultado esperado:

```text
T0 priority=38900,in_port=<puerto>,ip -> meter 50 pps,goto_table:1
TTL: 300s
```

## Endpoints

Ver estado:

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://192.168.201.251:8080/m6/self-monitor/status \
  | python3 -m json.tool
```

Ejecutar una muestra manual:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"demo_manual"}' \
  http://192.168.201.251:8080/m6/self-monitor/run-once \
  | python3 -m json.tool
```

Arrancar worker si `M6_SELF_MONITOR_ENABLED=true`:

```bash
curl -sS -X POST -H 'X-Security-Token: change-me' \
  http://192.168.201.251:8080/m6/self-monitor/start \
  | python3 -m json.tool
```

Detener worker:

```bash
curl -sS -X POST -H 'X-Security-Token: change-me' \
  http://192.168.201.251:8080/m6/self-monitor/stop \
  | python3 -m json.tool
```

Ver meters activos aplicados por M6:

```bash
curl -sS -H 'X-Security-Token: change-me' \
  'http://192.168.201.251:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

## Protecciones

- Apagado por defecto.
- Sin polling si `M6_SELF_MONITOR_ENABLED=false`.
- Solo guarda la ultima muestra por puerto, no historico largo.
- Cooldown por puerto de 300s.
- Maximo 5 acciones por minuto.
- Por defecto solo vigila puertos de usuarios en SW4.
- No usa `OUTPUT:NORMAL`.
- No crea threads por evento; usa un solo worker opcional.

