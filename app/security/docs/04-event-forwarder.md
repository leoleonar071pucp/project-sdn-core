# Event Forwarder

## Ubicación

```text
app/security/event_forwarder/
```

## Qué hace

Lee `eve.json` de forma incremental y transforma los eventos de Suricata en
peticiones para M4.

```text
eve.json → leer línea → validar → deduplicar → marcar recurso crítico
         → cola/reintento → POST /m4/events/suricata
```

## Protecciones

- Guarda el offset para continuar después de un reinicio.
- Ignora líneas inválidas sin detenerse.
- Evita reenviar eventos duplicados.
- Mantiene una cola local si M4 no responde.
- Usa backoff para reintentos.

## Modo actual

```env
DRY_RUN=true
```

En este modo escribe el payload resultante en un archivo local y no llama a
M4.
