# Suricata

## Ubicación

```text
app/security/suricata/
```

## Qué hace

Suricata inspecciona paquetes y genera evidencia en `eve.json`.

```text
Tráfico espejado → Suricata → eve.json → Event Forwarder → M4
```

## Inspección híbrida

- Recursos críticos: mirror permanente.
- Tráfico general: mirror temporal cuando M4 detecta una sospecha.

Los recursos críticos iniciales son portal, RADIUS, notas, administración y
base de datos.

## Archivos

- `suricata.yaml`: configuración base.
- `rules/local.rules`: reglas de demostración.
- `critical-assets.yaml`: recursos de inspección permanente.
- `fixtures/`: eventos de prueba.

## Límites

- HTTPS oculta normalmente el payload.
- Las firmas no garantizan detectar ataques desconocidos.
- También se requieren logs de aplicación, WAF o EDR para servicios críticos.
