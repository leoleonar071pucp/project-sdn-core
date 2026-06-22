# Base de datos de seguridad

## Ubicación

```text
app/security/sql/security_schema.sql
```

## Qué contiene

- `security_events`: evidencia recibida.
- `security_incidents`: incidentes correlacionados.
- `security_actions`: decisiones y resultados.
- `active_mirrors`: mirrors permanentes o temporales.

## Quién la utiliza

```text
M4 → eventos, incidentes y acciones
Telemetry Manager → estado de mirrors
```

M4 también puede leer las tablas existentes de identidad:

- `sesiones_activas`
- `ip_mac_binding`
- `radpostauth`

## Estado actual

El archivo está listo, pero no ha sido aplicado a MySQL. Durante las pruebas
se utilizaron repositorios en memoria y conexiones simuladas.
