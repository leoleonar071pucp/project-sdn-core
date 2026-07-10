# Telemetry Manager

## Ubicación

```text
app/security/telemetry_manager/
```

## Qué hace

Administra el ciclo de vida de mirrors permanentes y temporales.

```text
M4 → POST /mirrors → validar inventario → generar operación OVSDB
                   → registrar TTL → reconciliar/expirar
```

## Endpoints

```text
POST   /mirrors
GET    /mirrors
GET    /mirrors/{incident_id}
DELETE /mirrors/{incident_id}
POST   /mirrors/reconcile
```

## Inventario

El archivo:

```text
app/security/telemetry_manager/inventory/critical-assets.yaml
```

relaciona cada recurso con:

- Bridge OVS.
- Puerto OVS que se copiará.
- Puerto/túnel hacia Suricata.

Los valores `REQUIRED` deben completarse en la fase de despliegue.

## Seguridad actual

El código solo genera listas de argumentos `ovs-vsctl`. No usa shell ni
subprocess y nunca ejecuta la operación.
