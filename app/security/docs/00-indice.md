# Índice de la VM de seguridad

Esta carpeta documenta únicamente los componentes que se desplegarán en la VM
de seguridad y su relación con M6, ONOS y MySQL.

## Para comenzar

1. [01-resumen-arquitectura.md](01-resumen-arquitectura.md): visión simple y flujo general.
2. [08-configuracion-pendiente.md](08-configuracion-pendiente.md): qué falta completar antes del despliegue.
3. [13-fase-offline-seguridad-completa.md](13-fase-offline-seguridad-completa.md): estado técnico del código.

## Componentes

- [02-m4-correlador.md](02-m4-correlador.md)
- [03-suricata.md](03-suricata.md)
- [04-event-forwarder.md](04-event-forwarder.md)
- [05-flow-collector.md](05-flow-collector.md)
- [06-telemetry-manager.md](06-telemetry-manager.md)
- [07-base-datos-seguridad.md](07-base-datos-seguridad.md)

## Documentación detallada

- [09-estrategia-monitoreo-dinamico.md](09-estrategia-monitoreo-dinamico.md)
- [10-diagnostico-topologia-dpids-y-plan-secure.md](10-diagnostico-topologia-dpids-y-plan-secure.md)
- [11-pruebas-red-pendientes.md](11-pruebas-red-pendientes.md)
- [12-implementacion-mvp-seguridad.md](12-implementacion-mvp-seguridad.md)

## Ubicaciones principales

```text
app/security/
├── m4/
├── suricata/
├── event_forwarder/
├── flow_collector/
├── telemetry_manager/
├── sql/
├── docs/
└── docker-compose.yml
```
