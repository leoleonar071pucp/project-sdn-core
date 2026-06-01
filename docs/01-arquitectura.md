# Arquitectura General

## Componentes principales

El sistema se compone de estos bloques:

- `sdn-core`: servicio central en FastAPI.
- `PostgreSQL`: persistencia de usuarios, sesiones, roles y políticas.
- `ONOS`: controlador SDN donde se instalan y eliminan flows.
- `Kea DHCP`: servicio externo de asignación de IP.
- `sdn-security`: componente separado que puede solicitar bloqueos o acciones de seguridad.

## Relación entre componentes

```text
sdn-core
├── PostgreSQL
├── ONOS
├── Kea DHCP
└── sdn-security
```

## Flujo general esperado

1. Un usuario se autentica mediante M1.
2. M1 registra o actualiza la sesión activa y coordina la asignación de IP.
3. M2 evalúa permisos según rol, contexto y reglas.
4. M6 traduce la decisión a flows o reglas operativas para ONOS.
5. Si hay eventos de seguridad, otros componentes pueden pedir bloqueos que terminan convertidos en reglas de red.

## Medios de comunicación

- `sdn-core -> PostgreSQL`: persistencia y consulta de datos.
- `sdn-core -> ONOS`: llamadas HTTP REST.
- `sdn-core -> DHCP`: coordinación para asignación de IP.
- `sdn-security -> sdn-core`: solicitudes HTTP relacionadas con seguridad o bloqueo.

## Decisión de diseño importante

El core debe ser lo más `stateless` posible a nivel de proceso. La información crítica no debe quedarse en memoria local si luego se planea tener más de una réplica.
