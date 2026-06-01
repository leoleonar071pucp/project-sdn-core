# Arquitectura General

## Componentes principales

El sistema se compone de estos bloques:

- `sdn-core`: servicio central en FastAPI.
- `PostgreSQL`: persistencia de usuarios, sesiones, roles y políticas.
- `FreeRADIUS`: validación de credenciales apoyada en la base de datos del sistema.
- `ONOS`: controlador SDN donde se instalan y eliminan flows.
- `Kea DHCP`: servicio externo de asignación de IP.
- `sdn-security`: componente separado que puede solicitar bloqueos o acciones de seguridad.

## Relación entre componentes

```text
sdn-core
├── PostgreSQL
├── FreeRADIUS
├── ONOS
├── Kea DHCP
└── sdn-security
```

## Flujo general esperado

1. Un usuario llega al portal cautivo.
2. M1 coordina la autenticación con `FreeRADIUS`, que valida credenciales contra `PostgreSQL`.
3. Si el usuario es visitante, también queda clasificado desde el portal cautivo.
4. M1 registra o actualiza la sesión activa y coordina la asignación de IP.
5. M2 evalúa permisos según rol, contexto y reglas.
6. M2 precarga reglas proactivas `T2` al arranque del sistema y genera reglas lógicas cuando corresponda.
7. M6 traduce la regla lógica a un payload JSON para la REST API de ONOS.
8. ONOS instala o elimina los flows en los switches OVS mediante OpenFlow.
9. Si hay eventos de seguridad, otros componentes pueden pedir bloqueos que terminan convertidos en reglas de red.

## Flujo funcional de decisión

```text
[Usuario]
   |
   v
[Portal Cautivo]
   |
   v
[M1 + FreeRADIUS + PostgreSQL]
   |
   v
[M2 (genera regla lógica)]
   |
   v
[M6 (traduce a JSON)]
   |
   v (HTTP REST)
[ONOS Controller]
   |
   v (OpenFlow)
[Switches OVS]
```

## Medios de comunicación

- `sdn-core -> PostgreSQL`: persistencia y consulta de datos.
- `sdn-core -> FreeRADIUS`: validación de credenciales y flujo de autenticación.
- `sdn-core -> ONOS`: llamadas HTTP REST.
- `sdn-core -> DHCP`: coordinación para asignación de IP.
- `sdn-security -> sdn-core`: solicitudes HTTP relacionadas con seguridad o bloqueo.

## Responsabilidades por módulo

| Módulo | Acción principal | Se comunica con |
|--------|------------------|------------------|
| `M1` | Validar credenciales con apoyo de FreeRADIUS, gestionar sesiones activas, asignar IP vía DHCP | FreeRADIUS, PostgreSQL, DHCP server |
| `M2` | Evaluar permisos RBAC, generar reglas lógicas y precargar `T2` al arranque | PostgreSQL |
| `M6` | Traducir reglas lógicas a formato ONOS mediante REST API y JSON; consultar estado cuando haga falta reconciliar | ONOS cluster |
| `ONOS` | Instalar o eliminar flows en switches OVS | Switches OVS (OpenFlow) |

M6 no interactúa directamente con los switches. Su función principal es transformar la política en un mensaje que ONOS entienda, y ocasionalmente consultar el estado del controlador para reconciliar flows o verificar instalaciones.

## Decisión de diseño importante

El core debe ser lo más `stateless` posible a nivel de proceso. La información crítica no debe quedarse en memoria local si luego se planea tener más de una réplica.

En esta versión del proyecto, `M5` se resuelve únicamente con `PostgreSQL` como backend de persistencia y auditoría.
