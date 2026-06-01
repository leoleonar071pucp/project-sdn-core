# Visión General

## Qué es `sdn-core`

`sdn-core` es el módulo central del proyecto SDN del campus PUCP. Su función es concentrar la lógica principal del sistema en una sola aplicación backend basada en FastAPI.

La idea del proyecto es manejar en este servicio tres módulos principales:

- `M1`: autenticación y creación de sesión.
- `M2`: evaluación de políticas y permisos.
- `M6`: traducción de decisiones a flujos para ONOS.

## Enfoque de arquitectura

El proyecto sigue un enfoque de `monolito modular`. Eso significa:

- Existe un solo servicio principal desplegable.
- Dentro del servicio, cada responsabilidad se separa por módulos.
- La separación se hace a nivel de carpetas, routers, servicios y modelos.
- Aunque todo corre en una misma app, el código debe mantenerse desacoplado.

Este enfoque permite avanzar más rápido en desarrollo sin perder orden en la base de código.

## Qué debe entender cualquier integrante del equipo

- No se están construyendo microservicios para M1, M2 y M6.
- Sí se está separando el código de cada módulo para evitar mezclar responsabilidades.
- El estado compartido del sistema se guarda fuera de la app, principalmente en PostgreSQL.
- ONOS y DHCP son componentes externos que el core consume o coordina.
