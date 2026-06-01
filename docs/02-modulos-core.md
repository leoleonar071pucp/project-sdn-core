# Módulos del Core

## M1: Autenticación

Responsabilidad principal:

- Validar credenciales.
- Crear y cerrar sesiones.
- Registrar sesiones activas.
- Coordinar la asignación de IP según el contexto del usuario.

Ejemplos de endpoints esperados:

- `/auth/login`
- `/auth/logout`

## M2: Políticas

Responsabilidad principal:

- Evaluar permisos de acceso.
- Aplicar reglas RBAC y enfoque Zero Trust.
- Generar reglas macro o micro según el caso.

Ejemplos de endpoints esperados:

- `/policies/check`
- `/policies/rules`

## M6: Traductor a ONOS

Responsabilidad principal:

- Traducir decisiones lógicas a operaciones concretas sobre la red.
- Instalar flows.
- Eliminar flows.
- Encapsular la comunicación con la API REST de ONOS.

Ejemplos de endpoints esperados:

- `/flows/install`
- `/flows/remove`

## Cómo deben colaborar estos módulos

- M1 no debe contener lógica de instalación de flows.
- M2 no debe manejar directamente detalles HTTP de ONOS.
- M6 no debe decidir políticas de negocio por su cuenta.

La regla general es:

- M1 identifica.
- M2 decide.
- M6 ejecuta en la red.
