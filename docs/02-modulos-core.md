# Módulos del Core

## Convención de implementación

Todo el backend de `sdn-core` debe implementarse sobre `FastAPI` para mantener un único punto de entrada compatible con `Uvicorn`.

Reglas base:

- La instancia principal de la aplicación vive en `app/main.py`.
- Cada módulo funcional expone sus endpoints usando `APIRouter`.
- Los routers de los módulos se registran en la app principal con `include_router(...)`.
- La ejecución estándar del servicio se hace con `uvicorn app.main:app`.

## Estructura mínima por módulo

Cada módulo debe mantener esta separación:

- `router.py`: endpoints FastAPI del módulo.
- `service.py`: lógica de negocio.
- `models.py`: schemas Pydantic y estructuras del dominio.

## M1: Autenticación

Responsabilidad principal:

- Coordinar la autenticación con `FreeRADIUS`.
- Validar credenciales contra la base de datos en `PostgreSQL`.
- Crear y cerrar sesiones.
- Registrar sesiones activas.
- Coordinar la asignación de IP según el contexto del usuario.
- Clasificar visitantes desde el portal cautivo.

Ejemplos de endpoints esperados:

- `/auth/login`
- `/auth/logout`

## M2: Políticas

Responsabilidad principal:

- Evaluar permisos de acceso.
- Aplicar reglas RBAC y enfoque Zero Trust.
- Generar reglas macro o micro según el caso.
- Precargar las reglas proactivas `T2` al arranque del sistema.

Ejemplos de endpoints esperados:

- `/policies/check`
- `/policies/rules`

## M6: Traductor a ONOS

Responsabilidad principal:

- Traducir reglas lógicas a formato JSON compatible con ONOS.
- Encapsular la comunicación con la API REST de ONOS.
- Enviar solicitudes para instalar o eliminar flows a través de ONOS.
- Consultar el estado de ONOS cuando sea necesario reconciliar o verificar flows existentes.
- Mantener aislados los detalles de integración con el controlador SDN.

Ejemplos de endpoints esperados:

- `/flows/install`
- `/flows/remove`

## Cómo deben colaborar estos módulos

- M1 no debe contener lógica de instalación de flows.
- M2 no debe manejar directamente detalles HTTP de ONOS.
- M6 no debe decidir políticas de negocio por su cuenta.
- M6 no debe interactuar directamente con switches OVS.
- M5 se resuelve con PostgreSQL y no con un sistema separado de auditoría.

La regla general es:

- M1 identifica.
- M1 autentica usando `FreeRADIUS` y `PostgreSQL`.
- M2 decide.
- M6 traduce y envía a ONOS.
- ONOS ejecuta en la red sobre los switches OVS.
