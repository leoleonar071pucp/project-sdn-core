# Estructura del Repositorio

## Criterio general

El repositorio está organizado para que el equipo pueda ubicar rápidamente:

- la aplicación principal,
- los módulos funcionales,
- el código compartido,
- la configuración de infraestructura,
- y la documentación.

## Estructura actual

```text
sdn-core/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── dependencies.py
│   ├── modules/
│   │   ├── m1_auth/
│   │   ├── m2_policies/
│   │   └── m6_translator/
│   ├── common/
│   └── templates/
├── docker/
├── dhcp/
├── docs/
├── scripts/
├── sql/
├── requirements.txt
├── .env.example
└── README.md
```

## Qué va en cada carpeta

### `app/`

Contiene el código fuente principal del backend.

- `main.py`: crea la app FastAPI y registra routers.
- `config.py`: centraliza variables de entorno y configuración.
- `dependencies.py`: dependencias compartidas entre endpoints y servicios.

### `app/modules/`

Aquí vive la lógica separada por módulo funcional.

- `m1_auth`: autenticación.
- `m2_policies`: políticas.
- `m6_translator`: traducción de reglas y comunicación con ONOS.

Esta organización asume una implementación en `FastAPI`, aunque el documento académico original haya descrito una versión conceptual en `Flask`.

Cada módulo debe mantener, al menos:

- `router.py`
- `service.py`
- `models.py` o archivos equivalentes según crezca el dominio

### `app/common/`

Código transversal compartido:

- base de datos,
- logging,
- excepciones,
- utilidades comunes.

### `docker/`

Archivos para construir y levantar contenedores del proyecto.

### `dhcp/`

Configuración relacionada al servicio DHCP externo.

### `docs/`

Documentación para onboarding, arquitectura, acuerdos técnicos y contexto del proyecto.

### `scripts/`

Scripts operativos, por ejemplo arranque del servicio.

### `sql/`

Scripts SQL versionados, incluyendo el esquema inicial de la base de datos.

La base de datos PostgreSQL cubre tanto la parte operativa del core como la persistencia asociada a `M5`.

## Regla de mantenimiento

Si una pieza de código pertenece claramente a un módulo, no debe colocarse en `common/`. `common/` debe reservarse solo para elementos realmente compartidos.
