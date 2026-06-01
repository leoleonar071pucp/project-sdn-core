# Desarrollo y Despliegue

## Convención técnica base

El proyecto asume que todo el backend está construido sobre `FastAPI`.

Esta es la decisión oficial de implementación del repositorio, incluso si documentos previos de diseño mencionan `Flask`.

Esto permite:

- un solo punto de entrada para toda la aplicación,
- integración simple de módulos mediante routers,
- y arranque estándar con `Uvicorn`.

La convención operativa del proyecto es:

- `app/main.py` expone la instancia principal `app`.
- cada módulo define sus endpoints con `APIRouter`.
- `app/main.py` integra los módulos usando `include_router(...)`.

## Uvicorn y ejecución de la app

La aplicación usa FastAPI y se ejecuta con Uvicorn.

Hay dos formas habituales de correrla:

### Desarrollo local

```bash
uvicorn app.main:app --reload --port 5000
```

Esto permite recarga automática mientras se modifica el código.

### Producción

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --workers 4
```

También puede usarse Gunicorn como process manager si el despliegue lo requiere.

## Variables de entorno

La configuración debe centralizarse en `.env` y cargarse desde `app/config.py`.

Ejemplos esperados:

```ini
DATABASE_URL=postgresql://user:pass@postgres:5432/sdn_core
FREERADIUS_HOST=10.0.0.20
FREERADIUS_SECRET=change_me
ONOS_URL=http://onos-cluster-vip:8181/onos/v1
ONOS_USER=onos
ONOS_PASSWORD=rocks
DHCP_SERVER_IP=10.0.0.50
PORTAL_CAPTIVE_PORT=5000
```

## Docker

El proyecto incluye una carpeta `docker/` con:

- `Dockerfile`
- `docker-compose.yml`

Esto permite levantar un entorno reproducible para desarrollo o despliegues iniciales.

## Escalabilidad horizontal

El diseño planteado asume que:

- el core puede tener varias réplicas,
- todas apuntan a la misma base de datos,
- todas hablan con el mismo cluster ONOS,
- y el balanceo se hace por fuera del proceso de la aplicación.

Esto implica que:

- no se debe guardar estado crítico solo en memoria,
- las sesiones y decisiones persistentes deben quedar en PostgreSQL,
- DHCP sigue siendo un servicio aparte,
- y la instalación real de flows sigue dependiendo de ONOS, no de M6 directamente.

## Notas operativas del diseño actual

- `M1` se integra con `FreeRADIUS`, pero la fuente de credenciales y roles sigue siendo `PostgreSQL`.
- Los visitantes también pasan por el portal cautivo y se clasifican ahí mismo.
- `M2` debe cargar reglas proactivas `T2` al inicio del sistema.
- `M6` normalmente instala o elimina reglas, pero puede consultar el estado de ONOS para reconciliación.
- `M5` no tendrá un backend adicional: se implementa sobre `PostgreSQL`.

## Recomendaciones para el equipo

- Mantener `.env.example` actualizado con cualquier variable nueva.
- No hardcodear URLs, credenciales ni puertos en servicios o routers.
- Si una integración externa cambia, documentarla también en `docs/`.
- Cualquier cambio estructural fuerte debe reflejarse en esta carpeta para que el resto del equipo no pierda contexto.
