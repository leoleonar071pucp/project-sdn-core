# Desarrollo y Despliegue

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
- y DHCP sigue siendo un servicio aparte.

## Recomendaciones para el equipo

- Mantener `.env.example` actualizado con cualquier variable nueva.
- No hardcodear URLs, credenciales ni puertos en servicios o routers.
- Si una integración externa cambia, documentarla también en `docs/`.
- Cualquier cambio estructural fuerte debe reflejarse en esta carpeta para que el resto del equipo no pierda contexto.
