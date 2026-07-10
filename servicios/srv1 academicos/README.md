# Servidor Académicos (srv1 academicos)

Un único contenedor `nginx` sirve los siguientes servicios:

- `telecom-http` -> HTTP 8001
- `telecom-https` -> HTTPS 1443
- `info-http` -> HTTP 8002
- `info-https` -> HTTPS 2443
- `electro-http` -> HTTP 8003
- `electro-https` -> HTTPS 3443

Archivos principales:

- `docker-compose.yml`
- `nginx/nginx.conf`
- Carpetas HTML: `html/telecom-http`, `html/telecom-https`, `html/info-http`, `html/info-https`, `html/electro-http`, `html/electro-https`

Certificados
------------
Los certificados NO están en el repositorio. El contenedor monta certificados desde la VM:

`/etc/sdn/certs/sdn-server.pem` y `/etc/sdn/certs/sdn-server.key`

Uso
---
En la carpeta `servicios/srv1 academicos` ejecutar:

```bash
docker compose up -d
```

Detener:

```bash
docker compose down
```

Agregar un nuevo servicio
------------------------
1. Crear carpeta nueva bajo `html/` con `index.html`.
2. Añadir un `server {}` en `nginx/nginx.conf` apuntando a la nueva carpeta y puerto.
3. Reiniciar el contenedor: `docker compose restart nginx`.
