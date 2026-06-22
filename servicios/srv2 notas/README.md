# Servidor de Servicios HTTP/HTTPS con Docker + Nginx

Un único contenedor `nginx` sirve 4 servicios:

- `notas-http` -> HTTP 8080
- `notas-https` -> HTTPS 443
- `admin-http` -> HTTP 8081
- `admin-https` -> HTTPS 8443

Archivos principales:

- [docker-compose.yml](servicios/srv2%20notas/docker-compose.yml)
- [nginx/nginx.conf](servicios/srv2%20notas/nginx/nginx.conf)
- Carpetas HTML: `html/notas-http`, `html/notas-https`, `html/admin-http`, `html/admin-https`

Certificados
------------
Los certificados NO están en el repositorio. El contenedor monta certificados desde la VM:

`/etc/sdn/certs/sdn-server.pem` y `/etc/sdn/certs/sdn-server.key`

Uso
---
En la carpeta `servicios/srv2 notas` ejecutar:

```bash
docker compose up -d
```

Para detener y remover:

```bash
docker compose down
```

Agregar un nuevo servicio
------------------------
1. Crear una carpeta nueva bajo `html/` con un `index.html`.
2. Añadir un `server {}` en `nginx/nginx.conf` apuntando a la nueva carpeta y puerto.
3. Reiniciar el contenedor: `docker compose restart nginx`.

Notas
-----
- No almacenar certificados en el repositorio.
- Arquitectura diseñada para añadir más `server {}` y carpetas HTML sin cambiar la estructura base.