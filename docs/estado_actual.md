# Estado Actual del Proyecto SDN Core (Actualizado)

Este documento describe la estructura y el estado actual de los módulos principales del proyecto SDN Core tras las últimas actualizaciones e integraciones.

## 1. Módulo 1: Autenticación (M1)

El Módulo de Autenticación se encarga de validar a los usuarios que intentan acceder a la red y asignarles su correspondiente rol e IP.

### Portal Cautivo CLI (`logica_demo/portal_cautivo.py`)
Actualmente, **este archivo contiene la lógica central y funcional del M1**.
- **Tipo:** Interfaz de Línea de Comandos (CLI) interactiva, que actúa como un simulador de Portal Cautivo.
- **Flujo Implementado:**
  1. Conexión y Autenticación con el servidor **FreeRADIUS** (usando la librería `pyrad`).
  2. Consulta y validación a la **Base de Datos MySQL** (control de sesiones activas, usuarios, bloqueos por múltiples intentos fallidos).
  3. Lógica de asignación de IPs con **doble DHCP**: un DHCP de cuarentena (192.168.100.x) y un DHCP posterior (asignación del bloque final de IPs según el rol).
  4. Seguridad Anti-spoofing mediante registros de **IP-MAC Binding**.
  5. Emisión del **Token de Rol** hacia el módulo M6.

### Esqueleto API REST (`app/modules/m1_auth/`)
Esta carpeta contiene una estructura base de una API en FastAPI (`router.py`, `service.py`, `models.py`). 
- **Estado actual:** Es un *stub* (código vacío o estructural). 
- **Propósito:** Se usará a futuro si se decide migrar la lógica del `portal_cautivo.py` hacia un entorno web (API RESTful) que permita conectar un frontend gráfico moderno.

---

## 2. Módulo 2: Políticas y Autorización (M2)

El Módulo M2 se encarga de definir qué recursos tiene permitidos cada usuario (rol) mediante el uso de políticas estructuradas, abandonando la antigua estructura en Python puro.

### Arquitectura Dockerizada (`app/modules/m2_policies/`)
Recientemente actualizado por completo, ahora funciona levantando sus propios servicios a través de **Docker Compose**:
- **`docker-compose.yaml`**: Orquesta el levantamiento del M2 y su base de datos.
- **OPA (Open Policy Agent)** (`opa/policy.rego`): Las reglas de acceso están ahora definidas usando el lenguaje Rego. Esto permite evaluar si un acceso está permitido o denegado de forma mucho más ágil y estandarizada.
- **Base de Datos Simplificada** (`db/init.sql`): Se incluye un script de inicialización para levantar una base de datos propia para M2.
- **Script de Sincronización** (`sync/sync.py`): Se encarga de sincronizar o exportar los datos requeridos por las políticas.
- **Pruebas y Documentación**:
  - `client.http`: Archivo para testear endpoints HTTP rápidamente.
  - `data_completo.json`: Archivo de datos estáticos para evaluación.
  - `input-output M2.md`: Documentación de las entradas y salidas de este nuevo flujo.

---

## 3. Base de Datos Principal

- **`logica_demo/radius_db_pucp_sdn.sql`**: Es el dump central de la base de datos principal (`radius_db`).
  - Recientemente actualizado y reestructurado.
  - Almacena toda la lógica de usuarios, políticas RBAC (Roles), historiales de sesión, y el diccionario de bindings (IP+MAC).

---

## 4. Otros Módulos y Utilidades

- **Módulo M6 (`app/modules/m6_translator/`)**: Encargado de recibir el "Token de Rol" desde el M1 y (presumiblemente) traducir esas directivas para instalarlas como flujos OpenFlow en el controlador SDN (ej. ONOS o Ryu).
- **Scripts de Despliegue**: Se cuenta con múltiples archivos auxiliares (`ansible/`, `docker/`, `scripts/`, `setup_ansible.py`, etc.) para facilitar la orquestación y el despliegue del entorno SDN en distintas máquinas virtuales.

---

### Resumen de la Ejecución
Si deseas ejecutar la validación de un usuario hoy en día:
1. Debes levantar la base de datos y el servidor FreeRADIUS.
2. Ejecutar `python logica_demo/portal_cautivo.py` para interactuar con la consola de login.
3. Para la parte de validación de reglas, debes levantar el M2 con `docker-compose up -d` dentro de la carpeta `app/modules/m2_policies/`.
