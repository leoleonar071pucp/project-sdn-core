# Análisis Cuantitativo de Recursos Hardware - SDN Core

Este documento presenta el dimensionamiento técnico de la arquitectura SDN. Las métricas (vCores, RAM, Almacenamiento) se fundamentan explicando exactamente **por qué** se requiere esa cantidad en función de la **cantidad de usuarios esperados**, detallando el **consumo interno de cada módulo**, y **por qué no más o menos**.

---

## 1. Entorno de Laboratorio / Demo (El "Slide")
Este entorno emulado (Mininet/OVS) busca probar la viabilidad técnica sin consumir recursos excesivos.

> **Capacidad Soportada (Estimación):** 
> - **Uso estándar:** 5 a 15 usuarios concurrentes emulados.
> - **Pico máximo:** Hasta 30-50 dispositivos emulados.

### A. Plano de Gestión y Seguridad (VMs de Módulos)

| Máquina | Recurso | Cantidad | Justificación y Desglose por Módulo interno (Para 50 usuarios) |
|---|---|:---:|---|
| **VM 1: Auth & Autho**<br>(MySQL, FreeRADIUS, Portal M1, M2 OPA, M6) | **vCores** | **2** | **Desglose de uso de CPU:**<br>- **0.5 vCore** para MySQL (I/O intensivo al validar credenciales).<br>- **0.5 vCore** para FreeRADIUS y Portal M1 (Criptografía y peticiones HTTP concurrentes).<br>- **0.8 vCore** para M2 (Docker Daemon y evaluación de OPA).<br>- **0.2 vCore** para Sistema Operativo y red.<br>**¿Por qué no 1?** Si 50 usuarios ingresan a la vez, MySQL bloquearía al Portal M1 si ambos compiten por 1 núcleo, dando *Timeout*. **¿Por qué no 4?** La cola de procesos para 50 usuarios es corta; 2 núcleos sobrarían. |
| | **RAM** | **4 GB** | **Desglose de uso de RAM:**<br>- **OS Base:** 512 MB.<br>- **MySQL:** 1024 MB (Para el *InnoDB Buffer Pool*, evitando leer el disco duro).<br>- **FreeRADIUS + Portal M1:** 512 MB (Workers de Python y demonio RADIUS).<br>- **M2 (Docker + OPA):** 1024 MB (OPA carga `data_completo.json` a la RAM para velocidad extrema).<br>- **Margen OOM:** 1024 MB libres para picos.<br>**Total = ~4 GB.** **¿Por qué no 1 GB?** El *OOM Killer* actuaría apagando MySQL súbitamente por falta de RAM. |
| | **Disco** | **15 GB** | **Desglose de Disco:**<br>- **OS Base:** 3 GB.<br>- **Imágenes Docker (M2):** 5 GB (Alpine, OPA, volúmenes temporales).<br>- **MySQL BD:** 2 GB (Datos estructurales y espacio pre-asignado).<br>- **Logs y M1:** 1 GB.<br>- **Margen libre:** 4 GB.<br>**¿Por qué no menos?** Descargar imágenes Docker trabaría el sistema operativo al llenarse el disco (100%). |
| **VM 2: Monitoreo y Detección**<br>(M3, M4, MySQL, M5, M6) | **vCores** | **2** | **Desglose de uso de CPU:**<br>- **1.0 vCore** para M3/M4 (Detección y Sniffing de red constante).<br>- **0.5 vCore** para M5 (Recolección y estructuración de logs).<br>- **0.5 vCore** para OS y MySQL local/réplica.<br>**¿Por qué no 1?** Hacer captura de paquetes de 50 hosts simulados en 1 hilo causaría pérdida de paquetes maliciosos (Blind spots). |
| | **RAM** | **4 GB** | **Desglose de uso de RAM:**<br>- **OS Base:** 512 MB.<br>- **M3/M4 (Monitoreo en memoria):** 1024 MB (Mantener estados de sesión y amenazas).<br>- **M5 (Buffer de Logs):** 1024 MB (Para no colapsar el I/O del disco).<br>- **MySQL:** 512 MB.<br>- **Margen libre:** ~1024 MB.<br>**¿Por qué no menos?** Clasificar texto de logs en tiempo real fragmentaría una memoria de solo 1 GB. |
| | **Disco** | **20 GB** | **Desglose de Disco:**<br>- **OS Base:** 3 GB.<br>- **Capturas PCAP (M3/M4):** 7 GB (El tráfico de red crudo ocupa gigabytes rápidamente).<br>- **Archivos de Auditoría (M5):** 5 GB.<br>- **Margen libre:** 5 GB.<br>**¿Por qué no menos?** El disco colapsaría al 100% tras unas pocas horas de pruebas continuas. |

### B. Plano de Control

| Máquina | Recurso | Cantidad | Justificación y Desglose por Módulo interno (Para 50 usuarios) |
|---|---|:---:|---|
| **Controlador SDN**<br>(ONOS) | **vCores** | **2** | **Desglose de uso de CPU:**<br>- **1 vCore** para el Servidor OpenFlow (mantener las sesiones TCP con 5 switches).<br>- **1 vCore** para el motor de Inteligencia (Cálculo Dijkstra y traductor M6).<br>**¿Por qué no 1?** Enviar flujos y escuchar eventos a la vez retrasaría los "pings" de los 50 usuarios. |
| | **RAM** | **4 GB** | **Desglose de uso de RAM:**<br>- **OS Base:** 512 MB.<br>- **JVM (Java Virtual Machine):** 2048 MB (Reserva dura requerida para ONOS `-Xms2G`).<br>- **Subsistemas Atomix:** 512 MB.<br>- **Margen libre:** ~1 GB.<br>**¿Por qué no menos?** ONOS entraría en ciclos constantes de *Garbage Collection* intentando liberar RAM, congelando el controlador. |

---

## 2. Entorno de Producción (Escala Universitaria)
La emulación se reemplaza con servidores reales para **10,000 a 25,000 dispositivos**.

### A. Plano de Gestión y Seguridad (Clusterizado)

| Componente | Recurso | Cantidad | Justificación y Desglose (Para picos de 25k usuarios) |
|---|---|:---:|---|
| **VM Base de Datos**<br>(MySQL Cluster) | **vCores** | **16** | **¿Por qué 16?** Cada inicio de sesión ejecuta ~4 validaciones (Bloqueos, Binding, Historial). 25k usuarios a las 8:00 AM implican miles de transacciones por segundo. 16 núcleos paralelizan estas colas. |
| | **RAM** | **64 GB** | **Desglose:**<br>- **InnoDB Buffer Pool:** 50 GB. Aloja la tabla total de 25k alumnos y profesores **íntegramente en la RAM**.<br>- **Conexiones activas:** 10 GB (Memoria por cada hilo de conexión).<br>**¿Por qué no 16 GB?** La BD tendría que leer las tablas del disco sólido físico (SSD), elevando la latencia de 1 ms a 15 ms, creando embotellamientos masivos. |
| | **Disco** | **1 TB NVMe** | **Desglose:**<br>- **Tablas maestras:** 50 GB.<br>- **Redo/Undo Logs:** 150 GB (Transaccionalidad).<br>- **Historial (Auditoría anual):** 700 GB.<br>**¿Por qué no menos/HDD?** Un disco mecánico tiene ~150 IOPS. Necesitamos SSD NVMe (>50,000 IOPS) para grabar historial de red a velocidad extrema. |
| **VM Lógica Central**<br>(FreeRADIUS, M1, M2) | **vCores** | **8** | **Desglose:**<br>- **FreeRADIUS:** 4 vCores (Exclusivo para algoritmos de Hashing MD5/SHA y túneles EAP).<br>- **Portal M1 + M2 (OPA):** 4 vCores (Workers web y evaluación de políticas en JSON). |
| | **RAM** | **16 GB** | **Desglose:**<br>- **Workers Web (Gunicorn/FastAPI):** 4 GB.<br>- **Diccionario de M2 en RAM:** 8 GB.<br>**¿Por qué no menos?** Procesos paralelos compitiendo por RAM terminarían *dropeando* solicitudes HTTP de los estudiantes. |

### B. Plano de Control

| Componente | Recurso | Cantidad | Justificación y Desglose (Para picos de 25k usuarios) |
|---|---|:---:|---|
| **Nodos Controlador**<br>(Ej. 3 x ONOS) | **vCores** | **16**<br>*(Por nodo)* | **Desglose:**<br>- **Procesamiento de Packet-In:** 8 vCores. 25k dispositivos moviéndose por el campus generan miles de paquetes "nuevos" hacia el controlador.<br>- **Algoritmos de red:** 8 vCores para recalcular caminos si un switch de fibra cae. |
| | **RAM** | **64 GB**<br>*(Por nodo)* | **Desglose:**<br>- **JVM Heap Size:** 48 GB fijos para almacenar 1 millón+ de Flow Rules en memoria.<br>- **Base Atomix:** 12 GB para sincronización entre los 3 controladores.<br>**¿Por qué no menos?** Falta de RAM genera un fallo en cascada (crash-loop) que apagará el WiFi/red cableada en toda la universidad. |

### Glosario Técnico Clave:
* **OOM Killer (Out-Of-Memory Killer):** Un guardia del kernel de Linux. Cuando la RAM se agota, elige a los procesos más pesados (MySQL, Docker, ONOS) y los "asesina" abruptamente para evitar un crasheo general.
* **InnoDB Buffer Pool:** La porción de memoria RAM que MySQL secuestra para cachear datos. El secreto de una red rápida es que este parámetro sea tan grande que MySQL casi no use el disco duro para lecturas.
* **IOPS (Input/Output Operations Per Second):** Medida de velocidad de lectura/escritura. Las BD de producción (como el M5 o el M1) requieren almacenamiento NVMe para no colapsar.
