# Análisis Cuantitativo de Recursos Hardware - SDN Core

Este documento presenta el dimensionamiento técnico de la arquitectura SDN. Las métricas (vCores, RAM, Almacenamiento) se fundamentan explicando exactamente **por qué** se requiere esa cantidad en función de la **cantidad de usuarios esperados**, y **por qué no más o menos**.

---

## 1. Entorno de Laboratorio / Demo (El "Slide")
Este entorno emulado (Mininet/OVS) busca probar la viabilidad técnica sin consumir recursos excesivos.

> **Capacidad Soportada (Estimación):** 
> - **Uso estándar:** 5 a 15 usuarios concurrentes emulados.
> - **Pico máximo:** Hasta 30-50 dispositivos emulados (hosts virtuales de Mininet) realizando *pings* o *curl* básicos antes de saturar el hipervisor.
> *Justificación general para esta escala:* Los recursos solicitados a continuación están calculados **exactamente para soportar estas 50 conexiones simultáneas sin crashear**. Pedir menos provocaría caídas durante la demo. Pedir más recursos sería un desperdicio injustificado para una prueba local donde no habrá tráfico humano real masivo.

### A. Plano de Gestión y Seguridad (VMs de Módulos)

| Máquina / Componentes | Recurso | Cantidad | Justificación Estricta (¿Por qué esto y no más/menos para 50 usuarios?) |
|---|---|:---:|---|
| **VM 1: Auth & Autho**<br>(MySQL, FreeRADIUS, Portal M1, M2 OPA, M6) | **vCores** | **2** | **¿Por qué 2?** Se requiere 1 núcleo dedicado para atender de manera síncrona las validaciones de base de datos MySQL y otro en paralelo para que OPA evalúe políticas al instante. **¿Por qué no menos (1)?** Si 50 usuarios intentan loguearse en el mismo segundo, MySQL bloquearía la CPU durante lecturas, causando que FreeRADIUS dé "Time out". **¿Por qué no más?** Con máximo 50 usuarios, la cola de procesamiento nunca será suficientemente larga para aprovechar un tercer o cuarto núcleo; estarían ociosos. |
| | **RAM** | **2 a 4 GB** | **¿Por qué 2-4 GB?** MySQL usa RAM para caché de tablas (buffer pool); Docker y OPA cargan datos en memoria. **¿Por qué no menos (1 GB)?** Con 1 GB existe alto riesgo de que actúe el *OOM Killer* (Out-Of-Memory Killer), apagando la BD súbitamente si los 50 usuarios inician sesión a la vez. **¿Por qué no más?** No manejaremos miles de conexiones simultáneas en la demo, por lo que más de 4 GB es RAM sobrante. |
| | **Disco** | **15 GB** | **¿Por qué 15 GB?** Ubuntu base (~3 GB), más imágenes Docker (~5 GB), más librerías Python y BD. Deja espacio seguro. **¿Por qué no menos?** Descargar nuevas imágenes Docker llenaría rápidamente el disco causando fallas del sistema operativo. **¿Por qué no más?** Con 50 usuarios de prueba, no se generarán históricos de logs masivos. |
| **VM 2: Monitoreo y Detección**<br>(M3, M4, MySQL, M5, M6) | **vCores** | **2** | **¿Por qué 2?** El monitoreo (M3/M4) inspecciona paquetes constantemente para detectar amenazas en tiempo real. Si 50 usuarios envían tráfico simultáneo, 1 núcleo lee los paquetes y el otro procesa las anomalías. **¿Por qué no menos?** Hacer captura (sniffing) y análisis en 1 solo núcleo causaría pérdida de paquetes, dejando escapar amenazas. **¿Por qué no más?** Con 50 hosts de prueba, 2 núcleos absorben la carga sin saturarse. |
| | **RAM** | **2 a 4 GB** | **¿Por qué 2-4 GB?** Procesar y organizar logs de auditoría (M5) antes de guardarlos requiere memoria RAM que actúe como un "buffer". **¿Por qué no menos?** Los procesos de recolección de logs podrían colapsar por falta de memoria al intentar clasificar megabytes de texto. **¿Por qué no más?** 50 usuarios no generarán los terabytes de registros que justificarían subir a 8 GB o más. |
| | **Disco** | **20 GB** | **¿Por qué 20 GB?** Capturar paquetes de red (PCAP) y mantener registros de los 50 usuarios requiere espacio de escritura. **¿Por qué no menos?** El disco podría llenarse al 100% en horas si la prueba de tráfico es continua, colgando el sistema. **¿Por qué no más?** Al ser un entorno de demo, los logs no necesitan guardarse indefinidamente, 20 GB es margen suficiente. |

### B. Plano de Control

| Máquina / Componentes | Recurso | Cantidad | Justificación Estricta (¿Por qué esto y no más/menos para 50 usuarios?) |
|---|---|:---:|---|
| **Controlador SDN**<br>(ONOS) | **vCores** | **2** | **¿Por qué 2?** ONOS tiene hilos que escuchan a los switches (OpenFlow) y otros que compilan reglas. **¿Por qué no menos?** Con 1 CPU, el enrutamiento se pondría en pausa mientras procesa nuevos flujos de los 50 hosts. **¿Por qué no más?** La topología es chica (5 switches) y 50 hosts. |
| | **RAM** | **4 GB** | **¿Por qué 4 GB?** La Máquina Virtual de Java (JVM) necesita una reserva fuerte de memoria (~2 GB fijos) sólo para arrancar ONOS de manera estable. **¿Por qué no menos?** El recolector de basura (*Garbage Collector*) consumiría el 100% del procesador intentando liberar espacio diminuto. **¿Por qué no más?** 50 usuarios no generarán el millón de flujos de red que justificarían saltar a 8 GB. |

---

## 2. Entorno de Producción (Escala Universitaria)
La emulación se reemplaza con clústeres reales.

> **Capacidad Soportada (Estimación):** 
> - **Uso estándar:** 10,000 a 15,000 conexiones simultáneas.
> - **Pico máximo:** 25,000 a 30,000 dispositivos (Ej. 8:00 AM al inicio de clases).
> *Justificación general para esta escala:* Los recursos empresariales solicitados a continuación están diseñados para el volumen masivo de una universidad. Subestimar recursos aquí causaría caídas de la red del campus completo. Sobredimensionar sin justificación sería un gasto excesivo en servidores.

### A. Plano de Gestión y Seguridad (Clusterizado)

| Componente | Recurso | Cantidad | Justificación Estricta (¿Por qué esto y no más/menos para 25k usuarios?) |
|---|---|:---:|---|
| **Base de Datos**<br>(MySQL Cluster) | **vCores** | **16** | **¿Por qué 16?** A las 8:00 AM, miles de alumnos inician sesión. Cada núcleo procesa cientos de estas validaciones criptográficas y bloqueos en la BD por segundo. **¿Por qué no menos?** Se generarían colas de espera eternas y el portal daría "Error 504 Gateway Timeout". |
| | **RAM** | **64 GB** | **¿Por qué 64 GB?** Para cargar la tabla entera de 25,000+ usuarios y sus políticas activas directamente en la RAM (*InnoDB Buffer Pool*). **¿Por qué no menos?** Si la RAM no alcanza, la BD tendrá que buscar en el disco magnético, ralentizando el login por varios segundos. **¿Por qué no más?** El diccionario de la universidad no suele sobrepasar el tamaño que entra en 64GB; irse a 128GB no aportaría mejora tangible. |
| | **Disco** | **1 TB (SSD NVMe)** | **¿Por qué 1 TB NVMe?** El historial de 25,000 usuarios iniciando/cerrando sesión y moviéndose entre antenas WiFi genera un registro brutal (Auditoría). **¿Por qué no menos/HDD?** Un HDD colapsaría por saturación de lectura/escritura física (IOPS). Menos capacidad implicaría borrar logs antes de tiempo (malas prácticas de auditoría). |
| **Lógica**<br>(FreeRADIUS, M1, M2 OPA) | **vCores** | **8** | **¿Por qué 8?** Desencriptar túneles TLS y hacer hash de contraseñas de miles de usuarios por minuto es trabajo puro de procesador matemático. **¿Por qué no menos?** El servidor RADIUS dropearía solicitudes. **¿Por qué no más?** 8 núcleos dedicados puros logran balancear cargas web (API/OPA) sin encarecer licenciamiento de software. |

### B. Plano de Control

| Componente | Recurso | Cantidad | Justificación Estricta (¿Por qué esto y no más/menos para 25k usuarios?) |
|---|---|:---:|---|
| **Clúster Controlador SDN**<br>(ONOS en 3 a 5 nodos) | **vCores** | **8 a 16**<br>*(Por nodo)* | **¿Por qué 8-16?** Los controladores SDN centrales en redes masivas calculan constantemente el camino más corto hacia 100+ switches si hay cambios físicos o de políticas de miles de estudiantes de forma reactiva. **¿Por qué no menos?** Un bucle o cambio repentino de flujos (Broadcast Storm) paralizaría la red. |
| | **RAM** | **32 a 64 GB**<br>*(Por nodo)* | **¿Por qué 32-64 GB?** ONOS guarda todos los nodos (celulares de 25k alumnos, switches de campus) en una base en RAM (Atomix). **¿Por qué no menos?** Falta de RAM causa crasheos *Out of Memory* en cascada, desconectando todo el campus universitario. **¿Por qué no más?** Porque ONOS utiliza un sistema de clúster escalado horizontalmente (es mejor sumar nodos de 64GB que tener un solo monstruo de 256GB). |

### Glosario Técnico Clave:
* **OOM Killer (Out-Of-Memory Killer):** Un guardia de seguridad interno del sistema operativo Linux. Cuando la RAM se agota, Linux escoge a los procesos más pesados (generalmente la Base de Datos o ONOS) y los "asesina" abruptamente para evitar un crasheo del sistema completo.
* **IOPS (Input/Output Operations Per Second):** Métrica que define qué tan rápido un disco puede leer y escribir. Crítico en bases de datos a escala de 25,000 usuarios.
