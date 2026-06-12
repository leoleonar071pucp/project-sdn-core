# Dimensionamiento SDN Core - Versión Presentación (PPT)

Este documento contiene las tablas de recursos resumidas para uso directo en diapositivas. Mantiene el sustento técnico pero en un formato *bullet-point* rápido de leer.

---

## 1. Entorno de Laboratorio / Demo (50 Usuarios Max)

### A. Plano de Gestión y Seguridad (VMs)

| Componente | Recurso | Cantidad | Justificación Breve |
|---|---|:---:|---|
| **VM 1: Auth & Autho**<br>(MySQL, RADIUS, M1, M2) | **vCores** | **2** | Necesarios para paralelismo: MySQL (0.5), FreeRADIUS/M1 (0.5), Docker/OPA (0.8). *Menos de 2 causaría Timeouts en logins simultáneos.* |
| | **RAM** | **4 GB** | OS (0.5GB), Buffer de MySQL (1GB), RADIUS/M1 (0.5GB), Docker/OPA (1GB). *Margen extra de 1GB para evitar crasheos por OOM Killer.* |
| | **Disco** | **15 GB** | Sistema Base (3GB) + Imágenes Docker (5GB) + BD/Logs. *Evita que el sistema colapse al llegar al 100% descargando contenedores.* |
| **VM 2: Monitoreo**<br>(M3, M4, M5, MySQL) | **vCores** | **2** | Inspección de red (1.0) y estructuración de logs (0.5). *Un solo núcleo causaría pérdida de paquetes maliciosos durante el sniffing.* |
| | **RAM** | **4 GB** | Buffer en memoria para indexar los Logs de Auditoría (1GB) y reglas de M3/M4 (1GB). *1 GB total fragmentaría la memoria y colapsaría el monitoreo.* |
| | **Disco** | **20 GB** | Necesario para escribir Capturas de Red crudas (PCAP) y Logs constantes. *Suficiente para pruebas sin saturar la VM.* |

### B. Plano de Control

| Componente | Recurso | Cantidad | Justificación Breve |
|---|---|:---:|---|
| **Controlador SDN**<br>(ONOS) | **vCores** | **2** | Hilos separados para Sesiones OpenFlow (1.0) y Algoritmo de Enrutamiento (1.0). *1 núcleo generaría lag (ping alto) al recalcular rutas.* |
| | **RAM** | **4 GB** | ONOS (Java) exige una reserva rígida de 2GB (JVM Heap). *Con menos memoria, el recolector de basura bloquearía el controlador SDN al 100% CPU.* |

### C. Plano de Datos y Nodos Finales (Emulados)

| Componente | Recurso | Cantidad | Justificación Breve |
|---|---|:---:|---|
| **Switches y Hosts**<br>(SW1-SW5, H1-H4) | **vCores** | **1** | Open vSwitch y comandos simples (ping/curl) operan rápido. *Suficiente para pruebas; no requieren paralelismo.* |
| | **RAM** | **1 GB** | Cumple el límite mínimo del SO base Ubuntu CLI. *Evita lentitud del sistema operativo.* |
| | **Disco** | **3 GB** | Peso real de la instalación base sin interfaz gráfica. |

---

## 2. Entorno de Producción Universitario (25,000 Usuarios Max)

### A. Plano de Gestión y Seguridad (Cluster)

| Componente | Recurso | Cantidad | Justificación Breve |
|---|---|:---:|---|
| **Base de Datos**<br>(MySQL Cluster) | **vCores** | **16** | Paraleliza miles de bloqueos, lecturas y escrituras por segundo generadas a las 8:00 AM. *Previene colas de espera eternas en el portal.* |
| | **RAM** | **64 GB** | Carga la tabla total de 25k usuarios directo en RAM (*InnoDB Buffer Pool*). *Multiplica la velocidad de login; evita leer discos mecánicos.* |
| | **Disco** | **1 TB (NVMe)** | Requiere SSD NVMe (>50,000 IOPS) para grabar historial de red intensivo. *Un HDD estándar colapsaría el rendimiento de toda la auditoría.* |
| **Lógica Central**<br>(RADIUS, M1, M2) | **vCores** | **8** | Dedicados para algoritmos criptográficos (Hashing/Túneles) y evaluación JSON veloz. *Previene que RADIUS rechace peticiones por sobrecarga.* |
| | **RAM** | **16 GB** | Soporta múltiples procesos paralelos (Workers Python) y reglas OPA cacheadas. |

### B. Plano de Control

| Componente | Recurso | Cantidad | Justificación Breve |
|---|---|:---:|---|
| **Nodos Controlador**<br>(Clúster ONOS x3) | **vCores** | **16**<br>*(c/u)* | Requiere potencia brutal para procesar tormentas de *Packet-In* y recalcular de forma reactiva la topología entera del campus. |
| | **RAM** | **64 GB**<br>*(c/u)* | **48 GB exclusivos para la JVM**. Almacena la tabla de flujos global y bases de sincronización (Atomix). *Evita caídas en cascada que tumbarían el WiFi de la universidad.* |

### C. Plano de Datos (Nodos Físicos)
*A escala de producción, los Switches (SW) ya no son máquinas virtuales, sino hardware de red físico (Ej. equipos Edgecore o Aruba con soporte OpenFlow).*
- **Consumo de Servidor:** 0 vCores, 0 RAM.
- **Razón:** El tráfico se procesa por hardware dedicado en el switch a nivel electrónico (ASICs / Memoria TCAM) a velocidades de 10 a 40 Gbps, por lo que no usan la CPU ni la RAM de tus servidores.
