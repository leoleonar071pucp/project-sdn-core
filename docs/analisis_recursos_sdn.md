# Dimensionamiento de Recursos Computacionales - SDN Core

Este documento presenta el dimensionamiento técnico de la arquitectura SDN, estructurado específicamente para cumplir con los criterios de evaluación. Cada componente detalla sus recursos asignados, su plataforma y una justificación técnica basada en la carga de trabajo de las pruebas piloto y su proyección a nivel de producción.

---

## 1. Entorno de Laboratorio / Demo (Prueba Piloto)
Este entorno emulado (Mininet/OVS) busca probar la viabilidad técnica y los escenarios de prueba funcionales.
- **Carga de trabajo esperada:** 5 a 15 usuarios concurrentes emulados, con picos de hasta 50 dispositivos realizando solicitudes simultáneas.

### Tabla de Dimensionamiento - Nodos de Gestión, Control y Datos

| Identificador del Componente | Función en la Solución | SO / Plataforma | vCPU | RAM | Disco | Justificación de la Asignación (Carga de 50 usuarios) |
|---|---|---|:---:|:---:|:---:|---|
| **VM 1: Auth & Autho**<br>(M1, M2, RADIUS, MySQL) | Gestión de identidades, evaluación de políticas RBAC (OPA) y validación criptográfica de credenciales. | **Ubuntu 18.04 LTS**<br>+ Docker | **2** | **4 GB** | **8 GB** | **vCPU (2):** Paraleliza la lectura de MySQL y la evaluación OPA para que los 50 logins concurrentes no den *Timeout*.<br>**RAM (4GB):** MySQL necesita ~1GB para cachear tablas en memoria (evitando leer disco); Docker/OPA ocupan ~1GB. El resto previene crasheos del *OOM Killer*.<br>**Disco (8GB):** 3GB del SO + 4GB de imágenes Docker y BD. Es holgado y económico para un entorno de prueba. |
| **VM 2: Monitoreo y Detección**<br>(M3, M4, M5) | Inspección profunda de paquetes (DPI), detección de amenazas en tiempo real y recolección de logs (Auditoría). | **Ubuntu 18.04 LTS** | **2** | **4 GB** | **8 GB** | **vCPU (2):** 1 núcleo dedicado a "sniffear" la red sin perder paquetes, y 1 para analizar las anomalías detectadas.<br>**RAM (4GB):** Los procesos de indexación de logs (M5) consumen mucha memoria temporal como *buffer*. 1GB causaría fragmentación crítica.<br>**Disco (8GB):** Se reduce a 8GB ya que es un demo. El SO ocupa 3GB, dejando 5GB para capturas temporales (PCAP) de 50 usuarios en una prueba corta sin saturar la VM. |
| **Controlador SDN**<br>(ONOS) | Cerebro de la red. Descubre topología, calcula enrutamiento e instala flujos OpenFlow enviados por M6. | **Ubuntu 18.04 LTS**<br>JVM (Java) | **2** | **4 GB** | **8 GB** | **vCPU (2):** 1 hilo para mantener las 5 sesiones TCP OpenFlow y 1 para compilar rutas (Intent Framework).<br>**RAM (4GB):** ONOS (Java) exige una reserva dura mínima de 2GB (JVM Heap). Con menos, el recolector de basura bloquearía el controlador al 100% de CPU.<br>**Disco (8GB):** ONOS guarda la topología en memoria RAM, no en disco, por lo que 8GB para su instalación y el SO base sobran. |
| **Switches de Red**<br>(SW1 a SW5) | Plano de datos emulado. Conmutación de paquetes según reglas inyectadas por el controlador. | **Ubuntu 18.04 LTS**<br>Open vSwitch | **1** | **1 GB** | **3 GB** | **Recursos (1vCPU/1GB):** Open vSwitch delega la inteligencia al controlador. 1vCPU basta para consultar su tabla de flujos interna para el tráfico leve de 50 usuarios. 1GB evita paginación del SO.<br>**Disco (3GB):** Peso neto del SO CLI. |
| **Nodos Finales**<br>(H1 a H4, Servidores) | Emulación de dispositivos de usuario (alumnos) y servidores de recursos destino. | **Ubuntu 18.04 LTS**<br>(CLI) | **1** | **1 GB** | **3 GB** | **Recursos (1vCPU/1GB):** Máquinas ligeras para correr comandos simples (`ping`, `curl`, `ssh`). No requieren paralelismo ni almacenamiento pesado. |

---

## 2. Criterios de Escalabilidad: Entorno de Producción Universitario
Para evidenciar que la arquitectura puede evolucionar sin requerir cambios sustanciales en su diseño lógico, se proyecta el dimensionamiento hacia una red real de campus para **10,000 a 25,000 conexiones**. 

*(Nota: La lógica del código M1/M2/M6 se mantiene idéntica, solo escala el hardware subyacente de las máquinas).*

### Tabla de Proyección - Clúster de Producción

| Identificador del Componente | Función en la Solución | SO / Plataforma | vCPU | RAM | Disco | Justificación de Escalabilidad (Carga de 25k usuarios) |
|---|---|---|:---:|:---:|:---:|---|
| **Clúster Base de Datos**<br>(MySQL Galera) | Persistencia de sesiones, usuarios y políticas RBAC con alta disponibilidad. | **Linux Enterprise**<br>(RHEL / Ubuntu) | **16** | **64 GB** | **1 TB NVMe** | **vCPU (16):** Resuelve miles de transacciones paralelas a las 8:00 AM.<br>**RAM (64GB):** *InnoDB Buffer Pool* gigante para alojar las 25,000 cuentas de alumnos 100% en RAM, logrando validaciones en sub-milisegundos.<br>**Disco (1TB):** Discos NVMe con altísimo IOPS para registrar el gigantesco historial de sesiones y auditorías de la universidad. |
| **Clúster Lógica y Autho**<br>(M1, M2 OPA, RADIUS) | Criptografía EAP, motor de políticas OPA y API de Portal Cautivo. | **Linux Enterprise**<br>Kubernetes / Docker | **8** | **16 GB** | **50 GB** | **vCPU (8):** Balanceadores de carga y *workers* paralelos absorben la criptografía pesada de RADIUS para que no dropee solicitudes.<br>**RAM (16GB):** Almacena las reglas compiladas de la universidad en memoria (OPA) para respuesta ultra rápida. |
| **Monitoreo/Observabilidad**<br>(M3, M4, M5 Logs) | Ingesta masiva de syslogs (Elasticsearch) e inspección DPI. | **Linux Enterprise**<br>Elastic Stack | **24+** | **128 GB+** | **2 TB+ SSD** | **Recursos Masivos:** La ingesta analítica tipo *Big Data* en tiempo real exige memoria colosal para buscar patrones de ataques entre millones de líneas de log diarios y retenerlos por meses (cumplimiento legal). |
| **Clúster Controlador SDN**<br>(3 a 5 nodos ONOS) | Sincronización de estado global (Atomix) y cálculo de algoritmos SPF. | **Linux Enterprise**<br>JVM Cluster | **16**<br>*(c/u)* | **64 GB**<br>*(c/u)* | **250 GB**<br>*(c/u)* | **CPU/RAM:** El estado distribuido de toda la universidad (switches físicos, puntos de acceso, celulares) debe vivir replicado en la memoria de los 3 nodos. Si falta RAM, el crasheo *Out Of Memory* tumba el campus entero. |
| **Plano de Datos**<br>(Core y Distribución) | Conmutación de hardware y enrutamiento físico (Bare-metal). | **ONL / ArubaOS-CX**<br>Switches OpenFlow | **0** | **0** | **0** | **En producción, el plano de datos no gasta recursos de servidores.** Son equipos físicos dedicados con procesadores ASIC y memoria TCAM que reenvían a 40/100 Gbps sin tocar la CPU de la virtualización. |
