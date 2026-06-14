# Dimensionamiento SDN Core - Versión Presentación (PPT)

Tablas compactas de recursos optimizadas para diapositivas, incluyendo plataformas y alineadas con la rúbrica de evaluación.

---

## 1. Entorno de Laboratorio / Demo (Prueba Piloto: 50 Usuarios)

| Componente | Función | SO / Plataforma | vCPU | RAM | Disco | Justificación Rápida |
|---|---|---|:---:|:---:|:---:|---|
| **VM 1: Auth & Autho**<br>(M1, M2, RADIUS, DB) | Evaluar políticas OPA y validar logins criptográficos. | **Ubuntu 18.04**<br>+ Docker | **2** | **4 GB** | **8 GB** | **CPU/RAM:** Paraleliza procesos de MySQL y OPA para no generar *Timeouts* de login. Previene crasheos por *OOM Killer*. |
| **VM 2: Monitoreo**<br>(M3, M4, M5 Logs) | Sniffing de red y correlación/recolección de alertas. | **Ubuntu 18.04** | **2** | **4 GB** | **8 GB** | **CPU:** 1 núcleo para captura (evitando pérdida de paquetes) y 1 para analizar. **Disco:** 8GB es holgado para PCAPs de prueba corta. |
| **Controlador SDN**<br>(ONOS) | Cerebro: Descubre topología y enruta paquetes. | **Ubuntu 18.04**<br>+ Java (JVM) | **2** | **4 GB** | **8 GB** | **RAM:** Java exige reserva dura (2GB Heap). Menos memoria causaría *Garbage Collection* constante y lag en la red. |
| **Switches de Red**<br>(SW1 - SW5) | Plano de datos: reenvío de paquetes OpenFlow. | **Ubuntu 18.04**<br>+ OVS | **1** | **1 GB** | **3 GB** | **Recursos:** El enrutamiento se delega a ONOS. 1vCPU y 1GB sobra para que el switch opere sin paginar memoria al disco. |
| **Nodos Finales**<br>(Hosts / Servidores) | Clientes emulados que generan tráfico de prueba. | **Ubuntu 18.04**<br>(CLI) | **1** | **1 GB** | **3 GB** | Nodos zombies para comandos `ping`/`curl`. El mínimo soportado por Ubuntu Server sin fallar. |

---

## 2. Entorno de Producción Universitario (Escalabilidad: 25k Usuarios)

| Componente | Función | SO / Plataforma | vCPU | RAM | Disco | Justificación de Escalabilidad |
|---|---|---|:---:|:---:|:---:|---|
| **Clúster Base de Datos**<br>(MySQL) | Persistencia de sesiones, usuarios y RBAC. | **Linux Enterprise** | **16** | **64 GB** | **1 TB**<br>(NVMe) | **Escalabilidad:** Carga la tabla entera de 25k alumnos directamente en RAM (*Buffer Pool*) logrando respuestas en milisegundos. |
| **Clúster Lógica**<br>(M1, M2, RADIUS) | Criptografía y API de portal cautivo. | **Linux Enterprise**<br>+ K8s / Docker | **8** | **16 GB** | **50 GB** | **Escalabilidad:** Múltiples workers balanceados para absorber ráfagas masivas de Hashing (RADIUS) a las 8:00 AM. |
| **Monitoreo/Logs**<br>(M3, M4, M5) | Ingesta masiva de syslogs e inspección DPI. | **Linux Enterprise**<br>+ Elastic Stack | **24+** | **128 GB+** | **2 TB+**<br>(SSD) | **Escalabilidad:** Las bases analíticas *Big Data* (Elastic) exigen RAM masiva para buscar ataques en millones de registros. |
| **Controlador SDN**<br>(Clúster ONOS x3) | Sincronización del estado de red. | **Linux Enterprise**<br>+ JVM Cluster | **16**<br>*(c/u)* | **64 GB**<br>*(c/u)* | **250 GB**<br>*(c/u)* | **Escalabilidad:** Si falta memoria para el árbol de la topología distribuida, el crasheo *OOM* tumbaría la red del campus entero. |
| **Plano de Datos**<br>(Switches Core) | Conmutación de hardware (Bare-metal). | **Equipos Físicos**<br>(Aruba / Cisco) | **0** | **0** | **0** | **Escalabilidad:** Procesan a 40-100 Gbps por puerto mediante chips ASIC/TCAM físicos, sin usar virtualización. |
