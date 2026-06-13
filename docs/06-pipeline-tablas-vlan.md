# Pipeline de OpenFlow (Enfoque Híbrido con VLANs)

Este documento detalla cómo se estructuran las tablas de flujo (*Flow Tables*) en los switches de acceso (borde) combinando la lógica de **VLANs** (del diseño original) con la arquitectura moderna **híbrida** (proactiva/reactiva) de 5 tablas.

## Concepto General

El objetivo de este diseño es:
1. **Disfrazar al tráfico:** Asignar una etiqueta VLAN a los paquetes dependiendo de si el usuario está en cuarentena (VLAN 90) o si ya se autenticó (VLAN 210, 300, etc.). Esto se hace en la primera tabla.
2. **Proteger el Switch (Enfoque Híbrido):** No llenar la memoria del switch (TCAM) con reglas inactivas. Las reglas de acceso a recursos tienen un tiempo de expiración (`idle_timeout`). Si el usuario deja de usarlas, se borran solas y se vuelven a pedir al controlador (ONOS) solo cuando se necesitan.

---

## El Viaje Inicial: Asignación de IP (DHCP)

Antes de que el usuario pueda hacer nada, necesita una IP. Como el servidor DHCP vive dentro de ONOS, este es el flujo inicial (Momento 0):

1. El usuario conecta su PC y envía un **DHCP Discover** (UDP al puerto 67) a la red. El paquete llega sin etiqueta VLAN.
2. En la **Tabla 1**, el switch ve que no tiene VLAN y le asigna la **VLAN 90** (Cuarentena).
3. En la **Tabla 2**, el switch tiene una regla proactiva (fija) que dice: *"Todo paquete VLAN 90 que vaya al puerto UDP 67, mándalo al Controlador"*.
4. El paquete llega a ONOS (vía *Packet-In*). La app DHCP de ONOS lo recibe y le ofrece una IP de cuarentena (ej. `192.168.100.45`).

A partir de ahí, la PC del usuario tiene IP, pero todo su tráfico está etiquetado con la VLAN 90 por el switch.

---

## Estructura de Tablas (Pipeline)

### Tabla 0 (T0): Seguridad Perimetral
**Propósito:** Detener amenazas de forma inmediata antes de procesar reglas complejas.

| Prioridad | Match (Condición) | Acciones (Instructions) | Idle_timeout | Motivo |
| :--- | :--- | :--- | :--- | :--- |
| **50000** | `dl_src=00:11:22...` | `clear_actions()` (DROP) | `3600` | MAC atacando detectada por seguridad. |
| **0** | *(Cualquier otro)* | `goto_table(1)` | `0` (Fija) | Tráfico limpio pasa a T1. |

### Tabla 1 (T1): Identidad (Etiquetado VLAN)
**Propósito:** Poner la etiqueta correcta al paquete. Es la única tabla que modifica el paquete (`SET_FIELD`). M1 (Autenticación) es el dueño de esta tabla.

| Prioridad | Match (Condición) | Acciones (Instructions) | Hard_timeout | Motivo |
| :--- | :--- | :--- | :--- | :--- |
| **1000** | `dl_src=AA:BB...` | `apply(set_vlan=210), goto(2)` | `28800` (8h) | Sesión de **Estudiante** válida. |
| **1000** | `dl_src=FF:EE...` | `apply(set_vlan=300), goto(2)` | `36000` (10h)| Sesión de **Docente** válida. |
| **10** | `vlan_vid=none` | `apply(set_vlan=90), goto(2)` | `0` (Fija) | **Regla Base:** Equipo nuevo entra a Cuarentena. |

> **Nota:** Se usa `hard_timeout` en las sesiones validadas para forzar que el acceso expire sí o sí cuando se acabe el tiempo de sesión dictado por FreeRADIUS (ej. 8 horas), obligando a un nuevo login.

### Tabla 2 (T2): Accesos Macro (Híbrida)
**Propósito:** Definir qué recursos se pueden alcanzar según la VLAN. Aquí conviven reglas **Proactivas** (fijas) para recursos básicos y reglas **Reactivas** (con `idle_timeout`) para accesos específicos que se instalan al iniciar sesión.

| Prioridad | Match (Condición) | Acciones (Instructions) | Idle_timeout | Tipo | Motivo |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **500** | `vlan=90, udp, tp_dst=67` | `apply(output:CONTROLLER)`| `0` | Proactiva | Permitir tráfico DHCP. |
| **400** | `vlan=90, nw_dst=10.0.0.10`| `apply(output:PORTAL)` | `0` | Proactiva | Permitir ir al Portal Cautivo. |
| **200** | `vlan=210, nw_dst=10.0.0.21`| `apply(output:NORMAL)` | **`300` (5m)** | Reactiva | **Estudiantes** a Cursos. |
| **200** | `vlan=300, nw_dst=10.0.0.30`| `apply(output:NORMAL)` | **`300` (5m)** | Reactiva | **Docentes** a Notas. |
| **0** | *(Cualquier otro)* | `goto_table(3)` | `0` | Proactiva | Lo no resuelto pasa a T3. |

> **La Magia del Timeout (5 minutos):** Si el estudiante deja de entrar a Cursos por 5 minutos, la regla se borra sola del switch para ahorrar memoria. Si luego vuelve a entrar, el switch no sabrá qué hacer, enviará el paquete a ONOS (T4), OPA dirá que sí tiene permiso, y ONOS reinstalará la regla de forma transparente.

### Tabla 3 (T3): Denegaciones y Excepciones
**Propósito:** Mantener limpia la T2 aislando los bloqueos explícitos o permisos muy temporales.

| Prioridad | Match (Condición) | Acciones (Instructions) | Idle_timeout | Motivo |
| :--- | :--- | :--- | :--- | :--- |
| **300** | `vlan=210, nw_dst=10.0.0.30` | `clear_actions()` (DROP) | **`300` (5m)**| Estudiante bloqueado a Notas (Dictado por OPA). |
| **0** | *(Cualquier otro)* | `goto_table(4)` | `0` | Pasa a T4. |

### Tabla 4 (T4): Table-Miss (Bajo Demanda)
**Propósito:** Enviar al cerebro (ONOS) el tráfico que no hizo match con ninguna regla anterior.

| Prioridad | Match (Condición) | Acciones (Instructions) | Motivo |
| :--- | :--- | :--- | :--- |
| **0** | *(Cualquier otro)* | `apply(output:CONTROLLER)` | Enviar Packet-In a ONOS para evaluación (OPA decide). |

---

## Resumen del Flujo de Usuario

1. **Conexión:** PC conecta -> No tiene IP -> Switch le pone VLAN 90 (T1) -> Envía DHCP a ONOS (T2) -> Recibe IP de cuarentena `192.168.100.X`.
2. **Navegación bloqueada:** PC intenta ir a Google -> T1 le pone VLAN 90 -> T2 no tiene regla de internet para VLAN 90 -> T3 tampoco -> T4 lo manda a ONOS -> ONOS bloquea/redirecciona al Portal.
3. **Login:** PC va a Portal Cautivo (`10.0.0.10`) -> T1 pone VLAN 90 -> T2 sí tiene regla para el Portal -> Login Exitoso.
4. **Liberación:** M1 avisa a ONOS -> ONOS instala regla en T1: *"MAC AA:BB ahora es VLAN 210"*.
5. **Acceso:** PC va a Cursos (`10.0.0.21`) -> T1 le pone VLAN 210 -> T2 dice *"VLAN 210 a Cursos, pasa"*. (Si la regla expira, se repide vía T4).
