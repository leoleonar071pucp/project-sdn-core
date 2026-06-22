# Estrategia de Monitoreo Dinámico, Detección y Mitigación

## 1. Objetivo

Este documento define la estrategia de seguridad para detectar y mitigar ataques dentro de la red SDN sin inspeccionar permanentemente el 100 % del tráfico ni sobrecargar al controlador ONOS, a los switches OVS o a la VM de seguridad.

La solución utiliza un modelo de **Radar y Microscopio**:

- El **Radar** observa eventos `Packet-In`, decisiones de política, contadores OpenFlow y muestras sFlow/NetFlow.
- El **Microscopio** activa captura profunda con Port Mirroring y Suricata únicamente cuando existe una sospecha concreta.
- La **Mitigación** se ejecuta mediante M6, que solicita a ONOS la instalación de reglas `DROP` de alta prioridad en la Tabla 0.

La estrategia complementa el pipeline híbrido T0–T4 descrito en `06-pipeline-tablas-vlan.md`.

## 2. Principio de operación

No todo `Packet-In` representa un ataque. Un evento puede producirse porque:

- No existe una regla para el tráfico.
- Una regla reactiva expiró.
- El usuario intenta acceder a un recurso no permitido.
- Existe una combinación IP/MAC inválida.
- El switch o el controlador acaba de reiniciarse.
- Se trata de tráfico normal de descubrimiento, ARP o DHCP.

Por esta razón, M6 no debe bloquear únicamente por contar eventos. La detección debe considerar el resultado de M2, la identidad del host y la diversidad de destinos o puertos intentados.

## 3. Responsabilidades de los componentes

### 3.1. Switch OVS

- Ejecuta el pipeline OpenFlow T0–T4.
- Envía un `Packet-In` a ONOS cuando el tráfico alcanza la regla `table-miss`.
- Mantiene contadores de paquetes y bytes en los flows.
- Puede generar muestras sFlow o resúmenes NetFlow.
- Puede crear un mirror temporal mediante OVSDB.

### 3.2. ONOS

- Recibe el `Packet-In` desde OVS.
- Extrae los datos mínimos del paquete y del punto de conexión.
- Invoca a M6 cuando el paquete requiere una decisión reactiva.
- Recibe de M6 la solicitud de instalación o eliminación de flows.
- Es el único componente que programa las tablas OpenFlow de los switches.

ONOS no envía el paquete completo a M6. Debe enviar solamente la información necesaria para decidir:

```json
{
  "device_id": "of:000072e0807e854c",
  "in_port": 2,
  "src_mac": "00:11:22:33:44:55",
  "src_ip": "10.2.1.105",
  "dst_ip": "10.0.0.30",
  "ip_proto": "TCP",
  "dst_port": 443,
  "vlan_id": 210,
  "timestamp": "2026-06-22T10:20:30Z"
}
```

### 3.3. M6: decisión reactiva y actuación

M6 recibe la consulta de ONOS y realiza las siguientes acciones:

1. Valida que existan una sesión activa y un binding coherente entre MAC, IP, switch y puerto.
2. Identifica al usuario y sus roles.
3. Consulta a M2/OPA para conocer si el acceso al recurso está permitido.
4. Devuelve la decisión a ONOS.
5. Si M2 permite el acceso, M6 solicita a ONOS instalar el flow correspondiente.
6. Si M2 deniega el acceso, M6 registra el intento para el análisis de seguridad.
7. Si se supera un umbral de riesgo, M6 genera un evento para M4.

M6 continúa siendo el único módulo del core autorizado para comunicarse con la API REST de ONOS. M6 no ejecuta directamente comandos `ovs-vsctl` sobre los switches.

### 3.4. M2/OPA

- Decide si el usuario puede acceder al recurso.
- Evalúa roles, excepciones temporales y denegaciones.
- Devuelve una decisión `ALLOW` o `DENY`.
- No decide por sí solo si el comportamiento constituye un ataque.

### 3.5. M4: correlación de seguridad

- Recibe alertas agregadas de M6.
- Recibe anomalías volumétricas del colector sFlow/NetFlow.
- Recibe alertas `EVE JSON` de Suricata.
- Calcula la severidad del incidente.
- Ordena vigilancia, contención temporal o bloqueo confirmado.

### 3.6. Gestor de telemetría

El mirroring pertenece a la infraestructura OVSDB y no a las tablas OpenFlow. Por ello debe existir un gestor de telemetría separado, aunque inicialmente pueda desplegarse dentro de la VM de seguridad.

Sus responsabilidades son:

- Crear y eliminar mirrors por OVSDB.
- Crear o reutilizar túneles GRE/ERSPAN.
- Mantener un identificador único por incidente.
- Aplicar un TTL a cada mirror.
- Eliminar únicamente el mirror asociado al incidente.

### 3.7. M5/PostgreSQL

- Conserva incidentes, decisiones y mitigaciones.
- Permite reconstruir qué usuario, dispositivo y flujo originaron una alerta.
- Almacena el estado persistente que no debe depender de la memoria local de M6.

## 4. Flujo reactivo ONOS–M6–M2

El flujo esperado cuando no existe una regla activa es:

```text
Host
  |
  v
Switch OVS (T4 table-miss)
  |
  | Packet-In
  v
ONOS
  |
  | Consulta reactiva
  v
M6
  |
  | Consulta de política
  v
M2 / OPA
  |
  | ALLOW o DENY
  v
M6
  |
  | Instalar flow, denegar o alertar
  v
ONOS
  |
  v
Switch OVS
```

Se propone que M6 exponga un endpoint específico:

```http
POST /m6/packet-in
```

Ejemplo de respuesta permitida:

```json
{
  "decision": "ALLOW",
  "install_flow": true,
  "table_id": 2,
  "idle_timeout": 300,
  "risk_score": 0
}
```

Ejemplo de respuesta denegada:

```json
{
  "decision": "DENY",
  "install_flow": false,
  "risk_score": 35,
  "reason": "denegado_por_politica"
}
```

## 5. Detección temprana en M6

M6 mantiene una ventana deslizante temporal por identidad de red. La clave recomendada es:

```text
(src_mac, src_ip, device_id, in_port)
```

Cada evento denegado debe registrar como mínimo:

- Timestamp.
- Usuario y rol, si existen.
- MAC e IP de origen.
- Switch y puerto de entrada.
- IP y puerto de destino.
- Resultado de M2.
- Resultado de la validación anti-spoofing.

### 5.1. Indicadores de riesgo

M6 puede incrementar una puntuación de riesgo cuando detecte:

| Evento | Ejemplo de puntuación |
|---|---:|
| Acceso denegado aislado | +1 |
| Binding IP/MAC/puerto inválido | +40 |
| Más de 10 destinos distintos en 5 segundos | +25 |
| Más de 20 puertos distintos en un destino | +35 |
| Más de 50 denegaciones en 10 segundos | +40 |
| Reincidencia durante una contención | +50 |

Los valores son iniciales y deben calibrarse mediante pruebas.

### 5.2. Respuestas por nivel

| Riesgo | Acción |
|---|---|
| 0–19 | Registrar únicamente |
| 20–49 | Alertar a M4 y aumentar observación |
| 50–79 | Activar mirror focalizado y contención temporal |
| 80–100 | Bloqueo inmediato en T0 y análisis posterior |

Una IP/MAC inválida o una señal crítica puede provocar contención inmediata sin esperar la inspección de Suricata.

### 5.3. Estado temporal

Para la demostración, la ventana puede implementarse con un diccionario en memoria protegido por un lock y con expiración de entradas.

Para múltiples réplicas o un despliegue persistente debe utilizarse Redis u otro almacén temporal compartido. Los incidentes confirmados se guardan en PostgreSQL.

## 6. Radar de tráfico

### 6.1. Eventos reactivos y decisiones de M2

Esta fuente observa tráfico que no posee un flow activo. Es útil para detectar:

- Escaneo de puertos.
- Enumeración de servidores.
- Intentos repetidos contra recursos prohibidos.
- Suplantación IP/MAC.
- Movimiento lateral no autorizado.

No permite observar continuamente el tráfico que ya está autorizado por una regla instalada.

### 6.2. Estadísticas OpenFlow

M6 o M4 pueden consultar los contadores de flows mediante la API REST de ONOS:

```bash
curl -u onos:rocks \
  http://<IP_ONOS>:8181/onos/v1/flows/of:0000000000000001
```

Estos contadores permiten detectar reglas con crecimiento anormal de paquetes o bytes sin copiar los paquetes completos.

### 6.3. sFlow

sFlow complementa los `Packet-In` porque también observa tráfico permitido que el switch procesa sin consultar al controlador.

Ejemplo de configuración OVS:

```bash
sudo ovs-vsctl \
  -- --id=@sflow create sFlow \
  agent=eth0 \
  target=\"192.168.100.50:6343\" \
  header=128 \
  sampling=1000 \
  polling=10 \
  -- set Bridge sw_borde sflow=@sflow
```

La tasa `sampling=1000` es un punto de partida. Debe ajustarse según el volumen de la maqueta.

### 6.4. NetFlow

NetFlow proporciona resúmenes por conversación y resulta útil para analizar volumen, duración y pares origen/destino.

```bash
sudo ovs-vsctl \
  -- set Bridge sw_borde netflow=@nf \
  -- --id=@nf create NetFlow \
  targets=\"192.168.100.50:2055\" \
  active-timeout=60
```

Para el MVP se recomienda seleccionar **sFlow o NetFlow**, no implementar ambos simultáneamente. sFlow es la primera opción para detectar picos y escaneos agresivos en tiempo cercano al real.

## 7. Microscopio: mirroring bajo demanda

El Port Mirroring se activa únicamente después de detectar una anomalía.

El alcance debe elegirse en este orden:

1. Puerto físico del sospechoso.
2. Puerto físico más VLAN.
3. VLAN completa solamente cuando no sea posible aislar el origen.

Esto evita copiar el tráfico de usuarios no relacionados con el incidente.

### 7.1. Túnel hacia la VM de seguridad

Para switches alejados del sensor puede utilizarse un túnel GRE:

```bash
sudo ovs-vsctl add-port sw_borde tun_seguridad \
  -- set Interface tun_seguridad \
  type=gre \
  options:remote_ip=<IP_VM_SEGURIDAD>
```

Cuando la plataforma lo permita, ERSPAN es preferible porque facilita conservar información sobre la procedencia de la captura.

La MTU, fragmentación, offloading y conservación de etiquetas VLAN deben verificarse experimentalmente. No debe asumirse que todo túnel conserva automáticamente evidencia perfecta.

### 7.2. Mirror por incidente

Cada mirror debe tener un nombre único:

```text
mirror_inc_<id_incidente>
```

Ejemplo conceptual:

```bash
sudo ovs-vsctl \
  -- --id=@p get Port tun_seguridad \
  -- --id=@m create Mirror \
  name=mirror_inc_1042 \
  select-src-port=<PUERTO_ORIGEN> \
  select-dst-port=<PUERTO_ORIGEN> \
  output-port=@p \
  -- add Bridge sw_borde mirrors @m
```

La sintaxis exacta depende de cómo estén nombrados los objetos `Port` en OVSDB.

### 7.3. Limpieza segura

No debe utilizarse:

```bash
ovs-vsctl clear Bridge sw_borde mirrors
```

Ese comando elimina todos los mirrors del bridge y puede interrumpir investigaciones simultáneas.

El gestor de telemetría debe buscar y eliminar únicamente `mirror_inc_<id_incidente>`. También debe ejecutar una limpieza automática al vencer el TTL, incluso si M4 o Suricata dejan de responder.

## 8. Inspección con Suricata

Suricata analiza el tráfico recibido por el mirror y genera alertas `EVE JSON`.

Puede aportar:

- Firmas de ataques conocidos.
- Metadatos de protocolos.
- Indicadores TLS y SNI.
- Patrones de escaneo o malware.
- Payload cuando el protocolo no está cifrado.

Suricata no puede garantizar la lectura del contenido de HTTPS sin descifrado TLS. Por ello, una exfiltración cifrada debe evaluarse combinando volumen, destino, horario, duración y alertas de protocolo.

### 8.1. Directriz de inspección híbrida

Suricata no debe permanecer completamente aislado del tráfico hasta que M4
detecte una anomalía. Un único payload malicioso enviado mediante una conexión
permitida puede:

- No generar un `Packet-In`.
- No producir suficiente volumen para sFlow o NetFlow.
- No ser observado por M6.
- No activar el mirror dinámico.

En ese escenario, un modelo exclusivamente reactivo perdería el ataque. Por
esta razón se adopta como directriz oficial una inspección híbrida:

```text
Recursos críticos → mirror permanente ───────────────┐
                                                     ├→ Suricata → M4
Tráfico general → M6/sFlow → mirror bajo demanda ───┘
```

Suricata permanece ejecutándose. Lo que cambia dinámicamente es el tráfico que
recibe.

#### Inspección permanente

Debe aplicarse a los recursos cuyo compromiso tenga mayor impacto:

- Portal cautivo.
- FreeRADIUS y servicios de autenticación.
- Servidor de notas.
- Panel administrativo.
- Bases de datos críticas.
- Servicios públicos expuestos.

Los mirrors permanentes deben configurarse por puerto o destino crítico,
evitando copiar VLANs completas cuando no sea necesario.

#### Inspección dinámica

Se utiliza para:

- Tráfico general de usuarios.
- Servidores académicos no críticos.
- Hosts que presentan ráfagas de denegaciones.
- Anomalías detectadas por sFlow o NetFlow.
- Hosts que M4 coloca en estado `WATCHING`.

M4 activa un mirror focalizado con TTL y el gestor de telemetría lo elimina al
finalizar la ventana de investigación.

#### Límites del enfoque

- Un ataque único contra un recurso no crítico puede escapar si no produce
  otra señal observable.
- El muestreo sFlow reduce visibilidad y no garantiza capturar un paquete
  concreto.
- Suricata no inspecciona normalmente el contenido cifrado de HTTPS.
- Los servicios críticos también deben protegerse mediante WAF, registros de
  aplicación, HIDS o EDR cuando corresponda.

La inspección permanente de recursos críticos y la inspección dinámica del
resto equilibran cobertura y consumo de recursos.

## 9. Flujos de seguridad

### 9.1. Port scan contra recursos prohibidos

1. El atacante intenta acceder a múltiples puertos o servidores.
2. El tráfico llega a T4 y OVS genera `Packet-In`.
3. ONOS consulta a M6.
4. M6 consulta a M2 y recibe varias decisiones `DENY`.
5. La ventana deslizante detecta diversidad anormal de puertos o destinos.
6. M6 envía a M4 un evento agregado, no un evento HTTP por cada paquete.
7. M4 ordena una contención temporal o activa un mirror focalizado.
8. Si el riesgo es crítico, M4 llama a `/m6/mitigacion`.
9. M6 solicita a ONOS instalar un `DROP` temporal en T0.
10. M5 registra el incidente y el gestor elimina el mirror al finalizar.

### 9.2. Tráfico permitido con volumen anormal

1. Un usuario autenticado posee un flow `ALLOW`.
2. El switch procesa el tráfico sin generar `Packet-In`.
3. sFlow o NetFlow detecta un crecimiento anormal de volumen.
4. El colector envía la anomalía a M4.
5. M4 relaciona IP/MAC con la sesión activa.
6. Se activa un mirror del puerto concreto del usuario.
7. Suricata aporta metadatos o firmas adicionales.
8. M4 decide si mantiene observación, limita o bloquea.
9. M6 aplica la mitigación mediante ONOS.

### 9.3. Suplantación IP/MAC

1. M1 registra el binding válido de usuario, MAC, IP, switch y puerto.
2. El pipeline instala reglas que esperan esa identidad.
3. Un paquete con combinación inválida no coincide con la regla de sesión.
4. OVS genera `Packet-In` y ONOS consulta a M6.
5. M6 compara el origen con `ip_mac_binding` y `sesiones_activas`.
6. Si existe inconsistencia, aumenta el riesgo y alerta a M4.
7. Para una violación inequívoca puede aplicarse contención inmediata en T0.

## 10. Contratos propuestos

### 10.1. Evento agregado de M6 hacia M4

```json
{
  "event_type": "policy_denial_burst",
  "src_mac": "00:11:22:33:44:55",
  "src_ip": "10.2.1.105",
  "device_id": "of:000072e0807e854c",
  "in_port": 2,
  "denials": 52,
  "unique_destinations": 14,
  "unique_ports": 31,
  "window_seconds": 10,
  "risk_score": 78
}
```

### 10.2. Directiva de M4 hacia M6

El endpoint actual `/m6/mitigacion` puede evolucionar para aceptar IP y MAC:

```json
{
  "incident_id": "1042",
  "ip_atacante": "10.2.1.105",
  "mac_atacante": "00:11:22:33:44:55",
  "switch_dpid": "of:000072e0807e854c",
  "tipo": "port_scan",
  "prioridad": 50000,
  "ttl_segundos": 600
}
```

Siempre que sea posible, el bloqueo debe combinar MAC, IP, switch y puerto para reducir falsos positivos y dificultar la suplantación.

## 11. Protección del plano de control

La ruta reactiva también puede ser atacada mediante una tormenta de `Packet-In`. Deben aplicarse:

- Rate limiting por switch y puerto.
- Deduplicación de solicitudes iguales.
- Cache temporal de decisiones de M2.
- Timeout estricto al consultar M6 y M2.
- Política segura ante caída de M6.
- Límite de memoria para las ventanas deslizantes.
- Circuit breaker para evitar cascadas de errores.

ONOS no debe realizar una llamada HTTP nueva por cada paquete idéntico. Debe agrupar o limitar los eventos antes de consultar repetidamente a M6.

## 12. Implementación incremental

### Fase 1: MVP

1. Implementar la aplicación reactiva en ONOS.
2. Crear `POST /m6/packet-in`.
3. Consultar M2/OPA desde M6.
4. Contabilizar únicamente decisiones denegadas y bindings inválidos.
5. Generar alertas agregadas hacia M4.
6. Reutilizar `/m6/mitigacion` para instalar `DROP` temporal en T0.
7. Persistir el incidente en PostgreSQL.

### Fase 2: Telemetría de tráfico permitido

1. Habilitar sFlow en switches de borde.
2. Instalar un colector en la VM de seguridad.
3. Correlacionar las muestras con `sesiones_activas`.
4. Detectar picos, fan-out y volúmenes anormales.

### Fase 3: Microscopio dinámico

1. Implementar el gestor OVSDB.
2. Crear mirrors por puerto y con TTL.
3. Transportar la captura mediante GRE/ERSPAN.
4. Integrar `EVE JSON` de Suricata con M4.
5. Automatizar la limpieza específica por incidente.

## 13. Estado respecto al repositorio

Actualmente el repositorio ya contiene:

- Pipeline de mitigación en Tabla 0.
- Endpoints `POST /m6/packet-in`, `/m6/mitigacion` y `/m6/unblock`.
- Consultas de estado de host y mitigación desde M4.
- Traducción e instalación de flows mediante ONOS.
- Consulta de políticas desde M6.
- Tablas `sesiones_activas`, `ip_mac_binding` y `lista_negra_t0`.
- Servicio M4 independiente con correlación, riesgo e incidentes.
- Adaptadores preparados para M6, Suricata, sFlow y NetFlow.
- Esquema SQL de seguridad listo para aplicación manual.
- Modo completamente simulado mediante flags desactivados por defecto.

Queda por implementar:

- Aplicación ONOS que invoque a M6 ante un `Packet-In`.
- Colector sFlow/NetFlow.
- Gestor de mirroring mediante OVSDB.
- Forwarder real de `EVE JSON` desde Suricata.
- Pruebas sobre la red cuando los switches dejen el modo standalone.

## 14. Decisión de arquitectura

La estrategia oficial queda resumida así:

```text
Packet-In → ONOS → M6 → M2/OPA → decisión de acceso
                         |
                         v
                 detección temprana
                         |
                         v
                        M4
                /        |         \
          observar    capturar    bloquear
                        |            |
                   Suricata      M6 → ONOS → T0
```

M6 participa en la detección porque conoce las decisiones reactivas de M2, pero M4 conserva la responsabilidad de correlacionar señales y decidir la respuesta de seguridad. ONOS controla OpenFlow y un gestor separado controla OVSDB y los mirrors.

## 15. Contenido de la VM de seguridad

La VM de seguridad concentra los componentes de observación profunda y correlación. No programa directamente las tablas OpenFlow.

```text
                         VM DE SEGURIDAD
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Colector sFlow/NetFlow ─┐                                  │
│                          │                                  │
│  Suricata → EVE JSON ────┼──→ M4 Correlacionador            │
│                          │          │                       │
│  Alertas de M6 ──────────┘          │ decisión              │
│                                     ├──→ Gestor de mirrors  │
│  PostgreSQL/M5 ─────────────────────┤                       │
│                                     └──→ M6                 │
└──────────────────────────────────────────┼──────────────────┘
                                           v
                                     ONOS → OVS → T0
```

La VM contiene:

- **M4**, como motor central de correlación y respuesta.
- **Suricata**, para inspección del tráfico espejado.
- **Un colector sFlow o NetFlow**, para observar tráfico permitido y detectar anomalías volumétricas.
- **El gestor de telemetría**, para crear y eliminar mirrors mediante OVSDB.
- **Un agente de envío de eventos**, por ejemplo Vector, Filebeat o un lector propio de `eve.json`.
- Opcionalmente Redis, para ventanas temporales compartidas, deduplicación y estado de incidentes.

M4 recibe señales de todos estos componentes, pero es el único que combina la evidencia y decide la acción de seguridad.

## 16. Arquitectura interna propuesta para M4

M4 se implementará como un módulo del monolito FastAPI:

```text
app/security/m4/
├── __init__.py
├── router.py
├── models.py
├── service.py
├── correlator.py
├── risk_engine.py
├── incident_manager.py
├── repositories/
│   ├── __init__.py
│   ├── event_repository.py
│   ├── incident_repository.py
│   └── identity_repository.py
├── clients/
│   ├── __init__.py
│   ├── m6_client.py
│   ├── m2_client.py
│   └── telemetry_client.py
└── adapters/
    ├── __init__.py
    ├── m6_adapter.py
    ├── suricata_adapter.py
    ├── sflow_adapter.py
    └── netflow_adapter.py
```

Los componentes externos de la VM de seguridad se ubicarán en:

```text
app/security/
├── docker-compose.yml
├── suricata/
│   ├── suricata.yaml
│   └── rules/
├── flow_collector/
│   └── config/
└── telemetry_manager/
    ├── __init__.py
    ├── main.py
    ├── models.py
    ├── mirror_service.py
    ├── ovsdb_client.py
    └── cleanup.py
```

La persistencia adicional puede definirse en:

```text
app/security/sql/security_schema.sql
```

Con tablas como:

- `security_events`
- `security_incidents`
- `security_actions`
- `active_mirrors`

El router de M4 se registrará en `app/main.py`, mientras que URLs, ventanas y TTL se configurarán en `app/config.py`.

## 17. Entradas y salidas de M4

M4 recibe evidencia mediante adaptadores y envía órdenes mediante clientes:

```text
ENTRADAS                                      SALIDAS

M6 ─────────→ m6_adapter.py ───────┐
Suricata ───→ suricata_adapter.py ─┼→ M4 ─→ m6_client.py
sFlow ──────→ sflow_adapter.py ────┤      └→ telemetry_client.py
NetFlow ────→ netflow_adapter.py ──┘
```

### 17.1. Endpoints de entrada

```text
POST /m4/events/m6
POST /m4/events/suricata
POST /m4/events/telemetry
```

También puede utilizarse un único endpoint:

```text
POST /m4/events
```

si todos los productores envían el modelo normalizado.

### 17.2. Modelo normalizado

Todas las fuentes deben convertirse a un evento común:

```json
{
  "source": "suricata",
  "event_type": "web_attack",
  "timestamp": "2026-06-22T10:20:30Z",
  "src_ip": "10.2.1.105",
  "src_mac": "00:11:22:33:44:55",
  "dst_ip": "10.0.0.30",
  "dst_port": 443,
  "switch_dpid": "of:000072e0807e854c",
  "in_port": 2,
  "severity": 90,
  "metadata": {}
}
```

## 18. Papel de Suricata en M4

Suricata no decide si debe bloquearse un host. Su responsabilidad es detectar y producir evidencia.

```text
Mirror OVS → GRE/ERSPAN → Suricata → eve.json → M4
```

Un evento original de Suricata:

```json
{
  "src_ip": "10.2.1.105",
  "dest_ip": "10.0.0.30",
  "alert": {
    "signature": "Possible SQL Injection",
    "severity": 1
  }
}
```

es transformado por `suricata_adapter.py`:

```json
{
  "source": "suricata",
  "event_type": "web_attack",
  "src_ip": "10.2.1.105",
  "dst_ip": "10.0.0.30",
  "severity": 90
}
```

No se necesita un `suricata_client.py` para consumir `eve.json`, porque Suricata es una fuente de eventos y no un actuador controlado por M4.

Solo sería necesario un cliente de Suricata si posteriormente M4 necesitara:

- Consultar estadísticas mediante una API o socket.
- Recargar reglas.
- Habilitar o deshabilitar funciones del sensor.

Para el MVP, `suricata_adapter.py` es suficiente.

## 19. Diferencias entre los componentes internos de M4

### 19.1. `service.py`: coordinador del caso de uso

Es el punto que orquesta el proceso completo:

```text
recibir evento
→ normalizar
→ correlacionar
→ evaluar riesgo
→ actualizar incidente
→ ejecutar acción
→ persistir resultado
```

No debe contener directamente todas las reglas de puntuación ni las llamadas HTTP.

### 19.2. `correlator.py`: asociación de evidencias

Responde:

> ¿Qué eventos pertenecen al mismo host o incidente?

Relaciona eventos utilizando:

- IP y MAC de origen.
- Switch y puerto de entrada.
- Usuario o sesión activa.
- Destino y protocolo.
- Cercanía temporal.

Por ejemplo:

```text
M6:       40 accesos denegados desde 10.2.1.105
sFlow:    volumen anormal desde 10.2.1.105
Suricata: firma de ataque desde 10.2.1.105
```

El correlador determina que las tres señales pertenecen al mismo incidente.

### 19.3. `risk_engine.py`: evaluación del peligro

Responde:

> ¿Qué tan peligroso es el incidente y qué acción se recomienda?

Calcula:

- Puntuación de riesgo.
- Nivel de confianza.
- Tipo probable de amenaza.
- Acción recomendada.

Ejemplo de puntuaciones iniciales:

```text
Acceso denegado aislado             +2
Ráfaga de denegaciones             +30
Escaneo de puertos                 +45
Binding IP/MAC inválido            +80
Pico de tráfico                    +30
Posible DDoS                       +60
Posible exfiltración               +50
Alerta crítica de Suricata        +100
Coincidencia entre varias fuentes  +20
```

### 19.4. `incident_manager.py`: ciclo de vida e idempotencia

Responde:

> ¿En qué estado está el incidente y debe ejecutarse nuevamente la acción?

Mantiene la máquina de estados:

```text
NEW → WATCHING → MIRRORING → CONTAINED → BLOCKED → CLOSED
```

También controla:

- TTL del bloqueo.
- Mirror actualmente activo.
- Reincidencias.
- Transiciones de estado.
- Acciones ya ejecutadas.
- Prevención de bloqueos y mirrors duplicados.
- Cierre del incidente.

### 19.5. Resumen

```text
correlator.py
¿Qué evidencias están relacionadas?

risk_engine.py
¿Qué tan peligroso es y qué se recomienda?

incident_manager.py
¿En qué estado está y debe ejecutarse la acción?

service.py
Coordina el procedimiento completo.
```

## 20. Motor de decisión de M4

Las decisiones se basan en puntuación y reglas críticas:

| Riesgo o condición | Acción |
|---|---|
| Evento aislado de baja confianza | `LOG` |
| Riesgo entre 15 y 29 | `WATCH` |
| Riesgo entre 30 y 49 | `MIRROR` |
| Riesgo entre 50 y 79 | `TEMP_BLOCK` |
| Riesgo igual o superior a 80 | `BLOCK` |
| Binding IP/MAC inequívocamente inválido | `TEMP_BLOCK` inmediato |
| Alerta crítica de Suricata | `BLOCK` inmediato |

La correlación entre fuentes independientes aumenta la confianza:

- M6 + sFlow: tráfico no autorizado y comportamiento volumétrico.
- M6 + Suricata: denegaciones y firma de ataque.
- sFlow + Suricata: anomalía volumétrica y evidencia DPI.
- M6 + sFlow + Suricata: bloqueo de alta confianza.

### 20.1. Escenarios

| Escenario | Evidencia | Respuesta |
|---|---|---|
| Acceso denegado aislado | M6 | Registrar |
| Port scan | Muchos `DENY`, destinos y puertos | Mirror o bloqueo temporal |
| Spoofing | Binding inválido informado por M6 | Bloqueo temporal inmediato |
| DDoS sobre acceso permitido | sFlow detecta volumen | Mirror; bloqueo si continúa |
| Posible exfiltración | sFlow/NetFlow, horario y destino | Mirror y análisis |
| Ataque web | Suricata alto o crítico | Bloqueo |
| Varias fuentes coinciden | M6 + telemetría + Suricata | Bloqueo de alta confianza |

## 21. Qué consulta M4 a cada componente

M4 no debe obtener toda la información a través de M6. Cada dato tiene un propietario.

| Información | Fuente |
|---|---|
| Historial de login y logout | PostgreSQL/M5 |
| Intentos fallidos de autenticación | PostgreSQL/FreeRADIUS |
| Sesión actualmente activa | PostgreSQL/M1 |
| Binding IP–MAC–switch–puerto | PostgreSQL |
| Rol del usuario | PostgreSQL/M1 |
| Permisos de acceso | M2/OPA |
| Flows instalados para una sesión | M6 |
| Estado de un bloqueo | M6 |
| Estado de ONOS y switches | M6 |
| Contadores OpenFlow | M6 consultando ONOS |
| Alertas DPI | Suricata |
| Volumen y conversaciones | sFlow/NetFlow |

M4 puede leer PostgreSQL mediante repositorios de solo lectura. No debe distribuir consultas SQL por el motor de riesgo.

`identity_repository.py` debe ofrecer operaciones como:

```python
get_active_session(ip=None, mac=None)
get_authentication_history(user_id, since)
get_failed_logins(user_id, window_minutes=10)
validate_binding(ip, mac, switch_dpid, in_port)
```

## 22. Relación entre M4 y M6

M4 consulta a M6 cuando necesita conocer o modificar el estado del plano de red.

### 22.1. Consultas propuestas

```text
GET /m6/security/host-state
GET /m6/security/mitigations/{incident_id}
POST /m6/mitigacion
POST /m6/unblock
```

Ejemplo:

```http
GET /m6/security/host-state?ip=10.2.1.105
```

```json
{
  "ip": "10.2.1.105",
  "mac": "00:11:22:33:44:55",
  "switch_dpid": "of:000072e0807e854c",
  "in_port": 2,
  "flows_installed": 6,
  "blocked": true,
  "block_expires_at": "2026-06-22T11:00:00Z"
}
```

M4 no debe preguntarle a M6 por el historial de autenticación. Esa información pertenece a M1, FreeRADIUS y PostgreSQL.

### 22.2. Responsabilidad de `m6_client.py`

`m6_client.py` es la salida de M4 hacia M6. Sus métodos propuestos son:

```python
get_host_network_state(ip, mac=None)
get_mitigation_status(incident_id)
block_host(command)
unblock_host(command)
```

M4 puede enviar:

```text
TEMP_BLOCK → bloqueo T0 durante 60–600 segundos
BLOCK      → bloqueo T0 más prolongado
UNBLOCK    → eliminación del flow de mitigación
RATE_LIMIT → limitación futura, si M6 la implementa
```

Ejemplo de orden:

```json
{
  "incident_id": "1042",
  "accion": "BLOCK",
  "ip_atacante": "10.2.1.105",
  "mac_atacante": "00:11:22:33:44:55",
  "switch_dpid": "of:000072e0807e854c",
  "in_port": 2,
  "tipo": "port_scan",
  "prioridad": 50000,
  "ttl_segundos": 600
}
```

Respuesta esperada de M6:

```json
{
  "ok": true,
  "action_id": "act-875",
  "flow_ids": ["51a7bc"],
  "devices": ["of:000072e0807e854c"],
  "expires_at": "2026-06-22T11:00:00Z"
}
```

Después de recibirla, `incident_manager.py` registra la acción y cambia el incidente a `BLOCKED` o `CONTAINED`.

## 23. Relación entre M4 y el gestor de telemetría

`telemetry_client.py` solicita operaciones sobre mirrors:

```text
POST   /mirrors
GET    /mirrors/{incident_id}
DELETE /mirrors/{incident_id}
```

Ejemplo:

```json
{
  "incident_id": "1042",
  "switch_dpid": "of:000072e0807e854c",
  "in_port": 2,
  "src_mac": "00:11:22:33:44:55",
  "ttl_seconds": 300
}
```

El gestor traduce el DPID al bridge OVS correspondiente, crea el mirror y garantiza su eliminación por TTL.

## 24. Ejemplo completo de correlación

M4 recibe una alerta de Suricata:

```text
Posible ataque SQL desde 10.2.1.105 hacia 10.0.0.30
```

El procesamiento es:

1. `suricata_adapter.py` normaliza la alerta.
2. `identity_repository.py` identifica la sesión, el usuario, MAC, rol, switch y puerto.
3. M4 consulta el historial reciente de autenticación.
4. `m2_client.py` comprueba si el usuario tenía permiso para llegar al destino.
5. `m6_client.py` consulta si el host ya está bloqueado y qué estado de red posee.
6. `correlator.py` busca eventos de M6 y sFlow relacionados.
7. `risk_engine.py` calcula el riesgo.
8. `incident_manager.py` determina si debe crearse o actualizarse el incidente.
9. `service.py` ejecuta la acción autorizada.

Ejemplo:

```text
Suricata: posible ataque SQL             +60
M2: destino no autorizado                +20
Historial: 8 autenticaciones fallidas    +15
M6: host todavía no bloqueado              0
Coincidencia entre fuentes               +10
                                           ───
Riesgo total                              100
Acción                                    BLOCK
```

M4 envía la orden a M6, M6 solicita el flow a ONOS y ONOS instala el `DROP` en T0.

## 25. Regla final de responsabilidades

```text
M1 / PostgreSQL
Identidad, sesiones e historial de autenticación.

M2 / OPA
Decisión de autorización.

M6 / ONOS
Estado y ejecución sobre el plano de red.

Suricata
Evidencia DPI.

sFlow / NetFlow
Evidencia volumétrica y conversaciones.

M4
Correlación, puntuación de riesgo y decisión de seguridad.

Gestor de telemetría
Creación y limpieza de mirrors mediante OVSDB.
```

Suricata y los colectores aportan evidencia. M4 toma la decisión. M6 ejecuta la acción de red mediante ONOS.
