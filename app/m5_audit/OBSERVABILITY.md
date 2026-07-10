# SDK de Observabilidad M5 - Guía de Uso

## Tabla de contenidos

1. [Introducción](#introducción)
2. [Arquitectura general](#arquitectura-general)
3. [Cómo usar la librería en otros módulos](#cómo-usar-la-librería-en-otros-módulos)
4. [Flujo de datos: de SDK a visualización](#flujo-de-datos-de-sdk-a-visualización)
5. [Stack observability](#stack-observability)
6. [Configuración del docker-compose](#configuración-del-docker-compose)

---

## Introducción

El SDK de observabilidad ubicado en `m5_audit/observability/` es una librería Python que centraliza la telemetría del proyecto SDN. Proporciona:

- **Tracing distribuido**: usando OpenTelemetry Traces para rastrear operaciones
- **Logging estructurado**: enviando logs con contexto y atributos
- **Context propagation**: manteniendo información de sesión/usuario/rol a lo largo de las operaciones
- **Event-driven**: emitiendo eventos estándar del dominio (autenticación, políticas, seguridad, red)

La librería es **no-intrusiva**: si la observabilidad falla, el negocio continúa sin interrupciones.

---

## Arquitectura general

```
┌─────────────────────────────────────────────────────────────────┐
│                      Tu Módulo (M1, M2, M3, etc.)              │
│                                                                  │
│    obs = Observability(TelemetryConfig(...))                   │
│    obs.set_context(user_id, session_id, ...)                  │
│    obs.event(Events.AUTH_LOGIN_STARTED, attributes={...})    │
│    with obs.span("operacion_crítica"):                        │
│        ...negocio...                                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ (OpenTelemetry OTLP)
                              ▼
         ┌────────────────────────────────────────┐
         │   otel-collector:4318                  │
         │  (OpenTelemetry Collector Contrib)    │
         │  - Recibe traces y logs                │
         │  - Procesa y enruta datos              │
         └────────────────────────────────────────┘
              │                        │
         Traces                    Logs
              │                        │
              ▼                        ▼
        ┌──────────┐          ┌──────────┐
        │  Tempo   │          │  Loki    │
        │ (Traces) │          │ (Logs)   │
        └──────────┘          └──────────┘
              │                        │
              └────────────┬───────────┘
                           │
                           ▼
                    ┌────────────────┐
                    │   Grafana      │
                    │ (Visualización)│
                    └────────────────┘
```

---

## Cómo usar la librería en otros módulos

### Paso 1: Instalar la librería
NO ES NECESARIO CON DOCKER
Agrega las dependencias de `m5_audit/observability/requirements.txt` a tu módulo:

```bash
pip install -r m5_audit/observability/requirements.txt
```

### Paso 2: Importar y configurar

En tu módulo principal (ej. `m1_auth.py`):

```python
from observability import Observability, TelemetryConfig, Events

# Crear la configuración con tu nombre de servicio
obsConfig = TelemetryConfig(
    service_name="m1-auth",           # Nombre único del módulo
    service_version="1.0.0",          # Versión semántica
    instance_id="auth-instance-1",    # Opcional: ID de la instancia
)

# Crear la instancia de Observability (Singleton)
obs = Observability(obsConfig)
```

### Paso 3: Establecer contexto de ejecución

Al iniciar una operación (ej. en una request HTTP, una sesión de usuario):

```python
obs.set_context(
    context_id="request-12345",      # ID único de la operación
    session_id="sess-67890",         # ID de la sesión del usuario
    user_id="user-42",               # ID del usuario
    role="estudiante"                # Rol del usuario
)
```

El contexto se propaga automáticamente a todos los eventos y spans generados.

### Paso 4: Emitir eventos

Los eventos representan sucesos importantes del dominio:

```python
# Evento simple
obs.event(
    Events.AUTH_LOGIN_STARTED
)

# Evento con atributos adicionales
obs.event(
    Events.AUTH_SUCCESS,
    attributes={
        "auth.method": "RADIUS",
        "auth.duration.ms": 245,
        "network.client.ip": "192.168.1.100",
    }
)

# Evento de error con contexto
obs.event(
    Events.AUTH_LOGIN_FAILED,
    attributes={
        "auth.cause": "INVALID_CREDENTIALS",
        "auth.remaining_attempts": 2,
        "auth.duration.ms": 189,
    }
)
```

**Atributos reservados** (no puedes usarlos):
- `event.name`
- `event.domain`
- `context.id`
- `session.id`
- `user.id`
- `role.name`

### Paso 5: Crear spans para tracing

Los spans registran la duración y resultado de operaciones:

```python
# Usar como context manager (recomendado)
with obs.span("autenticar_usuario"):
    resultado = realizar_autenticacion()
    if not resultado:
        # El span se marca automáticamente con errores si lanzas excepción
        raise AuthenticationError("Credenciales inválidas")

# O manualmente
span = obs.span("consultar_base_datos")
with span:
    datos = conexion_db.query(...)
```

Los spans capturan:
- Nombre de la operación
- Tiempo de inicio y fin
- Excepciones si las hay
- Contexto actual

### Paso 6: Limpiar contexto (opcional)

Al finalizar la sesión/request:

```python
obs.clear_context()
```

---

## Ejemplo completo: M1 Auth

```python
#!/usr/bin/env python3
from observability import Observability, TelemetryConfig, Events

obsConfig = TelemetryConfig(
    service_name="m1-auth",
    service_version="1.0.0",
)
obs = Observability(obsConfig)

def autenticar(usuario: str, contrasena: str, ip: str) -> dict:
    """
    Autentica un usuario y retorna su sesión.
    """
    context_id = f"auth-{time.time()}"
    session_id = generar_session_id()
    
    # Establecer contexto
    obs.set_context(
        context_id=context_id,
        session_id=session_id,
        user_id=usuario,
        role="desconocido"  # Se actualiza después
    )
    
    # Evento inicial
    obs.event(Events.AUTH_LOGIN_STARTED)
    
    # Operación con span
    with obs.span("validar_credenciales"):
        if not validar_contra_radius(usuario, contrasena):
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.cause": "INVALID_CREDENTIALS",
                    "network.client.ip": ip,
                }
            )
            return {"ok": False, "motivo": "Credenciales inválidas"}
    
    # Obtener rol
    with obs.span("obtener_rol_usuario"):
        rol = obtener_rol(usuario)
        if not rol:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={"auth.cause": "UNKNOWN_ROLE"}
            )
            return {"ok": False, "motivo": "Rol no reconocido"}
    
    # Actualizar contexto con el rol
    obs.set_context(
        context_id=context_id,
        session_id=session_id,
        user_id=usuario,
        role=rol
    )
    
    # Evento exitoso
    obs.event(Events.AUTH_SUCCESS, attributes={"auth.role": rol})
    
    return {"ok": True, "session_id": session_id, "role": rol}
```

---

## Flujo de datos: de SDK a visualización

### 1. **Generación de datos en tu módulo**

```python
obs.event(Events.AUTH_SUCCESS, attributes={"auth.method": "RADIUS"})
```

Esto crea un `LogRecord` con:
- `body`: "User authenticated successfully."
- `severity_number`: 2 (INFO)
- `attributes`:
  ```
  {
    "event.name": "auth.success",
    "event.domain": "identity",
    "context.id": "request-12345",
    "session.id": "sess-67890",
    "user.id": "user-42",
    "role.name": "estudiante",
    "auth.method": "RADIUS"
  }
  ```

### 2. **Exportación OTLP al Collector**

El SDK de OpenTelemetry agrupa logs y traces en **lotes (batches)** y los envía vía HTTP al collector:

```
POST http://otel-collector:4318/v1/logs
Content-Type: application/x-protobuf

[LogRecord, LogRecord, LogRecord, ...]
```

Y para traces:

```
POST http://otel-collector:4318/v1/traces
Content-Type: application/x-protobuf

[Span, Span, Span, ...]
```

### 3. **Procesamiento en el Collector**

El `otel-collector` recibe los datos y los **procesa y enruta**:

**Configuración** (`otel-collector/config.yaml`):

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318  # ✓ Recibe aquí

processors:
  memory_limiter:  # Limita memoria
  batch:           # Agrupa datos

exporters:
  otlp/tempo:
    endpoint: tempo:4317   # ✓ Envía traces aquí
  
  otlp_http/loki:
    endpoint: http://loki:3100/otlp  # ✓ Envía logs aquí

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp/tempo]
    
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp_http/loki]
```

### 4. **Almacenamiento en Backends**

**Tempo** recibe traces:
- Almacena en `/var/tempo/traces` (local filesystem)
- Retención: 24 horas

**Loki** recibe logs:
- Almacena en `/loki/chunks` (local filesystem)
- Retención: 32 horas
- Indexa por labels como `service.name`, `level`, etc.

### 5. **Visualización en Grafana**

Grafana consulta:

| Tipo | Backend | Query | Resultado |
|------|---------|-------|-----------|
| Logs | Loki | `{service_name="m1-auth"}` | Ver logs de M1 en tiempo real |
| Traces | Tempo | Service: "m1-auth" | Ver latencia de operaciones |
| Dashboard | Loki + Tempo | Combina ambos | Vista unificada |

---

## Stack Observability

### Componentes

1. **OpenTelemetry Collector** (`otel/opentelemetry-collector-contrib:0.139.0`)
   - Puerto: `4318` (HTTP OTLP)
   - Recibe, procesa y enruta telemetría

2. **Loki** (`grafana/loki:3.5.5`)
   - Puerto: `3100`
   - Backend de logs
   - Indexación por labels
   - Retención: 32 horas

3. **Tempo** (`grafana/tempo:2.9.2`)
   - Puerto: `3200`
   - Backend de traces distribuidos
   - Retención: 24 horas
   - Útil para correlacionar operaciones

4. **Grafana** (`grafana/grafana-oss:12.2.0`)
   - Puerto: `3000`
   - Panel de visualización
   - Dashboards pre-configurados en `grafana/provisioning/`

### Red interna

Todos los servicios están en la red `observability`:

```
tu-modulo --HTTP:4318--> otel-collector
otel-collector --OTLP:4317--> tempo
otel-collector --HTTP:3100--> loki
grafana --query--> loki:3100 + tempo:3200
```

---

## Configuración del docker-compose

### Iniciar el stack

```bash
cd app/m5_audit
docker-compose up -d
```

### Verificar servicios

```bash
# Verificar estado
docker-compose ps

# Ver logs del collector
docker-compose logs -f otel-collector

# Acceder a Grafana
http://localhost:3000
# Usuario: admin
# Contraseña: admin1
```

### Configuración de Loki

**`loki/config.yaml`**:

```yaml
auth_enabled: false  # Sin autenticación (desarrollo)

server:
  http_listen_port: 3100

storage_config:
  filesystem:
    directory: /loki/chunks  # Almacenamiento local

schema_config:
  configs:
    - from: "2025-01-01"
      store: tsdb           # Time-series database
      schema: v13           # Esquema de Loki

limits_config:
  allow_structured_metadata: true  # Permite metadatos personalizados
  retention_period: 32h            # Retención de 32 horas
```

### Configuración de Tempo

**`tempo/tempo.yaml`**:

```yaml
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: 0.0.0.0:4317  # Recibe traces aquí

storage:
  trace:
    backend: local
    local:
      path: /var/tempo/traces  # Almacenamiento local
```

### Configuración del Collector

**`otel-collector/config.yaml`**:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  memory_limiter:
    check_interval: 5s
    limit_percentage: 50
    spike_limit_percentage: 25

exporters:
  otlp/tempo:
    endpoint: tempo:4317

  otlp_http/loki:
    endpoint: http://loki:3100/otlp

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp/tempo]
    
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp_http/loki]
```

### Volumes

Cada servicio persiste datos en volumenes Docker:

```yaml
volumes:
  grafana-data:    # Dashboards y configuración de Grafana
  loki-data:       # Logs indexados
  tempo-data:      # Traces
```

---

## Checklist de integración

Para agregar observabilidad a un nuevo módulo:

- [ ] Copiar `m5_audit/observability/requirements.txt` a tu módulo
- [ ] Instalar: `pip install -r requirements.txt`
- [ ] Importar: `from observability import Observability, TelemetryConfig, Events`
- [ ] Crear instancia: `obs = Observability(TelemetryConfig(...))`
- [ ] Llamar `obs.set_context(...)` al inicio de cada operación
- [ ] Usar `obs.event(...)` para registrar eventos del dominio
- [ ] Usar `obs.span(...)` para medir latencias de operaciones críticas
- [ ] Llamar `obs.clear_context()` al finalizar la operación
- [ ] Verificar en Grafana que aparecen los datos

---

## Troubleshooting

### Los logs no aparecen en Grafana

**Síntomas**: Ejecutas eventos pero no ves nada en Loki

**Causas posibles**:

1. El collector no está corriendo
   ```bash
   docker-compose ps | grep otel-collector
   ```

2. El endpoint del collector no es accesible desde tu módulo
   ```bash
   curl http://otel-collector:4318/v1/logs
   ```

3. La librería no está emitiendo logs (está marcado con `TODO`)
   - El método `event()` en `observability.py` solo prepara atributos pero no emite el LogRecord

### Los traces no aparecen en Tempo

**Síntomas**: Usas `obs.span()` pero no ves nada en Grafana > Tempo

**Causas**:

1. Verificar que Tempo recibe datos
   ```bash
   docker-compose logs tempo | grep "receiver"
   ```

2. Los spans se exportan automáticamente al cerrar el context manager

### Memoria alta en el collector

**Síntoma**: El contenedor `otel-collector` consume mucha memoria

**Solución**:

Ajusta en `otel-collector/config.yaml`:

```yaml
processors:
  memory_limiter:
    limit_percentage: 50         # Reducir si es necesario
    spike_limit_percentage: 20   # Reducir picos
```

---

## Próximas mejoras

1. **Implementar la emisión real de logs** en `observability.py:event()`
   - Actualmente está marcado como `TODO`
   - Necesita llamar a `self._telemetry.logger.emit(log_record)`

2. **Agregar ContextVar para multi-threading**
   - Actualmente usa baggage global
   - En aplicaciones con múltiples threads, podrían contaminarse contextos

3. **Configurar provisioning de Grafana**
   - Pre-crear dashboards para M1, M2, M3, etc.
   - Alertas automáticas para eventos críticos

4. **Exportar a backends externos**
   - Cloud: Datadog, New Relic, Elastic
   - Cambiar exporters en `otel-collector/config.yaml`

---

## Referencias

- [OpenTelemetry Python SDK](https://opentelemetry.io/docs/languages/python/)
- [Loki Documentation](https://grafana.com/docs/loki/latest/)
- [Tempo Documentation](https://grafana.com/docs/tempo/latest/)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
