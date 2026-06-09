# Módulo OPA de Control de Acceso - Contrato de Interfaz

## Descripción General

Este módulo de OPA (Open Policy Agent) decide qué recursos puede acceder un usuario en función de:
- Sus **roles** (ej. `estudiante_teleco`, `docente`, `admin_ti`, etc.)
- Excepciones manuales (permisos especiales o denegaciones explícitas)
- Condiciones de los recursos (combinación `AND`/`OR` sobre roles y/o facultad)

Expone dos endpoints principales:

1. **Evaluación completa** → devuelve **todos** los recursos accesibles por el usuario.
2. **Consulta individual** → decide si se permite o deniega el acceso a un recurso específico.

---

## Endpoint 1: Evaluación completa

**Ruta:** `POST /v1/data/policy/result`

### Entrada (Input)

| Campo      | Tipo            | Obligatorio | Descripción                                        |
|------------|-----------------|-------------|----------------------------------------------------|
| `usuario`  | string          | Sí          | Identificador único del usuario (ej. `"20221203"`) |
| `roles`    | array de string | Sí          | Lista de roles asignados (vacío si ninguno)        |
| `facultad` | string o null   | No          | Facultad a la que pertenece (solo para ciertos recursos) |

**Ejemplo:**

```json
{
    "input": {
        "usuario": "20221203",
        "roles": ["estudiante_teleco"],
        "facultad": null
    }
}
```

### Salida (Output)

Nota: OPA envuelve la respuesta de sus reglas dentro de la clave `result`.

```json
{
    "result": {
        "usuario": "string",
        "roles": ["string"],
        "permisos": [
            {
                "recurso": {
                    "id": 1,
                    "nombre": "cursos_teleco_http",
                    "ip_dst": "10.0.0.21",
                    "puerto": 80,
                    "protocolo": "tcp"
                },
                "tabla": "T2",           // T2 = política general, T3 = excepción
                "ancho_banda": "50Mbps",
                "expires_at": null       // ISO 8601 o null
            }
        ]
    }
}
```


## Endpoint 2: Consulta individual

**Ruta:** `POST /v1/data/policy/allow_resource`

### Entrada (Input)

| Campo      | Tipo            | Obligatorio | Descripción                                        |
|------------|-----------------|-------------|----------------------------------------------------|
| `usuario`  | string          | Sí          | Identificador único del usuario (ej. `"20221203"`) |
| `roles`    | array de string | Sí          | Lista de roles asignados (vacío si ninguno)        |
| `recurso_id` | int           | Sí (intercambiable con `recurso`)          | ID numérico del recurso |
| `recurso` | string        | No          | Nombre del recurso, ineficiente |
| `facultad` | string o null   | No          | Facultad a la que pertenece (solo para ciertos recursos) |

```json
{
    "input": {
        "usuario": "string",
        "roles": ["string"],
        "recurso_id": 1,          // recomendado
        "facultad": "string | null"
    }
}
```

### Salida (Output)

Nota: OPA envuelve la respuesta dentro de la clave `result`. Dependiendo de si se permite o deniega, los campos cambian.

**Caso Permitido:**
```json
{
    "result": {
        "allow": true,
        "ancho_banda": "50Mbps",
        "expires_at": null,
        "razon": "condiciones_generales" // o "excepcion"
    }
}
```

**Caso Denegado:**
```json
{
    "result": {
        "allow": false,
        "razon": "denegado_por_politica"
    }
}
```

---

## Catálogo de recursos (IDs y nombres)

| ID | Nombre                    |
|----|---------------------------|
| 1  | cursos_teleco_http        |
| 2  | cursos_teleco_https       |
| 3  | cursos_info_http          |
| 4  | cursos_info_https         |
| 5  | cursos_electro_http       |
| 6  | cursos_electro_https      |
| 7  | servidor_notas_http       |
| 8  | servidor_notas_https      |
| 9  | panel_admin_http          |
| 10 | panel_admin_https         |
| 11 | biblioteca_digital        |
| 12 | laboratorio_teleco_ssh    |
| 13 | impresora_estudiantes     |
| 14 | internet_visitantes       |
| 15 | servidor_investigacion    |

---

## Reglas de negocio (resumen)

- **Denegación por excepción** → prevalece sobre cualquier otra regla.
- **Excepción permisiva** → permite y puede cambiar ancho de banda / expiración.
- **Política general** → solo si no hay excepción y se cumplen las condiciones del recurso.
- Las excepciones con `expires_at` en el pasado se ignoran automáticamente.

## Consideraciones

- El `input` en la petición siempre debe ir envuelto en el objeto `{"input": {...}}`.
- La respuesta de OPA siempre viene envuelta en un objeto `{"result": {...}}`.
- Los roles deben coincidir exactamente (es sensible a mayúsculas/minúsculas).
- El módulo evalúa la fecha de expiración de las excepciones internamente; el cliente no necesita validarla.

---

## ¿Cómo funciona para el equipo de desarrolladores?

Para el equipo de desarrollo, la arquitectura se compone de 3 piezas principales levantadas por el `docker-compose`:

1. **Base de Datos (db):** Una base de datos MySQL (m2-db) que contiene toda la información real de recursos, políticas y excepciones de los usuarios. Aquí es donde la aplicación debe hacer los cambios persistentes.
2. **Agente OPA (opa):** Es el motor de políticas (m2-opa) que se expone en el puerto `8181`. OPA evalúa los permisos **completamente en memoria**, por lo que es extremadamente rápido. Al reiniciar el contenedor, OPA arranca vacío (solo con su archivo `policy.rego`).
3. **Servicio Sincronizador (sync):** Es un contenedor (m2-sync) que actúa como puente. Se conecta a la base de datos de MySQL y **carga periódicamente** (mediante polling) los recursos y excepciones hacia OPA usando su API de datos. 

**Flujo de trabajo del desarrollador:**
- **No se insertan datos directamente a OPA.** Cualquier cambio en los recursos o en las excepciones de un usuario debe hacerse en la base de datos MySQL.
- Una vez hecho el cambio en base de datos, el servicio `sync` lo detectará en su siguiente intervalo de sincronización (por ejemplo, cada 30 segundos para excepciones y 300 segundos para recursos, según las variables de entorno) y lo empujará a la memoria de OPA.
- A partir de ese momento, los endpoints de políticas de OPA evaluarán correctamente las reglas con la información actualizada.
- Esto permite mantener consultas de autorización de latencia muy baja sin golpear la base de datos en cada petición, ideal para arquitecturas de alta concurrencia.