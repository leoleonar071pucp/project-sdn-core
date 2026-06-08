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


```json
{
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


```json
{
    "allow": true,
    "ancho_banda": "50Mbps",
    "expires_at": null,
    "razon": "condiciones_generales"
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

- El `input` debe ir siempre envuelto en `{"input": {...}}`.
- Los roles deben coincidir exactamente (caso sensible).
- Para añadir o modificar excepciones, editar el objeto `excepciones_por_usuario` en `data.json` y recargar OPA.
- El módulo evalúa la fecha de expiración internamente; el cliente no necesita validarla.