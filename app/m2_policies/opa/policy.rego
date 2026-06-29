package policy

import rego.v1

import data.pool.recursos
import data.pool.excepciones

# ─────────────────────────────────────────────────────────────
# EXCEPCIÓN VIGENTE
# ─────────────────────────────────────────────────────────────

excepcion_vigente(ex) if {
    not ex.expires_at
}

excepcion_vigente(ex) if {
    exp_ns := time.parse_rfc3339_ns(ex.expires_at)
    time.now_ns() < exp_ns
}

# ─────────────────────────────────────────────────────────────
# ÍNDICE DE EXCEPCIONES DEL USUARIO
# ─────────────────────────────────────────────────────────────

_raw_exceptions := object.get(excepciones, input.usuario, [])

_denied_rids contains rid if {
    some ex in _raw_exceptions
    ex.allow == false
    rid := ex.recurso_id
}

user_deny_map[rid] := ex if {
    some ex in _raw_exceptions
    ex.allow == false
    rid := ex.recurso_id
}

user_allow_map[rid] := ex if {
    some ex in _raw_exceptions
    ex.allow == true
    excepcion_vigente(ex)
    rid := ex.recurso_id
    not _denied_rids[rid]
}

user_exceptions_map[rid] := ex if {
    ex := user_deny_map[rid]
}

user_exceptions_map[rid] := ex if {
    ex := user_allow_map[rid]
}

denegados contains rid if {
    user_exceptions_map[rid].allow == false
}

permisivos[rid] := ex if {
    ex := user_exceptions_map[rid]
    ex.allow == true
}

# ─────────────────────────────────────────────────────────────
# HELPER DE RESOLUCIÓN DE ID
# ─────────────────────────────────────────────────────────────

resolve_rid := rid if {
    rid := sprintf("%v", [input.recurso_id])
    recursos[rid]
} else := rid if {
    some rid
    recursos[rid].nombre == input.recurso
}

# ─────────────────────────────────────────────────────────────
# EVALUACIÓN COMPLETA — /policy/result
# ─────────────────────────────────────────────────────────────

result := {
    "usuario": input.usuario,
    "roles":   input.roles,
    "permisos": [p |
        some rid
        r := recursos[rid]
        p := construir_permiso(rid, r)
    ],
}


construir_permiso(rid, r) := permiso if {
    not denegados[rid]
    ex := permisivos[rid]
    permiso := {
        "recurso":     recurso_base(r),
        "tabla":       "T3",
        "ancho_banda": object.get(ex, "ancho_banda", r.ancho_banda_default),
        "expires_at":  object.get(ex, "expires_at", null),
    }
} else := permiso if {
    not denegados[rid]
    not permisivos[rid]
    cumple_grupos(r.grupos)
    permiso := {
        "recurso":     recurso_base(r),
        "tabla":       "T2",
        "ancho_banda": r.ancho_banda_default,
        "expires_at":  null,
    }
}

recurso_base(r) := {
    "id":        r.id,
    "nombre":    r.nombre,
    "ip_srv":    r.ip_servidor,
    "mac_srv":   r.mac_servidor,
    "puerto":    r.puerto,
    "protocolo": r.protocolo,
}

# ─────────────────────────────────────────────────────────────
# CONSULTA INDIVIDUAL — /policy/allow_resource
# ─────────────────────────────────────────────────────────────

allow_resource := decision if {
    rid := resolve_rid
    r   := recursos[rid]
    ex  := user_exceptions_map[rid]
    ex.allow == true
    decision := {
        "allow":       true,
        "recurso":     recurso_base(r),
        "ancho_banda": object.get(ex, "ancho_banda", r.ancho_banda_default),
        "expires_at":  object.get(ex, "expires_at", null),
        "razon":       "excepcion_temporal_permisiva",
    }
} else := decision if {
    rid := resolve_rid
    ex  := user_exceptions_map[rid]
    ex.allow == false
    decision := {
        "allow": false,
        "razon": "excepcion_temporal_denegatoria",
    }
} else := decision if {
    rid := resolve_rid
    r   := recursos[rid]
    not user_exceptions_map[rid]
    cumple_grupos(r.grupos)
    decision := {
        "allow":       true,
        "recurso":     recurso_base(r),
        "ancho_banda": r.ancho_banda_default,
        "expires_at":  null,
        "razon":       "condiciones_generales",
    }
} else := decision if {
    rid := resolve_rid
    r   := recursos[rid]
    not user_exceptions_map[rid]
    not cumple_grupos(r.grupos)
    decision := {
        "allow": false,
        "razon": "denegado_por_politica",
    }
}

# ─────────────────────────────────────────────────────────────
# LÓGICA DNF
# OR entre grupos, AND dentro de cada grupo
# ─────────────────────────────────────────────────────────────
cumple_grupos(grupos) if {
    some grupo in grupos
    grupo_cumple(grupo)
}

grupo_cumple(grupo) if {
    count(grupo) > 0
    every cond in grupo {
        evaluar_condicion(cond)
    }
}

# ─────────────────────────────────────────────────────────────
# CONDICIONES
# ─────────────────────────────────────────────────────────────

# Rol específico
evaluar_condicion(cond) if {
    cond.tipo == "rol"
    cond.valor != "any"
    cond.valor in input.roles
}

evaluar_condicion(cond) if {
    cond.tipo == "rol"
    cond.valor == "any"
    count(input.roles) > 0
}

# Facultad
evaluar_condicion(cond) if {
    cond.tipo == "facultad"
    input.facultad == cond.valor
}