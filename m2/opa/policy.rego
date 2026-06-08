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

# rids con deny explícito (set, para lookup O(1))
_denied_rids contains rid if {
    some ex in _raw_exceptions
    ex.allow == false
    rid := ex.recurso_id
}

# Mapa deny: recurso_id → excepción
user_deny_map[rid] := ex if {
    some ex in _raw_exceptions
    ex.allow == false
    rid := ex.recurso_id
}

# Mapa allow vigente: recurso_id → excepción
# Solo entra si NO existe deny para ese mismo rid
user_allow_map[rid] := ex if {
    some ex in _raw_exceptions
    ex.allow == true
    excepcion_vigente(ex)
    rid := ex.recurso_id
    not _denied_rids[rid]
}

# Vista unificada: deny gana sobre allow.
# Se expresa como dos reglas independientes en vez de else,
# porque OPA no admite else en object rules con variable en head.
user_exceptions_map[rid] := ex if {
    ex := user_deny_map[rid]
}

user_exceptions_map[rid] := ex if {
    ex := user_allow_map[rid]
}

# Sets derivados para uso en construir_permiso
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
    permisivos[rid]
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
    cumple_condiciones(r.condiciones, r.combinacion)
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
    "ip_dst":    r.ip_dst,
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
    decision := {
        "allow":       ex.allow,
        "ancho_banda": object.get(ex, "ancho_banda", r.ancho_banda_default),
        "expires_at":  object.get(ex, "expires_at", null),
        "razon":       "excepcion",
    }
} else := decision if {
    rid := resolve_rid
    r   := recursos[rid]
    not user_exceptions_map[rid]
    cumple_condiciones(r.condiciones, r.combinacion)
    decision := {
        "allow":       true,
        "ancho_banda": r.ancho_banda_default,
        "expires_at":  null,
        "razon":       "condiciones_generales",
    }
} else := decision if {
    rid := resolve_rid
    recursos[rid]
    not user_exceptions_map[rid]
    r := recursos[rid]
    not cumple_condiciones(r.condiciones, r.combinacion)
    decision := {
        "allow": false,
        "razon": "denegado_por_politica",
    }
}

# ─────────────────────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────────────────────

cumple_condiciones(condiciones, "or") if {
    some cond in condiciones
    evaluar_condicion(cond)
}

# Recursos sin condiciones, se asume que se cumplen (caso base).
#cumple_condiciones([], "and") if { true }
#cumple_condiciones([], "or") if { true }

cumple_condiciones(condiciones, "and") if {
    count(condiciones) > 0
    every cond in condiciones {
        evaluar_condicion(cond)
    }
}

evaluar_condicion(cond) if {
    cond.tipo == "rol"
    cond.valor in input.roles
}

evaluar_condicion(cond) if {
    cond.tipo == "facultad"
    input.facultad == cond.valor
}