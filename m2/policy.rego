package policy

import data.recursos
import data.excepciones

# POLÍTICA COMPLETA (login)
result = {
  "usuario": input.usuario,
  "roles": input.roles,
  "permisos": [p | nombre := recursos[n]; p := construir_permiso(nombre, recursos[n])]
}

construir_permiso(nombre, r) = permiso {
  ex := excepciones[_]
  ex.usuario == input.usuario
  ex.recurso == nombre
  ex.allow == true
  bw := coalesce(ex.ancho_banda, r.ancho_banda_default)
  exp := coalesce(ex.expires_at, r.expires_default)
  permiso := {
    "recurso": {"ip_dst": r.ip_dst, "puerto": r.puerto, "protocolo": r.protocolo},
    "tabla": "T3",
    "ancho_banda": bw,
    "expires_at": exp
  }
}

construir_permiso(nombre, r) = permiso {
  not excepcion_denegatoria(nombre)
  cumple_condiciones(r.condiciones, r.combinacion)
  permiso := {
    "recurso": {"ip_dst": r.ip_dst, "puerto": r.puerto, "protocolo": r.protocolo},
    "tabla": "T2",
    "ancho_banda": r.ancho_banda_default,
    "expires_at": r.expires_default
  }
}

excepcion_denegatoria(nombre) {
  ex := excepciones[_]
  ex.usuario == input.usuario
  ex.recurso == nombre
  ex.allow == false
}

# CONSULTA DE UN SOLO RECURSO (demanda)
allow_resource = decision {
  recurso := input.recurso
  r := recursos[recurso]
  ex := excepciones[_]
  ex.usuario == input.usuario
  ex.recurso == recurso
  decision := {
    "allow": ex.allow,    
    "ancho_banda": r.ancho_banda_default,
    "expires_at": r.expires_default,
    "razon": "excepcion"
  }
}

allow_resource = decision {
  recurso := input.recurso
  r := recursos[recurso]
  cumple_condiciones(r.condiciones, r.combinacion)
  not excepcion_aplicable(recurso)
  decision := {
    "allow": true,
    "ancho_banda": r.ancho_banda_default,
    "expires_at": r.expires_default,
    "razon": "condiciones_generales"
  }
}

allow_resource = decision {
  recurso := input.recurso
  r := recursos[recurso]
  not cumple_condiciones(r.condiciones, r.combinacion)
  not excepcion_aplicable(recurso)
  decision := {
    "allow": false,
    "razon": "denegado_por_politica"
  }
}

excepcion_aplicable(recurso) {
  ex := excepciones[_]
  ex.usuario == input.usuario
  ex.recurso == recurso
}

# ---------- FUNCIONES AUXILIARES ----------
cumple_condiciones(condiciones, combinacion) {
  combinacion == "or"
  alguna_condicion(condiciones)
}
cumple_condiciones(condiciones, combinacion) {
  combinacion == "and"
  count(condiciones) > 0
  todas_condiciones(condiciones)
}
alguna_condicion(condiciones) {
  cond := condiciones[_]
  evaluar_condicion(cond)
}
todas_condiciones(condiciones) {
  cond := condiciones[_]
  evaluar_condicion(cond)
}
evaluar_condicion(cond) {
  cond.tipo == "rol"
  input.roles[_] == cond.valor
}
evaluar_condicion(cond) {
  cond.tipo == "facultad"
  input.facultad == cond.valor
}
coalesce(val, def) = val { val != null }
coalesce(val, def) = def { val == null }