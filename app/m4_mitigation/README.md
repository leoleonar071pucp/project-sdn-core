# M4 Mitigation

Esta carpeta queda como placeholder historico del modulo M4.

La implementacion real del M4 de seguridad esta en:

```text
app/security/m4
```

Motivo:

```text
M4 ya no es solo "mitigation".
Ahora cumple el rol de correlador de seguridad:
recibe eventos, calcula riesgo, administra incidentes y solicita mitigaciones a M6.
```

Por eso el nombre actual mas preciso es:

```text
app/security/m4
```

Documentacion tecnica:

```text
app/security/m4/README.md
```

Recomendacion:

- No duplicar codigo en `app/m4_mitigation`.
- Mantener una sola implementacion real para evitar divergencias.
- Si el equipo decide mover M4 aqui, hacerlo en una migracion separada,
  actualizando imports, Dockerfile, tests, despliegue y documentacion.
