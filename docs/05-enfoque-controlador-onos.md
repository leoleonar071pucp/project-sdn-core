# Enfoque del Controlador ONOS

## Objetivo de este documento

Este documento explica qué enfoque usará la solución para autenticación y autorización en la red SDN, y cómo se implementará la interacción entre el `sdn-core`, `ONOS` y los switches `OVS`.

El objetivo es dejar claro:

- si la solución es `proactiva`, `reactiva` o `híbrida`,
- cómo se combinan reglas precargadas con reglas bajo demanda,
- y cuándo se usa la `REST API` de ONOS.

## Enfoques posibles

### Enfoque proactivo

En un enfoque proactivo, las reglas se instalan antes de que llegue el tráfico real del usuario.

Ventajas:

- menor carga sobre el controlador,
- menos latencia en el primer acceso,
- comportamiento más predecible.

Desventajas:

- requiere conocer de antemano muchos casos de tráfico,
- puede instalar reglas que quizá nunca se usen.

En este proyecto, el enfoque proactivo aplica sobre todo a:

- reglas estructurales del pipeline,
- redirección al portal cautivo,
- reglas base `T2` por CIDR y rol,
- reglas base de operación normal.

### Enfoque reactivo

En un enfoque reactivo, las reglas se instalan cuando aparece un paquete que aún no tiene una regla previa en el switch.

Ventajas:

- más flexible,
- útil para casos excepcionales o poco frecuentes,
- evita llenar las tablas con combinaciones innecesarias.

Desventajas:

- el primer paquete genera latencia,
- aumenta la dependencia del controlador,
- puede generar más carga si hay muchos `Packet-In`.

En este proyecto, el enfoque reactivo aplica a:

- reglas de sesión con expiración,
- reposición de reglas expiradas,
- reglas `T2` que deban regenerarse bajo demanda,
- reglas `T3` para accesos diferenciados,
- excepciones por multirol,
- ciertos bloqueos o decisiones dinámicas.

### Enfoque híbrido

La solución adoptará un enfoque `híbrido`.

Eso significa:

- usar reglas proactivas para el tráfico común,
- y reglas reactivas para los casos especiales.

Este enfoque es el más adecuado para el proyecto porque:

- el tráfico normal de la universidad se puede resumir por bloques CIDR y roles,
- pero los casos especiales requieren decisiones más finas por usuario, recurso o contexto,
- y así se evita saturar al controlador con todo el tráfico.

## Decisión oficial para este proyecto

La solución usará un enfoque `híbrido`.

La distribución por tablas será:

- `T0`: reactivo por eventos de seguridad o mitigación.
- `T1`: híbrido. Tiene reglas base proactivas para portal/redirección, pero las reglas de sesión válida expiran y deben regenerarse bajo demanda.
- `T2`: híbrido. Tiene reglas macro precargadas, pero no todas vivirán de forma permanente; algunas se reinstalarán o pedirán bajo demanda para evitar llenar las flow tables con reglas inactivas.
- `T3`: reactivo para excepciones, multirol y permisos micro.
- `T4`: table-miss que envía tráfico no resuelto al controlador.

## Cómo participa ONOS

`ONOS` es el controlador SDN del proyecto.

Su rol es:

- recibir eventos del plano de datos cuando un switch no sabe qué hacer,
- mantener la visión lógica de la red,
- instalar flows en los switches `OVS`,
- y aplicar las decisiones del `sdn-core`.

Es importante distinguir que:

- `M6` no programa directamente a los switches,
- `M6` habla con `ONOS`,
- y `ONOS` es quien programa a los switches.

## Qué es la REST API de ONOS

La `REST API` de `ONOS` es el canal que usará el `sdn-core` para pedir al controlador que instale, elimine o consulte reglas.

En este proyecto, quien usa esa API es `M6`.

Se utilizará para:

- instalar flows,
- eliminar flows,
- consultar flows,
- consultar devices,
- reconciliar estado cuando sea necesario.

La idea es:

- `M2` toma la decisión lógica,
- `M6` la traduce,
- `M6` llama a `ONOS` por `REST API`,
- `ONOS` instala la regla en el switch.

## Cómo se gestionan las reglas en este diseño

La solución no asume que todas las reglas vivan para siempre en los switches.

La razón es práctica:

- las flow tables son finitas,
- no conviene llenarlas con reglas inactivas,
- y algunas reglas deben expirar si el usuario deja de usar la red o deja de acceder a un recurso.

Por eso, en este diseño:

- algunas reglas se precargan,
- otras se reinstalan si expiraron,
- y otras solo aparecen cuando el tráfico real las necesita.

### Reglas en T1

`T1` no es completamente proactiva.

Tiene dos tipos de reglas:

- reglas base permanentes para secuestro hacia portal, DNS permitido y comportamiento inicial,
- reglas de sesión válida con `timeout`, que se crean cuando el usuario ya se autenticó.

Eso significa que la parte estructural de `T1` es proactiva, pero la parte de sesión activa es reactiva o bajo demanda.

### Reglas en T2

`T2` tampoco debe entenderse como completamente proactiva.

Aunque existe una idea de precargar reglas macro por CIDR, en la práctica no todas deben permanecer activas para siempre si eso afecta la capacidad del switch.

Por eso puede haber:

- reglas macro base instaladas al arranque,
- reglas que expiran por inactividad,
- reglas que deben volver a pedirse o regenerarse bajo demanda.

La meta no es que `T2` esté vacía, sino evitar que se llene con reglas que no se usan.

## Implementación esperada en el proyecto

La implementación esperada será la siguiente:

### Tráfico común

- existirá un conjunto de reglas base precargadas en `T1` y `T2`,
- la mayor parte del tráfico podrá resolverse directamente en hardware,
- pero algunas reglas deberán recrearse si expiraron por timeout.

### Tráfico especial

- si el tráfico no está cubierto por reglas activas en `T2`,
- o si la regla ya expiró,
- el sistema debe volver a decidir e instalar la regla necesaria,
- normalmente en `T2` o `T3` según el caso.

## Responsabilidades en esta estrategia

- `M1`: autentica, crea sesión y habilita el contexto inicial del usuario.
- `M2`: decide permisos y determina qué regla lógica hace falta.
- `M6`: traduce esa regla a formato ONOS y usa la `REST API`.
- `ONOS`: instala y elimina flows en los switches `OVS`.
- `OVS`: ejecuta las reglas mientras estén vigentes.
