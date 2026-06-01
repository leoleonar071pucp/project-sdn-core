-- 1. Tabla: usuarios
CREATE TABLE usuarios (
    id_usuario SERIAL PRIMARY KEY,
    codigo_pucp VARCHAR(20) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    estado_cuenta VARCHAR(20) DEFAULT 'ACTIVO'
);

-- 2. Tabla: roles_facultad
CREATE TABLE roles_facultad (
    id_rol SERIAL PRIMARY KEY,
    nombre_rol VARCHAR(50) NOT NULL UNIQUE,
    cidr_asignado VARCHAR(18) NOT NULL
);

-- 3. Tabla intermedia multi-rol: usuarios_roles
CREATE TABLE usuarios_roles (
    id_usuario INT NOT NULL,
    id_rol INT NOT NULL,
    PRIMARY KEY (id_usuario, id_rol),
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
    FOREIGN KEY (id_rol) REFERENCES roles_facultad(id_rol) ON DELETE CASCADE
);

-- 4. Tabla: sesiones_activas
CREATE TABLE sesiones_activas (
    id_sesion SERIAL PRIMARY KEY,
    id_usuario INT NOT NULL,
    mac_address VARCHAR(17) NOT NULL UNIQUE,
    ip_asignada VARCHAR(15) NOT NULL,
    switch_dpid VARCHAR(30) NOT NULL,
    in_port INT NOT NULL,
    login_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario) ON DELETE CASCADE
);

-- 5. Tabla: permisos_micro_t3
CREATE TABLE permisos_micro_t3 (
    id_permiso SERIAL PRIMARY KEY,
    id_usuario INT NOT NULL,
    destino_ip VARCHAR(15) NOT NULL,
    protocolo VARCHAR(10) NOT NULL,
    puerto_destino INT,
    accion_switch VARCHAR(50) NOT NULL,
    valido_hasta TIMESTAMP NOT NULL,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario) ON DELETE CASCADE
);

-- 6. Tabla: politicas_macro_t2
CREATE TABLE politicas_macro_t2 (
    id_politica SERIAL PRIMARY KEY,
    id_rol INT NOT NULL,
    destino_ip VARCHAR(18) NOT NULL,
    protocolo VARCHAR(10) NOT NULL,
    puerto_destino INT,
    FOREIGN KEY (id_rol) REFERENCES roles_facultad(id_rol) ON DELETE CASCADE
);

-- 7. Tabla: lista_negra_t0 (Sin llaves foráneas según la leyenda)
CREATE TABLE lista_negra_t0 (
    id_amenaza SERIAL PRIMARY KEY,
    identificador VARCHAR(20) NOT NULL,
    tipo_identificador VARCHAR(10) NOT NULL,
    motivo_bloqueo TEXT NOT NULL,
    fecha_deteccion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expira_bloqueo TIMESTAMP
);
