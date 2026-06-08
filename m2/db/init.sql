-- ============================================================
-- M2 – Esquema de base de datos para OPA (MySQL)
-- ============================================================
-- Se han conservado todas las tablas originales.
-- Las columnas eliminadas o añadidas están justificadas
-- con comentarios (--).
-- ============================================================

-- SET FOREIGN_KEY_CHECKS=0;   -- para evitar problemas de orden en la creación

-- ------------------------------------------------------------
-- Tabla usuarios (debe crearse antes que politicas_temporales)
-- ------------------------------------------------------------
CREATE TABLE usuarios (
  id_usuario INT NOT NULL AUTO_INCREMENT,
  codigo_pucp VARCHAR(20) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  estado_cuenta ENUM('ACTIVO','INACTIVO','BLOQUEADO') NOT NULL DEFAULT 'ACTIVO',
  intentos_fallidos INT NOT NULL DEFAULT 0,
  fecha_bloqueo DATETIME NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id_usuario),
  UNIQUE INDEX codigo_pucp (codigo_pucp),
  INDEX idx_estado (estado_cuenta)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Tabla roles_facultad
-- ------------------------------------------------------------
CREATE TABLE roles_facultad (
  id_rol INT NOT NULL AUTO_INCREMENT,
  nombre_rol VARCHAR(50) NOT NULL,
  cidr_asignado VARCHAR(18) NOT NULL,
  descripcion VARCHAR(100) NULL,
  PRIMARY KEY (id_rol),
  UNIQUE INDEX nombre_rol (nombre_rol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Tabla servidores (se mantiene para gestión administrativa)
-- ------------------------------------------------------------
CREATE TABLE servidores (
  id_servidor INT NOT NULL AUTO_INCREMENT,
  nombre_servidor VARCHAR(50) NOT NULL,
  ip_servidor VARCHAR(15) NOT NULL,
  descripcion VARCHAR(100) NULL,
  PRIMARY KEY (id_servidor),
  UNIQUE INDEX nombre_servidor (nombre_servidor),
  UNIQUE INDEX ip_servidor (ip_servidor)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Tabla recursos
-- ------------------------------------------------------------
CREATE TABLE recursos (
  id_recurso INT NOT NULL AUTO_INCREMENT,
  nombre_recurso VARCHAR(50) NOT NULL,
  id_servidor INT NOT NULL,
  ip_dst VARCHAR(15) NOT NULL,
  puerto INT NOT NULL COMMENT '80, 443, 22, 67, 68...',
  protocolo VARCHAR(5) NOT NULL COMMENT 'TCP o UDP',
  -- NUEVO: ancho de banda por defecto, usado por OPA cuando no hay excepción
  ancho_banda_default VARCHAR(20) DEFAULT '50Mbps',
  PRIMARY KEY (id_recurso),
  INDEX id_servidor (id_servidor),
  INDEX idx_ip_puerto (ip_dst, puerto),
  CONSTRAINT recursos_ibfk_1 FOREIGN KEY (id_servidor) REFERENCES servidores(id_servidor)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Tabla politicas_rbac (reglas generales T2)
-- ------------------------------------------------------------
CREATE TABLE politicas_rbac (
  id_politica INT NOT NULL AUTO_INCREMENT,
  id_rol INT NOT NULL,
  id_recurso INT NOT NULL,
  -- ELIMINADO: accion ENUM('ALLOW','DENY') -> las políticas generales solo son ALLOW;
  --              los denegados no se almacenan aquí, se deniegan por defecto.
  -- ELIMINADO: tabla_of ENUM('T1','T2','T3') -> siempre van a T2, no es necesario.
  -- ELIMINADO: timeout_seg -> las reglas generales no caducan.
  prioridad INT NOT NULL DEFAULT 10,
  activo TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (id_politica),
  INDEX id_recurso (id_recurso),
  INDEX idx_rol_recurso (id_rol, id_recurso),
  CONSTRAINT politicas_rbac_ibfk_1 FOREIGN KEY (id_rol) REFERENCES roles_facultad(id_rol),
  CONSTRAINT politicas_rbac_ibfk_2 FOREIGN KEY (id_recurso) REFERENCES recursos(id_recurso)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Tabla politicas_temporales (excepciones T3)
-- ------------------------------------------------------------
CREATE TABLE politicas_temporales (
  id INT NOT NULL AUTO_INCREMENT,
  id_usuario INT NOT NULL,
  id_recurso INT NOT NULL,
  -- REEMPLAZADO: accion ENUM('ALLOW','DENY') → allow BOOLEAN NOT NULL
  --              (true = permitir, false = denegar)
  allow BOOLEAN NOT NULL,
  razon TEXT,                               -- NUEVO: motivo del permiso/denegación
  ancho_banda VARCHAR(20),                  -- NUEVO: ancho de banda personalizado opcional
  -- ELIMINADO: tabla_of ENUM('T3') → todas las excepciones van a T3, innecesario
  prioridad INT NOT NULL DEFAULT 800,
  expiration TIMESTAMP NULL COMMENT 'Cuando expira el permiso temporal',
  activo TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  INDEX id_recurso (id_recurso),
  INDEX idx_usuario_exp (id_usuario, expiration),
  CONSTRAINT politicas_temporales_ibfk_1 FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  CONSTRAINT politicas_temporales_ibfk_2 FOREIGN KEY (id_recurso) REFERENCES recursos(id_recurso)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS=1;

-- ============================================================
-- Datos de ejemplo (coinciden con el data.json)
-- ============================================================

-- Roles
INSERT INTO roles_facultad (id_rol, nombre_rol, cidr_asignado, descripcion) VALUES
(1,'estudiante_teleco','10.2.1.0/24','Estudiante Telecomunicaciones'),
(2,'estudiante_info','10.2.2.0/24','Estudiante Informática'),
(3,'estudiante_electro','10.2.3.0/24','Estudiante Electrónica'),
(4,'docente','10.3.0.0/24','Docente'),
(5,'admin_ti','10.4.0.0/24','Administrador TI'),
(6,'visitante','10.1.0.0/24','Visitante externo');

-- Servidores
INSERT INTO servidores (id_servidor, nombre_servidor, ip_servidor, descripcion) VALUES
(1,'Servidor Teleco','10.0.0.21','Cursos Telecomunicaciones'),
(2,'Servidor Info','10.0.0.22','Cursos Informática'),
(3,'Servidor Electro','10.0.0.23','Cursos Electrónica'),
(4,'Servidor Notas','10.0.0.30','Gestión de notas'),
(5,'Panel Admin','10.0.0.40','Panel Administración TI'),
(6,'Biblioteca Digital','10.0.0.50','Biblioteca central'),
(7,'Lab Teleco SSH','10.0.0.61','SSH laboratorio Teleco'),
(8,'Impresora','10.0.0.70','Impresora estudiantes'),
(9,'Internet Visitantes','192.168.201.1','Salida a Internet'),
(10,'Investigación','10.0.0.80','Servidor proyectos investigación');

-- Recursos (endpoints)
INSERT INTO recursos (id_recurso, nombre_recurso, id_servidor, ip_dst, puerto, protocolo, ancho_banda_default) VALUES
(1,'cursos_teleco_http',1,'10.0.0.21',80,'tcp','50Mbps'),
(2,'cursos_teleco_https',1,'10.0.0.21',443,'tcp','50Mbps'),
(3,'cursos_info_http',2,'10.0.0.22',80,'tcp','50Mbps'),
(4,'cursos_info_https',2,'10.0.0.22',443,'tcp','50Mbps'),
(5,'cursos_electro_http',3,'10.0.0.23',80,'tcp','50Mbps'),
(6,'cursos_electro_https',3,'10.0.0.23',443,'tcp','50Mbps'),
(7,'servidor_notas_http',4,'10.0.0.30',80,'tcp','100Mbps'),
(8,'servidor_notas_https',4,'10.0.0.30',443,'tcp','100Mbps'),
(9,'panel_admin_http',5,'10.0.0.40',80,'tcp','200Mbps'),
(10,'panel_admin_https',5,'10.0.0.40',443,'tcp','200Mbps'),
(11,'biblioteca_digital',6,'10.0.0.50',443,'tcp','80Mbps'),
(12,'laboratorio_teleco_ssh',7,'10.0.0.61',22,'tcp','20Mbps'),
(13,'impresora_estudiantes',8,'10.0.0.70',9100,'tcp','10Mbps'),
(14,'internet_visitantes',9,'192.168.201.1',0,'ip','5Mbps'),
(15,'servidor_investigacion',10,'10.0.0.80',443,'tcp','200Mbps');

-- Políticas RBAC (T2) – combinación implícita "or"
INSERT INTO politicas_rbac (id_rol, id_recurso) VALUES
(1,1),(4,1),(5,1),
(1,2),(4,2),(5,2),
(2,3),(4,3),(5,3),
(2,4),(4,4),(5,4),
(3,5),(4,5),(5,5),
(3,6),(4,6),(5,6),
(4,7),(5,7),
(4,8),(5,8),
(5,9),(5,10),
(1,11),(2,11),(3,11),(4,11),(5,11),
(1,12),(4,12),(5,12),
(1,13),(2,13),(3,13),
(6,14),
(4,15);  -- solo docente (sin facultad, porque la tabla no lo soporta aún)

-- Usuarios de ejemplo (para las excepciones)
INSERT INTO usuarios (id_usuario, codigo_pucp, password_hash, estado_cuenta) VALUES
(1,'20261234','hash1','ACTIVO'),
(2,'prof_lopez','hash2','ACTIVO'),
(3,'admin_jefe','hash3','ACTIVO'),
(4,'multi_rol','hash4','ACTIVO'),
(5,'visitante_ext','hash5','ACTIVO');

-- Excepciones (T3) – incluyen allow, ancho de banda y expiración
INSERT INTO politicas_temporales (id_usuario, id_recurso, allow, razon, ancho_banda, expiration) VALUES
(1,7,true,'beca de colaboración','30Mbps','2026-06-30 23:59:59'),
(2,7,false,'bloqueo temporal por sospecha',NULL,NULL),
(3,9,false,'acceso solo desde red cableada',NULL,NULL),
(4,8,false,'acceso revocado por directiva',NULL,NULL),
(5,1,true,'invitado a feria tecnológica',NULL,'2026-06-05 12:00:00');