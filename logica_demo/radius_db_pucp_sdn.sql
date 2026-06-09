-- ============================================================
-- BASE DE DATOS: SDN PUCP - Sistema de Autenticación y Autorización
-- Arquitectura: CIDR-based (doble DHCP — cuarentena 192.168.100.0/24 → subred del rol)
-- Rol identificado por IP/CIDR
-- Compatible con FreeRADIUS + M1 (portal_cautivo.py) + M2 (OPA) + M4 + M3 + M6
-- Grupo 2 - TEL354
-- ============================================================

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

CREATE SCHEMA IF NOT EXISTS `radius_db`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `radius_db`;

-- ============================================================
-- TABLA: lista_negra_t0
-- Usada por M4 (seguridad activa).
-- M4 escribe aqui cuando detecta una amenaza.
-- M6 instala regla DROP en T0 para cada registro activo.
-- identificador puede ser IP o MAC.
-- ============================================================
CREATE TABLE IF NOT EXISTS `lista_negra_t0` (
    `id_amenaza`         INT             NOT NULL AUTO_INCREMENT,
    `identificador`      VARCHAR(20)     NOT NULL COMMENT 'IP o MAC del host amenaza',
    `tipo_identificador` ENUM('IP','MAC') NOT NULL,
    `motivo_bloqueo`     TEXT            NOT NULL,
    `fecha_deteccion`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expira_bloqueo`     TIMESTAMP       NULL DEFAULT NULL COMMENT 'NULL = bloqueo permanente',
    `activo`             TINYINT(1)      NOT NULL DEFAULT '1',
    PRIMARY KEY (`id_amenaza`),
    INDEX `idx_identificador` (`identificador` ASC),
    INDEX `idx_expira`        (`expira_bloqueo` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='M4 escribe aqui. M6 instala DROP en T0 para cada registro activo.';

-- ============================================================
-- TABLA: roles_facultad
-- Define los roles del sistema con su bloque CIDR asignado.
-- cidr_asignado: subred que el servidor DHCP reserva para este rol
--               tras la autenticación. Es el identificador funcional
--               del rol en el pipeline OpenFlow (match ip_src).
-- FreeRADIUS devuelve el nombre_rol en el atributo Filter-Id.
-- M1 traduce nombre_rol → cidr_asignado con el diccionario CIDR_POR_ROL.
-- ============================================================
CREATE TABLE IF NOT EXISTS `roles_facultad` (
    `id_rol`        INT          NOT NULL AUTO_INCREMENT,
    `nombre_rol`    VARCHAR(50)  NOT NULL,
    `cidr_asignado` VARCHAR(18)  NOT NULL COMMENT 'Subred del rol — identifica el rol en el pipeline OpenFlow',
    `descripcion`   VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_rol`),
    UNIQUE INDEX `nombre_rol`    (`nombre_rol` ASC),
    UNIQUE INDEX `cidr_asignado` (`cidr_asignado` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

--                           nombre_rol              cidr_asignado      descripcion
INSERT INTO `roles_facultad` (nombre_rol, cidr_asignado, descripcion) VALUES
('Cuarentena',             '192.168.100.0/24', 'Estado inicial — solo DHCP y portal cautivo'),
('Visitante',              '10.1.0.0/24',      'Acceso externo limitado via Gateway'),
('Estudiante_Telecom',     '10.2.1.0/24',      'Acceso a cursos Telecomunicaciones'),
('Estudiante_Informatica', '10.2.2.0/24',      'Acceso a cursos Informatica'),
('Estudiante_Electronica', '10.2.3.0/24',      'Acceso a cursos Electronica'),
('Docente',                '10.3.0.0/24',      'Acceso a cursos de las 3 facultades y notas'),
('Admin_TI',               '10.4.0.0/24',      'Acceso total a la infraestructura');

-- ============================================================
-- TABLA: servidores
-- Catálogo de servidores y sus IPs.
-- OPA/M2 usa esto como data al inicializarse.
-- ============================================================
CREATE TABLE IF NOT EXISTS `servidores` (
    `id_servidor`     INT          NOT NULL AUTO_INCREMENT,
    `nombre_servidor` VARCHAR(50)  NOT NULL,
    `ip_servidor`     VARCHAR(15)  NOT NULL,
    `descripcion`     VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_servidor`),
    UNIQUE INDEX `nombre_servidor` (`nombre_servidor` ASC),
    UNIQUE INDEX `ip_servidor`     (`ip_servidor` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `servidores` (nombre_servidor, ip_servidor, descripcion) VALUES
('portal_cautivo',     '10.0.0.10',     'Portal Cautivo / NAS - RADIUS Client'),
('dhcp_server',        '10.0.0.2',      'Servidor DHCP'),
('cursos_telecom',     '10.0.0.21',     'Servidor de Cursos - Facultad Telecomunicaciones'),
('cursos_informatica', '10.0.0.22',     'Servidor de Cursos - Facultad Informatica'),
('cursos_electronica', '10.0.0.23',     'Servidor de Cursos - Facultad Electronica'),
('notas',              '10.0.0.30',     'Servidor de Notas - Docentes'),
('panel_admin_ti',     '10.0.0.40',     'Panel de Control - Admin TI'),
('gateway_internet',   '192.168.201.1', 'Gateway Internet - Visitantes');

-- ============================================================
-- TABLA: recursos
-- Define recursos accesibles por rol (ip_dst + puerto).
-- M2/OPA construye las politicas sobre esta tabla.
-- ============================================================
CREATE TABLE IF NOT EXISTS `recursos` (
    `id_recurso`     INT         NOT NULL AUTO_INCREMENT,
    `nombre_recurso` VARCHAR(50) NOT NULL,
    `id_servidor`    INT         NOT NULL,
    `ip_dst`         VARCHAR(15) NOT NULL,
    `puerto`         INT         NOT NULL COMMENT '80, 443, 22, 67, 68...',
    `protocolo`      VARCHAR(5)  NOT NULL COMMENT 'TCP o UDP',
    PRIMARY KEY (`id_recurso`),
    INDEX `id_servidor`   (`id_servidor` ASC),
    INDEX `idx_ip_puerto` (`ip_dst` ASC, `puerto` ASC),
    CONSTRAINT `recursos_ibfk_1`
        FOREIGN KEY (`id_servidor`) REFERENCES `servidores` (`id_servidor`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `recursos` (nombre_recurso, id_servidor, ip_dst, puerto, protocolo) VALUES
('portal_http',            1, '10.0.0.10',      80,  'TCP'),
('portal_https',           1, '10.0.0.10',      443, 'TCP'),
('dhcp_discover',          2, '255.255.255.255', 67,  'UDP'),
('dhcp_offer',             2, '255.255.255.255', 68,  'UDP'),
('cursos_telecom_http',    3, '10.0.0.21',       80,  'TCP'),
('cursos_telecom_https',   3, '10.0.0.21',       443, 'TCP'),
('cursos_info_http',       4, '10.0.0.22',       80,  'TCP'),
('cursos_info_https',      4, '10.0.0.22',       443, 'TCP'),
('cursos_electro_http',    5, '10.0.0.23',       80,  'TCP'),
('cursos_electro_https',   5, '10.0.0.23',       443, 'TCP'),
('notas_http',             6, '10.0.0.30',       80,  'TCP'),
('notas_https',            6, '10.0.0.30',       443, 'TCP'),
('panel_admin_http',       7, '10.0.0.40',       80,  'TCP'),
('panel_admin_https',      7, '10.0.0.40',       443, 'TCP'),
('gateway_http',           8, '192.168.201.1',   80,  'TCP'),
('gateway_https',          8, '192.168.201.1',   443, 'TCP');

-- ============================================================
-- TABLA: politicas_rbac
-- Tabla central de autorización: rol + recurso = accion.
-- OPA carga esto al inicio y evalua cada solicitud.
-- tabla_of = T1|T2|T3 indica en qué tabla OpenFlow instalar.
-- cidr_rol = CIDR del rol (copia de roles_facultad.cidr_asignado),
--            es el campo match que M6 usa como ip_src en el selector OpenFlow.
-- prioridad = prioridad del flow entry en ONOS.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_rbac` (
    `id_politica` INT                  NOT NULL AUTO_INCREMENT,
    `id_rol`      INT                  NOT NULL,
    `cidr_rol`    VARCHAR(18)          NOT NULL COMMENT 'CIDR del rol — match ip_src en selector OpenFlow',
    `id_recurso`  INT                  NOT NULL,
    `accion`      ENUM('ALLOW','DENY') NOT NULL,
    `tabla_of`    ENUM('T1','T2','T3') NOT NULL COMMENT 'Tabla OpenFlow destino',
    `prioridad`   INT                  NOT NULL COMMENT 'Prioridad del flow entry',
    `timeout_seg` INT                  NULL DEFAULT NULL COMMENT 'NULL = permanente',
    `activo`      TINYINT(1)           NOT NULL DEFAULT '1',
    PRIMARY KEY (`id_politica`),
    INDEX `id_recurso`        (`id_recurso` ASC),
    INDEX `idx_cidr_recurso`  (`cidr_rol` ASC, `id_recurso` ASC),
    INDEX `idx_rol_recurso`   (`id_rol` ASC, `id_recurso` ASC),
    CONSTRAINT `politicas_rbac_ibfk_1`
        FOREIGN KEY (`id_rol`)     REFERENCES `roles_facultad` (`id_rol`),
    CONSTRAINT `politicas_rbac_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos` (`id_recurso`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- cidr_rol incluido en cada INSERT para que OPA/M6 no necesiten JOIN
-- Cuarentena (192.168.100.0/24) — T1 proactivo al arrancar ONOS
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(1, '192.168.100.0/24', 1,  'ALLOW', 'T1', 100, NULL),
(1, '192.168.100.0/24', 2,  'ALLOW', 'T1', 100, NULL),
(1, '192.168.100.0/24', 3,  'ALLOW', 'T1', 500, NULL),
(1, '192.168.100.0/24', 4,  'ALLOW', 'T1', 500, NULL);

-- Visitante (10.1.0.0/24) — T2 proactivo
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(2, '10.1.0.0/24', 15, 'ALLOW', 'T2', 100, NULL),
(2, '10.1.0.0/24', 16, 'ALLOW', 'T2', 100, NULL);

-- Estudiante Telecom (10.2.1.0/24)
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(3, '10.2.1.0/24', 5,  'ALLOW', 'T2', 100, NULL),
(3, '10.2.1.0/24', 6,  'ALLOW', 'T2', 100, NULL),
(3, '10.2.1.0/24', 7,  'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 8,  'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 9,  'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 10, 'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 11, 'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 12, 'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 13, 'DENY',  'T3', 200, NULL),
(3, '10.2.1.0/24', 14, 'DENY',  'T3', 200, NULL);

-- Estudiante Informatica (10.2.2.0/24)
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(4, '10.2.2.0/24', 7,  'ALLOW', 'T2', 100, NULL),
(4, '10.2.2.0/24', 8,  'ALLOW', 'T2', 100, NULL),
(4, '10.2.2.0/24', 5,  'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 6,  'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 9,  'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 10, 'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 11, 'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 12, 'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 13, 'DENY',  'T3', 200, NULL),
(4, '10.2.2.0/24', 14, 'DENY',  'T3', 200, NULL);

-- Estudiante Electronica (10.2.3.0/24)
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(5, '10.2.3.0/24', 9,  'ALLOW', 'T2', 100, NULL),
(5, '10.2.3.0/24', 10, 'ALLOW', 'T2', 100, NULL),
(5, '10.2.3.0/24', 5,  'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 6,  'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 7,  'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 8,  'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 11, 'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 12, 'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 13, 'DENY',  'T3', 200, NULL),
(5, '10.2.3.0/24', 14, 'DENY',  'T3', 200, NULL);

-- Docente (10.3.0.0/24)
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(6, '10.3.0.0/24', 5,  'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 6,  'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 7,  'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 8,  'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 9,  'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 10, 'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 11, 'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 12, 'ALLOW', 'T2', 100, NULL),
(6, '10.3.0.0/24', 13, 'DENY',  'T3', 200, NULL),
(6, '10.3.0.0/24', 14, 'DENY',  'T3', 200, NULL);

-- Admin TI (10.4.0.0/24) — acceso total
INSERT INTO `politicas_rbac` (id_rol, cidr_rol, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(7, '10.4.0.0/24', 5,  'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 6,  'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 7,  'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 8,  'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 9,  'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 10, 'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 11, 'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 12, 'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 13, 'ALLOW', 'T2', 100, NULL),
(7, '10.4.0.0/24', 14, 'ALLOW', 'T2', 100, NULL);

-- ============================================================
-- TABLA: usuarios
-- Almacena las credenciales de los usuarios PUCP.
-- FreeRADIUS consulta aqui via modulo rlm_sql.
-- M1 (portal_cautivo.py) actualiza estado_cuenta al bloquear.
-- ============================================================
CREATE TABLE IF NOT EXISTS `usuarios` (
    `id_usuario`        INT          NOT NULL AUTO_INCREMENT,
    `codigo_pucp`       VARCHAR(20)  NOT NULL,
    `password_hash`     VARCHAR(255) NOT NULL,
    `estado_cuenta`     ENUM('ACTIVO','INACTIVO','BLOQUEADO') NOT NULL DEFAULT 'ACTIVO',
    `intentos_fallidos` INT          NOT NULL DEFAULT '0',
    `fecha_bloqueo`     DATETIME     NULL DEFAULT NULL,
    `created_at`        TIMESTAMP    NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_usuario`),
    UNIQUE INDEX `codigo_pucp`  (`codigo_pucp` ASC),
    INDEX `idx_codigo_pucp`     (`codigo_pucp` ASC),
    INDEX `idx_estado`          (`estado_cuenta` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- Usuarios de prueba (3 estudiantes + 3 docentes + 1 admin)
INSERT INTO `usuarios` (codigo_pucp, password_hash, estado_cuenta) VALUES
('20192434',    SHA2('pass_teleco123',  256), 'ACTIVO'),
('20200101',    SHA2('pass_info123',    256), 'ACTIVO'),
('20200202',    SHA2('pass_electro123', 256), 'ACTIVO'),
('DOC20192020', SHA2('pass_doc1123',    256), 'ACTIVO'),
('DOC20192021', SHA2('pass_doc2123',    256), 'ACTIVO'),
('DOC20192022', SHA2('pass_doc3123',    256), 'ACTIVO'),
('ADMIN001',    SHA2('pass_admin123',   256), 'ACTIVO');

-- ============================================================
-- TABLA: usuarios_roles
-- Relación muchos-a-muchos entre usuarios y roles.
-- Permite multi-rol (ej: docente con acceso admin temporal).
-- ============================================================
CREATE TABLE IF NOT EXISTS `usuarios_roles` (
    `id_usuario` INT NOT NULL,
    `id_rol`     INT NOT NULL,
    PRIMARY KEY (`id_usuario`, `id_rol`),
    INDEX `id_rol` (`id_rol` ASC),
    CONSTRAINT `usuarios_roles_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`      (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `usuarios_roles_ibfk_2`
        FOREIGN KEY (`id_rol`)     REFERENCES `roles_facultad` (`id_rol`)     ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `usuarios_roles` (id_usuario, id_rol) VALUES
(1, 3),  -- 20192434    -> Estudiante_Telecom
(2, 4),  -- 20200101    -> Estudiante_Informatica
(3, 5),  -- 20200202    -> Estudiante_Electronica
(4, 6),  -- DOC20192020 -> Docente
(5, 6),  -- DOC20192021 -> Docente
(6, 6),  -- DOC20192022 -> Docente
(7, 7);  -- ADMIN001    -> Admin_TI

-- ============================================================
-- TABLA: sesiones_activas
-- M1 (portal_cautivo.py) crea un registro aqui después del Access-Accept
-- y del segundo DHCP (cuando el dispositivo recibe su IP de rol).
-- ip_asignada: IP del bloque CIDR del rol (ej. 10.2.1.45 para Telecom).
-- cidr_rol: identifica el rol en el pipeline OpenFlow (match ip_src).
-- M4 puede cambiar estado a REVOCADA.
-- ACTIVA=sesion vigente | CERRADA=logout voluntario | REVOCADA=terminada por M4
-- ============================================================
CREATE TABLE IF NOT EXISTS `sesiones_activas` (
    `id_sesion`       INT          NOT NULL AUTO_INCREMENT,
    `id_usuario`      INT          NOT NULL,
    `mac_address`     VARCHAR(17)  NOT NULL COMMENT 'Una MAC = una sesion activa',
    `ip_asignada`     VARCHAR(15)  NOT NULL COMMENT 'IP del bloque CIDR del rol (post segundo DHCP)',
    `cidr_rol`        VARCHAR(18)  NOT NULL COMMENT 'CIDR del rol — match ip_src en el pipeline OpenFlow',
    `nombre_rol`      VARCHAR(50)  NOT NULL COMMENT 'Nombre del rol: ej Estudiante_Telecom',
    `switch_dpid`     VARCHAR(30)  NOT NULL COMMENT 'DPID del switch OpenFlow',
    `in_port`         INT          NOT NULL COMMENT 'Puerto fisico del switch',
    `login_timestamp` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `estado`          ENUM('ACTIVA','CERRADA','REVOCADA') NOT NULL DEFAULT 'ACTIVA',
    PRIMARY KEY (`id_sesion`),
    UNIQUE INDEX `mac_address`  (`mac_address` ASC),
    INDEX `id_usuario`          (`id_usuario` ASC),
    INDEX `idx_mac`             (`mac_address` ASC),
    INDEX `idx_estado`          (`estado` ASC),
    INDEX `idx_cidr`            (`cidr_rol` ASC),
    INDEX `idx_ip`              (`ip_asignada` ASC),
    CONSTRAINT `sesiones_activas_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Rol identificado por cidr_rol e ip_asignada — segundo DHCP asigna IP del bloque del rol';

-- ============================================================
-- TABLA: historial_sesiones
-- Auditoría completa de sesiones cerradas o revocadas.
-- M1 mueve el registro de sesiones_activas aqui al cerrar sesión.
-- M5 lee esta tabla para monitoreo y auditoría.
-- Nunca se borra.
-- ============================================================
CREATE TABLE IF NOT EXISTS `historial_sesiones` (
    `id_historial`     INT          NOT NULL AUTO_INCREMENT,
    `id_usuario`       INT          NOT NULL,
    `mac_address`      VARCHAR(17)  NOT NULL,
    `ip_asignada`      VARCHAR(15)  NOT NULL,
    `cidr_rol`         VARCHAR(18)  NOT NULL COMMENT 'CIDR del rol que tenia la sesion',
    `nombre_rol`       VARCHAR(50)  NOT NULL,
    `switch_dpid`      VARCHAR(30)  NOT NULL,
    `in_port`          INT          NOT NULL,
    `login_timestamp`  TIMESTAMP    NOT NULL,
    `logout_timestamp` TIMESTAMP    NULL DEFAULT NULL,
    `motivo_cierre`    ENUM('LOGOUT','TIMEOUT','REVOCADA') NOT NULL DEFAULT 'LOGOUT',
    PRIMARY KEY (`id_historial`),
    INDEX `idx_usuario` (`id_usuario`),
    INDEX `idx_mac`     (`mac_address`),
    INDEX `idx_login`   (`login_timestamp`),
    CONSTRAINT `historial_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Auditoria completa de sesiones. M5 lee esta tabla. Nunca se borra.';

-- ============================================================
-- TABLA: ip_mac_binding
-- Anti-spoofing: vincula el par IP+MAC a una sesion activa.
-- M1 escribe al crear la sesion (post segundo DHCP).
-- T1 valida este par antes de permitir tráfico.
-- Se elimina en cascada cuando se borra la sesion activa.
-- ============================================================
CREATE TABLE IF NOT EXISTS `ip_mac_binding` (
    `id_binding`  INT         NOT NULL AUTO_INCREMENT,
    `ip_asignada` VARCHAR(15) NOT NULL COMMENT 'IP del bloque CIDR del rol',
    `mac_address` VARCHAR(17) NOT NULL,
    `id_sesion`   INT         NOT NULL,
    `created_at`  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_binding`),
    UNIQUE INDEX `idx_ip`     (`ip_asignada`),
    UNIQUE INDEX `idx_mac`    (`mac_address`),
    UNIQUE INDEX `idx_sesion` (`id_sesion`),
    CONSTRAINT `binding_ibfk_1`
        FOREIGN KEY (`id_sesion`) REFERENCES `sesiones_activas` (`id_sesion`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Anti-spoofing: par IP+MAC vinculado a una sesion activa. M1 escribe, T1 valida.';

-- ============================================================
-- TABLA: politicas_temporales
-- Excepciones individuales por usuario (multi-rol temporal).
-- M2 aplica esto sobre politicas_rbac si existe registro activo.
-- OPA hace polling cada 60 seg via Bundle para refrescar.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_temporales` (
    `id`         INT                  NOT NULL AUTO_INCREMENT,
    `id_usuario` INT                  NOT NULL,
    `id_recurso` INT                  NOT NULL,
    `accion`     ENUM('ALLOW','DENY') NOT NULL,
    `tabla_of`   ENUM('T3')           NOT NULL DEFAULT 'T3' COMMENT 'Siempre en T3 (excepcion personal)',
    `prioridad`  INT                  NOT NULL DEFAULT '800',
    `expiration` TIMESTAMP            NOT NULL COMMENT 'Cuando expira el permiso temporal',
    `activo`     TINYINT(1)           NOT NULL DEFAULT '1',
    PRIMARY KEY (`id`),
    INDEX `id_recurso`        (`id_recurso` ASC),
    INDEX `idx_usuario_exp`   (`id_usuario` ASC, `expiration` ASC),
    CONSTRAINT `politicas_temporales_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `politicas_temporales_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos`  (`id_recurso`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLAS NATIVAS DE FREERADIUS (requeridas por rlm_sql)
-- ============================================================

-- radacct: Accounting de sesiones RADIUS
-- FreeRADIUS escribe aqui en Accounting-Request (Start/Update/Stop)
-- callingstationid = MAC del dispositivo cliente
CREATE TABLE IF NOT EXISTS `radacct` (
    `radacctid`           BIGINT       NOT NULL AUTO_INCREMENT,
    `acctsessionid`       VARCHAR(64)  NOT NULL DEFAULT '',
    `acctuniqueid`        VARCHAR(32)  NOT NULL DEFAULT '',
    `username`            VARCHAR(64)  NOT NULL DEFAULT '',
    `groupname`           VARCHAR(64)  NOT NULL DEFAULT '',
    `realm`               VARCHAR(64)  NULL DEFAULT '',
    `nasipaddress`        VARCHAR(15)  NOT NULL DEFAULT '',
    `nasportid`           VARCHAR(15)  NULL DEFAULT NULL,
    `nasporttype`         VARCHAR(32)  NULL DEFAULT NULL,
    `acctstarttime`       DATETIME     NULL DEFAULT NULL,
    `acctupdatetime`      DATETIME     NULL DEFAULT NULL,
    `acctstoptime`        DATETIME     NULL DEFAULT NULL,
    `acctinterval`        INT          NULL DEFAULT NULL,
    `acctsessiontime`     INT UNSIGNED NULL DEFAULT NULL,
    `acctauthentic`       VARCHAR(32)  NULL DEFAULT NULL,
    `connectinfo_start`   VARCHAR(50)  NULL DEFAULT NULL,
    `connectinfo_stop`    VARCHAR(50)  NULL DEFAULT NULL,
    `acctinputoctets`     BIGINT       NULL DEFAULT NULL,
    `acctoutputoctets`    BIGINT       NULL DEFAULT NULL,
    `calledstationid`     VARCHAR(50)  NOT NULL DEFAULT '',
    `callingstationid`    VARCHAR(50)  NOT NULL DEFAULT '',
    `acctterminatecause`  VARCHAR(32)  NOT NULL DEFAULT '',
    `servicetype`         VARCHAR(32)  NULL DEFAULT NULL,
    `framedprotocol`      VARCHAR(32)  NULL DEFAULT NULL,
    `framedipaddress`     VARCHAR(15)  NOT NULL DEFAULT '',
    `framedipv6address`   VARCHAR(45)  NOT NULL DEFAULT '',
    `framedipv6prefix`    VARCHAR(45)  NOT NULL DEFAULT '',
    `framedinterfaceid`   VARCHAR(44)  NOT NULL DEFAULT '',
    `delegatedipv6prefix` VARCHAR(45)  NOT NULL DEFAULT '',
    `class`               VARCHAR(64)  NULL DEFAULT NULL,
    PRIMARY KEY (`radacctid`),
    UNIQUE INDEX `acctuniqueid`      (`acctuniqueid` ASC),
    INDEX `idx_username`             (`username` ASC),
    INDEX `idx_framedip`             (`framedipaddress` ASC),
    INDEX `idx_acctsessionid`        (`acctsessionid` ASC),
    INDEX `idx_acctstarttime`        (`acctstarttime` ASC),
    INDEX `idx_callingstationid`     (`callingstationid` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- radcheck: FreeRADIUS verifica credenciales aqui
-- username = codigo_pucp, attribute = 'Cleartext-Password'
CREATE TABLE IF NOT EXISTS `radcheck` (
    `id`        INT          NOT NULL AUTO_INCREMENT,
    `username`  VARCHAR(64)  NOT NULL,
    `attribute` VARCHAR(64)  NOT NULL,
    `op`        CHAR(2)      NOT NULL DEFAULT ':=',
    `value`     VARCHAR(253) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_username` (`username` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `radcheck` (username, attribute, op, value) VALUES
('20192434',    'Cleartext-Password', ':=', 'pass_teleco123'),
('20200101',    'Cleartext-Password', ':=', 'pass_info123'),
('20200202',    'Cleartext-Password', ':=', 'pass_electro123'),
('DOC20192020', 'Cleartext-Password', ':=', 'pass_doc1123'),
('DOC20192021', 'Cleartext-Password', ':=', 'pass_doc2123'),
('DOC20192022', 'Cleartext-Password', ':=', 'pass_doc3123'),
('ADMIN001',    'Cleartext-Password', ':=', 'pass_admin123');

-- radgroupcheck: atributos verificados a nivel de grupo
CREATE TABLE IF NOT EXISTS `radgroupcheck` (
    `id`        INT          NOT NULL AUTO_INCREMENT,
    `groupname` VARCHAR(64)  NOT NULL,
    `attribute` VARCHAR(64)  NOT NULL,
    `op`        CHAR(2)      NOT NULL DEFAULT ':=',
    `value`     VARCHAR(253) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_groupname` (`groupname` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- radgroupreply: FreeRADIUS devuelve estos atributos en el Access-Accept por grupo
-- Filter-Id lleva el nombre del rol hacia el Portal Cautivo
-- Session-Timeout define el tiempo máximo de sesión en segundos
-- Framed-IP-Netmask + Framed-Pool le indican al DHCP qué pool asignar
CREATE TABLE IF NOT EXISTS `radgroupreply` (
    `id`        INT          NOT NULL AUTO_INCREMENT,
    `groupname` VARCHAR(64)  NOT NULL,
    `attribute` VARCHAR(64)  NOT NULL,
    `op`        CHAR(2)      NOT NULL DEFAULT '=',
    `value`     VARCHAR(253) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_groupname` (`groupname` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `radgroupreply` (groupname, attribute, op, value) VALUES
('Estudiante_Telecom',     'Filter-Id',       '=', 'Estudiante_Telecom'),
('Estudiante_Telecom',     'Session-Timeout', '=', '28800'),
('Estudiante_Telecom',     'Framed-Pool',     '=', '10.2.1.0/24'),
('Estudiante_Informatica', 'Filter-Id',       '=', 'Estudiante_Informatica'),
('Estudiante_Informatica', 'Session-Timeout', '=', '28800'),
('Estudiante_Informatica', 'Framed-Pool',     '=', '10.2.2.0/24'),
('Estudiante_Electronica', 'Filter-Id',       '=', 'Estudiante_Electronica'),
('Estudiante_Electronica', 'Session-Timeout', '=', '28800'),
('Estudiante_Electronica', 'Framed-Pool',     '=', '10.2.3.0/24'),
('Docente',                'Filter-Id',       '=', 'Docente'),
('Docente',                'Session-Timeout', '=', '36000'),
('Docente',                'Framed-Pool',     '=', '10.3.0.0/24'),
('Admin_TI',               'Filter-Id',       '=', 'Admin_TI'),
('Admin_TI',               'Session-Timeout', '=', '43200'),
('Admin_TI',               'Framed-Pool',     '=', '10.4.0.0/24');

-- radreply: atributos individuales por usuario en el Access-Accept
-- (vacía — el rol siempre viene del grupo)
CREATE TABLE IF NOT EXISTS `radreply` (
    `id`        INT          NOT NULL AUTO_INCREMENT,
    `username`  VARCHAR(64)  NOT NULL,
    `attribute` VARCHAR(64)  NOT NULL,
    `op`        CHAR(2)      NOT NULL DEFAULT '=',
    `value`     VARCHAR(253) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_username` (`username` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- radusergroup: asigna usuario a grupo en FreeRADIUS
CREATE TABLE IF NOT EXISTS `radusergroup` (
    `id`        INT         NOT NULL AUTO_INCREMENT,
    `username`  VARCHAR(64) NOT NULL,
    `groupname` VARCHAR(64) NOT NULL,
    `priority`  INT         NOT NULL DEFAULT '1',
    PRIMARY KEY (`id`),
    INDEX `idx_username` (`username` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `radusergroup` (username, groupname, priority) VALUES
('20192434',    'Estudiante_Telecom',     1),
('20200101',    'Estudiante_Informatica', 1),
('20200202',    'Estudiante_Electronica', 1),
('DOC20192020', 'Docente',               1),
('DOC20192021', 'Docente',               1),
('DOC20192022', 'Docente',               1),
('ADMIN001',    'Admin_TI',              1);

-- radpostauth: log de autenticaciones (Access-Accept y Access-Reject)
-- FreeRADIUS escribe aqui en el post-auth
CREATE TABLE IF NOT EXISTS `radpostauth` (
    `id`       INT          NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(64)  NOT NULL,
    `pass`     VARCHAR(64)  NOT NULL,
    `reply`    VARCHAR(32)  NOT NULL,
    `authdate` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_username` (`username` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- PERMISOS MYSQL PARA FREERADIUS Y M1
-- Ejecutar como root después de importar este script
-- ============================================================
CREATE USER IF NOT EXISTS 'radius'@'localhost' IDENTIFIED BY 'radius_pass';

GRANT SELECT ON radius_db.radcheck           TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radreply           TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radusergroup       TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupcheck      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupreply      TO 'radius'@'localhost';
GRANT ALL    ON radius_db.radacct            TO 'radius'@'localhost';
GRANT ALL    ON radius_db.radpostauth        TO 'radius'@'localhost';
GRANT ALL    ON radius_db.usuarios           TO 'radius'@'localhost';
GRANT ALL    ON radius_db.sesiones_activas   TO 'radius'@'localhost';
GRANT ALL    ON radius_db.ip_mac_binding     TO 'radius'@'localhost';
GRANT ALL    ON radius_db.historial_sesiones TO 'radius'@'localhost';
GRANT SELECT ON radius_db.politicas_rbac     TO 'radius'@'localhost';
GRANT SELECT ON radius_db.recursos           TO 'radius'@'localhost';
GRANT SELECT ON radius_db.roles_facultad     TO 'radius'@'localhost';
GRANT SELECT ON radius_db.servidores         TO 'radius'@'localhost';

FLUSH PRIVILEGES;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;