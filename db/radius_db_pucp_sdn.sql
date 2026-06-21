-- ============================================================
-- BASE DE DATOS: SDN PUCP - Sistema de Autenticación y Autorización
-- IP única + VLAN tag dinámica por rol
-- Compatible con FreeRADIUS + M1 (portal_cautivo.py) + M2 (OPA) + M4 + M3 + M6
-- Arquitectura: VLAN-based (un solo momento DHCP , o sea solo tiene una asignación a IP, rol en VLAN tag)
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
-- M4 escribe aqui cuando detecta amenaza.
-- M6 instala regla DROP en T0 para cada registro activo.
-- identificador puede ser IP o MAC.
-- ============================================================
CREATE TABLE IF NOT EXISTS `lista_negra_t0` (
    `id_amenaza`         INT          NOT NULL AUTO_INCREMENT,
    `identificador`      VARCHAR(20)  NOT NULL COMMENT 'IP o MAC del host amenaza',
    `tipo_identificador` ENUM('IP','MAC') NOT NULL,
    `motivo_bloqueo`     TEXT         NOT NULL,
    `fecha_deteccion`    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expira_bloqueo`     TIMESTAMP    NULL DEFAULT NULL COMMENT 'NULL = bloqueo permanente',
    `activo`             TINYINT(1)   NOT NULL DEFAULT '1',
    PRIMARY KEY (`id_amenaza`),
    INDEX `idx_identificador` (`identificador` ASC),
    INDEX `idx_expira` (`expira_bloqueo` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='M4 escribe aqui. M6 instala DROP en T0 para cada registro activo.';

-- ============================================================
-- TABLA: roles_facultad
-- Define los roles del sistema.
-- vlan_id: tag que M6 imprime en el puerto de ingreso del cliente
--          al autenticarse (SET_FIELD vlan_vid en ONOS).
-- FreeRADIUS devuelve el nombre_rol en el atributo Filter-Id.
-- M1 traduce nombre_rol → vlan_id con el diccionario VLAN_POR_ROL.
-- ============================================================
CREATE TABLE IF NOT EXISTS `roles_facultad` (
    `id_rol`        INT          NOT NULL AUTO_INCREMENT,
    `nombre_rol`    VARCHAR(50)  NOT NULL,
    `vlan_id`       INT          NOT NULL COMMENT 'VLAN tag que M6 instala en el switch post-autenticacion',
    `descripcion`   VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_rol`),
    UNIQUE INDEX `nombre_rol` (`nombre_rol` ASC),
    UNIQUE INDEX `vlan_id`    (`vlan_id` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

--                            nombre_rol cidr (informativo)  vlan_id  descripcion
INSERT INTO `roles_facultad` (nombre_rol, vlan_id, descripcion) VALUES
('Cuarentena',              90,  'Estado inicial — solo DHCP y portal cautivo'),
('Visitante',              100,  'Acceso externo limitado via Gateway'),
('Estudiante_Telecom',     210,  'Acceso a cursos Telecomunicaciones'),
('Estudiante_Informatica', 220,  'Acceso a cursos Informatica'),
('Estudiante_Electronica', 230,  'Acceso a cursos Electronica'),
('Docente',                300,  'Acceso a cursos de las 3 facultades y notas'),
('Admin_TI',               400,  'Acceso total a la infraestructura');

-- ============================================================
-- TABLA: servidores
-- Catalogo de servidores y sus IPs.
-- OPA/M2 usa esto como data al inicializarse.
-- ============================================================
CREATE TABLE IF NOT EXISTS `servidores` (
    `id_servidor`     INT         NOT NULL AUTO_INCREMENT,
    `nombre_servidor` VARCHAR(50) NOT NULL,
    `ip_servidor`     VARCHAR(15) NOT NULL,
    `mac_servidor`    VARCHAR(17) NOT NULL,
    `descripcion`     VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_servidor`),
    UNIQUE INDEX `nombre_servidor` (`nombre_servidor` ASC),
    UNIQUE INDEX `ip_servidor` (`ip_servidor` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `servidores` (nombre_servidor, ip_servidor, mac_servidor, descripcion) VALUES
('portal_cautivo',    '192.168.100.2',    'fa:16:3e:df:01:af', 'Portal Cautivo / NAS - RADIUS Client'),
('dhcp_server',       '192.168.200.200',  'fa:16:3e:a0:37:c0', 'Servidor DHCP'),
('srv1_academicos',   '192.168.100.101',  'fa:16:3e:05:3f:5f', 'Servidor de Cursos - Facultades'),  -- H3
('srv2_notas',        '192.168.100.102',  'fa:16:3e:00:9c:f3', 'Servidor de Notas - Admins'),     -- H4
('gateway_internet',  '192.168.100.1',    'fa:16:3e:4a:c5:c0', 'Gateway Internet');        -- Gateway

-- ============================================================
-- TABLA: recursos
-- Define recursos accesibles por rol (ip_dst + puerto).
-- M2/OPA construye las politicas sobre esta tabla.
-- ============================================================
CREATE TABLE IF NOT EXISTS `recursos` (
    `id_recurso`     INT         NOT NULL AUTO_INCREMENT,
    `nombre_recurso` VARCHAR(50) NOT NULL,
    `id_servidor`    INT         NOT NULL,
    `puerto`         INT         NOT NULL DEFAULT 0 COMMENT '80, 443, 22, 67, 68...',
    `protocolo`      VARCHAR(5)  NOT NULL COMMENT 'TCP o UDP',
    `ancho_banda_default` VARCHAR(20) DEFAULT '100Mbps',
    PRIMARY KEY (`id_recurso`),
    INDEX `id_servidor` (`id_servidor` ASC),
    CONSTRAINT `recursos_ibfk_1`
        FOREIGN KEY (`id_servidor`) REFERENCES `servidores` (`id_servidor`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO `recursos` (nombre_recurso, id_servidor, puerto, protocolo, ancho_banda_default) VALUES
('portal_http',           1,     80,  'TCP', '25Mbps'),
('portal_https',          1,     443, 'TCP', '30Mbps'),
('cursos_telecom_http',   3,     8001,  'TCP', '100Mbps'),
('cursos_telecom_https',  3,     1443, 'TCP', '100Mbps'),
('cursos_info_http',      3,     8002,  'TCP', '100Mbps'),
('cursos_info_https',     3,     2443, 'TCP', '100Mbps'),
('cursos_electro_http',   3,     8003,  'TCP', '100Mbps'),
('cursos_electro_https',  3,     3443, 'TCP', '100Mbps'),
('notas_http',            4,     8080,  'TCP', '200Mbps'),
('notas_https',           4,     443, 'TCP', '200Mbps'),
('panel_admin_http',      4,     8081,  'TCP', '150Mbps'),
('panel_admin_https',     4,     8443, 'TCP', '150Mbps'),
('internet_gi',           5,     0, 'ANY', '75Mbps');

-- ============================================================
-- TABLA: politicas_rbac
-- Tabla central de autorización: rol + recurso = accion.
-- OPA carga esto al inicio y evalua cada solicitud.
-- prioridad = prioridad del flow entry en ONOS.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_rbac` (
    `id_politica`   INT     NOT NULL AUTO_INCREMENT,
    `group_id`      INT     NOT NULL DEFAULT 1 COMMENT 'Grupo DNF: OR entre grupos, AND dentro del grupo',
    `id_recurso`    INT     NOT NULL,
    `tipo_condicion` VARCHAR(20)  NOT NULL DEFAULT 'rol' COMMENT 'rol, facultad, ...',
    `id_rol`        INT     NOT NULL,
    `valor_condicion` VARCHAR(100) NULL COMMENT 'Valor para condiciones no basadas en rol',
    `prioridad`     INT           NOT NULL COMMENT 'Prioridad del flow entry',
    `activo`        TINYINT(1)    NOT NULL DEFAULT '1',
    PRIMARY KEY (`id_politica`),
    INDEX `id_recurso` (`id_recurso` ASC),
    INDEX `idx_rol_recurso` (`id_rol` ASC, `id_recurso` ASC),
    CONSTRAINT `politicas_rbac_ibfk_1`
        FOREIGN KEY (`id_rol`) REFERENCES `roles_facultad` (`id_rol`),
    CONSTRAINT `politicas_rbac_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos` (`id_recurso`)
) ENGINE=InnoDB
  AUTO_INCREMENT=1
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- vlan_id incluido en cada INSERT para que OPA/M6 no necesiten JOIN
-- Cuarentena (vlan_id=90) — T1 proactivo al arrancar ONOS
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(1, 1,  1, 100),
(1, 1,  2, 100);

-- Visitante (vlan_id=100) — T2 proactivo
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(1, 2, 13, 100);

-- Estudiante Telecom (vlan_id=210)
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(1, 3, 3, 100),
(1, 3, 4, 100);

-- Estudiante Informatica (vlan_id=220)
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(1, 4, 5, 100),
(1, 4, 6, 100);

-- Estudiante Electronica (vlan_id=230)
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(1, 5, 7, 100),
(1, 5, 8, 100);

-- Docente (vlan_id=300)
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(2, 6, 3, 100),
(2, 6, 4, 100),
(2, 6, 5, 100),
(2, 6, 6, 100),
(2, 6, 7, 100),
(2, 6, 8, 100),
(1, 6, 9, 100),
(1, 6, 10, 100);

-- Admin TI (vlan_id=400) — acceso total
INSERT INTO `politicas_rbac` (group_id, id_rol, id_recurso, prioridad) VALUES
(3, 7, 3, 100),
(3, 7, 4, 100),
(3, 7, 5, 100),
(3, 7, 6, 100),
(3, 7, 7, 100),
(3, 7, 8, 100),
(3, 7, 9, 100),
(3, 7, 10, 100),
(1, 7, 11, 100),
(1, 7, 12, 100);

-- Grupo 4: Docente Y Admin_TI → recurso 11 (panel_admin_http)
INSERT INTO politicas_rbac (group_id, id_rol, id_recurso, prioridad) VALUES
(4, 6, 11, 100),  -- Docente
(4, 7, 11, 100);  -- Admin_TI

-- Grupo 5: Estudiante_Informatica Y Admin_TI → recurso 9 (notas_http)
INSERT INTO politicas_rbac (group_id, id_rol, id_recurso, prioridad) VALUES
(5, 4, 9, 100),  -- Estudiante_Informatica
(5, 7, 9, 100);  -- Admin_TI

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
    UNIQUE INDEX `codigo_pucp` (`codigo_pucp` ASC),
    INDEX `idx_codigo_pucp` (`codigo_pucp` ASC),
    INDEX `idx_estado` (`estado_cuenta` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- Usuarios de prueba (7 usuarios: 3 estudiantes + 3 docentes + 1 admin)
INSERT INTO `usuarios` (codigo_pucp, password_hash, estado_cuenta) VALUES
('20192434',    SHA2('pass_teleco123',  256), 'ACTIVO'),
('20200101',    SHA2('pass_info123',    256), 'ACTIVO'),
('20200202',    SHA2('pass_electro123', 256), 'ACTIVO'),
('DOC20192020', SHA2('pass_doc1123',    256), 'ACTIVO'),
('DOC20192021', SHA2('pass_doc2123',    256), 'ACTIVO'),
('DOC20192022', SHA2('pass_doc3123',    256), 'ACTIVO'),
('ADMIN001',    SHA2('pass_admin123',   256), 'ACTIVO'),
('multi_teleco_docente', SHA2('pass_multi1', 256), 'ACTIVO'),
('multi_info_admin',     SHA2('pass_multi2', 256), 'ACTIVO'),
('multi_docente_admin',  SHA2('pass_multi3', 256), 'ACTIVO');

-- Se hace este cambio para el rol Visitante 
-- 
SET sql_mode='NO_AUTO_VALUE_ON_ZERO';

INSERT INTO `usuarios` (id_usuario, codigo_pucp, password_hash, estado_cuenta) VALUES
(0, 'VISITANTE_SISTEMA', 'N/A_VISITANTE', 'ACTIVO');

CREATE TABLE IF NOT EXISTS `historial_sesiones` (
    `id_historial`      INT          NOT NULL AUTO_INCREMENT,
    `id_sesion_orig`  INT          NOT NULL COMMENT 'id_sesion original de sesiones_activas',
    `id_usuario`        INT          NOT NULL,
    `mac_address`       VARCHAR(17)  NOT NULL,
    `ip_asignada`       VARCHAR(15)  NOT NULL,
    `vlan_id`           INT          NOT NULL,
    `nombre_rol`        VARCHAR(50)  NOT NULL,
    `switch_dpid`       VARCHAR(30)  NOT NULL,
    `in_port`           INT          NOT NULL,
    `login_timestamp`   TIMESTAMP    NOT NULL,
    `logout_timestamp`  TIMESTAMP    NULL DEFAULT NULL,
    `motivo_cierre`     ENUM('LOGOUT_VOLUNTARIO','REVOCADA_M4','EXPIRACION','ADMIN') NOT NULL,
    PRIMARY KEY (`id_historial`),
    INDEX `idx_usuario` (`id_usuario`),
    INDEX `idx_mac`     (`mac_address`),
    INDEX `idx_login`   (`login_timestamp`),
    INDEX `idx_logout_ts`   (`logout_timestamp` ASC),
    CONSTRAINT `historial_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Auditoria completa de sesiones. M5 lee esta tabla. Nunca se borra.';

-- ============================================================
-- TABLA: politicas_temporales
-- Excepciones individuales por usuario (multi-rol temporal).
-- M2 aplica esto sobre politicas_rbac si existe registro.
-- OPA hace polling cada 60 seg via Bundle para refrescar.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_temporales` (
    `id`         INT               NOT NULL AUTO_INCREMENT,
    `id_usuario` INT               NOT NULL,
    `id_recurso` INT               NOT NULL,
    `allow`     BOOLEAN           NOT NULL,       -- L: logico 
    `razon`     VARCHAR(255)     NULL DEFAULT NULL COMMENT 'Motivo de la excepcion temporal',   -- L: Para logs/auditoria y control de excepciones
    `ancho_banda` VARCHAR(20) DEFAULT '50Mbps',   -- L: Para meter
    `prioridad`  INT               NOT NULL DEFAULT '800',
    `expiration` TIMESTAMP         NOT NULL COMMENT 'Cuando expira el permiso temporal',
    `activo`     TINYINT(1)        NOT NULL DEFAULT '1',
    PRIMARY KEY (`id`),
    INDEX `id_recurso` (`id_recurso` ASC),
    INDEX `idx_usuario_exp` (`id_usuario` ASC, `expiration` ASC),
    CONSTRAINT `politicas_temporales_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `politicas_temporales_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos` (`id_recurso`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- L:
INSERT INTO politicas_temporales (id_usuario, id_recurso, allow, razon, ancho_banda, expiration) VALUES
(1,7,true,'beca de colaboración','30Mbps','2026-06-30 23:59:59'),
(2,8,false,'acceso revocado por directiva',NULL,'2026-07-30 23:59:59'),
(3,3,true,'invitado a feria tecnológica',NULL,'2026-06-05 12:00:00');
-- multi_teleco_docente: denegación a cursos_telecom_https (recurso 4)
INSERT INTO politicas_temporales (id_usuario, id_recurso, allow, razon, ancho_banda, expiration) VALUES
(8, 4, false, 'Denegación por prueba multirol', NULL, '2026-12-31 23:59:59');

-- multi_info_admin: permiso especial a notas_https (recurso 10) con ancho_banda extra
INSERT INTO politicas_temporales (id_usuario, id_recurso, allow, razon, ancho_banda, expiration) VALUES
(9, 10, true, 'Permiso con ancho_banda extra', '60Mbps', '2026-12-31 23:59:59');

-- multi_docente_admin: denegación a panel_admin_https (recurso 12)
INSERT INTO politicas_temporales (id_usuario, id_recurso, allow, razon, ancho_banda, expiration) VALUES
(10, 12, false, 'Denegación panel admin', NULL, '2026-12-31 23:59:59');

-- ============================================================
-- TABLA: sesiones_activas
-- M1 (portal_cautivo.py) crea un registro aqui despues del Access-Accept.
-- ip_asignada: SIEMPRE del pool 192.168.100.0/24 — NO cambia al autenticarse.
-- vlan_id: VLAN tag activa en el puerto del switch para esta sesion.
--          M6 instala SET_FIELD vlan_vid=<vlan_id> en el puerto de ingreso.
-- M4 puede cambiar estado a REVOCADA.
-- ACTIVA=sesion vigente | CERRADA=logout voluntario | REVOCADA=terminada por M4
-- ============================================================
CREATE TABLE IF NOT EXISTS `sesiones_activas` (
    `id_sesion`       INT          NOT NULL AUTO_INCREMENT,
    `id_usuario`      INT          NOT NULL,
    `mac_address`     VARCHAR(17)  NOT NULL COMMENT 'Una MAC = una sesion activa',
    `ip_asignada`     VARCHAR(15)  NOT NULL COMMENT 'IP del pool 192.168.100.0/24 — no cambia durante la sesion',
    `vlan_id`         INT          NOT NULL DEFAULT 90 COMMENT 'VLAN tag activa en el switch (90=cuarentena, 210=teleco, etc)',
    `nombre_rol`      VARCHAR(50)  NOT NULL COMMENT 'Rol del usuario: ej Estudiante_Telecom',
    `switch_dpid`     VARCHAR(30)  NOT NULL COMMENT 'DPID del switch OpenFlow',
    `in_port`         INT          NOT NULL COMMENT 'Puerto fisico del switch',
    `login_timestamp` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `estado`          ENUM('ACTIVA','CERRADA','REVOCADA') NOT NULL DEFAULT 'ACTIVA',
    PRIMARY KEY (`id_sesion`),
    UNIQUE INDEX `mac_address` (`mac_address` ASC),
    INDEX `id_usuario` (`id_usuario` ASC),
    INDEX `idx_mac` (`mac_address` ASC),
    INDEX `idx_estado` (`estado` ASC),
    INDEX `idx_vlan` (`vlan_id` ASC),
    INDEX `idx_ip` (`ip_asignada` ASC),
    CONSTRAINT `sesiones_activas_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='IP fija 192.168.100.0/24 — rol identificado por vlan_id, no por IP';

-- ============================================================
-- TABLA: usuarios_roles
-- Relacion muchos-a-muchos entre usuarios y roles.
-- Permite multi-rol (ej: docente con acceso admin temporal).
-- ============================================================
CREATE TABLE IF NOT EXISTS `usuarios_roles` (
    `id_usuario` INT NOT NULL,
    `id_rol`     INT NOT NULL,
    `activo`     TINYINT(1)        NOT NULL DEFAULT '1',    -- L: Agregado para quitar un rol, borrado logico
    PRIMARY KEY (`id_usuario`, `id_rol`),
    INDEX `id_rol` (`id_rol` ASC),
    CONSTRAINT `usuarios_roles_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `usuarios_roles_ibfk_2`
        FOREIGN KEY (`id_rol`) REFERENCES `roles_facultad` (`id_rol`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- Asignacion de roles
INSERT INTO `usuarios_roles` (id_usuario, id_rol, activo) VALUES
(1, 3, 1),  -- 20192434    -> Estudiante_Telecom
(2, 4, 1),  -- 20200101    -> Estudiante_Informatica
(3, 5, 1),  -- 20200202    -> Estudiante_Electronica
(4, 6, 1),  -- DOC20192020 -> Docente
(5, 6, 1),  -- DOC20192021 -> Docente
(6, 6, 1),  -- DOC20192022 -> Docente
(7, 7, 1),  -- ADMIN001    -> Admin_TI

(8, 3, 1),  -- multi_teleco_docente -> Estudiante_Telecom
(8, 6, 1),  -- multi_teleco_docente -> Docente
(9, 4, 1),  -- multi_info_admin -> Estudiante_Informatica
(9, 7, 1),  -- multi_info_admin -> Admin_TI
(10,6, 1),  -- multi_docente_admin -> Docente
(10,7, 1);  -- multi_docente_admin -> Admin_TI

-- ============================================================
-- TABLAS NATIVAS DE FREERADIUS (requeridas por rlm_sql)
-- ============================================================

-- radacct: Accounting de sesiones RADIUS
-- FreeRADIUS escribe aqui en Accounting-Request (Start/Update/Stop)
-- callingstationid = MAC del dispositivo cliente
CREATE TABLE IF NOT EXISTS `radacct` (
    `radacctid`           BIGINT      NOT NULL AUTO_INCREMENT,
    `acctsessionid`       VARCHAR(64) NOT NULL DEFAULT '',
    `acctuniqueid`        VARCHAR(32) NOT NULL DEFAULT '',
    `username`            VARCHAR(64) NOT NULL DEFAULT '',
    `groupname`           VARCHAR(64) NOT NULL DEFAULT '',
    `realm`               VARCHAR(64) NULL DEFAULT '',
    `nasipaddress`        VARCHAR(15) NOT NULL DEFAULT '',
    `nasportid`           VARCHAR(15) NULL DEFAULT NULL,
    `nasporttype`         VARCHAR(32) NULL DEFAULT NULL,
    `acctstarttime`       DATETIME    NULL DEFAULT NULL,
    `acctupdatetime`      DATETIME    NULL DEFAULT NULL,
    `acctstoptime`        DATETIME    NULL DEFAULT NULL,
    `acctinterval`        INT         NULL DEFAULT NULL,
    `acctsessiontime`     INT UNSIGNED NULL DEFAULT NULL,
    `acctauthentic`       VARCHAR(32) NULL DEFAULT NULL,
    `connectinfo_start`   VARCHAR(50) NULL DEFAULT NULL,
    `connectinfo_stop`    VARCHAR(50) NULL DEFAULT NULL,
    `acctinputoctets`     BIGINT      NULL DEFAULT NULL,
    `acctoutputoctets`    BIGINT      NULL DEFAULT NULL,
    `calledstationid`     VARCHAR(50) NOT NULL DEFAULT '',
    `callingstationid`    VARCHAR(50) NOT NULL DEFAULT '',
    `acctterminatecause`  VARCHAR(32) NOT NULL DEFAULT '',
    `servicetype`         VARCHAR(32) NULL DEFAULT NULL,
    `framedprotocol`      VARCHAR(32) NULL DEFAULT NULL,
    `framedipaddress`     VARCHAR(15) NOT NULL DEFAULT '',
    `framedipv6address`   VARCHAR(45) NOT NULL DEFAULT '',
    `framedipv6prefix`    VARCHAR(45) NOT NULL DEFAULT '',
    `framedinterfaceid`   VARCHAR(44) NOT NULL DEFAULT '',
    `delegatedipv6prefix` VARCHAR(45) NOT NULL DEFAULT '',
    `class`               VARCHAR(64) NULL DEFAULT NULL,
    PRIMARY KEY (`radacctid`),
    UNIQUE INDEX `acctuniqueid` (`acctuniqueid` ASC),
    INDEX `idx_username` (`username` ASC),
    INDEX `idx_framedip` (`framedipaddress` ASC),
    INDEX `idx_acctsessionid` (`acctsessionid` ASC),
    INDEX `idx_acctstarttime` (`acctstarttime` ASC),
    INDEX `idx_callingstationid` (`callingstationid` ASC)
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

-- Credenciales de usuarios (FreeRADIUS lee directamente)
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

-- radgroupreply: FreeRADIUS devuelve estos atributos por grupo en el Access-Accept
-- Filter-Id lleva el nombre del rol hacia el Portal Cautivo
-- Session-Timeout define el tiempo maximo de sesion (segundos)
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

-- Se añadió el rol Visitante y su session timeout (30 minutos)
-- Atributo que FreeRADIUS devuelve en el Access-Accept para indicarle
-- a M1 que el rol del cliente es "Visitante". Sin esta fila, el
-- visitante se autentica contra radcheck pero RADIUS nunca informa
-- el rol, y M1 no puede completar el registro de sesion.
-- Para estudiante y docente maximo es 2H (7200)
INSERT INTO `radgroupreply` (groupname, attribute, op, value) VALUES
('Visitante',              'Filter-Id',       '=', 'Visitante'),
('Estudiante_Telecom',     'Filter-Id',       '=', 'Estudiante_Telecom'),
('Estudiante_Telecom',     'Session-Timeout', '=', '7200'),
('Estudiante_Informatica', 'Filter-Id',       '=', 'Estudiante_Informatica'),
('Estudiante_Informatica', 'Session-Timeout', '=', '7200'),
('Estudiante_Electronica', 'Filter-Id',       '=', 'Estudiante_Electronica'),
('Estudiante_Electronica', 'Session-Timeout', '=', '7200'),
('Docente',                'Filter-Id',       '=', 'Docente'),
('Docente',                'Session-Timeout', '=', '7200'),
('Admin_TI',               'Filter-Id',       '=', 'Admin_TI'),
('Admin_TI',               'Session-Timeout', '=', '43200');

-- radreply: atributos individuales devueltos por usuario en el Access-Accept
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

CREATE TABLE IF NOT EXISTS `ip_mac_binding` (
    `id_binding`      INT         NOT NULL AUTO_INCREMENT,
    `ip_asignada`     VARCHAR(15) NOT NULL,
    `mac_address`     VARCHAR(17) NOT NULL,
    `id_usuario`      INT         NOT NULL,
    `switch_dpid`     VARCHAR(30) NOT NULL COMMENT 'Switch donde esta conectado el cliente',
    `in_port`         INT         NOT NULL COMMENT 'Puerto del switch',
    `id_sesion`       INT         NOT NULL,
    `created_at`      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_binding`),
    UNIQUE INDEX `uq_ip_asignada`  (`ip_asignada` ASC)  COMMENT 'Una IP activa = un binding',
    UNIQUE INDEX `uq_mac_address`  (`mac_address` ASC)  COMMENT 'Una MAC activa = un binding',
    INDEX `idx_id_usuario`         (`id_usuario` ASC),
    CONSTRAINT `ip_mac_binding_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `binding_ibfk_1`
        FOREIGN KEY (`id_sesion`) REFERENCES `sesiones_activas` (`id_sesion`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Binding IP-MAC activos vinculado a una sesion activa. M1 escribe, T1 valida.';


-- ============================================================
-- PERMISOS MYSQL PARA FREERADIUS Y M1
-- Ejecutar como root despues de importar este script:
-- ============================================================
CREATE USER IF NOT EXISTS 'radius'@'localhost' IDENTIFIED WITH mysql_native_password BY 'radius_pass';
GRANT SELECT ON radius_db.radcheck          TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radreply          TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radusergroup      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupcheck     TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupreply     TO 'radius'@'localhost';
GRANT ALL    ON radius_db.radacct           TO 'radius'@'localhost';
GRANT ALL    ON radius_db.radpostauth       TO 'radius'@'localhost';
GRANT ALL    ON radius_db.usuarios          TO 'radius'@'localhost';
GRANT ALL    ON radius_db.sesiones_activas  TO 'radius'@'localhost';
GRANT ALL    ON radius_db.ip_mac_binding    TO 'radius'@'localhost';
GRANT ALL    ON radius_db.historial_sesiones TO 'radius'@'localhost';
GRANT SELECT ON radius_db.politicas_rbac    TO 'radius'@'localhost';
GRANT SELECT ON radius_db.recursos          TO 'radius'@'localhost';
GRANT SELECT ON radius_db.roles_facultad    TO 'radius'@'localhost';
GRANT SELECT ON radius_db.servidores        TO 'radius'@'localhost';

-- 'radius' solo tenia SELECT en estas dos tablas, pero el flujo
-- de visitante necesita escribir credenciales temporales (insertar al
-- autenticar, borrar al cerrar sesion). Sin esto, las operaciones de
-- escritura sobre radcheck/radusergroup fallaban por falta de permisos
GRANT SELECT ON radius_db.radcheck             TO 'radius'@'localhost';
GRANT INSERT, DELETE ON radius_db.radcheck     TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radusergroup         TO 'radius'@'localhost';
GRANT INSERT, DELETE ON radius_db.radusergroup TO 'radius'@'localhost';
FLUSH PRIVILEGES;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;