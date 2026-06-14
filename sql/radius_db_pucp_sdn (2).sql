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
    `id_amenaza`         INT             NOT NULL AUTO_INCREMENT,
    `identificador`      VARCHAR(20)     NOT NULL COMMENT 'IP o MAC del host amenaza',
    `tipo_identificador` ENUM('IP','MAC') NOT NULL,
    `motivo_bloqueo`     TEXT            NOT NULL,
    `fecha_deteccion`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expira_bloqueo`     TIMESTAMP       NULL     DEFAULT NULL COMMENT 'NULL = bloqueo permanente',
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
-- Define los roles del sistema y su VLAN asociada.
-- vlan_id: tag que M6 aplica en el puerto de ingreso del cliente
--          post-autenticacion (SET_FIELD vlan_vid en ONOS).
-- cidr_asignado: informativo — todos comparten 192.168.100.0/24.
-- FreeRADIUS devuelve nombre_rol en Filter-Id.
-- M1 traduce nombre_rol → vlan_id con VLAN_POR_ROL.
-- ============================================================
CREATE TABLE IF NOT EXISTS `roles_facultad` (
    `id_rol`        INT          NOT NULL AUTO_INCREMENT,
    `nombre_rol`    VARCHAR(50)  NOT NULL,
    `cidr_asignado` VARCHAR(18)  NOT NULL COMMENT 'Informativo — pool DHCP compartido 192.168.100.0/24',
    `vlan_id`       INT          NOT NULL COMMENT 'VLAN tag que M6 instala en el switch post-autenticacion',
    `descripcion`   VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_rol`),
    UNIQUE INDEX `uq_nombre_rol` (`nombre_rol` ASC),
    UNIQUE INDEX `uq_vlan_id`    (`vlan_id` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Roles del sistema. vlan_id es el identificador de rol en el pipeline OpenFlow.';
 
INSERT INTO `roles_facultad` (nombre_rol, cidr_asignado, vlan_id, descripcion) VALUES
('Cuarentena',             '192.168.100.0/24',  90,  'Estado inicial — solo DHCP y portal cautivo'),
('Visitante',              '192.168.100.0/24', 100,  'Acceso externo limitado via Gateway'),
('Estudiante_Telecom',     '192.168.100.0/24', 210,  'Acceso a cursos Telecomunicaciones'),
('Estudiante_Informatica', '192.168.100.0/24', 220,  'Acceso a cursos Informatica'),
('Estudiante_Electronica', '192.168.100.0/24', 230,  'Acceso a cursos Electronica'),
('Docente',                '192.168.100.0/24', 300,  'Acceso a cursos de las 3 facultades y notas'),
('Admin_TI',               '192.168.100.0/24', 400,  'Acceso total a la infraestructura');

-- ============================================================
-- TABLA: servidores
-- Catalogo de servidores y sus IPs correspondiente.
-- OPA/M2 usa esto como data al inicializarse.
-- ============================================================
CREATE TABLE IF NOT EXISTS `servidores` (
    `id_servidor`     INT          NOT NULL AUTO_INCREMENT,
    `nombre_servidor` VARCHAR(50)  NOT NULL,
    `ip_servidor`     VARCHAR(15)  NOT NULL,
    `descripcion`     VARCHAR(100) NULL DEFAULT NULL,
    PRIMARY KEY (`id_servidor`),
    UNIQUE INDEX `uq_nombre_servidor` (`nombre_servidor` ASC),
    UNIQUE INDEX `uq_ip_servidor`     (`ip_servidor` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Catalogo de servidores. M2/OPA carga esto al inicializarse.';
 
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
-- Define recursos accesibles por rol (ip_dst + puerto + protocolo).
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
    INDEX `idx_id_servidor`  (`id_servidor` ASC),
    INDEX `idx_ip_puerto`    (`ip_dst` ASC, `puerto` ASC),
    CONSTRAINT `recursos_ibfk_1`
        FOREIGN KEY (`id_servidor`) REFERENCES `servidores` (`id_servidor`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Recursos de red. M2/OPA mapea rol+recurso a politica ALLOW/DENY.';
 
INSERT INTO `recursos` (nombre_recurso, id_servidor, ip_dst, puerto, protocolo) VALUES
('portal_http',            1, '10.0.0.10',      80,  'TCP'),
('portal_https',           1, '10.0.0.10',     443,  'TCP'),
('dhcp_discover',          2, '255.255.255.255', 67,  'UDP'),
('dhcp_offer',             2, '255.255.255.255', 68,  'UDP'),
('cursos_telecom_http',    3, '10.0.0.21',       80,  'TCP'),
('cursos_telecom_https',   3, '10.0.0.21',      443,  'TCP'),
('cursos_info_http',       4, '10.0.0.22',       80,  'TCP'),
('cursos_info_https',      4, '10.0.0.22',      443,  'TCP'),
('cursos_electro_http',    5, '10.0.0.23',       80,  'TCP'),
('cursos_electro_https',   5, '10.0.0.23',      443,  'TCP'),
('notas_http',             6, '10.0.0.30',       80,  'TCP'),
('notas_https',            6, '10.0.0.30',      443,  'TCP'),
('panel_admin_http',       7, '10.0.0.40',       80,  'TCP'),
('panel_admin_https',      7, '10.0.0.40',      443,  'TCP'),
('gateway_http',           8, '192.168.201.1',   80,  'TCP'),
('gateway_https',          8, '192.168.201.1',  443,  'TCP');

-- ============================================================
-- TABLA: politicas_rbac
-- Tabla central de autorización: rol + recurso = accion.
-- M2/OPA carga esto al inicio y evalua cada solicitud.
-- tabla_of = T1|T2|T3 indica en que tabla OpenFlow instalar.
-- vlan_id  = VLAN del rol — campo match que M6 usa en el selector OpenFlow.
-- prioridad = prioridad del flow entry en ONOS.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_rbac` (
    `id_politica` INT                   NOT NULL AUTO_INCREMENT,
    `id_rol`      INT                   NOT NULL,
    `vlan_id`     INT                   NOT NULL COMMENT 'VLAN del rol — match en selector OpenFlow',
    `id_recurso`  INT                   NOT NULL,
    `accion`      ENUM('ALLOW','DENY')  NOT NULL,
    `tabla_of`    ENUM('T1','T2','T3')  NOT NULL COMMENT 'Tabla OpenFlow destino',
    `prioridad`   INT                   NOT NULL COMMENT 'Prioridad del flow entry en ONOS',
    `timeout_seg` INT                   NULL DEFAULT NULL COMMENT 'NULL = permanente',
    `activo`      TINYINT(1)            NOT NULL DEFAULT '1',
    PRIMARY KEY (`id_politica`),
    INDEX `idx_id_recurso`   (`id_recurso` ASC),
    INDEX `idx_vlan_recurso` (`vlan_id` ASC, `id_recurso` ASC),
    INDEX `idx_rol_recurso`  (`id_rol` ASC, `id_recurso` ASC),
    CONSTRAINT `politicas_rbac_ibfk_1`
        FOREIGN KEY (`id_rol`)     REFERENCES `roles_facultad` (`id_rol`),
    CONSTRAINT `politicas_rbac_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos`       (`id_recurso`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Politicas RBAC. vlan_id incluido para que M6 no necesite JOIN.';
 
-- Cuarentena (vlan_id=90) — T1 proactivo al arrancar ONOS
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(1, 90,  1,  'ALLOW', 'T1', 100, NULL),
(1, 90,  2,  'ALLOW', 'T1', 100, NULL),
(1, 90,  3,  'ALLOW', 'T1', 500, NULL),
(1, 90,  4,  'ALLOW', 'T1', 500, NULL);
 
-- Visitante (vlan_id=100) — T2 proactivo
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(2, 100, 15, 'ALLOW', 'T2', 100, NULL),
(2, 100, 16, 'ALLOW', 'T2', 100, NULL);
 
-- Estudiante Telecom (vlan_id=210)
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(3, 210, 5,  'ALLOW', 'T2', 100, NULL),
(3, 210, 6,  'ALLOW', 'T2', 100, NULL),
(3, 210, 7,  'DENY',  'T3', 200, NULL),
(3, 210, 8,  'DENY',  'T3', 200, NULL),
(3, 210, 9,  'DENY',  'T3', 200, NULL),
(3, 210, 10, 'DENY',  'T3', 200, NULL),
(3, 210, 11, 'DENY',  'T3', 200, NULL),
(3, 210, 12, 'DENY',  'T3', 200, NULL),
(3, 210, 13, 'DENY',  'T3', 200, NULL),
(3, 210, 14, 'DENY',  'T3', 200, NULL);
 
-- Estudiante Informatica (vlan_id=220)
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(4, 220, 7,  'ALLOW', 'T2', 100, NULL),
(4, 220, 8,  'ALLOW', 'T2', 100, NULL),
(4, 220, 5,  'DENY',  'T3', 200, NULL),
(4, 220, 6,  'DENY',  'T3', 200, NULL),
(4, 220, 9,  'DENY',  'T3', 200, NULL),
(4, 220, 10, 'DENY',  'T3', 200, NULL),
(4, 220, 11, 'DENY',  'T3', 200, NULL),
(4, 220, 12, 'DENY',  'T3', 200, NULL),
(4, 220, 13, 'DENY',  'T3', 200, NULL),
(4, 220, 14, 'DENY',  'T3', 200, NULL);
 
-- Estudiante Electronica (vlan_id=230)
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(5, 230, 9,  'ALLOW', 'T2', 100, NULL),
(5, 230, 10, 'ALLOW', 'T2', 100, NULL),
(5, 230, 5,  'DENY',  'T3', 200, NULL),
(5, 230, 6,  'DENY',  'T3', 200, NULL),
(5, 230, 7,  'DENY',  'T3', 200, NULL),
(5, 230, 8,  'DENY',  'T3', 200, NULL),
(5, 230, 11, 'DENY',  'T3', 200, NULL),
(5, 230, 12, 'DENY',  'T3', 200, NULL),
(5, 230, 13, 'DENY',  'T3', 200, NULL),
(5, 230, 14, 'DENY',  'T3', 200, NULL);
 
-- Docente (vlan_id=300)
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(6, 300, 5,  'ALLOW', 'T2', 100, NULL),
(6, 300, 6,  'ALLOW', 'T2', 100, NULL),
(6, 300, 7,  'ALLOW', 'T2', 100, NULL),
(6, 300, 8,  'ALLOW', 'T2', 100, NULL),
(6, 300, 9,  'ALLOW', 'T2', 100, NULL),
(6, 300, 10, 'ALLOW', 'T2', 100, NULL),
(6, 300, 11, 'ALLOW', 'T2', 100, NULL),
(6, 300, 12, 'ALLOW', 'T2', 100, NULL),
(6, 300, 13, 'DENY',  'T3', 200, NULL),
(6, 300, 14, 'DENY',  'T3', 200, NULL);
 
-- Admin TI (vlan_id=400) — acceso total
INSERT INTO `politicas_rbac` (id_rol, vlan_id, id_recurso, accion, tabla_of, prioridad, timeout_seg) VALUES
(7, 400, 5,  'ALLOW', 'T2', 100, NULL),
(7, 400, 6,  'ALLOW', 'T2', 100, NULL),
(7, 400, 7,  'ALLOW', 'T2', 100, NULL),
(7, 400, 8,  'ALLOW', 'T2', 100, NULL),
(7, 400, 9,  'ALLOW', 'T2', 100, NULL),
(7, 400, 10, 'ALLOW', 'T2', 100, NULL),
(7, 400, 11, 'ALLOW', 'T2', 100, NULL),
(7, 400, 12, 'ALLOW', 'T2', 100, NULL),
(7, 400, 13, 'ALLOW', 'T2', 100, NULL),
(7, 400, 14, 'ALLOW', 'T2', 100, NULL);

-- ============================================================
-- TABLA: usuarios
-- Almacena credenciales y estado de cuenta de los usuarios PUCP.
-- M1 actualiza estado_cuenta e intentos_fallidos.
-- ============================================================
CREATE TABLE IF NOT EXISTS `usuarios` (
    `id_usuario`        INT          NOT NULL AUTO_INCREMENT,
    `codigo_pucp`       VARCHAR(20)  NOT NULL,
    `password_hash`     VARCHAR(255) NOT NULL COMMENT 'SHA2-256 de la contrasena — referencia interna',
    `estado_cuenta`     ENUM('ACTIVO','INACTIVO','BLOQUEADO') NOT NULL DEFAULT 'ACTIVO',
    `intentos_fallidos` INT          NOT NULL DEFAULT '0',
    `fecha_bloqueo`     DATETIME     NULL DEFAULT NULL,
    `created_at`        TIMESTAMP    NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_usuario`),
    UNIQUE INDEX `uq_codigo_pucp` (`codigo_pucp` ASC),
    INDEX `idx_codigo_pucp` (`codigo_pucp` ASC),
    INDEX `idx_estado`      (`estado_cuenta` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Usuarios PUCP. M1 gestiona bloqueos. FreeRADIUS usa radcheck para auth.';
 
INSERT INTO `usuarios` (codigo_pucp, password_hash, estado_cuenta) VALUES
('20192434',    SHA2('pass_teleco123',  256), 'ACTIVO'),
('20200101',    SHA2('pass_info123',    256), 'ACTIVO'),
('20200202',    SHA2('pass_electro123', 256), 'ACTIVO'),
('DOC20192020', SHA2('pass_doc1123',    256), 'ACTIVO'),
('DOC20192021', SHA2('pass_doc2123',    256), 'ACTIVO'),
('DOC20192022', SHA2('pass_doc3123',    256), 'ACTIVO'),
('ADMIN001',    SHA2('pass_admin123',   256), 'ACTIVO');

-- ============================================================
-- TABLA: politicas_temporales
-- Excepciones individuales por usuario (multi-rol temporal) a acceso temporal a recursos.
-- M2 aplica esto sobre politicas_rbac si existe registro.
-- OPA hace polling cada 60 seg via Bundle para refrescar.
-- ============================================================
CREATE TABLE IF NOT EXISTS `politicas_temporales` (
    `id`         INT                  NOT NULL AUTO_INCREMENT,
    `id_usuario` INT                  NOT NULL,
    `id_recurso` INT                  NOT NULL,
    `accion`     ENUM('ALLOW','DENY') NOT NULL,
    `tabla_of`   ENUM('T3')           NOT NULL DEFAULT 'T3' COMMENT 'Siempre T3 — excepcion personal sobre T2',
    `prioridad`  INT                  NOT NULL DEFAULT '800',
    `expiration` TIMESTAMP            NOT NULL COMMENT 'Cuando expira el permiso temporal',
    `activo`     TINYINT(1)           NOT NULL DEFAULT '1',
    PRIMARY KEY (`id`),
    INDEX `idx_id_recurso`   (`id_recurso` ASC),
    INDEX `idx_usuario_exp`  (`id_usuario` ASC, `expiration` ASC),
    CONSTRAINT `politicas_temporales_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`  (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `politicas_temporales_ibfk_2`
        FOREIGN KEY (`id_recurso`) REFERENCES `recursos`  (`id_recurso`)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Excepciones temporales por usuario. M2 las evalua sobre politicas_rbac.';

-- ============================================================
-- TABLA: sesiones_activas
-- Solo contiene sesiones con estado ACTIVA.
-- Al logout o revocacion: registro se mueve a historial_sesiones y se
-- elimina de aqui (DELETE). No existen estados CERRADA/REVOCADA aqui.
--
-- Ciclo de vida:
--   Login exitoso  → INSERT sesiones_activas + INSERT ip_mac_binding
--   Logout/revocacion → INSERT historial_sesiones + DELETE ip_mac_binding
--                       + DELETE sesiones_activas
--
-- ip_asignada: SIEMPRE del pool 192.168.100.0/24 — NO cambia al autenticarse.
-- vlan_id: VLAN tag activa en el puerto del switch para esta sesion.
--          M6 instala SET_FIELD vlan_vid=<vlan_id> en el puerto de ingreso.
-- ============================================================
CREATE TABLE IF NOT EXISTS `sesiones_activas` (
    `id_sesion`       INT         NOT NULL AUTO_INCREMENT,
    `id_usuario`      INT         NOT NULL,
    `mac_address`     VARCHAR(17) NOT NULL COMMENT 'Una MAC = una sesion activa a la vez',
    `ip_asignada`     VARCHAR(15) NOT NULL COMMENT 'IP del pool 192.168.100.0/24 — no cambia post-auth',
    `vlan_id`         INT         NOT NULL DEFAULT 90 COMMENT 'VLAN tag activa en el switch (90=cuarentena)',
    `nombre_rol`      VARCHAR(50) NOT NULL COMMENT 'Ej: Estudiante_Telecom',
    `switch_dpid`     VARCHAR(30) NOT NULL COMMENT 'DPID del switch OpenFlow de acceso',
    `in_port`         INT         NOT NULL COMMENT 'Puerto fisico del switch donde esta conectado el cliente',
    `login_timestamp` TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_sesion`),
    UNIQUE INDEX `uq_mac_address` (`mac_address` ASC),
    INDEX `idx_id_usuario` (`id_usuario` ASC),
    INDEX `idx_vlan`       (`vlan_id` ASC),
    INDEX `idx_ip`         (`ip_asignada` ASC),
    CONSTRAINT `sesiones_activas_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Solo sesiones ACTIVAS. Al cerrar → mover a historial_sesiones y DELETE aqui.';

-- ============================================================
-- TABLA: historial_sesiones
-- Audit trail de todas las sesiones cerradas o revocadas.
-- M1 inserta aqui en logout voluntario.
-- M4 inserta aqui en revocacion por amenaza.
-- M5 (Logs y auditoria) lee esta tabla.
-- ============================================================
CREATE TABLE IF NOT EXISTS `historial_sesiones` (
    `id_historial`    INT          NOT NULL AUTO_INCREMENT,
    `id_sesion_orig`  INT          NOT NULL COMMENT 'id_sesion original de sesiones_activas',
    `id_usuario`      INT          NOT NULL,
    `mac_address`     VARCHAR(17)  NOT NULL,
    `ip_asignada`     VARCHAR(15)  NOT NULL,
    `vlan_id`         INT          NOT NULL,
    `nombre_rol`      VARCHAR(50)  NOT NULL,
    `switch_dpid`     VARCHAR(30)  NOT NULL,
    `in_port`         INT          NOT NULL,
    `login_timestamp` TIMESTAMP    NOT NULL COMMENT 'Momento del login original',
    `logout_timestamp`TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Momento del cierre',
    `motivo_cierre`   ENUM('LOGOUT_VOLUNTARIO','REVOCADA_M4','EXPIRACION','ADMIN') NOT NULL,
    `detalle`         VARCHAR(255) NULL DEFAULT NULL COMMENT 'Detalle adicional (ej: motivo de revocacion)',
    PRIMARY KEY (`id_historial`),
    INDEX `idx_id_usuario`  (`id_usuario` ASC),
    INDEX `idx_mac`         (`mac_address` ASC),
    INDEX `idx_logout_ts`   (`logout_timestamp` ASC),
    INDEX `idx_motivo`      (`motivo_cierre` ASC),
    CONSTRAINT `historial_sesiones_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Audit trail de sesiones cerradas. M5 lee aqui para logs y auditoria.';
  
-- ============================================================
-- TABLA: ip_mac_binding
-- Vinculacion IP-MAC activa para anti-spoofing.
-- M1 inserta al hacer login (junto con sesiones_activas).
-- M1 elimina al hacer logout.
-- M4 consulta aqui para detectar IP Spoofing:
--   si el trafico llega con una IP cuyo MAC no coincide → alerta.
-- ============================================================
CREATE TABLE IF NOT EXISTS `ip_mac_binding` (
    `id_binding`      INT         NOT NULL AUTO_INCREMENT,
    `ip_asignada`     VARCHAR(15) NOT NULL COMMENT 'IP del cliente en el pool 192.168.100.0/24',
    `mac_address`     VARCHAR(17) NOT NULL COMMENT 'MAC del dispositivo autenticado',
    `id_usuario`      INT         NOT NULL,
    `switch_dpid`     VARCHAR(30) NOT NULL COMMENT 'Switch donde esta conectado el cliente',
    `in_port`         INT         NOT NULL COMMENT 'Puerto del switch',
    `created_at`      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_binding`),
    UNIQUE INDEX `uq_ip_asignada`  (`ip_asignada` ASC)  COMMENT 'Una IP activa = un binding',
    UNIQUE INDEX `uq_mac_address`  (`mac_address` ASC)  COMMENT 'Una MAC activa = un binding',
    INDEX `idx_id_usuario`         (`id_usuario` ASC),
    CONSTRAINT `ip_mac_binding_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Bindings IP-MAC activos. M4 consulta para detectar IP Spoofing.';

-- ============================================================
-- TABLA: usuarios_roles
-- Relacion muchos-a-muchos entre usuarios y roles.
-- Permite multi-rol (ej: docente con acceso admin temporal).
-- ============================================================
CREATE TABLE IF NOT EXISTS `usuarios_roles` (
    `id_usuario` INT NOT NULL,
    `id_rol`     INT NOT NULL,
    PRIMARY KEY (`id_usuario`, `id_rol`),
    INDEX `idx_id_rol` (`id_rol` ASC),
    CONSTRAINT `usuarios_roles_ibfk_1`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios`      (`id_usuario`) ON DELETE CASCADE,
    CONSTRAINT `usuarios_roles_ibfk_2`
        FOREIGN KEY (`id_rol`)     REFERENCES `roles_facultad` (`id_rol`)    ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Asignacion de roles a usuarios. Base para politicas_temporales.';
 
INSERT INTO `usuarios_roles` (id_usuario, id_rol) VALUES
(1, 3),  -- 20192434    -> Estudiante_Telecom
(2, 4),  -- 20200101    -> Estudiante_Informatica
(3, 5),  -- 20200202    -> Estudiante_Electronica
(4, 6),  -- DOC20192020 -> Docente
(5, 6),  -- DOC20192021 -> Docente
(6, 6),  -- DOC20192022 -> Docente
(7, 7);  -- ADMIN001    -> Admin_TI

-- ============================================================
-- TABLAS NATIVAS DE FREERADIUS (requeridas por el módulo de rlm_sql) :D
-- ============================================================

-- radacct: Accounting de sesiones RADIUS
-- FreeRADIUS escribe aqui en Accounting-Request (Start/Update/Stop)
CREATE TABLE IF NOT EXISTS `radacct` (
    `radacctid`           BIGINT       NOT NULL AUTO_INCREMENT,
    `acctsessionid`       VARCHAR(64)  NOT NULL DEFAULT '',
    `acctuniqueid`        VARCHAR(32)  NOT NULL DEFAULT '',
    `username`            VARCHAR(64)  NOT NULL DEFAULT '',
    `groupname`           VARCHAR(64)  NOT NULL DEFAULT '',
    `realm`               VARCHAR(64)  NULL     DEFAULT '',
    `nasipaddress`        VARCHAR(15)  NOT NULL DEFAULT '',
    `nasportid`           VARCHAR(15)  NULL     DEFAULT NULL,
    `nasporttype`         VARCHAR(32)  NULL     DEFAULT NULL,
    `acctstarttime`       DATETIME     NULL     DEFAULT NULL,
    `acctupdatetime`      DATETIME     NULL     DEFAULT NULL,
    `acctstoptime`        DATETIME     NULL     DEFAULT NULL,
    `acctinterval`        INT          NULL     DEFAULT NULL,
    `acctsessiontime`     INT UNSIGNED NULL     DEFAULT NULL,
    `acctauthentic`       VARCHAR(32)  NULL     DEFAULT NULL,
    `connectinfo_start`   VARCHAR(50)  NULL     DEFAULT NULL,
    `connectinfo_stop`    VARCHAR(50)  NULL     DEFAULT NULL,
    `acctinputoctets`     BIGINT       NULL     DEFAULT NULL,
    `acctoutputoctets`    BIGINT       NULL     DEFAULT NULL,
    `calledstationid`     VARCHAR(50)  NOT NULL DEFAULT '',
    `callingstationid`    VARCHAR(50)  NOT NULL DEFAULT '',
    `acctterminatecause`  VARCHAR(32)  NOT NULL DEFAULT '',
    `servicetype`         VARCHAR(32)  NULL     DEFAULT NULL,
    `framedprotocol`      VARCHAR(32)  NULL     DEFAULT NULL,
    `framedipaddress`     VARCHAR(15)  NOT NULL DEFAULT '',
    `framedipv6address`   VARCHAR(45)  NOT NULL DEFAULT '',
    `framedipv6prefix`    VARCHAR(45)  NOT NULL DEFAULT '',
    `framedinterfaceid`   VARCHAR(44)  NOT NULL DEFAULT '',
    `delegatedipv6prefix` VARCHAR(45)  NOT NULL DEFAULT '',
    `class`               VARCHAR(64)  NULL     DEFAULT NULL,
    PRIMARY KEY (`radacctid`),
    UNIQUE INDEX `uq_acctuniqueid`     (`acctuniqueid` ASC),
    INDEX `idx_username`               (`username` ASC),
    INDEX `idx_framedip`               (`framedipaddress` ASC),
    INDEX `idx_acctsessionid`          (`acctsessionid` ASC),
    INDEX `idx_acctstarttime`          (`acctstarttime` ASC),
    INDEX `idx_callingstationid`       (`callingstationid` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Accounting RADIUS. FreeRADIUS escribe en Start/Update/Stop.';

-- radcheck: FreeRADIUS verifica credenciales aqui
-- username = codigo_pucp, attribute = Cleartext-Password
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
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Credenciales para FreeRADIUS. op := significa reemplaza cualquier valor.';
 
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
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Atributos de verificacion a nivel de grupo en FreeRADIUS.';
 
-- radgroupreply: atributos que FreeRADIUS devuelve en el Access-Accept por grupo
-- Filter-Id  → lleva el nombre_rol al portal cautivo (M1 lo traduce a vlan_id)
-- Session-Timeout → tiempo maximo de sesion en segundos
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
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Atributos de respuesta por grupo. Filter-Id lleva el nombre_rol a M1.';
 
INSERT INTO `radgroupreply` (groupname, attribute, op, value) VALUES
('Visitante',              'Filter-Id',       '=', 'Visitante'),
('Visitante',              'Session-Timeout', '=', '14400'),
('Estudiante_Telecom',     'Filter-Id',       '=', 'Estudiante_Telecom'),
('Estudiante_Telecom',     'Session-Timeout', '=', '28800'),
('Estudiante_Informatica', 'Filter-Id',       '=', 'Estudiante_Informatica'),
('Estudiante_Informatica', 'Session-Timeout', '=', '28800'),
('Estudiante_Electronica', 'Filter-Id',       '=', 'Estudiante_Electronica'),
('Estudiante_Electronica', 'Session-Timeout', '=', '28800'),
('Docente',                'Filter-Id',       '=', 'Docente'),
('Docente',                'Session-Timeout', '=', '36000'),
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
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Atributos individuales de respuesta RADIUS por usuario.';
 
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
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Asignacion usuario-grupo para FreeRADIUS rlm_sql.';
 
INSERT INTO `radusergroup` (username, groupname, priority) VALUES
('20192434',    'Estudiante_Telecom',     1),
('20200101',    'Estudiante_Informatica', 1),
('20200202',    'Estudiante_Electronica', 1),
('DOC20192020', 'Docente',               1),
('DOC20192021', 'Docente',               1),
('DOC20192022', 'Docente',               1),
('ADMIN001',    'Admin_TI',              1);
 
-- radpostauth: log de autenticaciones (Access-Accept y Access-Reject)
CREATE TABLE IF NOT EXISTS `radpostauth` (
    `id`       INT         NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(64) NOT NULL,
    `pass`     VARCHAR(64) NOT NULL,
    `reply`    VARCHAR(32) NOT NULL,
    `authdate` TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_username` (`username` ASC)
) ENGINE=InnoDB
  DEFAULT CHARACTER SET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Log de autenticaciones RADIUS. FreeRADIUS escribe en post-auth.';
  
-- ============================================================
-- PERMISOS MYSQL
-- Ejecutar como root. Crea el usuario radius si no existe
-- y le otorga los permisos minimos necesarios.
-- ============================================================
-- CREATE USER IF NOT EXISTS 'radius'@'localhost' IDENTIFIED BY 'radius_pass';
 
-- FreeRADIUS (rlm_sql) — solo lectura en tablas de autenticacion
GRANT SELECT ON radius_db.radcheck      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radreply      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radusergroup  TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupcheck TO 'radius'@'localhost';
GRANT SELECT ON radius_db.radgroupreply TO 'radius'@'localhost';
GRANT SELECT ON radius_db.usuarios      TO 'radius'@'localhost';
 
-- FreeRADIUS — escritura en tablas de accounting y log
GRANT SELECT, INSERT, UPDATE ON radius_db.radacct     TO 'radius'@'localhost';
GRANT INSERT                  ON radius_db.radpostauth TO 'radius'@'localhost';
 
-- M1 (portal_cautivo.py) — gestiona sesiones activas, historial y bindings
GRANT SELECT, INSERT, UPDATE, DELETE ON radius_db.sesiones_activas  TO 'radius'@'localhost';
GRANT SELECT, INSERT                 ON radius_db.historial_sesiones TO 'radius'@'localhost';
GRANT SELECT, INSERT, DELETE         ON radius_db.ip_mac_binding     TO 'radius'@'localhost';
GRANT SELECT, UPDATE                 ON radius_db.usuarios           TO 'radius'@'localhost';
 
-- M4 — lectura de bindings y escritura en lista negra
GRANT SELECT                         ON radius_db.ip_mac_binding  TO 'radius'@'localhost';
GRANT SELECT, INSERT, UPDATE         ON radius_db.lista_negra_t0  TO 'radius'@'localhost';
 
-- M2/OPA — solo lectura de politicas
GRANT SELECT ON radius_db.politicas_rbac      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.politicas_temporales TO 'radius'@'localhost';
GRANT SELECT ON radius_db.roles_facultad      TO 'radius'@'localhost';
GRANT SELECT ON radius_db.recursos            TO 'radius'@'localhost';
GRANT SELECT ON radius_db.servidores          TO 'radius'@'localhost';
GRANT SELECT ON radius_db.sesiones_activas    TO 'radius'@'localhost';
 
FLUSH PRIVILEGES;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
