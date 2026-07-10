-- M4 security schema for MySQL 8 / radius_db.
-- This file is intentionally not applied automatically.

USE `radius_db`;

CREATE TABLE IF NOT EXISTS `security_events` (
    `id_event` BIGINT NOT NULL AUTO_INCREMENT,
    `idempotency_key` VARCHAR(64) NOT NULL,
    `source` ENUM('m6','suricata','sflow','netflow') NOT NULL,
    `event_type` VARCHAR(64) NOT NULL,
    `event_timestamp` DATETIME(6) NOT NULL,
    `src_ip` VARCHAR(45) NULL,
    `src_mac` VARCHAR(17) NULL,
    `dst_ip` VARCHAR(45) NULL,
    `dst_port` INT NULL,
    `protocol` VARCHAR(16) NULL,
    `switch_dpid` VARCHAR(64) NULL,
    `in_port` INT NULL,
    `username` VARCHAR(64) NULL,
    `role_name` VARCHAR(64) NULL,
    `severity` INT NOT NULL DEFAULT 0,
    `metadata_json` JSON NOT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_event`),
    UNIQUE KEY `uq_security_event_idempotency` (`idempotency_key`),
    KEY `idx_security_event_identity` (`src_ip`, `src_mac`),
    KEY `idx_security_event_time` (`event_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `security_incidents` (
    `incident_id` VARCHAR(36) NULL,
    `asset_id` VARCHAR(64) NULL,
    `permanent` TINYINT(1) NOT NULL DEFAULT 0,
    `incident_key` VARCHAR(255) NOT NULL,
    `state` ENUM(
        'NEW','WATCHING','MIRRORING','CONTAINED','BLOCKED','CLOSED'
    ) NOT NULL,
    `score` INT NOT NULL DEFAULT 0,
    `threat_type` VARCHAR(64) NOT NULL,
    `recommended_action` ENUM(
        'LOG','WATCH','MIRROR','TEMP_BLOCK','BLOCK','UNBLOCK'
    ) NOT NULL,
    `payload_json` JSON NOT NULL,
    `created_at` DATETIME(6) NOT NULL,
    `updated_at` DATETIME(6) NOT NULL,
    PRIMARY KEY (`incident_id`),
    UNIQUE KEY `uq_security_incident_key` (`incident_key`),
    KEY `idx_security_incident_state` (`state`),
    KEY `idx_security_incident_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `security_actions` (
    `action_id` VARCHAR(36) NOT NULL,
    `incident_id` VARCHAR(36) NOT NULL,
    `action_type` ENUM(
        'LOG','WATCH','MIRROR','TEMP_BLOCK','BLOCK','UNBLOCK'
    ) NOT NULL,
    `status` ENUM('RECOMMENDED','SIMULATED','EXECUTED','FAILED') NOT NULL,
    `payload_json` JSON NOT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`action_id`),
    KEY `idx_security_action_incident` (`incident_id`),
    CONSTRAINT `security_action_incident_fk`
        FOREIGN KEY (`incident_id`)
        REFERENCES `security_incidents` (`incident_id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `active_mirrors` (
    `mirror_id` VARCHAR(64) NOT NULL,
    `incident_id` VARCHAR(36) NOT NULL,
    `switch_dpid` VARCHAR(64) NOT NULL,
    `bridge_name` VARCHAR(64) NULL,
    `in_port` INT NULL,
    `src_mac` VARCHAR(17) NULL,
    `status` ENUM('PLANNED','SIMULATED','ACTIVE','EXPIRED','REMOVED','FAILED')
        NOT NULL DEFAULT 'PLANNED',
    `expires_at` DATETIME(6) NULL,
    `payload_json` JSON NOT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`mirror_id`),
    KEY `idx_active_mirror_incident` (`incident_id`),
    KEY `idx_active_mirror_asset` (`asset_id`),
    KEY `idx_active_mirror_expiry` (`status`, `expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
