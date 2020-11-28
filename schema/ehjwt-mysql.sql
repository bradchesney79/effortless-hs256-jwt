CREATE DATABASE EHJWT;

USE EHJWT;

CREATE TABLE IF NOT EXISTS `revoked_ehjwt` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `jti` bigint unsigned NOT NULL,
  `sub` bigint unsigned NOT NULL,
  `exp` int unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `jti_i` (`jti`) USING HASH,
  KEY `sub_i` (`sub`) USING HASH
) ENGINE=InnoDB;