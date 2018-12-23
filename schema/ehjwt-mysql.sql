CREATE TABLE IF NOT EXISTS `revoked_ehjwt` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `jti` bigint(20) unsigned NOT NULL,
  `sub` int(10) unsigned NOT NULL,
  `exp` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `jti_i` (`jti`) USING HASH,
  KEY `sub_i` (`sub`) USING HASH
) ENGINE=InnoDB;