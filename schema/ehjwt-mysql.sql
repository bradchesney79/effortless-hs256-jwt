CREATE TABLE IF NOT EXISTS `revoked_ehjwt` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `jti` bigint unsigned NOT NULL,
  `sub` int unsigned NOT NULL,
  `exp` int unsigned NOT NULL,
  PRIMARY KEY (`id`);
  ) ENGINE=InnoDB;