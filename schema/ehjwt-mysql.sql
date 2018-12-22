


CREATE TABLE `revoked_ehjwt` IF NOT EXISTS (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `jti` int(10) unsigned DEFAULT NULL,
  `sub` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `exp` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`);