CREATE TABLE IF NOT EXISTS `auth` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `timestamp` datetime NOT NULL
) ;

CREATE TABLE IF NOT EXISTS `clients` (
  `id` INTEGER PRIMARY KEY,
  `version` varchar(50) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS `input` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `realm` varchar(50) default NULL,
  `success` tinyint(1) default NULL,
  `input` text NOT NULL
) ;
CREATE INDEX input_index ON input(session, timestamp, realm);

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` INTEGER PRIMARY KEY,
  `ip` varchar(61) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS `sessions` (
  `id` char(32) NOT NULL PRIMARY KEY,
  `starttime` datetime NOT NULL,
  `endtime` datetime default NULL,
  `sensor` int(4) NOT NULL,
  `ip` varchar(61) NOT NULL default '',
  `termsize` varchar(7) default NULL,
  `client` int(4) default NULL
) ;
CREATE INDEX sessions_index ON sessions(starttime, sensor);

CREATE TABLE IF NOT EXISTS `ttylog` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `ttylog` varchar(100) NOT NULL,
  `size` int(11) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `timestamp` datetime NOT NULL,
  `url` text NOT NULL,
  `outfile` text default NULL,
  `shasum` varchar(64) default NULL
) ;
CREATE INDEX downloads_index ON downloads(session, timestamp);

CREATE TABLE IF NOT EXISTS `keyfingerprints` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `username` varchar(100) NOT NULL,
  `fingerprint` varchar(100) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS `params` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `arch` varchar(32) NOT NULL
) ;
CREATE INDEX arch_index ON params(arch);

CREATE TABLE IF NOT EXISTS `ipforwards` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  FOREIGN KEY(`session`) REFERENCES `sessions`(`id`)
) ;

CREATE TABLE IF NOT EXISTS `ipforwardsdata` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  `data` text NOT NULL,
  FOREIGN KEY(`session`) REFERENCES `sessions`(`id`)
) ;
