CREATE TABLE IF NOT EXISTS `auth` (
  `id` int(11) NOT NULL auto_increment,
  `session` char(32) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE IF NOT EXISTS `clients` (
  `id` int(4) NOT NULL auto_increment,
  `version` varchar(50) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE IF NOT EXISTS `input` (
  `id` int(11) NOT NULL auto_increment,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `realm` varchar(50) default NULL,
  `success` tinyint(1) default NULL,
  `input` text NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`,`realm`)
) ;

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` int(11) NOT NULL auto_increment,
  `ip` varchar(255) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE IF NOT EXISTS `sessions` (
  `id` char(32) NOT NULL,
  `starttime` datetime NOT NULL,
  `endtime` datetime default NULL,
  `sensor` int(4) NOT NULL,
  `ip` varchar(61) NOT NULL default '',
  `termsize` varchar(7) default NULL,
  `client` int(4) default NULL,
  PRIMARY KEY  (`id`),
  KEY `starttime` (`starttime`,`sensor`)
) ;

CREATE TABLE IF NOT EXISTS `ttylog` (
  `id` int(11) NOT NULL auto_increment,
  `session` char(32) NOT NULL,
  `ttylog` varchar(100) NOT NULL,
  `size` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `timestamp` datetime NOT NULL,
  `url` text NOT NULL,
  `outfile` text default NULL,
  `shasum` varchar(64) default NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`)
) ;

CREATE TABLE IF NOT EXISTS `keyfingerprints` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `username` varchar(100) NOT NULL,
  `fingerprint` varchar(100) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE IF NOT EXISTS `params` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `arch` varchar(32) NOT NULL,
  PRIMARY KEY  (`id`)
) ;
CREATE INDEX arch_index ON params (arch);

CREATE TABLE IF NOT EXISTS `ipforwards` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  PRIMARY KEY  (`id`),
  FOREIGN KEY (`session`) REFERENCES `sessions`(`id`)
) ;

CREATE TABLE IF NOT EXISTS `ipforwardsdata` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  `data` text NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`),
  FOREIGN KEY (`session`) REFERENCES `sessions`(`id`)
) ;
