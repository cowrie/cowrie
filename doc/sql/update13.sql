CREATE TABLE IF NOT EXISTS `params` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `arch` varchar(32) NOT NULL,
  PRIMARY KEY  (`id`)
) ;
CREATE INDEX arch_index ON params (arch);
