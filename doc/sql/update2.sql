--
-- WARNING: Existing data may be lost & messed up
--

ALTER TABLE `session` RENAME `sessions` ;

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` int(11) NOT NULL auto_increment,
  `ip` varchar(15) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

INSERT INTO `sensors` (`ip`) (SELECT DISTINCT `sensor` FROM `sessions`) ;

UPDATE `sessions` SET `sensor` =
    (SELECT `id` FROM `sensors` WHERE `sensors`.`ip` = `sessions`.`sensor`) ;

ALTER TABLE `sessions` CHANGE `sensor` `sensor` INT( 4 ) NOT NULL ;

CREATE TABLE IF NOT EXISTS `ttylog` (
  `id` int(11) NOT NULL auto_increment,
  `session` int(11) NOT NULL,
  `ttylog` mediumblob NOT NULL,
  PRIMARY KEY  (`id`)
) ;

INSERT INTO `ttylog` (`session`, `ttylog`)
    (SELECT `id`, `ttylog` FROM `sessions` WHERE LENGTH(`ttylog`) > 0) ;

ALTER TABLE `sessions` DROP `ttylog` ;
