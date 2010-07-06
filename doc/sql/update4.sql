ALTER TABLE `sessions` ADD `client` INT( 4 ) NULL DEFAULT NULL ;
CREATE TABLE `clients` (
    `id` INT( 4 ) NOT NULL AUTO_INCREMENT ,
    `version` VARCHAR( 50 ) NOT NULL ,
    PRIMARY KEY ( `id` )
) ;
