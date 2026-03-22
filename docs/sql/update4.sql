-- SPDX-FileCopyrightText: 2010 Upi Tamminen <desaster@gmail.com>
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

ALTER TABLE `sessions` ADD `client` INT( 4 ) NULL DEFAULT NULL ;
CREATE TABLE `clients` (
    `id` INT( 4 ) NOT NULL AUTO_INCREMENT ,
    `version` VARCHAR( 50 ) NOT NULL ,
    PRIMARY KEY ( `id` )
) ;
