-- SPDX-FileCopyrightText: 2019 Guilherme Borges <g.borges@campus.fct.unl.pt>
-- SPDX-FileCopyrightText: 2023 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

CREATE TABLE IF NOT EXISTS `ipforwards` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(15) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  PRIMARY KEY  (`id`),
  FOREIGN KEY (`session`) REFERENCES `sessions`(`id`)
) ;

CREATE TABLE IF NOT EXISTS `ipforwardsdata` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(15) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  `data` text NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`),
  FOREIGN KEY (`session`) REFERENCES `sessions`(`id`)
) ;
