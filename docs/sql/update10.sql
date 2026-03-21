-- SPDX-FileCopyrightText: 2015 g0tmi1k <have.you.g0tmi1k@gmail.com>
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

CREATE TABLE `keyfingerprints` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `username` varchar(100) NOT NULL,
  `fingerprint` varchar(100) NOT NULL,
  PRIMARY KEY  (`id`),
) ;
