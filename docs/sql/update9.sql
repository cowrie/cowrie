-- SPDX-FileCopyrightText: 2015 g0tmi1k <have.you.g0tmi1k@gmail.com>
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

ALTER TABLE `ttylog` CHANGE `ttylog` `ttylog` VARCHAR(100) NOT NULL;
ALTER TABLE `ttylog` ADD `size` INT(11) NOT NULL;
