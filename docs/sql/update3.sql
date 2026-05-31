-- SPDX-FileCopyrightText: 2010 Upi Tamminen <desaster@gmail.com>
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

ALTER TABLE `sessions` ADD `termsize` VARCHAR( 7 ) NULL DEFAULT NULL ,
ADD `termtitle` VARCHAR( 255 ) NULL DEFAULT NULL ;
