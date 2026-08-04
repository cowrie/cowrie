-- SPDX-FileCopyrightText: 2010 Upi Tamminen <desaster@gmail.com>
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

/* For the asynchronous mysql code, change session to use a 32 character
 * string instead of int(11) */

ALTER TABLE `auth` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
ALTER TABLE `input` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
ALTER TABLE `sessions` CHANGE `id` `id` CHAR( 32 ) NOT NULL ;
ALTER TABLE `ttylog` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
