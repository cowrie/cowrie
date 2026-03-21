-- SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

/* ipv6 support in `sessions` & `sensors` */
ALTER TABLE `sessions` CHANGE `ip` VARCHAR( 61 ) NOT NULL DEFAULT '';
ALTER TABLE `sensors` CHANGE `ip` VARCHAR( 61 ) NOT NULL DEFAULT '';