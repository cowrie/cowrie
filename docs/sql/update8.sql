-- SPDX-FileCopyrightText: 2015-2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

ALTER TABLE `downloads` ADD `shasum` VARCHAR(64) DEFAULT NULL;
