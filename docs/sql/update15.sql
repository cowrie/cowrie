-- SPDX-FileCopyrightText: 2019 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

/* `dst_ip` can also contain FQDN, not just IP */
ALTER TABLE `ipforwards` CHANGE `dst_ip` `session` VARCHAR( 255 ) NOT NULL ;
ALTER TABLE `ipforwardsdata` CHANGE `dst_ip` `session` VARCHAR( 255 ) NOT NULL ;
