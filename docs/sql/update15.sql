/* `dst_ip` can also contain FQDN, not just IP */
ALTER TABLE `ipforwards` CHANGE `dst_ip` `session` VARCHAR( 255 ) NOT NULL ;
ALTER TABLE `ipforwardsdata` CHANGE `dst_ip` `session` VARCHAR( 255 ) NOT NULL ;
