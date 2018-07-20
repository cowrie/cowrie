/* For the asynchronous mysql code, change session to use a 32 character
 * string instead of int(11) */

ALTER TABLE `auth` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
ALTER TABLE `input` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
ALTER TABLE `sessions` CHANGE `id` `id` CHAR( 32 ) NOT NULL ;
ALTER TABLE `ttylog` CHANGE `session` `session` CHAR( 32 ) NOT NULL ;
