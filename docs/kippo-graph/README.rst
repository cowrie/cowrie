How to send Cowrie output to kippo-graph
########################################

Kippo-Graph Prerequisites
=========================

* Working Cowrie installation
* LAMP stack (Linux, Apache, MySQL, PHP)

Kippo-Graph Installation
========================

This covers a simple installation, with kippo-graph and Cowrie on the same server.
Please see here for installation: https://github.com/ikoniaris/kippo-graph

MySQL configuration for Kippo-Graph
===================================

Configuring Cowrie requires setting up the SQL tables and then telling Cowrie to use them.

To install the tables and create the Cowrie user account enter the following commands::

    $ mysql -u root -p
    CREATE DATABASE cowrie;
    GRANT ALL ON cowrie.* TO 'cowrie'@'localhost' IDENTIFIED BY 'PASSWORD HERE';
    FLUSH PRIVILEGES;
    exit

Next create the database schema::

    $ cd /opt/cowrie/
    $ mysql -u cowrie -p
    USE cowrie;
    source ./docs/sql/mysql.sql;
    exit

disable MySQL strict mode::

    $ vi /etc/mysql/conf.d/disable_strict_mode.cnf

    [mysqld]
    sql_mode=IGNORE_SPACE,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

Cowrie Configuration for Kippo-Graph
====================================

Edit cowrie.cfg::

    $ vi etc/cowrie.cfg

Activate output to mysql::

    [output_mysql]
    host = localhost
    database = cowrie
    username = cowrie
    password = PASSWORD HERE
    port = 3306
    debug = false

Set read access to tty-files for group www-data (group maybe differ on other distributions)::

    $ sudo apt-get install acl
    $ sudo setfacl -Rm g:www-data:rx /opt/cowrie/var/lib/cowrie/tty/

Kippo-Graph Configuration
=========================

Edit config file::

    $ vi /var/www/html/kippo-graph/config.php

Change db settings::

    define('DB_HOST', 'localhost');
    define('DB_USER', 'cowrie');
    define('DB_PASS', 'PASSWORD HERE');
    define('DB_NAME', 'cowrie');
    define('DB_PORT', '3306');

Apache2 configuration (optional)
================================

To secure the installation

Create password database::

    $ cd /etc/apache2/
    $ htpasswd -c /etc/apache2/cowrie.passwd <username>
    $ htpasswd /etc/apache2/cowrie.passwd <username> (second user)


    $ vi /etc/apache2/sites-enabled/000-default.conf

Between the <VirtualHost> </VirtualHost> tags, add::

    <Location />
        AuthBasicAuthoritative On
        AllowOverride AuthConfig

        AuthType Basic
        AuthName "cowrie honeypot"
        AuthUserFile /etc/apache2/cowrie.passwd
        Require valid-user
    </Location>


