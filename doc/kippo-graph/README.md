# How to process Cowrie output in kippo-graph

(Note: work in progress, instructions are not verified)


## Prerequisites

* Working Cowrie installation
* LAMP (See below)

## Installation


We'll examine simple installation, when we install kippo-graph on the same machine that used for cowrie.

Please see here for installation:
https://github.com/ikoniaris/kippo-graph

## cowrie Configuration

cd /opt/cowrie
vi cowrie.cfg

* Activate output to mysql
[output_mysql]
host = localhost
database = cowrie
username = cowrie
password = secret (please change!)
port = 3306
debug = false

* set read access to tty-files for group www-data (on debian! maybe differ on other distributions)
sudo apt-get install act
sudo setfacl -Rm g:www-data:rx /opt/cowrie/log/tty/


## kippo-graph Configuration

cd /var/www/html/kippo-graph
vi config.php

* Change db settings
define('DB_HOST', '127.0.0.1');
define('DB_USER', 'username');
define('DB_PASS', 'password');
define('DB_NAME', 'database');
define('DB_PORT', '3306');


