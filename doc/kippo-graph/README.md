# How to process Cowrie output in kippo-graph

* (Note: work in progress, instructions are not verified)
* Tested on Debian 9.


## Prerequisites

* Working Cowrie installation
* LAMP stack (Linux, Apache, MySQL, PHP)

## Installation

This covers a simple installation, with kippo-graph and Cowrie on the same server.
Please see here for installation: https://github.com/ikoniaris/kippo-graph


## mySQL configuration

Configuring Cowrie requires setting up the SQL tables and then telling Cowrie to use them.

To install the tables and create the Cowrie user account enter the following commands:
```
mysql -u root -p
CREATE DATABASE cowrie;
GRANT ALL ON cowrie.* TO 'cowrie'@'localhost' IDENTIFIED BY 'PASSWORD HERE';
FLUSH PRIVILEGES;
exit
```

next create the database schema:
```
cd /opt/cowrie/
mysql -u cowrie -p
USE cowrie;
source ./doc/sql/mysql.sql;
exit
```

## cowrie configuration

```
vi /opt/cowrie/cowrie.cfg
```


* Activate output to mysql
```
[output_mysql]
host = localhost
database = cowrie
username = cowrie
password = PASSWORD HERE
port = 3306
debug = false
```

* set read access to tty-files for group www-data (group maybe differ on other distributions)
```
sudo apt-get install act
sudo setfacl -Rm g:www-data:rx /opt/cowrie/log/tty/
```

## kippo-graph Configuration

```
vi /var/www/html/kippo-graph/config.php
```


* Change db settings
```
define('DB_HOST', 'localhost');
define('DB_USER', 'cowrie');
define('DB_PASS', 'PASSWORD HERE');
define('DB_NAME', 'cowrie'); 
define('DB_PORT', '3306');
```

## Apache2 configuration (optional)

* to secure the installation

Create password database:
```
cd /etc/apache2/
htpasswd -c /etc/apache2/cowrie.passwd <username>
htpasswd /etc/apache2/cowrie.passwd <username> (second user)
```


```
vi /etc/apache2/sites-enabled/000-default.conf
```
Between the <VirtualHost> </VirtualHost> tags, add:
```
<Location />
    AuthBasicAuthoritative On
    AllowOverride AuthConfig

    AuthType Basic
    AuthName "cowrie honeypot"
    AuthUserFile /etc/apache2/cowrie.passwd
    Require valid-user
   </Location>
```

