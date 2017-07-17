# How to process cowrie output in kippo-graph

* (Note: work in progress, instructions are not verified)
* Tested on Debian 9.
* Just work for new attacks!


## Prerequisites

* Working cowrie installation
* LAMP (See below)

## Installation

We'll examine simple installation, when we install kippo-graph on the same machine that used for cowrie.

Please see here for installation:
https://github.com/ikoniaris/kippo-graph


## mySQL configuration

Configuring cowrie requires setting up the sql tables and then telling cowrie to use them.

To install the tables and create the cowrie user account enter the following commands:
```
mysql -u root -p
CREATE DATABASE cowrie;
GRANT ALL ON cowrie.* TO 'cowrie'@'localhost' IDENTIFIED BY 'PASSWORD HERE';
FLUSH PRIVILEGES;
exit
```

now we need to populate the table structure
```
cd /opt/cowrie/
mysql -u cowrie -p
USE cowrie;
source ./doc/sql/mysql.sql;
exit
```

## cowrie configuration

vi /opt/cowrie/cowrie.cfg


* Activate output to mysql
```
[output_mysql]
host = localhost
database = cowrie
username = cowrie
password = secret >>> (please change!)
port = 3306
debug = false
```

* set read access to tty-files for group www-data (group maybe differ on other distributions)
```
sudo apt-get install act
## for current logs
sudo setfacl -m g:www-data:rx /opt/cowrie/log/tty/*.log
## and new default for new logs
sudo setfacl -Rdm g:www-data:rx /opt/cowrie/log/tty/
```

## kippo-graph Configuration

vi /var/www/html/kippo-graph/config.php


* Change db settings
```
define('DB_HOST', 'localhost');
define('DB_USER', 'cowrie');
define('DB_PASS', 'secret'); >>> (please change!)
define('DB_NAME', 'cowrie'); 
define('DB_PORT', '3306');
```

## apache2 Configuration (optional)

* to secure the installation

Create password database
```
cd /etc/apache2/
htpasswd -c /etc/apache2/cowrie.passwd <username>
htpasswd /etc/apache2/cowrie.passwd <username> (second user)
```

vi /etc/apache2/sites-enabled/000-default.conf (for http!)
```
Between the <VirtualHost> </VirtualHost> tags

<Location /kippo-graph>
    AuthBasicAuthoritative On
    AllowOverride AuthConfig

    AuthType Basic
    AuthName "cowrie honeypot"
    AuthUserFile /etc/apache2/cowrie.passwd
    Require valid-user
   </Location>
```

Don't forget to reload apache to activate your changes ;)

## open kippo-graph
You can now access kippo-graph with http(s)://your-server-address/kippo-graph/
