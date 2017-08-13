# How to send Cowrie output to MySQL database

## Prerequisites

* Working Cowrie installation
* Working MySQL database

## Installation

```
su - cowrie
source cowrie/cowrie-env/bin/activate
pip install MySQL-python
```

## mySQL configuration

First create the database and grant access to the Cowrie user account:
```
mysql -u root -p
CREATE DATABASE cowrie;
GRANT ALL ON cowrie.* TO 'cowrie'@'localhost' IDENTIFIED BY 'PASSWORD HERE';
FLUSH PRIVILEGES;
exit
```

Next load the database schema:
```
cd /opt/cowrie/
mysql -u cowrie -p
USE cowrie;
source ./doc/sql/mysql.sql;
exit
```

## cowrie configuration

* Add the following entries to ~/cowrie/cowrie.cfg

```
[output_mysql]
host = localhost
database = cowrie
username = cowrie
password = PASSWORD HERE
port = 3306
debug = false
```

