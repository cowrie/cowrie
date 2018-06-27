
# Installing Cowrie in nine steps.

* [Step 0: Change existing sshd listening port](#step-0-change-existing-sshd-listening-port)
* [Step 1: Install dependencies](#step-1-install-dependencies)
* [Step 2: Checkout the code](#step-2-checkout-the-code)
* [Install without systemd support](#install-without-systemd-support)
    * [Step 3: Create a user account](#step-3-create-a-user-account)
    * [Step 4: Setup Virtual Environment](#step-4-setup-virtual-environment)
    * [Step 5: Install configuration file](#step-5-install-configuration-file)
    * [Step 6: Generate a DSA key (OPTIONAL)](#step-6-generate-a-dsa-key)
    * [Step 7: Fixing permissions](#step-7-fixing-permissions)
    * [Step 8: Starting Cowrie](#step-8-turning-on-cowrie)
    * [Step 9: Port redirection](#step-9-port-redirection)
* [Install with systemd support](#install-with-systemd-support)
    * [Step 3: Create a user account](#step-3-create-a-user-account)
    * [Step 4: Setup Virtual Environment](#step-4-setup-virtual-environment)
    * [Step 5: Create folders and fix permissions](#step-5-create-folders-and-fix-permissions)
    * [Step 6: Install systemd, rsyslog and logrotate configurations](#Install-systemd-rsyslog-and-logrotate-configurations)
    * [Step 7: Install cowrie configuration file](#step-5-install-cowrie-configuration-file)
    * [Step 8: Starting Cowrie](#step-7-starting-cowrie)
    * [Step 9: Capture traffic](#step-8-capture-traffic)
* [Optional settings](#optinal-settings)
    * [Running within supervisord (OPTIONAL)](#running-using-supervisord)
    * [Configure Additional Output Plugins (OPTIONAL)](#configure-additional-output-plugins-optional)
* [Troubleshooting](#troubleshooting)

## Step 0: Change existing sshd listening port

Cowrie is an SSH honeypot. It is likely you will want it to accept
connections on the normal SSH port (22).  However, this is the same
port you are likely using for administration. To start modify the
SSH listening port for your system.

As root, edit `/etc/ssh/sshd_config` and set the `Port` variable
to your preferred port.

_If you use a host firewall (iptables), you must open up this new
port number in your host firewall._

```
# systemctl daemon-reload
# systemctl restart ssh.service
```
This may disconnect your ssh session. Reconnect using the new port number.

## Step 1: Install dependencies

Install system-wide support for Python virtual environments
and other dependencies. Actual Python packages are installed later.

On Debian based systems:

```
# apt-get install git python-virtualenv libssl-dev libffi-dev build-essential libpython-dev python2.7-minimal
```

## Step 2: Checkout the code
```
# git clone http://github.com/micheloosterhof/cowrie /opt/cowrie
```

## Install without systemd support
This section explains how to install Cowrie on a system without systemd.

**Note**: All commands are run as root

### Step 3: Create a user account
It's strongly recommended to run with a dedicated non-root user id:

```
# useradd -r -s /bin/bash -U -M cowrie
```

### Step 4: Setup Virtual Environment
Next create a virtual environment:

```
# virtualenv /opt/cowrie/cowrie-env
```

Alternatively, create a Python3 virtual environment (under development)

```
# virtualenv --python=python3 /opt/cowrie/cowrie-env
```

Activate the virtual environment and install packages

```
# source /opt/cowrie/cowrie-env/bin/activate
(cowrie-env) # pip install --upgrade pip
(cowrie-env) # pip install --upgrade -r /opt/cowrie/requirements.txt
(cowrie-env) # deactivate
```

### Step 5: Install configuration file
The configuration for Cowrie is stored in `cowrie.cfg.dist` and
`cowrie.cfg`. Both files are combined on startup, where entries from
cowrie.cfg take precedence. The .dist file can be overwritten by
upgrades, cowrie.cfg will not be touched. To run with a standard
configuration, there is no need to change anything. To enable telnet,
create cowrie.cfg and input only the following:

```
[telnet]
enabled = true
```

### Step 6: Generate a DSA key (OPTIONAL)
This step should not be necessary, however some versions of Twisted
are not compatible. To avoid problems in advance, run:

```
# cd /opt/cowrie/data
# ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
```

### Step 7: Setting permissions
Cowrie runs with its own user but we still need to be able
to read/write into some directories

```
# chown -R cowrie:cowrie /opt/cowrie/var
# chown -R cowrie:cowrie /opt/cowrie/log
# chown cowrie:cowrie /opt/cowrie/dl
# chown root:cowrie /opt/cowrie/data
# chmod 775 /opt/cowrie/data
```

_Note_: You will need to update permissions after you upgrade Cowrie from git.

### Step 8: Starting Cowrie
Start Cowrie with the `bin/cowrie` command. You can add the cowrie/bin
directory to your path if desired. An existing virtual environment
is preserved if activated, otherwise Cowrie will attempt to load
the environment called "cowrie-env"

```
# su cowrie -c '/opt/cowrie/bin/cowrie start'
```

### Step 9: Port redirection

Cowrie runs by default on port 2222. The following firewall rule
will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```
Note that you should test this rule only from another host; it
doesn't apply to loopback connections. Alternatively you can run
authbind to listen as non-root on port 22 directly:

```
$ sudo apt-get install authbind
$ sudo touch /etc/authbind/byport/22
$ sudo chown cowrie:cowrie /etc/authbind/byport/22
$ sudo chmod 770 /etc/authbind/byport/22
```
Or for telnet:

```
$ apt-get install authbind
$ sudo touch /etc/authbind/byport/23
$ sudo chown cowrie:cowrie /etc/authbind/byport/23
$ sudo chmod 770 /etc/authbind/byport/23
```
Edit `bin/cowrie` and modify the `AUTHBIND_ENABLED` setting
Change `listen_port` to `22` in `cowrie.cfg`

## Install with systemd support
This chapter explains how to install Cowrie to your system using systemd.

Supported systems are:

- Debian 9 alias Stretch and higher
- Ubuntu 18.04 alias Bionic Beaver and higher

**Note**: All commands are run as root.

### Step 3: Create a user account
It's strongly recommended to run with a dedicated non-root user id:

```
# useradd -r -s /bin/false -U -M cowrie
```

### Step 4: Setup Virtual Environment
Next create your virtual environment:

```
# virtualenv /opt/cowrie-env
```

Alternatively, create a Python3 virtual environment (under development)

```
# virtualenv --python=python3 /opt/cowrie-env
```

Activate the virtual environment and install packages

```
# source /opt/cowrie-env/bin/activate
(cowrie-env) # pip install --upgrade pip
(cowrie-env) # pip install --upgrade -r /opt/cowrie/requirements.txt
(cowrie-env) # deactivate
```

### Step 5: Create folders and fix permissions

```
# chown root:cowrie /opt/cowrie/data
# chmod 0775 /opt/cowrie/data
# mkdir -p /var/lib/cowrie/{downloads,tty}
# chmod -R cowrie:cowrie /var/lib/cowrie
```

### Step 6: Install systemd, rsyslog and logrotate configurations
This will prepare your system to run Cowrie with systemd, collect all
logs to /var/log/cowrie and having logrotate taking care of it.

```
# cp /opt/cowrie/doc/systemd/etc/logrotate.d/cowrie /etc/logrotate.d
# cp /opt/cowrie/doc/systemd/etc/rsyslog.d/cowrie.conf /etc/rsyslog.d
# cp /opt/cowrie/doc/systemd/etc/systemd/system/* /etc/systemd/system
```

### Step 7: Install Cowrie configurations file
The configuration for Cowrie is stored in cowrie.cfg.dist and
cowrie.cfg. Both files are combined on startup, where entries from
cowrie.cfg take precedence. The .dist file can be overwritten by
upgrades, cowrie.cfg will not be touched. To run with a standard
configuration, there is no need to change anything. The version below
is prepared to run with systemd:

```
# cp /opt/cowrie/doc/systemd/cowrie.cfg /opt/cowrie
```

To enable Telnet modify `/opt/cowrie/cowrie.cfg`
```
[telnet]
enabled = true
```

And enable the socket in `/etc/systemd/system/cowrie.socket`
```
ListenStream=2223
```

### Step 8: Starting Cowrie
First we need to reload some other services. This is only needed when
something in the config files changed.

```
# systemctl enable cowrie.socket
# systemctl enable cowrie.service
# systemctl daemon-reload
# systemctl restart rsyslog.service
# systemctl restart logrotate.service
```

Start Cowrie:

```
# systemctl start cowrie.service
```

### Step 9: Accept connections
To capture now traffic we have two options:
1. running Cowrie on port 22 (recommended)
2. redirecting traffic with iptables

#### Running on port 22

Modify `/etc/systemd/system/cowrie.socket` and set

```
ListenStream=22
```
_Note_: It's important that this is the first ListenStream.
Otherwise you might end up mixing SSH and Telnet traffic

```
# systemctl daemon-reload
# systemctl restart ssh.service
```

#### Redirecting traffic
All port redirection commands are system-wide and need to be executed as root.

Cowrie runs by default on port 2222. This can be modified in the configuration file.
The following firewall rule will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## Optional settings
### Running using Supervisord
_Note_: This is not needed for systems with systemd.

On Debian, put the below in /etc/supervisor/conf.d/cowrie.conf
```
[program:cowrie]
command=/home/cowrie/cowrie/bin/cowrie start
directory=/home/cowrie/cowrie/
user=cowrie
autorestart=true
redirect_stderr=true
```
Update the `bin/cowrie script`, change:
 ```
 DAEMONIZE=""
 ```
 to:
 ```
 DAEMONIZE="-n"
 ```

### Configure Additional Output Plugins

Cowrie automatically outputs event data to text and JSON log files
in ~/cowrie/log.  Additional output plugins can be configured to
record the data other ways.  Supported output plugins include:

* Cuckoo
* ELK (Elastic) Stack
* Graylog
* Kippo-Graph
* Splunk
* SQL (MySQL, SQLite3, RethinkDB)

See ~/cowrie/doc/[Output Plugin]/README.md for details.


## Troubleshooting

* If you see `twistd: Unknown command: cowrie` there are two
possibilities. If there's a python stack trace, it probably means
there's a missing or broken dependency. If there's no stack trace,
double check that your PYTHONPATH is set to the source code directory.
* Default file permissions

To make Cowrie logfiles public readable, change the ```--umask 0077``` option in start.sh into ```--umask 0022```

# Updating Cowrie

Updating is an easy process. First stop your honeypot. Then fetch
updates from GitHub, as a next step upgrade your Python dependencies.

```
bin/cowrie stop
git pull
pip install --upgrade -r requirements.txt
bin/cowrie start
```

# Modifying Cowrie

The pre-login banner can be set by creating the file `honeyfs/etc/issue.net`.
The post-login banner can be customized by editing `honeyfs/etc/motd`.

