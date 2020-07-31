
Installing Cowrie in seven steps.
#################################

This guide describes how to install Cowrie in `shell` mode. For `proxy` mode
read `PROXY.rst`.

* [Step 1: Install dependencies](#step-1-install-dependencies)
* [Step 2: Create a user account](#step-2-create-a-user-account)
* [Step 3: Checkout the code](#step-3-checkout-the-code)
* [Step 4: Setup Virtual Environment](#step-4-setup-virtual-environment)
* [Step 5: Install configuration file](#step-5-install-configuration-file)
* [Step 6: Starting Cowrie](#step-6-starting-cowrie)
* [Step 8: Listening on port 22 (OPTIONAL)](#step-8-listening-on-port-22-optional)
* [Installing Backend Pool dependencies (OPTIONAL)](#running-using-supervisord)
* [Running within supervisord (OPTIONAL)](#running-using-supervisord)
* [Configure Additional Output Plugins (OPTIONAL)](#configure-additional-output-plugins-optional)
* [Troubleshooting](#troubleshooting)
* [Updating Cowrie](#updating-cowrie)
* [Modifying Cowrie](#modifying-cowrie)

Step 1: Install dependencies
****************************

First we install system-wide support for Python virtual environments and other dependencies.
Actual Python packages are installed later.

On Debian based systems (last verified on Debian 10, 2019-08-18):
For a Python3 based environment::

    $ sudo apt-get install git python-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv

Step 2: Create a user account
*****************************

It's strongly recommended to run with a dedicated non-root user id::

    $ sudo adduser --disabled-password cowrie
    Adding user 'cowrie' ...
    Adding new group 'cowrie' (1002) ...
    Adding new user 'cowrie' (1002) with group 'cowrie' ...
    Changing the user information for cowrie
    Enter the new value, or press ENTER for the default
    Full Name []:
    Room Number []:
    Work Phone []:
    Home Phone []:
    Other []:
    Is the information correct? [Y/n]

    $ sudo su - cowrie

Step 3: Checkout the code
*************************

Check out the code::

    $ git clone http://github.com/cowrie/cowrie
    Cloning into 'cowrie'...
    remote: Counting objects: 2965, done.
    remote: Compressing objects: 100% (1025/1025), done.
    remote: Total 2965 (delta 1908), reused 2962 (delta 1905), pack-reused 0
    Receiving objects: 100% (2965/2965), 3.41 MiB | 2.57 MiB/s, done.
    Resolving deltas: 100% (1908/1908), done.
    Checking connectivity... done.

    $ cd cowrie

Step 4: Setup Virtual Environment
*********************************

Next you need to create your virtual environment::

    $ pwd
    /home/cowrie/cowrie
    $ virtualenv --python=python3 cowrie-env
    New python executable in ./cowrie/cowrie-env/bin/python
    Installing setuptools, pip, wheel...done.

Activate the virtual environment and install packages::

    $ source cowrie-env/bin/activate
    (cowrie-env) $ pip install --upgrade pip
    (cowrie-env) $ pip install --upgrade -r requirements.txt

Step 5: Install configuration file
**********************************

The configuration for Cowrie is stored in cowrie.cfg.dist and
cowrie.cfg (Located in cowrie/etc). Both files are read on startup, where entries from
cowrie.cfg take precedence. The .dist file can be overwritten by
upgrades, cowrie.cfg will not be touched. To run with a standard
configuration, there is no need to change anything. To enable telnet,
for example, create cowrie.cfg and input only the following::

    [telnet]
    enabled = true

Step 6: Starting Cowrie
***********************

Start Cowrie with the cowrie command. You can add the cowrie/bin
directory to your path if desired. An existing virtual environment
is preserved if activated, otherwise Cowrie will attempt to load
the environment called "cowrie-env"::


    $ bin/cowrie start
    Activating virtualenv "cowrie-env"
    Starting cowrie with extra arguments [] ...

Step 7: Listening on port 22 (OPTIONAL)
***************************************

There are three methods to make Cowrie accessible on the default SSH port (22): `iptables`, `authbind` and `setcap`.

Iptables
========

Port redirection commands are system-wide and need to be executed as root.
A firewall redirect can make your existing SSH server unreachable, remember to move the existing
server to a different port number first.

The following firewall rule will forward incoming traffic on port 22 to port 2222 on Linux::

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

Or for telnet::

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

Note that you should test this rule only from another host; it doesn't apply to loopback connections.

On MacOS run::

    $ echo "rdr pass inet proto tcp from any to any port 22 -> 127.0.0.1 port 2222" | sudo pfctl -ef -

Authbind
========

Alternatively you can run authbind to listen as non-root on port 22 directly::

    $ sudo apt-get install authbind
    $ sudo touch /etc/authbind/byport/22
    $ sudo chown cowrie:cowrie /etc/authbind/byport/22
    $ sudo chmod 770 /etc/authbind/byport/22

Edit bin/cowrie and modify the AUTHBIND_ENABLED setting

Change the listening port to 22 in cowrie.cfg::

    [ssh]
    listen_endpoints = tcp:22:interface=0.0.0.0

Or for telnet::

    $ apt-get install authbind
    $ sudo touch /etc/authbind/byport/23
    $ sudo chown cowrie:cowrie /etc/authbind/byport/23
    $ sudo chmod 770 /etc/authbind/byport/23

Change the listening port to 23 in cowrie.cfg::

    [telnet]
    listen_endpoints = tcp:2223:interface=0.0.0.0

Setcap
======

Or use setcap to give permissions to Python to listen on ports<1024:: 

    $ setcap cap_net_bind_service=+ep /usr/bin/python3

And change the listening ports in `cowrie.cfg` as above.


Installing Backend Pool dependencies (OPTIONAL)
***********************************************

If you want to use the proxy functionality combined with the automatic
backend pool, you need to install some dependencies, namely qemu, libvirt,
and their Python interface. In Debian/Ubuntu::

    $ sudo apt-get install qemu qemu-system-arm qemu-system-x86 libvirt-dev libvirt-daemon libvirt-daemon-system libvirt-clients nmap

Then install the Python API to run the backend pool::

    (cowrie-env) $ pip install libvirt-python==6.4.0

To allow Qemu to use disk images and snapshots, set it to run with the user and group of the user running the pool
(usually called 'cowrie' too::

    $ sudo vim /etc/libvirt/qemu.conf

Search and set both `user` and `group` to `"cowrie"`, or the username/group you'll be running the backend pool with.

Running using Supervisord (OPTIONAL)
************************************

On Debian, put the below in /etc/supervisor/conf.d/cowrie.conf::

    [program:cowrie]
    command=/home/cowrie/cowrie/bin/cowrie start
    directory=/home/cowrie/cowrie/
    user=cowrie
    autorestart=true
    redirect_stderr=true

Update the bin/cowrie script, change::

    DAEMONIZE=""

to::

    DAEMONIZE="-n"

Configure Additional Output Plugins (OPTIONAL)
**********************************************

Cowrie automatically outputs event data to text and JSON log files
in `var/log/cowrie`.  Additional output plugins can be configured to
record the data other ways.  Supported output plugins include:

* Cuckoo
* ELK (Elastic) Stack
* Graylog
* Kippo-Graph
* Splunk
* SQL (MySQL, SQLite3, RethinkDB)

See ~/cowrie/docs/[Output Plugin]/README.rst for details.


Troubleshooting
###############

If you see `twistd: Unknown command: cowrie` there are two
  possibilities. If there's a Python stack trace, it probably means
  there's a missing or broken dependency. If there's no stack trace,
  double check that your PYTHONPATH is set to the source code directory.

Default file permissions

To make Cowrie logfiles public readable, change the ``--umask 0077`` option in start.sh into ``--umask 0022``

Updating Cowrie
#################

Updating is an easy process. First stop your honeypot. Then fetch updates from GitHub, and upgrade your Python dependencies::

    bin/cowrie stop
    git pull
    pip install --upgrade -r requirements.txt

If you use output plugins like SQL, Splunk, or ELK, remember to also upgrade your dependencies for these too::

    pip install --upgrade -r requirements-output.txt

And finally, start Cowrie back up after finishing all updates::

    bin/cowrie start

Modifying Cowrie
################

The pre-login banner can be set by creating the file `honeyfs/etc/issue.net`.
The post-login banner can be customized by editing `honeyfs/etc/motd`.
