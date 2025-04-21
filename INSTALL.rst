Installing Cowrie in seven steps
################################

This guide describes how to install Cowrie in ``shell`` mode. For ``proxy`` mode
read `PROXY.rst`.

* :ref:`Step 1: Install system dependencies<Step 1: Install system dependencies>`
* :ref:`Step 2: Create a user account<Step 2: Create a user account>`
* :ref:`Step 3: Checkout the code<Step 3: Checkout the code>`
* :ref:`Step 4: Setup Virtual Environment<Step 4: Setup Virtual Environment>`
* :ref:`Step 5: Install configuration file<Step 5: Install configuration file>`
* :ref:`Step 6: Starting Cowrie<Step 6: Starting Cowrie>`
* :ref:`Step 7: Listening on port 22 (OPTIONAL)<Step 7: Listening on port 22 (OPTIONAL)>`
* :ref:`Installing Backend Pool dependencies (OPTIONAL)<Installing Backend Pool dependencies (OPTIONAL)>`
* :ref:`Running using supervisord (OPTIONAL)<Running using supervisord (OPTIONAL)>`
* :ref:`Configure Additional Output Plugins (OPTIONAL)<Configure Additional Output Plugins (OPTIONAL)>`
* :ref:`Troubleshooting<Troubleshooting>`
* :ref:`Updating Cowrie<Updating Cowrie>`
* :ref:`Modifying Cowrie<Modifying Cowrie>`

Step 1: Install system dependencies
***********************************

First we install system-wide support for Python virtual environments and other dependencies.
Actual Python packages are installed later.

On Debian based systems (last verified on Debian Bookworm)::

    $ sudo apt-get install git python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind

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
    $ python3 -m venv cowrie-env
    New python executable in ./cowrie/cowrie-env/bin/python
    Installing setuptools, pip, wheel...done.

Activate the virtual environment and install packages::

    $ source cowrie-env/bin/activate
    (cowrie-env) $ python -m pip install --upgrade pip
    (cowrie-env) $ python -m pip install --upgrade -r requirements.txt

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

And change the listening ports in ``cowrie.cfg`` as above.


Installing Backend Pool dependencies (OPTIONAL)
***********************************************

If you want to use the proxy functionality combined with the automatic
backend pool, you need to install some dependencies, namely QEMU, libvirt,
and their Python interface. In Debian/Ubuntu::

    $ sudo apt-get install qemu-system-arm qemu-system-x86 libvirt-dev libvirt-daemon libvirt-daemon-system libvirt-clients nmap

Then install the Python API to run the backend pool::

    (cowrie-env) $ python -m pip install -r requirements-pool.txt

To allow QEMU to use disk images and snapshots, set it to run with the user and group of the user running the pool
(usually called 'cowrie' too::

    $ sudo vi /etc/libvirt/qemu.conf

Search and set both `user` and `group` to `"cowrie"`, or the username/group you'll be running the backend pool with.

Running using Supervisord (OPTIONAL)
************************************

On Debian, put the below in /etc/supervisor/conf.d/cowrie.conf::

    [program:cowrie]
    command=/home/cowrie/cowrie/bin/cowrie start -n
    directory=/home/cowrie/cowrie/
    user=cowrie
    autorestart=true
    redirect_stderr=true

Configure Additional Output Plugins (OPTIONAL)
**********************************************

Cowrie automatically outputs event data to text and JSON log files
in ``var/log/cowrie``.  Additional output plugins can be configured to
record the data other ways.  Supported output plugins include:

* Cuckoo
* ELK (Elastic) Stack
* Graylog
* Splunk
* SQL (MySQL, SQLite3, RethinkDB)

See ~/cowrie/docs/[Output Plugin]/README.rst for details.


Troubleshooting
***************

CryptographyDeprecationWarning: Blowfish has been deprecated
============================================================

The following warning may occur, this can be safely ignored, and
is not the reason your Cowrie installation is not working::

    CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.

twistd: unknown command: cowrie
===============================

If you see ``twistd: Unknown command: cowrie`` there are two
possibilities. If there's a Python stack trace, it probably means
there's a missing or broken dependency. If there's no stack trace,
double check that your PYTHONPATH is set to the source code directory.

Default file permissions
========================

To make Cowrie logfiles public readable, change the ``--umask 0077``
option in ``bin/cowrie`` into ``--umask 0022``

General approach
================

Check the log file in ``var/log/cowrie/cowrie.log``.

Updating Cowrie
***************

First stop your honeypot. Then pull updates from GitHub, and upgrade your Python dependencies::

    $ bin/cowrie stop
    $ git pull
    $ python -m pip install --upgrade -r requirements.txt

If you use output plugins like SQL, Splunk, or ELK, remember to also upgrade your dependencies for these too::

    $ python -m pip install --upgrade -r requirements-output.txt

And finally, restart Cowrie after finishing all updates::

    $ bin/cowrie start

Modifying Cowrie
****************

The pre-login banner can be set by creating the file ``honeyfs/etc/issue.net``.
The post-login banner can be customized by editing ``honeyfs/etc/motd``.
