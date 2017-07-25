
# Installing Cowrie in seven steps.

* [Step 1: Install dependencies](#step-1-install-dependencies)
* [Step 2: Create a user account](#step-2-create-a-user-account)
* [Step 3: Checkout the code](#step-3-checkout-the-code)
* [Step 4: Setup Virtual Environment](#step-4-setup-virtual-environment)
* [Step 5: Install configuration file](#step-5-install-configuration-file)
* [Step 6: Generate a DSA key](#step-6-generate-a-dsa-key)
* [Step 7: Turning on cowrie](#step-7-turning-on-cowrie)
* [Step 8: Port redirection (optional)](#step-8-port-redirection-optional)
* [Running within supervisord(optional)](#running-using-supervisord)
* [Troubleshooting](#troubleshooting)

## Step 1: Install dependencies

First we install support for Python virtual environments and other dependencies.
The actual Python packages are installed later.

On Debian based systems (last verified on Debian 9, 2017-07-25):
```
$ sudo apt-get install git python-virtualenv libssl-dev libffi-dev build-essential libpython-dev python2.7-minimal authbind
```

## Step 2: Create a user account

It's strongly recommended to install under a dedicated non-root user id:

```
$ sudo adduser --disabled-password cowrie
Adding user `cowrie' ...
Adding new group `cowrie' (1002) ...
Adding new user `cowrie' (1002) with group `cowrie' ...
Changing the user information for cowrie
Enter the new value, or press ENTER for the default
Full Name []:
Room Number []:
Work Phone []:
Home Phone []:
Other []:
Is the information correct? [Y/n]

$ sudo su - cowrie
```

## Step 3: Checkout the code

```
$ git clone http://github.com/micheloosterhof/cowrie
Cloning into 'cowrie'...
remote: Counting objects: 2965, done.
remote: Compressing objects: 100% (1025/1025), done.
remote: Total 2965 (delta 1908), reused 2962 (delta 1905), pack-reused 0
Receiving objects: 100% (2965/2965), 3.41 MiB | 2.57 MiB/s, done.
Resolving deltas: 100% (1908/1908), done.
Checking connectivity... done.

$ cd cowrie
```

## Step 4: Setup Virtual Environment

Next you need to create your virtual environment:

```
$ pwd
/home/cowrie/cowrie
$ virtualenv cowrie-env
New python executable in ./cowrie/cowrie-env/bin/python
Installing setuptools, pip, wheel...done.
```

Activate the virtual environment and install packages

```
$ source cowrie-env/bin/activate
(cowrie-env) $ pip install -r requirements.txt
```

## Step 5: Install configuration file

The configuration for Cowrie is stored in cowrie.cfg.dist and
cowrie.cfg. Both files are read, where entries from cowrie.cfg take
precedence. The .dist file can be overwritten on upgrades, cowrie.cfg
will not be changed. To run with a standard configuration, there
is no need to change anything. To enable telnet, for example, create
cowrie.cfg and input only the following:

```
[telnet]
enabled = true
```

## Step 6: Generate a DSA key

This step should not be necessary, however some versions of twisted
are not compatible. To avoid problems in advance, run:

```
$ cd data
$ ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
$ cd ..
```

## Step 7: Turning on cowrie

Cowrie is implemented as a module for Twisted, but to properly
import everything the top-level source directory needs to be in
python's os.path. This sometimes won't happen correctly, so make
it explicit:

```
# or another path to the top-level cowrie folder
$ export PYTHONPATH=/home/cowrie/cowrie
```

Start Cowrie with the cowrie command. You can add the cowrie/bin directory
to your path if desired. If the virtual environment is called "cowrie-env"
it will be automatically activated. Otherwise you will need to activate it
manually

```
$ bin/cowrie start
Activating virtualenv "cowrie-env"
Starting cowrie with extra arguments [] ...
```

## Step 8: Port redirection (optional)

Cowrie runs by default on port 2222. This can be modified in the configuration file.
The following firewall rule will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Note that you should test this rule only from another host; it
doesn't apply to loopback connections. Alternatively you can run
authbind to listen as non-root on port 22 directly:

```
$ apt-get install authbind
$ touch /etc/authbind/byport/22
$ chown cowrie:cowrie /etc/authbind/byport/22
$ chmod 770 /etc/authbind/byport/22
```

Or for telnet:

```
$ apt-get install authbind
$ sudo touch /etc/authbind/byport/23
$ sudo chown cowrie:cowrie /etc/authbind/byport/23
$ sudo chmod 770 /etc/authbind/byport/23
```

* Edit bin/cowrie and modify the AUTHBIND_ENABLED setting
* Change listen_port to 22 in cowrie.cfg

## Running using Supervisord
On Debian, put the below in /etc/supervisor/conf.d/cowrie.conf
```
[program:cowrie]
command=/home/cowrie/cowrie/bin/cowrie start
directory=/home/cowrie/cowrie/
user=cowrie
autorestart=true
redirect_stderr=true
```
Update the bin/cowrie script, change:
 ```
 DAEMONIZE=""
 ```
 to:
 ```
 DAEMONIZE="-n"
 ```

## Troubleshooting

* If you see `twistd: Unknown command: cowrie` there are two
possibilities. If there's a python stack trace, it probably means
there's a missing or broken dependency. If there's no stack trace,
double check that your PYTHONPATH is set to the source code directory.
* Default file permissions

To make Cowrie logfiles public readable, change the ```--umask 0077``` option in start.sh into ```--umask 0022```

