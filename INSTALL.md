
# Installing Cowrie in seven steps.

* [Step 1: Install dependencies](#step-1-install-dependencies)
* [Step 2: Create a user account](#step-2-create-a-user-account)
* [Step 3: Checkout the code](#step-3-checkout-the-code)
* [Step 3: Setup Virtual Environment](#step-3-setup-virtual-environment)
* [Step 4: Install configuration file](#step-4-install-configuration-file)
* [Step 5: Generate a DSA key](#step-5-generate-a-dsa-key)
* [Step 6: Starting cowrie](#step-6-starting-cowrie)
* [Step 7: Port redirection (optional)](#step-7-port-redirection-optional)
* [Running within supervisord(optional)](#running-using-supervisord)
* [Troubleshooting](#troubleshooting)
* [Installing on OSX for development](#installing-on-osx-for-development)

## Step 1: Install dependencies

First we install support for Python virtual environments and other dependencies.
The actual Python packages are installed later.

On Debian based systems (tested on Debian 8, 2016-08-30):
```
$ sudo apt-get install git virtualenv libmpfr-dev libssl-dev libmpc-dev libffi-dev build-essential libpython-dev python2.7-minimal
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

## Step 3: Setup Virtual Environment

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

## Step 4: Install configuration file

Take a look at the configuration file and make changes as desired.
The defaults work well in most cases.
```
$ cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

## Step 5: Generate a DSA key

This step should not be necessary, however some versions of Twisted
are not compatible. To avoid problems in advance, run:

```
$ cd etc
$ ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
$ cd ..
```

## Step 6: Starting cowrie

If you use a virtual environment and it uses the default name of
'cowrie-env' it will be activated automatically.

If you use another virtual environment activate it first:

```
$ source venv/bin/activate
```

To start Cowrie:

```
$ bin/cowrie start
Starting cowrie in the background...
```

## Step 7: Port redirection (optional)

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
* Change listen_port to 22 in etc/cowrie.cfg

## Running using Supervisord
On Debian, put the below in /etc/supervisor/conf.d/cowrie.conf
```
[program:cowrie]
command=/home/cowrie/cowrie/start.sh cowrie-env
directory=/home/cowrie/cowrie/
user=cowrie
autorestart=true
redirect_stderr=true
```
Update the start.sh script, change:
 ```
 DAEMONIZE=""
 ```
 to:
 ```
 DAEMONIZE="-n"
 ```

## Troubleshooting

* For some versions of Twisted you may receive the following error messages:

```
....
  File "/usr/lib/python2.7/site-packages/Crypto/PublicKey/DSA.py", line 342, in _generate
      key = self._math.dsa_construct(obj.y, obj.g, obj.p, obj.q, obj.x)
      TypeError: must be long, not mpz
```

This is caused by Twisted incompatibilities. A workaround is to run:

```
$ cd cowrie/etc
$ ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
```

* If there are issues creating the RSA keys, the following is a workaround:

```
$ cd cowrie/etc
$ ssh-keygen -t rsa -b 2048 -f ssh_host_rsa_key
```

* If you see `twistd: Unknown command: cowrie` there are two
possibilities. If there's a python stack trace, it probably means
there's a missing or broken dependency. If there's no stack trace,
double check that your PYTHONPATH is set to the source code directory.
* Default file permissions

To make Cowrie logfiles public readable, change the ```UMASK=0077``` variable in bin/cowrie to ```UMASK=0022```

## Installing on OSX for development

gmpy2 requires a number of libraries which are not included by default with Sierra and must be installed, suggested method is by using [homebrew](http://brew.sh/) 

```
brew install gmp
brew install mpfr
brew install mpc
brew install libmpc
```
