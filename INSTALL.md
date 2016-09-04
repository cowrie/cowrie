
# Installing Cowrie in seven steps.

- [Installing Cowrie in seven steps.](#installing-cowrie-in-six-steps)
  * [Step 1: Install required Python packages](#step-1--install-required-debian-packages)
    + [Option A: dependencies for virtualenv](#option-a--dependencies-for-virtualenv)
    + [Option B: dependencies for bare install](#option-b--dependencies-for-bare-install)
  * [Step 2: Create a user account](#step-2--create-a-user-account)
  * [Step 3: Checkout the code](#step-3--checkout-the-code)
  * [Step 3: Setup virtualenv (if desired)](#step-3--setup-virtualenv--if-desired-)
  * [Step 4: Install configuration file](#step-4--install-configuration-file)
  * [Step 5: Generate a DSA key](#step-5--generate-a-dsa-key)
  * [Step 6: Turning on cowrie](#step-6--turning-on-cowrie)
  * [Step 7: Port redirection (optional)](#step-7--port-redirection--optional-)
  * [Troubleshooting](#troubleshooting)

## Step 1: Install dependencies

There are two ways to install Cowrie's Python dependencies: in a
Python virtual environment or directly on to the system.  The virtual
environment is preferred as it isolates Cowrie and its dependencies
from other Python software on the system.

### Option A: dependencies for virtualenv

This install virtual environments and other dependencies. The actual python packages are installed later.

On Debian based systems (tested on Debian 8, 2016-08-30):
```
$ sudo apt-get install git virtualenv libmpfr-dev libssl-dev libmpc-dev libffi-dev build-essential libpython-dev
```

### Option B: dependencies for bare install

Install prerequisites on Debian based systems (untested 2016-08-30):

```
$ sudo apt-get install git python-twisted python-configparser python-crypto python-pyasn1 python-gmpy2 python-mysqldb python-zope.interface
```
**NOTE**: 'python-gmpy2' will cause a signficant delay when attempting to login to the fake ssh server if installed on a Raspberry Pi (Tested on a RPi model 1B). Use 'python-gmpy' to reduce the login delay significantly. 

Install prerequisites on Alpine based systems (untested 2016-08-30):

```
$ sudo apk add python py-asn1 py-twisted py-zope-interface libffi-dev \
        py-cryptography py-pip py-six py-cffi py-idna py-ipaddress py-openssl
$ sudo pip install enum34
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

## Step 3: Setup virtualenv (if desired)

If you're choosing the virtualenv installation route, you need to create your virtual environment:

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

Take a look at the configuration file and make changes as desired.  The defaults work well in most cases.
```
$ cp cowrie.cfg.dist cowrie.cfg
```

## Step 5: Generate a DSA key

This step should not be necessary, however some versions of twisted
are not compatible.  To avoid problems in advance, run:

```
$ cd data
$ ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
$ cd ..
```

## Step 6: Turning on cowrie

Cowrie is implemented as a module for twisted, but to properly
import everything the top-level source directory needs to be in
python's os.path.  This sometimes won't happen correctly, so make
it explicit:

```
# or whatever path to the top-level cowrie folder
$ export PYTHONPATH=/home/cowrie/cowrie
```

In the absence of a virtual environment, you may run:

```
$ ./start.sh
```

When using Python Virtual Environments you can add the name of the
venv as the first argument or activate it before starting.

```
$ ./start.sh cowrie-env
Starting cowrie in the background...
```

## Step 7: Port redirection (optional)

Cowrie runs by default on port 2222. This can be modified in the configuration file.
The following firewall rule will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Note that you should test this rule only from another host; it
doesn't apply to loopback connections.  Alternatively you can run
authbind to listen as non-root on port 22 directly:

```
$ apt-get install authbind
$ touch /etc/authbind/byport/22
$ chown cowrie:cowrie /etc/authbind/byport/22
$ chmod 770 /etc/authbind/byport/22
```

* Edit start.sh and modify the AUTHBIND_ENABLED setting
* Change listen_port to 22 in cowrie.cfg

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
$ cd cowrie/data
$ ssh-keygen -t dsa -b 1024 -f ssh_host_dsa_key
```

* If you see `twistd: Unknown command: cowrie` there are two
possibilities.  If there's a python stack trace, it probably means
there's a missing or broken dependency.  If there's no stack trace,
double check that your PYTHONPATH is set to the source code directory.
* Default file permissions

To make Cowrie logfiles public readable, change the ```--umask 0077``` option in start.sh into ```--umask 0022```

