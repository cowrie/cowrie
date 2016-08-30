- [Installing cowrie in six steps.](#installing-cowrie-in-six-steps)
  * [Step 1: Create a user account](#step-1--create-a-user-account)
  * [Step 2: Checkout the code](#step-2--checkout-the-code)
  * [Step 3: Setup Dependencies](#step-3--setup-dependencies)
    + [Option A: Install with Python packages from your Linux Distribution](#option-a--install-with-python-packages-from-your-linux-distribution)
    + [Option B Install with Python Virtual Environments](#option-b-install-with-python-virtual-environments)
  * [Step 4: Install configuration file](#step-4--install-configuration-file)
  * [Step 5: Start](#step-5--start)
  * [Step 6: Port redirection (optional)](#step-6--port-redirection--optional-)
  * [Troubleshooting](#troubleshooting)


# Installing cowrie in six steps.

## Step 1: Create a user account

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

## Step 2: Checkout the code

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

## Step 3: Setup Dependencies 
### Option A: Install with Python packages from your Linux Distribution

Install prerequisites on Debian based systems:

```
$ sudo apt-get install python-twisted python-configparser python-crypto python-pyasn1 python-gmpy2 python-mysqldb python-zope.interface
```

Install prerequisites on RedHat based systems:

```
$ sudo yum install <tbd> <tbd> <tbd>
```

Install prerequisites on Alpine based systems:

```
$ sudo apk add python py-asn1 py-twisted py-zope-interface libffi-dev \
        py-cryptography py-pip py-six py-cffi py-idna py-ipaddress py-openssl
$ sudo pip install enum34
```

### Option B Install with Python Virtual Environments

On Debian based systems:
```
$ sudo apt-get install virtualenv libmpfr-dev openssl-dev libmpc-dev libffi-dev
```
On RedHat based systems you will need the corresponding packages.

Create a virtual environment

```
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

```
$ cp cowrie.cfg.dist cowrie.cfg
```

## Step 5: Start

Cowrite is implemented as a module for twisted, but to properly import everything the top-level source directory needs to be in os.path.  If you're using a virtual environment this sometimes won't happen correctly, so make it explicit:

```
$ export PYTHONPATH=/path/to/cowrie
```

In the absence of a virtual environment, you may run:

```
$ ./start.sh
```

When using Python Virtual Environments you can add the name of the venv as the first argument

```
$ ./start.sh cowrie-env
Starting cowrie in the background...
```

## Step 6: Port redirection (optional)

Cowrie runs by default on port 2222. This can be modified in the configuration file.
The following firewall rule will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Alternatively you can run authbind to listen as non-root on port 22 directly:

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

* If you see `twistd: Unknown command: cowrie` there are two possibilities.  If there's a python stack trace, it probably means there's a missing dependency.  If there's no stack trace, double check that your PYTHONPATH is set to the source code directory.
* Default file permissions

To make Cowrie logfiles public readable, change the ```--umask 0077``` option in start.sh into ```--umask 0022```

