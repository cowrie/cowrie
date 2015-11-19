# Installation

Installing cowrie in six easy steps.

It's recommended to install under a separate non-root user id:

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

$ git clone http://github.com/micheloosterhof/cowrie
Cloning into 'cowrie'...
remote: Counting objects: 2965, done.
remote: Compressing objects: 100% (1025/1025), done.
remote: Total 2965 (delta 1908), reused 2962 (delta 1905), pack-reused 0
Receiving objects: 100% (2965/2965), 3.41 MiB | 2.57 MiB/s, done.
Resolving deltas: 100% (1908/1908), done.
Checking connectivity... done.

$ cd cowrie

$ cp cowrie.cfg.dist cowrie.cfg

$ ./start.sh
Starting cowrie in the background...
```

Cowry runs by default on port 2222. This can be modified in the configuration file. Running on port 22 is not recommended.
The following firewall rule will forward incoming traffic on port 22 to port 2222.

```
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```


# Bugs and workarounds

* For some versions of Twisted you may receive the following error messagse:

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

