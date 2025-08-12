Cowrie
######

Welcome to the Cowrie GitHub repository
*****************************************

This is the official repository for the Cowrie SSH and Telnet
Honeypot effort.

What is Cowrie
*****************************************

Cowrie is a medium to high interaction SSH and Telnet honeypot
designed to log brute force attacks and the shell interaction
performed by the attacker. In medium interaction mode (shell) it
emulates a UNIX system in Python, in high interaction mode (proxy)
it functions as an SSH and telnet proxy to observe attacker behavior
to another system.

`Cowrie <http://github.com/cowrie/cowrie/>`_ is maintained by Michel Oosterhof.

Documentation
****************************************

The Documentation can be found `here <https://docs.cowrie.org/en/latest/index.html>`_.

Slack
*****************************************

You can join the Cowrie community at the following `Slack workspace <https://www.cowrie.org/slack/>`_.

Features
*****************************************

* Choose to run as an emulated shell (default):
   * Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
   * Possibility of adding fake file contents so the attacker can `cat` files such as `/etc/passwd`. Only minimal file contents are included
   * Cowrie saves files downloaded with wget/curl or uploaded with SFTP and scp for later inspection

* Or proxy SSH and telnet to another system
   * Run as a pure telnet and ssh proxy with monitoring
   * Or let Cowrie manage a pool of QEMU emulated servers to provide the systems to login to

For both settings:

* Session logs are stored in an `UML Compatible <http://user-mode-linux.sourceforge.net/>`_  format for easy replay with the `bin/playlog` utility.
* SFTP and SCP support for file upload
* Support for SSH exec commands
* Logging of direct-tcp connection attempts (ssh proxying)
* Forward SMTP connections to SMTP Honeypot (e.g. `mailoney <https://github.com/awhitehatter/mailoney>`_)
* JSON logging for easy processing in log management solutions

Docker
*****************************************

Docker images are available on Docker Hub.

* To get started quickly and give Cowrie a try, run::

    $ docker run -p 2222:2222 cowrie/cowrie:latest
    $ ssh -p 2222 root@localhost

For more detailed instructions on using Docker in Cowrie, check
:ref:`Building Docker Images<Building Docker Images>`

Requirements
*****************************************

Software required to run locally:

* Python 3.10+
* python-virtualenv

For Python dependencies, see `requirements.txt <https://github.com/cowrie/cowrie/blob/main/requirements.txt>`_.

Files of interest:
*****************************************

* `etc/cowrie.cfg` - Cowrie's configuration file.
* `etc/cowrie.cfg.dist <https://github.com/cowrie/cowrie/blob/main/etc/cowrie.cfg.dist>`_ - default settings, don't change this file
* `etc/userdb.txt` - credentials to access the honeypot
* `src/cowrie/data/fs.pickle` - fake filesystem, this only contains metadata (path, uid, gid, size)
* `honeyfs/ <https://github.com/cowrie/cowrie/tree/main/honeyfs>`_ - contents for the fake filesystem
* `honeyfs/etc/issue.net` - pre-login banner
* `honeyfs/etc/motd <https://github.com/cowrie/cowrie/blob/main/honeyfs/etc/issue>`_ - post-login banner
* `src/cowrie/data/txtcmds/` - output for simple fake commands
* `var/log/cowrie/cowrie.json` - audit output in JSON format
* `var/log/cowrie/cowrie.log` - log/debug output
* `var/lib/cowrie/tty/` - session logs, replayable with the `bin/playlog` utility.
* `var/lib/cowrie/downloads/` - files transferred from the attacker to the honeypot are stored here
* `bin/createfs` - create your own fake filesystem
* `bin/playlog` - utility to replay session logs

Contributors
***************

Many people have contributed to Cowrie over the years. Special thanks to:

* Upi Tamminen (desaster) for all his work developing Kippo on which Cowrie was based
* Dave Germiquet (davegermiquet) for TFTP support, unit tests, new process handling
* Olivier Bilodeau (obilodeau) for Telnet support
* Ivan Korolev (fe7ch) for many improvements over the years.
* Florian Pelgrim (craneworks) for his work on code cleanup and Docker.
* Guilherme Borges (sgtpepperpt) for SSH and telnet proxy (GSoC 2019)
* And many many others.
