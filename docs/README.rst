Cowrie
######

|travis|_
|codecov|_

Welcome to the Cowrie GitHub repository
*****************************************

This is the official repository for the Cowrie SSH and Telnet
Honeypot effort.

What is Cowrie
*****************************************

Cowrie is a medium interaction SSH and Telnet honeypot designed to
log brute force attacks and the shell interaction performed by the
attacker.

`Cowrie <http://github.com/cowrie/cowrie/>`_ is developed by Michel Oosterhof.

Documentation
****************************************

The Documentation can be found `here <https://cowrie.readthedocs.io/en/latest/index.html>`_.

Slack
*****************************************

You can join the Cowrie community at the following `Slack workspace <http://bit.ly/cowrieslack>`_.

Features
*****************************************

Some interesting features:

* Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
* Possibility of adding fake file contents so the attacker can `cat` files such as `/etc/passwd`. Only minimal file contents are included
* Session logs are stored in an `UML Compatible <http://user-mode-linux.sourceforge.net/>`_  format for easy replay with original timings with the `bin/playlog` utility.
* Cowrie saves files downloaded with wget/curl or uploaded with SFTP and scp for later inspection log

Additional functionality over standard kippo:

* SFTP and SCP support for file upload
* Support for SSH exec commands
* Logging of direct-tcp connection attempts (ssh proxying)
* Forward SMTP connections to SMTP Honeypot (e.g. `mailoney <https://github.com/awhitehatter/mailoney>`_)
* Logging in JSON format for easy processing in log management solutions
* Many, many additional commands

Docker
*****************************************

Docker versions are available.

* To get started quickly and give Cowrie a try, run::

    docker run -p 2222:2222 cowrie/cowrie
    ssh -p 2222 root@localhost

* On Docker Hub: https://hub.docker.com/r/cowrie/cowrie

* Or get the Dockerfile directly at https://github.com/cowrie/docker-cowrie

Requirements
*****************************************

Software required:

* Python 3.5+ (Python 2.7 supported for now but we recommend to upgrade)
* python-virtualenv

For Python dependencies, see `requirements.txt <https://github.com/cowrie/cowrie/blob/master/requirements.txt>`_.

Files of interest:
*****************************************

* `cowrie.cfg` - Cowrie's configuration file. Default values can be found in `etc/cowrie.cfg.dist <https://github.com/cowrie/cowrie/blob/master/etc/cowrie.cfg.dist>`_.
* `share/cowrie/fs.pickle <https://github.com/cowrie/cowrie/blob/master/share/cowrie/fs.pickle>`_ - fake filesystem
* `etc/userdb.txt` - credentials allowed or disallowed to access the honeypot
* `honeyfs/ <https://github.com/cowrie/cowrie/tree/master/honeyfs>`_ - file contents for the fake filesystem - feel free to copy a real system here or use `bin/fsctl`
* `honeyfs/etc/issue.net` - pre-login banner
* `honeyfs/etc/motd <https://github.com/cowrie/cowrie/blob/master/honeyfs/etc/issue>`_ - post-login banner
* `var/log/cowrie/cowrie.json` - transaction output in JSON format
* `var/log/cowrie/cowrie.log` - log/debug output
* `var/lib/cowrie/tty/` - session logs, replayable with the `bin/playlog` utility.
* `var/lib/cowrie/downloads/` - files transferred from the attacker to the honeypot are stored here
* `share/cowrie/txtcmds/ <https://github.com/cowrie/cowrie/tree/master/share/cowrie/txtcmds>`_ - file contents for simple fake commands
* `bin/createfs <https://github.com/cowrie/cowrie/blob/master/bin/createfs>`_ - used to create the fake filesystem
* `bin/playlog <https://github.com/cowrie/cowrie/blob/master/bin/playlog>`_ - utility to replay session logs

I have some questions!
*****************************************

Please visit the `Slack workspace <http://bit.ly/cowrieslack>`_ and join the #questions channel.

Contributors
***************

Many people have contributed to Cowrie over the years. Special thanks to:

* Upi Tamminen (desaster) for all his work developing Kippo on which Cowrie was based
* Dave Germiquet (davegermiquet) for TFTP support, unit tests, new process handling
* Olivier Bilodeau (obilodeau) for Telnet support
* Ivan Korolev (fe7ch) for many improvements over the years.
* Florian Pelgrim (craneworks) for his work on code cleanup and Docker.
* And many many others.


.. |travis| image:: https://travis-ci.org/cowrie/cowrie.svg?branch=master
.. _travis: https://travis-ci.org/cowrie/cowrie

.. |codecov| image:: https://codecov.io/gh/cowrie/cowrie/branch/master/graph/badge.svg
.. _codecov:  https://codecov.io/gh/cowrie/cowrie
