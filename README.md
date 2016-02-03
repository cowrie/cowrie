# Cowrie

Cowrie is a medium interaction SSH honeypot designed to log brute force attacks and the shell interaction performed by the attacker.

Cowrie is directly based on [Kippo](http://github.com/desaster/kippo/) by Upi Tamminen (desaster).

## Features

Some interesting features:

* Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
* Possibility of adding fake file contents so the attacker can `cat` files such as `/etc/passwd`. Only minimal file contents are included
* Session logs stored in an [UML Compatible](http://user-mode-linux.sourceforge.net/)  format for easy replay with original timings
* Cowrie saves files downloaded with wget/curl or uploaded with SFTP and scp for later inspection

Additional functionality over standard kippo:

* SFTP and SCP support for file upload
* Support for SSH exec commands
* Logging of direct-tcp connection attempts (ssh proxying)
* Logging in JSON format for easy processing in log management solutions
* Many, many additional commands

## Requirements

Software required:

* An operating system (tested on Debian, CentOS, FreeBSD and Windows 7)
* Python 2.7+
* Twisted 8.0+
* python-crypto
* python-pyasn1
* python-gmpy2 (recommended)
* Zope Interface 3.6.0+

## Files of interest:

* `cowrie.cfg` - Cowrie's configuration file. Default values can be found in `cowrie.cfg.dist`
* `data/fs.pickle` - fake filesystem
* `data/userdb.txt` - credentials allowed or disallowed to access the honeypot
* `dl/` - files transferred from the attacker to the honeypot are stored here
* `honeyfs/` - file contents for the fake filesystem - feel free to copy a real system here or use `utils/fsctl.py`
* `log/cowrie.json` - transaction output in JSON format
* `log/cowrie.log` - log/debug output
* `log/tty/*.log` - session logs
* `txtcmds/` - file contents for the fake commands
* `utils/createfs.py` - used to create the fake filesystem
* `utils/playlog.py` - utility to replay session logs

## Is it secure?

Maybe. See [FAQ](https://github.com/desaster/kippo/wiki/FAQ)

## I have some questions!

Please visit https://github.com/micheloosterhof/cowrie/issues
