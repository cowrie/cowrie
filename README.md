
# Welcome to the Cowrie GitHub repository

This is the official repository for the Cowrie SSH and Telnet
Honeypot effort.

# What is Cowrie

Cowrie is a medium interaction SSH and Telnet honeypot designed to
log brute force attacks and the shell interaction performed by the
attacker.

[Cowrie](http://github.com/micheloosterhof/cowrie/) is developed by Michel Oosterhof.

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
* Forward SMTP connections to SMTP Honeypot (e.g. [mailoney](https://github.com/awhitehatter/mailoney))
* Logging in JSON format for easy processing in log management solutions
* Many, many additional commands

## Requirements

Software required:

* Python 2.7+, (Python 3 not yet supported due to Twisted dependencies)
* Zope Interface 3.6.0+
* Twisted 12.0+
* python-crypto
* python-cryptography
* python-pyasn1
* python-gmpy2 (recommended)
* python-mysqldb (for MySQL output)
* python-OpenSSL

## Files of interest:

* `cowrie.cfg` - Cowrie's configuration file. Default values can be found in `cowrie.cfg.dist`
* `data/fs.pickle` - fake filesystem
* `data/userdb.txt` - credentials allowed or disallowed to access the honeypot
* `dl/` - files transferred from the attacker to the honeypot are stored here
* `honeyfs/` - file contents for the fake filesystem - feel free to copy a real system here or use `bin/fsctl`
* `log/cowrie.json` - transaction output in JSON format
* `log/cowrie.log` - log/debug output
* `log/tty/*.log` - session logs
* `txtcmds/` - file contents for the fake commands
* `bin/createfs` - used to create the fake filesystem
* `bin/playlog` - utility to replay session logs

## Is it secure?

Maybe. See [FAQ](https://github.com/micheloosterhof/cowrie/wiki/Frequently-Asked-Questions)

## I have some questions!

Please visit https://github.com/micheloosterhof/cowrie/issues

## Contributors

Many people have contributed to Cowrie over the years. Special thanks to:

* Upi Tamminen (desaster) for all his work developing Kippo on which Cowrie was based

