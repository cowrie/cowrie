
# Welcome to the Cowrie GitHub repository

This is the official repository for the Cowrie SSH and Telnet
Honeypot effort.

# What is Cowrie

Cowrie is a medium interaction SSH and Telnet honeypot designed to
log brute force attacks and the shell interaction performed by the
attacker.

[Cowrie](http://github.com/micheloosterhof/cowrie/) is developed by Michel Oosterhof.

## Slack

You can join the Cowrie community at the following [Slack workspace](https://cowrie.slack.com/join/shared_invite/enQtMzc3NjY3OTYwMjI0LThiY2ViMjkyNDgzOTE2ZjI3NTI0N2QxZmI2Yzg2ZmFkYmFlYTg1NTU4OWZjOWM0MjBlNjQ2MjA1NmUyOWVlNDA)

## Features

Some interesting features:

* Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
* Possibility of adding fake file contents so the attacker can `cat` files such as `/etc/passwd`. Only minimal file contents are included
* Session logs are stored in an [UML Compatible](http://user-mode-linux.sourceforge.net/)  format for easy replay with original timings with the `bin/playlog` utility.
* Cowrie saves files downloaded with wget/curl or uploaded with SFTP and scp for later inspection

Additional functionality over standard kippo:

* SFTP and SCP support for file upload
* Support for SSH exec commands
* Logging of direct-tcp connection attempts (ssh proxying)
* Forward SMTP connections to SMTP Honeypot (e.g. [mailoney](https://github.com/awhitehatter/mailoney))
* Logging in JSON format for easy processing in log management solutions
* Many, many additional commands

## Docker

Docker versions are available.
* Get the Dockerfile directly at https://github.com/cowrie/docker-cowrie
* Run from the Docker regstry with: ```docker pull cowrie/cowrie```

## Requirements

Software required:

* Python 2.7+, (Python 3 not yet supported due to Twisted dependencies)
* python-virtualenv

For Python dependencies, see requirements.txt

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

Please visit https://cowrie.slack.com/ and join the #questions channel

## I'd like to install with Docker

Run:
```docker pull cowrie/cowrie```
to download images from hub.docker.com

Or look at https://github.com/cowrie/docker-cowrie for the Dockerfile

## Contributors

Many people have contributed to Cowrie over the years. Special thanks to:

* Upi Tamminen (desaster) for all his work developing Kippo on which Cowrie was based
* Dave Germiquet (davegermiquet) for TFTP support, unit tests, new process handling
* Olivier Bilodeau (obilodeau) for Telnet support
* Ivan Korolev (fe7ch) for many improvements over the years.
* And many many others.

