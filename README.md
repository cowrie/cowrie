# Kippo

Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.

Kippo is inspired, but not based on [Kojoney](http://kojoney.sourceforge.net/).

## Demo

Some interesting logs from a live Kippo installation below (viewable within a web browser with the help of Ajaxterm). Note that some commands may have been improved since these logs were recorded.

  * [2009-11-22](http://kippo.rpg.fi/playlog/?l=20091122-075013-5055.log)
  * [2009-11-23](http://kippo.rpg.fi/playlog/?l=20091123-003854-3359.log)
  * [2009-11-23](http://kippo.rpg.fi/playlog/?l=20091123-012814-626.log)
  * [2010-03-16](http://kippo.rpg.fi/playlog/?l=20100316-233121-1847.log)

## Features

Some interesting features:
* Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
* Possibility of adding fake file contents so the attacker can 'cat' files such as /etc/passwd. Only minimal file contents are included 
* Session logs stored in an [UML Compatible](http://user-mode-linux.sourceforge.net/)  format for easy replay with original timings 
* Just like Kojoney, Kippo saves files downloaded with wget for later inspection
* Trickery; ssh pretends to connect somewhere, exit doesn't really exit, etc 

## Requirements

Software required:

* An operating system (tested on Debian, CentOS, FreeBSD and Windows 7)
* Python 2.5+
* Twisted 8.0+
* PyCrypto
* Zope Interface

See Wiki for some installation instructions.

## How to run it?

Edit kippo.cfg to your liking and start the honeypot by running:

`./start.sh`

start.sh is a simple shell script that runs Kippo in the background using twistd. Detailed startup options can be given by running twistd manually. For example, to run Kippo in foreground:

`twistd -y kippo.tac -n`

By default Kippo listens for ssh connections on port 2222. You can change this, but do not change it to 22 as it requires root privileges. Use port forwarding instead. (More info: MakingKippoReachable).

Files of interest:

* dl/ - files downloaded with wget are stored here
* log/kippo.log - log/debug output
* log/tty/ - session logs
* utils/playlog.py - utility to replay session logs
* utils/createfs.py - used to create fs.pickle
* fs.pickle - fake filesystem
* honeyfs/ - file contents for the fake filesystem - feel free to copy a real system here

## Is it secure?

Maybe. See [FAQ](https://github.com/desaster/kippo/wiki/FAQ)

## I have some questions!

I ~~am~~ _might be_ reachable via e-mail: *desaster* at *gmail* dot *com*, or as *desaster* on the *#honeypots* channel in the *freenode* IRC network.
