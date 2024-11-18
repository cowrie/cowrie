Release Notes
#############

Release 2.6.0
*************
* Breaking change: default location of static files has moved from share/cowrie to src/cowrie/data
* In the configuration file the `share_path` is now `data_path`
* Python 3.12 support
* Python 3.13 support
* Pypy 3.10 support
* Python 3.8 no longer supported
* Twisted 24.10 support
* Docker builds now use Debian 12 Bookworm
* New output plugins: Oracle, Remote Syslog, Axiom
* New commands: finger, groups, locate, lspci
* Cowrie can now be installed with `pip install -e`

Release 2.5.0
*************

* Datadog output module (Fred Baguelin <frederic.baguelin@datadoghq.com>)
* General improvements to shell expansion handling
* New version of Twisted supported
* Python 3.11 support
* Pypy 3.9 support
* Add session type to Telegram output

Release 2.4.0
*************

* Deprecate Python 3.7
* Early support for Python 3.11
* ThreatJammer output plugin (@diegoparrilla)
* Telegram output plugin (@Louren)
* Discord output plugin (@CyberSparkNL)
* Updated mongodb output plugin
* Dependency upgrades
* Docker repo merged with this one
* `wget` and `curl` rewritten using `treq`.
* Migrate test framework from trial to unittest (@lazycrazyowl)

Release 2.3.0
*************

* Deprecate Python 3.6
* Support Python 3.10
* Dependency updates
* MISP Output plugin extension
* add new public keys ECDSAKeys and ed25519 (#1627)
* fix userdb.example (#1619)
* cache url submission to virustotal
* MySQL connector (#1575) - needs new external dependency mysql-connector-python
* Fix mysql string expansion (#1565)
* Rewrite CSIRTG output plugin to use new library version
* Fixed the Slack output to work with the versions 2.x of slackclient
* fix MySQL error handling
* fix tar command
* limit connections to private address ranges
* Update GreyNoise Output Script to Use Community API (#1524)
* Implement getopt-style parsing for uname (#1516)
* Allow SSLv3 connections for wget and curl
* Support for 301 redirects in wget
* Malshare update API (#1472)
* Remove hpfeeds.py infavour of hpfeeds3.py

Release 2.2.0
*************

* Deprecate Python 2.7 and 3.5
* Command substitution with backticks
* Better ``chmod`` command line parsing
* Add ``uniq`` command.
* Enhanced command substitution functionality.
* Fix nc hang
* Rename built-in user ``richard`` to ``phil``, it's used as detection mechanism.
* Binary suppport for ``cat``, ``grep`` and other commands
* Azure Sentinel output plugin

Release 2.1.0
*************

* Deprecate Python 2.7. Still works but removed from testing suite and fixing 2.7 problems will no longer have priority.
* Disable crashreporter
* Updated ELK documentation and output plugin
* ``tee`` command added. Updates to ``cat``, ``dd`` and ``wc``.
* Fixed SSH compression issue with AsyncSSH client
* AbuseIP output plugin.

Release 2.0.1
*************

* 2019-10-31 Fix for exec commands when tty logging is disabled
* 2019-10-31 Fix for print output to stdout for curl/wget
* 2019-10-31 Fix for SQL to store full hostname (don't forget to update the database schema)
* 2019-10-15 Slack link now at https://cowrie.org/slack
* 2019-10-04 Subshell ((echo test)) evaluation now working

Release 2.0.0
*************

* 2019-09-06 Crash reporter is enabled by default and will upload data on crashes to api.cowrie.org. This can be disabled in by setting ``enabled=false`` in ``[output_crashreporter]``
* 2019-09-05 Proxy functionality now active by @sgtpepperpt and GSoC2019
* 2019-06-20 Move `auth_none` and `auth_keyboard_interactive_enabled` to [ssh] config section

Release 1.6.0
*************

* 2019-03-31 New documentation theme
* 2019-03-23 Greynoise output plugin (@mzfr)
* 2019-03-19 direct-tcp forwarding now written to databases (@gborges)
* 2019-03-19 Reverse DNS output plugin (@mzfr)
* 2019-03-17 Shell emulation pipe upgrade (@nunonovais)
* 2019-03-14 Shell emulation environment variables improved (@nunonovais)
* 2019-03-14 SSH crypto parameters now configurable in config file (@msharma)
* 2019-03-13 Disable keyboard-interactive authentication by default with option to enable
* 2019-03-13 Added `wc`, `crontab`, `chpasswd` command (@nunonovais)
* 2019-
* 2019-03-07 Output of `ssh -V` now configurable in cowrie.cfg with ssh_version setting
* 2019-03-07 Multiple timezone support in cowrie.cfg timezone directive. Default timezone is now UTC for both cowrie.log and cowrie.json
* 2019-03-12 Handle multiple password prompt. Option to enable or disable keyboard interactive prompt.

Release 1.5.3
*************

* 2019-01-27 Telnet NAWS negotation removed to stop NMAP cowrie detection
* 2019-01-27 Various fixes for Python2/3 compatibility
* 2019-01-09 Documentation converted to ReStructuredText
* 2018-12-04 Fixes for VT outut plugin to only submit new files

Release 1.5.2
*************

* 2018-11-19 Fix tftp exception and tftp test
* 2018-11-14 Remove `dblog` mechanism and `splunk` legacy output plugin.
* 2018-11-01 Add Python3 support for Splunk output plugin
* 2018-10-23 Improved free command
* 2018-10-20 Improved uname command
* 2018-10-16 Save VT results to JSON log

Release 1.5.1
*************

* 2018-10-13 Fixes VT uploads, tab completion on Python3, Hassh support, setuptools functional. userdb migration
* 2018-09-07 NOTE! data/userdb.txt has moved to etc/userdb.txt and a default config is no longer provided!
* 2018-08-25 Downloads and TTY logs have moved to the var/ directory
* 2018-08-11 SSH keys now stored in var/lib/cowrie
* 2018-07-21 source code has move to the src/ directory. Delete old directories twisted/cowrie with compiled code
* 2018-06-29 txtcmds have been moved to share/cowrie/txtcmds
* 2018-06-28 filesystem config entry has changed. please verify if you have custom entry or pickle file
* 2018-06-23 fingerprint log message now holds KEX attributes and a unique fingerprint for the client
* 2018-04-27 Output plugins now require the mandatory config entry 'enabled'.
* 2018-02-06 cowrie.log now uses same rotation mechanism as cowrie.json. One file per day, rather than the default 1MB per file.
* 2017-12-13 Default umask for logs is now 0007. This means group members can access.
* 2017-10-24 Can store uploaded and downloaded artifacts to S3
* 2017-09-23 First proxy implementation for exec commands only
* 2017-07-03 Cuckoo v2 integration
* 2017-05-16 now combines config files: cowrie.cfg.dist and cowrie.cfg in this order
* 2017-05-09 start.sh and stop.sh have been replace by bin/cowrie start|stop
* 2017-04-27 New syntax "listen_endpoints" for configuring listening IP addresses/portnumbers
* 2017-03-15 SSH Forwarding/SFTP/keys/version config have been moved to [ssh]. Change your config file!
* 2017-02-12 Implemented toggle for SSH forwarding
* 2016-08-22 Merged Telnet support by @obilodeau!
* 2016-08-20 Update your libraries! 'configparser' now required: "pip install configparser"
* 2016-05-06 Load pickle once at startup for improved speed
* 2016-04-28 files in utils/ have been moved to bin/
* 2016-01-19 Support openssh style delayed compression
* 2016-01-13 Correct '.' support and +s and +t bits in ls
* 2016-01-13 Full username/group in SFTP ls
* 2016-01-05 Basic VirusTotal support has been added
* 2016-01-04 No longer crash when client tries ecdsa
* 2015-12-28 Interact port (default 5123) only listens on loopback interface now (127.0.0.1)
* 2015-12-24 Redirect to file (>) now works for most commands and is logged in dl/ directory
* 2015-12-06 UID information is now retrieved from honeyfs/etc/passwd. If you added additional users
             you will need to add these to the passwd file as well
* 2015-12-04 New 'free' command with '-h' and '-m' options
* 2015-12-03 New 'env' command that prints environment variables
* 2015-02-02 Now use honeyfs/etc/passwd and group to get uid/gid info
* 2015-11-29 Size limit now enforced for SFTP uploads
* 2015-11-25 New 'sudo' command added
* 2015-11-19 Queued input during commands is now sent to shell to be executed
             when command is finished
* 2015-11-18 Added SANS DShield output (Thanks @UnrealAkama)
* 2015-11-17 Added ElasticSearch output (Thanks @UnrealAkama)
* 2015-11-17 Standard input is now saved with SHA256 checksum. Duplicate data is not saved
* 2015-11-12 New 'busybox' command added (Thanks @mak)
* 2015-09-26 keyboard-interactive is back as authentication method, after
             Twisted removed support initially
* 2015-07-30 Local syslog output module
* 2015-06-15 Cowrie now has a '-c' startup switch to specify the configuration file
* 2015-06-15 Removed exec_enabled option. This feature is now always enabled
* 2015-06-03 Cowrie now uses twisted plugins and has gained the '-p' commandline option
* 2015-06-01 Cowrie no longer search for config files in /etc and /etc/cowrie
* 2015-04-12 JSON output is now default via 'output' plugin mechanism. Rotates daily
* 2015-04-10 Fix for downloading files via SFTP
* 2015-03-31 Small tweaks on session close, closing session does not close ssh transport
* 2015-03-18 Merged 'AuthRandom' login class by Honigbij
* 2015-02-25 Internals for dblog/ modules changed completely.
             Now accepts structured logging arguments, and uses eventids instead of regex parsing
* 2015-02-20 Removed screen clear/reset on logout
* 2015-02-19 Configuration directives have changed! ssh_addr has become listen_addr and ssh_port has become listen_port. The old keywords are still accepted for backwards compatibility

* default behaviour is changed to disable the exit jail
* sftp support
* exec support
* stdin is saved as a file in dl/ when using exec commands
    to support commands like 'cat >file; ./file'
* allow wget download over non-80 port
* simple JSON logging added
* accept log and deny publickey authentication
* add uname -r, -m flags
* add working sleep command
* enabled ssh diffie-hellman-group-exchange-sha1 algorithm
* add 'bash -c' support (no effect option)
* enable support for && multiple commands
* create uuid to uniquely identify each session
* log and deny direct-tcpip attempts
* add "chattr" command
* support emacs keybindings (c-a, c-b, c-f, c-p, c-n, c-e)
* add "sync" command
* accept, log and deny public key authentication
* add "uname -r" support
* logstash and kibana config files added, based on JSON log
* fix for honeypot detection (pre-auth differences with openssh)
* added verbose logging of client requested key exchange parameters (for client fingerprinting)
* fixes for behavior with non-existent files (cd /test, cat /test/nonexistent, etc)
* fix for ability to ping/ssh non-existent IP address
* always send ssh exit-status 0 on exec and shell
* ls output is now alphabetically sorted
* banner_file is deprecated. honeyfs/etc/issue.net is default
* add 'dir' alias for 'ls'
* add 'help' bash builtin
* add 'users' aliased to 'whoami'
* add 'killall' and 'killall5' aliased to nop
* add 'poweroff' 'halt' and 'reboot' aliases for shutdown
* add environment passing to commands
* added 'which', 'netstat' and 'gcc' from kippo-extra
* logging framework allows for keyword use
