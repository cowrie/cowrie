
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
