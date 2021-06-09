Frequently asked questions
##########################

Do I need to copy all the content of cowrie.cfg.dist to cowrie.cfg?
*******************************************************************

No, Cowrie merges your local settings in ``cowrie.cfg`` and
the default settings will automatically be read from ``cowrie.cfg.dist``

Why certain commands aren't implemented?
****************************************

Implementing all possible UNIX commands in Python is not worth the
time and effort. Cowrie tries to provide most common commands used by attackers
of the honeypot. If you see attackers use a command that you'd like
to see implemented, please let us know, or send a pull request.

How do I add or modify the default user?
****************************************

The default Cowrie users is called `phil` these days. Having the same
user always available is an easy way to identify Cowrie so it's recommend to change
this setup. You can modify it by doing the following::

	$ vi honeyfs/etc/passwd

And edit the userid. Then::

	$ bin/fsctl share/cowrie/fs.pickle
        fs.pickle:/$ mv /home/phil /home/joe

And then restart Cowrie::

	$ bin/cowrie restart


How do I add files to the file system?
**************************************

The file system meta data is stored in the pickle file. The file
contents is stored in the `honeyfs` directory.  To add a file, the
minimum action is to modify the pickle file. Doing this makes the
file show up in `ls` and other commands. But it won't have any
contents available. To add file contents, you'll need a file to
honeyfs.

First add a file system entry, the `1024` here is the file size. The
`chown` commands only takes numerical uid's, they should match
entries in `honeyfs/etc/passwd`::

	$ bin/fsctl share/cowrie/fs.pickle
        fs.pickle:/$ touch /home/phil/myfile 1024
        fs.pickle:/$ chown 1000:1000 /home/phil/myfile

Then create or copy a file in the `honeyfs`::

	$ cp myfile /honeyfs/home/phil
