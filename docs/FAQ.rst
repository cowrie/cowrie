.. SPDX-FileCopyrightText: 2019 Mehtab Zafar <mehtab.zafar98@gmail.com>
.. SPDX-FileCopyrightText: 2019-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

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

The default Cowrie user is called `phil` these days. Having the same
user always available is an easy way to identify Cowrie, so it's
recommended to change this. The bundled defaults are baked into
``src/cowrie/data/fs.pickle`` as ``A_CONTENTS`` bytes — either edit a
copy of the pickle directly, or set ``[honeypot] contents_path`` in
``etc/cowrie.cfg`` and drop an override file at ``<contents_path>/etc/passwd``.

For the per-file-override path::

        [honeypot]
        contents_path = /opt/cowrie/honeyfs

And then::

	$ mkdir -p /opt/cowrie/honeyfs/etc
	$ cp /path/to/your/passwd /opt/cowrie/honeyfs/etc/passwd

Rename the user in the filesystem tree too::

	$ fsctl src/cowrie/data/fs.pickle
        fs.pickle:/$ mv /home/phil /home/joe

(For a custom copy of the pickle, copy it out first, set
``[shell] filesystem`` to point at it, and edit there — see
INSTALL.rst's "Customising the honeypot" section.)

And then restart Cowrie::

	(cowrie-env) $ cowrie restart


How do I add files to the file system?
**************************************

The filesystem metadata and embedded contents both live in
``src/cowrie/data/fs.pickle``. Adding a new path makes it show up in
``ls`` and other commands; you can populate its contents the same way.

Use ``fsctl`` to add the filesystem entry and load its contents::

	(cowrie-env) $ fsctl src/cowrie/data/fs.pickle
        fs.pickle:/$ touch /home/phil/myfile 1024
        fs.pickle:/$ chown 1000:1000 /home/phil/myfile
        fs.pickle:/$ load /home/phil/myfile /local/path/to/myfile
        fs.pickle:/$ exit

For bulk content updates (e.g. loading every file under a local
directory tree), use ``fsctl <pickle> "embed <local-dir>"``.
