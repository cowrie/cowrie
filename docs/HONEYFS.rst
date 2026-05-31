.. SPDX-FileCopyrightText: 2020-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Changing the Cowrie file system
###############################

Introduction
************

Part of Cowrie is an emulated file system. Each honeypot visitor
will get their own personal copy of this file system and this will
be deleted when they log off. They can delete or change any file,
nothing will be preserved.

The file system implementation consists of two parts: the `pickle`
file, which mostly holds metadata for the files (filename, directory,
permissions, owner, size, file type, etc) but has contents for a
few files. Most files have no content.

The `honeyfs` directory holds user created file contents, this overrides
content from the pickle file and is a quick way to have custom content

To show the contents of the file, it needs both a meta data entry (pickle)
and a honeyfs file.

Creating a new pickle file
**************************

Create a directory where you put all files you'd like to be show in your filesystem
Create the pickle file::

  $ source cowrie-env/bin/activate
  (cowrie-env) $ createfs -l YOUR-DIR -d DEPTH -o custom.pickle

Make sure your config picks up custom.pickle, by referencing it in `cowrie.cfg`::

  [shell]
  filesystem = custom.pickle

Or set an environment variable::

  $ export COWRIE_SHELL_FILESYSTEM=custom.pickle

Customizing text command output
*******************************

Some commands in Cowrie are implemented as simple text output files under
``txtcmds``. Operators can point Cowrie at a custom directory with
``[honeypot] txtcmds_path``::

  [honeypot]
  txtcmds_path = /opt/cowrie/txtcmds

The command path below that directory must match the path in the virtual
filesystem. For example, to customize ``/usr/bin/lscpu`` output, create::

  /opt/cowrie/txtcmds/usr/bin/lscpu

The command still needs an entry in the virtual filesystem pickle, the same
way files in ``honeyfs`` need matching metadata. If a command is not present
under ``txtcmds_path``, Cowrie falls back to the bundled ``cowrie.data/txtcmds``
output.
