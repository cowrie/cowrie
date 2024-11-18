
Changing the Cowrie file system
###############################

Introduction
************

Part of Cowrie is an emulated file system. Each honeypot visitor
will get their own personal copy of this file system and this will
be deleted when they log off. They can delete or change any file,
nothing will be preserved.

The file system implementation consists of two parts: the `pickle` file,
which holds metadata for the files (filename, directory, permissions, owner,
size, file type, etc), and the `honeyfs` directory that holds file contents.
The honeyfs directory only has a subset files by default. Most files do not
have content associated with them.

To show the contents of the file, it needs both a meta data entry (pickle)
and a honeyfs file.

Creating a new pickle file
**************************

Create a directory where you put all files you'd like to be show in your filesystem
Create the pickle file::

  $ source cowrie-env/bin/activate
  $ bin/createfs -l YOUR-DIR -d DEPTH -o custom.pickle

Make sure your config picks up custom.pickle, by referencing it in `cowrie.cfg`::

  [shell]
  filesystem = custom.pickle

Or set an environment variable::

  $ export COWRIE_SHELL_FILESYSTEM=custom.pickle
