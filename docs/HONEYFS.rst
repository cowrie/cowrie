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

Building from a real container
******************************

For a more realistic surface than hand-curating a directory, ``bin/build-fs-pickle.sh``
spins up a real container, optionally installs a package set, and runs ``createfs``
against ``/`` to produce a pickle. This is how ``src/cowrie/data/fs.pickle`` itself
is regenerated.

The default invocation builds the stock Debian 12 surface::

  $ bin/build-fs-pickle.sh                      # or: make build-fs-pickle

Output goes to ``src/cowrie/data/fs.pickle.new``; review it, then ``mv`` it into
place.

Override the OS family with ``FAMILY=`` and the base image with ``IMAGE=``. Three
families are supported:

- ``apt`` (default) — Debian/Ubuntu. Installs ``python3`` plus ``$PACKAGES`` via
  ``apt-get``.
- ``opkg`` — OpenWrt rootfs. Installs ``python3-light`` plus ``$PACKAGES`` via
  ``opkg``. Requires ``IMAGE=`` (e.g. ``openwrt/rootfs:x86-64-23.05.5``).
- ``none`` — no install step. The image must already contain ``python3``. Useful
  for prebuilt rootfs images and BusyBox-style targets (e.g. ``IMAGE=python:3-alpine``).

Examples::

  # Custom Debian package set:
  $ FAMILY=apt PACKAGES="openssh-server vim curl" bin/build-fs-pickle.sh

  # OpenWrt persona:
  $ FAMILY=opkg IMAGE=openwrt/rootfs:x86-64-23.05.5 \
        OUT=/path/to/personas/openwrt/fs.pickle.new \
        bin/build-fs-pickle.sh

  # BusyBox-like persona:
  $ FAMILY=none IMAGE=python:3-alpine \
        OUT=/path/to/personas/busybox/fs.pickle.new \
        bin/build-fs-pickle.sh

``OUT=`` may point anywhere on the host, so the same script can build pickles for
multiple personas into separate output paths.
