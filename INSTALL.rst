.. SPDX-FileCopyrightText: 2019-2026 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Installing Cowrie
#################

Cowrie supports two install paths:

* **Pip install** (recommended for operators). Install the published
  package, ``cowrie init`` a state directory, edit ``etc/cowrie.cfg``,
  start. No source checkout required.
* **Source checkout** (developers and contributors). Clone the repo and
  install in editable mode.

For ``proxy`` mode, see ``PROXY.rst``.

Contents
========

* :ref:`Quick start: pip install<INSTALL:Quick start: pip install>`
* :ref:`Step 1: System dependencies<INSTALL:Step 1: System dependencies>`
* :ref:`Step 2: Create a user account<INSTALL:Step 2: Create a user account>`
* :ref:`Step 3: Install Cowrie<INSTALL:Step 3: Install Cowrie>`
* :ref:`Step 4: Initialise the state directory<INSTALL:Step 4: Initialise the state directory>`
* :ref:`Step 5: Configure<INSTALL:Step 5: Configure>`
* :ref:`Step 6: Start Cowrie<INSTALL:Step 6: Start Cowrie>`
* :ref:`Step 7: Listening on port 22 (OPTIONAL)<INSTALL:Step 7: Listening on port 22 (OPTIONAL)>`
* :ref:`Installing Backend Pool dependencies (OPTIONAL)<INSTALL:Installing Backend Pool dependencies (OPTIONAL)>`
* :ref:`Running using supervisord (OPTIONAL)<INSTALL:Running using supervisord (OPTIONAL)>`
* :ref:`Configure Additional Output Plugins (OPTIONAL)<INSTALL:Configure Additional Output Plugins (OPTIONAL)>`
* :ref:`Troubleshooting<INSTALL:Troubleshooting>`
* :ref:`Updating Cowrie<INSTALL:Updating Cowrie>`
* :ref:`Customising the honeypot<INSTALL:Customising the honeypot>`

Quick start: pip install
========================

For most operators, this is the shortest path::

    $ mkdir ~/my-honeypot && cd ~/my-honeypot
    $ python3 -m venv cowrie-env
    $ source cowrie-env/bin/activate
    (cowrie-env) $ pip install cowrie
    (cowrie-env) $ cowrie init
    (cowrie-env) $ $EDITOR etc/cowrie.cfg     # optional
    (cowrie-env) $ cowrie start

The venv lives inside the honeypot directory alongside ``etc/`` and
``var/``, keeping each honeypot self-contained.

The pip-install workflow described here requires Cowrie 3.0.0 or later
(or the current ``main`` branch). Earlier releases need the source
checkout path below.

``cowrie init`` writes ``./etc/cowrie.cfg`` from the bundled template.
On first ``cowrie start`` cowrie creates the rest of the state layout
(``var/log/cowrie/``, ``var/lib/cowrie/``, ``var/run/``) under the same
directory and generates SSH host keys. Pick the directory you want
state to live in before running ``init``.

Read on for system-dependency setup, port-22 listening, and other
optional pieces.

Step 1: System dependencies
***************************

Cowrie itself is pure Python, but several of its dependencies have
native components (``cryptography``, ``cffi``, ``bcrypt``, optional
``mysqlclient`` / ``libvirt-python``). On most distros you need
build-essential plus the OpenSSL and libffi headers for these to
compile during ``pip install``.

On Debian-based systems (last verified on Debian Bookworm)::

    $ sudo apt-get install python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind

For a source checkout, additionally install::

    $ sudo apt-get install git docker.io

(``docker.io`` is only needed if you want to rebuild ``fs.pickle`` from
a Debian container via ``make build-fs-pickle``.)

Step 2: Create a user account
*****************************

It is strongly recommended to run Cowrie as a dedicated non-root user::

    $ sudo adduser --disabled-password cowrie
    $ sudo su - cowrie

Cowrie refuses to start as root.

Step 3: Install Cowrie
**********************

Pip install (operators)
=======================

Pick the directory you want cowrie state (logs, downloads, host keys,
ttylogs) to live in, create the venv inside it, and install::

    $ mkdir ~/my-honeypot && cd ~/my-honeypot
    $ python3 -m venv cowrie-env
    $ source cowrie-env/bin/activate
    (cowrie-env) $ python -m pip install --upgrade pip
    (cowrie-env) $ python -m pip install cowrie

The venv is kept alongside ``etc/`` and ``var/`` so the honeypot
directory is self-contained.

Source checkout (developers)
============================

If you plan to modify Cowrie or run against unreleased code, you also
need the development extras (mypy, ruff, pre-commit, tox, sphinx,
etc.) and a few extra system packages for native builds::

    $ sudo apt-get install git docker.io
    $ git clone https://github.com/cowrie/cowrie
    $ cd cowrie
    $ python3 -m venv cowrie-env
    $ source cowrie-env/bin/activate
    (cowrie-env) $ python -m pip install --upgrade pip
    (cowrie-env) $ python -m pip install -e '.[dev]'

``docker.io`` is only required if you want to use ``make
build-fs-pickle`` to regenerate the bundled filesystem from a Debian
container. The ``[dev]`` extra brings in the typecheckers, linters,
test runner, and docs toolchain that match what CI uses.

In source-checkout mode, the repo root *is* the state directory.
``cowrie start`` detects this and skips the ``cowrie init`` step.

Step 4: Initialise the state directory
**************************************

(Skip this step if you are using a source checkout.)

From inside the honeypot directory you created in Step 3, run::

    (cowrie-env) $ cowrie init
    Wrote etc/cowrie.cfg
    Created var/log/cowrie, var/lib/cowrie, var/lib/cowrie/downloads, var/lib/cowrie/tty, var/run
    Edit etc/cowrie.cfg to customise hostname, ports, etc., then run `cowrie start`.

``cowrie init`` writes ``./etc/cowrie.cfg`` from the bundled template
and creates the ``var/`` skeleton so the first ``cowrie start`` has
somewhere to write logs and a PID file. SSH host keys are generated
on first start.

If the config already exists, ``cowrie init`` refuses with a non-zero
exit code rather than overwriting your edits — re-running ``cowrie
init`` is *not* idempotent.

Step 5: Configure
*****************

Configuration lives in ``./etc/cowrie.cfg`` relative to the directory
you run Cowrie from. The full set of available settings and their
defaults are documented in the bundled ``cowrie.cfg.dist`` (also
materialised by ``cowrie init`` for browsing).

Cowrie loads configuration in layers:

1. Bundled defaults (the ``cowrie.cfg.dist`` shipped inside the package).
2. ``/etc/cowrie/cowrie.cfg`` (system-wide install, if present).
3. ``./etc/cowrie.cfg`` (per-state-directory).
4. ``./cowrie.cfg`` (alternate flat layout).

Later layers override earlier ones for any keys they set. Your
``etc/cowrie.cfg`` only needs to contain the keys you want to change.

To enable Telnet, for example, the entire ``cowrie.cfg`` could be::

    [telnet]
    enabled = true

Step 6: Start Cowrie
********************

::

    (cowrie-env) $ cowrie start

Cowrie runs in the current working directory. Logs land in
``./var/log/cowrie/`` and the PID file is ``./var/run/cowrie.pid``.

``cowrie start`` refuses to run from a directory that has not been
initialised. If you see ``ERROR: cowrie is not initialised`` you are
probably in the wrong directory — ``cd`` into your state directory
first, or run ``cowrie init``.

Step 7: Listening on port 22 (OPTIONAL)
***************************************

The SSH daemon runs on port 22 by default. Cowrie defaults to port
2222. To collect most traffic, you need Cowrie listening on 22. This
requires two changes: relocate any existing SSH server, then expose
Cowrie on the lower port.

There are three approaches: ``iptables`` redirection, ``authbind``, or
``setcap``.

Iptables
========

Port redirection is system-wide and runs as root. A firewall redirect
can make your existing SSH server unreachable — move it to a different
port first.

Linux::

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

With nft::

    $ sudo nft add rule ip nat prerouting tcp dport 22 redirect to 2222

Telnet equivalents::

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
    $ sudo nft add rule ip nat prerouting tcp dport 23 redirect to 2223

Note: test from another host — these rules do not apply to loopback.

macOS::

    $ echo "rdr pass inet proto tcp from any to any port 22 -> 127.0.0.1 port 2222" | sudo pfctl -ef -

Authbind
========

Run Cowrie as a non-root user but bind directly to port 22::

    $ sudo apt-get install authbind
    $ sudo touch /etc/authbind/byport/22
    $ sudo chown cowrie:cowrie /etc/authbind/byport/22
    $ sudo chmod 770 /etc/authbind/byport/22

Set the listening port in ``etc/cowrie.cfg``::

    [ssh]
    listen_endpoints = tcp:22:interface=0.0.0.0

Or for Telnet::

    $ sudo touch /etc/authbind/byport/23
    $ sudo chown cowrie:cowrie /etc/authbind/byport/23
    $ sudo chmod 770 /etc/authbind/byport/23

And in ``etc/cowrie.cfg``::

    [telnet]
    listen_endpoints = tcp:23:interface=0.0.0.0

Start with authbind enabled::

    $ AUTHBIND_ENABLED=yes cowrie start

Setcap
======

Grant the Python binary the bind-low-port capability::

    $ setcap cap_net_bind_service=+ep /usr/bin/python3

Then change the listen ports in ``etc/cowrie.cfg`` as above.

Installing Backend Pool dependencies (OPTIONAL)
***********************************************

If you want proxy mode with the automatic backend pool, install QEMU
and libvirt::

    $ sudo apt-get install qemu-system-arm qemu-system-x86 libvirt-dev libvirt-daemon libvirt-daemon-system libvirt-clients nmap

Then install the Python extra::

    (cowrie-env) $ python -m pip install 'cowrie[pool]'

(In a source checkout: ``python -m pip install -e '.[pool]'``.)

To let QEMU use disk images and snapshots, edit
``/etc/libvirt/qemu.conf`` and set both ``user`` and ``group`` to the
user running the pool (typically ``cowrie``).

Running using supervisord (OPTIONAL)
************************************

In ``/etc/supervisor/conf.d/cowrie.conf``::

    [program:cowrie]
    command=/home/cowrie/cowrie-env/bin/cowrie start -n
    directory=/home/cowrie/my-honeypot
    user=cowrie
    autorestart=true
    redirect_stderr=true

The ``directory=`` must point at the state directory you initialised in
Step 4.

Configure Additional Output Plugins (OPTIONAL)
**********************************************

Cowrie automatically outputs event data to text and JSON log files in
``./var/log/cowrie``. Additional output plugins can record the data
elsewhere. Supported plugins include:

* Cuckoo
* ELK (Elastic) Stack
* Graylog
* Splunk
* SQL (MySQL, SQLite3, RethinkDB)

See ``docs/[Output Plugin]/README.rst`` for details.

Troubleshooting
***************

cowrie is not initialised in this directory
===========================================

You ran ``cowrie start`` from a directory that does not look like a
cowrie state directory. Either ``cd`` to your state directory first, or
run ``cowrie init`` to set up the current directory.

CryptographyDeprecationWarning: Blowfish has been deprecated
============================================================

Safe to ignore::

    CryptographyDeprecationWarning: TripleDES has been moved to ...

twistd: unknown command: cowrie
===============================

Two possibilities. If there is a Python stack trace, a dependency is
missing or broken. Without a stack trace, double-check that you
activated the right virtualenv.

General approach
================

Check the log file ``./var/log/cowrie/cowrie.log`` (relative to wherever
you started Cowrie).

Updating Cowrie
***************

Cowrie commands operate on the current working directory — the PID
file, log paths, and state files are all relative to wherever you ran
``cowrie start`` from. Stop and start commands must be issued from the
same directory.

Stop your honeypot first::

    (cowrie-env) $ cd ~/my-honeypot
    (cowrie-env) $ cowrie stop

Pip install::

    (cowrie-env) $ python -m pip install --upgrade cowrie

Source checkout::

    (cowrie-env) $ cd ~/cowrie
    (cowrie-env) $ git pull
    (cowrie-env) $ python -m pip install --upgrade -e .

If you use the SQL/Splunk/ELK output plugins, also upgrade their
optional dependencies::

    (cowrie-env) $ python -m pip install --upgrade -r requirements-output.txt

Restart::

    (cowrie-env) $ cd ~/my-honeypot
    (cowrie-env) $ cowrie start

Customising the honeypot
************************

The simulated filesystem and the default file contents that attackers
see (``/etc/passwd``, ``/etc/hostname``, ``/proc/cpuinfo``, etc.) ship
inside the bundled ``fs.pickle``. Three customisation paths:

Per-file operator override
==========================

Set ``contents_path`` in ``etc/cowrie.cfg`` to a directory of your
choice, and drop a file at the matching path inside it::

    [honeypot]
    contents_path = /opt/cowrie/honeyfs

Then::

    $ mkdir -p /opt/cowrie/honeyfs/etc
    $ vi /opt/cowrie/honeyfs/etc/issue.net

Files present in this directory override the bundled defaults at
matching paths. Anything not overridden continues to come from the
pickle. Only files that already exist in the pickle are visible to
attackers via ``cat``; adding a brand-new path requires editing the
pickle itself.

Editing the pickle
==================

The bundled ``fs.pickle`` lives inside the installed Cowrie package and
is read-only from an operator's perspective. To edit it, copy it out
first and point ``[shell] filesystem`` at your local copy::

    (cowrie-env) $ python -c "from cowrie.core.resources import read_data_bytes; \
        open('var/lib/cowrie/fs.pickle', 'wb').write(read_data_bytes('fs.pickle'))"

Add to ``etc/cowrie.cfg``::

    [shell]
    filesystem = var/lib/cowrie/fs.pickle

Then edit with ``fsctl``. For a one-off file change::

    $ fsctl var/lib/cowrie/fs.pickle "load /etc/passwd /path/to/your/passwd"

For a bulk update of many files from a local directory::

    $ fsctl var/lib/cowrie/fs.pickle "embed /path/to/your/honeyfs"

Use ``fsctl <pickle>`` with no command to enter the interactive shell.

Rebuilding the pickle from scratch
==================================

To regenerate the bundled filesystem from a fresh Debian container with
custom packages, see ``bin/build-fs-pickle.sh`` and the ``make
build-fs-pickle`` target. Paths listed in ``createfs.py``'s
``EMBED_PATHS`` have their bytes baked into the pickle during the
build.

Local testing with SSH
**********************

After starting Cowrie, you can test by connecting via SSH:

1. Start Cowrie::

       (cowrie-env) $ cd ~/my-honeypot
       (cowrie-env) $ cowrie start

2. Connect (Cowrie listens on 2222 by default)::

       $ ssh -p 2222 root@localhost

3. If authentication fails, check ``etc/userdb.txt`` and confirm an
   allow rule exists. Rules are processed top-to-bottom and stop at
   the first match.

4. Logs land in ``./var/log/cowrie/cowrie.log`` — all recorded
   activity, login attempts, and shell commands.
