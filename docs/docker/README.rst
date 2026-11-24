.. SPDX-FileCopyrightText: 2019-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Docker Repository
=================

Docker Images are available on Docker Hub: https://hub.docker.com/r/cowrie/cowrie

Docker Quick Start
******************

To run Cowrie in Docker::

    $ docker run -p 2222:2222 cowrie/cowrie
    $ ssh -p 2222 root@localhost


Configuring Cowrie in Docker with Environment Variables
*******************************************************

Cowrie in Docker can be configured using environment variables. The
variable starts with ``COWRIE_`` then has the section name in capitals,
followed by the stanza in capitals. This example enables
telnet support::

    COWRIE_TELNET_ENABLED=yes

And then start Cowrie as::

    $ docker run -e COWRIE_TELNET_ENABLED=yes -p 2223:2223 cowrie/cowrie
    $ telnet localhost 2223


Configuring Cowrie in Docker with Config Files
**********************************************

Alternatively, Cowrie in Docker can use an `etc` mount to store
configuration data. Docker can either mount a volume or a directory.

Mounting a volume or directory on `/etc` will make existing files
unavailable to Cowrie, so make sure to copy `userdb.txt` and
`cowrie.cfg.dist` there too!

Create ```cowrie.cfg``` inside the etc directory (or volume)
with the following contents to enable telnet in Cowrie in Docker::

    [telnet]
    enabled = yes

Start Cowrie as::

    $ docker run -p 2223:2223 --mount type=bind,source=./etc,target=/cowrie/cowrie-git/etc cowrie/cowrie
    $ telnet localhost 2223

Environment variables take precedence over the configuration file.


Building Docker Images
*******************************

If you want to make extensive changes to the Docker image, it may be easier to build
your own local docker image with::

    $ make docker-load

The image needs ``src/cowrie/_version.py``, which ``setuptools_scm`` generates from
the git history and which is not tracked in git. ``make`` writes it before the build.
A plain ``docker build`` from a fresh clone does not have it, and ``.git`` is excluded
from the build context, so pass the version in instead::

    $ pip install setuptools-scm
    $ docker build -f docker/Dockerfile \
        --build-arg SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COWRIE=$(python3 -m setuptools_scm) .

Without the build argument the image still builds and runs, reporting version
``0.0.0+unknown``.
