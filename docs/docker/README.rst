Docker Repository
=================

Quick Trial
***********

To run Cowrie in Docker locally without creating your own image, run::

    $ docker run -p 2222:2222 cowrie/cowrie

Then run an SSH client to port 2222 to test it::

    $ ssh -p 2222 root@localhost


Configuring Cowrie in Docker
****************************

Cowrie in Docker can be configured using environment variables. The
variable starts with ``COWRIE_`` then has the section name in capitals,
followed by the stanza in capitals. This example enables
telnet support::

    COWRIE_TELNET_ENABLED=yes

Alternatively, Cowrie in Docker can use an `etc` volume to store
configuration data.  Create ```cowrie.cfg``` inside the etc volume
with the following contents to enable telnet in your Cowrie Honeypot
in Docker::

    [telnet]
    enabled = yes

Building Your Own Docker Images
*******************************

If you want to make extensive changes to the Docker image, it may be easier to build
your own local docker image with::

    $ make docker-load
