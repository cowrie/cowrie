Using TCP tunneling with Squid
#################################

Squid Prerequisites
===================

* Working Cowrie installation
* Working Squid installation with CONNECT allowed
* Rate limit and black/white lists in Squid (optional)

Squid Installation
==================

Install Squid::

     $ sudo apt-get install squid

Squid Configuration
===================

See ``squid.conf`` for an example configuration.

Cowrie Configuration for Squid
==============================

Uncomment and update the following entries to ``etc/cowrie.cfg`` under the SSH section::

    [ssh]
    forward_tunnel = true
    forward_tunnel_80 = 127.0.0.1:3128
    forward_tunnel_443 = 127.0.0.1:3128

## Restart Cowrie

Restart::

    $ bin/cowrie restart
