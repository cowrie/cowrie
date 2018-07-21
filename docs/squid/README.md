# Using TCP tunneling with Squid


## Prerequisites

* Working Cowrie installation
* Working Squid installation with CONNECT allowed
* (optional) Rate limit and black/white lists in Squid


## Installation

```
$ sudo apt-get install squid
```


## Squid Configuration

See `squid.conf` for an example configuration.


## Cowrie Configuration

Uncomment and update the following entries to ~/cowrie/cowrie.cfg under the SSH section:

```
forward_tunnel = true

forward_tunnel_80 = 127.0.0.1:3128
forward_tunnel_443 = 127.0.0.1:3128
```


## Restart Cowrie

```
$ cd ~/cowrie/bin/
$ ./cowrie restart
```
