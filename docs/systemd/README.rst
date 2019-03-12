Automatically starting Cowrie with systemd
###########################################

NOTE: untested

* Copy the file `docs/systemd/system/cowrie.socket` to `/etc/systemd/system`

* Copy the file `docs/systemd/system/cowrie.service` to `/etc/systemd/system`

* Examine `/etc/systemd/system/cowrie.server` and ensure the paths are correct for your installation if you use non-standard file system locations.

* Modify `etc/cowrie.cfg` to listen on ports via systemd:

    [ssh]
    listen_endpoints = systemd:domain=INET6:index=0

    [telnet]
    listen_endpoints = systemd:domain=INET6:index=1

* Modify `bin/cowrie` script like this:

  * Change DAEMONIZE="" line to DAEMONIZE="-n"
  * Change #STDOUT="no" line to STDOUT="yes"

* Run sudo systemctl start cowrie.socket && sudo systemctl enable cowrie.socket
