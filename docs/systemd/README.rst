Automatically starting Cowrie with systemd
###########################################

NOTE: untested

* Copy the file ``docs/systemd/system/cowrie.socket`` to ``/etc/systemd/system``

* Copy the file ``docs/systemd/system/cowrie.service`` to ``/etc/systemd/system``

* Examine ``/etc/systemd/system/cowrie.service`` and ensure the paths are correct for your installation if you use non-standard file system locations.

* Add entries to ``etc/cowrie.cfg`` to listen on ports via systemd. These must match your cowrie.socket configuration::

    [ssh]
    listen_endpoints = systemd:domain=INET6:index=0

    [telnet]
    listen_endpoints = systemd:domain=INET6:index=1

* Run::

    $ sudo systemctl daemon-reload
    $ sudo systemctl start cowrie.service
    $ sudo systemctl enable cowrie.service
