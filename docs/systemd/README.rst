Automatically starting Cowrie with systemd
###########################################

* Copy the file ``docs/systemd/system/cowrie.service`` to ``/etc/systemd/system``

* Examine ``/etc/systemd/system/cowrie.service`` and ensure the paths are correct for your installation if you use non-standard file system locations.


* Run::

    $ sudo systemctl daemon-reload
    $ sudo systemctl enable cowrie.service
    $ sudo systemctl start cowrie.service
