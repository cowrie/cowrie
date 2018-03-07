# Automatically starting Cowrie with systemd

* Copy the file `cowrie.service` to `/etc/systemd/service`
* Reload systemd with `systemctl daemon-reload`
* Start Cowrie with `service cowrie start`
* Enable start at boot-time with `sudo systemctl enable cowrie.service``
