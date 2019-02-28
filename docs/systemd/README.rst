Automatically starting Cowrie with systemd
###########################################

NOTE: untested

* Copy the file `systemd/system/cowrie.socket` to `/etc/systemd/system`

* Copy the file `systemd/system/cowrie.service` to `/etc/systemd/system`

* Modify `bin/cowrie` script like this:

  * Change DAEMONIZE="" line to DAEMONIZE="-n"
  * Change #STDOUT="no" line to STDOUT="yes"

* Run sudo systemctl start cowrie.socket && sudo systemctl enable cowrie.socket
