Analysing snapshots and downloaded content
##########################################

One interesting aspect of Cowrie is the capability to analyse any downloaded malware and
content into the honeypot. The snapshot mechanism can be leveraged to analyse any download
and any change performed against the base image, to determine which files have been changed.

This guide shows how that can be achieved by leveraging using the ``libguestfs-tools`` package.

Getting the a filesystem diff
*****************************

The first step is getting the differences between each VM that was used and the base image provided.
The tool we'll be using is ``virt-diff``, which provides a similar syntax to that of Unix's ``diff``.

.. code-block:: bash

    $ sudo virt-diff -a ~/cowrie-imgs/ubuntu18.04-minimal.qcow2 -A snapshot-ubuntu18.04-a70b9671ad4d44619af2c4a41a28aec0.qcow2

(the tool might need to be run with sudo due to a permission denied error)

The output will contain all changed files and their content, which might get long easily. The
following command outputs the names of changed files, to be easier to read (assuming the output
from ``virt-diff`` is stored in a file diff.txt)

.. code-block:: bash

    $ grep -aE "^\+ |^- |^= " diff.txt

Here is an example output, in a VM were we created a file called ``avirus``::

    = - 0644       1024 /boot/grub/grubenv
    = - 0600       1036 /root/.bash_history
    + - 0644         14 /root/avirus
    + d 0700       4096 /tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-resolved.service-syUmHS
    + d 1777       4096 /tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-resolved.service-syUmHS/tmp
    + d 0700       4096 /tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-timesyncd.service-SrDysr
    + d 1777       4096 /tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-timesyncd.service-SrDysr/tmp
    + - 0644       2163 /var/backups/apt.extended_states.0
    + - 0644          0 /var/lib/apt/daily_lock
    = - 0644          0 /var/lib/private/systemd/timesync/clock
    = - 0600        512 /var/lib/systemd/random-seed
    = - 0644          0 /var/lib/systemd/timers/stamp-apt-daily-upgrade.timer
    = - 0644          0 /var/lib/systemd/timers/stamp-apt-daily.timer
    = - 0644          0 /var/lib/systemd/timers/stamp-fstrim.timer
    = - 0644          0 /var/lib/ubuntu-release-upgrader/release-upgrade-available
    = - 0640      14534 /var/log/auth.log
    = - 0640    8388608 /var/log/journal/19497399992e49388d57aa395b993b2c/system.journal
    = - 0640     346383 /var/log/kern.log
    = - 0664     292292 /var/log/lastlog
    = - 0640     436458 /var/log/syslog
    = - 0664      19968 /var/log/wtmp
    + d 0700       4096 /var/tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-resolved.service-u5dZk6
    + d 1777       4096 /var/tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-resolved.service-u5dZk6/tmp
    + d 0700       4096 /var/tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-timesyncd.service-Tcil4E
    + d 1777       4096 /var/tmp/systemd-private-9f5f6c41f75f48f4991c55f3fc3d6435-systemd-timesyncd.service-Tcil4E/tmp

As you can see, the created file is shown among lots of log and temporary files. There is
no good way to eliminate these, but we can use grep to ignore them:

.. code-block:: bash

    $ grep -aE "^\+ |^- |^= " diff.txt | grep -aEv "/tmp/systemd|/var/log|/var/lib"

Which now gives us a clearer output::

    = - 0644       1024 /boot/grub/grubenv
    = - 0600       1036 /root/.bash_history
    + - 0644         14 /root/avirus
    + - 0644       2163 /var/backups/apt.extended_states.0

Getting interesting files
*************************

To be able to get and read the files you're interested in, you'll need to mount the snapshot
into your machine and copy the file(s) into your disk. The steps we describe are taken from
`here <http://ask.xmodulo.com/mount-qcow2-disk-image-linux.html>`_, and rewritten here for
clarity.

We start by mounting the image in a temporary dir:

.. code-block:: bash

    $ mkdir /tmp/mount_qcow2
    $ sudo guestmount -a snapshot-ubuntu18.04-a70b9671ad4d44619af2c4a41a28aec0.qcow2 -m /dev/sda1 --ro /tmp/mount_qcow2

If we now search for the file in the mount directory we can see its contents, and then unmount
the drive:

.. code-block:: bash

    $ sudo ls -halt /tmp/mount_qcow2/root
    total 32K
    -rw-------  1 root root 1.1K Jul 28 21:45 .bash_history
    drwx------  3 root root 4.0K Jul 28 21:45 .
    -rw-r--r--  1 root root   14 Jul 28 21:45 avirus
    drwxr-xr-x 22 root root 4.0K Jul 15 01:57 ..
    -rw-r--r--  1 root root   74 Jul 15 00:59 .selected_editor
    drwx------  2 root root 4.0K Jul 15 00:59 .cache
    -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
    -rw-r--r--  1 root root  148 Aug 17  2015 .profile

    $ sudo cat /tmp/mount_qcow2/root/avirus
    virus content

    $ sudo guestunmount /tmp/mount_qcow2/

**Note:** the device to be mounted from the image isn't always ``/dev/sda1``. However, if you
run the command as-is, ``guestmount`` will check if ``/dev/sda1`` exists and, if not, it will
list available partitions for you.
