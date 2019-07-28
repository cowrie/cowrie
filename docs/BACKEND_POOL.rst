Backend Pool
############

The Backend Pool manages a set of dynamic backend virtual machines to be used by
Cowrie's proxy. The pool keeps a set of VMs running at all times, ensuring different
attackers each see a "pristine" VM, while repeated connections from the same IP are
served with the same VM, thus ensuring a consistent view to the attacker. Furthermore,
VMs in the pool have their networking capabilities restricted by default: some attacks
consist of downloading malicious software or accessing illegal content through
insecure machines (such as your honeypot). Therefore, we limit any access to the
Internet via a network filter, which you can configure as you see fit.

The VMs in the backend pool, and all infrastructure (snapshots, networking and filtering)
are backed-up by Qemu/libvirt. We provide two example VM images (for Ubuntu Server 18.04
and OpenWRT 18.06.4) whose configurations are already set and ready to be deployed.
Further below in this guide we'll discuss how to create your own images and customise
libvirt's XML configuration files.

Proxy configurations
********************

When the proxy starts, and regardless whether the backend pool runs on the same machine
as the proxy or not, some configurations are sent by the proxy to the pool during runtime.

These are:

* **pool_max_vms**: the number of VMs to be kept running in the pool

* **pool_vm_unused_timeout**: how much time (seconds) a used VM is kept running (so that
  an attacker that reconnects is served the same VM.

* **apool_share_guests**: what to do if no "pristine" VMs are available (i.e., all have
  been connected to); if set to true we serve a random one from the used, if false we
  throw an exception.


Backend Pool configuration
**************************

In this section we'll discuss the `[backend_pool]` section of the configuration file.

The backend pool can be run in the same machine as the rest of Cowrie, or in a separate
one. In the former case, you'd be running Cowrie with

.. code-block:: python

    [backend_pool]
    pool_only = false

    [proxy]
    pool_local = true

If you want to deploy the backend pool in a different machine, then you'll need to
invert the configuration: the pool machine has `pool_only = true` (SSH and Telnet
are disabled), and the proxy machine has `pool_local = false`.

**Note:** The communication protocol used between the proxy and the backend pool
is unencrypted. Although no sensitive data should be passed, we recommend you to
only use private or local interfaces for listening when setting up `listen_endpoints`.

Recycling VMs
=============

Currently, handling of virtual machines by the pool is not perfect. Sometimes,
VMs reach an inconsistent state or become unreliable. To counter that, and ensure
fresh VMs are ready constantly, we use the `recycle_period` to periodically
terminate running instances, and boot new ones.

Snapshots
=========

VMs running in the pool are based on a base image that is kept unchanged. When booting,
each VM creates a snaphost that keeps track of differences between the base image and
snapshot. If you want to analyse snapshots and see any changes made in the VMs, set
`save_snapshots` to true.

XML configs (advanced)
======================

You can change libvirt's XML configs from the default ones in `share/cowrie/pool_configs`.
However, if you're using one of the default images provided, then you probably don't
need to.

Guest configurations
====================

A set of guest (VM) parameters can be defined as we explain below:

* **guest_config**: the XML configuration for the guest (default_guest.xml works for x86 machines,
  and wrt_arm_guest.xml for ARM-based OpenWRT)

* **guest_privkey**: currently unused

* **guest_tag**: an identifiable name for snapshots and logging

* **guest_ssh_port / guest_telnet_port**: which ports are listening for these on the VM
  (no relation with the ports Cowrie's listening to)

* **guest_image_path**: the base image upon which all VMs are created from

* **guest_backend**: the emulation tool used; if you have an older machine or the emulated
  architecture is different from the host one, then use software-based "qemu"; however,
  if you are able to, use "kvm", it's **much** faster.

* **guest_memory**: memory assigned to the guest; choose a value considering the number
  of guests you'll have running in total (`pool_max_vms`)


NATing
======

VMs are assigned an IP in a local network defined by libvirt. If you need to access the VMs
from a different machine (i.e., running the backend pool remotely), then an external-facing
IP (as defined in `nat_public_ip`) is needed for the proxy to connect to.

For this purpose, we provide a simple form of NAT that, for each VM request, and if enabled,
starts a TCP proxy to forward data from a publicly-acessible IP to the internal libvirt interface.

Creating VM images
******************

Creating a new type of VM involves three steps: creating a base image, installing the OS,
and tweaking configs.

To create a disk image issue

.. code-block:: bash

    # qemu-img create -f qcow2 image-name.qcow2 8G

(the qcow2 format is needed to ensure create snapshots, thus providing isolation between
each VM instance; you can specify the size you want for the disk)

Then you'll have to install an OS into it

.. code-block:: bash

    $ virt-install --name temp-domain --memory 1024 --disk image-name.qcow2 --cdrom os-install-cd.iso --boot cdrom

(to use virt-install you need to install the virtinst package)

After install check that the VM has network connectivity. If you set the pool to use the
created image and SSHdoes not come up, log into the VM via libvirt (e.g., using virt-manager)
and try the following (might change depending on system)

.. code-block:: bash

    # ip link show
    # ip link set enp1s0 up
    # dhclient

In Ubuntu dhclient can be set to run with netplan, for example, to be run on startup.

Set up Telnet
=============

Steps used in Ubuntu, can be useful in other distros

.. code-block:: bash

    # apt-get -y install telnetd xinetd
    # touch /etc/xinetd.d/telnet
    # printf "service telnet\n{\ndisable = no\nflags = REUSE\nsocket_type = stream\nwait = no\nuser = root\nserver = /usr/sbin/in.telnetd\nlog_on_failure += USERID\n}" > /etc/xinetd.d/telnet
    # printf "pts/0\npts/1\npts/2\npts/3\npts/4\npts/5\npts/6\npts/7\npts/8\npts/9" >> /etc/securetty
    # service xinetd start
