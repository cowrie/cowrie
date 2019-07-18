qemu/libvirt Python examples to handle a guest

# Tips
## Create a VM
```
# qemu-img create -f qcow2 ubuntu18.04-cloud.qcow2 8G
$ virt-install --name ubuntu-cloud --memory 2048 --disk ubuntu18.04-cloud.qcow2 --cdrom ubuntu-18.04-minimal-cloudimg-amd64.img --boot cdrom
```

After install check that the VM has network connectivity. If you set the pool to use the created image and SSH does not come up, log into the VM via libvirt (e.g. using virt-manager) and try the following (might change depending on system):

## Get network up and running on guest after creation:
```
# ip link show
# ip link set enp1s0 up
# dhclient
```

In Ubuntu dhclient can be set to run with netplan, for example.

## Set up Telnet
In Ubuntu:
```
# apt-get -y install telnetd xinetd
# touch /etc/xinetd.d/telnet
# printf "service telnet\n{\ndisable = no\nflags = REUSE\nsocket_type = stream\nwait = no\nuser = root\nserver = /usr/sbin/in.telnetd\nlog_on_failure += USERID\n}" > /etc/xinetd.d/telnet
# printf "pts/0\npts/1\npts/2\npts/3\npts/4\npts/5\npts/6\npts/7\npts/8\npts/9" >> /etc/securetty
# service xinetd start
```
