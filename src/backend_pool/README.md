QEMU/libvirt Python examples to handle a guest

# Developer Guide
We'll start by looking at the classes that compose the Backend Pool, from "outermost" to the inner, specific classes.

## pool_server.py
The main interface of the backend pool is exposed as a TCP server in _pool\_server.py_. The protocol is a very simple
wire protocol, always composed of an op-code, a status code (for responses), and any needed data thereafter.

## pool_service.py
The server interfaces exposes a producer-consumer infinite loop that runs on _pool\_service.py_.

The **producer** is an infinite loop started by the server, and runs every 5 seconds. It creates VMs up to the
configured limit, checks which VMs become available (by testing if they accept SSH and/or Telnet connections), and
destroys VMs that are no longer needed.

**Consumer** methods are called by server request, and basically involve requesting and freeing VMs. All operations on
shared data in the producer-consumer are guarded by a lock, since there may be concurrent requests. The lock protects
the _guests_ list, which contains references for each VM backend (in our case libvirt/QEMU instances).

Since we won't be dealing with a very large number of VMs (never more than 100, we find that a single simple lock is
enough.

The Pool Service expects to find a "backend service" with a given interface:
* A method to initialise the backend interface and environment (start_backend), stop it and destroy the current
environment (stop_backend), and shutdown it permanently for the current execution (shutdown_backend).
* A method to create a new guest (create_guest)
* A method to destroy a guest (destroy_guest)

Currently the service supports a libvirt/QEMU backend. However, by splitting the logic from generic guest handling /
interaction with main Cowrie, from the logic to create guests in a low-level perspective, we hope to ease development
of different kinds of backends in the future.

## libvirt classes
The main class for libvirt is _backend\_service.py_, and implements the interface discussed above. Guest, network and
snapshot handlers deal with those specific components of libvirt's handling.

Initialising libvirt involves connecting to the running system daemon, creating a network filter to restrict guest's
Internet access, and creating a "cowrie" network in libvirt.

Guest creation is started by creating a snapshot from the base qcow2 image defined in the configs, and instantiating
a guest from the XML provided. The Guest Handler replaces templates ("{guest_name}") with user configs for the wanted
guest. If the XML provided does not contain templates, then no replacement takes place, naturally.
