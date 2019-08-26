The SSH proxy is divided into a server module (frontend) and a client module (backend).
When clients (the attackers) connect to Cowrie, we start a connection (using Twisted Conch's client) to a specified server.

The proxy's structure is:

```
                +------------------------------------------------------+
                |                                                      |
                |                                                      |
+----------+    |   +----------+      +-----------+      +---------+   |    +------------+
|          |    |   |          |      |           |      |         |   |    |            |
| ATTACKER +<-->-<->+ FRONTEND +<---->+  HANDLER  +<---->+ BACKEND +<->+<-->+ SSH SERVER |
|          |    |   |          |      |           |      |         |   |    |            |
+----------+    |   +----------+      +-----------+      +---------+   |    +------------+
                |                                                      |
                |                     COWRIE'S PROXY                   |
                +------------------------------------------------------+


```

Frontend is serverTransport.py, handler is ssh.py, and backend is clientTransport.py.

When an attacker connects, authentication is performed between them and the frontend, and between backend and server. The frontend part is handled by Cowrie and Twisted's own service. The backend part is a simple password authentication specified in the config - we assume backends are in a secure network anyway.

After authentication all SSH transport data is forwarded from attacker to server. Our proxy intercepts all messages and handles them as needed in ssh.py. We support exec, direct-tcpip and sftp, all of which have their own specification in the protocols directory. If a service is disabled in config, the handler does not forward the request to the server, instead creating and returning a default error message immediately.


## Authentication
Authentication leverages the same mechanism found in Cowrie's shell: it's set as a service provided by Twisted, and the same configurations apply when using both shell and proxy backends.

## Managing the VM pool
The flow to get VMs from the pool might be a little complicated because of the amount of back-and-forth needed when using deferreds.

The Pool interface is started in the Cowrie plugin (if enabled by configuration, of course), and the reference to it passed to both SSH and Telnet factories.

When the pool handler is started by the plugin, it immediately establishes a connection to the pool server, setting values from configuration into that server. If the connection fails, or these values are not set correclty, Cowrie is aborted, since it wouldn't be possible to continue without a correctly configured pool.

### SSH
When a new SSH connection is received in the frontend (serverTransport.py), the later has two tasks: perform userauth and connect to a backend. We start this in the connectionMade function. A pool connection is requested, and if that connection is successful we call pool_connection_success.

We then request a backend via send_vm_request. If any of these operations fail, we disconnect the frontend. Else we have a function called when data is received from the pool, **received_pool_data**.

When we receive a response to a VM request operation, we known we can start connecting to the backend, which we do. After that connection is established we can glue the two transports - frontend and backend - when the backendConnected variable is set to true in the backend.
