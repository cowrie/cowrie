Using the Proxy
###############

The SSH and Telnet proxies can be used to provide a fully-fledged environment,
in contrast to the emulated shell traditionally provided by Cowrie. With a real
backend environment where attackers can execute any Unix command, Cowrie becomes a
high-interaction honeypot.

To use the proxy, start by changing the ``backend`` option to ``proxy`` in the ``[honeypot]`` section.
In the remainder of this guide we will refer to the ``[proxy]`` section of the config file.

Choosing a Backend
******************

Cowrie supports a simple backend (i.e., a real machine or virtual machines provided by you),
but you can use Cowrie's backend pool, which provides a set of VMs, handling their boot
and cleanup, also ensuring that different attackers (different IPs) each see a "fresh" environment,
while connections from the same IP get the same VM.

**VERY IMPORTANT NOTE:** some attacks consist of downloading malicious software or accessing
illegal content through insecure machines (such as your honeypot). If you are using your **own backend**,
be sure to restrict networking to the Internet on your backend, and ensure other machines
on your local network are isolated from the backend machine. The backend pool restricts
networking and does its best to ensure total isolation, to the best of Qemu/libvirt (and our
own) capabilities. **Be very careful to protect your network and devices!**

Configuring the Proxy
*********************

Backend configs
===============

If you choose the simple backend, configure the hosts and ports for your backend. For the
backend pool, configure the variables starting with ``pool\_``. You'll also need to deal with
the ``[backend_pool]`` section, which we detail in the
`Backend Pool's own documentation <https://docs.cowrie.org/en/latest/BACKEND_POOL.html>`_.

The backend pool can be run in the same machine as Cowrie, or on a remote one (e.g. Cowrie on a
Raspberry Pi, and the pool in a larger machine). In the former case, set ``pool`` to ``local``;
in the later, set ``pool`` to ``remote`` and specify its host and port, matching with the
``listen_endpoints`` of the ``[backend_pool]`` section. Further configurations sent by the client
are explained in
`Backend Pool's own documentation <https://docs.cowrie.org/en/latest/BACKEND_POOL.html>`_.

Authentication
==============

Regardless of the used type of backend, Cowrie will need credentials to access the machine.
These can be of any account on it, as long as it supports password authentication.

Note that these are totally independent of the credentials attackers can use (as set in
``userdb``). ``userdb`` credentials are the ones attackers may use to connect to Cowrie, while
``backend_user`` and ``backend_pass`` are used to connect Cowrie to the backend.

Telnet prompt detection
=======================

Due to the different implementations of Telnet, there is not a single reliable way of catching
the authentication phase of the protocol as in SSH. Therefore, we rely on regex expressions
to detect authentication prompts, allowing us to identify the credentials supplied by the
attacker and check if they are accepted by ``userdb``. If they are, we send the ``backend_user``
and ``backend_pass`` to the backend (spoofing  the authentication); if not, we send ``backend_pass``
appended with the word ``fake`` to force a login failed prompt (and fail authentication overall).

If you don't want to spoof authentication, set ``telnet_spoof_authentication`` to false. In this
mode, only the backend real details will be accepted to authenticate, thus bypassing ``userdb``.

The expressions to detect authentication prompts are ``telnet_username_prompt_regex`` and
``telnet_password_prompt_regex``. A further expression we use is defined in
``telnet_username_in_negotiation_regex``. Some clients send their username in the first phases of
the protocol negotiation, which some systems (the backend) use to only show the password prompt
the first time authentication is tried (thus assuming the client's username as the username
they'll use to login into the system). Cowrie tries to capture this username and use it when
comparing the auth details with the ``userdb``.

Analysing traffic
=================

Analysing raw traffic can be interesting when setting up Cowrie, in particular to set-up
Telnet prompt detection. For this, you can set ``log_raw`` to true.
