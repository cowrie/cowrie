All username credentials, when sent to backend, have the configured username that is known to succeed (i.e. exist in
the backend). When we spoof the password we decide whether the login is valid or not, and in the second case we send
an invalid password, thus causing auth to fail.


# Caveats in the protocol:

* When username is being input (and chars are being sent to the backend), the **client expects to receive their echo**.
In our proxy, we do the echo locally, since **we don't want the backend to see our authentication** (in the end we send
to the backend  what we want it to see). When we send the username in the end, the **backend then sends the full echo**
of the username, which look for and **ignore** in the proxy.

* Backspaces in authentication are sent as **0x7F from the frontend**, but it expects to **receive "0x08 0x08"
as echo**, so we also have to look for that in the proxy's handler.
