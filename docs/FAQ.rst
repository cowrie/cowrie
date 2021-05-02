Frequently asked questions
##########################

Why can't I start cowrie on port 22?
*************************************

The possible answer for that is you might already have a service
(possibly SSH) running on that port so setting up Cowrie on that
port will cause a problem. Try changing the port in ``listen_endpoints``
present in config file (``etc/cowrie.cfg``).
 
Why do I get logged into my own system when accessing cowrie on port 22?
************************************************************************

This is probably a similar problem as it was in the above question.
This can also be fixed by changing the port in the config file.

What I am getting permission denied when running cowrie on port 22?
*******************************************************************

You need root privileges to run Cowrie on any port lower than 1024.
This can be fixed by setting up `Authbind
<https://cowrie.readthedocs.io/en/latest/INSTALL.html#authbind>`_.

Do I need to copy all the content of cowrie.cfg.dist to cowrie.cfg?
*******************************************************************

No, Cowrie merges your local settings in ``cowrie.cfg`` and
the default settings will automatically be read from ``cowrie.cfg.dist``

Why certain commands aren't implemented?
****************************************

Implementing all possible UNIX commands in Python is not worth the
time and effort. Cowrie tries to provide most common commands used by attackers
of the honeypot. If you see attackers use a command that you'd like
to see implemented, please let us know, or send a pull request.

