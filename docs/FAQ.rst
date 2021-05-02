Frequently asked questions
##########################

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

