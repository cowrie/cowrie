Frequently asked questions
##########################

Why can't I start cowrie on port 22?
*************************************

The possible answer for that is you might already have a service(possibly SSH) running on that port so setting up Cowrie on that port will cause a problem. Try changing the port in `listen_endpoints` present in config file(cowrie.cfg.dist/cowrie.cfg).

Why do I get logged into my own system when accessing cowrie on port 22?
************************************************************************

This is probably a similar problem as it was in the above question. This can also be fixed by changing the port in the config file.

What I am getting permission denied when running cowrie on port 22?
*******************************************************************

You need root privileges to run Cowrie on any port lower than 1024. This can be fixed by setting up `Authbind <https://cowrie.readthedocs.io/en/latest/INSTALL.html#authbind>`_.

Do I need to copy all the content of cowrie.cfg.dist to cowrie.cfg?
*******************************************************************

No, Cowrie can read add your only local changes to cowrie.cfg and the remaining settings will automatically be read from cowrie.cfg.dist


Why certain commands aren't implemented?
****************************************

There are lots of UNIX command implemented in cowrie and that is because Cowrie is more focused to provide proxy support i.e use Cowrie to connect to an actual machine that is actual machine having support for all the UNIX functionalities.

