.. SPDX-FileCopyrightText: 2019-2021 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Automatically starting Cowrie with supervisord
#################################################

* Copy the file ``docs/supervisor/cowrie.conf`` to ``/etc/supervisor/conf.d/``

* Edit the copied file: ``command`` must point at the ``cowrie`` script in
  your virtual environment, and ``directory`` at the state directory you
  initialized with ``cowrie init`` (see the supervisord section of
  `the installation guide <https://docs.cowrie.org/en/latest/INSTALL.html>`_).

* Reload supervisord::

    $ sudo supervisorctl reread
    $ sudo supervisorctl update
