.. SPDX-FileCopyrightText: 2019-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

.. cowrie documentation master file, created by
   sphinx-quickstart on Sun Dec 30 18:27:51 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Cowrie's documentation!
==================================

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   README.rst
   INSTALL.rst
   FAQ.rst

.. toctree::
   :maxdepth: 2
   :caption: Configuring the honeypot

   HONEYFS.rst
   PROXY.rst
   BACKEND_POOL.rst
   SNAPSHOTS.rst
   LLM.rst

.. toctree::
   :maxdepth: 2
   :caption: Deployment

   docker/README.rst
   systemd/README.rst
   supervisor/README.rst
   squid/README.rst

.. toctree::
   :maxdepth: 2
   :caption: Output integrations

   datadog/README.rst
   elk/README.rst
   graylog/README.rst
   prometheus/README.rst
   sentinel/README.rst
   splunk/README.rst
   sql/README.rst
   virustotal/README.rst

.. toctree::
   :maxdepth: 2
   :caption: Reference

   OUTPUT.rst
   EVENT_PIPELINE.rst

.. toctree::
   :maxdepth: 2
   :caption: Project

   CONTRIBUTING.rst
   CHANGELOG.rst
   LICENSE.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
