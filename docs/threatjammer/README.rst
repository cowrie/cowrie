How to send Cowrie output to Threat Jammer
##########################################

.. image:: https://threatjammer.com/threatjammer-risk-score.png
    :align: center
    :width: 400
    :height: 200
    :alt: threatjammer.com


Threat Jammer Prerequisites
***************************

* Working Cowrie installation
* A Threat Jammer API Key

Threat Jammer Introduction
**************************

What is Threat Jammer
=====================
`Threat Jammer <https://threatjammer.com>`_ is a service to access high-quality threat intelligence data from a variety of sources and integrate it into their applications with the sole purpose of detecting and blocking malicious activity. This output module feeds the private denylists of Threat Jammer with successful and unsuccessful login attempts thanks to the asynchronous `Reporting API of Threat Jammer <https://threatjammer.com/docs/introduction-threat-jammer-report-api>`_. The user can use the denylists in their own infrastructure firewalls or WAFs, or use it for forensic analysis.

When users feed Threat Jammer with their data using the Reporting API, they increase the chance of finding malicious activity and reducing the false positives. Crowdsourced Intelligence means that our users can report their data to the Threat Jammer system, and Threat Jammer will assess the data and decide whether aggregate the data to the crowdsourced intelligence database. If the data has enough quality and is ready to consume, Threat Jammer will share it with the community.

Anybody can sign up and use the service for free forever. 

Cowrie Configuration for Threat Jammer
**************************************

Quick start
===========
To use the output module the user must `sign up and obtain an API KEY <https://threatjammer.com/docs/threat-jammer-api-keys>`_. The sign-up is free forever. 

Once the developers have obtained an API Key, they have to open the configuration file of cowrie::

    [output_threatjammer]
    enabled = false
    bearer_token = THREATJAMMER_API_TOKEN
    #api_url=https://dublin.report.threatjammer.com/v1/ip
    #track_login = true
    #track_session = false
    #ttl = 86400
    #category = ABUSE
    #tags = COWRIE,LOGIN,SESSION

and edit the section ``[output_threatjammer]`` as follows:

* Change the ``enabled`` parameter to  ``true``.
* Change the ``THREATJAMMER_API_TOKEN`` placeholder with the real API Key of the user in the ``bearer_token`` parameter.

[Re]start Cowrie. If the output module was initialized succeessfully, the user will see the following message in the Cowrie log::

    [-] ThreatJammer.com output plugin successfully initialized. Category=ABUSE. TTL=86400. Session Tracking=False. Login Tracking=True

Other parameters
================
The following parameters can change how the output module works, so use it with caution:

api_url
-------
Points to the server running the Report API. By default it points to the Dublin Region, but more regions will be deployed in the future.

track_login
-----------
Send information about the IP addresses that tried to login successfully or not. By default is  ``true``.

track_session
-------------
Send information about the IP addresses that created a session. By default is ``false``.

ttl
---
Time to Live in seconds of the reported IP addresses in the private denylist in Threat Jammer. When the TTL expires, the IP address will be automatically removed. If the same IP address is reported more than once, the TTL resets. The default value is ``86400``.

category
--------
The category to classify the IP address. By default is ``ABUSE``. See `Platform Datasets <https://threatjammer.com/docs/introduction-threat-jammer-user-api#platform-datasets>`_ for the list of categories.

tags
----
Comma separated list of tags to classify the IP addresses. Must be alphanumeric and uppercase. By default, ``COWRIE,LOGIN,SESSION``.

Rate limits and buffers
=======================
The output module will send the information every 60 seconds or if the buffer of pending IP addresses to send to the Report API is 1000. The first condition will trigger the send action to the Report API server.

There is a limit of 6 hits per minute per API Key. If the limit is reached, the service returns a 429 response code. A single honeypot should never trigger the rate limit.

About the Module
****************
Python and OS versions
======================
The code has passed the tests implemented in the CI workflows, as expected. This module is compatible with versions of Python from v3.7 and up.

The code does not use any library not already present in the project. It uses ``twisted`` extensively to communicate with the server.

The code has been extensively tested with the Docker build files with buster-slim and bullseye-slim provided by the project. It was also tested on an Ubuntu 20.04 with Python 3.8. 

Minimal testing was done using other versions of Python, and no other operating systems were used throughout the tests. This plugin is thus a beta version.
