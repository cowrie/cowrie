.. SPDX-FileCopyrightText: 2019-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

How to send Cowrie output to an ELK stack
#########################################

This guide sets up a single-machine Elastic Stack 8.x (Elasticsearch,
Logstash, Kibana) on the host that runs Cowrie. *Filebeat* ships Cowrie's
JSON log to *Logstash*, and *Nginx* acts as a reverse proxy in front of
*Kibana*. Many other arrangements are possible.

The Elastic packages bundle their own Java runtime; you do not need to
install Java separately.

ELK Prerequisites
=================

* Working Cowrie installation
* Cowrie JSON log file (enabled by default, ``var/log/cowrie/cowrie.json``)
* Several GB of free RAM; Elasticsearch alone wants 1 GB+ of heap

Installing the Elastic Stack
============================

Add Elastic's package repository and key::

    $ sudo apt install curl gpg ca-certificates apt-transport-https
    $ curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    $ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
    $ sudo apt update

Install Elasticsearch, Logstash, Kibana, Filebeat and Nginx::

    $ sudo apt install elasticsearch logstash kibana filebeat
    $ sudo apt install nginx apache2-utils

Enable the services::

    $ sudo systemctl enable elasticsearch logstash kibana filebeat nginx

**Save the password.** Installing the ``elasticsearch`` package prints a
generated password for the built-in ``elastic`` superuser. You will need it
for Logstash and for the command-line checks below. If you lost it, reset
it with::

    $ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

ElasticSearch Configuration
===========================

The Elasticsearch configuration file is ``/etc/elasticsearch/elasticsearch.yml``.
For a single-node setup, add::

    discovery.type: single-node

and remove any generated ``cluster.initial_master_nodes`` line, then start
the service::

    $ sudo systemctl start elasticsearch

Elasticsearch 8 enables TLS and authentication by default; it listens on
port 9200 over HTTPS with a self-signed certificate authority in
``/etc/elasticsearch/certs/http_ca.crt``. Test it::

    $ curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200

Enter the ``elastic`` password when prompted; you should get a JSON object
in return.

Kibana Configuration
====================

Kibana enrolls itself with Elasticsearch using an enrollment token.
Generate one and hand it to Kibana::

    $ sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
    $ sudo /usr/share/kibana/bin/kibana-setup --enrollment-token '<paste token here>'

In ``/etc/kibana/kibana.yml``, set:

    * ``server.host`` - keep it at ``localhost`` when Nginx provides
      authentication (below); set an external interface only if you expose
      Kibana directly
    * ``server.name`` - a display name for this Kibana instance

Then start Kibana::

    $ sudo systemctl start kibana

Logstash Configuration
======================

Copy the example pipeline from ``docs/elk/`` and the Elasticsearch CA
certificate::

    $ sudo cp logstash-cowrie.conf /etc/logstash/conf.d/
    $ sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/http_ca.crt
    $ sudo chown logstash:logstash /etc/logstash/http_ca.crt

Edit ``/etc/logstash/conf.d/logstash-cowrie.conf`` and set the ``password``
(and ``ssl_certificate_authorities`` path if you copied the CA elsewhere)
in the ``elasticsearch`` output section.

GeoIP lookups need no separate download: Logstash ships with MaxMind
GeoLite2 databases and keeps them updated automatically.

Start Logstash::

    $ sudo systemctl start logstash

FileBeat Configuration
======================

Filebeat is not mandatory (Logstash can read Cowrie's log file directly),
but it is nice to have: it backs off automatically when Logstash is under
pressure, and it makes it easy to feed multiple sensors into one stack.

Copy the example configuration::

    $ sudo cp filebeat-cowrie.conf /etc/filebeat/filebeat.yml

Check the following parameters:

    * ``filebeat.inputs`` - the path must point to Cowrie's JSON log
    * ``output.logstash`` - Logstash listens on port 5044 by default

Start Filebeat::

    $ sudo systemctl start filebeat

Nginx
=====

Kibana listens on localhost port 5601. To reach it remotely, set up a
reverse proxy with basic authentication.

Create an administrative Kibana user and password::

    $ sudo htpasswd -c /etc/nginx/htpasswd.users admin_kibana

Edit the Nginx configuration ``/etc/nginx/sites-available/default``.
Customize the port to what you like, and specify your server's name (or IP
address)::

    server {
         listen YOURPORT;

         server_name YOURIPADDRESS;

         auth_basic "Restricted Access";
         auth_basic_user_file /etc/nginx/htpasswd.users;

         location / {
               proxy_pass http://localhost:5601;
               proxy_http_version 1.1;
               proxy_set_header Upgrade $http_upgrade;
               proxy_set_header Connection 'upgrade';
               proxy_set_header Host $host;
               proxy_cache_bypass $http_upgrade;
         }
    }

Start the service::

    $ sudo systemctl start nginx

Using Kibana
============

Once events flow, list the indices::

    $ curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic 'https://localhost:9200/_cat/indices?v'

You should see a ``cowrie-logstash-DATE`` index. On a single node its
health shows yellow until the number of replicas is set to 0::

    $ curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic -XPUT 'https://localhost:9200/cowrie-logstash-REPLACEHERE/_settings' -H "Content-Type: application/json" -d '{ "index" : {"number_of_replicas" : 0 } }'

It should answer ``{"acknowledged":true}``.

In Kibana, create a data view (Stack Management / Data Views) for::

    cowrie-logstash-*

Use the default settings and the ``@timestamp`` field.

Tuning the ELK stack
====================

Refer to Elastic's documentation for sizing and performance tuning.

ELK log files get big: ensure you have enough space in ``/var``, and
consider index lifecycle management to expire old indices.

ElasticSearch Troubleshooting
=============================

- View service logs with ``sudo journalctl -u elasticsearch`` (or
  ``logstash``, ``kibana``, ``filebeat``)
- Test the Logstash pipeline syntax with
  ``sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t``
- If the date in Kibana is incorrect, check (Advanced Settings /
  dateFormat)
