How to send Cowrie output to an ELK stack
#########################################

ElasticSearch Prerequisites
===========================

* Working Cowrie installation
* Cowrie JSON log file (enable ``output_json`` in ``cowrie.cfg``)
* Java 8

ElasticSearch Installation
==========================

This is a simple setup for ELK stack, to be done on the same machine that is used for cowrie. We use *Filebeat* to send logs to *Logstash*, and we use *Nginx* as a reverse proxy to access *Kibana*. Note there are many other possible configurations!

Add Elastic's repository and key::

    $ wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    $ echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    $ apt-get update

Install logstash, elasticsearch, kibana and filebeat::

     $ sudo apt -y install apt-transport-https wget default-jre
     $ sudo apt install elasticsearch logstash kibana
     $ sudo apt install filebeat
     $ sudo apt install nginx apache2-utils

Enable the services::

     $ sudo systemctl enable elasticsearch logstash kibana filebeat nginx


ElasticSearch Configuration
===========================

ElasticSearch configuration file is located in ``/etc/elasticsearch/elasticsearch.yml``. The default settings need not be changed.

If you are only operating a single ElasticSearch node, you can add the following configuration item::

   discovery.type: single-node

By default, ElasticSearch listens on port 9200. Test it::

   curl http://localhost:9200

You should get a JSON object in return.


Kibana Configuration
====================

Make a folder for logs::

    $ sudo mkdir /var/log/kibana
    $ sudo chown kibana:kibana /var/log/kibana

Change the following parameters in ``/etc/kibana/kibana.yml`` to reflect your server setup:

    * ``server.host``  - set it to `localhost` if you use nginx for basic authentication or external interface if you use XPack (see below)
    * ``server.name`` - name of the server
    * ``elasticsearch.hosts`` - address of the elasticsearch: ["http://localhost:9200"]
    * ``elasticsearch.username`` - only needed only if you use XPack (see below)
    * ``elasticsearch.password`` - only needed only if you use XPack (see below)
    * ``logging.dest`` - set path to logs (`/var/log/kibana/kibana.log`)

Logstash Configuration
======================

Get GeoIP data from www.maxmind.com (free but requires registration): download the GeoLite2 City GZIP. Unzip it and locate the mmdb file.
Place it somewhere in your filesystem and make sure that "logstash" user can read it::

    $ sudo mkdir -p /opt/logstash/vendor/geoip/
    $ sudo mv GeoLite2-City.mmdb /opt/logstash/vendor/geoip

Configure logstash::

    $ sudo cp logstash-cowrie.conf /etc/logstash/conf.d

Make sure the configuration file is correct. Check the input section (path), filter (geoip databases) and output (elasticsearch hostname)::

    $ sudo systemctl restart logstash


FileBeat Configuration
======================

FileBeat is not mandatory (it is possible to directly read Cowrie logs from Logstash) but nice to have, because if Logstash is under pressure, it automatically knows to slow down + it is possible to deal with multiple sensor inputs.

Configure filebeat::

    $ sudo cp filebeat-cowrie.conf /etc/filebeat/filebeat.yml

Check the following parameters::

    filebeat.inputs: the path must point to cowrie's json logs
    output.elasticsearch: must be false because we want Filebeat to send to Logstash, not directly to ElasticSearch
    output.logstash: must be true. The default port for Logstash is 5044, so hosts should be ["localhost:5044"]


Start filebeat::

    $ sudo systemctl start filebeat

Nginx
==================

ELK has been configured on localhost. If you wish to access it remotely, you can setup a reverse proxy to Kibana's backend server, which runs on port 5601 by default.

Install Nginx::

     $ sudo apt install nginx apache2-utils

Create an administrative Kibana user and password::

     $ sudo htpasswd -c /etc/nginx/htpasswd.users admin_kibana

Edit Nginx configuration /etc/nginx/sites-available/default. Customize port to what you like, and specify your server's name (or IP address)::

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
==================

You can list indexes with::

     $ curl 'http://localhost:9200/_cat/indices?v'

You should see a Cowrie index cowrie-logstash-DATE... Its health is yellow because the number of replicas should be set to 0 (unless you want another configuration)::

     $ curl -XPUT 'localhost:9200/cowrie-logstash-REPLACEHERE/_settings' -H "Content-Type: application/json" -d '{ "index" : {"number_of_replicas" : 0 } }'

It should answer {"acknowledged":true}

In Kibana's GUI, create an index pattern (Management / Index Patterns) for ::

     cowrie-logstash-*

Use default settings and timestamp.


Tuning ELK stack
==================

Refer to Elastic's documentation about proper configuration of the system for the best ElasticSearch's performance

You may avoid installing nginx for restricting access to Kibana by installing official Elastic's plugin called "X-Pack" (https://www.elastic.co/products/stack)

ELK log files get big: ensure you have enough space in /var, consider setting up LVM or ZFS partitions.

ElasticSearch Troubleshooting
=============================

- View service logs with:  ``sudo journalctl -u service``
- If the date in Kibana is incorrect, check (Advanced Settings / dateFormat)
