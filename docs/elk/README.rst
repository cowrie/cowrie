How to process Cowrie output in an ELK stack
#############################################

(Note: work in progress, instructions are not verified)


Prerequisites
================

* Working Cowrie installation
* Cowrie JSON log file (enable database json in cowrie.cfg)
* Java 8

Installation
================


We'll examine simple installation, when we install ELK stack on the same machine that used for cowrie.

Add Elastic's repository and key::

    wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    apt-get update

Install logstash, elasticsearch and kibana::

     sudo apt-get install elasticsearch logstash kibana

Set them to autostart::

    sudo update-rc.d elasticsearch defaults 95 10
    sudo update-rc.d kibana defaults 95 10

ElasticSearch Configuration
=============================

ElasticSearch configuration file is located in `/etc/elasticsearch/elasticsearch.yml`. The default settings need not be changed.

Kibana Configuration
=============================

Make a folder for logs::

    sudo mkdir /var/log/kibana
    sudo chown kibana:kibana /var/log/kibana

Change the following parameters in `/etc/kibana/kibana.yml` to reflect your server setup::

    "server.host"  - set it to "localhost" if you use nginx for basic authentication or external interface if you use XPack (see below)
    "server.name" - name of the server
    "elasticsearch.url" - address of the elasticsearch: ["http://localhost:9200"]
    "elasticsearch.username", "elasticsearch.password" - needed only if you use XPack (see below)
    "logging.dest" - set path to logs (/var/log/kibana/kibana.log)

Logstash Configuration
=============================

Get GeoIP data from www.maxmind.com (free but requires registration): download the GeoLite2 City GZIP. Unzip it and locate the mmdb file.
Place it somewhere in your filesystem and make sure that "logstash" user can read it::

    sudo mkdir -p /var/opt/logstash/vendor/geoip/
    sudo mv GeoLite2-City.mmdb /var/opt/logstash/vendor/geoip

Configure logstash::

    sudo cp logstash-cowrie.conf /etc/logstash/conf.d

Make sure the configuration file is correct. Check the input section (path), filter (geoip databases) and output (elasticsearch hostname)::

    sudo systemctl restart logstash 

By default the logstash is creating debug logs in /tmp.

To test whether logstash is working correctly, check the file in /tmp::

    tail /tmp/cowrie-logstash.log

To test whether data is loaded into ElasticSearch, run the following query::

    curl 'http://<hostname>:9200/_search?q=cowrie&size=5'

(Replace `<hostname>` with the name or IP address of the machine on which ElasticSearch is running, e.g., `localhost`.)

If this gives output, your data is correctly loaded into ElasticSearch

When you successfully configured logstash, remove "file" and "stdout" blocks from output section of logstash configuration.

Distributed setup of sensors or multiple sensors on the same host
================================================================================

If you have multiple sensors, you will need to setup up FileBeat to feed logstash with logs from all sensors
 
On the logstash server:
 
Change "input" section of the logstash to the following::
 
    input {
       beats {
           port => 5044
	   type => "cowrie"
       }
    }

On the sensor servers:
 
Install filebeat::

    sudo apt-get install filebeat
 
Enable autorun for it::

    sudo update-rc.d filebeat defaults 95 10

Configure filebeat::
 
    sudo cp filebeat-cowrie.conf /etc/filebeat/filebeat.yml

Check the following parameters::

    log input paths - path to cowrie's json logs
    logstash output hosts - check ip of the logstash host
 
Start filebeat::

    sudo systemctl start filebeat

Nginx
==================

ELK has been configured on localhost. If you wish to access it remotely, you can setup a reverse proxy.

Install Nginx::

     sudo apt install nginx apache2-utils
     
Create an administrative Kibana user and password::

      sudo htpasswd -c /etc/nginx/htpasswd.users admin_kibana

Edit Nginx configuration /etc/nginx/sites-available/default

      server {
           listen 80;

           server_name example.com;

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

     sudo systemctl start nginx
     
      
Using Kibana
==================

Create an index pattern (Management / Index Patterns)::

     logstash-*

Use default settings and timestamp.

     
Tuning ELK stack
==================

Refer to elastic's documentation about proper configuration of the system for the best elasticsearch's performance

You may avoid installing nginx for restricting access to kibana by installing official elastic's plugin called "X-Pack" (https://www.elastic.co/products/stack)
