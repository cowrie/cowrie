# How to process Cowrie output in an ELK stack

(Note: work in progress, instructions are not verified)


## Prerequisites

* Working Cowrie installation
* Cowrie JSON log file (enable database json in cowrie.cfg)
* Java 8

## Installation


We'll examine simple installation, when we install ELK stack on the same machine that used for cowrie.

* Add Elastic's repository and key
```
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
apt-get update
```

* Install logstash, elasticsearch and kibana

```
sudo apt-get install elasticsearch logstash kibana
```

* Set them to autostart
```
sudo update-rc.d elasticsearch defaults 95 10
sudo update-rc.d kibana defaults 95 10
```

## ElasticSearch Configuration

TBD

## Kibana Configuration

* Make a folder for logs

```
sudo mkdir /var/log/kibana
sudo chown kibana:kibana /var/log/kibana
```

* Change the following parameters in `/etc/kibana/kibana.yml` to reflect your server setup:

```
"server.host"  - set it to "localhost" if you use nginx for basic authentication or external interface if you use XPack (see below)
"server.name" - name of the server
"elasticsearch.url" - address of the elasticsearch
"elasticsearch.username", "elasticsearch.password" - needed only if you use XPack (see below)
"logging.dest" - set path to logs (/var/log/kibana/kibana.log)
```

* Make sure the file `/etc/kibana/kibana.yml` contains a line like

```
tilemap.url: https://tiles.elastic.co/v2/default/{z}/{x}/{y}.png?elastic_tile_service_tos=agree&my_app_name=kibana
```
or your map visualizations won't have any background. When this file is created during the installation
of Kibana, it does _not_ contain such a line, not even in commented out form.

## Logstash Configuration

* Download GeoIP data

```
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
```

* Place these somewhere in your filesystem and make sure that "logstash" user can read it

```
sudo mkdir -p /var/opt/logstash/vendor/geoip/
sudo mv GeoLite2-City.mmdb /var/opt/logstash/vendor/geoip
```

* Configure logstash

```
sudo cp logstash-cowrie.conf /etc/logstash/conf.d
```

* Make sure the configuration file is correct. Check the input section (path), filter (geoip databases) and output (elasticsearch hostname)

```
sudo service logstash restart
```

* By default the logstash is creating debug logs in /tmp.

* To test whether logstash is working correctly, check the file in /tmp

```
tail /tmp/cowrie-logstash.log
```

* To test whether data is loaded into ElasticSearch, run the following query:

```
curl 'http://<hostname>:9200/_search?q=cowrie&size=5'
```

(Replace `<hostname>` with the name or IP address of the machine on which ElasticSearch is running, e.g., `localhost`.)

* If this gives output, your data is correctly loaded into ElasticSearch

* When you successfully configured logstash, remove "file" and "stdout" blocks from output section of logstash configuration.

## Distributed setup of sensors or multiple sensors on the same host

 If you have multiple sensors, you will need to setup up FileBeat to feed logstash with logs from all sensors
 
 On the logstash server:
 
 * Change "input" section of the logstash to the following:
 
 ```
 input {
    beats {
        port => 5044
    }
 }
 ```
 
 On the sensor servers:
 
 * Install filebeat
 ```
 wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
 echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
 sudo apt-get update
 sudo apt-get install filebeat
 ```
 
 * Enable autorun for it
 ```
 sudo update-rc.d filebeat defaults 95 10
 ```

 * Configure filebeat
 
 ```
 sudo cp filebeat-cowrie.conf /etc/filebeat/filebeat.yml
 ```

 * Check the following parameters
 ```
 paths - path to cowrie's json logs
 logstash - check ip of the logstash host
 ```
 
 * Start filebeat
 
 ```
 sudo service filebeat start
 ``` 

## Tuning ELK stack

* Refer to elastic's documentation about proper configuration of the system for the best elasticsearch's performance

* You may avoid installing nginx for restricting access to kibana by installing official elastic's plugin called "X-Pack" (https://www.elastic.co/products/x-pack) 