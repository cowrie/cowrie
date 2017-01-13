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
apt-get install elasticsearch logstash kibana
```

* Set them to autostart
```
update-rc.d elasticsearch defaults 95 10
update-rc.d kibana defaults 95 10
```

## ElasticSearch Configuration

TBD

## Logstash Configuration

* Download GeoIP data

```
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
```

* Place these somewhere in your filesystem and make sure that "logstash" user can read it

* Configure logstash

```
cp logstash-cowrie.conf /etc/logstash/conf.d
```

* Make sure the configuration file is correct. Check the input section (path), filter (geoip databases) and output (elasticsearch hostname)

```
service logstash restart
```

* By default the logstash is creating debug logs in /tmp.

* To test whether logstash is working correctly, check the file in /tmp

```
tail /tmp/cowrie-logstash.log
```

* To test whether data is loaded into ElasticSearch, run the following query:

```
http://<hostname>:9200/_search?q=cowrie&size=5
```

* If this gives output, your data is correctly loaded into ElasticSearch

* When you successfully configured logstash, remove "file" and "stdout" blocks from output section of logstash configuration.

## Tuning ELK stack

* Refer to elastic's documentation about proper configuration of the system for the best elasticsearch's performance

* You may avoid installing nginx for restricting access to the kibana by installing official elastic's plugin called "XPack" 