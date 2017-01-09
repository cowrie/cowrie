# How to process Cowrie output in an ELK stack

(Note: work in progress, instructions are not verified)


## Prerequisites

* Working Cowrie installation
* Cowrie JSON log file (enable database json in cowrie.cfg)

## Installation

* Install logstash, elasticsearch and kibana

```
apt-get install logstash
apt-get install elasticsearch
````

* Install Kibana

This may be different depending on your operating system. Kibana will need additional components such as a web server


## ElasticSearch Configuration

TBD

## Logstash Configuration

* Download GeoIP data

```
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
```

* Place these somewhere in your filesystem.

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

## How to process old logs

* A lot of people have trouble to send previously generated logs into Logstash. 

Refer to [this](https://github.com/auyer/TCP-Log-Sender-logstash) GitHub project to a very simple Python program that sends the Logs line-by-line over TCP to a Local Logstash:
[github.com/auyer/TCP-Log-Sender-logstash](https://github.com/auyer/TCP-Log-Sender-logstash)
