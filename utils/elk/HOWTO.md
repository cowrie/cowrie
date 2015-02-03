How to process Kippo output in an ELK stack
===========================================

(Note: work in progress, instructions are not verified)

* Install logstash, elasticsearch and kibana

    apt-get install logstash
    apt-get install elasticsearch
    apt-get install kibana

* Download GeoIP data

    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz

* Place these somewhere in your filesystem.

* Configure logstash

    cp logstash-kippo.conf /etc/logstash/conf.d
    service logstash restart

* By default the logstash is creating debug logs in /tmp.

* To test whether logstash is working correctly, check the file in /tmp

    tail /tmp/kippo-logstash.log

* To test whether data is loaded into ElasticSearch, run the following query:

    http://<hostname>:9200/_search?q=kippo&size=5

