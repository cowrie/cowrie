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

