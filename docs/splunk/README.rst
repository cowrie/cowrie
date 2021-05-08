How to send Cowrie output to Splunk
###################################

Splunk Output Module
====================

* In Splunk, enable the HTTP Event Collector (go to Settings->Add Data)
* Do not enable `Indexer Acknowledgment`
* Copy the authorization token for later use
* Modify ``cowrie.cfg`` to enable the ``[output_splunk]`` section
* Configure the URL for HTTP Event Collector and add the authorization token you copied in the previous step
* Optionally enable sourcetype, source, host and index settings

File Based
==========

* Collect ``var/log/cowrie/cowrie.json`` output file using Splunk

Reporting
=========

Please see: https://github.com/aplura/Tango
