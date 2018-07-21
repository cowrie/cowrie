# How to process Cowrie output with Splunk

## Sending data

### Splunk Output Module

* In Splunk, enable the HTTP Event Collector (go to Settings->Add Data)
* Do not enable `Indexer Acknowledgment`
* Copy the authorization token for later use
* Modify `cowrie.cfg` to enable the `[splunk]` section
* Add URL to HTTP Event Collector and add the authorization token
* Optionally enable sourcetype, source, host and index settings

### File Based

* Collect cowrie.json output file using Splunk

## Reporting

Please see: https://github.com/aplura/Tango
