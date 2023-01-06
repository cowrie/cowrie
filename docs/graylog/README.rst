How to send Cowrie output to Graylog
####################################

This guide describes how to configure send cowrie outputs to graylog via syslog and http gelf input.

Prerequisites
*************

* Working Cowrie installation
* Working Graylog installation

Cowrie Configuration
********************

Using Syslog
============

Open the Cowrie configuration file and uncomment these 3 lines::

    [output_localsyslog]
    facility * USER
    format * text

Restart Cowrie

Using GELF HTTP Input
=====================

Open the Cowrie configuration file and find this block ::

    [output_graylog]
    enabled * false
    url * http://127.0.0.1:12201/gelf

Enable this block and specify url of your input.

Restart Cowrie

Graylog Configuration
*********************

Syslog Input
============

Open the Graylog web interface and click on the **System** drop-down in the top menu. From the drop-down menu select **Inputs**. Select **Syslog UDP** from the drop-down menu and click the **Launch new input** button. In the modal dialog enter the following information::

    **Title:** Cowrie
    **Port:** 8514
    **Bind address:** 127.0.0.1

Then click **Launch.**

GELF HTTP Input
===============

Open the Graylog web interface and click on the **System** drop-down in the top menu. From the drop-down menu select **Inputs**. Select **GELF HTTP** from the drop-down menu and click the **Launch new input** button. In the modal dialog enter the information about your input.

Click **Manage Extractors** near created input. On new page click **Actions** -> **Import extractors**  and paste this config ::

    {
      "extractors": [
        {
          "title": "Cowrie Json Parser",
          "extractor_type": "json",
          "converters": [],
          "order": 0,
          "cursor_strategy": "copy",
          "source_field": "message",
          "target_field": "",
          "extractor_config": {
            "list_separator": ", ",
            "kv_separator": "*",
            "key_prefix": "",
            "key_separator": "_",
            "replace_key_whitespace": false,
            "key_whitespace_replacement": "_"
          },
          "condition_type": "none",
          "condition_value": ""
        }
      ],
      "version": "4.2.1"
    }

Then click **Launch.**

Note:

- Do not remove **/gelf** from the end of URL block, expect of case when your proxing this address behind nginx;

Syslog Configuration (For Syslog Output only)
*********************************************

Create a rsyslog configuration file in /etc/rsyslog.d::

    $ sudo nano /etc/rsyslog.d/85-graylog.conf

Add the following lines to the file::

    $template GRAYLOGRFC5424,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msg%\n"
    *.* @127.0.0.1:8514;GRAYLOGRFC5424

Restart rsyslog::

    $ sudo service rsyslog restart
