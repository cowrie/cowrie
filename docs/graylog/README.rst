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

Open the Cowrie configuration file and enable localsyslog output::

    [output_localsyslog]
    enabled = true
    facility = USER
    format = text

Restart Cowrie

Using GELF HTTP Input
=====================

Open the Cowrie configuration file and find this block ::

    [output_graylog]
    enabled = false
    url = http://127.0.0.1:12201/gelf

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

Then click **Launch.**

Note:

- Do not remove **/gelf** from the end of URL block, expect of case when your proxing this address behind nginx;

Parsing Cowrie JSON
===================

Extractor
---------
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

Pipeline
--------
When running Graylog with the Forwarder input, traditional extractors are not available. Instead, you can use a pipeline rule to parse the JSON data.

Create a Stream and add the Cowrie logs to it.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Streams** -> **Create Stream** -> **Title:** Cowrie -> **Description:** Cowrie logs -> **Create Stream**

Create a Stream Rule for the Cowrie Stream.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Streams** -> **Cowrie** -> **Manage Rules** -> **Add Stream Rule** -> **Type:** `match input` **Input:** `Cowrie (GELF HTTP)` -> **Save**

Create a Pipeline Rule for the Cowrie Stream.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**System** -> **Pipelines** -> **Manage rules** -> **Create Rule** -> **Use Source Code Editor**

Paste the following code into the Rule source::

    rule "Parse Cowrie message"
    when
      has_field("message")
    then
      // If you want to keep the original message, uncomment the following line and comment out the next line.
      //let json_string = regex_replace("\"message\"", to_string($message.message), "\"cowrie_message\"");
      let json_string = to_string($message.message);
      let json = parse_json(json_string);
      let map = to_map(json);
      set_fields(map);
    end

Create a Pipeline for the Cowrie Stream.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**System** -> **Pipelines** -> **Manage pipelines** -> **Add new pipeline** -> **Title:** `Parse Cowrie logs` -> **Description:** Cowrie logs -> **Create Pipeline**

Under the **Pipeline connections** section, connect the Cowrie Stream to the Pipeline by clicking the **Edit connections** button and selecting the Cowrie Stream.

Under Pipeline Stages, edit Stage 0 and add the Pipeline Rule to the Stage.

Syslog Configuration (For Syslog Output only)
*********************************************

Create a rsyslog configuration file in /etc/rsyslog.d::

    $ sudo nano /etc/rsyslog.d/85-graylog.conf

Add the following lines to the file::

    $template GRAYLOGRFC5424,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msg%\n"
    *.* @127.0.0.1:8514;GRAYLOGRFC5424

Restart rsyslog::

    $ sudo service rsyslog restart
