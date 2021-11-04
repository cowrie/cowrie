How to send Cowrie output to Graylog via syslog
####################################


Prerequisites
======================

* Working Cowrie installation
* Working Graylog installation

Cowrie Configuration
======================

Open the Cowrie configuration file and uncomment these 3 lines::

    [output_localsyslog]
    facility = USER
    format = text

Restart Cowrie

Graylog Configuration
======================

Open the Graylog web interface and click on the **System** drop-down in the top menu. From the drop-down menu select **Inputs**. Select **Syslog UDP** from the drop-down menu and click the **Launch new input** button. In the modal dialog enter the following information::

    **Title:** Cowrie
    **Port:** 8514
    **Bind address:** 127.0.0.1

Then click **Launch.**

Syslog Configuration
======================

Create a rsyslog configuration file in /etc/rsyslog.d::

    $ sudo nano /etc/rsyslog.d/85-graylog.conf

Add the following lines to the file::

    $template GRAYLOGRFC5424,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msg%\n"
    *.* @127.0.0.1:8514;GRAYLOGRFC5424

Restart rsyslog::

    $ sudo service rsyslog restart

How to send Cowrie output to Graylog via HTTP GELF input
####################################


Prerequisites
======================

* Working Cowrie installation
* Working Graylog installation
* Working HTTP Gelf Input on Graylog

Cowrie Configuration
======================

Open the Cowrie configuration file and find this block ::

    [output_graylog_gelf]
    enabled = false
    url = http://127.0.0.1:12201/gelf
    tls = False
    cert =
    key =

Enable this block and specify url of your input.
If you need tls - change status to True and specify path to your tls cert and key.

Restart Cowrie

Graylog Configuration
======================

Open the Graylog web interface and click on the **System** drop-down in the top menu. From the drop-down menu select **Inputs**. Select **GELF HTTP** from the drop-down menu and click the **Launch new input** button. In the modal dialog enter the information about your input.

Then click **Launch.**

Note:

- If TLS is enabled - in URL block you must specify **https://**

- Do not remove **/gelf** from the end of URL block, expect of case when your proxing this address behind nginx;