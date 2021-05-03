How to send Cowrie output to Azure Sentinel
===========================================

Open your Sentinel worksapce and navigate to `Data connectors` >
`Syslog` > `Open connector page`. Expand `Install agent on a non-Azure
Linux Machine`, the select `Download & install agent for non-Azure
Linux machines`. Select the Linux tab and either copy the shell
script that is presented, or take note of your Workspace ID and
Primary Key and install the agent on your host by hand::

  $ wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh
  $ chmod +x onboard_agent.sh
  $ ./onboard_agent.sh -w <workspace ID> -s <key> -d opinsights.azure.com

Once installed, return to the Syslog connector page and select `Open
your workspace advanced settings configuration`. Select `Data` >
`Custom Logs`. Check `Apply below configuration to my linux machines`
then add a new custom log source: When prompted, upload the ``cowrie.json``
file you downloaded.

The default delimeter is correct (newline).  Specify
``/opt/cowrie/var/log/cowrie/cowrie.json`` as the log collection path.

Name the custom log ``cowrie_JSON``. Sentinel will automatically
append _CL to this name.

It will take a while for this to roll out to the host, but eventually
you'll be able to run the log analytics query cowrie_JSON_CL and
see data coming in.

Take the contents of ``cowrie-parser.txt`` from the ``docs/sentinel`` folder
and paste them into a new log analytics query. Run the query,
then save this off as a function with the name, alias and category
of `Cowrie`.

Once events are being ingested and parsed by Azure Sentinel,
``linux_workbook.json`` can be imported to define a custom workbook to
interact with Cowrie data.
