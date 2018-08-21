from __future__ import absolute_import, division

import json
import time

from slackclient import SlackClient

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):
        self.slack_channel = CONFIG.get('output_slack', 'channel')
        self.slack_token = CONFIG.get('output_slack', 'token')
        cowrie.core.output.Output.__init__(self)

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        self.sc = SlackClient(self.slack_token)
        self.sc.api_call(
            "chat.postMessage",
            channel=self.slack_channel,
            text="%s %s" % (time.strftime('%Y-%m-%d %H:%M:%S'), json.dumps(logentry, indent=4, sort_keys=True))
        )
