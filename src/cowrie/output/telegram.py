# Simple Telegram Bot logger

from __future__ import absolute_import, division

import treq
from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

class Output(cowrie.core.output.Output):
    """
    telegram output
    """

    def start(self):
        self.bot_id = CowrieConfig().get('output_telegram', 'bot_id') 
        self.chat_id = CowrieConfig().get('output_telegram', 'chat_id') 

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        if "cowrie.login" in logentry['eventid']:
            msgtxt = "[Cowrie] " # + logentry['timestamp']
            msgtxt += "  " + logentry['message']
            msgtxt += "  (session " + logentry['session'] + ")"

            log.msg("Telegram plugin will try to call TelegramBot")
            try:
                resp = treq.get('https://api.telegram.org/bot' + self.bot_id + '/sendMessage',
                                       params=[('chat_id', str(self.chat_id)), ('text', msgtxt)])
#                content = resp.text()
            except (defer.CancelledError, error.ConnectingCancelledError, error.DNSLookupError):
                log.msg("Telegram plugin request timeout")
