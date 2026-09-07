# SPDX-FileCopyrightText: 2022 Louren van Garderen <mail@lourenvangarderen.nl>
# SPDX-FileCopyrightText: 2023-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# Simple Telegram Bot logger

from html import escape

import treq
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig


def esc(value: str) -> str:
    """Escape a value for a Telegram message sent with parse_mode=HTML.

    Telegram's HTML mode wants "<", ">" and "&" escaped in text. Quotes are
    left alone: nothing here is interpolated into an attribute, and Telegram
    does not define the numeric entity html.escape would produce for "'".
    """
    return escape(str(value), quote=False)


class Output(cowrie.core.output.Output):
    """
    telegram output
    """

    _log = Logger()

    def start(self):
        self.bot_token = CowrieConfig.get("output_telegram", "bot_token")
        self.chat_id = CowrieConfig.get("output_telegram", "chat_id")

    def stop(self):
        pass

    def write(self, event):
        for i in list(event):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        # Prepare logon type
        # if "HoneyPotSSHTransport" in (event["system"].split(","))[0]:
        #     logon_type = "SSH"
        # elif "CowrieTelnetTransport" in (event["system"].split(","))[0]:
        #     logon_type = "Telnet"
        # else:
        #     logon_type = ""

        # The message is sent with parse_mode=HTML, so every value put into it
        # is escaped: the command, credentials and URL are attacker-controlled,
        # and a literal "<", ">" or "&" would otherwise be read as markup --
        # breaking the message, or rendering markup the attacker chose.
        # Prepare base message
        msgtxt = "<strong>[Cowrie " + esc(event["sensor"]) + "]</strong>"
        msgtxt += "\nEvent: " + esc(event["eventid"])
        # msgtxt += "\nLogon type: " + logon_type
        msgtxt += "\nSource: <code>" + esc(event["src_ip"]) + "</code>"
        msgtxt += "\nSession: <code>" + esc(event["session"]) + "</code>"

        if event["eventid"] == "cowrie.login.success":
            msgtxt += "\nUsername: <code>" + esc(event["username"]) + "</code>"
            msgtxt += "\nPassword: <code>" + esc(event["password"]) + "</code>"
            self.send_message(msgtxt)
        elif event["eventid"] in ["cowrie.command.failed", "cowrie.command.input"]:
            msgtxt += "\nCommand: <pre>" + esc(event["input"]) + "</pre>"
            self.send_message(msgtxt)
        elif event["eventid"] == "cowrie.session.file_download":
            msgtxt += "\nUrl: " + esc(event.get("url", ""))
            self.send_message(msgtxt)

    def send_message(self, message):
        self._log.info("Telegram plugin will try to call TelegramBot")
        # treq.get returns a Deferred; a network failure surfaces there, not as
        # a synchronous exception, so it needs an errback rather than a
        # try/except to avoid an unhandled Deferred error.
        d = treq.get(
            "https://api.telegram.org/bot" + self.bot_token + "/sendMessage",
            params=[
                ("chat_id", str(self.chat_id)),
                ("parse_mode", "HTML"),
                ("text", message),
            ],
            allow_redirects=False,
        )
        d.addErrback(self._request_failed)

    def _request_failed(self, failure):
        self._log.info(
            "Telegram plugin request error: {error}", error=failure.getErrorMessage()
        )
