# Simple Telegram Bot logger

import treq
from twisted.python import log
import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    telegram output
    """

    def start(self):
        self.bot_token = CowrieConfig.get("output_telegram", "bot_token")
        self.chat_id = CowrieConfig.get("output_telegram", "chat_id")

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]

        logon_type = ""
        # Prepare logon type
        if "HoneyPotSSHTransport" in (logentry["system"].split(","))[0]:
            logon_type = "SSH"
        elif "CowrieTelnetTransport" in (logentry["system"].split(","))[0]:
            logon_type = "Telnet"

        # Prepare base message
        msgtxt = "<strong>[Cowrie " + logentry["sensor"] + "]</strong>"
        msgtxt += "\nEvent: " + logentry["eventid"]
        msgtxt += "\nLogon type: " + logon_type
        msgtxt += "\nSource: <code>" + logentry["src_ip"] + "</code>"
        msgtxt += "\nSession: <code>" + logentry["session"] + "</code>"

        if logentry["eventid"] == "cowrie.login.success":
            msgtxt += "\nUsername: <code>" + logentry["username"] + "</code>"
            msgtxt += "\nPassword: <code>" + logentry["password"] + "</code>"
            self.send_message(msgtxt)
        elif logentry["eventid"] in ["cowrie.command.failed", "cowrie.command.input"]:
            msgtxt += "\nCommand: <pre>" + logentry["input"] + "</pre>"
            self.send_message(msgtxt)
        elif logentry["eventid"] == "cowrie.session.file_download":
            msgtxt += "\nUrl: " + logentry.get("url", "")
            self.send_message(msgtxt)

    def send_message(self, message):
        log.msg("Telegram plugin will try to call TelegramBot")
        try:
            treq.get(
                "https://api.telegram.org/bot" + self.bot_token + "/sendMessage",
                params=[
                    ("chat_id", str(self.chat_id)),
                    ("parse_mode", "HTML"),
                    ("text", message),
                ],
            )
        except Exception:
            log.msg("Telegram plugin request error")
