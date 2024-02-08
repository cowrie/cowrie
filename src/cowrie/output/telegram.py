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

    def write(self, event):
        for i in list(event.keys()):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        logon_type = ""
        # Prepare logon type
        if "HoneyPotSSHTransport" in (event["system"].split(","))[0]:
            logon_type = "SSH"
        elif "CowrieTelnetTransport" in (event["system"].split(","))[0]:
            logon_type = "Telnet"

        # Prepare base message
        msgtxt = "<strong>[Cowrie " + event["sensor"] + "]</strong>"
        msgtxt += "\nEvent: " + event["eventid"]
        msgtxt += "\nLogon type: " + logon_type
        msgtxt += "\nSource: <code>" + event["src_ip"] + "</code>"
        msgtxt += "\nSession: <code>" + event["session"] + "</code>"

        if event["eventid"] == "cowrie.login.success":
            msgtxt += "\nUsername: <code>" + event["username"] + "</code>"
            msgtxt += "\nPassword: <code>" + event["password"] + "</code>"
            self.send_message(msgtxt)
        elif event["eventid"] in ["cowrie.command.failed", "cowrie.command.input"]:
            msgtxt += "\nCommand: <pre>" + event["input"] + "</pre>"
            self.send_message(msgtxt)
        elif event["eventid"] == "cowrie.session.file_download":
            msgtxt += "\nUrl: " + event.get("url", "")
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
