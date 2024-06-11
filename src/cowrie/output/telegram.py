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
        self.events_logged = CowrieConfig.get("output_telegram", "events_logged")

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

        # Parse event to log list
            
        events_logged_list: list[str] = self.events_logged.replace(' ','').split(",")

        # Prepare base message
        msgtxt = "<strong>[Cowrie " + event["sensor"] + "]</strong>"
        msgtxt += "\nEvent: " + event["eventid"]
        msgtxt += "\nLogon type: " + logon_type
        msgtxt += "\nSource: <code>" + event["src_ip"] + "</code>"
        msgtxt += "\nSession: <code>" + event["session"] + "</code>"

        if event["eventid"] == "cowrie.login.success" and ("login" in events_logged_list):
            msgtxt += "\nUsername: <code>" + event["username"] + "</code>"
            msgtxt += "\nPassword: <code>" + event["password"] + "</code>"
            self.send_message(msgtxt)
        elif event["eventid"] in ["cowrie.command.failed", "cowrie.command.input"] and ("commands" in events_logged_list):
            msgtxt += "\nCommand: <pre>" + event["input"] + "</pre>"
            self.send_message(msgtxt)
        elif event["eventid"] == "cowrie.session.file_download" and ("file_download" in events_logged_list):
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
