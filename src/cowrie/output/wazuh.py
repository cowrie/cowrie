##############################
# Made by 4nt1 at Securejump #
##############################

import json
from io import BytesIO
from datetime import datetime

from twisted.internet import reactor, ssl
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, FileBodyProducer, readBody
from twisted.web.http_headers import Headers
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer

import cowrie.core.output
from cowrie.core.config import CowrieConfig
from twisted.python import log

def json_serializer(obj):
    if hasattr(obj, "name"):
        return obj.name
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, "__dict__"):
        return str(obj)
    else:
        return str(obj)

def json_content(response):
    def cb_body(body):
        return json.loads(body.decode("utf-8"))
    
    d = readBody(response)
    d.addCallback(cb_body)
    return d

class Output(cowrie.core.output.Output):

    def start(self):
        contextFactory = WhitelistContextFactory()
        self.auth_url = CowrieConfig.get("output_wazuh", "auth_url").encode("utf8")
        self.event_url = CowrieConfig.get("output_wazuh", "event_url").encode("utf8")
        self.username = CowrieConfig.get("output_wazuh", "username", fallback=None)
        self.password = CowrieConfig.get("output_wazuh", "password", fallback=None)
        self.agent = Agent(reactor, contextFactory)

    def stop(self):
        pass

    def write(self, event):
        cleaned_event = self.clean_event_data(event)
        event_json_string = json.dumps(cleaned_event, default=json_serializer)
        wazuh_entry = {
            "events": [event_json_string]
        }
        self.postentry(wazuh_entry)
    
    def clean_event_data(self, data):
        if isinstance(data, dict):
            return {k: self.clean_event_data(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return [self.clean_event_data(item) for item in data]
        elif hasattr(data, "name"):
            return data.name
        elif isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, bytes):
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()
        elif hasattr(data, "__dict__"):
            return str(data)
        else:
            return data

    def makeBasic(self):
        import base64
        return base64.b64encode(f"{self.username}:{self.password}".encode()).decode("utf-8")

    @inlineCallbacks
    def authenticate(self):
        headers = Headers(
            {
                b"User-Agent": [b"Cowrie Wazuh Agent"],
                b"Authorization": [b"Basic " + self.makeBasic().encode("utf-8")],
                b"Content-Type": [b"application/json"]
            }
        )
        response = yield self.agent.request(b"POST", self.auth_url, headers)
        result = yield json_content(response)
        returnValue(result)

    @inlineCallbacks
    def postentry(self, entry):
        try:
            token_response = yield self.authenticate()
            
            headers = Headers(
                {
                    b"User-Agent": [b"Cowrie Wazuh Agent"],
                    b"Authorization": [b"Bearer " + token_response["data"]["token"].encode("utf-8")],
                    b"Content-Type": [b"application/json"]
                }
            )
            
            json_data = json.dumps(entry, default=json_serializer)
            body = FileBodyProducer(BytesIO(json_data.encode("utf8")))
            response = yield self.agent.request(b"POST", self.event_url, headers, body)
            
            if response.code == 200:
                log.msg("Wazuh: Event sent successfully")
            else:
                log.msg(f"Wazuh: Request failed with status {response.code}")
            
        except Exception as e:
            log.msg(f"Wazuh: Error sending event: {e}")

@implementer(IPolicyForHTTPS)
class WhitelistContextFactory:
    def creatorForNetloc(self, hostname, port):
        return ssl.CertificateOptions(verify=False)
