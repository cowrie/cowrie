
"""
Output plugin for HPFeeds

"""

from __future__ import division, absolute_import
import json
import logging

from hpfeeds.twisted import ClientSessionService
from twisted.internet import reactor, ssl, protocol, endpoints
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """
    Output plugin for HPFeeds
    """

    channel = 'cowrie.sessions'

    def start(self):
        """
        """
        log.msg("WARNING: Beta version of new hpfeeds enabled. This will become hpfeeds in a future release.")

        if CONFIG.has_option('output_hpfeeds', 'channel'):
            self.channel = CONFIG.get('output_hpfeeds', 'channel')

        if CONFIG.has_option('output_hpfeeds', 'endpoint'):
            endpoint = CONFIG.get('output_hpfeeds', 'endpoint')
        else:
            server = CONFIG.get('output_hpfeeds', 'server')
            port = CONFIG.getint('output_hpfeeds', 'port')

            if CONFIG.has_option('output_hpfeeds', 'tlscert'):
                with open(CONFIG.get('output_hpfeeds', 'tlscert')) as fp:
                    authority = ssl.Certificate.loadPEM(fp.read())
                options = ssl.optionsForClientTLS(server, authority)
                endpoint = endpoints.SSL4ClientEndpoint(reactor, server, port, options)
            else:
                endpoint = endpoints.HostnameEndpoint(reactor, server, port)

        ident = CONFIG.get('output_hpfeeds', 'identifier')
        secret = CONFIG.get('output_hpfeeds', 'secret')

        self.meta = {}

        self.client = ClientSessionService(endpoint, ident, secret)
        self.client.startService()

    def stop(self):
        """
        """
        self.client.stopService()


    def write(self, entry):
        """
        """
        session = entry["session"]
        if entry["eventid"] == 'cowrie.session.connect':
            self.meta[session] = {'session':session,
                'startTime': entry["timestamp"], 'endTime':'',
                'peerIP': entry["src_ip"], 'peerPort': entry["src_port"],
                'hostIP': entry["dst_ip"], 'hostPort': entry["dst_port"],
                'loggedin': None, 'credentials':[], 'commands':[],
                'unknownCommands':[], 'urls':[], 'version': None,
                'ttylog': None, 'hashes': set(), 'protocol': entry['protocol']}

        elif entry["eventid"] == 'cowrie.login.success':
            u, p = entry['username'], entry['password']
            self.meta[session]['loggedin'] = (u, p)

        elif entry["eventid"] == 'cowrie.login.failed':
            u, p = entry['username'], entry['password']
            self.meta[session]['credentials'].append((u, p))

        elif entry["eventid"] == 'cowrie.command.input':
            c = entry['input']
            self.meta[session]['commands'].append(c)

        elif entry["eventid"] == 'cowrie.command.failed':
            uc = entry['input']
            self.meta[session]['unknownCommands'].append(uc)

        elif entry["eventid"] == 'cowrie.session.file_download':
            url = entry['url']
            self.meta[session]['urls'].append(url)
            self.meta[session]['hashes'].add(entry['shasum'])

        elif entry["eventid"] == 'cowrie.session.file_upload':
            self.meta[session]['hashes'].add(entry['shasum'])

        elif entry["eventid"] == 'cowrie.client.version':
            v = entry['version']
            self.meta[session]['version'] = v

        elif entry["eventid"] == 'cowrie.log.closed':
            # entry["ttylog"]
            with open(entry["ttylog"]) as ttylog:
                self.meta[session]['ttylog'] = ttylog.read().encode('hex')

        elif entry["eventid"] == 'cowrie.session.closed':
            meta = self.meta.pop(session, None)
            if meta:
                log.msg('publishing metadata to hpfeeds', logLevel=logging.DEBUG)
                meta['endTime'] = entry["timestamp"]
                meta['hashes'] = list(meta['hashes'])
                self.client.publish(self.channel, json.dumps(meta).encode('utf-8'))
