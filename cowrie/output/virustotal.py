# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
Send SSH logins to Virustotal
Work in Progress - not functional yet
"""

from zope.interface import implementer

import json
import os
import urllib
import urlparse

from twisted.python import log
from twisted.web.iweb import IBodyProducer
from twisted.internet import defer, reactor
from twisted.web import client, http_headers
from twisted.internet.ssl import ClientContextFactory

import cowrie.core.output


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self, cfg):
        self.apiKey = cfg.get('output_virustotal', 'api_key')
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        Start output plugin
        """
        pass


    def stop(self):
        """
        Stop output plugin
        """
        pass


    def write(self, entry):
        """
        """
        if entry["eventid"] == 'cowrie.session.file_download':
            log.msg("Sending url to VT")
            self.posturl(entry["url"])

            log.msg("Sending file to VT")
            p = urlparse.urlparse(entry["url"]).path
            if p == "":
                fileName = entry["shasum"]
            else:
                b = os.path.basename(p)
                if b == "":
                    fileName = entry["shasum"]
                else:
                    fileName = b
            self.postfile(entry["outfile"], fileName)

        elif entry["eventid"] == 'cowrie.session.file_upload':
            log.msg("Sending file to VT")
            self.postfile(entry["outfile"], entry["filename"])


    def postfile(self, artifact, fileName):
        """
        Send a file to VirusTotal
        """
        vtUrl = "https://www.virustotal.com/vtapi/v2/file/scan"
        contextFactory = WebClientContextFactory()
        fields = {('apikey', self.apiKey)}
        files = {('file', fileName, open(artifact, 'rb'))}
        contentType, body = encode_multipart_formdata(fields, files)
        producer = StringProducer(body)
        headers = http_headers.Headers({
            'User-Agent': ['Cowrie SSH Honeypot'],
            'Accept': ['*/*'],
            'Content-Type': [contentType]
        })

        agent = client.Agent(reactor, contextFactory)
        d = agent.request('POST', vtUrl, headers, producer)

        def cbBody(body):
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: %s %s" % (response.code, response.phrase,))
                return


        def cbError(failure):
            failure.printTraceback()


        def processResult(result):
            log.msg( "VT postfile result: %s" % result)
            j = json.loads(result)
            #log.msg( "VT postfile result: %s", repr(j) )
            if j["response_code"] == 0:
                log.msg( "response=0: posting comment")
                d = self.postcomment(j["resource"])
                return d


        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


    def posturl(self, scanUrl):
        """
        Send a URL to VirusTotal with Twisted

        response_code:
        If the item you searched for was not present in VirusTotal's dataset this result will be 0.
        If the requested item is still queued for analysis it will be -2.
        If the item was indeed present and it could be retrieved it will be 1.
        """
        vtUrl = "https://www.virustotal.com/vtapi/v2/url/scan"
        headers = http_headers.Headers({'User-Agent': ['Cowrie SSH Honeypot']})
        fields = {"apikey": self.apiKey, "url": scanUrl}
        data = urllib.urlencode(fields)
        body = StringProducer(data)
        contextFactory = WebClientContextFactory()

        agent = client.Agent(reactor, contextFactory)
        d = agent.request('POST', vtUrl, headers, body)

        def cbBody(body):
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            #failure.printTraceback()
            return processResult(failure.value.response)


        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: %s %s" % (response.code, response.phrase,))
                return


        def cbError(failure):
            failure.printTraceback()


        def processResult(result):
            j = json.loads(result)
            log.msg( "VT posturl result: %s", repr(j) )
            if j["response_code"] == 0:
                log.msg( "response=0: posting comment")
                d = self.postcomment(j["resource"])
                return d


        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def postcomment(self, resource):
        """
        Send a comment to VirusTotal with Twisted
        """
        vtUrl = "https://www.virustotal.com/vtapi/v2/comments/put"
        parameters = { "resource": resource,
                       "comment": "First seen by Cowrie SSH honeypot http://github.com/micheloosterhof/cowrie",
                       "apikey": self.apiKey}
        headers = http_headers.Headers({'User-Agent': ['Cowrie SSH Honeypot']})
        data = urllib.urlencode(parameters)
        body = StringProducer(data)
        contextFactory = WebClientContextFactory()

        agent = client.Agent(reactor, contextFactory)
        d = agent.request('POST', vtUrl, headers, body)

        def cbBody(body):
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: %s %s" % (response.code, response.phrase,))
                return


        def cbError(failure):
            failure.printTraceback()


        def processResult(result):
            j = json.loads(result)
            log.msg( "VT postcomment result: %s", repr(j) )
            return j["response_code"]

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)



@implementer(IBodyProducer)
class StringProducer(object):

    def __init__(self, body):
        self.body = body
        self.length = len(body)


    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)


    def pauseProducing(self):
        pass


    def stopProducing(self):
        pass


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTPS instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: application/octet-stream')
        L.append('')
        L.append(value.read())
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


