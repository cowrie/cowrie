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

from __future__ import division, absolute_import

from zope.interface import implementer

import json
import os

try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urllib import urlencode
    from urlparse import urlparse

from twisted.python import log
from twisted.web.iweb import IBodyProducer
from twisted.internet import defer, reactor
from twisted.web import client, http_headers
from twisted.internet.ssl import ClientContextFactory

import cowrie.core.output

COWRIE_USER_AGENT = 'Cowrie Honeypot'
VTAPI_URL = b'https://www.virustotal.com/vtapi/v2/'
COMMENT = "First seen by #Cowrie SSH/telnet Honeypot http://github.com/micheloosterhof/cowrie"

class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self, cfg):
        self.apiKey = cfg.get('output_virustotal', 'api_key')
        self.debug = cfg.getboolean('output_virustotal', 'debug', fallback=False)
        self.upload = cfg.getboolean('output_virustotal', 'upload', fallback=True)
        self.comment = cfg.getboolean('output_virustotal', 'comment', fallback=True)
        self.commenttext = cfg.get('output_virustotal', 'commenttext', fallback=COMMENT)
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        Start output plugin
        """
        self.agent = client.Agent(reactor, WebClientContextFactory())


    def stop(self):
        """
        Stop output plugin
        """
        pass


    def write(self, entry):
        """
        """
        if entry["eventid"] == 'cowrie.session.file_download':
            #TODO: RENABLE
            #log.msg("Sending url to VT")
            #self.scanurl(entry["url"])

            log.msg("Checking scan report at VT")
            self.scanfile(entry)

        elif entry["eventid"] == 'cowrie.session.file_upload':
            log.msg("Checking scan report at VT")
            self.scanfile(entry["shasum"])

            #log.msg("Sending file to VT")
            #self.postfile(entry["outfile"], entry["filename"])


    def scanfile(self, entry):
        """
        Check file scan report for a hash
        Argument is full event so we can access full file later on
        """
        vtUrl = VTAPI_URL+b'file/report'
        headers = http_headers.Headers({'User-Agent': [COWRIE_USER_AGENT]})
        fields = {'apikey': self.apiKey, 'resource': entry["shasum"]}
        body = StringProducer(urlencode(fields).encode("utf-8"))
        d = self.agent.request(b'POST', vtUrl, headers, body)

        def cbResponse(response):
            """
            Main response callback, check HTTP response code
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                #d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: {} {}".format(response.code, response.phrase))
                return


        def cbBody(body):
            """
            Received body
            """
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbError(failure):
            log.msg("VT: Error in scanfile")
            failure.printTraceback()


        def processResult(result):
            """
            Extract the information we need from the body
            """
            if self.debug:
                log.msg("VT scanfile result: {}".format(result))
            j = json.loads(result)
            log.msg("VT: {}".format(j["verbose_msg"]))
            if j["response_code"] == 0:
                log.msg("VT: response=0: this is a new file")
                p = urlparse(entry["url"]).path
                if p == "":
                    fileName = entry["shasum"]
                else:
                    b = os.path.basename(p)
                    if b == "":
                        fileName = entry["shasum"]
                    else:
                        fileName = b
                if self.upload == True:
                    return self.postfile(entry["outfile"], fileName)
                else:
                    return
            elif j["response_code"] == 1:
                log.msg("VT: response=1: this has been scanned before")
                log.msg("VT: {}/{} bad; permalink: {}".format(j["positives"], j["total"], j["permalink"]))
            elif j["response_code"] == -2:
                log.msg("VT: response=1: this has been queued for analysis already")
                log.msg("VT: permalink: {}".format(j["permalink"]))
            else:
                log.msg("VT: unexpected response code".format(j["response_code"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


    def postfile(self, artifact, fileName):
        """
        Send a file to VirusTotal
        """
        vtUrl = VTAPI_URL+b'file/scan'
        fields = {('apikey', self.apiKey)}
        files = {('file', fileName, open(artifact, 'rb'))}
        if self.debug:
            log.msg("submitting to VT: "+repr(files))
        contentType, body = encode_multipart_formdata(fields, files)
        producer = StringProducer(body)
        headers = http_headers.Headers({
            'User-Agent': [COWRIE_USER_AGENT],
            'Accept': ['*/*'],
            'Content-Type': [contentType]
        })

        d = self.agent.request(b'POST', vtUrl, headers, producer)

        def cbBody(body):
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbResponse(response):
            """
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: {} {}".format(response.code, response.phrase))
                return


        def cbError(failure):
            """
            """
            failure.printTraceback()


        def processResult(result):
            """
            """
            if self.debug:
                log.msg("VT postfile result: {}".format(result))
            j = json.loads(result)
            # This is always a new resource, since we did the scan before
            # so always create the comment
            log.msg( "response=0: posting comment")
            if self.comment == True:
                return self.postcomment(j["resource"])
            else:
                return

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


    def scanurl(self, url):
        """
        Check url scan report for a hash
        """
        vtUrl = VTAPI_URL+b'url/report'
        headers = http_headers.Headers({'User-Agent': [COWRIE_USER_AGENT]})
        fields = {'apikey': self.apiKey, 'resource': url, 'scan': 1}
        body = StringProducer(urlencode(fields).encode("utf-8"))
        d = self.agent.request(b'POST', vtUrl, headers, body)

        def cbResponse(response):
            """
            Main response callback, checks HTTP response code
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                #d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: {} {}".format(response.code, response.phrase))
                return


        def cbBody(body):
            """
            Received body
            """
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbError(failure):
            log.msg("cbError")
            failure.printTraceback()


        def processResult(result):
            """
            Extract the information we need from the body
            """
            j = json.loads(result)
            # log.msg("VT scanurl result: {}".format(repr(j)))
            log.msg("VT: {}".format(j["verbose_msg"]))
            if j["response_code"] == 0:
                log.msg("VT: response=0: this is a new file")
                return d
            elif j["response_code"] == 1:
                log.msg("VT: response=1: this has been scanned before")
                log.msg("VT: {}/{} bad".format(j["positives"], j["total"]))
                log.msg("VT: permalink: {}".format(j["permalink"]))
            elif j["response_code"] == -2:
                log.msg("VT: response=1: this has been queued for analysis already")
                log.msg("VT: permalink: {}".format(j["permalink"]))
            else:
                log.msg("VT: unexpected response code".format(j["response_code"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


    def postcomment(self, resource):
        """
        Send a comment to VirusTotal with Twisted
        """
        vtUrl = VTAPI_URL+b'comments/put'
        parameters = { "resource": resource,
                       "comment": self.commenttext,
                       "apikey": self.apiKey}
        headers = http_headers.Headers({'User-Agent': [COWRIE_USER_AGENT]})
        body = StringProducer(urlencode(parameters).encode("utf-8"))
        d = self.agent.request(b'POST', vtUrl, headers, body)

        def cbBody(body):
            """
            """
            return processResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)


        def cbResponse(response):
            """
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg("VT Request failed: {} {}".format(response.code, response.phrase))
                return


        def cbError(failure):
            """
            """
            failure.printTraceback()


        def processResult(result):
            """
            """
            if self.debug:
                log.msg("VT postcomment result: {}".format(result))
            j = json.loads(result)
            return j["response_code"]

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d



class WebClientContextFactory(ClientContextFactory):
    """
    """
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)



@implementer(IBodyProducer)
class StringProducer(object):
    """
    """

    def __init__(self, body):
        self.body = body
        self.length = len(body)


    def startProducing(self, consumer):
        """
        """
        consumer.write(self.body)
        return defer.succeed(None)


    def pauseProducing(self):
        """
        """
        pass


    def stopProducing(self):
        """
        """
        pass



def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTPS instance
    """
    BOUNDARY = b'----------ThIs_Is_tHe_bouNdaRY_$'
    L = []
    for (key, value) in fields:
        L.append(b'--' + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%s"' % key.encode())
        L.append(b'')
        L.append(value.encode())
    for (key, filename, value) in files:
        L.append(b'--' + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%s"; filename="%s"' % (key.encode(), filename.encode()))
        L.append(b'Content-Type: application/octet-stream')
        L.append(b'')
        L.append(value.read())
    L.append(b'--' + BOUNDARY + b'--')
    L.append(b'')
    body = b'\r\n'.join(L)
    content_type = b'multipart/form-data; boundary=%s' % BOUNDARY

    return content_type, body


