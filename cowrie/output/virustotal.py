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
import re
import urllib
import warnings
import urllib2

from twisted.python import log
from twisted.web.iweb import IBodyProducer
from twisted.internet import abstract, defer, reactor, protocol
from twisted.web import client, http_headers, iweb
from twisted.internet.ssl import ClientContextFactory

from twisted.web.error import SchemeNotSupported
from twisted.web._newclient import Request, Response, HTTP11ClientProtocol
from twisted.web._newclient import ResponseDone, ResponseFailed
from twisted.web._newclient import PotentialDataLoss

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
        if entry["eventid"] == 'COW0007':
            log.msg("Sending url to VT")
            if self.posturl(entry["url"]) == 0:
                log.msg("Not seen before by VT")
                self.postcomment(entry["url"])

        elif entry["eventid"] == 'COW0017':
            log.msg("Sending SFTP file to VT")
            if self.postfile(entry["outfile"], entry["filename"]) == 0:
                log.msg("Not seen before by VT")
                self.postcomment(entry["url"])


#    def postfile(self, artifact, fileName):
#        """
#        Send a file to VirusTotal
#        """
#        vtUrl = "https://www.virustotal.com/vtapi/v2/file/scan"
#        fields = [("apikey", self.apiKey)]
#        files = {'file': (fileName, open(artifact, 'rb'))}
#
#        agent = agent.request('POST', vtUrl, None, None)
#
#        def cbResponse(ignored):
#            print 'Response received'
#            d.addCallback(cbResponse)
#
#        r = requests.post(vtUrl, files=files, data=fields)
#        # if r.status_code != 200 # error
#        j = r.json()
#        log.msg( "Sent file to VT: %s" % (j,) )
#        return j["response_code"]
#
#        #contentType = "multipart/form-data; boundary={}".format(boundary)
#        #headers.setRawHeaders("Content-Type", [contentType])
#        #headers.setRawHeaders("Content-Length", [len(body)])


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
            return logResult(body)


        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial 
            """
            return logResult(failure.value.response)


        def cbResponse(response):
            # print 'Response code:', response.code
            # FIXME: Check for 200
            d = readBody(response)
            d.addCallback(cbBody)
            d.addErrback(cbPartial)
            return d


        def cbError(failure):
            failure.printTraceback()


        def logResult(result):
            j = json.loads(result)
            log.msg( "VT result: %s", repr(j) )
            return j["response_code"]
            
        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


    def postcomment(self, resource):
        """
        Send a comment to VirusTotal
        """
        url = "https://www.virustotal.com/vtapi/v2/comments/put"
        parameters = { "resource": resource,
                       "comment": "Captured by Cowrie SSH honeypot http://github.com/cowrie/cowrie",
                       "apikey": self.apiKey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        response_data = response.read()
        j = json.loads(response_data)
        log.msg( "Updated comment for %s to VT: %s" % (resource, j,) )



class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)



class _ReadBodyProtocol(protocol.Protocol):
    """
    Protocol that collects data sent to it.

    This is a helper for L{IResponse.deliverBody}, which collects the body and
    fires a deferred with it.

    @ivar deferred: See L{__init__}.
    @ivar status: See L{__init__}.
    @ivar message: See L{__init__}.

    @ivar dataBuffer: list of byte-strings received
    @type dataBuffer: L{list} of L{bytes}
    """

    def __init__(self, status, message, deferred):
        """
        @param status: Status of L{IResponse}
        @ivar status: L{int}

        @param message: Message of L{IResponse}
        @type message: L{bytes}

        @param deferred: deferred to fire when response is complete
        @type deferred: L{Deferred} firing with L{bytes}
        """
        self.deferred = deferred
        self.status = status
        self.message = message
        self.dataBuffer = []


    def dataReceived(self, data):
        """
        Accumulate some more bytes from the response.
        """
        self.dataBuffer.append(data)


    def connectionLost(self, reason):
        """
        Deliver the accumulated response bytes to the waiting L{Deferred}, if
        the response body has been completely received without error.
        """
        if reason.check(ResponseDone):
            self.deferred.callback(b''.join(self.dataBuffer))
        elif reason.check(PotentialDataLoss):
            self.deferred.errback(
                client.PartialDownloadError(self.status, self.message,
                                     b''.join(self.dataBuffer)))
        else:
            self.deferred.errback(reason)



def readBody(response):
    """
    Get the body of an L{IResponse} and return it as a byte string.

    This is a helper function for clients that don't want to incrementally
    receive the body of an HTTP response.

    @param response: The HTTP response for which the body will be read.
    @type response: L{IResponse} provider

    @return: A L{Deferred} which will fire with the body of the response.
        Cancelling it will close the connection to the server immediately.
    """
    def cancel(deferred):
        """
        Cancel a L{readBody} call, close the connection to the HTTP server
        immediately, if it is still open.

        @param deferred: The cancelled L{defer.Deferred}.
        """
        abort = getAbort()
        if abort is not None:
            abort()

    d = defer.Deferred(cancel)
    protocol = _ReadBodyProtocol(response.code, response.phrase, d)
    def getAbort():
        return getattr(protocol.transport, 'abortConnection', None)

    response.deliverBody(protocol)

    if protocol.transport is not None and getAbort() is None:
        warnings.warn(
            'Using readBody with a transport that does not have an '
            'abortConnection method',
            category=DeprecationWarning,
            stacklevel=2)

    return d



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

"""
def get_report(resource, filename, dl_url='unknown', honeypot=None, origin=None):

    apikey = config().get('virustotal', 'apikey')
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": resource,
                  "apikey":   apikey }

    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    j = simplejson.loads(json)

    if j['response_code'] == 1: # file known
        cfg = config()
        args = {'shasum': resource, 'url': dl_url, 'permalink': j['permalink']}

        # we don't use dispatcher, so this check is needed
        if cfg.has_section('database_mysql'):
            mysql_logger = cowrie.output.mysql.DBLogger(cfg)
            mysql_logger.handleVirustotal(args)
            args_scan = {'shasum': resource, 'json': json}
            mysql_logger.handleVirustotalScan(args_scan)

        if origin == 'db':
            # we don't use dispatcher, so this check is needed
            if cfg.has_section('database_textlog'):
                text_logger = cowrie.output.textlog.DBLogger(cfg)
                text_logger.handleVirustotalLog('log_from database', args)
        else:
            msg = 'Virustotal report of %s [%s] at %s' % \
                (resource, dl_url, j['permalink'])
            # we need to print msg, because logs from SFTP are dispatched this way
            print msg
            if honeypot:
                honeypot.logDispatch(msg)

    elif j['response_code'] == 0: # file not known
        if origin == 'db':
            return j['response_code']

        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
        host = "www.virustotal.com"
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", apikey)]
        filepath = "dl/%s" % resource
        file_to_send = open(filepath, "rb").read()
        files = [("file", filename, file_to_send)]
        json = postfile.post_multipart(host, url, fields, files)
        print json

        msg = 'insert to Virustotal backlog %s [%s]' % \
            (resource, dl_url)
        print msg
        virustotal_backlogs.insert(resource, dl_url)
    else:
        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
    return j['response_code']

"""
