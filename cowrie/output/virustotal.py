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

import json
import re
import urllib
import urllib2

from twisted.python import log

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


    def postfile(self, scanFile):
        """
        Send a file to VirusTotal
        """
        vtHost = "www.virustotal.com"
        vtUrl = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", self.apiKey)]
        file_to_send = open("test.txt", "rb").read()
        files = [("file", "test.txt", file_to_send)]
        response_data = postfile.post_multipart(vtHost, vtUrl, fields, files)
        j = json.loads(response_data)
        log.msg( "Sent file to VT: %s" % (j,) )


    def posturl(self, scanUrl):
        """
        Send a URL to VirusTotal

        response_code: if the item you searched for was not present in VirusTotal's dataset this result will be 0.
        If the requested item is still queued for analysis it will be -2.
        If the item was indeed present and it could be retrieved it will be 1.
        """
        vtUrl = "https://www.virustotal.com/vtapi/v2/url/scan"
        fields = {"apikey": self.apiKey, "url": scanUrl}
        data = urllib.urlencode(fields)
        req = urllib2.Request(vtUrl, data)
        response = urllib2.urlopen(req)
        response_data = response.read()
        j = json.loads(response_data)
        log.msg( "Sent URL to VT: %s" % (j,) )
        return j["response_code"]


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
