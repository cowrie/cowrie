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
This module contains ...
"""

from twisted.python import log

#  cowrie.client.fingerprint
#  cowrie.client.size
#  cowrie.client.var
#  cowrie.client.version
#  cowrie.command.failed
#  cowrie.command.success
#  cowrie.direct-tcpip.data
#  cowrie.direct-tcpip.request
#  cowrie.log.closed
#  cowrie.log.open
#  cowrie.login.failed
#  cowrie.login.success
#  cowrie.session.closed
#  cowrie.session.connect
#  cowrie.session.file_download
#  cowrie.session.file_upload

def formatCef(logentry):
    """
    Take logentry and turn into CEF string
    """
    #  Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
    cefVendor = "Cowrie"
    cefProduct = "Cowrie"
    cefVersion = "1.0"
    cefSignature = logentry["eventid"]
    cefName = logentry["eventid"]
    cefSeverity = "5"

    cefExtensions = {
        'app': 'SSHv2',
        'destinationServicename': 'sshd',
        'deviceExternalId': logentry['sensor'],
        'msg': log.textFromEventDict(logentry),
        'src' : logentry['src_ip'],
        'proto': 'tcp'
    }

    if logentry['eventid'] == 'cowrie.session.connect':
        cefExtensions['spt'] = logentry['src_port']
        cefExtensions['dpt'] = logentry['dst_port']
        cefExtensions['src'] = logentry['src_ip']
        cefExtensions['dst'] = logentry['dst_ip']
    elif logentry['eventid'] == 'cowrie.login.success':
        cefExtensions['duser'] = logentry['username']
        cefExtensions['outcome'] = 'success'
    elif logentry['eventid'] == 'cowrie.login.failed':
        cefExtensions['duser'] = logentry['username']
        cefExtensions['outcome'] = 'failed'
    elif logentry['eventid'] == 'cowrie.file.file_download':
        cefExtensions['filehash'] = logentry['filehash']
        cefExtensions['filePath'] = logentry['filename']
        cefExtensions['fsize'] = logentry['size']
    elif logentry['eventid'] == 'cowrie.file.file_upload':
        cefExtensions['filehash'] = logentry['filehash']
        cefExtensions['filePath'] = logentry['filename']
        cefExtensions['fsize'] = logentry['size']

    # 'out' 'outcome'  request, rt

    cefList = []
    for key in cefExtensions.keys():
        value = str(cefExtensions[key]).replace(' ', '\ ')
        cefList.append(key+"="+value)
    cefExtension = ' '.join(cefList)

    cefString = "CEF:0|" + \
      cefVendor + "|" + \
      cefProduct + "|" + \
      cefVersion + "|" + \
      cefSignature + "|" + \
      cefName + "|" + \
      cefSeverity + "|" + \
      cefExtension

    return cefString

