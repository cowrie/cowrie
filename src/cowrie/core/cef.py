from __future__ import absolute_import, division


def formatCef(logentry):
    """
    Take logentry and turn into CEF string
    """
    # Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|
    # Device Version|Signature ID|Name|Severity|[Extension]
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
        'msg': logentry['message'],
        'src': logentry['src_ip'],
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
    for key in list(cefExtensions.keys()):
        value = str(cefExtensions[key])
        cefList.append('{}={}'.format(key, value))

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
