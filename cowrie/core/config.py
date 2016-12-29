# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import configparser


def readConfigFile(cfgfile):
    config = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation(),
        defaults={
            'empty': '',  # Prevent whitespace from being stripped: 'value: ${empty}' => 'value: '
            '\\n': '\n',  # New line: '${\n}'
            '\\r': '\r',  # Carriage return: '${\r}'
            '\\r\\n': '\r\n',  # CRLF: '${\r\n}'
            't\\r\\n': '\r\r\n',  # CRLF for telnet (see CowrieTelnetTransport.write()): '${t\r\n}'
            ' ': ' ',  # A single space character: '${ }'
            '\\t': '\t',  # Tab escape: '${\t}'
            '\t': '\t',  # Literal tab character: '${	}'
        })
    config.read(cfgfile)
    return config

