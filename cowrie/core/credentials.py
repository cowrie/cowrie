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

from zope.interface import implementer

from twisted.cred.credentials import IUsernamePassword, \
    ICredentials

class IUsername(ICredentials):
    """
    Encapsulate username only

    @type username: C{str}
    @ivar username: The username associated with these credentials.
    """



class IUsernamePasswordIP(IUsernamePassword):
    """
    I encapsulate a username, a plaintext password and a source IP

    @type username: C{str}
    @ivar username: The username associated with these credentials.

    @type password: C{str}
    @ivar password: The password associated with these credentials.

    @type ip: C{str}
    @ivar ip: The source ip address associated with these credentials.
    """



class IPluggableAuthenticationModulesIP(ICredentials):
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """



@implementer(IPluggableAuthenticationModulesIP)
class PluggableAuthenticationModulesIP:
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """

    def __init__(self, username, pamConversion, ip):
        self.username = username
        self.pamConversion = pamConversion
        self.ip = ip



@implementer(IUsername)
class Username:
    """
    """
    def __init__(self, username):
        self.username = username



@implementer(IUsernamePasswordIP)
class UsernamePasswordIP:
    """
    This credential interface also provides an IP address
    """
    def __init__(self, username, password, ip):
        self.username = username
        self.password = password
        self.ip = ip

