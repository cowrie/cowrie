# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
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

from twisted.python import log

from cowrie.ssh_proxy.protocols import base_protocol


class SFTP(base_protocol.BaseProtocol):
    prevID = ''
    ID = ''
    handle = ''
    path = ''
    command = ''
    payloadSize = 0
    payloadOffset = 0
    theFile = ''

    packetLayout = {
        1: 'SSH_FXP_INIT',
        # ['uint32', 'version'], [['string', 'extension_name'], ['string', 'extension_data']]]
        2: 'SSH_FXP_VERSION',
        # [['uint32', 'version'], [['string', 'extension_name'], ['string', 'extension_data']]]
        3: 'SSH_FXP_OPEN',
        # [['uint32', 'id'], ['string', 'filename'], ['uint32', 'pflags'], ['ATTRS', 'attrs']]
        4: 'SSH_FXP_CLOSE',  # [['uint32', 'id'], ['string', 'handle']]
        5: 'SSH_FXP_READ',  # [['uint32', 'id'], ['string', 'handle'], ['uint64', 'offset'], ['uint32', 'len']]
        6: 'SSH_FXP_WRITE',
        # [['uint32', 'id'], ['string', 'handle'], ['uint64', 'offset'], ['string', 'data']]
        7: 'SSH_FXP_LSTAT',  # [['uint32', 'id'], ['string', 'path']]
        8: 'SSH_FXP_FSTAT',  # [['uint32', 'id'], ['string', 'handle']]
        9: 'SSH_FXP_SETSTAT',  # [['uint32', 'id'], ['string', 'path'], ['ATTRS', 'attrs']]
        10: 'SSH_FXP_FSETSTAT',  # [['uint32', 'id'], ['string', 'handle'], ['ATTRS', 'attrs']]
        11: 'SSH_FXP_OPENDIR',  # [['uint32', 'id'], ['string', 'path']]
        12: 'SSH_FXP_READDIR',  # [['uint32', 'id'], ['string', 'handle']]
        13: 'SSH_FXP_REMOVE',  # [['uint32', 'id'], ['string', 'filename']]
        14: 'SSH_FXP_MKDIR',  # [['uint32', 'id'], ['string', 'path'], ['ATTRS', 'attrs']]
        15: 'SSH_FXP_RMDIR',  # [['uint32', 'id'], ['string', 'path']]
        16: 'SSH_FXP_REALPATH',  # [['uint32', 'id'], ['string', 'path']]
        17: 'SSH_FXP_STAT',  # [['uint32', 'id'], ['string', 'path']]
        18: 'SSH_FXP_RENAME',  # [['uint32', 'id'], ['string', 'oldpath'], ['string', 'newpath']]
        19: 'SSH_FXP_READLINK',  # [['uint32', 'id'], ['string', 'path']]
        20: 'SSH_FXP_SYMLINK',  # [['uint32', 'id'], ['string', 'linkpath'], ['string', 'targetpath']]
        101: 'SSH_FXP_STATUS',
        # [['uint32', 'id'], ['uint32', 'error_code'], ['string', 'error_message'], ['string', 'language']]
        102: 'SSH_FXP_HANDLE',  # [['uint32', 'id'], ['string', 'handle']]
        103: 'SSH_FXP_DATA',  # [['uint32', 'id'], ['string', 'data']]
        104: 'SSH_FXP_NAME',
        # [['uint32', 'id'], ['uint32', 'count'], [['string', 'filename'], ['string', 'longname'], ['ATTRS', 'attrs']]]
        105: 'SSH_FXP_ATTRS',  # [['uint32', 'id'], ['ATTRS', 'attrs']]
        200: 'SSH_FXP_EXTENDED',  # []
        201: 'SSH_FXP_EXTENDED_REPLY'  # []
    }

    def __init__(self, uuid, chan_name, ssh):
        super(SFTP, self).__init__(uuid, chan_name, ssh)

        self.clientPacket = base_protocol.BaseProtocol()
        self.serverPacket = base_protocol.BaseProtocol()

        self.parent = None
        self.parentPacket = None
        self.offset = 0

    def parse_packet(self, parent, payload):
        self.parent = parent

        if parent == '[SERVER]':
            self.parentPacket = self.serverPacket
        elif parent == '[CLIENT]':
            self.parentPacket = self.clientPacket

        if self.parentPacket.packetSize == 0:
            self.parentPacket.packetSize = int(payload[:4].hex(), 16) - len(payload[4:])
            payload = payload[4:]
            self.parentPacket.data = payload
            payload = ''

        else:
            if len(payload) > self.parentPacket.packetSize:
                self.parentPacket.data = self.parentPacket.data + payload[:self.parentPacket.packetSize]
                payload = payload[self.parentPacket.packetSize:]
                self.parentPacket.packetSize = 0
            else:
                self.parentPacket.packetSize -= len(payload)
                self.parentPacket.data = self.parentPacket.data + payload
                payload = ''

        if self.parentPacket.packetSize == 0:
            self.handle_packet(parent)

        if len(payload) != 0:
            self.parse_packet(parent, payload)

    def handle_packet(self, parent):
        self.packetSize = self.parentPacket.packetSize
        self.data = self.parentPacket.data

        sftp_num = self.extract_int(1)
        packet = self.packetLayout[sftp_num]

        self.prevID = self.ID
        self.ID = self.extract_int(4)

        if packet == 'SSH_FXP_OPENDIR':
            self.path = self.extract_string()

        elif packet == 'SSH_FXP_REALPATH':
            self.path = self.extract_string()
            self.command = b'cd ' + self.path
            log.msg(parent + '[SFTP] Entered Command: ' + self.command.decode())

        elif packet == 'SSH_FXP_OPEN':
            self.path = self.extract_string()
            pflags = '{0:08b}'.format(self.extract_int(4))

            if pflags[6] == '1':
                self.command = b'put ' + self.path
                self.theFile = ''
                # self.out.download_started(self.uuid, self.path)
            elif pflags[7] == '1':
                self.command = b'get ' + self.path
            else:
                # Unknown PFlag
                log.msg(parent + '[SFTP] New SFTP pflag detected: %s %s' %
                        (pflags, self.data))

            log.msg(parent + ' [SFTP] Entered Command: ' + self.command.decode())

        elif packet == 'SSH_FXP_READ':
            pass

        elif packet == 'SSH_FXP_WRITE':
            if self.handle == self.extract_string():
                self.offset = self.extract_int(8)
                self.theFile = self.theFile[:self.offset].encode() + self.extract_data()

        elif packet == 'SSH_FXP_HANDLE':
            if self.ID == self.prevID:
                self.handle = self.extract_string()

        elif packet == 'SSH_FXP_READDIR':
            if self.handle == self.extract_string():
                self.command = b'ls ' + self.path

        elif packet == 'SSH_FXP_SETSTAT':
            self.path = self.extract_string()
            self.command = self.extract_attrs() + ' ' + self.path

        elif packet == 'SSH_FXP_EXTENDED':
            cmd = self.extract_string()
            self.path = self.extract_string()

            if cmd == 'statvfs@openssh.com':
                self.command = b'df ' + self.path
            elif cmd == 'hardlink@openssh.com':
                self.command = b'ln ' + self.path + b' ' + self.extract_string()
            elif cmd == 'posix-rename@openssh.com':
                self.command = b'mv ' + self.path + b' ' + self.extract_string()
            else:
                # UNKNOWN COMMAND
                log.msg(parent + '[SFTP] New SFTP Extended Command detected: %s %s' %
                        (cmd, self.data))

        elif packet == 'SSH_FXP_EXTENDED_REPLY':
            log.msg(parent + '[SFTP] Entered Command: ' + self.command.decode())
            # self.out.command_entered(self.uuid, self.command)

        elif packet == 'SSH_FXP_CLOSE':
            if self.handle == self.extract_string():
                if b'get' in self.command:
                    log.msg(parent + ' [SFTP] Finished Downloading: ' + self.path.decode())
                elif b'put' in self.command:
                    log.msg(parent + ' [SFTP] Finished Uploading: ' + self.path.decode())

                    # if self.out.cfg.getboolean(['download', 'passive']):
                    #     # self.out.make_downloads_folder()
                    #     outfile = self.out.downloadFolder + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")\
                    #     + "-" + self.path.split('/')[-1]
                    #     f = open(outfile, 'wb')
                    #     f.write(self.theFile)
                    #     f.close()
                    #     #self.out.file_downloaded((self.uuid, True, self.path, outfile, None))

        elif packet == 'SSH_FXP_SYMLINK':
            self.command = b'ln -s ' + self.extract_string() + b' ' + self.extract_string()

        elif packet == 'SSH_FXP_MKDIR':
            self.command = b'mkdir ' + self.extract_string()

        elif packet == 'SSH_FXP_REMOVE':
            self.command = b'rm ' + self.extract_string()

        elif packet == 'SSH_FXP_RMDIR':
            self.command = b'rmdir ' + self.extract_string()

        elif packet == 'SSH_FXP_STATUS':
            if self.ID == self.prevID:
                code = self.extract_int(4)
                if code in [0, 1]:
                    if b'get' not in self.command and b'put' not in self.command:
                        log.msg(parent + ' [SFTP] Entered Command: ' + self.command.decode())
                else:
                    message = self.extract_string()
                    log.msg(parent + ' [SFTP] Failed Command: ' + self.command.decode() + ' Reason: ' + message)

    def extract_attrs(self):
        cmd = ''
        flags = '{0:08b}'.format(self.extract_int(4))

        if flags[5] == '1':
            perms = '{0:09b}'.format(self.extract_int(4))
            # log.msg(log.LPURPLE, self.parent + '[SFTP]', 'PERMS:' + perms)
            chmod = str(int(perms[:3], 2)) + str(int(perms[3:6], 2)) + str(int(perms[6:], 2))
            cmd = 'chmod ' + chmod
        elif flags[6] == '1':
            user = str(self.extract_int(4))
            group = str(self.extract_int(4))
            cmd = 'chown ' + user + ':' + group
        else:
            pass
            # Unknown attribute
            # log.msg(log.LRED, self.parent + '[SFTP]',
            #         'New SFTP Attribute detected - Please raise a HonSSH issue on github with the details: %s %s' %
            #         (flags, self.data))
        return cmd


'''
CLIENT                              SERVER

    SSH_FXP_INIT    -->
                    <--    SSH_FXP_VERSION

    SSH_FXP_OPEN    -->
                    <--    SSH_FXP_HANDLE (or SSH_FXP_STATUS if fail)

    SSH_FXP_READ    -->
                    <--    SSH_FXP_DATA (or SSH_FXP_STATUS if fail)

    SSH_FXP_WRITE   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_REMOVE  -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_RENAME  -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_MKDIR   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_RMDIR   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_OPENDIR -->
                    <--    SSH_FXP_HANDLE (or SSH_FXP_STATUS if fail)

    SSH_FXP_READDIR -->
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_STAT    -->         //Follows symlinks
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_LSTAT    -->         //Does not follow symlinks
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_FSTAT    -->         //Works on an open file/handle not a file path like (L)STAT
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_SETSTAT -->          //Sets file attributes on path
                    <--    SSH_FXP_STATUS

    SSH_FXP_FSETSTAT-->          //Sets file attributes on a handle
                    <--    SSH_FXP_STATUS

    SSH_FXP_READLINK -->        //Used to find the target of a symlink
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_SYMLINK  -->        //Used to create a symlink
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_REALPATH -->          //Relative path
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_CLOSE   -->                     //Closes handle not session
                    <--    SSH_FXP_STATUS
'''
