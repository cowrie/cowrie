#

from __future__ import division, absolute_import

import time
import re
import tftpy
import os

from cowrie.shell.honeypot import HoneyPotCommand
from cowrie.shell.fs import *
from cowrie.shell.customparser import CustomParser
from cowrie.shell.customparser import OptionNotFound
from cowrie.shell.customparser import ExitException

"""
"""

commands = {}


class Progress(object):
    """
    """
    def __init__(self, protocol):
        self.progress = 0
        self.out = protocol


    def progresshook(self, pkt):
        """
        """
        if isinstance(pkt, tftpy.TftpPacketDAT):
            self.progress += len(pkt.data)
            self.out.write("Transferred %d bytes" % self.progress + "\n")
        elif isinstance(pkt, tftpy.TftpPacketOACK):
            self.out.write("Received OACK, options are: %s" % pkt.options + "\n")



class command_tftp(HoneyPotCommand):
    """
    """

    port = 69
    hostname = None
    file_to_get = None

    def makeTftpRetrieval(self):
        """
        """
        progresshook = Progress(self).progresshook
        cfg = self.protocol.cfg

        if cfg.has_option('honeypot', 'download_limit_size'):
            self.limit_size = int(cfg.get('honeypot', 'download_limit_size'))

        self.download_path = cfg.get('honeypot', 'download_path')

        tmp_fname = '%s_%s_%s_%s' % \
                    (time.strftime('%Y%m%d%H%M%S'),
                     self.protocol.getProtoTransport().transportId,
                     self.protocol.terminal.transport.session.id,
                     re.sub('[^A-Za-z0-9]', '_', self.file_to_get))
        self.safeoutfile = os.path.join(self.download_path, tmp_fname)

        tclient = None

        try:
            tclient = tftpy.TftpClient(self.hostname, int(self.port))
            tclient.download(self.file_to_get, self.safeoutfile, progresshook)

            url = 'tftp://%s/%s' % (self.hostname, self.file_to_get.strip('/'))

            self.file_to_get = self.fs.resolve_path(self.file_to_get, self.protocol.cwd)

            if hasattr(tclient.context, 'metrics'):
                self.fs.mkfile(self.file_to_get, 0, 0, tclient.context.metrics.bytes, 33188)
            else:
                self.fs.mkfile(self.file_to_get, 0, 0, 0, 33188)

        except tftpy.TftpException as err:
            if tclient and tclient.context and not tclient.context.fileobj.closed:
                tclient.context.fileobj.close()

        if os.path.exists(self.safeoutfile):

            if os.path.getsize(self.safeoutfile) == 0:
                os.remove(self.safeoutfile)
                self.safeoutfile = None
                return

            with open(self.safeoutfile, 'rb') as f:
                shasum = hashlib.sha256(f.read()).hexdigest()
                hash_path = os.path.join(self.download_path, shasum)

            # If we have content already, delete temp file
            if not os.path.exists(hash_path):
                os.rename(self.safeoutfile, hash_path)
            else:
                os.remove(self.safeoutfile)
                log.msg("Not storing duplicate content " + shasum)

            self.protocol.logDispatch(eventid='cowrie.session.file_download',
                                      format='Downloaded tftpFile (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                                      url=url,
                                      outfile=hash_path,
                                      shasum=shasum)

            # Link friendly name to hash
            # os.symlink(shasum, self.safeoutfile)

            self.safeoutfile = None

            # Update the honeyfs to point to downloaded file
            self.fs.update_realfile(self.fs.getfile(self.file_to_get), hash_path)
            self.fs.chown(self.file_to_get, self.protocol.user.uid, self.protocol.user.gid)
            self.exit()


    def start(self):
        """
        """
        parser = CustomParser(self)
        parser.prog = "tftp"
        parser.add_argument("hostname", nargs='?', default=None)
        parser.add_argument("-c", nargs=2)
        parser.add_argument("-l")
        parser.add_argument("-g")
        parser.add_argument("-p")
        parser.add_argument("-r")

        try:
            args = parser.parse_args(self.args)
            if args.c:
                if len(args.c) > 1:
                    command = args.c[0]
                    self.file_to_get = args.c[1]
                    if args.hostname is None:
                        raise OptionNotFound("Hostname is invalid")
                    self.hostname = args.hostname

            elif args.r:
                self.file_to_get = args.r
                self.hostname = args.g
            else:
                parser.print_usage()
                raise OptionNotFound("Missing!!")

            if self.hostname is None:
                raise OptionNotFound("Hostname is invalid")

            self.makeTftpRetrieval()

        except OptionNotFound:
            self.exit()
            return
        except ExitException:
            self.exit()
            return
        except Exception:
            self.exit()
            return

        self.exit()


commands['tftp'] = command_tftp
commands['/usr/bin/tftp'] = command_tftp
