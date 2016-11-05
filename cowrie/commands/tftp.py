#!/usr/bin/env python

import time
import re
import tftpy
import os
from cowrie.core.customparser import CustomParser
from cowrie.core.customparser import OptionNotFound
from cowrie.core.customparser import ExitException
from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *


commands = {}


class Progress(object):

    def __init__(self, protocol):

        self.progress = 0
        self.out = protocol


    def progresshook(self, pkt):

        if isinstance(pkt, tftpy.TftpPacketDAT):
            self.progress += len(pkt.data)
            self.out.write("Transferred %d bytes" % self.progress + "\n")
        elif isinstance(pkt, tftpy.TftpPacketOACK):
            self.out.write("Received OACK, options are: %s" % pkt.options + "\n")


class command_tftp(HoneyPotCommand):

    port = 69

    hostname = None
    file_to_get = None

    def makeTftpRetrieval(self):

        progresshook = Progress(self).progresshook

        tclient = tftpy.TftpClient(self.hostname,
                                   int(self.port))
        cfg = self.protocol.cfg
        if cfg.has_option('honeypot', 'download_limit_size'):
            self.limit_size = int(cfg.get('honeypot', 'download_limit_size'))

        self.download_path = cfg.get('honeypot', 'download_path')

        self.safeoutfile = '%s/%s_%s' % \
                           (self.download_path,
                            time.strftime('%Y%m%d%H%M%S'),
                            re.sub('[^A-Za-z0-9]', '_', self.file_to_get))

        self.protocol.logDispatch(eventid='cowrie.session.file_download',
                                  format='Downloaded tftpFile to %(outfile)s',
                                  outfile=self.safeoutfile
                                  )

        log.msg(eventid='cowrie.session.file_download',
                format='Downloaded tftpFile to %(outfile)s',
                outfile=self.safeoutfile
                )

        try:
            tclient.download(self.file_to_get, self.safeoutfile, progresshook)
            self.file_to_get = self.fs.resolve_path(self.file_to_get, self.protocol.cwd)
            self.fs.mkfile(self.file_to_get, 0, 0, tclient.context.metrics.bytes, 33188)
            self.fs.update_realfile(self.fs.getfile(self.file_to_get), self.safeoutfile)
            f = self.fs.getfile(self.file_to_get)
            f[A_REALFILE] = self.safeoutfile

        except tftpy.TftpException, err:
            return

        except KeyboardInterrupt:
            pass


    def start(self):

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
