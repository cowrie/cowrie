#

from __future__ import division, absolute_import

import tftpy

from twisted.python import log

from cowrie.core.artifact import Artifact
from cowrie.core.config import CONFIG
from cowrie.shell.customparser import CustomParser, OptionNotFound
from cowrie.shell.honeypot import HoneyPotCommand


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

        if CONFIG.has_option('honeypot', 'download_limit_size'):
            self.limit_size = CONFIG.getint('honeypot', 'download_limit_size')

        self.artifactFile = Artifact(self.file_to_get)

        tclient = None
        url = ''

        try:
            tclient = tftpy.TftpClient(self.hostname, int(self.port))

            # tftpy can't handle unicode string as filename
            # so we have to convert unicode type to str type
            tclient.download(str(self.file_to_get), self.artifactFile, progresshook)

            url = 'tftp://%s/%s' % (self.hostname, self.file_to_get.strip('/'))

            self.file_to_get = self.fs.resolve_path(self.file_to_get, self.protocol.cwd)

            if hasattr(tclient.context, 'metrics'):
                self.fs.mkfile(self.file_to_get, 0, 0, tclient.context.metrics.bytes, 33188)
            else:
                self.fs.mkfile(self.file_to_get, 0, 0, 0, 33188)

        except tftpy.TftpException:
            if tclient and tclient.context and not tclient.context.fileobj.closed:
                tclient.context.fileobj.close()

        if url:

            # log to cowrie.log
            log.msg(format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                    url=url,
                    outfile=self.artifactFile.shasumFilename,
                    shasum=self.artifactFile.shasum)

            self.protocol.logDispatch(eventid='cowrie.session.file_download',
                                      format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                                      url=url,
                                      outfile=self.artifactFile.shasumFilename,
                                      shasum=self.artifactFile.shasum,
                                      destfile=self.file_to_get)

            # Update the honeyfs to point to downloaded file
            self.fs.update_realfile(self.fs.getfile(self.file_to_get), self.artifactFile.shasumFilename)
            self.fs.chown(self.file_to_get, self.protocol.user.uid, self.protocol.user.gid)


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

            if self.hostname.find(':') != -1:
                host, port = self.hostname.split(':')
                self.hostname = host
                self.port = int(port)

            self.makeTftpRetrieval()

        except Exception as err:
            log.err(str(err))

        self.exit()


commands['tftp'] = command_tftp
commands['/usr/bin/tftp'] = command_tftp
