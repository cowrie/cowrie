from __future__ import annotations
import tftpy
from tftpy.TftpPacketTypes import TftpPacketDAT, TftpPacketOACK

from twisted.python import log

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.customparser import CustomParser

commands = {}


class Progress:
    def __init__(self, protocol):
        self.progress = 0
        self.out = protocol

    def progresshook(self, pkt):
        if isinstance(pkt, TftpPacketDAT):
            self.progress += len(pkt.data)
            self.out.write(f"Transferred {self.progress} bytes\n")
        elif isinstance(pkt, TftpPacketOACK):
            self.out.write(f"Received OACK, options are: {pkt.options}\n")


class Command_tftp(HoneyPotCommand):
    port = 69
    hostname = None
    file_to_get: str
    limit_size = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)

    def makeTftpRetrieval(self) -> None:
        progresshook = Progress(self).progresshook

        self.artifactFile = Artifact(self.file_to_get)

        tclient = None
        url = ""

        try:
            tclient = tftpy.TftpClient(self.hostname, int(self.port))

            # tftpy can't handle unicode string as filename
            # so we have to convert unicode type to str type
            tclient.download(str(self.file_to_get), self.artifactFile, progresshook)

            url = "tftp://{}/{}".format(self.hostname, self.file_to_get.strip("/"))

            self.file_to_get = self.fs.resolve_path(self.file_to_get, self.protocol.cwd)

            if hasattr(tclient.context, "metrics"):
                self.fs.mkfile(
                    self.file_to_get, 0, 0, tclient.context.metrics.bytes, 33188
                )
            else:
                self.fs.mkfile(self.file_to_get, 0, 0, 0, 33188)

        except tftpy.TftpException:
            if tclient and tclient.context and not tclient.context.fileobj.closed:
                tclient.context.fileobj.close()

        self.artifactFile.close()

        if url:
            # log to cowrie.log
            log.msg(
                format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
                url=url,
                outfile=self.artifactFile.shasumFilename,
                shasum=self.artifactFile.shasum,
            )

            self.protocol.logDispatch(
                eventid="cowrie.session.file_download",
                format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
                url=url,
                outfile=self.artifactFile.shasumFilename,
                shasum=self.artifactFile.shasum,
                destfile=self.file_to_get,
            )

            # Update the honeyfs to point to downloaded file
            self.fs.update_realfile(
                self.fs.getfile(self.file_to_get), self.artifactFile.shasumFilename
            )
            self.fs.chown(
                self.file_to_get, self.protocol.user.uid, self.protocol.user.gid
            )

    def start(self) -> None:
        parser = CustomParser(self)
        parser.prog = "tftp"
        parser.add_argument("hostname", nargs="?", default=None)
        parser.add_argument("-c", nargs=2)
        parser.add_argument("-l")
        parser.add_argument("-g")
        parser.add_argument("-p")
        parser.add_argument("-r")

        args = parser.parse_args(self.args)
        if args.c:
            if len(args.c) > 1:
                self.file_to_get = args.c[1]
                if args.hostname is None:
                    self.exit()
                    return
                self.hostname = args.hostname
        elif args.r:
            self.file_to_get = args.r
            self.hostname = args.g
        else:
            self.write(
                "usage: tftp [-h] [-c C C] [-l L] [-g G] [-p P] [-r R] [hostname]\n"
            )
            self.exit()
            return

        if self.hostname is None:
            self.exit()
            return

        if self.hostname.find(":") != -1:
            host, port = self.hostname.split(":")
            self.hostname = host
            self.port = int(port)

        self.makeTftpRetrieval()
        self.exit()


commands["/usr/bin/tftp"] = Command_tftp
commands["tftp"] = Command_tftp
