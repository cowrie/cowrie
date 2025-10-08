# Author: Claud Xiao

from __future__ import annotations

import getopt
import os
from typing import TYPE_CHECKING

from twisted.internet import defer, reactor
from twisted.internet.protocol import ClientCreator, Protocol
from twisted.protocols.ftp import CommandFailed, FTPClient
from twisted.python import log

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.network import communication_allowed
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from twisted.python.failure import Failure

commands = {}


class FTPFileReceiver(Protocol):
    """
    Protocol to receive FTP file data
    """

    def __init__(self, artifact: Artifact) -> None:
        self.artifact = artifact
        self.bytes_received = 0

    def dataReceived(self, data: bytes) -> None:
        self.artifact.write(data)
        self.bytes_received += len(data)

    def connectionLost(self, reason: Failure | None = None) -> None:
        # Transfer complete
        pass


class Command_ftpget(HoneyPotCommand):
    """
    ftpget command
    """

    download_path = CowrieConfig.get("honeypot", "download_path", fallback=".")
    verbose: bool
    host: str
    port: int
    username: str
    password: str
    remote_path: str
    remote_dir: str
    remote_file: str
    artifactFile: Artifact
    ftp_client: FTPClient | None

    def help(self) -> None:
        self.write(
            """BusyBox v1.20.2 (2016-06-22 15:12:53 EDT) multi-call binary.

Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE

Download a file via FTP

    -c Continue previous transfer
    -v Verbose
    -u USER     Username
    -p PASS     Password
    -P NUM      Port\n\n"""
        )

    def start(self) -> None:
        try:
            optlist, args = getopt.getopt(self.args, "cvu:p:P:")
        except getopt.GetoptError:
            self.help()
            self.exit()
            return

        if len(args) < 2:
            self.help()
            self.exit()
            return

        self.verbose = False
        self.username = ""
        self.password = ""
        self.port = 21
        self.host = ""
        self.local_file = ""
        self.remote_path = ""

        for opt in optlist:
            if opt[0] == "-v":
                self.verbose = True
            elif opt[0] == "-u":
                self.username = opt[1]
            elif opt[0] == "-p":
                self.password = opt[1]
            elif opt[0] == "-P":
                try:
                    self.port = int(opt[1])
                except ValueError:
                    pass

        if len(args) == 2:
            self.host, self.remote_path = args
        elif len(args) >= 3:
            self.host, self.local_file, self.remote_path = args[:3]

        self.remote_dir = os.path.dirname(self.remote_path)
        self.remote_file = os.path.basename(self.remote_path)
        if not self.local_file:
            self.local_file = self.remote_file

        fakeoutfile = self.fs.resolve_path(self.local_file, self.protocol.cwd)
        path = os.path.dirname(fakeoutfile)
        if not path or not self.fs.exists(path) or not self.fs.isdir(path):
            self.write(
                f"ftpget: can't open '{self.local_file}': No such file or directory"
            )
            self.exit()
            return

        if not communication_allowed(self.host):
            self.exit()
            return

        self.url_log = "ftp://"
        if self.username:
            self.url_log = f"{self.url_log}{self.username}"
            if self.password:
                self.url_log = f"{self.url_log}:{self.password}"
            self.url_log = f"{self.url_log}@"
        self.url_log = f"{self.url_log}{self.host}"
        if self.port != 21:
            self.url_log = f"{self.url_log}:{self.port}"
        self.url_log = f"{self.url_log}/{self.remote_path}"

        self.artifactFile = Artifact(self.local_file)
        self.ftp_client = None
        self.fakeoutfile = fakeoutfile

        # Start async download
        d = self.ftp_download_async()
        if d:
            d.addCallback(self._download_success)
            d.addErrback(self._download_error)
        else:
            self.artifactFile.close()
            self.exit()

    def ftp_download_async(self) -> defer.Deferred[None] | None:
        """
        Async FTP download using Twisted FTPClient
        """
        # Create FTP client
        username = self.username or "anonymous"
        password = self.password or "busybox@"

        creator = ClientCreator(reactor, FTPClient, username, password, passive=True)

        # Connect
        if self.verbose:
            self.write(f"Connecting to {self.host}\n")

        d = creator.connectTCP(self.host, self.port, timeout=30)
        d.addCallback(self._ftp_connected)
        return d  # type: ignore[no-any-return]

    def _ftp_connected(self, client: FTPClient) -> defer.Deferred[None]:
        """
        Called when FTP connection established
        """
        self.ftp_client = client

        if self.verbose:
            self.write("ftpget: cmd (null) (null)\n")
            username = self.username or "anonymous"
            password = self.password or "busybox@"
            self.write(f"ftpget: cmd USER {username}\n")
            self.write(f"ftpget: cmd PASS {password}\n")

        # Change to remote directory if needed
        d: defer.Deferred[None]
        if self.remote_dir:
            d = client.cwd(self.remote_dir)
        else:
            d = defer.succeed(None)

        d.addCallback(lambda _: self._start_retrieval())
        return d

    def _start_retrieval(self) -> defer.Deferred[None]:
        """
        Start file retrieval
        """
        if self.verbose:
            self.write("ftpget: cmd TYPE I (null)\n")
            self.write("ftpget: cmd PASV (null)\n")
            self.write(f"ftpget: cmd SIZE {self.remote_path}\n")
            self.write(f"ftpget: cmd RETR {self.remote_path}\n")

        # Create receiver protocol
        receiver = FTPFileReceiver(self.artifactFile)

        # Retrieve file
        if self.ftp_client:
            d: defer.Deferred[None] = self.ftp_client.retrieveFile(
                self.remote_file, receiver
            )
            d.addCallback(lambda _: self._quit_ftp())
            return d
        else:
            return defer.fail(Exception("FTP client not connected"))

    def _quit_ftp(self) -> defer.Deferred[None]:
        """
        Quit FTP connection
        """
        if self.verbose:
            self.write("ftpget: cmd (null) (null)\n")
            self.write("ftpget: cmd QUIT (null)\n")

        d: defer.Deferred[None]
        if self.ftp_client:
            d = self.ftp_client.quit()
            return d
        else:
            return defer.succeed(None)

    def _download_success(self, result: None) -> None:
        """
        Called when download completes successfully
        """
        self.artifactFile.close()

        # log to cowrie.log
        log.msg(
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url_log,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
        )

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download",
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url_log,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
            destfile=self.local_file,
        )

        # Update the honeyfs to point to downloaded file
        self.fs.mkfile(
            self.fakeoutfile,
            0,
            0,
            os.path.getsize(self.artifactFile.shasumFilename),
            33188,
        )
        self.fs.update_realfile(
            self.fs.getfile(self.fakeoutfile), self.artifactFile.shasumFilename
        )
        self.fs.chown(self.fakeoutfile, self.protocol.user.uid, self.protocol.user.gid)

        self.exit()

    def _download_error(self, failure: Failure) -> None:
        """
        Called when download fails
        """
        self.artifactFile.close()

        error_msg = "Connection error"

        if failure.check(CommandFailed):
            # FTP command failed (auth, file not found, etc)
            error_msg = f"FTP error: {failure.value.args[0]}"
        else:
            # Network/connection error
            error_msg = f"Connection failed: {failure.getErrorMessage()}"

        log.msg(
            format="Attempt to download file(s) from URL (%(url)s) failed: %(error)s",
            url=self.url_log,
            error=error_msg,
        )

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download.failed",
            format="Attempt to download file(s) from URL (%(url)s) failed",
            url=self.url_log,
        )

        self.write(f"ftpget: {error_msg}\n")
        self.exit()


commands["/usr/bin/ftpget"] = Command_ftpget
commands["ftpget"] = Command_ftpget
