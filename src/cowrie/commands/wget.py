# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getopt
import os
import time
import posixpath
from typing import Any
from urllib import parse

from twisted.internet import defer, error, reactor
from twisted.internet.defer import inlineCallbacks, CancelledError
from twisted.internet.protocol import ClientCreator, Protocol
from twisted.python import log
from twisted.protocols.ftp import CommandFailed, FTPClient
from twisted.web.iweb import UNKNOWN_LENGTH

import treq

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.network import communication_allowed
from cowrie.shell.command import HoneyPotCommand

commands = {}


def tdiff(seconds: int) -> str:
    days, remainder = divmod(seconds, 86400)  # 86400 = 24*60*60
    hours, remainder = divmod(remainder, 3600)  # 3600 = 60*60
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days >= 1:
        parts.append(f"{days}d")
    if hours >= 1:
        parts.append(f"{hours}h")
    if minutes >= 1:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def sizeof_fmt(num: float) -> str:
    for x in ["bytes", "K", "M", "G", "T"]:
        if num < 1024.0:
            return f"{num}{x}"
        num /= 1024.0
    raise ValueError


# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands(s: str, sep: str = ",") -> str:
    if len(s) <= 3:
        return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]


class _FTPWgetReceiver(Protocol):
    """
    Receive FTP data and forward to wget collector
    """

    def __init__(self, command: Command_wget) -> None:
        self.command = command

    def dataReceived(self, data: bytes) -> None:
        self.command.collect(data)

    def connectionLost(self, reason=None):
        # Download completion handled by command callbacks
        return None


class Command_wget(HoneyPotCommand):
    """
    wget command
    """

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    quiet: bool = False

    outfile: str | None = None  # outfile is the file saved inside the honeypot
    artifact: (
        Artifact  # artifact is the file saved for forensics in the real file system
    )
    currentlength: int = 0  # partial size during download
    totallength: int = 0  # total length
    proglen: int = 0
    url: bytes
    host: str
    scheme: str
    ftp_client: FTPClient | None = None
    ftp_remote_dir: str | None = None
    ftp_remote_file: str | None = None
    started: float

    def print_usage_error(self, error_msg: str = "") -> None:
        """Print usage error message"""
        if error_msg:
            self.errorWrite(f"wget: {error_msg}\n")
        self.errorWrite("Usage: wget [OPTION]... [URL]...\n\n")
        self.errorWrite("Try `wget --help' for more options.\n")

    @inlineCallbacks
    def start(self):
        url: str
        try:
            optlist, args = getopt.getopt(
                self.args,
                "cqO:TP:",
                [
                    "quiet",
                    "header=",
                    "max-redirect=",
                    "post-data",
                    "timeout=",
                    "tries=",
                ],
            )
        except getopt.GetoptError as err:
            self.print_usage_error(f"invalid option -- '{err.opt}'")
            self.exit()
            return

        if len(args):
            url = args[0].strip()
        else:
            self.print_usage_error("missing URL")
            self.exit()
            return

        self.outfile = None
        self.quiet = False
        for opt in optlist:
            if opt[0] == "-O":
                self.outfile = opt[1]
            if opt[0] == "-q":
                self.quiet = True

        # for some reason getopt doesn't recognize "-O -"
        # use try..except for the case if passed command is malformed
        try:
            if not self.outfile:
                if "-O" in args:
                    self.outfile = args[args.index("-O") + 1]
        except Exception:
            pass

        if "://" not in url:
            url = f"http://{url}"

        urldata = parse.urlparse(url)
        self.scheme = (urldata.scheme or "http").lower()

        if urldata.hostname:
            self.host = urldata.hostname
        else:
            pass

        allowed = yield communication_allowed(self.host)
        if not allowed:
            log.msg("Attempt to access blocked network address")
            if not self.quiet:
                tm = time.strftime("%Y-%m-%d %H:%M:%S")
                self.errorWrite(f"--{tm}--  {url}\n")
                self.errorWrite(
                    f"Resolving {self.host} ({self.host})... failed: nodename nor servname provided, or not known.\n"
                )
            self.errorWrite(f"wget: unable to resolve host address ‘{self.host}’\n")
            self.exit()
            return None

        self.url = url.encode("utf8")

        if self.outfile is None:
            self.outfile = urldata.path.split("/")[-1]
            if not len(self.outfile.strip()) or not urldata.path.count("/"):
                self.outfile = "index.html"

        if self.outfile != "-":
            self.outfile = self.fs.resolve_path(self.outfile, self.protocol.cwd)
            path = os.path.dirname(self.outfile)
            if not path or not self.fs.exists(path) or not self.fs.isdir(path):
                self.errorWrite(
                    f"wget: {self.outfile}: Cannot open: No such file or directory\n"
                )
                self.exit()
                return

        self.artifact = Artifact("wget-download")

        if not self.quiet:
            if urldata.port is not None:
                port = urldata.port
            elif self.scheme == "https":
                port = 443
            elif self.scheme == "ftp":
                port = 21
            else:
                port = 80
            tm = time.strftime("%Y-%m-%d %H:%M:%S")
            self.errorWrite(f"--{tm}--  {url}\n")
            self.errorWrite(f"Connecting to {self.host}:{port}... connected.\n")
            proto_label = "HTTP" if self.scheme in ("http", "https") else self.scheme.upper()
            self.errorWrite(f"{proto_label} request sent, awaiting response... ")

        if self.scheme == "ftp":
            self.deferred = self.ftpDownload(urldata)
            if self.deferred:
                self.deferred.addErrback(self.error)
        else:
            self.deferred = self.httpDownload(url)
            if self.deferred:
                self.deferred.addCallback(self.success)
                self.deferred.addErrback(self.error)

    def httpDownload(self, url: str) -> Any:
        """
        Download `url`
        """
        headers = {"User-Agent": ["Wget/1.25.0 (linux-gnu)"]}

        # TODO: use designated outbound interface
        # out_addr = None
        # if CowrieConfig.has_option("honeypot", "out_addr"):
        #     out_addr = (CowrieConfig.get("honeypot", "out_addr"), 0)

        deferred = treq.get(url=url, allow_redirects=True, headers=headers, timeout=10)
        return deferred

    def ftpDownload(self, urldata: parse.ParseResult) -> Any:
        """
        Download `url` via FTP
        """
        username = parse.unquote(urldata.username) if urldata.username else "anonymous"
        password = parse.unquote(urldata.password) if urldata.password else "busybox@"
        port = urldata.port or 21

        raw_path = urldata.path or ""
        if urldata.params:
            raw_path = f"{raw_path};{urldata.params}"
        remote_path = parse.unquote(raw_path)

        if not remote_path or remote_path.endswith("/"):
            self.errorWrite("wget: unsupported directory target in FTP URL\n")
            self.exit()
            return None

        self.ftp_remote_dir = posixpath.dirname(remote_path)
        self.ftp_remote_file = posixpath.basename(remote_path)

        if not self.ftp_remote_file:
            self.errorWrite("wget: missing remote filename in FTP URL\n")
            self.exit()
            return None

        self.ftp_client = None

        creator = ClientCreator(reactor, FTPClient, username, password, passive=True)
        deferred = creator.connectTCP(self.host, port, timeout=30)
        deferred.addCallback(self._ftp_connected)
        return deferred

    def _ftp_connected(self, client: FTPClient) -> defer.Deferred[Any]:
        """
        Handle established FTP connection
        """
        self.ftp_client = client

        if self.ftp_remote_dir and self.ftp_remote_dir not in (".", "./"):
            d: defer.Deferred[Any] = client.cwd(self.ftp_remote_dir)
        else:
            d = defer.succeed(None)

        d.addCallback(lambda _: self._ftp_start_retrieve())
        return d

    def _ftp_start_retrieve(self) -> defer.Deferred[Any]:
        """
        Start retrieving file over FTP
        """
        if not self._begin_download(None, "application/octet-stream", "200 OK"):
            if self.ftp_client:
                try:
                    quit_deferred = self.ftp_client.quit()
                    if isinstance(quit_deferred, defer.Deferred):
                        quit_deferred.addErrback(
                            lambda failure: log.msg(
                                f"FTP quit failed during abort: {failure.getErrorMessage()}"
                            )
                        )
                except Exception as e:  # pragma: no cover - defensive
                    log.msg(f"FTP quit raised exception during abort: {e!s}")
                finally:
                    self.ftp_client = None
            return defer.succeed(None)

        if not self.ftp_client or not self.ftp_remote_file:
            return defer.fail(Exception("FTP client not connected"))

        receiver = _FTPWgetReceiver(self)
        deferred = self.ftp_client.retrieveFile(self.ftp_remote_file, receiver)
        deferred.addCallback(self._ftp_after_retrieve)
        return deferred  # type: ignore[no-any-return]

    def _ftp_after_retrieve(self, result: Any) -> Any:
        """
        Cleanup after FTP retrieval completes
        """
        if self.ftp_client:
            try:
                quit_deferred = self.ftp_client.quit()
                if isinstance(quit_deferred, defer.Deferred):
                    quit_deferred.addErrback(
                        lambda failure: log.msg(
                            f"FTP quit failed: {failure.getErrorMessage()}"
                        )
                    )
            except Exception as e:  # pragma: no cover - defensive
                log.msg(f"FTP quit raised exception: {e!s}")
            finally:
                self.ftp_client = None

        self.collectioncomplete(None)
        return result

    def _begin_download(
        self, total_length: int | None, contenttype: str, status_line: str = "200 OK"
    ) -> bool:
        """
        Prepare transfer bookkeeping and display status
        """
        if total_length is not None:
            self.totallength = total_length
        else:
            self.totallength = 0

        if (
            total_length is not None
            and self.limit_size > 0
            and self.totallength > self.limit_size
        ):
            log.msg(
                f"Not saving URL ({self.url.decode()}) (size: {self.totallength}) exceeds file size limit ({self.limit_size})"
            )
            self.exit()
            return False

        self.currentlength = 0
        self.proglen = 0
        self.contenttype = contenttype
        self.speed = 0.0
        self.started = time.time()

        if not self.quiet:
            self.errorWrite(f"{status_line}\n")
            if total_length is not None:
                self.errorWrite(
                    f"Length: {self.totallength} ({sizeof_fmt(self.totallength)}) [{self.contenttype}]\n"
                )
            else:
                self.errorWrite(f"Length: unspecified [{self.contenttype}]\n")

            if self.outfile in (None, "-"):
                self.errorWrite("Saving to: `STDOUT'\n\n")
            else:
                self.errorWrite(f"Saving to: `{self.outfile}'\n\n")

        return True

    def handle_CTRL_C(self) -> None:
        self.write("^C\n")
        self.exit()

    def success(self, response):
        """
        successful treq get
        """
        if response.headers.hasHeader(b"content-type"):
            contenttype = response.headers.getRawHeaders(b"content-type")[0].decode()
        else:
            contenttype = "text/whatever"

        status_line = "200 OK"
        code = getattr(response, "code", None)
        phrase = getattr(response, "phrase", None)
        if code is not None:
            if phrase:
                if isinstance(phrase, bytes):
                    phrase = phrase.decode()
                status_line = f"{code} {phrase}"
            else:
                status_line = str(code)

        total_length: int | None
        if response.length != UNKNOWN_LENGTH:
            total_length = response.length
        else:
            total_length = None

        if not self._begin_download(total_length, contenttype, status_line):
            return None

        deferred = treq.collect(response, self.collect)
        deferred.addCallback(self.collectioncomplete)
        return deferred

    def collect(self, data: bytes) -> None:
        """
        partial collect
        """
        eta: float
        self.currentlength += len(data)
        if self.limit_size > 0 and self.currentlength > self.limit_size:
            log.msg(
                f"Not saving URL ({self.url.decode()}) (size: {self.currentlength}) exceeds file size limit ({self.limit_size})"
            )
            self.exit()
            return

        self.artifact.write(data)

        self.speed = self.currentlength / (time.time() - self.started)
        if self.totallength != 0:
            percent = int(self.currentlength / self.totallength * 100)
            spercent = f"{percent}%"
            eta = (self.totallength - self.currentlength) / self.speed
        else:
            spercent = f"{self.currentlength / 1000:3.0f}K"
            percent = 0
            eta = 0.0

        s = "\r{} [{}] {} {:3.1f}K/s  eta {}".format(
            spercent.rjust(3),
            ("%s>" % (int(39.0 / 100.0 * percent) * "=")).ljust(39),
            splitthousands(str(int(self.currentlength))).ljust(12),
            self.speed / 1000,
            tdiff(int(eta)),
        )
        if not self.quiet:
            self.errorWrite(s.ljust(self.proglen))
        self.proglen = len(s)
        self.lastupdate = time.time()

        if not self.outfile:
            self.writeBytes(data)

    def collectioncomplete(self, data: None) -> None:
        """
        this gets called once collection is complete
        """
        self.artifact.close()

        self.totallength = self.currentlength

        if not self.quiet:
            self.errorWrite(
                "\r100% [{}] {} {:3.1f}K/s".format(
                    "%s>" % (38 * "="),
                    splitthousands(str(int(self.totallength))).ljust(12),
                    self.speed / 1000,
                )
            )
            self.errorWrite("\n\n")
            self.errorWrite(
                "{} ({:3.2f} KB/s) - `{}' saved [{}/{}]\n\n".format(
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    self.speed / 1000,
                    self.outfile,
                    self.currentlength,
                    self.totallength,
                )
            )

        # Update the honeyfs to point to artifact file if output is to file
        if self.outfile and self.protocol.user:
            self.fs.mkfile(
                self.outfile,
                self.protocol.user.uid,
                self.protocol.user.gid,
                self.currentlength,
                33188,
            )
            self.fs.update_realfile(
                self.fs.getfile(self.outfile), self.artifact.shasumFilename
            )

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download",
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url.decode(),
            outfile=self.artifact.shasumFilename,
            shasum=self.artifact.shasum,
        )
        log.msg(
            eventid="cowrie.session.file_download",
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url.decode(),
            outfile=self.artifact.shasumFilename,
            shasum=self.artifact.shasum,
        )
        self.exit()

    def error(self, response):
        """
        handle errors
        """
        self.protocol.logDispatch(
            eventid="cowrie.session.file_download.failed",
            format="Attempt to download file(s) from URL (%(url)s) failed",
            url=self.url.decode(),
        )

        if response.check(error.DNSLookupError) is not None:
            self.write(
                f"Resolving no.such ({self.host})... failed: nodename nor servname provided, or not known.\n"
            )
            self.write(f"wget: unable to resolve host address ‘{self.host}’\n")
            self.exit()
            return

        if response.check(CancelledError) is not None:
            self.write("failed: Operation timed out.\n")
            self.exit()
            return

        if response.check(CommandFailed) is not None:
            details = ""
            value = getattr(response, "value", None)
            if value and getattr(value, "args", None):
                details = value.args[0]
            self.write(f"wget: FTP error: {details}\n")
            self.exit()
            return

        if response.check(error.ConnectingCancelledError) is not None:
            self.write("cancel failed: Operation timed out.\n")
            self.exit()
            return

        if response.check(error.ConnectingDone) is not None:
            self.write("No data received.\n")
            self.exit()
            return

        log.err(f"Unhandled wget error: {response!s}")
        log.msg(f"Uhhandled wget traceback: {response.printTraceback()}")
        if hasattr(response, "getErrorMessage"):  # Exceptions
            log.msg(f"Unhandled wget error message: {response.getErrorMessage}")
        self.write("\n")
        self.exit()


commands["/usr/bin/wget"] = Command_wget
commands["wget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget
commands["dget"] = Command_wget
