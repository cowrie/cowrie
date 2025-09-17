# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getopt
import os
import time
from typing import Any
from urllib import parse

from twisted.internet import error
from twisted.internet.defer import inlineCallbacks, CancelledError
from twisted.python import log
from twisted.web.iweb import UNKNOWN_LENGTH

import treq

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.network import communication_allowed
from cowrie.shell.command import HoneyPotCommand

commands = {}


def tdiff(seconds: int) -> str:
    t = seconds
    days = int(t / (24 * 60 * 60))
    t -= days * 24 * 60 * 60
    hours = int(t / (60 * 60))
    t -= hours * 60 * 60
    minutes = int(t / 60)
    t -= minutes * 60

    s = f"{t}s"
    if minutes >= 1:
        s = f"{minutes}m {s}"
    if hours >= 1:
        s = f"{hours}h {s}"
    if days >= 1:
        s = f"{days}d {s}"
    return s


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
    started: float

    @inlineCallbacks
    def start(self):
        url: str
        try:
            optlist, args = getopt.getopt(self.args, "cqO:P:", ["header="])
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            self.exit()
            return

        if len(args):
            url = args[0].strip()
        else:
            self.errorWrite("wget: missing URL\n")
            self.errorWrite("Usage: wget [OPTION]... [URL]...\n\n")
            self.errorWrite("Try `wget --help' for more options.\n")
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

        if urldata.hostname:
            self.host = urldata.hostname
        else:
            pass

        allowed = yield communication_allowed(self.host)
        if not allowed:
            log.msg("Attempt to access blocked network address")
            self.errorWrite(f"curl: (6) Could not resolve host: {self.host}\n")
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

        self.artifact = Artifact("curl-download")

        if not self.quiet:
            port = urldata.port if urldata.port is not None else 80
            tm = time.strftime("%Y-%m-%d %H:%M:%S")
            self.errorWrite(f"--{tm}--  {url}\n")
            self.errorWrite(f"Connecting to {self.host}:{port}... connected.\n")
            self.errorWrite("HTTP request sent, awaiting response... ")

        self.deferred = self.wgetDownload(url)
        if self.deferred:
            self.deferred.addCallback(self.success)
            self.deferred.addErrback(self.error)

    def wgetDownload(self, url: str) -> Any:
        """
        Download `url`
        """
        headers = {"User-Agent": ["curl/7.38.0"]}

        # TODO: use designated outbound interface
        # out_addr = None
        # if CowrieConfig.has_option("honeypot", "out_addr"):
        #     out_addr = (CowrieConfig.get("honeypot", "out_addr"), 0)

        deferred = treq.get(url=url, allow_redirects=True, headers=headers, timeout=10)
        return deferred

    def handle_CTRL_C(self) -> None:
        self.write("^C\n")
        self.exit()

    def success(self, response):
        """
        successful treq get
        """
        # TODO possible this is UNKNOWN_LENGTH
        if response.length != UNKNOWN_LENGTH:
            self.totallength = response.length
        else:
            self.totallength = 0

        if self.limit_size > 0 and self.totallength > self.limit_size:
            log.msg(
                f"Not saving URL ({self.url.decode()}) (size: {self.totallength}) exceeds file size limit ({self.limit_size})"
            )
            self.exit()
            return

        self.started = time.time()

        if not self.quiet:
            self.errorWrite("200 OK\n")

        if response.headers.hasHeader(b"content-type"):
            self.contenttype = response.headers.getRawHeaders(b"content-type")[
                0
            ].decode()
        else:
            self.contenttype = "text/whatever"

        if not self.quiet:
            if response.length != UNKNOWN_LENGTH:
                self.errorWrite(
                    f"Length: {self.totallength} ({sizeof_fmt(self.totallength)}) [{self.contenttype}]\n"
                )
            else:
                self.errorWrite(f"Length: unspecified [{self.contenttype}]\n")

            if self.outfile is None:
                self.errorWrite("Saving to: `STDOUT'\n\n")
            else:
                self.errorWrite(f"Saving to: `{self.outfile}'\n\n")

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
