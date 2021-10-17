# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getopt
import ipaddress
import os
import time

from twisted.internet import reactor, ssl  # type: ignore
from twisted.python import compat, log
from twisted.web import client

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}


def tdiff(seconds):
    t = seconds
    days = int(t / (24 * 60 * 60))
    t -= days * 24 * 60 * 60
    hours = int(t / (60 * 60))
    t -= hours * 60 * 60
    minutes = int(t / 60)
    t -= minutes * 60

    s = "%ds" % (int(t),)
    if minutes >= 1:
        s = f"{minutes}m {s}"
    if hours >= 1:
        s = f"{hours}h {s}"
    if days >= 1:
        s = f"{days}d {s}"
    return s


def sizeof_fmt(num):
    for x in ["bytes", "K", "M", "G", "T"]:
        if num < 1024.0:
            return f"{num}{x}"
        num /= 1024.0


# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands(s, sep=","):
    if len(s) <= 3:
        return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]


class Command_wget(HoneyPotCommand):
    """
    wget command
    """

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    downloadPath: str = CowrieConfig.get("honeypot", "download_path")
    quiet: bool = False

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

        self.outfile: str = None
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

        urldata = compat.urllib_parse.urlparse(url)

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
                    "wget: {}: Cannot open: No such file or directory\n".format(
                        self.outfile
                    )
                )
                self.exit()
                return

        self.deferred = self.download(self.url, self.outfile)
        if self.deferred:
            self.deferred.addCallback(self.success)
            self.deferred.addErrback(self.error, self.url)
        else:
            self.exit()

    def download(self, url, fakeoutfile, *args, **kwargs):
        """
        url - URL to download
        fakeoutfile - file in guest's fs that attacker wants content to be downloaded to
        """
        try:
            parsed = compat.urllib_parse.urlparse(url)
            scheme = parsed.scheme
            host = parsed.hostname.decode("utf8")
            port = parsed.port or (443 if scheme == b"https" else 80)
            if scheme != b"http" and scheme != b"https":
                raise NotImplementedError
            if not host:
                return None
        except Exception:
            self.errorWrite(f"{url}: Unsupported scheme.\n")
            return None

        if not self.quiet:
            self.errorWrite(
                "--{}--  {}\n".format(
                    time.strftime("%Y-%m-%d %H:%M:%S"), url.decode("utf8")
                )
            )
            self.errorWrite(f"Connecting to {host}:{port}... connected.\n")
            self.errorWrite("HTTP request sent, awaiting response... ")

        # TODO: need to do full name resolution.
        try:
            if ipaddress.ip_address(host).is_private:
                self.errorWrite(
                    "Resolving {} ({})... failed: nodename nor servname provided, or not known.\n".format(
                        host, host
                    )
                )
                self.errorWrite(f"wget: unable to resolve host address ‘{host}’\n")
                return None
        except ValueError:
            pass

        # File in host's fs that will hold content of the downloaded file
        # HTTPDownloader will close() the file object so need to preserve the name
        self.artifactFile = Artifact(self.outfile)

        factory = HTTPProgressDownloader(
            self, fakeoutfile, url, self.artifactFile, *args, **kwargs
        )

        out_addr = None
        if CowrieConfig.has_option("honeypot", "out_addr"):
            out_addr = (CowrieConfig.get("honeypot", "out_addr"), 0)

        if scheme == b"https":
            context_factory = ssl.optionsForClientTLS(hostname=host)
            self.connection = reactor.connectSSL(
                host, port, factory, context_factory, bindAddress=out_addr
            )

        elif scheme == b"http":
            self.connection = reactor.connectTCP(
                host, port, factory, bindAddress=out_addr
            )
        else:
            raise NotImplementedError

        return factory.deferred

    def handle_CTRL_C(self):
        self.errorWrite("^C\n")
        self.connection.transport.loseConnection()

    def success(self, data):
        if not os.path.isfile(self.artifactFile.shasumFilename):
            log.msg("there's no file " + self.artifactFile.shasumFilename)
            self.exit()

        # log to cowrie.log
        log.msg(
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
        )

        # log to output modules
        self.protocol.logDispatch(
            eventid="cowrie.session.file_download",
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
        )

        # Update honeyfs to point to downloaded file or write to screen
        if self.outfile != "-":
            self.fs.update_realfile(
                self.fs.getfile(self.outfile), self.artifactFile.shasumFilename
            )
            self.fs.chown(self.outfile, self.protocol.user.uid, self.protocol.user.gid)
        else:
            with open(self.artifactFile.shasumFilename, "rb") as f:
                self.writeBytes(f.read())

        self.exit()

    def error(self, error, url):
        # we need to handle 301 redirects separately
        if (
            hasattr(error, "webStatus")
            and error.webStatus
            and error.webStatus.decode() == "301"
        ):
            self.errorWrite(f"{error.webStatus.decode()} {error.webMessage.decode()}\n")
            https_url = error.getErrorMessage().replace("301 Moved Permanently to ", "")
            self.errorWrite(f"Location {https_url} [following]\n")

            # do the download again with the https URL
            self.deferred = self.download(https_url.encode("utf8"), self.outfile)
            if self.deferred:
                self.deferred.addCallback(self.success)
                self.deferred.addErrback(self.error, https_url)
            else:
                self.exit()
        else:
            if hasattr(error, "getErrorMessage"):  # exceptions
                errorMessage = error.getErrorMessage()
                self.errorWrite(errorMessage + "\n")
                # Real wget also adds this:
            if (
                hasattr(error, "webStatus")
                and error.webStatus
                and hasattr(error, "webMessage")
            ):  # exceptions
                self.errorWrite(
                    "{} ERROR {}: {}\n".format(
                        time.strftime("%Y-%m-%d %T"),
                        error.webStatus.decode(),
                        error.webMessage.decode("utf8"),
                    )
                )
            else:
                self.errorWrite(
                    "{} ERROR 404: Not Found.\n".format(time.strftime("%Y-%m-%d %T"))
                )

            # prevent cowrie from crashing if the terminal have been already destroyed
            try:
                self.protocol.logDispatch(
                    eventid="cowrie.session.file_download.failed",
                    format="Attempt to download file(s) from URL (%(self.url)s) failed",
                    url=self.url,
                )
            except Exception:
                pass

            self.exit()


# From http://code.activestate.com/recipes/525493/
class HTTPProgressDownloader(client.HTTPDownloader):
    def __init__(self, wget, fakeoutfile, url, outfile, headers=None):
        client.HTTPDownloader.__init__(
            self,
            url,
            outfile,
            headers=headers,
            agent=b"Wget/1.11.4",
            followRedirect=False,
        )
        self.status = None
        self.wget = wget
        self.fakeoutfile = fakeoutfile
        self.lastupdate = 0
        self.started = time.time()
        self.proglen = 0
        self.nomore = False
        self.quiet = self.wget.quiet

    def noPage(self, reason):  # Called for non-200 responses
        if self.status == b"304":
            client.HTTPDownloader.page(self, "")
        else:
            if hasattr(self, "status"):
                reason.webStatus = self.status
            if hasattr(self, "message"):
                reason.webMessage = self.message

            client.HTTPDownloader.noPage(self, reason)

    def gotHeaders(self, headers):
        if self.status == b"200":
            if not self.quiet:
                self.wget.errorWrite("200 OK\n")
            if b"content-length" in headers:
                self.totallength = int(headers[b"content-length"][0].decode())
            else:
                self.totallength = 0
            if b"content-type" in headers:
                self.contenttype = headers[b"content-type"][0].decode()
            else:
                self.contenttype = "text/whatever"
            self.currentlength = 0.0

            if self.totallength > 0:
                if not self.quiet:
                    self.wget.errorWrite(
                        "Length: {} ({}) [{}]\n".format(
                            self.totallength,
                            sizeof_fmt(self.totallength),
                            self.contenttype,
                        )
                    )
            else:
                if not self.quiet:
                    self.wget.errorWrite(f"Length: unspecified [{self.contenttype}]\n")
            if 0 < self.wget.limit_size < self.totallength:
                log.msg(f"Not saving URL ({self.wget.url}) due to file size limit")
                self.nomore = True
            if not self.quiet:
                if self.fakeoutfile == "-":
                    self.wget.errorWrite("Saving to: `STDOUT'\n\n")
                else:
                    self.wget.errorWrite(f"Saving to: `{self.fakeoutfile}'\n\n")

        return client.HTTPDownloader.gotHeaders(self, headers)

    def pagePart(self, data):
        if self.status == b"200":
            self.currentlength += len(data)

            # If downloading files of unspecified size, this could happen:
            if not self.nomore and 0 < self.wget.limit_size < self.currentlength:
                log.msg("File limit reached, not saving any more data!")
                self.nomore = True
            if (time.time() - self.lastupdate) < 0.5:
                return client.HTTPDownloader.pagePart(self, data)
            if self.totallength:
                percent = int(self.currentlength / self.totallength * 100)
                spercent = f"{percent}%"
            else:
                spercent = f"{self.currentlength / 1000}K"
                percent = 0
            self.speed = self.currentlength / (time.time() - self.started)
            eta = (self.totallength - self.currentlength) / self.speed
            s = "\r%s [%s] %s %dK/s  eta %s" % (
                spercent.rjust(3),
                ("%s>" % (int(39.0 / 100.0 * percent) * "=")).ljust(39),
                splitthousands(str(int(self.currentlength))).ljust(12),
                self.speed / 1000,
                tdiff(eta),
            )
            if not self.quiet:
                self.wget.errorWrite(s.ljust(self.proglen))
            self.proglen = len(s)
            self.lastupdate = time.time()
        return client.HTTPDownloader.pagePart(self, data)

    def pageEnd(self):
        if self.totallength != 0 and self.currentlength != self.totallength:
            return client.HTTPDownloader.pageEnd(self)
        if not self.quiet:
            self.wget.errorWrite(
                "\r100%%[%s] %s %dK/s"
                % (
                    "%s>" % (38 * "="),
                    splitthousands(str(int(self.totallength))).ljust(12),
                    self.speed / 1000,
                )
            )
            self.wget.errorWrite("\n\n")
            self.wget.errorWrite(
                "%s (%d KB/s) - `%s' saved [%d/%d]\n\n"
                % (
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    self.speed / 1000,
                    self.fakeoutfile,
                    self.currentlength,
                    self.totallength,
                )
            )
        if self.fakeoutfile != "-":
            self.wget.fs.mkfile(self.fakeoutfile, 0, 0, self.totallength, 33188)

        return client.HTTPDownloader.pageEnd(self)


commands["/usr/bin/wget"] = Command_wget
commands["wget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget
commands["dget"] = Command_wget
