# Copyright (c) 2022 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

from __future__ import annotations
from http.client import responses

import getopt
import os
from urllib import parse

from twisted.internet import error
from twisted.internet.defer import inlineCallbacks
from twisted.python import log

import treq

from cowrie.core.artifact import Artifact
from cowrie.core.network import communication_allowed
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand


commands = {}

CURL_HELP = """Usage: curl [options...] <url>
Options: (H) means HTTP/HTTPS only, (F) means FTP only
     --anyauth       Pick "any" authentication method (H)
 -a, --append        Append to target file when uploading (F/SFTP)
     --basic         Use HTTP Basic Authentication (H)
     --cacert FILE   CA certificate to verify peer against (SSL)
     --capath DIR    CA directory to verify peer against (SSL)
 -E, --cert CERT[:PASSWD] Client certificate file and password (SSL)
     --cert-type TYPE Certificate file type (DER/PEM/ENG) (SSL)
     --ciphers LIST  SSL ciphers to use (SSL)
     --compressed    Request compressed response (using deflate or gzip)
 -K, --config FILE   Specify which config file to read
     --connect-timeout SECONDS  Maximum time allowed for connection
 -C, --continue-at OFFSET  Resumed transfer offset
 -b, --cookie STRING/FILE  String or file to read cookies from (H)
 -c, --cookie-jar FILE  Write cookies to this file after operation (H)
     --create-dirs   Create necessary local directory hierarchy
     --crlf          Convert LF to CRLF in upload
     --crlfile FILE  Get a CRL list in PEM format from the given file
 -d, --data DATA     HTTP POST data (H)
     --data-ascii DATA  HTTP POST ASCII data (H)
     --data-binary DATA  HTTP POST binary data (H)
     --data-urlencode DATA  HTTP POST data url encoded (H)
     --delegation STRING GSS-API delegation permission
     --digest        Use HTTP Digest Authentication (H)
     --disable-eprt  Inhibit using EPRT or LPRT (F)
     --disable-epsv  Inhibit using EPSV (F)
 -D, --dump-header FILE  Write the headers to this file
     --egd-file FILE  EGD socket path for random data (SSL)
     --engine ENGINGE  Crypto engine (SSL). "--engine list" for list
 -f, --fail          Fail silently (no output at all) on HTTP errors (H)
 -F, --form CONTENT  Specify HTTP multipart POST data (H)
     --form-string STRING  Specify HTTP multipart POST data (H)
     --ftp-account DATA  Account data string (F)
     --ftp-alternative-to-user COMMAND  String to replace "USER [name]" (F)
     --ftp-create-dirs  Create the remote dirs if not present (F)
     --ftp-method [MULTICWD/NOCWD/SINGLECWD] Control CWD usage (F)
     --ftp-pasv      Use PASV/EPSV instead of PORT (F)
 -P, --ftp-port ADR  Use PORT with given address instead of PASV (F)
     --ftp-skip-pasv-ip Skip the IP address for PASV (F)
     --ftp-pret      Send PRET before PASV (for drftpd) (F)
     --ftp-ssl-ccc   Send CCC after authenticating (F)
     --ftp-ssl-ccc-mode ACTIVE/PASSIVE  Set CCC mode (F)
     --ftp-ssl-control Require SSL/TLS for ftp login, clear for transfer (F)
 -G, --get           Send the -d data with a HTTP GET (H)
 -g, --globoff       Disable URL sequences and ranges using {} and []
 -H, --header LINE   Custom header to pass to server (H)
 -I, --head          Show document info only
 -h, --help          This help text
     --hostpubmd5 MD5  Hex encoded MD5 string of the host public key. (SSH)
 -0, --http1.0       Use HTTP 1.0 (H)
     --ignore-content-length  Ignore the HTTP Content-Length header
 -i, --include       Include protocol headers in the output (H/F)
 -k, --insecure      Allow connections to SSL sites without certs (H)
     --interface INTERFACE  Specify network interface/address to use
 -4, --ipv4          Resolve name to IPv4 address
 -6, --ipv6          Resolve name to IPv6 address
 -j, --junk-session-cookies Ignore session cookies read from file (H)
     --keepalive-time SECONDS  Interval between keepalive probes
     --key KEY       Private key file name (SSL/SSH)
     --key-type TYPE Private key file type (DER/PEM/ENG) (SSL)
     --krb LEVEL     Enable Kerberos with specified security level (F)
     --libcurl FILE  Dump libcurl equivalent code of this command line
     --limit-rate RATE  Limit transfer speed to this rate
 -l, --list-only     List only names of an FTP directory (F)
     --local-port RANGE  Force use of these local port numbers
 -L, --location      Follow redirects (H)
     --location-trusted like --location and send auth to other hosts (H)
 -M, --manual        Display the full manual
     --mail-from FROM  Mail from this address
     --mail-rcpt TO  Mail to this receiver(s)
     --mail-auth AUTH  Originator address of the original email
     --max-filesize BYTES  Maximum file size to download (H/F)
     --max-redirs NUM  Maximum number of redirects allowed (H)
 -m, --max-time SECONDS  Maximum time allowed for the transfer
     --negotiate     Use HTTP Negotiate Authentication (H)
 -n, --netrc         Must read .netrc for user name and password
     --netrc-optional Use either .netrc or URL; overrides -n
     --netrc-file FILE  Set up the netrc filename to use
 -N, --no-buffer     Disable buffering of the output stream
     --no-keepalive  Disable keepalive use on the connection
     --no-sessionid  Disable SSL session-ID reusing (SSL)
     --noproxy       List of hosts which do not use proxy
     --ntlm          Use HTTP NTLM authentication (H)
 -o, --output FILE   Write output to <file> instead of stdout
     --pass PASS     Pass phrase for the private key (SSL/SSH)
     --post301       Do not switch to GET after following a 301 redirect (H)
     --post302       Do not switch to GET after following a 302 redirect (H)
     --post303       Do not switch to GET after following a 303 redirect (H)
 -#, --progress-bar  Display transfer progress as a progress bar
     --proto PROTOCOLS  Enable/disable specified protocols
     --proto-redir PROTOCOLS  Enable/disable specified protocols on redirect
 -x, --proxy [PROTOCOL://]HOST[:PORT] Use proxy on given port
     --proxy-anyauth Pick "any" proxy authentication method (H)
     --proxy-basic   Use Basic authentication on the proxy (H)
     --proxy-digest  Use Digest authentication on the proxy (H)
     --proxy-negotiate Use Negotiate authentication on the proxy (H)
     --proxy-ntlm    Use NTLM authentication on the proxy (H)
 -U, --proxy-user USER[:PASSWORD]  Proxy user and password
     --proxy1.0 HOST[:PORT]  Use HTTP/1.0 proxy on given port
 -p, --proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)
     --pubkey KEY    Public key file name (SSH)
 -Q, --quote CMD     Send command(s) to server before transfer (F/SFTP)
     --random-file FILE  File for reading random data from (SSL)
 -r, --range RANGE   Retrieve only the bytes within a range
     --raw           Do HTTP "raw", without any transfer decoding (H)
 -e, --referer       Referer URL (H)
 -J, --remote-header-name Use the header-provided filename (H)
 -O, --remote-name   Write output to a file named as the remote file
     --remote-name-all Use the remote file name for all URLs
 -R, --remote-time   Set the remote file's time on the local output
 -X, --request COMMAND  Specify request command to use
     --resolve HOST:PORT:ADDRESS  Force resolve of HOST:PORT to ADDRESS
     --retry NUM   Retry request NUM times if transient problems occur
     --retry-delay SECONDS When retrying, wait this many seconds between each
     --retry-max-time SECONDS  Retry only within this period
 -S, --show-error    Show error. With -s, make curl show errors when they occur
 -s, --silent        Silent mode. Don't output anything
     --socks4 HOST[:PORT]  SOCKS4 proxy on given host + port
     --socks4a HOST[:PORT]  SOCKS4a proxy on given host + port
     --socks5 HOST[:PORT]  SOCKS5 proxy on given host + port
     --socks5-hostname HOST[:PORT] SOCKS5 proxy, pass host name to proxy
     --socks5-gssapi-service NAME  SOCKS5 proxy service name for gssapi
     --socks5-gssapi-nec  Compatibility with NEC SOCKS5 server
 -Y, --speed-limit RATE  Stop transfers below speed-limit for 'speed-time' secs
 -y, --speed-time SECONDS  Time for trig speed-limit abort. Defaults to 30
     --ssl           Try SSL/TLS (FTP, IMAP, POP3, SMTP)
     --ssl-reqd      Require SSL/TLS (FTP, IMAP, POP3, SMTP)
 -2, --sslv2         Use SSLv2 (SSL)
 -3, --sslv3         Use SSLv3 (SSL)
     --ssl-allow-beast Allow security flaw to improve interop (SSL)
     --stderr FILE   Where to redirect stderr. - means stdout
     --tcp-nodelay   Use the TCP_NODELAY option
 -t, --telnet-option OPT=VAL  Set telnet option
     --tftp-blksize VALUE  Set TFTP BLKSIZE option (must be >512)
 -z, --time-cond TIME  Transfer based on a time condition
 -1, --tlsv1         Use TLSv1 (SSL)
     --trace FILE    Write a debug trace to the given file
     --trace-ascii FILE  Like --trace but without the hex output
     --trace-time    Add time stamps to trace/verbose output
     --tr-encoding   Request compressed transfer encoding (H)
 -T, --upload-file FILE  Transfer FILE to destination
     --url URL       URL to work with
 -B, --use-ascii     Use ASCII/text transfer
 -u, --user USER[:PASSWORD]  Server user and password
     --tlsuser USER  TLS username
     --tlspassword STRING TLS password
     --tlsauthtype STRING  TLS authentication type (default SRP)
 -A, --user-agent STRING  User-Agent to send to server (H)
 -v, --verbose       Make the operation more talkative
 -V, --version       Show version number and quit
 -w, --write-out FORMAT  What to output after completion
     --xattr        Store metadata in extended file attributes
 -q                 If used as the first parameter disables .curlrc
 """


class Command_curl(HoneyPotCommand):
    """
    curl command
    """

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    outfile: str | None = None  # outfile is the file saved inside the honeypot
    artifact: (
        Artifact  # artifact is the file saved for forensics in the real file system
    )
    currentlength: int = 0  # partial size during download
    totallength: int = 0  # total length
    silent: bool = False
    head_request: bool = False
    url: bytes
    host: str
    port: int

    @inlineCallbacks
    def start(self):
        try:
            optlist, args = getopt.getopt(
                self.args, "sho:OI", ["help", "manual", "silent", "head"]
            )
        except getopt.GetoptError as err:
            # TODO: should be 'unknown' instead of 'not recognized'
            self.write(f"curl: {err}\n")
            self.write(
                "curl: try 'curl --help' or 'curl --manual' for more information\n"
            )
            self.exit()
            return

        for opt in optlist:
            if opt[0] == "-h" or opt[0] == "--help":
                self.write(CURL_HELP)
                self.exit()
                return
            elif opt[0] == "-s" or opt[0] == "--silent":
                self.silent = True
            elif opt[0] == "-I" or opt[0] == "--head":
                self.head_request = True

        if len(args):
            if args[0] is not None:
                url = str(args[0]).strip()
        else:
            self.write(
                "curl: try 'curl --help' or 'curl --manual' for more information\n"
            )
            self.exit()
            return

        if "://" not in url:
            url = "http://" + url
        urldata = parse.urlparse(url)

        for opt in optlist:
            if opt[0] == "-o":
                self.outfile = opt[1]
            if opt[0] == "-O":
                self.outfile = urldata.path.split("/")[-1]
                if (
                    self.outfile is None
                    or not len(self.outfile.strip())
                    or not urldata.path.count("/")
                ):
                    self.write("curl: Remote file name has no length!\n")
                    self.exit()
                    return

        if self.outfile:
            self.outfile = self.fs.resolve_path(self.outfile, self.protocol.cwd)
            if self.outfile:
                path = os.path.dirname(self.outfile)
            if not path or not self.fs.exists(path) or not self.fs.isdir(path):
                self.write(
                    f"curl: {self.outfile}: Cannot open: No such file or directory\n"
                )
                self.exit()
                return

        self.url = url.encode("ascii")

        parsed = parse.urlparse(url)
        if parsed.scheme:
            scheme = parsed.scheme
        if scheme != "http" and scheme != "https":
            self.errorWrite(
                f'curl: (1) Protocol "{scheme}" not supported or disabled in libcurl\n'
            )
            self.exit()
            return
        if parsed.hostname:
            self.host = parsed.hostname
        else:
            self.errorWrite(
                f'curl: (1) Protocol "{scheme}" not supported or disabled in libcurl\n'
            )
            self.exit()
        self.port = parsed.port or (443 if scheme == "https" else 80)

        allowed = yield communication_allowed(self.host)
        if not allowed:
            log.msg("Attempt to access blocked network address")
            self.errorWrite(f"curl: (6) Could not resolve host: {self.host}\n")
            self.exit()
            return None

        self.artifact = Artifact("curl-download")

        self.deferred = self.treqDownload(url)
        if self.deferred:
            self.deferred.addCallback(self.success)
            self.deferred.addErrback(self.error)

    def treqDownload(self, url):
        """
        Download `url`
        """
        headers = {"User-Agent": ["curl/7.38.0"]}

        # TODO: use designated outbound interface
        # out_addr = None
        # if CowrieConfig.has_option("honeypot", "out_addr"):
        #     out_addr = (CowrieConfig.get("honeypot", "out_addr"), 0)
        if self.head_request:
            deferred = treq.head(url=url, allow_redirects=False, headers=headers, timeout=10)
        else:
            deferred = treq.get(url=url, allow_redirects=False, headers=headers, timeout=10)
        return deferred

    def handle_CTRL_C(self) -> None:
        self.write("^C\n")
        self.exit()

    def success(self, response):
        """
        successful treq get
        """
        self.totallength = response.length
        # TODO possible this is UNKNOWN_LENGTH

        if self.head_request:
            reason = responses.get(response.code, "")
            self.write(f"HTTP/1.1 {response.code} {reason}\n")
            for key, values in response.headers.getAllRawHeaders():
                decoded_key = key.decode() if isinstance(key, bytes) else key
                for value in values:
                    decoded_value = value.decode() if isinstance(value, bytes) else value
                    self.write(f"{decoded_key}: {decoded_value}\n")
            self.exit()
            return

        if self.limit_size > 0 and self.totallength > self.limit_size:
            log.msg(
                f"Not saving URL ({self.url.decode()}) (size: {self.totallength}) exceeds file size limit ({self.limit_size})"
            )
            self.exit()
            return

        if self.outfile and not self.silent:
            self.write(
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            )
            self.write(
                "                                 Dload  Upload   Total   Spent    Left  Speed\n"
            )

        deferred = treq.collect(response, self.collect)
        deferred.addCallback(self.collectioncomplete)
        return deferred

    def collect(self, data: bytes) -> None:
        """
        partial collect
        """
        self.currentlength += len(data)
        if self.limit_size > 0 and self.currentlength > self.limit_size:
            log.msg(
                f"Not saving URL ({self.url.decode()}) (size: {self.currentlength}) exceeds file size limit ({self.limit_size})"
            )
            self.exit()
            return

        self.artifact.write(data)

        if self.outfile and not self.silent:
            self.write(
                f"\r100  {self.currentlength}  100  {self.currentlength}    0     0  {63673}      0 --:--:-- --:--:-- --:--:-- {65181}"
            )

        if not self.outfile:
            self.writeBytes(data)

    def collectioncomplete(self, data: None) -> None:
        """
        this gets called once collection is complete
        """
        self.artifact.close()

        if self.outfile and not self.silent:
            self.write("\n")

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
        handle any exceptions
        """

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download.failed",
            format="Attempt to download file(s) from URL (%(url)s) failed",
            url=self.url.decode(),
        )
        log.msg(
            eventid="cowrie.session.file_download.failed",
            format="Attempt to download file(s) from URL (%(url)s) failed",
            url=self.url.decode(),
        )

        if response.check(error.DNSLookupError) is not None:
            self.write(f"curl: (6) Could not resolve host: {self.host}\n")
            self.exit()
            return

        elif response.check(error.ConnectingCancelledError) is not None:
            self.write(
                f"curl: (7) Failed to connect to {self.host} port {self.port}: Operation timed out\n"
            )
            self.exit()
            return

        elif response.check(error.ConnectionRefusedError) is not None:
            self.write(
                f"curl: (7) Failed to connect to {self.host} port {self.port}: Connection refused\n"
            )
            self.exit()
            return

        # possible errors:
        # defer.CancelledError,
        # error.ConnectingCancelledError,

        log.msg(response.printTraceback())
        if hasattr(response, "getErrorMessage"):  # Exceptions
            errormsg = response.getErrorMessage()
        log.msg(errormsg)
        self.write("\n")

        self.exit()


commands["/usr/bin/curl"] = Command_curl
commands["curl"] = Command_curl
