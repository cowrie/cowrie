# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import random
import re
from typing import Any, Optional
from collections.abc import Callable

from twisted.internet import defer, reactor
from twisted.internet.defer import inlineCallbacks

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_faked_package_class_factory:
    @staticmethod
    def getCommand(name: str) -> Callable:
        class Command_faked_installation(HoneyPotCommand):
            def call(self) -> None:
                self.write(f"{name}: Segmentation fault\n")

        return Command_faked_installation


class Command_aptget(HoneyPotCommand):
    """
    apt-get fake
    suppports only the 'install PACKAGE' command & 'moo'.
    Any installed packages, places a 'Segfault' at /usr/bin/PACKAGE.'''
    """

    packages: dict[str, dict[str, Any]]

    def start(self) -> None:
        if len(self.args) == 0:
            self.do_help()
        elif len(self.args) > 0 and self.args[0] == "-v":
            self.do_version()
        elif len(self.args) > 0 and self.args[0] == "install":
            self.do_install()
        elif len(self.args) > 0 and self.args[0] == "moo":
            self.do_moo()
        else:
            self.do_locked()
        self.packages = {}

    def sleep(self, time: float, time2: Optional[float] = None) -> defer.Deferred:
        d: defer.Deferred = defer.Deferred()
        if time2:
            time = random.randint(int(time * 100), int(time2 * 100.0)) / 100.0
        reactor.callLater(time, d.callback, None)  # type: ignore[attr-defined]
        return d

    def do_version(self) -> None:
        self.write(
            """apt 1.0.9.8.1 for amd64 compiled on Jun 10 2015 09:42:06
Supported modules:
*Ver: Standard .deb
*Pkg:  Debian dpkg interface (Priority 30)
 Pkg:  Debian APT solver interface (Priority -1000)
 S.L: 'deb' Standard Debian binary tree
 S.L: 'deb-src' Standard Debian source tree
 Idx: Debian Source Index
 Idx: Debian Package Index
 Idx: Debian Translation Index
 Idx: Debian dpkg status file
 Idx: EDSP scenario file\n"""
        )
        self.exit()

    def do_help(self) -> None:
        self.write(
            """apt 1.0.9.8.1 for amd64 compiled on Jun 10 2015 09:42:06
Usage: apt-get [options] command
       apt-get [options] install|remove pkg1 [pkg2 ...]
       apt-get [options] source pkg1 [pkg2 ...]

apt-get is a simple command line interface for downloading and
installing packages. The most frequently used commands are update
and install.

Commands:
   update - Retrieve new lists of packages
   upgrade - Perform an upgrade
   install - Install new packages (pkg is libc6 not libc6.deb)
   remove - Remove packages
   autoremove - Remove automatically all unused packages
   purge - Remove packages and config files
   source - Download source archives
   build-dep - Configure build-dependencies for source packages
   dist-upgrade - Distribution upgrade, see apt-get(8)
   dselect-upgrade - Follow dselect selections
   clean - Erase downloaded archive files
   autoclean - Erase old downloaded archive files
   check - Verify that there are no broken dependencies
   changelog - Download and display the changelog for the given package
   download - Download the binary package into the current directory

Options:
  -h  This help text.
  -q  Loggable output - no progress indicator
  -qq No output except for errors
  -d  Download only - do NOT install or unpack archives
  -s  No-act. Perform ordering simulation
  -y  Assume Yes to all queries and do not prompt
  -f  Attempt to correct a system with broken dependencies in place
  -m  Attempt to continue if archives are unlocatable
  -u  Show a list of upgraded packages as well
  -b  Build the source package after fetching it
  -V  Show verbose version numbers
  -c=? Read this configuration file
  -o=? Set an arbitrary configuration option, eg -o dir::cache=/tmp
See the apt-get(8), sources.list(5) and apt.conf(5) manual
pages for more information and options.
                       This APT has Super Cow Powers.\n"""
        )
        self.exit()

    @inlineCallbacks
    def do_install(self, *args):
        if len(self.args) <= 1:
            msg = "0 upgraded, 0 newly installed, 0 to remove and {0} not upgraded.\n"
            self.write(msg.format(random.randint(200, 300)))
            self.exit()
            return

        for y in [re.sub("[^A-Za-z0-9]", "", x) for x in self.args[1:]]:
            self.packages[y] = {
                "version": "{}.{}-{}".format(
                    random.choice([0, 1]), random.randint(1, 40), random.randint(1, 10)
                ),
                "size": random.randint(100, 900),
            }
        totalsize: int = sum(self.packages[x]["size"] for x in self.packages)

        self.write("Reading package lists... Done\n")
        self.write("Building dependency tree\n")
        self.write("Reading state information... Done\n")
        self.write("The following NEW packages will be installed:\n")
        self.write("  %s " % " ".join(self.packages) + "\n")
        self.write(
            "0 upgraded, %d newly installed, 0 to remove and 259 not upgraded.\n"
            % len(self.packages)
        )
        self.write("Need to get %s.2kB of archives.\n" % (totalsize))
        self.write(
            "After this operation, {:.1f}kB of additional disk space will be used.\n".format(
                totalsize * 2.2
            )
        )
        i = 1
        for p in self.packages:
            self.write(
                "Get:%d http://ftp.debian.org stable/main %s %s [%s.2kB]\n"
                % (i, p, self.packages[p]["version"], self.packages[p]["size"])
            )
            i += 1
            yield self.sleep(1, 2)
        self.write(f"Fetched {totalsize}.2kB in 1s (4493B/s)\n")
        self.write("Reading package fields... Done\n")
        yield self.sleep(1, 2)
        self.write("Reading package status... Done\n")
        self.write(
            "(Reading database ... 177887 files and directories currently installed.)\n"
        )
        yield self.sleep(1, 2)
        for p in self.packages:
            self.write(
                "Unpacking {} (from .../archives/{}_{}_i386.deb) ...\n".format(
                    p, p, self.packages[p]["version"]
                )
            )
            yield self.sleep(1, 2)
        self.write("Processing triggers for man-db ...\n")
        yield self.sleep(2)
        for p in self.packages:
            self.write(
                "Setting up {} ({}) ...\n".format(p, self.packages[p]["version"])
            )
            self.fs.mkfile("/usr/bin/%s" % p, 0, 0, random.randint(10000, 90000), 33188)
            self.protocol.commands[
                "/usr/bin/%s" % p
            ] = Command_faked_package_class_factory.getCommand(p)
            yield self.sleep(2)
        self.exit()

    def do_moo(self) -> None:
        self.write("         (__)\n")
        self.write("         (oo)\n")
        self.write("   /------\\/\n")
        self.write("  / |    ||\n")
        self.write(" *  /\\---/\\ \n")
        self.write("    ~~   ~~\n")
        self.write('...."Have you mooed today?"...\n')
        self.exit()

    def do_locked(self) -> None:
        self.errorWrite(
            "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n"
        )
        self.errorWrite("E: Unable to lock the list directory\n")
        self.exit()


commands["/usr/bin/apt-get"] = Command_aptget
commands["apt-get"] = Command_aptget
