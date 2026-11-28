# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_php(HoneyPotCommand):
    HELP = (
        "Usage: php [options] [-f] <file> [--] [args...]\n"
        "       php [options] -r <code> [--] [args...]\n"
        "       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]\n"
        "       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]\n"
        "       php [options] -- [args...]\n"
        "       php [options] -a\n"
        "\n"
        "  -a               Run interactively\n"
        "  -c <path>|<file> Look for php.ini file in this directory\n"
        "  -n               No php.ini file will be used\n"
        "  -d foo[=bar]     Define INI entry foo with value 'bar'\n"
        "  -e               Generate extended information for debugger/profiler\n"
        "  -f <file>        Parse and execute <file>.\n"
        "  -h               This help\n"
        "  -i               PHP information\n"
        "  -l               Syntax check only (lint)\n"
        "  -m               Show compiled in modules\n"
        "  -r <code>        Run PHP <code> without using script tags <?..?>\n"
        "  -B <begin_code>  Run PHP <begin_code> before processing input lines\n"
        "  -R <code>        Run PHP <code> for every input line\n"
        "  -F <file>        Parse and execute <file> for every input line\n"
        "  -E <end_code>    Run PHP <end_code> after processing all input lines\n"
        "  -H               Hide any passed arguments from external tools.\n"
        "  -s               Output HTML syntax highlighted source.\n"
        "  -v               Version number\n"
        "  -w               Output source with stripped comments and whitespace.\n"
        "  -z <file>        Load Zend extension <file>.\n"
        "\n"
        "  args...          Arguments passed to script. Use -- args when first argument\n"
        "                   starts with - or script is read from stdin\n"
        "\n"
        "  --ini            Show configuration file names\n"
        "\n"
        "  --rf <name>      Show information about function <name>.\n"
        "  --rc <name>      Show information about class <name>.\n"
        "  --re <name>      Show information about extension <name>.\n"
        "  --ri <name>      Show configuration for extension <name>.\n"
        "\n"
    )

    VERSION = "PHP 5.3.5 (cli)\nCopyright (c) 1997-2010 The PHP Group\n"

    def start(self) -> None:
        if self.args:
            if self.args[0] == "-v":
                self.write(Command_php.VERSION)
            elif self.args[0] == "-h":
                self.write(Command_php.HELP)
            self.exit()

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.success",
            "INPUT (%(realm)s): %(input)s",
            realm="php",
            input=line,
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/php"] = Command_php
commands["php"] = Command_php
