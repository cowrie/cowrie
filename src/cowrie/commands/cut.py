# ABOUTME: Emulates the GNU cut command for the honeypot shell.
# ABOUTME: Supports field selection (-f), custom delimiters (-d), and suppress mode (-s).

from __future__ import annotations

import getopt

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_cut(HoneyPotCommand):
    """
    cut command
    """

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "d:f:b:c:s", ["help", "version", "delimiter=", "fields="]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"cut: invalid option -- '{err.opt}'\n")
            self.errorWrite("Try 'cut --help' for more information.\n")
            self.exit()
            return

        delimiter = "\t"
        field_spec = None
        suppress = False

        for opt, val in optlist:
            if opt == "--help":
                self.help()
                self.exit()
                return
            elif opt == "--version":
                self.write("cut (GNU coreutils) 8.30\n")
                self.exit()
                return
            elif opt in ("-d", "--delimiter"):
                delimiter = val
            elif opt in ("-f", "--fields"):
                field_spec = val
            elif opt == "-s":
                suppress = True
            elif opt in ("-b", "-c"):
                # Accept but don't implement byte/character mode
                field_spec = val

        if field_spec is None:
            self.errorWrite(
                "cut: you must specify a list of bytes, characters, or fields\n"
            )
            self.errorWrite("Try 'cut --help' for more information.\n")
            self.exit()
            return

        self.delimiter = delimiter
        self.field_spec = field_spec
        self.suppress = suppress
        self.field_indices = self._parse_field_spec(field_spec)

        if self.input_data:
            self._process(self.input_data)
            self.exit()
        elif args:
            for arg in args:
                pname = self.fs.resolve_path(arg, self.protocol.cwd)
                try:
                    contents = self.fs.file_contents(pname)
                    self._process(contents)
                except Exception:
                    self.errorWrite(f"cut: {arg}: No such file or directory\n")
            self.exit()
        # else: wait for stdin via lineReceived / CTRL-D

    def _parse_field_spec(self, spec: str) -> list[tuple[int, int | None]]:
        """Parse a field specification like '1,3' or '2-4' or '1,3-' into ranges.

        Returns a list of (start, end) tuples where indices are 0-based.
        end=None means 'to the end of the line'.
        """
        ranges: list[tuple[int, int | None]] = []
        for part in spec.split(","):
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start = int(start_s) - 1 if start_s else 0
                end: int | None = int(end_s) if end_s else None
                ranges.append((start, end))
            else:
                idx = int(part) - 1
                ranges.append((idx, idx + 1))
        return ranges

    def _select_fields(self, fields: list[str]) -> list[str]:
        """Select fields based on the parsed field specification."""
        selected: list[str] = []
        for start, end in self.field_indices:
            if end is None:
                selected.extend(fields[start:])
            else:
                selected.extend(fields[start:end])
        return selected

    def _process(self, data: bytes) -> None:
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        for line in lines:
            line_str = line.decode("utf-8", errors="replace")
            if self.delimiter not in line_str:
                if not self.suppress:
                    self.write(line_str + "\n")
                continue
            fields = line_str.split(self.delimiter)
            selected = self._select_fields(fields)
            self.write(self.delimiter.join(selected) + "\n")

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="cut",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        self._process(line.encode("utf-8"))

    def handle_CTRL_D(self) -> None:
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: cut OPTION... [FILE]...
Print selected parts of lines from each FILE to standard output.

With no FILE, or when FILE is -, read standard input.

Mandatory arguments to long options are mandatory for short options too.
  -b, --bytes=LIST        select only these bytes
  -c, --characters=LIST   select only these characters
  -d, --delimiter=DELIM   use DELIM instead of TAB for field delimiter
  -f, --fields=LIST       select only these fields;  also print any line
                            that contains no delimiter character, unless
                            the -s option is specified
  -s, --only-delimited    do not print lines not containing delimiters
      --help     display this help and exit
      --version  output version information and exit

Use one, and only one of -b, -c or -f.  Each LIST is made up of one
range, or many ranges separated by commas.

Each range is one of:
  N     N'th byte, character or field, counted from 1
  N-    from N'th byte, character or field, to end of line
  N-M   from N'th to M'th (included) byte, character or field
  -M    from first to M'th (included) byte, character or field

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/cut>
or available locally via: info '(coreutils) cut invocation'
"""
        )


commands["/usr/bin/cut"] = Command_cut
commands["/bin/cut"] = Command_cut
commands["cut"] = Command_cut
