from __future__ import annotations
import argparse


class OptionNotFound(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ExitException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class CustomParser(argparse.ArgumentParser):
    def __init__(
        self,
        protocol,
        prog=None,
        usage=None,
        description=None,
        epilog=None,
        parents=None,
        formatter_class=argparse.HelpFormatter,
        prefix_chars="-",
        fromfile_prefix_chars=None,
        argument_default=None,
        conflict_handler="error",
        add_help=True,
    ):
        self.protocol = protocol
        if parents is None:
            parents = []
        super().__init__(
            prog=prog,
            usage=usage,
            description=description,
            epilog=epilog,
            parents=parents,
            formatter_class=formatter_class,
            prefix_chars=prefix_chars,
            fromfile_prefix_chars=fromfile_prefix_chars,
            argument_default=argument_default,
            conflict_handler=conflict_handler,
            add_help=add_help,
        )

    def exit(self, status=0, message=None):
        raise ExitException("Exiting...")

    def _print_message(self, message, file=None):
        super()._print_message(message, self.protocol)

    def error(self, message):
        self.print_usage(self.protocol)
        raise OptionNotFound("Sorry no option found")
