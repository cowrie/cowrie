from __future__ import division, absolute_import

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
    def __init__(self, protocol,
                 prog=None,
                 usage=None,
                 description=None,
                 epilog=None,
                 version=None,
                 parents=[],
                 formatter_class=argparse.HelpFormatter,
                 prefix_chars='-',
                 fromfile_prefix_chars=None,
                 argument_default=None,
                 conflict_handler='error',
                 add_help=True):
        self.protocol = protocol
        super(CustomParser, self).__init__(prog,
                                           usage,
                                           description,
                                           epilog,
                                           version,
                                           parents,
                                           formatter_class,
                                           prefix_chars,
                                           fromfile_prefix_chars,
                                           argument_default,
                                           conflict_handler,
                                           add_help)

    def exit(self, status=0, message=None):
        raise ExitException("Exiting...")


    def _print_message(self, message, file=None):
        super(CustomParser,self)._print_message(message, self.protocol)

    def error(self, message):
        self.print_usage(self.protocol)
        raise OptionNotFound("Sorry no option found")
