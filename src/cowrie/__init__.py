# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import sys

try:
    import cowrie._version as cowrie_version

    __version__ = cowrie_version
except ModuleNotFoundError:
    # This runs before any log observer exists and exits immediately, so
    # the logging system would swallow it; write straight to stderr.
    print(  # noqa: T201
        "Cowrie is not installed. Run `pip install -e .` to install Cowrie"
        " into your virtual enviroment",
        file=sys.stderr,
    )
    sys.exit(1)
