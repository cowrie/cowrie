# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import sys

from twisted.python import log

try:
    import cowrie._version as cowrie_version

    __version__ = cowrie_version
except ModuleNotFoundError:
    log.err(
        "Cowrie is not installed. Run `pip install -e .` to install Cowrie into your virtual enviroment"
    )
    sys.exit(1)
