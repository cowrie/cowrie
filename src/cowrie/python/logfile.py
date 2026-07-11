# SPDX-FileCopyrightText: 2018-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import sys
from os import environ
from pathlib import Path
from typing import TYPE_CHECKING, Any

from twisted.logger import (
    FilteringLogObserver,
    InvalidLogLevelError,
    Logger,
    LogLevel,
    LogLevelFilterPredicate,
    textFileLogObserver,
)
from twisted.python import context, logfile
from twisted.python.log import ILogContext

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Callable

_log = Logger()

# The [honeypot] option carrying the default diagnostic level, and the
# prefix for per-namespace overrides (log_level_cowrie.ssh = debug).
LOG_LEVEL_OPTION = "log_level"
NAMESPACE_PREFIX = LOG_LEVEL_OPTION + "_"
ENVIRONMENT_PREFIX = "COWRIE_HONEYPOT_LOG_LEVEL_"

# The console renderer's namespace for attacker-event lines. It gets an
# explicit info floor so a global log_level = warn quiets diagnostics
# without silently erasing the attack record from cowrie.log; operators
# who really want event lines gone set log_level_cowrie.events themselves.
EVENTS_NAMESPACE = "cowrie.events"


class CowrieDailyLogFile(logfile.DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate: float | tuple[int, int, int]) -> str:
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        if isinstance(tupledate, tuple):
            return f"{tupledate[0]:02d}-{tupledate[1]:02d}-{tupledate[2]:02d}"
        if isinstance(tupledate, float):
            return "_".join(map(str, self.toDate(tupledate)))
        raise TypeError


def _logLevel(name: str, option: str, fallback: LogLevel) -> LogLevel:
    try:
        level: LogLevel = LogLevel.levelWithName(name.strip().lower())
    except InvalidLogLevelError:
        _log.warn(
            "Invalid log level {name!r} for [honeypot] {option}; using {fallback}",
            name=name,
            option=option,
            fallback=fallback.name,
        )
        return fallback
    return level


def levelPredicate() -> LogLevelFilterPredicate:
    """
    The diagnostic verbosity for the log output, from configuration:
    [honeypot] log_level sets the default (info unless configured), and
    log_level_<namespace> options override per subsystem, e.g.
    ``log_level_cowrie.ssh = debug``. Namespaces are matched by dotted
    prefix, so a module-level override covers the classes within it.
    Note that configparser lowercases option names, so overrides work at
    module granularity (module paths are lowercase); a class-qualified
    namespace cannot be targeted directly. Environment variables
    (``COWRIE_HONEYPOT_LOG_LEVEL_<namespace>``) override the same way.
    """
    default = _logLevel(
        CowrieConfig.get("honeypot", LOG_LEVEL_OPTION, fallback="info"),
        LOG_LEVEL_OPTION,
        LogLevel.info,
    )
    predicate = LogLevelFilterPredicate(defaultLogLevel=default)
    configured: set[str] = set()
    for option in CowrieConfig.options("honeypot"):
        if option.startswith(NAMESPACE_PREFIX):
            namespace = option[len(NAMESPACE_PREFIX) :]
            level = _logLevel(CowrieConfig.get("honeypot", option), option, default)
            predicate.setLogLevelForNamespace(namespace, level)
            configured.add(namespace)
    # options() cannot see environment-only keys, so scan them directly;
    # the environment wins over the file, matching EnvironmentConfigParser.
    for key, value in environ.items():
        if key.startswith(ENVIRONMENT_PREFIX):
            namespace = key[len(ENVIRONMENT_PREFIX) :].lower()
            level = _logLevel(value, key, default)
            predicate.setLogLevelForNamespace(namespace, level)
            configured.add(namespace)
    if EVENTS_NAMESPACE not in configured:
        predicate.setLogLevelForNamespace(EVENTS_NAMESPACE, LogLevel.info)
    return predicate


def _observer(outFile: Any) -> Callable[[dict], None]:
    """
    The rendering pipeline shared by the file and stdout loggers:
    stamp the legacy connection prefix, filter by configured level,
    render classic log text.
    """
    # use Z for UTC (Zulu) time, it's shorter.
    if "TZ" in environ and environ["TZ"] == "UTC":
        timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
    else:
        timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"

    filtered = FilteringLogObserver(
        textFileLogObserver(outFile, timeFormat=timeFormat),
        [levelPredicate()],
    )

    def annotated(event: dict) -> None:
        # twisted.logger does not read the reactor's ILogContext, so a
        # Logger line emitted inside a connection's context would render
        # under its namespace instead of the [HoneyPotSSHTransport,3,ip]
        # prefix legacy log.msg inherited. Restore that prefix so
        # diagnostics stay correlatable to a session; lines outside any
        # connection context keep their namespace#level prefix.
        # (Levels still filter by namespace either way.)
        if "log_system" not in event:
            system = (context.get(ILogContext) or {}).get("system", "-")
            if system != "-":
                event = {**event, "log_system": system}
        filtered(event)

    return annotated


def logger() -> Callable[[dict], None]:
    """
    Custom logger that can log in a defined timezone and with custom
    roll over properties
    """
    directory = CowrieConfig.get("honeypot", "log_path", fallback=".")

    logtype = CowrieConfig.get("honeypot", "logtype", fallback="plain")
    cowrielog: Any
    if logtype == "rotating":
        cowrielog = CowrieDailyLogFile("cowrie.log", directory)
    elif logtype == "plain":
        cowrielog = open(Path(directory, "cowrie.log"), "a", encoding="utf-8")
    else:
        raise ValueError

    return _observer(cowrielog)


def stdoutLogger() -> Callable[[dict], None]:
    """
    The same filtered, session-prefixed rendering as ``logger()``, to
    stdout: used by ``COWRIE_STDOUT=yes`` and the Docker entry point so
    the log_level configuration applies there too.
    """
    return _observer(sys.stdout)
