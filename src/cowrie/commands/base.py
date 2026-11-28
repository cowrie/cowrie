# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Small built-in commands (whoami, id, date, yes, history, set, ...)
# ABOUTME: that do not need a module of their own.

# coding=utf-8

from __future__ import annotations

import datetime
import time
from typing import TYPE_CHECKING

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import LoopSignal

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_whoami(HoneyPotCommand):
    def call(self) -> None:
        self.write(f"{self.user['username']}\n")


commands["/usr/bin/whoami"] = Command_whoami
commands["whoami"] = Command_whoami
commands["/usr/bin/users"] = Command_whoami
commands["users"] = Command_whoami


class Command_help(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            """GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.
Use `man -k' or `info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                                                                                   history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]
 (( expression ))                                                                               if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi
 . filename [arguments]                                                                         jobs [-lnprs] [jobspec ...] or jobs -x command [args]
 :                                                                                              kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]
 [ arg... ]                                                                                     let arg [arg ...]
 [[ expression ]]                                                                               local [option] name[=value] ...
 alias [-p] [name[=value] ... ]                                                                 logout [n]
 bg [job_spec ...]                                                                              mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 bind [-lpvsPVS] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-c>  popd [-n] [+N | -N]
 break [n]                                                                                      printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]]                                                              pushd [-n] [+N | -N | dir]
 caller [expr]                                                                                  pwd [-LP]
 case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac                                     read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout>
 cd [-L|[-P [-e]]] [dir]                                                                        readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]>
 command [-pVv] command [arg ...]                                                               readonly [-aAf] [name[=value] ...] or readonly -p
 compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F>  select NAME [in WORDS ... ;] do COMMANDS; done
 compopt [-o|+o option] [-DE] [name ...]                                                        set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]
 continue [n]                                                                                   shift [n]
 coproc [NAME] command [redirections]                                                           shopt [-pqsu] [-o] [optname ...]
 declare [-aAfFgilrtux] [-p] [name[=value] ...]                                                 source filename [arguments]
 dirs [-clpv] [+N] [-N]                                                                         suspend [-f]
 disown [-h] [-ar] [jobspec ...]                                                                test [expr]
 echo [-neE] [arg ...]                                                                          time [-p] pipeline
 enable [-a] [-dnps] [-f filename] [name ...]                                                   times
 eval [arg ...]                                                                                 trap [-lp] [[arg] signal_spec ...]
 exec [-cl] [-a name] [command [arguments ...]] [redirection ...]                               true
 exit [n]                                                                                       type [-afptP] name [name ...]
 export [-fn] [name[=value] ...] or export -p                                                   typeset [-aAfFgilrtux] [-p] name[=value] ...
 false                                                                                          ulimit [-SHacdefilmnpqrstuvx] [limit]
 fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]                               umask [-p] [-S] [mode]
 fg [job_spec]                                                                                  unalias [-a] name [name ...]
 for NAME [in WORDS ... ] ; do COMMANDS; done                                                   unset [-f] [-v] [name ...]
 for (( exp1; exp2; exp3 )); do COMMANDS; done                                                  until COMMANDS; do COMMANDS; done
 function name { COMMANDS ; } or name () { COMMANDS ; }                                         variables - Names and meanings of some shell variables
 getopts optstring name [arg]                                                                   wait [id]
 hash [-lr] [-p pathname] [-dt] [name ...]                                                      while COMMANDS; do COMMANDS; done
 help [-dms] [pattern ...]                                                                      { COMMANDS ; }\n"""
        )


commands["help"] = Command_help


class Command_w(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f" {time.strftime('%H:%M:%S')} up {utils.uptime(self.protocol.uptime())},  1 user,  load average: 0.00, 0.00, 0.00\n"
        )
        self.write(
            "USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        )
        self.write(
            f"{self.user['username']:8s} pts/0    {self.protocol.clientIP[:17].ljust(17)} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))}    0.00s  0.00s  0.00s w\n"
        )


commands["/usr/bin/w"] = Command_w
commands["w"] = Command_w


class Command_who(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f"{self.user['username']:8s} pts/0        {time.strftime('%Y-%m-%d', time.localtime(self.protocol.logintime))} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))} ({self.protocol.clientIP})\n"
        )


commands["/usr/bin/who"] = Command_who
commands["who"] = Command_who


class Command_clear(HoneyPotCommand):
    def call(self) -> None:
        self.protocol.terminal.reset()


commands["/usr/bin/clear"] = Command_clear
commands["clear"] = Command_clear
commands["/usr/bin/reset"] = Command_clear
commands["reset"] = Command_clear


class Command_hostname(HoneyPotCommand):
    def call(self) -> None:
        if self.args:
            if self.user["uid"] == 0:
                self.protocol.hostname = self.args[0]
            else:
                self.write("hostname: you must be root to change the host name\n")
        else:
            self.write(f"{self.protocol.hostname}\n")


commands["/bin/hostname"] = Command_hostname
commands["hostname"] = Command_hostname


class Command_id(HoneyPotCommand):
    def call(self) -> None:
        u = self.user
        self.write(
            f"uid={u['uid']}({u['username']}) gid={u.get('gid', u['uid'])}({u['username']}) groups={u.get('gid', u['uid'])}({u['username']})\n"
        )


commands["/usr/bin/id"] = Command_id
commands["id"] = Command_id


class Command_history(HoneyPotCommand):
    def call(self) -> None:
        try:
            if self.args and self.args[0] == "-c":
                self.protocol.historyLines = []
                self.protocol.historyPosition = 0
                return
            count = 1
            for line in self.protocol.historyLines:
                # A typed line need not be valid UTF-8.
                self.write(f" {count:4d}  {line.decode(errors='replace')}\n")
                count += 1
        except Exception:
            # Non-interactive shell, do nothing
            pass


commands["history"] = Command_history


class Command_date(HoneyPotCommand):
    def call(self) -> None:
        time = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        self.write(f"{time.strftime('%a %b %d %H:%M:%S UTC %Y')}\n")


commands["/bin/date"] = Command_date
commands["date"] = Command_date


class Command_yes(HoneyPotCommand):
    def start(self) -> None:
        self.y()

    def y(self) -> None:
        if self.args:
            self.write(f"{' '.join(self.args)}\n")
        else:
            self.write("y\n")
        self.callLater(0.01, self.y)


commands["/usr/bin/yes"] = Command_yes
commands["yes"] = Command_yes


class Command_chattr(HoneyPotCommand):
    def call(self) -> None:
        if len(self.args) < 1:
            self.write("Usage: chattr [-RVf] [-+=AacDdeijsSu] [-v version] files...\n")
            return
        elif len(self.args) < 2:
            self.write("Must use '-v', =, - or +'\n")
            return
        if not self.fs.exists(self.args[1]):
            self.write(
                "chattr: No such file or directory while trying to stat "
                + self.args[1]
                + "\n"
            )


commands["/usr/bin/chattr"] = Command_chattr
commands["chattr"] = Command_chattr


class Command_set(HoneyPotCommand):
    """
    With operands, replace the positional parameters. Options (-e, +x,
    -o name ...) are accepted and ignored. With no arguments, list the
    shell's variables.
    """

    # This will show ALL environ vars, not only the global ones
    # With enhancements it should work like env when -o posix is used
    def call(self) -> None:
        if not self.args:
            self.list_variables()
            return
        args = iter(self.args)
        for arg in args:
            if arg == "--":
                self.shell.replace_positional_params(list(args))
                return
            if arg[:1] not in ("-", "+"):
                self.shell.replace_positional_params([arg, *args])
                return
            if arg in ("-o", "+o"):
                next(args, None)

    def list_variables(self) -> None:
        for i in sorted(self.environ):
            # Positional parameters live in environ but are not variables.
            if i.isdigit() or i in ("#", "@", "*"):
                continue
            self.write(f"{i}={self.environ[i]}\n")


commands["set"] = Command_set


class Command_export(HoneyPotCommand):
    """
    Mark shell variables for export so they appear in the environment of
    child processes. With no operands, list the exported variables.
    """

    def call(self) -> None:
        args = [a for a in self.args if a != "-p"]
        if not args:
            for name in sorted(self.exported):
                self.write(f'declare -x {name}="{self.environ.get(name, "")}"\n')
            return
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.environ[key] = val
                self.exported.add(key)
            else:
                self.exported.add(arg)


commands["export"] = Command_export


class Command_unset(HoneyPotCommand):
    """
    Remove variables from both the shell and the exported environment.
    """

    def call(self) -> None:
        for arg in self.args:
            if arg.startswith("-"):
                continue
            self.environ.pop(arg, None)
            self.exported.discard(arg)


commands["unset"] = Command_unset


class Command_nop(HoneyPotCommand):
    def call(self) -> None:
        pass


commands["umask"] = Command_nop
commands["alias"] = Command_nop
commands["jobs"] = Command_nop
commands["kill"] = Command_nop
commands["/bin/kill"] = Command_nop
commands["/bin/pkill"] = Command_nop
commands["/bin/killall"] = Command_nop
commands["/bin/killall5"] = Command_nop
commands["/bin/chown"] = Command_nop
commands["chown"] = Command_nop
commands["/bin/chgrp"] = Command_nop
commands["chgrp"] = Command_nop
commands[":"] = Command_nop
commands["do"] = Command_nop
commands["done"] = Command_nop


class Command_true(HoneyPotCommand):
    """The ``true`` utility: do nothing, successfully (exit 0)."""

    def start(self) -> None:
        self.exit(0)


commands["true"] = Command_true
commands["/bin/true"] = Command_true


class Command_false(HoneyPotCommand):
    """The ``false`` utility: do nothing, unsuccessfully (exit 1)."""

    def start(self) -> None:
        self.exit(1)


commands["false"] = Command_false
commands["/bin/false"] = Command_false


class Command_break(HoneyPotCommand):
    """``break`` -- stop the innermost enclosing for/while/until loop.

    Signals the shell running it; the loop's executor consumes the signal at
    the end of the current body. Only loops of that shell in the running
    function count: a function call, a subshell and a child shell start with
    none. Without a loop, bash reports the misuse and carries on with status 0.
    """

    signal = LoopSignal.BREAK

    def call(self) -> None:
        if self.shell._loop_depth > 0:
            self.shell._loop_signal = self.signal
            return
        self.errorWrite(
            f"{self.shell.error_prefix()}{self.signal.value}: "
            "only meaningful in a `for', `while', or `until' loop\n"
        )


class Command_continue(Command_break):
    """``continue`` -- skip to the next iteration of the innermost loop."""

    signal = LoopSignal.CONTINUE


commands["break"] = Command_break
commands["continue"] = Command_continue
