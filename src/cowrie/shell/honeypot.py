# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import copy
import enum
import fnmatch
import posixpath
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from twisted.python.failure import Failure

from twisted.internet.defer import Deferred, succeed
from twisted.logger import Logger
from twisted.python.compat import iterbytes

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.bashparse import (
    BashParser,
    BraceGroup,
    CaseClause,
    ForClause,
    FunctionDef,
    IfClause,
    Statement,
    Subshell,
    SyntaxError_,
    WhileClause,
)
from cowrie.shell.command import process_status
from cowrie.shell.parser import CommandParser
from cowrie.shell.pipe import PipeProtocol

# Honeypot safety caps. A loop in an uploaded script must never hang or exhaust
# the process: bound the number of iterations a single loop runs. Real malware
# downloaders loop a handful of times (over a few URLs or architectures); these
# ceilings are far above that yet keep a `while true` from running forever.
MAX_WHILE_ITERATIONS = 1000
MAX_FOR_ITEMS = 10000

# A word is a variable assignment only when a valid shell identifier precedes
# the =; bash treats words like "=", "=foo" or "1x=5" as command names.
ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


class LoopSignal(enum.Enum):
    """A pending ``break`` / ``continue`` for the innermost running loop.

    Set on the shell by the ``break`` / ``continue`` builtins and consumed by
    that shell's innermost loop continuation.
    """

    BREAK = "break"
    CONTINUE = "continue"


@dataclass
class _Continuation:
    """An internal queue entry that runs a Python callback when reached.

    Flow control schedules these between the statements it splices into
    ``cmdpending`` so it can react to a condition's exit status or step a loop.
    ``is_loop_cont`` marks the continuation that closes one loop-body iteration,
    which is where a pending ``break`` / ``continue`` is consumed.
    """

    fn: Callable[[], None]
    is_loop_cont: bool = False
    op: str | None = None


class HoneyPotShell:
    _log = Logger()

    def __init__(
        self,
        protocol: Any,
        interactive: bool = True,
        redirect: bool = False,
        effective_user: dict[str, Any] | None = None,
        reads_stdin: bool = False,
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        # The shell's commands arrive over a live stdin (an SSH exec channel
        # running `bash`): a drained queue means idle, not done, until EOF.
        self.reads_stdin: bool = reads_stdin
        self.effective_user = effective_user  # For su: {uid, gid, username, home}
        # Parsed-but-not-yet-evaluated statements; each is expanded against the
        # live environment only when it is about to run (see runCommand). A
        # subshell stays a single unit here so its &&/|| gate covers the whole
        # group; runCommand splices its statements in only when it runs.
        self.cmdpending: list[Statement | _Continuation] = []
        # A nested shell (e.g. a command substitution) inherits the live
        # environment and working directory of whichever shell or command is
        # currently running, as a forked shell process inherits its parent's;
        # the very first shell of a session falls back to the login
        # environment (all of which is exported) and the user's home. cwd is
        # this shell's own from here on: a cd inside a substitution or nested
        # script shell never changes the parent's.
        if protocol.cmdstack:
            parent = protocol.cmdstack[-1]
            self.environ: dict[str, str] = copy.copy(parent.environ)
            self.exported: set[str] = copy.copy(parent.exported)
            self.cwd: str = parent.cwd
        else:
            self.environ = copy.copy(protocol.environ)
            self.exported = set(protocol.environ.keys())
            if protocol.fs.exists(protocol.user.avatar.home):
                self.cwd = protocol.user.avatar.home
            else:
                self.cwd = "/"
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])
        self.parser = CommandParser()
        self.bashparser = BashParser(self)
        # Capture-subshell state (redirect=True): every statement's captured
        # stdout accumulates here -- one pipe buffer for the whole subshell,
        # like the pipe bash wires a $(...) child to. capture_done fires with
        # the finished subshell (buffer and final status) when it leaves the
        # cmdstack -- its queue drained, or an inner `exit` ended it: the
        # subshell's pipe seeing EOF.
        self.captured: bytes = b""
        self.capture_done: Deferred[HoneyPotShell] | None = None
        # Final status of the most recent command substitution expanded for
        # the current statement: bash makes it the statement's own status
        # when the statement is only assignments.
        self._subst_status: int | None = None
        # Exit status of the most recent command in this shell, for $? and the
        # && / || short-circuit logic.
        self.last_exit_code: int = 0
        # Shell functions defined in this shell, name -> body statements.
        self.functions: dict[str, list[Statement]] = {}
        # Flow-control state: how many loops are currently running (so break /
        # continue only act inside a loop) and a pending loop signal consumed by
        # the innermost loop continuation.
        self._loop_depth: int = 0
        self._loop_signal: LoopSignal | None = None
        # Trampoline state for _advance (see its docstring).
        self._advancing: bool = False
        self._advance_pending: bool = False
        # True once `exec` has replaced this shell with the command now
        # running: when that command finishes, the shell is gone (see resume).
        self._exec_replaced: bool = False

    # -- bashparse.ShellContext interface -----------------------------------

    def get_variable(self, name: str) -> str | None:
        """Look up a shell variable for the Lark word evaluator."""
        return self.environ.get(name)

    def get_status(self) -> str:
        """Return $? -- the last command's exit status as a string."""
        return str(self.last_exit_code)

    def command_substitution(self, source: str) -> Deferred[str]:
        """Run ``source`` as a command substitution: the returned Deferred
        fires with its captured stdout, trailing newlines stripped, once the
        subshell finishes -- the evaluator awaits it, as bash blocks on the
        substitution pipe.

        The inner source runs in a capture subshell with the same sequencing
        as a top-level line: a same-line assignment is visible to later
        statements, ``$?`` carries across them, and ``&&`` / ``||``
        short-circuit. Output is captured instead of reaching the terminal.
        """

        def finished(subshell: HoneyPotShell) -> str:
            # The subshell's status becomes $? for the rest of the expansion
            # and, via _subst_status, for a statement of only assignments
            # (`x=$(false)` leaves $? = 1).
            self.last_exit_code = subshell.last_exit_code
            self._subst_status = subshell.last_exit_code
            # The captured output is attacker bytes and need not be valid UTF-8.
            return subshell.captured.decode(errors="replace").rstrip("\n")

        return self.capture(source).addCallback(finished)

    def capture(self, source: str) -> Deferred[HoneyPotShell]:
        """Run ``source`` in a capture subshell and return a Deferred that
        fires with the finished subshell -- its accumulated stdout in
        ``captured`` and its final status in ``last_exit_code``.

        The subshell runs its statements through the normal cmdpending /
        _advance machinery, so a command that pauses on a Deferred (wget)
        keeps the subshell alive until it completes -- the returned Deferred
        is the parent's blocking read on the substitution pipe. When every
        statement completes synchronously the Deferred has already fired by
        the time this returns.
        """
        shell = HoneyPotShell(self.protocol, interactive=False, redirect=True)
        done: Deferred[HoneyPotShell] = Deferred()
        shell.capture_done = done
        self.protocol.cmdstack.append(shell)
        shell._queue_statements(self.bashparser.parse(source))
        shell._advance()
        return done

    def _harvest_capture(self) -> None:
        """Fold the finished statement's captured stdout into this capture
        subshell's buffer and clear ``protocol.pp`` so a statement that builds
        no pipe (a bare assignment, or a command-not-found) reads as empty
        output rather than re-reading the previous statement's capture."""
        if not self.redirect:
            return
        pp = self.protocol.pp
        if pp is not None:
            self.captured += pp.redirected_data
            self.protocol.pp = None

    def _complete_capture(self) -> None:
        """Fire ``capture_done`` with this finished subshell: it is gone and
        the parent's read on the substitution pipe sees EOF."""
        if self.capture_done is None:
            return
        self._harvest_capture()
        done, self.capture_done = self.capture_done, None
        done.callback(self)

    def exit_shell(self, code: int) -> None:
        """End this shell from the ``exit`` builtin: record the final status
        for whoever launched it, leave the cmdstack, and complete a capture
        subshell's substitution."""
        self.last_exit_code = code
        if self in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(self)
        self._complete_capture()

    def lineReceived(self, line: str) -> None:
        """Parse a command line with the Lark grammar and run the result."""
        self.protocol.events.dispatch(
            "cowrie.command.input", "CMD: %(input)s", input=line
        )
        self._queue_statements(self.bashparser.parse(line))
        self._advance()

    def queue_line(self, line: str) -> None:
        """Queue a line that arrived while a command holds the terminal.

        The statements are parsed now but run only when this shell resumes
        after the command exits, like tty input read by the next reader.
        """
        self.protocol.events.dispatch(
            "cowrie.command.input", "CMD: %(input)s", input=line
        )
        self._queue_statements(self.bashparser.parse(line))

    def _queue_statements(self, statements: list[Statement]) -> bool:
        """Append parsed statements to ``cmdpending`` for sequential execution.

        A subshell is queued as one unit so its join operator (e.g. the || in
        `x || (a; b)`) gates the whole group; runCommand splices the inner
        statements in only when the group actually runs. Cowrie does not give
        a ``(...)`` group its own isolated shell, so the inner statements run
        in the parent shell and their ``cd`` / variable effects persist.

        Returns False to stop queueing after a syntax error: commands already
        queued before the error still run, as in bash.
        """
        for statement in statements:
            if isinstance(statement, SyntaxError_):
                self._report_syntax_error(statement)
                return False
            if isinstance(statement, Subshell) and not self._reject_inner_error(
                statement.statements
            ):
                return False
            self.cmdpending.append(statement)
        return True

    def _reject_inner_error(self, statements: list[Statement]) -> bool:
        """Report a syntax error nested anywhere inside a subshell, since the
        whole line is rejected at parse time. Returns False once reported."""
        for statement in statements:
            if isinstance(statement, SyntaxError_):
                self._report_syntax_error(statement)
                return False
            if isinstance(statement, Subshell) and not self._reject_inner_error(
                statement.statements
            ):
                return False
        return True

    def _report_syntax_error(self, statement: SyntaxError_) -> None:
        """Write the message bash prints for a syntax error and set $? to 2."""
        if statement.token:
            self.protocol.terminal.write(
                f"-bash: syntax error near unexpected token `{statement.token}'\n".encode()
            )
        else:
            self.protocol.terminal.write(
                b"-bash: syntax error: unexpected end of file\n"
            )
        self.last_exit_code = 2  # bash uses 2 for a syntax error

    def _finish(self) -> None:
        """The command queue is drained: do the shell's idle action.

        An interactive shell shows the next prompt. A shell reading commands
        from live stdin stays resident awaiting the next line or EOF. A
        top-level non-interactive shell (an exec session) ends the process. A
        nested non-interactive shell that runs a script or ``-c`` commands
        (sh/bash/su) removes itself from the cmdstack and resumes the command
        that launched it -- this is what hands control back once the script's
        async commands (wget/curl) have all finished. A command-substitution
        capture subshell removes itself and completes its substitution.
        """
        if self.interactive:
            self.showPrompt()
        elif self.reads_stdin:
            # Idle, not done: the channel will deliver more lines or EOF.
            pass
        elif self.redirect:
            # Capture subshell: its program has run to completion, so the
            # substitution's pipe sees EOF. The suspended evaluation that
            # created it carries on from the capture_done callback, so no
            # resume() of the shell below is needed here.
            if self in self.protocol.cmdstack:
                self.protocol.cmdstack.remove(self)
            self._complete_capture()
        elif len(self.protocol.cmdstack) == 1:
            # Top-level non-interactive shell (an exec session): end the process
            # with the last command's status so the SSH channel reports a real
            # exit-status to the client.
            self.protocol.terminal.transport.processEnded(
                process_status(self.last_exit_code)
            )
        elif self.protocol.cmdstack[-1] is self:
            # Nested script / `-c` shell whose queue is drained: unwind it and
            # let the launching command carry on. Done here rather than with an
            # unconditional pop() at the call site because an async command
            # (wget/curl) leaves this shell mid-stack until it later resumes and
            # drains us.
            self.protocol.cmdstack.remove(self)
            if self.protocol.cmdstack:
                self.protocol.cmdstack[-1].resume()

    def _statement_failed(self, failure: Failure) -> None:
        """An error escaped a statement's expansion or setup: log it, give the
        statement bash's generic failure status, and carry on with the queue --
        a shell that stops responding would fingerprint the honeypot."""
        self._log.failure("shell statement failed", failure=failure)
        self.last_exit_code = 1
        self._advance()

    def _short_circuit(self, op: str | None) -> bool:
        """Whether a statement joined by ``op`` should be skipped given the last
        command's exit status: ``&&`` after a failure, ``||`` after a success.
        """
        return (op == "&&" and self.last_exit_code != 0) or (
            op == "||" and self.last_exit_code == 0
        )

    def _advance(self) -> None:
        """Run the next queued command, or finish when the queue is drained.

        This is a trampoline. A command that completes synchronously calls
        ``exit() -> resume() -> _advance()`` again before the original call
        returns, so a naive recursive design would grow the Python stack by one
        frame per command -- a long ``;`` list, or any loop, would overflow it.
        Instead a re-entrant ``_advance`` just flags that more work is pending
        and unwinds; the outermost call drives a flat loop. A command that
        instead pauses on a Deferred (e.g. wget) unwinds normally and its later
        ``resume`` starts a fresh drive.
        """
        if self._advancing:
            self._advance_pending = True
            return
        self._advancing = True
        try:
            running = True
            while running:
                self._advance_pending = False
                if self.cmdpending:
                    self.runCommand()
                else:
                    self._finish()
                running = self._advance_pending
        finally:
            self._advancing = False

    # -- flow control -------------------------------------------------------
    #
    # Compound commands are driven through the same cmdpending queue as simple
    # commands. A handler splices its body statements to the front and, where it
    # must observe a result (a loop test, the next iteration), appends a
    # _Continuation callback that runs once the spliced statements have finished
    # -- which works whether those statements complete synchronously or pause on
    # a Deferred (e.g. wget) and resume later.

    def _end_loop(self) -> None:
        self._loop_depth -= 1
        self._advance()

    def _loop_body_end(self, step: Callable[[], None]) -> _Continuation:
        """The continuation appended after a loop body. It consumes a pending
        break / continue (break ends the loop; continue and a normal pass both
        run ``step`` again to take the next iteration)."""

        def loop_cont() -> None:
            signal = self._loop_signal
            self._loop_signal = None
            if signal is LoopSignal.BREAK:
                self._end_loop()
            else:
                step()

        return _Continuation(loop_cont, is_loop_cont=True)

    def _run_for(self, node: ForClause) -> None:
        """``for VAR in WORDS; do BODY; done`` over the expanded word list."""
        if node.items:
            d = Deferred.fromCoroutine(self.bashparser.evaluate(node.items))
        else:
            d = succeed([])
        d.addCallback(self._run_for_expanded, node)
        d.addErrback(self._statement_failed)

    def _run_for_expanded(self, values: list[str], node: ForClause) -> None:
        """Loop over the expanded ``in`` list, one body pass per word."""
        values = values[:MAX_FOR_ITEMS]
        if not values:
            # A loop over an empty list runs the body zero times and succeeds.
            self.last_exit_code = 0
            self._advance()
            return

        self._loop_depth += 1
        index = 0

        def step() -> None:
            nonlocal index
            if index >= len(values):
                self._end_loop()
                return
            self.environ[node.var] = values[index]
            index += 1
            self.cmdpending[0:0] = [*node.body, self._loop_body_end(step)]
            self._advance()

        step()

    def _run_while(self, node: WhileClause) -> None:
        """``while COND; do BODY; done`` (``until`` inverts the test)."""
        self._loop_depth += 1
        iterations = 0
        # A loop's exit status is its body's last command, or 0 if the body
        # never ran -- never the condition's. Each condition test overwrites $?,
        # so snapshot the body's status before re-testing and restore it on exit.
        body_status = 0

        def test() -> None:
            nonlocal iterations, body_status
            if iterations:
                body_status = self.last_exit_code
            if iterations >= MAX_WHILE_ITERATIONS:
                self.last_exit_code = body_status
                self._end_loop()
                return
            iterations += 1
            self.cmdpending[0:0] = [*node.condition, _Continuation(decide)]
            self._advance()

        def decide() -> None:
            succeeded = self.last_exit_code == 0
            run_body = (not succeeded) if node.until else succeeded
            if not run_body:
                self.last_exit_code = body_status
                self._end_loop()
                return
            self.cmdpending[0:0] = [*node.body, self._loop_body_end(test)]
            self._advance()

        test()

    def _run_if(self, node: IfClause) -> None:
        """``if COND; then BODY; [elif ...] [else ...] fi``."""

        def try_branch(index: int) -> None:
            if index >= len(node.branches):
                if node.else_body is not None:
                    self.cmdpending[0:0] = list(node.else_body)
                else:
                    # No branch ran: an if with no matching arm succeeds.
                    self.last_exit_code = 0
                self._advance()
                return
            condition, body = node.branches[index]
            self.cmdpending[0:0] = [
                *condition,
                _Continuation(lambda: decide(index, body)),
            ]
            self._advance()

        def decide(index: int, body: list[Statement]) -> None:
            if self.last_exit_code == 0:
                self.cmdpending[0:0] = list(body)
                self._advance()
            else:
                try_branch(index + 1)

        try_branch(0)

    def _run_case(self, node: CaseClause) -> None:
        """``case WORD in PATTERN) BODY ;; ... esac`` -- first match wins."""
        if node.word:
            d = Deferred.fromCoroutine(self.bashparser.evaluate(node.word))
        else:
            d = succeed([])
        d.addCallback(self._run_case_expanded, node)
        d.addErrback(self._statement_failed)

    def _run_case_expanded(self, tokens: list[str], node: CaseClause) -> None:
        """Match the expanded case word against each pattern arm."""
        word = " ".join(tokens)
        for patterns, body in node.items:
            for pattern in patterns:
                if fnmatch.fnmatchcase(word, self._strip_quotes(pattern)):
                    # A matched body's status is its last command, or 0 when the
                    # body is empty; the prior command's status must not leak.
                    if not body:
                        self.last_exit_code = 0
                    self.cmdpending[0:0] = list(body)
                    self._advance()
                    return
        # No pattern matched: the case succeeds.
        self.last_exit_code = 0
        self._advance()

    @staticmethod
    def _strip_quotes(pattern: str) -> str:
        """Drop a single pair of surrounding quotes from a case pattern so a
        quoted literal like ``'x86_64'`` matches; glob metacharacters in an
        unquoted pattern are left untouched for fnmatch."""
        if len(pattern) >= 2 and pattern[0] == pattern[-1] and pattern[0] in "\"'":
            return pattern[1:-1]
        return pattern

    def _call_function(self, name: str, args: list[str]) -> None:
        """Run a function body with $1.. , $#, $@ and $* bound to ``args``.

        Only the positional parameters for this call ($1..$len(args)) are saved
        and restored. bash also unsets any higher-numbered parameters on entry,
        so a function called with fewer arguments than its caller would still
        see the caller's $2.. here; emulating that needs per-call param scoping.
        """
        body = self.functions[name]
        params = [str(i) for i in range(1, len(args) + 1)] + ["#", "@", "*"]
        saved = {key: self.environ.get(key) for key in params}

        for i, value in enumerate(args, start=1):
            self.environ[str(i)] = value
        self.environ["#"] = str(len(args))
        self.environ["@"] = " ".join(args)
        self.environ["*"] = " ".join(args)

        def restore() -> None:
            for key, value in saved.items():
                if value is None:
                    self.environ.pop(key, None)
                else:
                    self.environ[key] = value
            self._advance()

        self.cmdpending[0:0] = [*body, _Continuation(restore)]
        self._advance()

    def _strip_exec(self, tokens: list[str]) -> tuple[bool, bool]:
        """Consume a leading ``exec`` and its options from ``tokens`` in place.

        Returns ``(exec_seen, replaces_shell)``. ``exec cmd`` runs the remaining
        command through the normal machinery and, when it replaces the shell,
        the shell terminates once the command finishes. exec's own options do
        not change what runs (``-a NAME`` supplies argv[0], ``-c`` cleans the
        environment, ``-l`` makes it a login shell), so they are dropped. A
        pipeline stage and a backgrounded (``&``) command run in a subshell, so
        ``exec`` there never replaces this shell; a bare ``exec`` (possibly with
        only redirections) runs no command and the shell survives it.
        """
        if not tokens or tokens[0] != "exec":
            return False, False
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            opt = tokens.pop(0)
            if opt == "--":
                break
            if "a" in opt and tokens:
                tokens.pop(0)
        replaces = bool(tokens) and "|" not in tokens and tokens[-1] != "&"
        return True, replaces

    def runCommand(self):
        # Mid-pipeline: an earlier stage just finished but a downstream command
        # has not run yet. Let the pipe machinery drive the rest before touching
        # the next statement -- otherwise `a | b; c` would run c before b and
        # drop b's output.
        if self.protocol.pp is not None and self.protocol.pp.next_command is not None:
            return

        # A capture subshell folds the statement that just finished into its
        # output buffer before touching the next one; loop bodies and spliced
        # groups pass through here too, so every statement is collected.
        self._harvest_capture()

        # A pending break / continue: drop the rest of the current loop body up
        # to the innermost loop continuation, which consumes the signal.
        if self._loop_signal is not None:
            while self.cmdpending:
                node = self.cmdpending[0]
                if isinstance(node, _Continuation) and node.is_loop_cont:
                    break
                self.cmdpending.pop(0)
            if not self.cmdpending:
                # break / continue with no enclosing loop body left: ignore it.
                self._loop_signal = None

        if not self.cmdpending:
            # The queue is drained.
            self._finish()
            return

        command = self.cmdpending.pop(0)

        # Internal flow-control continuations run their callback and return; they
        # carry no exit status and are never short-circuited.
        if isinstance(command, _Continuation):
            command.fn()
            return

        # A syntax error nested in a compound body surfaces here when reached.
        if isinstance(command, SyntaxError_):
            self._report_syntax_error(command)
            self._advance()
            return

        # && / || short-circuit: skip this statement (or whole group) based on
        # the previous command's exit status, leaving $? unchanged.
        if self._short_circuit(command.op):
            self._advance()
            return

        if isinstance(command, Subshell):
            # The group runs: splice its statements to the front so they run in
            # order. The group's own gate was checked above; each inner
            # statement keeps its own &&/|| relative to its siblings.
            self.cmdpending[0:0] = command.statements
            self._advance()
            return

        if isinstance(command, BraceGroup):
            # A { ...; } group runs its statements in the current shell.
            self.cmdpending[0:0] = command.statements
            self._advance()
            return

        if isinstance(command, FunctionDef):
            # Defining a function records its body and succeeds.
            self.functions[command.name] = command.body
            self.last_exit_code = 0
            self._advance()
            return

        if isinstance(command, ForClause):
            self._run_for(command)
            return

        if isinstance(command, IfClause):
            self._run_if(command)
            return

        if isinstance(command, WhileClause):
            self._run_while(command)
            return

        if isinstance(command, CaseClause):
            self._run_case(command)
            return

        # Expand the statement's words against the *current* environment, just
        # before it runs, so a same-line `x=hi; echo $x` sees the value. A
        # command substitution in a word suspends the expansion until its
        # subshell finishes; the statement then runs from the callback. With
        # only synchronous substitutions the Deferred has already fired and
        # the statement runs before this returns.
        self._subst_status = None
        d = Deferred.fromCoroutine(self.bashparser.evaluate(command))
        d.addCallback(self._run_expanded)
        d.addErrback(self._statement_failed)

    def _run_expanded(self, cmdAndArgs: list[str]) -> None:
        """Run one expanded simple command / pipeline: split off leading
        assignments, resolve each stage to a command class, wire the pipe and
        redirections, and start it."""
        pp = None

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_tokens: list[str] = []
        cmd_array: list[dict[str, Any]] = []
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if ASSIGNMENT_WORD.match(piece):
                key, val = piece.split("=", 1)
                environ[key] = val
                continue
            cmd_tokens = [piece, *cmdAndArgs]
            break

        exec_seen, exec_replace = self._strip_exec(cmd_tokens)

        if not cmd_tokens:
            # A statement of only assignments (no command) persists those
            # variables for the rest of the session. They are shell variables,
            # not exported, so self.exported is left untouched. Its status is
            # that of the last command substitution its words ran, as in bash
            # (`x=$(false)` leaves $? = 1); with no substitution a bare
            # assignment succeeds.
            self.environ = environ
            self.last_exit_code = (
                self._subst_status if self._subst_status is not None else 0
            )
            self._advance()
            return

        # A call to a shell function defined earlier runs its body with the
        # positional parameters bound to the call arguments. A pipeline that
        # includes the function name is left to the normal command machinery.
        # `exec` never sees functions: it only runs files.
        if (
            not exec_replace
            and cmd_tokens[0] in self.functions
            and "|" not in cmd_tokens
        ):
            self._call_function(cmd_tokens[0], cmd_tokens[1:])
            return

        pipe_indices = [i for i, x in enumerate(cmd_tokens) if x == "|"]
        multipleCmdArgs: list[list[str]] = []
        pipe_indices.append(len(cmd_tokens))
        start = 0

        # Gather all arguments with pipes

        for _index, pipe_indice in enumerate(pipe_indices):
            multipleCmdArgs.append(cmd_tokens[start:pipe_indice])
            start = pipe_indice + 1

        first_args, first_ops = self.parser.parse_redirections(multipleCmdArgs.pop(0))
        if not first_args:
            if first_ops:
                # Handle redirection without command (e.g. > file). This
                # creates the backing files via _setup_redirections; register
                # them so they are hashed/renamed or removed at session close
                # instead of being orphaned in the download directory.
                pp = PipeProtocol(
                    self.protocol,
                    None,
                    [],
                    None,
                    None,
                    self.redirect,
                    first_ops,
                    cwd=self.cwd,
                )
                for real_path, virtual_path in pp.redirect_real_files:
                    self.protocol.terminal.redirFiles.add((real_path, virtual_path))
            self._advance()
            return

        cmd_array.append(
            {
                "command": first_args.pop(0),
                "rargs": first_args,
                "redirects": first_ops,
            }
        )

        for cmd_args in multipleCmdArgs:
            args, ops = self.parser.parse_redirections(cmd_args)
            if not args:
                continue
            cmd_array.append(
                {
                    "command": args.pop(0),
                    "rargs": args,
                    "redirects": ops,
                }
            )

        lastpp = None
        cmdclass = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            cmdclass = self.protocol.getCommand(
                cmd["command"], environ.get("PATH", "").split(":"), self.cwd
            )
            if cmdclass:
                self._log.info(
                    "Command found: {input}",
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                )
                if index == len(cmd_array) - 1:
                    lastpp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        None,
                        self.redirect,
                        cmd.get("redirects", []),
                        cwd=self.cwd,
                    )
                    pp = lastpp
                else:
                    pp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        lastpp,
                        self.redirect,
                        cmd.get("redirects", []),
                        cwd=self.cwd,
                    )
                    lastpp = pp
            else:
                self.protocol.events.dispatch(
                    "cowrie.command.failed",
                    "Command not found: %(input)s",
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                )
                if exec_seen and index == 0:
                    # exec applies to the first pipeline segment only; it
                    # reports a failed lookup as its own error.
                    message = f"-bash: exec: {cmd['command']}: not found\n".encode()
                else:
                    message = self.command_not_found_message(cmd["command"]).encode(
                        "utf8"
                    )
                redirects = cmd.get("redirects", [])
                if redirects:
                    temp_pp = PipeProtocol(
                        self.protocol,
                        None,
                        [],
                        None,
                        None,
                        self.redirect,
                        redirects,
                        cwd=self.cwd,
                    )
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:
                        self.protocol.terminal.redirFiles.add((real_path, virtual_path))
                else:
                    self.protocol.terminal.write(message)

                self.last_exit_code = 127  # command not found
                if exec_replace and not self.interactive:
                    # A failed exec ends a non-interactive shell with 127; an
                    # interactive one survives it (bash without execfail).
                    self._terminate(127)
                    return
                self._advance()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            self._advance()
            return

        if pp:
            self._exec_replaced = exec_replace
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

    def command_not_found_message(self, cmd: str) -> str:
        """
        Build the error a real shell prints when a command cannot be run.
        For a path-like command (one starting with "." or "/") match bash's
        errno-based messages: an existing directory yields "Is a directory"
        (EISDIR) and a path that does not exist yields "No such file or
        directory" (ENOENT). Anything else yields "command not found".
        """
        if cmd[:1] in (".", "/"):
            path = self.protocol.fs.resolve_path(cmd, self.cwd)
            if self.protocol.fs.isdir(path):
                return f"-bash: {cmd}: Is a directory\n"
            if not self.protocol.fs.exists(path):
                return f"-bash: {cmd}: No such file or directory\n"
        return f"-bash: {cmd}: command not found\n"

    def resume(self) -> None:
        if self._exec_replaced:
            # The command that replaced this shell via `exec` has finished;
            # there is no shell to come back to.
            self._terminate(self.last_exit_code)
            return
        if self.interactive:
            self.protocol.setInsertMode()
        # Go through the _advance trampoline so a command that resumes us
        # synchronously does not deepen the Python stack (see _advance).
        self._advance()

    def _terminate(self, code: int) -> None:
        """End this shell, as when `exec` replaces it: unwind to whatever ran
        it, or end the process with ``code`` when nothing else is running.

        This mirrors the `exit` builtin's teardown: the shell leaves the
        cmdstack and either the launching command carries on (nested shell) or,
        with the cmdstack empty, the process ends and the SSH channel reports
        ``code`` to the client.
        """
        self.last_exit_code = code
        if self in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(self)
        if self.capture_done is not None:
            # A capture subshell's substitution carries on from the
            # capture_done callback; resuming the shell below as well would
            # drive it twice.
            self._complete_capture()
            return
        if self.protocol.cmdstack:
            self.protocol.cmdstack[-1].resume()
        else:
            # The client may already be disconnected, leaving no transport.
            try:
                self.protocol.terminal.transport.processEnded(process_status(code))
            except AttributeError:
                pass

    def showPrompt(self) -> None:
        if not self.interactive:
            return

        prompt = ""
        if CowrieConfig.has_option("honeypot", "prompt"):
            prompt = CowrieConfig.get("honeypot", "prompt")
            prompt += " "
        else:
            # Use effective_user if set (from su), otherwise use session user
            if self.effective_user:
                username = self.effective_user["username"]
                uid = self.effective_user["uid"]
                home = self.effective_user["home"]
            else:
                username = self.protocol.user.username
                uid = self.protocol.user.uid
                home = self.protocol.user.avatar.home

            cwd = self.cwd
            homelen = len(home)
            if cwd == home:
                cwd = "~"
            elif len(cwd) > (homelen + 1) and cwd[: (homelen + 1)] == home + "/":
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{username}@{self.protocol.hostname}:{cwd}"
            if not uid:
                prompt += "# "  # "Root" user
            else:
                prompt += "$ "  # "Non-Root" user

        self.protocol.terminal.write(prompt.encode("ascii"))
        self.protocol.ps = (prompt.encode("ascii"), b"> ")

    def eofReceived(self) -> None:
        """
        EOF with the shell as the active reader (no command running) logs out,
        exiting with the last command's status ($?) as bash does.
        """
        self._log.info("received eof, logging out")
        self.protocol.terminal.transport.processEnded(
            process_status(self.last_exit_code)
        )

    def handle_CTRL_C(self) -> None:
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_TAB(self) -> None:
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            return

        line: bytes = b"".join(self.protocol.lineBuffer)
        if line[-1:] == b" ":
            clue = ""
        else:
            clue = line.split()[-1].decode("utf8")

        # clue now contains the string to complete or is empty.
        # line contains the buffer as bytes
        basedir = posixpath.dirname(clue)
        if basedir and basedir[-1] != "/":
            basedir += "/"

        if not basedir:
            tmppath = self.cwd
        else:
            tmppath = basedir

        try:
            r = self.protocol.fs.resolve_path(tmppath, self.cwd)
        except Exception:
            return

        if not self.protocol.fs.exists(r):
            return

        files = []
        for x in self.protocol.fs.get_path(r):
            if clue == "":
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(posixpath.basename(clue)):
                continue
            files.append(x)

        if not files:
            return

        # Clear early so we can call showPrompt if needed
        for _i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ""
        if len(files) == 1:
            newbuf = " ".join(
                [*line.decode("utf8").split()[:-1], f"{basedir}{files[0][fs.A_NAME]}"]
            )
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += "/"
            else:
                newbuf += " "
            newbyt = newbuf.encode("utf8")
        else:
            if posixpath.basename(clue):
                prefix = posixpath.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ""
            first = line.decode("utf8").split(" ")[:-1]
            newbuf = " ".join([*first, f"{basedir}{prefix}"])
            newbyt = newbuf.encode("utf8")
            if newbyt == b"".join(self.protocol.lineBuffer):
                self.protocol.terminal.write(b"\n")
                maxlen = max(len(x[fs.A_NAME]) for x in files) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b"\n")
                    self.protocol.terminal.write(
                        file[fs.A_NAME].ljust(maxlen).encode("utf8")
                    )
                    count += 1
                self.protocol.terminal.write(b"\n")
                self.showPrompt()

        self.protocol.lineBuffer = list(iterbytes(newbyt))
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)
