"""
DGD (Dworkin's Game Driver) adapter for checkpointed image environments.

DGD is an object-oriented persistent application server that runs compiled
LPC code on a bytecode VM. Its key properties for this integration:

  - Statedumps: Full or incremental snapshots of the entire runtime state
    (all objects, compiled code, data, callouts). Created with dump_state()
    and restored by restarting with the statedump file.
  - Runtime recompilation: Objects can be recompiled in place without restart.
    The Kernellib's object manager handles data migration via call_touch().
  - Atomic functions: Code can run in atomic context where all side effects
    are rolled back on error (implemented via dataplanes).
  - Wiztool: Administrative CLI accessible over telnet. Supports compile,
    upgrade, code, clone, destruct, and arbitrary LPC evaluation.
  - Network: Telnet ports (interactive), binary ports (raw TCP), UDP ports.

Communication model:
  Connect to a telnet port, authenticate as an admin user, and issue
  wiztool commands. Responses are parsed from the text stream.

References:
  - https://github.com/dworkin/dgd
  - https://chattheatre.github.io/lpc-doc/dgd/unusual.html
  - https://noahgibbs.github.io/self_conscious_dgd/
"""

from __future__ import annotations

import re
import time
from typing import Any

from twisted.internet import defer
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.python import log

from cowrie.checkpointed.base import (
    CheckpointedEnvironment,
    CheckpointInfo,
    EnvironmentCapability,
    EvalResult,
    ObjectInfo,
)
from cowrie.checkpointed.transport import LineBuffer, connect_tcp


# Wiztool prompt patterns
_DGD_PROMPTS = ["> ", "# "]
_COMPILE_OK = re.compile(r"^/\S+\s+compiled\s*$")
_OBJECT_PATH = re.compile(r"^(/[\w/]+(?:\.c)?)\s*$")


class DGDEnvironment(CheckpointedEnvironment):
    """
    Adapter for DGD instances using the Kernellib wiztool interface.

    Connects via telnet to the DGD wiztool and provides:
      - LPC code evaluation via 'code' command
      - Object compilation/recompilation via 'compile' / 'upgrade'
      - Object inspection via 'status' and LPC introspection calls
      - Statedump creation via dump_state() kfun
      - Statedump listing from the configured dump directory
    """

    def __init__(
        self,
        name: str,
        host: str = "localhost",
        port: int = 6047,
        admin_user: str = "admin",
        admin_password: str = "",
        statedump_dir: str = "",
    ) -> None:
        super().__init__(name, host, port)
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.statedump_dir = statedump_dir
        self._proto: LineBuffer | None = None
        self._authenticated = False

    @property
    def environment_type(self) -> str:
        return "dgd"

    @property
    def language(self) -> str:
        return "LPC"

    @property
    def capabilities(self) -> EnvironmentCapability:
        return (
            EnvironmentCapability.EVAL
            | EnvironmentCapability.CHECKPOINT
            | EnvironmentCapability.RESTORE
            | EnvironmentCapability.INCREMENTAL_CHECKPOINT
            | EnvironmentCapability.HOTBOOT
            | EnvironmentCapability.RUNTIME_RECOMPILE
            | EnvironmentCapability.OBJECT_INSPECT
            | EnvironmentCapability.OBJECT_MODIFY
            | EnvironmentCapability.ATOMIC_TRANSACTIONS
            | EnvironmentCapability.MULTIPLE_INHERITANCE
        )

    # -- Connection --

    @inlineCallbacks
    def connect(self) -> Deferred[bool]:
        try:
            self._proto = yield connect_tcp(self.host, self.port)
            # Wait for the login prompt
            yield self._proto.wait_for_prompt(["login: ", "Login: "], timeout_ms=10000)
            self._connected = True
            log.msg(f"DGD: connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            log.err(f"DGD: connection failed: {e}")
            self._connected = False
            return False

    @inlineCallbacks
    def disconnect(self) -> Deferred[None]:
        if self._proto and self._proto.transport:
            self._proto.send_line("quit")
            self._proto.transport.loseConnection()
        self._connected = False
        self._authenticated = False
        self._proto = None

    @inlineCallbacks
    def authenticate(self, username: str = "", password: str = "") -> Deferred[bool]:
        if not self._proto:
            return False
        user = username or self.admin_user
        passwd = password or self.admin_password

        # Send username
        self._proto.send_line(user)
        lines = yield self._proto.wait_for_prompt(
            ["Password: ", "password: ", "> ", "# "], timeout_ms=5000
        )

        # Send password if prompted
        prompt_text = "\n".join(lines)
        if "assword" in prompt_text:
            self._proto.send_line(passwd)
            lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=5000)

        self._authenticated = True
        log.msg(f"DGD: authenticated as {user}")
        return True

    # -- Code evaluation --

    @inlineCallbacks
    def evaluate(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate LPC code using the wiztool 'code' command.

        The wiztool 'code' command compiles and executes an LPC expression.
        Multi-line code is supported by the wiztool but we send it as a
        single line for simplicity.
        """
        self._require_connected()
        start = time.monotonic()

        # The wiztool 'code' command evaluates an LPC expression
        self._proto.send_line(f"code {code}")
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=timeout_ms)

        elapsed = (time.monotonic() - start) * 1000
        output = "\n".join(lines)

        # Check for errors
        if "$" in output and "error" in output.lower():
            return EvalResult(
                success=False,
                error=output,
                environment_type="dgd",
                elapsed_ms=elapsed,
            )

        # Extract the return value (wiztool prints $N = <value>)
        return_val = None
        for line in lines:
            if line.startswith("$") and "=" in line:
                return_val = line.split("=", 1)[1].strip()

        return EvalResult(
            success=True,
            output=output,
            return_value=return_val,
            environment_type="dgd",
            elapsed_ms=elapsed,
        )

    @inlineCallbacks
    def compile_object(self, path: str, source: str = "") -> Deferred[EvalResult]:
        """
        Compile or recompile a DGD object.

        If source is provided, it should be written to the object's file
        path first (via the DGD editor or file system). Then we issue
        'compile <path>' for new objects or 'upgrade <path>' for
        recompilation of existing objects.

        path: Object path like '/obj/thing' (with or without .c extension)
        """
        self._require_connected()
        start = time.monotonic()

        if source:
            # Write source via the wiztool editor
            yield self._write_source(path, source)

        # Try compile first; if it's already compiled, use upgrade
        self._proto.send_line(f"compile {path}")
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=10000)
        output = "\n".join(lines)
        elapsed = (time.monotonic() - start) * 1000

        if "already compiled" in output.lower() or "exists" in output.lower():
            # Object exists, recompile with upgrade
            self._proto.send_line(f"upgrade {path}")
            lines = yield self._proto.wait_for_prompt(
                _DGD_PROMPTS, timeout_ms=10000
            )
            output = "\n".join(lines)
            elapsed = (time.monotonic() - start) * 1000

        success = bool(_COMPILE_OK.search(output)) or "compiled" in output.lower()
        return EvalResult(
            success=success,
            output=output,
            error="" if success else output,
            environment_type="dgd",
            elapsed_ms=elapsed,
            side_effects=["object_compiled"] if success else [],
        )

    # -- Object inspection --

    @inlineCallbacks
    def inspect_object(self, object_id: str) -> Deferred[ObjectInfo]:
        """
        Inspect a DGD object using the wiztool 'status' command
        and LPC introspection kfuns.
        """
        self._require_connected()

        # Use wiztool status command
        self._proto.send_line(f"status {object_id}")
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=5000)
        raw = "\n".join(lines)

        # Parse basic info from status output
        info = ObjectInfo(
            object_id=object_id,
            name=object_id.split("/")[-1].replace(".c", ""),
            environment_type="dgd",
            raw=raw,
        )

        # Get function (method) names via function_object()
        result = yield self.evaluate(
            f'object_name(find_object("{object_id}"))'
        )
        if result.success and result.return_value:
            info.name = str(result.return_value).strip('"')

        # List functions
        result = yield self.evaluate(
            f'status(find_object("{object_id}"))'
        )
        if result.success:
            info.raw = result.output

        return info

    @inlineCallbacks
    def list_objects(
        self, pattern: str = "", limit: int = 100
    ) -> Deferred[list[ObjectInfo]]:
        """List objects by querying the DGD object registry."""
        self._require_connected()

        # Use wiztool to list objects
        cmd = "status" if not pattern else f"status {pattern}"
        self._proto.send_line(cmd)
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=10000)

        objects = []
        for line in lines:
            match = _OBJECT_PATH.match(line.strip())
            if match and len(objects) < limit:
                path = match.group(1)
                objects.append(
                    ObjectInfo(
                        object_id=path,
                        name=path.split("/")[-1].replace(".c", ""),
                        environment_type="dgd",
                    )
                )
        return objects

    @inlineCallbacks
    def get_source(self, object_id: str, method: str = "") -> Deferred[str]:
        """
        Retrieve source code for a DGD object.
        Uses the wiztool 'more' or 'list' command to read the source file.
        """
        self._require_connected()
        path = object_id if object_id.endswith(".c") else f"{object_id}.c"
        self._proto.send_line(f"more {path}")
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=10000)
        source = "\n".join(lines)

        if method:
            # Extract a specific function from the source
            extracted = self._extract_function(source, method)
            return extracted if extracted else source

        return source

    # -- Checkpoint management --

    @inlineCallbacks
    def create_checkpoint(
        self, label: str = "", incremental: bool = False
    ) -> Deferred[CheckpointInfo]:
        """
        Create a statedump by calling dump_state() via the wiztool.

        DGD writes the statedump to its configured statedump file.
        Incremental statedumps write only changes since the last dump.
        """
        self._require_connected()

        # dump_state(1) = incremental, dump_state(0) = full
        incr_arg = "1" if incremental else "0"
        result = yield self.evaluate(f"dump_state({incr_arg})")

        checkpoint_id = f"dgd-{int(time.time())}"
        return CheckpointInfo(
            checkpoint_id=checkpoint_id,
            environment_type="dgd",
            label=label or f"DGD statedump {'incremental' if incremental else 'full'}",
            incremental=incremental,
            metadata={
                "env_name": self.name,
                "dump_result": result.output,
            },
        )

    @inlineCallbacks
    def restore_checkpoint(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore requires restarting DGD with the statedump file.
        This triggers a shutdown; the external process manager must restart DGD.
        """
        self._require_connected()
        log.msg(
            f"DGD: restore requires server restart with statedump. "
            f"Initiating shutdown for checkpoint {checkpoint_id}."
        )
        # Signal DGD to shut down -- the process manager should restart
        # with the appropriate statedump
        result = yield self.evaluate("shutdown()")
        self._connected = False
        return result.success

    @inlineCallbacks
    def list_checkpoints(self) -> Deferred[list[CheckpointInfo]]:
        """List statedump files from the configured directory."""
        # Query DGD for the statedump path via status
        self._proto.send_line("status")
        lines = yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=5000)

        # Return what we know from the registry; actual file listing
        # would require filesystem access
        return []

    # -- DGD-specific: hotboot --

    @inlineCallbacks
    def hotboot(self, binary_path: str = "") -> Deferred[bool]:
        """
        Perform a DGD hotboot: statedump + exec new binary.
        Network connections are preserved across the restart.
        """
        self._require_connected()
        result = yield self.evaluate("dump_state(1)")
        if not result.success:
            return False

        if binary_path:
            result = yield self.evaluate(f'hotboot("{binary_path}")')
        else:
            result = yield self.evaluate("hotboot()")

        return result.success

    # -- DGD-specific: atomic evaluation --

    @inlineCallbacks
    def atomic_eval(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate code in an atomic context.
        All side effects roll back on error (DGD dataplanes).
        """
        # Wrap in an atomic function call via the wiztool
        atomic_code = f"catch {{ atomic {{ {code} }} }}"
        return (yield self.evaluate(atomic_code, timeout_ms))

    # -- Helpers --

    def _require_connected(self) -> None:
        if not self._connected or not self._proto:
            raise ConnectionError(
                f"DGD environment {self.name!r} is not connected"
            )

    @inlineCallbacks
    def _write_source(self, path: str, source: str) -> Deferred[None]:
        """Write source code via the wiztool editor."""
        file_path = path if path.endswith(".c") else f"{path}.c"
        self._proto.send_line(f"ed {file_path}")
        yield self._proto.wait_for_prompt([":", "*"], timeout_ms=3000)

        # Enter append mode
        self._proto.send_line("a")
        for line in source.split("\n"):
            self._proto.send_line(line)
        self._proto.send_line(".")  # End append mode

        # Write and quit
        self._proto.send_line("wq")
        yield self._proto.wait_for_prompt(_DGD_PROMPTS, timeout_ms=3000)

    @staticmethod
    def _extract_function(source: str, func_name: str) -> str:
        """Extract a single function definition from LPC source."""
        lines = source.split("\n")
        in_func = False
        brace_depth = 0
        result_lines: list[str] = []

        for line in lines:
            if not in_func:
                # Look for the function signature
                if func_name in line and ("{" in line or "(" in line):
                    in_func = True
                    result_lines.append(line)
                    brace_depth += line.count("{") - line.count("}")
            else:
                result_lines.append(line)
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    break

        return "\n".join(result_lines)
