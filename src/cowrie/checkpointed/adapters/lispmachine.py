"""
Lisp Machine adapter for checkpointed image environments.

Lisp Machines (Symbolics, LMI Lambda, TI Explorer, MIT CADR) use world/band
files as their checkpoint mechanism. The entire Lisp environment -- all
functions, variables, processes, the OS itself -- lives as Lisp objects in
memory and is persisted to a world file. Key properties:

  - World files (.vlod): Binary memory page snapshots. Loading a world
    restores the complete Lisp environment to its saved state.
  - IDS (Incremental Disk Save): Delta saves relative to a parent world.
  - Cold boot: Load world from LOD partition. Warm boot: resume from
    existing PAGE partition contents.
  - Open Genera (VLM): Symbolics Ivory emulator for x86-64 Linux.
    The .vlod file IS the world. Save World writes a new .vlod.
  - LambdaDelta: LMI Lambda emulator. CADR emulator (usim): MIT CADR.
  - Meroko: TI Explorer I emulator.

Communication model:
  - Telnet to a Genera Lisp Listener for sending forms
  - NFS file sharing between host and the running Genera
  - For LambdaDelta/CADR: similar telnet access via emulated network

This is the most challenging environment to integrate due to the age
of the systems and limited external API surface.

References:
  - https://github.com/JMlisp/og2vlm
  - https://archives.loomcom.com/genera/genera-install.html
  - https://github.com/dseagrav/ld (LambdaDelta)
  - https://github.com/sethk/meroko
"""

from __future__ import annotations

import os
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


# Lisp prompt patterns (Genera uses various prompts)
_LISP_PROMPTS = [
    "Command: ",      # Genera Dynamic Lisp Listener
    "Lisp> ",         # Generic Lisp prompt
    "> ",             # Minimal prompt
    "* ",             # SBCL-style (for comparison testing)
]

# Genera-specific patterns
_GENERA_VALUE = re.compile(r"^(\S+.*)$")


class LispMachineEnvironment(CheckpointedEnvironment):
    """
    Adapter for emulated Lisp Machines.

    Connects via telnet to a Lisp Listener on the emulated machine and
    provides Lisp form evaluation, world save/restore, and basic
    object (symbol/function) inspection.

    Supported emulators:
      - Open Genera (VLM): Symbolics Ivory on x86-64 Linux
      - LambdaDelta: LMI Lambda emulator
      - CADR (usim): MIT CADR emulator
      - Meroko: TI Explorer I emulator

    The emulator_type parameter selects dialect-specific behavior.
    """

    def __init__(
        self,
        name: str,
        host: str = "localhost",
        port: int = 23,  # Telnet
        emulator_type: str = "genera",  # genera | lambda | cadr | meroko
        world_dir: str = "",
        nfs_share: str = "",
    ) -> None:
        super().__init__(name, host, port)
        self.emulator_type = emulator_type.lower()
        self.world_dir = world_dir
        self.nfs_share = nfs_share
        self._proto: LineBuffer | None = None

    @property
    def environment_type(self) -> str:
        return "lispmachine"

    @property
    def language(self) -> str:
        if self.emulator_type == "genera":
            return "Zetalisp/Common Lisp"
        elif self.emulator_type in ("lambda", "cadr"):
            return "Zetalisp"
        return "Lisp"

    @property
    def capabilities(self) -> EnvironmentCapability:
        caps = (
            EnvironmentCapability.EVAL
            | EnvironmentCapability.CHECKPOINT
            | EnvironmentCapability.OBJECT_INSPECT
            | EnvironmentCapability.OBJECT_MODIFY
        )
        if self.nfs_share:
            caps |= EnvironmentCapability.FILE_EXCHANGE
        return caps

    # -- Connection --

    @inlineCallbacks
    def connect(self) -> Deferred[bool]:
        try:
            self._proto = yield connect_tcp(self.host, self.port)
            # Wait for the Lisp Listener prompt
            lines = yield self._proto.wait_for_prompt(
                _LISP_PROMPTS, timeout_ms=30000
            )
            self._connected = True
            welcome = "\n".join(lines)
            log.msg(
                f"LispMachine({self.emulator_type}): connected to "
                f"{self.host}:{self.port}"
            )
            return True
        except Exception as e:
            log.err(f"LispMachine: connection failed: {e}")
            return False

    @inlineCallbacks
    def disconnect(self) -> Deferred[None]:
        if self._proto and self._proto.transport:
            # Send logout/disconnect
            if self.emulator_type == "genera":
                self._proto.send_line(":Logout")
            self._proto.transport.loseConnection()
        self._connected = False
        self._proto = None

    @inlineCallbacks
    def authenticate(self, username: str = "", password: str = "") -> Deferred[bool]:
        """
        Genera authentication: Login to a Lisp Listener.
        Some configurations require a :Login command.
        """
        if not self._proto:
            return False

        if username:
            if self.emulator_type == "genera":
                self._proto.send_line(f":Login {username}")
            else:
                self._proto.send_line(username)
            yield self._proto.wait_for_prompt(
                _LISP_PROMPTS + ["Password:"], timeout_ms=5000
            )

        if password:
            self._proto.send_line(password)
            yield self._proto.wait_for_prompt(_LISP_PROMPTS, timeout_ms=5000)

        return True

    # -- Code evaluation --

    @inlineCallbacks
    def evaluate(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate a Lisp form in the connected Listener.

        For Genera: Sends the form to the Dynamic Lisp Listener
        For CADR/Lambda: Sends to the Zetalisp listener
        """
        self._require_connected()
        start = time.monotonic()

        # Send the form
        self._proto.send_line(code)
        lines = yield self._proto.wait_for_prompt(
            _LISP_PROMPTS, timeout_ms=timeout_ms
        )

        elapsed = (time.monotonic() - start) * 1000
        output = "\n".join(lines)

        # Detect errors
        error = ""
        if self.emulator_type == "genera":
            # Genera signals errors with ">>Error:" or ">>Trap:"
            if ">>Error:" in output or ">>Trap:" in output or ">>TRAP" in output:
                error = output
        else:
            if "Error" in output and ">>Error" not in code:
                error = output

        # The last non-prompt line is typically the return value
        return_val = None
        for line in reversed(lines):
            line = line.strip()
            if line and not any(line.endswith(p.strip()) for p in _LISP_PROMPTS):
                return_val = line
                break

        return EvalResult(
            success=not error,
            output=output,
            error=error,
            return_value=return_val,
            environment_type="lispmachine",
            elapsed_ms=elapsed,
        )

    @inlineCallbacks
    def compile_object(self, path: str, source: str = "") -> Deferred[EvalResult]:
        """
        Compile/load a Lisp source file or evaluate a defun/defclass form.

        path: File path on the Lisp Machine filesystem, or a symbol name.
        source: If provided, a defun/defclass/defsystem form to evaluate.
                If path is a file, source is written via NFS and loaded.
        """
        self._require_connected()

        if source:
            if self.nfs_share and path.endswith(".lisp"):
                # Write source to NFS share and load it
                nfs_path = os.path.join(self.nfs_share, os.path.basename(path))
                try:
                    with open(nfs_path, "w") as f:
                        f.write(source)
                except OSError as e:
                    return EvalResult(
                        success=False,
                        error=f"Failed to write to NFS: {e}",
                        environment_type="lispmachine",
                    )
                # Load the file
                return (yield self.evaluate(f'(load "{path}")'))
            else:
                # Evaluate the source directly as a form
                return (yield self.evaluate(source))
        else:
            # Compile existing file
            if self.emulator_type == "genera":
                return (yield self.evaluate(f':Compile File {path}'))
            else:
                return (yield self.evaluate(f'(compile-file "{path}")'))

    # -- Object inspection --

    @inlineCallbacks
    def inspect_object(self, object_id: str) -> Deferred[ObjectInfo]:
        """
        Inspect a Lisp symbol, function, or CLOS class.

        object_id: A symbol name like 'make-instance' or a class name
                   like 'standard-class'.
        """
        self._require_connected()

        info = ObjectInfo(
            object_id=object_id,
            name=object_id,
            environment_type="lispmachine",
        )

        # Get describe output
        result = yield self.evaluate(f"(describe '{object_id})")
        if result.success:
            info.raw = result.output

        # Check if it's a function
        result = yield self.evaluate(f"(fboundp '{object_id})")
        is_function = result.success and result.return_value and result.return_value != "NIL"

        if is_function:
            # Get arglist
            if self.emulator_type == "genera":
                result = yield self.evaluate(
                    f"(arglist '{object_id})"
                )
            else:
                result = yield self.evaluate(
                    f"(sb-introspect:function-lambda-list #'{object_id})"
                )
            if result.success:
                info.properties["arglist"] = str(result.return_value)

        # Check if it's a class
        result = yield self.evaluate(f"(find-class '{object_id} nil)")
        is_class = result.success and result.return_value and result.return_value != "NIL"

        if is_class:
            # Get superclasses
            if self.emulator_type == "genera":
                result = yield self.evaluate(
                    f"(clos:class-direct-superclasses (find-class '{object_id}))"
                )
            else:
                result = yield self.evaluate(
                    f"(mapcar #'class-name "
                    f"(sb-mop:class-direct-superclasses (find-class '{object_id})))"
                )
            if result.success and result.return_value:
                info.parent = str(result.return_value)

            # Get direct subclasses
            if self.emulator_type == "genera":
                result = yield self.evaluate(
                    f"(clos:class-direct-subclasses (find-class '{object_id}))"
                )
            else:
                result = yield self.evaluate(
                    f"(mapcar #'class-name "
                    f"(sb-mop:class-direct-subclasses (find-class '{object_id})))"
                )
            if result.success and result.return_value:
                raw_children = str(result.return_value)
                info.children = [
                    s.strip().strip("()")
                    for s in raw_children.split()
                    if s.strip("()")
                ]

            # Get slots
            if self.emulator_type == "genera":
                result = yield self.evaluate(
                    f"(mapcar #'clos:slot-definition-name "
                    f"(clos:class-slots (find-class '{object_id})))"
                )
            else:
                result = yield self.evaluate(
                    f"(mapcar #'sb-mop:slot-definition-name "
                    f"(sb-mop:class-slots (find-class '{object_id})))"
                )
            if result.success:
                info.properties["slots"] = str(result.return_value)

        return info

    @inlineCallbacks
    def list_objects(
        self, pattern: str = "", limit: int = 100
    ) -> Deferred[list[ObjectInfo]]:
        """
        List symbols in the current package matching a pattern.
        For CLOS classes, list subclasses of a root class.
        """
        self._require_connected()

        if pattern.startswith("class:"):
            # List CLOS classes
            class_name = pattern[6:]
            result = yield self.evaluate(
                f"(mapcar #'class-name "
                f"(sb-mop:class-direct-subclasses (find-class '{class_name})))"
            )
        else:
            # List symbols matching pattern
            if self.emulator_type == "genera":
                # Genera: use mapatoms or apropos
                result = yield self.evaluate(
                    f'(apropos-list "{pattern or "*"}")'
                )
            else:
                result = yield self.evaluate(
                    f'(apropos-list "{pattern or ""}")'
                )

        objects = []
        if result.success and result.return_value:
            raw = str(result.return_value)
            # Parse the list of symbols
            symbols = re.findall(r"[A-Z][\w*+-]+", raw, re.IGNORECASE)
            for sym in symbols[:limit]:
                objects.append(
                    ObjectInfo(
                        object_id=sym,
                        name=sym,
                        environment_type="lispmachine",
                    )
                )
        return objects

    @inlineCallbacks
    def get_source(self, object_id: str, method: str = "") -> Deferred[str]:
        """
        Retrieve source code for a function or method.

        On Genera: Uses (ed) or (function-source) to retrieve source.
        """
        self._require_connected()

        if self.emulator_type == "genera":
            if method:
                result = yield self.evaluate(
                    f"(clos:method-source "
                    f"(find-method #'{method} nil "
                    f"(list (find-class '{object_id}))))"
                )
            else:
                result = yield self.evaluate(
                    f"(function-lambda-expression #'{object_id})"
                )
        else:
            if method:
                result = yield self.evaluate(
                    f"(sb-introspect:definition-source "
                    f"(find-method #'{method} nil "
                    f"(list (find-class '{object_id}))))"
                )
            else:
                result = yield self.evaluate(
                    f"(function-lambda-expression #'{object_id})"
                )

        return result.output if result.success else result.error

    # -- Checkpoint management --

    @inlineCallbacks
    def create_checkpoint(
        self, label: str = "", incremental: bool = False
    ) -> Deferred[CheckpointInfo]:
        """
        Save the Lisp world.

        For Genera: (si:save-world) or :Save World command
        For CADR/Lambda: (disk-save) or equivalent
        """
        self._require_connected()

        if self.emulator_type == "genera":
            # Genera Save World
            world_name = label or f"checkpoint-{int(time.time())}"
            if incremental:
                # IDS: Incremental Disk Save
                cmd = f':Save World "{world_name}" :Incremental Yes'
            else:
                cmd = f':Save World "{world_name}"'
            result = yield self.evaluate(cmd)
        elif self.emulator_type in ("lambda", "cadr"):
            result = yield self.evaluate("(disk-save)")
        else:
            result = yield self.evaluate("(si:disk-save)")

        checkpoint_id = f"lisp-{int(time.time())}"
        return CheckpointInfo(
            checkpoint_id=checkpoint_id,
            environment_type="lispmachine",
            label=label or f"Lisp world save ({self.emulator_type})",
            incremental=incremental,
            metadata={
                "env_name": self.name,
                "emulator": self.emulator_type,
                "save_result": result.output,
            },
        )

    @inlineCallbacks
    def restore_checkpoint(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore requires cold-booting the emulator with a saved world file.
        This shuts down the current session.
        """
        log.msg(
            f"LispMachine: restore requires cold boot with saved world. "
            f"Halting for checkpoint {checkpoint_id}."
        )
        if self.emulator_type == "genera":
            result = yield self.evaluate(":Halt Machine")
        else:
            result = yield self.evaluate("(si:halt)")
        self._connected = False
        return True

    @inlineCallbacks
    def list_checkpoints(self) -> Deferred[list[CheckpointInfo]]:
        """
        List available world files.
        On Genera: (si:find-world-files) or directory listing.
        """
        self._require_connected()

        if self.emulator_type == "genera":
            result = yield self.evaluate(
                ":Show Directory SYS:WORLDS;*.VLOD"
            )
        else:
            result = yield self.evaluate("(si:list-worlds)")

        # Parse output into checkpoint info objects
        checkpoints = []
        if result.success:
            for line in result.output.split("\n"):
                line = line.strip()
                if line and (".vlod" in line.lower() or ".lod" in line.lower()):
                    checkpoints.append(
                        CheckpointInfo(
                            checkpoint_id=line.split()[0] if line.split() else line,
                            environment_type="lispmachine",
                            label=line,
                            metadata={
                                "env_name": self.name,
                                "emulator": self.emulator_type,
                            },
                        )
                    )
        return checkpoints

    # -- Helpers --

    def _require_connected(self) -> None:
        if not self._connected or not self._proto:
            raise ConnectionError(
                f"LispMachine environment {self.name!r} is not connected"
            )
