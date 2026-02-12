"""
Smalltalk adapter for checkpointed image environments.

Smalltalk systems (Pharo, Squeak, GNU Smalltalk) use image-based persistence
where the entire object memory is serialized to a binary .image file. Key
properties for this integration:

  - Image files: Binary snapshot of all objects, classes, methods, processes,
    and application state. Resuming an image picks up exactly where it stopped.
  - Changes file: A rolling log of all source modifications since the last
    base image, serving as crash recovery journal and audit trail.
  - Tonel format: Modern git-friendly source format (one file per class)
    used by Iceberg for version control integration.
  - Multiple interaction modes:
    * PharoSmalltalkInteropServer: HTTP API purpose-built for LLM integration,
      with an MCP server wrapper
    * NeoConsole: Telnet REPL for headless Pharo images
    * GNU Smalltalk: Pipe-based scripting (echo code | gst)
    * Pharo CLI: Command-line image management

Communication model:
  Pharo: HTTP API (preferred) or NeoConsole telnet REPL
  GNU Smalltalk: stdin/stdout piping for scripted evaluation
  Squeak: Similar to Pharo but with fewer external interaction tools

References:
  - https://github.com/mumez/PharoSmalltalkInteropServer
  - https://github.com/mumez/pharo-smalltalk-interop-mcp-server
  - https://github.com/svenvc/NeoConsole
  - https://www.gnu.org/software/smalltalk/manual/gst.html
"""

from __future__ import annotations

import os
import time
from typing import Any

from twisted.internet import defer, protocol, reactor, utils
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.python import log

from cowrie.checkpointed.base import (
    CheckpointedEnvironment,
    CheckpointInfo,
    EnvironmentCapability,
    EvalResult,
    ObjectInfo,
)
from cowrie.checkpointed.transport import (
    LineBuffer,
    HTTPTransport,
    connect_tcp,
)


class SmalltalkEnvironment(CheckpointedEnvironment):
    """
    Adapter for Smalltalk image environments (Pharo, Squeak, GNU Smalltalk).

    Supports three communication backends:
      1. HTTP API (Pharo + PharoSmalltalkInteropServer): Best for structured
         interaction. Provides eval, introspection, search, package management.
      2. NeoConsole (Pharo): Telnet REPL for simpler command-line access.
      3. Pipe (GNU Smalltalk): Send code via stdin, read results from stdout.
    """

    def __init__(
        self,
        name: str,
        host: str = "localhost",
        port: int = 1701,  # NeoConsole default
        variant: str = "pharo",  # pharo | squeak | gnu
        http_port: int = 8080,
        image_path: str = "",
        gst_binary: str = "gst",
    ) -> None:
        super().__init__(name, host, port)
        self.variant = variant.lower()
        self.http_port = http_port
        self.image_path = image_path
        self.gst_binary = gst_binary

        self._proto: LineBuffer | None = None  # NeoConsole
        self._http: HTTPTransport | None = None

        # Set up HTTP transport for Pharo with InteropServer
        if self.variant == "pharo" and http_port:
            self._http = HTTPTransport(f"http://{host}:{http_port}")

    @property
    def environment_type(self) -> str:
        return "smalltalk"

    @property
    def language(self) -> str:
        return "Smalltalk"

    @property
    def capabilities(self) -> EnvironmentCapability:
        caps = (
            EnvironmentCapability.EVAL
            | EnvironmentCapability.CHECKPOINT
            | EnvironmentCapability.OBJECT_INSPECT
            | EnvironmentCapability.OBJECT_MODIFY
            | EnvironmentCapability.RUNTIME_RECOMPILE
            | EnvironmentCapability.FILE_EXCHANGE
        )
        if self._http:
            caps |= EnvironmentCapability.HTTP_API
        return caps

    # -- Connection --

    @inlineCallbacks
    def connect(self) -> Deferred[bool]:
        if self.variant == "gnu":
            # GNU Smalltalk uses pipe mode -- no persistent connection
            self._connected = True
            log.msg(f"Smalltalk(GNU): ready for pipe-based evaluation")
            return True

        if self._http:
            # Test HTTP connection
            try:
                status, body = yield self._http.get("/ping")
                if status == 200:
                    self._connected = True
                    log.msg(
                        f"Smalltalk(Pharo): connected via HTTP API at "
                        f"{self.host}:{self.http_port}"
                    )
                    return True
            except Exception as e:
                log.msg(
                    f"Smalltalk: HTTP API not available ({e}), "
                    f"falling back to NeoConsole"
                )

        # Fall back to NeoConsole telnet
        try:
            self._proto = yield connect_tcp(self.host, self.port)
            yield self._proto.wait_for_prompt(
                ["NeoConsole", ">", "Pharo"], timeout_ms=10000
            )
            self._connected = True
            log.msg(
                f"Smalltalk({self.variant}): connected via NeoConsole at "
                f"{self.host}:{self.port}"
            )
            return True
        except Exception as e:
            log.err(f"Smalltalk: connection failed: {e}")
            return False

    @inlineCallbacks
    def disconnect(self) -> Deferred[None]:
        if self._proto and self._proto.transport:
            self._proto.send_line("quit")
            self._proto.transport.loseConnection()
        self._connected = False
        self._proto = None

    @inlineCallbacks
    def authenticate(self, username: str = "", password: str = "") -> Deferred[bool]:
        # NeoConsole and PharoInteropServer typically don't require auth
        # for local connections. HTTP API may use token auth.
        return True

    # -- Code evaluation --

    @inlineCallbacks
    def evaluate(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate a Smalltalk expression.

        Routes to the appropriate backend:
          - HTTP API: POST /api/evaluate with code body
          - NeoConsole: 'eval <code>' command
          - GNU Smalltalk: pipe code to gst process
        """
        self._require_connected()
        start = time.monotonic()

        if self._http and self.variant == "pharo":
            result = yield self._eval_http(code, timeout_ms)
        elif self._proto:
            result = yield self._eval_neoconsole(code, timeout_ms)
        elif self.variant == "gnu":
            result = yield self._eval_gst(code, timeout_ms)
        else:
            result = EvalResult(
                success=False,
                error="No evaluation backend available",
                environment_type="smalltalk",
            )

        result.elapsed_ms = (time.monotonic() - start) * 1000
        return result

    @inlineCallbacks
    def _eval_http(self, code: str, timeout_ms: int) -> Deferred[EvalResult]:
        """Evaluate via PharoSmalltalkInteropServer HTTP API."""
        status, body = yield self._http.post(
            "/api/evaluate", {"code": code}
        )
        if status == 200 and isinstance(body, dict):
            return EvalResult(
                success=not body.get("error"),
                output=body.get("result", ""),
                error=body.get("error", ""),
                return_value=body.get("result"),
                environment_type="smalltalk",
            )
        return EvalResult(
            success=False,
            error=f"HTTP {status}: {body}",
            environment_type="smalltalk",
        )

    @inlineCallbacks
    def _eval_neoconsole(self, code: str, timeout_ms: int) -> Deferred[EvalResult]:
        """Evaluate via NeoConsole telnet REPL."""
        # NeoConsole 'eval' command
        self._proto.send_line(f"eval {code}")
        lines = yield self._proto.wait_for_prompt([">"], timeout_ms=timeout_ms)
        output = "\n".join(lines)

        error = ""
        if "Error" in output or "error" in output:
            error = output

        return EvalResult(
            success=not error,
            output=output,
            error=error,
            return_value=output.strip() if not error else None,
            environment_type="smalltalk",
        )

    @inlineCallbacks
    def _eval_gst(self, code: str, timeout_ms: int) -> Deferred[EvalResult]:
        """Evaluate via GNU Smalltalk pipe (gst -e)."""
        try:
            # Use Twisted's utils.getProcessOutputAndValue for async subprocess
            stdout, stderr, exit_code = yield utils.getProcessOutputAndValue(
                self.gst_binary,
                args=["-e", code],
                env=os.environ,
            )
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            return EvalResult(
                success=exit_code == 0,
                output=stdout_str,
                error=stderr_str if exit_code != 0 else "",
                return_value=stdout_str.strip() if exit_code == 0 else None,
                environment_type="smalltalk",
            )
        except Exception as e:
            return EvalResult(
                success=False,
                error=str(e),
                environment_type="smalltalk",
            )

    @inlineCallbacks
    def compile_object(self, path: str, source: str = "") -> Deferred[EvalResult]:
        """
        Compile a Smalltalk class definition or method.

        path: Class name (e.g. 'MyClass') or 'MyClass>>methodName'
        source: Smalltalk source code for the class or method.
        """
        self._require_connected()

        if not source:
            return EvalResult(
                success=False,
                error="Source code required for Smalltalk compilation",
                environment_type="smalltalk",
            )

        if ">>" in path:
            # Method compilation: 'ClassName>>methodName'
            class_name = path.split(">>")[0]
            # Wrap in method installation
            code = f"{class_name} compile: '{self._escape_st(source)}'."
        else:
            # Class definition: evaluate directly (it's a message send)
            code = source

        return (yield self.evaluate(code))

    # -- Object inspection --

    @inlineCallbacks
    def inspect_object(self, object_id: str) -> Deferred[ObjectInfo]:
        """
        Inspect a Smalltalk class or object.
        object_id: Class name like 'OrderedCollection' or expression.
        """
        self._require_connected()

        if self._http:
            return (yield self._inspect_http(object_id))

        # Use eval to introspect
        info = ObjectInfo(
            object_id=object_id,
            name=object_id,
            environment_type="smalltalk",
        )

        # Get superclass
        result = yield self.evaluate(f"{object_id} superclass name")
        if result.success and result.return_value:
            info.parent = str(result.return_value).strip("'")

        # Get instance variable names
        result = yield self.evaluate(f"{object_id} instVarNames")
        if result.success:
            info.raw = result.output

        # Get method selectors
        result = yield self.evaluate(
            f"({object_id} selectors asArray copyFrom: 1 to: "
            f"({object_id} selectors size min: 50))"
        )
        if result.success and result.return_value:
            # Parse the printed array
            methods_str = str(result.return_value)
            info.methods = [
                m.strip().strip("#'")
                for m in methods_str.strip("(){}").split(".")
                if m.strip()
            ]

        # Get subclasses
        result = yield self.evaluate(
            f"{object_id} subclasses collect: [:c | c name]"
        )
        if result.success and result.return_value:
            info.children = [
                c.strip().strip("'")
                for c in str(result.return_value).strip("(){}").split(".")
                if c.strip()
            ]

        return info

    @inlineCallbacks
    def _inspect_http(self, object_id: str) -> Deferred[ObjectInfo]:
        """Inspect via PharoSmalltalkInteropServer."""
        status, body = yield self._http.get(
            f"/api/classes/{object_id}"
        )
        info = ObjectInfo(
            object_id=object_id,
            name=object_id,
            environment_type="smalltalk",
        )
        if status == 200 and isinstance(body, dict):
            info.parent = body.get("superclass", "")
            info.methods = body.get("methods", [])
            info.children = body.get("subclasses", [])
            info.properties = {
                "instVars": body.get("instanceVariables", []),
                "classVars": body.get("classVariables", []),
                "category": body.get("category", ""),
            }
            info.raw = str(body)
        return info

    @inlineCallbacks
    def list_objects(
        self, pattern: str = "", limit: int = 100
    ) -> Deferred[list[ObjectInfo]]:
        """List Smalltalk classes matching a pattern."""
        self._require_connected()

        if self._http:
            status, body = yield self._http.get(
                f"/api/classes?pattern={pattern}&limit={limit}"
            )
            if status == 200 and isinstance(body, list):
                return [
                    ObjectInfo(
                        object_id=c.get("name", ""),
                        name=c.get("name", ""),
                        environment_type="smalltalk",
                        parent=c.get("superclass", ""),
                    )
                    for c in body[:limit]
                ]

        # Eval-based class search
        if pattern:
            code = (
                f"(Smalltalk allClasses select: [:c | "
                f"c name includesSubstring: '{self._escape_st(pattern)}']) "
                f"collect: [:c | c name]"
            )
        else:
            code = (
                f"(Smalltalk allClasses copyFrom: 1 to: {limit}) "
                f"collect: [:c | c name]"
            )

        result = yield self.evaluate(code)
        objects = []
        if result.success and result.return_value:
            raw = str(result.return_value)
            for name in raw.strip("(){}").split("."):
                name = name.strip().strip("'#")
                if name:
                    objects.append(
                        ObjectInfo(
                            object_id=name,
                            name=name,
                            environment_type="smalltalk",
                        )
                    )
                    if len(objects) >= limit:
                        break
        return objects

    @inlineCallbacks
    def get_source(self, object_id: str, method: str = "") -> Deferred[str]:
        """
        Retrieve source code for a class or method.
        object_id: Class name
        method: Selector name (optional)
        """
        self._require_connected()

        if self._http and method:
            status, body = yield self._http.get(
                f"/api/classes/{object_id}/methods/{method}"
            )
            if status == 200 and isinstance(body, dict):
                return body.get("source", "")

        if method:
            code = f"({object_id}>>{method}) sourceCode"
        else:
            # Get class definition
            code = f"{object_id} definition"

        result = yield self.evaluate(code)
        return result.output if result.success else result.error

    # -- Checkpoint management --

    @inlineCallbacks
    def create_checkpoint(
        self, label: str = "", incremental: bool = False
    ) -> Deferred[CheckpointInfo]:
        """
        Save the Smalltalk image.

        For Pharo/Squeak: Sends 'Smalltalk saveImage' or NeoConsole 'save'.
        For GNU Smalltalk: ObjectDumper based serialization.
        """
        self._require_connected()

        if self._proto:
            # NeoConsole has a 'save' command
            self._proto.send_line("save")
            yield self._proto.wait_for_prompt([">"], timeout_ms=30000)
        elif self._http:
            yield self._http.post("/api/save", {})
        else:
            yield self.evaluate("Smalltalk snapshot: true andQuit: false")

        checkpoint_id = f"st-{int(time.time())}"
        return CheckpointInfo(
            checkpoint_id=checkpoint_id,
            environment_type="smalltalk",
            label=label or f"Smalltalk image save ({self.variant})",
            incremental=False,
            metadata={
                "env_name": self.name,
                "variant": self.variant,
                "image_path": self.image_path,
            },
        )

    @inlineCallbacks
    def restore_checkpoint(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore by relaunching the VM with a saved image file.
        Requires external process management.
        """
        log.msg(
            f"Smalltalk: restore requires restarting the VM with the saved "
            f"image file. Saving current state and shutting down."
        )
        if self._proto:
            self._proto.send_line("quit")
        elif self._http:
            yield self._http.post("/api/quit", {})
        else:
            yield self.evaluate("Smalltalk snapshot: true andQuit: true")
        self._connected = False
        return True

    @inlineCallbacks
    def list_checkpoints(self) -> Deferred[list[CheckpointInfo]]:
        """Smalltalk images don't maintain checkpoint history; return empty."""
        return []

    # -- Helpers --

    def _require_connected(self) -> None:
        if not self._connected:
            raise ConnectionError(
                f"Smalltalk environment {self.name!r} is not connected"
            )

    @staticmethod
    def _escape_st(s: str) -> str:
        """Escape a string for embedding in Smalltalk source code."""
        return s.replace("'", "''")
