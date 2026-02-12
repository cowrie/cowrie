"""
LambdaMOO adapter for checkpointed image environments.

LambdaMOO is a MOO (MUD, Object-Oriented) server where the entire database
lives in RAM and is periodically checkpointed to a text file. Key properties:

  - Objects identified by number (#0, #1, #123). Each has properties and
    verbs (methods). Prototype-based inheritance via parent objects.
  - The MOO language: dynamically typed, similar to Lua/JavaScript.
    Verbs are programs on objects with argument parsing specs.
  - Checkpoints: The server forks and writes the full database to a text
    file at $dump_interval (default 3600s). USR2 triggers immediate dump.
  - ToastStunt: The actively maintained fork adds HTTP listener,
    JSON support, cURL, and RESTful access.
  - mooR: A Rust rewrite (1.0-beta) with multithreading and modern
    protocol support.

Communication model:
  Connect via telnet to the MOO port, authenticate as a programmer/wizard
  character, and issue MOO commands. The ';' prefix evaluates MOO code
  in the connected player's context.

References:
  - https://www.hayseed.net/MOO/manuals/ProgrammersManual.html
  - https://github.com/lisdude/toaststunt
  - https://codeberg.org/timbran/moor
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
from cowrie.checkpointed.transport import LineBuffer, connect_tcp, HTTPTransport


# MOO object reference pattern
_OBJ_REF = re.compile(r"#(\d+)")
# Property listing pattern
_PROP_RE = re.compile(r"^\s*\.(\w+)\s+(.*)$")
# Verb listing pattern
_VERB_RE = re.compile(r"^\s*(\w[\w-]*)\s+(this|any|none)\s+(none|any|this)")


class LambdaMOOEnvironment(CheckpointedEnvironment):
    """
    Adapter for LambdaMOO, ToastStunt, and mooR servers.

    Supports two communication modes:
      1. Telnet: Connect as a wizard player, use ';' eval prefix
      2. HTTP (ToastStunt only): REST API for structured access

    The telnet mode works with all MOO servers. HTTP mode provides
    cleaner programmatic access but requires ToastStunt.
    """

    def __init__(
        self,
        name: str,
        host: str = "localhost",
        port: int = 7777,
        wizard_name: str = "wizard",
        wizard_password: str = "",
        http_port: int = 0,
        use_toaststunt: bool = False,
    ) -> None:
        super().__init__(name, host, port)
        self.wizard_name = wizard_name
        self.wizard_password = wizard_password
        self.http_port = http_port
        self.use_toaststunt = use_toaststunt
        self._proto: LineBuffer | None = None
        self._http: HTTPTransport | None = None

        if http_port and use_toaststunt:
            self._http = HTTPTransport(f"http://{host}:{http_port}")

    @property
    def environment_type(self) -> str:
        return "lambdamoo"

    @property
    def language(self) -> str:
        return "MOO"

    @property
    def capabilities(self) -> EnvironmentCapability:
        caps = (
            EnvironmentCapability.EVAL
            | EnvironmentCapability.CHECKPOINT
            | EnvironmentCapability.OBJECT_INSPECT
            | EnvironmentCapability.OBJECT_MODIFY
        )
        if self.use_toaststunt:
            caps |= EnvironmentCapability.HTTP_API
            caps |= EnvironmentCapability.MULTIPLE_INHERITANCE
        return caps

    # -- Connection --

    @inlineCallbacks
    def connect(self) -> Deferred[bool]:
        try:
            self._proto = yield connect_tcp(self.host, self.port)
            # MOO servers typically send a welcome message
            yield self._proto.wait_for_prompt(
                ["***", "the character's name", ">"], timeout_ms=10000
            )
            self._connected = True
            log.msg(f"LambdaMOO: connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            log.err(f"LambdaMOO: connection failed: {e}")
            return False

    @inlineCallbacks
    def disconnect(self) -> Deferred[None]:
        if self._proto and self._proto.transport:
            self._proto.send_line("@quit")
            self._proto.transport.loseConnection()
        self._connected = False
        self._proto = None

    @inlineCallbacks
    def authenticate(self, username: str = "", password: str = "") -> Deferred[bool]:
        if not self._proto:
            return False

        wizard = username or self.wizard_name
        passwd = password or self.wizard_password

        # MOO login: "connect <name> <password>"
        self._proto.send_line(f"connect {wizard} {passwd}")
        lines = yield self._proto.wait_for_prompt(
            [">", "***", "connected"], timeout_ms=5000
        )
        response = "\n".join(lines)

        if "incorrect" in response.lower() or "invalid" in response.lower():
            log.err(f"LambdaMOO: authentication failed for {wizard}")
            return False

        log.msg(f"LambdaMOO: authenticated as {wizard}")
        return True

    # -- Code evaluation --

    @inlineCallbacks
    def evaluate(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate MOO code using the ';' (eval) prefix.

        In MOO, the ';' prefix causes the rest of the line to be compiled
        and executed as a MOO verb body. The result is printed to the player.
        Multi-line eval is entered with ';;' and terminated with '.'.
        """
        self._require_connected()
        start = time.monotonic()

        # Use HTTP if available (ToastStunt)
        if self._http and self.use_toaststunt:
            return (yield self._eval_http(code, timeout_ms))

        # Single-line eval via telnet
        if "\n" not in code:
            self._proto.send_line(f"; {code}")
        else:
            # Multi-line: use ;; ... .
            self._proto.send_line(";;")
            for line in code.split("\n"):
                self._proto.send_line(line)
            self._proto.send_line(".")

        lines = yield self._proto.wait_for_prompt([">"], timeout_ms=timeout_ms)
        elapsed = (time.monotonic() - start) * 1000
        output = "\n".join(lines)

        # MOO eval prints "=> <value>" for the return value
        return_val = None
        error = ""
        for line in lines:
            if line.startswith("=> "):
                return_val = line[3:]
            elif line.startswith("#-1:") or "error" in line.lower():
                error = line

        return EvalResult(
            success=not error,
            output=output,
            error=error,
            return_value=return_val,
            environment_type="lambdamoo",
            elapsed_ms=elapsed,
        )

    @inlineCallbacks
    def _eval_http(self, code: str, timeout_ms: int) -> Deferred[EvalResult]:
        """Evaluate MOO code via ToastStunt's HTTP/JSON interface."""
        start = time.monotonic()
        status, body = yield self._http.post(
            "/eval", {"code": code}
        )
        elapsed = (time.monotonic() - start) * 1000

        if status == 200 and isinstance(body, dict):
            return EvalResult(
                success=body.get("success", False),
                output=body.get("output", ""),
                error=body.get("error", ""),
                return_value=body.get("result"),
                environment_type="lambdamoo",
                elapsed_ms=elapsed,
            )
        return EvalResult(
            success=False,
            error=f"HTTP {status}: {body}",
            environment_type="lambdamoo",
            elapsed_ms=elapsed,
        )

    @inlineCallbacks
    def compile_object(self, path: str, source: str = "") -> Deferred[EvalResult]:
        """
        Compile a verb on a MOO object.

        In MOO, you don't compile objects -- you program individual verbs.
        path: Should be in format '#object:verb_name' (e.g. '#123:look')
        source: The verb program source code.
        """
        self._require_connected()
        start = time.monotonic()

        if ":" not in path:
            return EvalResult(
                success=False,
                error=f"MOO path must be '#object:verb' format, got: {path}",
                environment_type="lambdamoo",
            )

        obj_ref, verb_name = path.split(":", 1)

        if source:
            # Use @program to set verb code
            self._proto.send_line(f"@program {obj_ref}:{verb_name}")
            yield self._proto.wait_for_prompt(
                ["Enter new program", ">"], timeout_ms=3000
            )
            for line in source.split("\n"):
                self._proto.send_line(line)
            self._proto.send_line(".")
            lines = yield self._proto.wait_for_prompt([">"], timeout_ms=10000)
        else:
            # Just verify the verb exists
            self._proto.send_line(f"@list {obj_ref}:{verb_name}")
            lines = yield self._proto.wait_for_prompt([">"], timeout_ms=5000)

        elapsed = (time.monotonic() - start) * 1000
        output = "\n".join(lines)
        success = "error" not in output.lower()

        return EvalResult(
            success=success,
            output=output,
            error="" if success else output,
            environment_type="lambdamoo",
            elapsed_ms=elapsed,
            side_effects=["verb_programmed"] if success and source else [],
        )

    # -- Object inspection --

    @inlineCallbacks
    def inspect_object(self, object_id: str) -> Deferred[ObjectInfo]:
        """
        Inspect a MOO object using @show and @display commands.
        object_id: Object reference like '#123' or '$room'
        """
        self._require_connected()

        # @show gives properties, @display gives verbs
        self._proto.send_line(f"@show {object_id}")
        lines = yield self._proto.wait_for_prompt([">"], timeout_ms=5000)
        raw = "\n".join(lines)

        info = ObjectInfo(
            object_id=object_id,
            name=object_id,
            environment_type="lambdamoo",
            raw=raw,
        )

        # Parse @show output for properties
        for line in lines:
            prop_match = _PROP_RE.match(line)
            if prop_match:
                info.properties[prop_match.group(1)] = prop_match.group(2)
            if "Name:" in line:
                info.name = line.split("Name:", 1)[1].strip()
            elif "Owner:" in line:
                info.owner = line.split("Owner:", 1)[1].strip()
            elif "Parent:" in line:
                info.parent = line.split("Parent:", 1)[1].strip()
            elif "Location:" in line:
                info.location = line.split("Location:", 1)[1].strip()

        # Get verbs with @display
        self._proto.send_line(f"@display {object_id}")
        lines = yield self._proto.wait_for_prompt([">"], timeout_ms=5000)
        for line in lines:
            verb_match = _VERB_RE.match(line)
            if verb_match:
                info.methods.append(verb_match.group(1))

        return info

    @inlineCallbacks
    def list_objects(
        self, pattern: str = "", limit: int = 100
    ) -> Deferred[list[ObjectInfo]]:
        """
        List MOO objects. Pattern can be an owner or name filter.
        Uses eval to query the object database.
        """
        self._require_connected()

        # Query max_object() to know the range, then filter
        result = yield self.evaluate("max_object()")
        if not result.success:
            return []

        max_obj = 100  # Default
        try:
            val = str(result.return_value).strip()
            match = _OBJ_REF.search(val)
            if match:
                max_obj = int(match.group(1))
        except (ValueError, AttributeError):
            pass

        # List valid objects up to limit
        objects = []
        scan_range = min(max_obj + 1, limit * 2)  # Scan more than limit
        result = yield self.evaluate(
            f"{{o, names | names = {{}}; "
            f"for o in [#0..#{min(scan_range, max_obj)}] "
            f"if (valid(o)) names = listappend(names, "
            f"{{tostr(o), o.name}}); endfor; return names;}}"
        )

        if result.success and result.return_value:
            # Parse the list output
            raw = str(result.return_value)
            for match in re.finditer(r'\{\"(#\d+)\",\s*\"([^\"]*)\"\}', raw):
                obj_id, obj_name = match.groups()
                if pattern and pattern.lower() not in obj_name.lower():
                    continue
                objects.append(
                    ObjectInfo(
                        object_id=obj_id,
                        name=obj_name,
                        environment_type="lambdamoo",
                    )
                )
                if len(objects) >= limit:
                    break

        return objects

    @inlineCallbacks
    def get_source(self, object_id: str, method: str = "") -> Deferred[str]:
        """
        Retrieve verb source code.
        object_id: '#123' or '#123:verb_name'
        method: If object_id doesn't contain ':', this specifies the verb.
        """
        self._require_connected()

        if ":" in object_id:
            target = object_id
        elif method:
            target = f"{object_id}:{method}"
        else:
            # List all verbs and their code
            result = yield self.evaluate(f"verbs({object_id})")
            return result.output if result.success else result.error

        self._proto.send_line(f"@list {target}")
        lines = yield self._proto.wait_for_prompt([">"], timeout_ms=5000)
        return "\n".join(lines)

    # -- Checkpoint management --

    @inlineCallbacks
    def create_checkpoint(
        self, label: str = "", incremental: bool = False
    ) -> Deferred[CheckpointInfo]:
        """
        Trigger a MOO database checkpoint.
        Calls $dump_interval or suspend(0) + dump_database() depending
        on the server variant.
        """
        self._require_connected()

        # Standard LambdaMOO: call the checkpoint verb
        result = yield self.evaluate(
            "typeof($server_options.dump_interval) == INT "
            "&& dump_database()"
        )

        # If that didn't work, try the #0:checkpoint approach
        if not result.success:
            result = yield self.evaluate("#0:checkpoint()")

        checkpoint_id = f"moo-{int(time.time())}"
        return CheckpointInfo(
            checkpoint_id=checkpoint_id,
            environment_type="lambdamoo",
            label=label or "LambdaMOO database checkpoint",
            incremental=False,  # MOO always does full dumps
            metadata={
                "env_name": self.name,
                "dump_result": result.output,
            },
        )

    @inlineCallbacks
    def restore_checkpoint(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore requires restarting the MOO server with a different DB file.
        The server must be stopped and restarted externally.
        """
        log.msg(
            f"LambdaMOO: restore requires server restart with DB file. "
            f"Shutting down for checkpoint {checkpoint_id}."
        )
        result = yield self.evaluate("shutdown()")
        self._connected = False
        return True

    @inlineCallbacks
    def list_checkpoints(self) -> Deferred[list[CheckpointInfo]]:
        """MOO servers don't track historical checkpoints; return empty."""
        return []

    # -- Object tree --

    @inlineCallbacks
    def get_object_tree(
        self, root_id: str = "#1", depth: int = 3
    ) -> Deferred[dict[str, Any]]:
        """Return the inheritance tree rooted at the given object."""
        self._require_connected()

        result = yield self.evaluate(f"children({root_id})")
        children_raw = str(result.return_value) if result.success else ""

        tree: dict[str, Any] = {"id": root_id, "children": []}

        if depth > 0:
            # Parse children list
            for match in _OBJ_REF.finditer(children_raw):
                child_id = f"#{match.group(1)}"
                if depth > 1:
                    subtree = yield self.get_object_tree(child_id, depth - 1)
                    tree["children"].append(subtree)
                else:
                    tree["children"].append({"id": child_id, "children": []})

        return tree

    # -- Helpers --

    def _require_connected(self) -> None:
        if not self._connected or not self._proto:
            raise ConnectionError(
                f"LambdaMOO environment {self.name!r} is not connected"
            )
