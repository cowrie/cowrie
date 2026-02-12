"""
Abstract base classes for checkpointed image environments.

All image-based environments share these fundamental capabilities:
  1. The world is a single mutable state (objects + code + data)
  2. Code can be evaluated/compiled into the running world
  3. Objects can be inspected and modified at runtime
  4. The entire state can be checkpointed (snapshotted) and restored
  5. Communication happens over network protocols (telnet, TCP, HTTP)

Each adapter implements this protocol for its specific environment.
"""

from __future__ import annotations

import abc
import enum
import time
from dataclasses import dataclass, field
from typing import Any

from twisted.internet.defer import Deferred


class EnvironmentCapability(enum.Flag):
    """Capabilities that a checkpointed environment may support."""

    EVAL = enum.auto()               # Evaluate code in the running world
    CHECKPOINT = enum.auto()         # Create state snapshots
    RESTORE = enum.auto()            # Restore from a snapshot
    INCREMENTAL_CHECKPOINT = enum.auto()  # Incremental/delta snapshots
    HOTBOOT = enum.auto()            # Zero-downtime restart with state preservation
    RUNTIME_RECOMPILE = enum.auto()  # Recompile objects without restart
    OBJECT_INSPECT = enum.auto()     # Inspect object state
    OBJECT_MODIFY = enum.auto()      # Modify object properties at runtime
    ATOMIC_TRANSACTIONS = enum.auto()  # Atomic rollback on error
    HTTP_API = enum.auto()           # Structured HTTP/REST interface
    FILE_EXCHANGE = enum.auto()      # File-based code/data exchange
    MULTIPLE_INHERITANCE = enum.auto()  # Object model supports MI


@dataclass
class CheckpointInfo:
    """Metadata about a checkpoint/snapshot."""

    checkpoint_id: str
    environment_type: str
    timestamp: float = field(default_factory=time.time)
    label: str = ""
    size_bytes: int = 0
    incremental: bool = False
    parent_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp


@dataclass
class ObjectInfo:
    """Introspection data for an object in the environment."""

    object_id: str
    name: str
    environment_type: str
    parent: str = ""
    children: list[str] = field(default_factory=list)
    owner: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    methods: list[str] = field(default_factory=list)
    location: str = ""
    flags: dict[str, bool] = field(default_factory=dict)
    raw: str = ""  # Environment-specific raw representation


@dataclass
class EvalResult:
    """Result of evaluating code in a checkpointed environment."""

    success: bool
    output: str = ""
    error: str = ""
    return_value: Any = None
    environment_type: str = ""
    elapsed_ms: float = 0.0
    side_effects: list[str] = field(default_factory=list)


class CheckpointedEnvironment(metaclass=abc.ABCMeta):
    """
    Abstract protocol for checkpointed image environments.

    Implementations connect to a running instance of DGD, LambdaMOO,
    Smalltalk, or a Lisp Machine and provide a uniform interface for
    code evaluation, object inspection, and checkpoint management.

    All async operations return Twisted Deferreds.
    """

    def __init__(self, name: str, host: str, port: int) -> None:
        self.name = name
        self.host = host
        self.port = port
        self._connected = False

    @property
    @abc.abstractmethod
    def environment_type(self) -> str:
        """Return the environment type identifier (e.g. 'dgd', 'lambdamoo')."""

    @property
    @abc.abstractmethod
    def language(self) -> str:
        """Return the primary language name (e.g. 'LPC', 'MOO', 'Smalltalk')."""

    @property
    @abc.abstractmethod
    def capabilities(self) -> EnvironmentCapability:
        """Return the set of capabilities this environment supports."""

    @property
    def connected(self) -> bool:
        return self._connected

    # -- Connection lifecycle --

    @abc.abstractmethod
    def connect(self) -> Deferred[bool]:
        """
        Establish connection to the running environment.
        Returns Deferred[True] on success, Deferred[False] on failure.
        """

    @abc.abstractmethod
    def disconnect(self) -> Deferred[None]:
        """Cleanly disconnect from the environment."""

    @abc.abstractmethod
    def authenticate(self, username: str, password: str) -> Deferred[bool]:
        """Authenticate with the environment (admin/wizard credentials)."""

    # -- Code evaluation --

    @abc.abstractmethod
    def evaluate(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate a code expression in the environment's native language.

        For DGD: LPC code executed via the wiztool
        For LambdaMOO: MOO code evaluated in a programmer context
        For Smalltalk: Smalltalk expressions via NeoConsole/HTTP API/pipe
        For Lisp Machines: Lisp forms sent to a Listener
        """

    @abc.abstractmethod
    def compile_object(self, path: str, source: str = "") -> Deferred[EvalResult]:
        """
        Compile or recompile an object from source.

        path: Environment-specific object path
              DGD: '/obj/thing.c'  LambdaMOO: '#123'  Smalltalk: 'MyClass'
        source: If provided, the source code to compile. If empty, recompile
                the existing object from its current source.
        """

    # -- Object inspection --

    @abc.abstractmethod
    def inspect_object(self, object_id: str) -> Deferred[ObjectInfo]:
        """Retrieve introspection data for an object."""

    @abc.abstractmethod
    def list_objects(
        self, pattern: str = "", limit: int = 100
    ) -> Deferred[list[ObjectInfo]]:
        """
        List objects matching a pattern.

        pattern: Environment-specific filter
                 DGD: glob on object path, e.g. '/usr/System/*'
                 LambdaMOO: name pattern or owner filter
                 Smalltalk: class name pattern
                 Lisp: package/symbol pattern
        """

    @abc.abstractmethod
    def get_source(self, object_id: str, method: str = "") -> Deferred[str]:
        """
        Retrieve source code for an object or a specific method/verb.

        object_id: The object identifier
        method: If provided, return only this method/verb's source.
                If empty, return the full object source.
        """

    # -- Checkpoint management --

    @abc.abstractmethod
    def create_checkpoint(
        self, label: str = "", incremental: bool = False
    ) -> Deferred[CheckpointInfo]:
        """
        Trigger a checkpoint/snapshot of the current world state.

        label: Human-readable label for the checkpoint
        incremental: If True and supported, create an incremental snapshot
        """

    @abc.abstractmethod
    def restore_checkpoint(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore the environment to a previous checkpoint.
        Returns True on success. The environment may restart.
        """

    @abc.abstractmethod
    def list_checkpoints(self) -> Deferred[list[CheckpointInfo]]:
        """List available checkpoints for this environment."""

    # -- Optional capabilities (default no-op implementations) --

    def hotboot(self, binary_path: str = "") -> Deferred[bool]:
        """Perform a zero-downtime restart preserving state (DGD only)."""
        from twisted.internet import defer

        return defer.succeed(False)

    def atomic_eval(self, code: str, timeout_ms: int = 5000) -> Deferred[EvalResult]:
        """
        Evaluate code atomically -- all side effects are rolled back on error.
        Supported natively by DGD; simulated via checkpoint/restore elsewhere.
        """
        return self.evaluate(code, timeout_ms)

    def get_object_tree(
        self, root_id: str = "", depth: int = 3
    ) -> Deferred[dict[str, Any]]:
        """
        Return a tree of objects rooted at root_id.
        Useful for understanding inheritance and containment hierarchies.
        """
        from twisted.internet import defer

        return defer.succeed({})

    # -- Utility methods --

    def has_capability(self, cap: EnvironmentCapability) -> bool:
        """Check if this environment supports a specific capability."""
        return bool(self.capabilities & cap)

    def status(self) -> dict[str, Any]:
        """Return a status dictionary for this environment."""
        return {
            "name": self.name,
            "type": self.environment_type,
            "language": self.language,
            "host": self.host,
            "port": self.port,
            "connected": self.connected,
            "capabilities": [c.name for c in EnvironmentCapability if self.has_capability(c)],
        }

    def __repr__(self) -> str:
        state = "connected" if self.connected else "disconnected"
        return f"<{self.__class__.__name__} {self.name!r} ({self.environment_type}) [{state}]>"
