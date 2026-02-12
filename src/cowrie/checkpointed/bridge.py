"""
Bridge connecting Claude Code tools to checkpointed image environments.

This module provides the high-level interface that maps Claude Code
operations (evaluate code, inspect objects, manage checkpoints) to
the appropriate environment adapter. It serves as the entry point
for all interactions between Claude Code and the image environments.

The bridge handles:
  - Environment registration and lifecycle
  - Routing operations to the correct adapter
  - Session management (connect, authenticate, disconnect)
  - Unified result formatting for Claude Code tool output
  - Error handling and retry logic

Usage from Claude Code:
  The bridge is instantiated with a configuration section from cowrie.cfg
  and provides methods that map to Claude Code tool calls.
"""

from __future__ import annotations

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
from cowrie.checkpointed.checkpoint import CheckpointManager
from cowrie.checkpointed.adapters.dgd import DGDEnvironment
from cowrie.checkpointed.adapters.lambdamoo import LambdaMOOEnvironment
from cowrie.checkpointed.adapters.smalltalk import SmalltalkEnvironment
from cowrie.checkpointed.adapters.lispmachine import LispMachineEnvironment


# Map of environment type names to adapter classes
ADAPTER_CLASSES: dict[str, type[CheckpointedEnvironment]] = {
    "dgd": DGDEnvironment,
    "lambdamoo": LambdaMOOEnvironment,
    "moo": LambdaMOOEnvironment,
    "toaststunt": LambdaMOOEnvironment,
    "smalltalk": SmalltalkEnvironment,
    "pharo": SmalltalkEnvironment,
    "squeak": SmalltalkEnvironment,
    "gnu-smalltalk": SmalltalkEnvironment,
    "lispmachine": LispMachineEnvironment,
    "genera": LispMachineEnvironment,
    "cadr": LispMachineEnvironment,
    "lambda": LispMachineEnvironment,
    "meroko": LispMachineEnvironment,
}


class EnvironmentBridge:
    """
    High-level bridge between Claude Code and checkpointed environments.

    Manages one or more environment connections and provides a unified
    API for code evaluation, object inspection, and checkpoint management.
    """

    def __init__(self, registry_path: str = "") -> None:
        self.checkpoint_mgr = CheckpointManager(registry_path=registry_path)
        self._envs: dict[str, CheckpointedEnvironment] = {}
        self._default_env: str = ""

    @property
    def environments(self) -> dict[str, CheckpointedEnvironment]:
        return dict(self._envs)

    @property
    def default_environment(self) -> str:
        return self._default_env

    # -- Environment lifecycle --

    def create_environment(
        self, name: str, env_type: str, **kwargs: Any
    ) -> CheckpointedEnvironment:
        """
        Create and register an environment adapter.

        name: Unique name for this environment instance
        env_type: One of the keys in ADAPTER_CLASSES
        **kwargs: Passed to the adapter constructor (host, port, etc.)
        """
        adapter_cls = ADAPTER_CLASSES.get(env_type.lower())
        if adapter_cls is None:
            raise ValueError(
                f"Unknown environment type {env_type!r}. "
                f"Available: {sorted(ADAPTER_CLASSES.keys())}"
            )

        # Handle variant-specific kwargs
        if env_type.lower() in ("pharo", "squeak", "gnu-smalltalk"):
            kwargs.setdefault("variant", env_type.lower().replace("-", ""))
        if env_type.lower() in ("genera", "cadr", "lambda", "meroko"):
            kwargs.setdefault("emulator_type", env_type.lower())
        if env_type.lower() == "toaststunt":
            kwargs.setdefault("use_toaststunt", True)

        env = adapter_cls(name=name, **kwargs)
        self._envs[name] = env
        self.checkpoint_mgr.register_environment(env)

        if not self._default_env:
            self._default_env = name

        log.msg(
            f"Bridge: created {env.environment_type} environment {name!r} "
            f"-> {env.host}:{env.port}"
        )
        return env

    @inlineCallbacks
    def connect_environment(
        self,
        name: str,
        username: str = "",
        password: str = "",
    ) -> Deferred[bool]:
        """Connect to and authenticate with an environment."""
        env = self._get_env(name)
        connected = yield env.connect()
        if not connected:
            return False

        if username or password:
            authed = yield env.authenticate(username, password)
            if not authed:
                yield env.disconnect()
                return False

        return True

    @inlineCallbacks
    def disconnect_environment(self, name: str) -> Deferred[None]:
        yield self._get_env(name).disconnect()

    @inlineCallbacks
    def disconnect_all(self) -> Deferred[None]:
        for env in self._envs.values():
            if env.connected:
                try:
                    yield env.disconnect()
                except Exception as e:
                    log.err(f"Bridge: error disconnecting {env.name}: {e}")

    def set_default(self, name: str) -> None:
        """Set the default environment for operations."""
        if name not in self._envs:
            raise KeyError(f"Environment {name!r} not registered")
        self._default_env = name

    # -- Code evaluation --

    @inlineCallbacks
    def evaluate(
        self,
        code: str,
        env_name: str = "",
        timeout_ms: int = 5000,
        atomic: bool = False,
    ) -> Deferred[EvalResult]:
        """
        Evaluate code in an environment.

        code: Code in the environment's native language
        env_name: Target environment (uses default if empty)
        timeout_ms: Evaluation timeout
        atomic: If True, use atomic evaluation (DGD only natively)
        """
        env = self._get_env(env_name or self._default_env)

        if atomic and env.has_capability(EnvironmentCapability.ATOMIC_TRANSACTIONS):
            result = yield env.atomic_eval(code, timeout_ms)
        else:
            result = yield env.evaluate(code, timeout_ms)

        return result

    @inlineCallbacks
    def compile(
        self,
        path: str,
        source: str = "",
        env_name: str = "",
    ) -> Deferred[EvalResult]:
        """Compile or recompile an object from source."""
        env = self._get_env(env_name or self._default_env)
        return (yield env.compile_object(path, source))

    # -- Object inspection --

    @inlineCallbacks
    def inspect(
        self, object_id: str, env_name: str = ""
    ) -> Deferred[dict[str, Any]]:
        """
        Inspect an object and return a formatted dictionary.
        Suitable for Claude Code tool output.
        """
        env = self._get_env(env_name or self._default_env)
        info = yield env.inspect_object(object_id)
        return {
            "object_id": info.object_id,
            "name": info.name,
            "environment": env.environment_type,
            "language": env.language,
            "parent": info.parent,
            "children": info.children,
            "owner": info.owner,
            "properties": info.properties,
            "methods": info.methods,
            "location": info.location,
            "flags": info.flags,
        }

    @inlineCallbacks
    def list_objects(
        self, pattern: str = "", env_name: str = "", limit: int = 100
    ) -> Deferred[list[dict[str, str]]]:
        """List objects matching a pattern, formatted for tool output."""
        env = self._get_env(env_name or self._default_env)
        objects = yield env.list_objects(pattern, limit)
        return [
            {"id": o.object_id, "name": o.name, "parent": o.parent}
            for o in objects
        ]

    @inlineCallbacks
    def get_source(
        self, object_id: str, method: str = "", env_name: str = ""
    ) -> Deferred[str]:
        """Retrieve source code for an object or method."""
        env = self._get_env(env_name or self._default_env)
        return (yield env.get_source(object_id, method))

    # -- Checkpoint management --

    @inlineCallbacks
    def checkpoint(
        self,
        env_name: str = "",
        label: str = "",
        incremental: bool = False,
    ) -> Deferred[dict[str, Any]]:
        """Create a checkpoint and return formatted metadata."""
        name = env_name or self._default_env
        info = yield self.checkpoint_mgr.create(
            name, label=label, incremental=incremental
        )
        return {
            "checkpoint_id": info.checkpoint_id,
            "environment": info.environment_type,
            "timestamp": info.timestamp,
            "label": info.label,
            "incremental": info.incremental,
        }

    @inlineCallbacks
    def restore(self, checkpoint_id: str) -> Deferred[bool]:
        """Restore an environment to a checkpoint."""
        return (yield self.checkpoint_mgr.restore(checkpoint_id))

    def list_checkpoints(self, env_name: str = "") -> list[dict[str, Any]]:
        """List checkpoints, optionally filtered by environment."""
        if env_name:
            checkpoints = self.checkpoint_mgr.list_for_environment(env_name)
        else:
            checkpoints = self.checkpoint_mgr.list_all()
        return [
            {
                "checkpoint_id": c.checkpoint_id,
                "environment": c.environment_type,
                "timestamp": c.timestamp,
                "label": c.label,
                "age_seconds": c.age_seconds,
            }
            for c in checkpoints
        ]

    # -- Status and discovery --

    def status(self) -> dict[str, Any]:
        """Return bridge status suitable for tool output."""
        return {
            "environments": {
                name: env.status() for name, env in self._envs.items()
            },
            "default": self._default_env,
            "checkpoint_count": len(self.checkpoint_mgr.checkpoints),
            "supported_types": sorted(ADAPTER_CLASSES.keys()),
        }

    def environment_info(self, env_name: str = "") -> dict[str, Any]:
        """Get detailed info about an environment."""
        env = self._get_env(env_name or self._default_env)
        status = env.status()
        status["language_examples"] = _LANGUAGE_EXAMPLES.get(
            env.environment_type, {}
        )
        return status

    # -- Internal --

    def _get_env(self, name: str) -> CheckpointedEnvironment:
        if not name:
            raise ValueError("No environment specified and no default set")
        if name not in self._envs:
            raise KeyError(
                f"Environment {name!r} not registered. "
                f"Available: {list(self._envs.keys())}"
            )
        return self._envs[name]


# Language-specific code examples for Claude Code context
_LANGUAGE_EXAMPLES: dict[str, dict[str, str]] = {
    "dgd": {
        "eval": 'code 1 + 2',
        "compile": 'compile /obj/example',
        "recompile": 'upgrade /obj/example',
        "inspect": 'status /obj/example',
        "checkpoint": 'code dump_state(1)',
        "hello_world": 'code "Hello, World!"',
        "define_object": (
            'inherit "/lib/base";\n'
            'string name;\n'
            'void create() { name = "example"; }\n'
            'string query_name() { return name; }'
        ),
    },
    "lambdamoo": {
        "eval": '; 1 + 2',
        "compile": '@program #123:verb_name',
        "inspect": '@show #123',
        "list_verbs": '@display #123',
        "checkpoint": '; dump_database()',
        "hello_world": '; player:tell("Hello, World!");',
        "define_verb": (
            '@verb #123:greet this none this\n'
            '@program #123:greet\n'
            'player:tell("Hello, " + this.name + "!");\n'
            '.'
        ),
    },
    "smalltalk": {
        "eval": "3 + 4",
        "compile": "MyClass compile: 'myMethod ^42'",
        "inspect": "MyClass inspect",
        "checkpoint": "Smalltalk snapshot: true andQuit: false",
        "hello_world": "Transcript show: 'Hello, World!'",
        "define_class": (
            "Object subclass: #MyClass\n"
            "  instanceVariableNames: 'name'\n"
            "  classVariableNames: ''\n"
            "  package: 'MyPackage'"
        ),
    },
    "lispmachine": {
        "eval": "(+ 1 2)",
        "compile": ':Compile File SYS:EXAMPLE;CODE.LISP',
        "inspect": "(describe 'make-instance)",
        "checkpoint": ':Save World "checkpoint"',
        "hello_world": '(format t "Hello, World!~%")',
        "define_function": (
            "(defun greet (name)\n"
            '  (format t "Hello, ~A!~%" name))'
        ),
        "define_class": (
            "(defclass person ()\n"
            "  ((name :initarg :name :accessor person-name)\n"
            "   (age  :initarg :age  :accessor person-age)))"
        ),
    },
}
