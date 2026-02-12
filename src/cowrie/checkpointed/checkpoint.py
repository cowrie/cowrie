"""
Checkpoint manager for image-based environments.

Manages the lifecycle of checkpoints (snapshots) across all environment
types. Provides a unified interface for creating, restoring, listing,
comparing, and pruning checkpoints regardless of the underlying
environment's native checkpoint mechanism.

Checkpoint storage:
  - DGD: statedumps written by the DGD driver to its configured path
  - LambdaMOO: database dumps forked to the checkpoint file path
  - Smalltalk: .image files saved by the VM
  - Lisp Machines: .vlod world files or IDS (incremental disk saves)

The manager tracks checkpoint metadata in a local registry and delegates
actual snapshot creation/restoration to each environment's adapter.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from twisted.internet import defer
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.python import log

from cowrie.checkpointed.base import (
    CheckpointedEnvironment,
    CheckpointInfo,
    EnvironmentCapability,
)


class CheckpointManager:
    """
    Manages checkpoints across one or more checkpointed environments.

    Tracks checkpoint metadata in a JSON registry file and delegates
    to environment adapters for the actual snapshot operations.
    """

    def __init__(self, registry_path: str = "") -> None:
        self.registry_path = registry_path or os.path.join(
            os.getcwd(), "var", "lib", "cowrie", "checkpoints.json"
        )
        self._environments: dict[str, CheckpointedEnvironment] = {}
        self._checkpoints: dict[str, CheckpointInfo] = {}
        self._load_registry()

    def register_environment(self, env: CheckpointedEnvironment) -> None:
        """Register an environment for checkpoint management."""
        self._environments[env.name] = env
        log.msg(
            f"CheckpointManager: registered {env.environment_type} "
            f"environment {env.name!r}"
        )

    def unregister_environment(self, name: str) -> None:
        self._environments.pop(name, None)

    @property
    def environments(self) -> dict[str, CheckpointedEnvironment]:
        return dict(self._environments)

    @property
    def checkpoints(self) -> dict[str, CheckpointInfo]:
        return dict(self._checkpoints)

    # -- Checkpoint operations --

    @inlineCallbacks
    def create(
        self,
        env_name: str,
        label: str = "",
        incremental: bool = False,
    ) -> Deferred[CheckpointInfo]:
        """
        Create a checkpoint for the named environment.
        Returns the CheckpointInfo with a unique ID.
        """
        env = self._get_env(env_name)
        if not env.has_capability(EnvironmentCapability.CHECKPOINT):
            raise ValueError(
                f"Environment {env_name!r} does not support checkpoints"
            )
        if incremental and not env.has_capability(
            EnvironmentCapability.INCREMENTAL_CHECKPOINT
        ):
            log.msg(
                f"CheckpointManager: {env_name} does not support incremental "
                f"checkpoints, falling back to full checkpoint"
            )
            incremental = False

        log.msg(
            f"CheckpointManager: creating {'incremental ' if incremental else ''}"
            f"checkpoint for {env_name!r}"
            + (f" label={label!r}" if label else "")
        )

        info = yield env.create_checkpoint(label=label, incremental=incremental)

        # Assign a registry ID if the adapter didn't
        if not info.checkpoint_id:
            info.checkpoint_id = str(uuid.uuid4())[:12]

        self._checkpoints[info.checkpoint_id] = info
        self._save_registry()

        log.msg(
            f"CheckpointManager: checkpoint {info.checkpoint_id} created "
            f"for {env_name!r}"
        )
        return info

    @inlineCallbacks
    def restore(self, checkpoint_id: str) -> Deferred[bool]:
        """
        Restore an environment to a previously created checkpoint.
        The environment may restart; reconnection may be required.
        """
        info = self._get_checkpoint(checkpoint_id)
        env_name = info.metadata.get("env_name", "")

        # Find the environment that owns this checkpoint
        env = None
        if env_name and env_name in self._environments:
            env = self._environments[env_name]
        else:
            for e in self._environments.values():
                if e.environment_type == info.environment_type:
                    env = e
                    break

        if env is None:
            raise ValueError(
                f"No registered environment for checkpoint {checkpoint_id} "
                f"(type={info.environment_type})"
            )

        if not env.has_capability(EnvironmentCapability.RESTORE):
            raise ValueError(
                f"Environment {env.name!r} does not support restore"
            )

        log.msg(
            f"CheckpointManager: restoring {env.name!r} to checkpoint "
            f"{checkpoint_id}"
        )
        success = yield env.restore_checkpoint(checkpoint_id)
        return success

    def list_for_environment(self, env_name: str) -> list[CheckpointInfo]:
        """List all tracked checkpoints for a specific environment."""
        env = self._get_env(env_name)
        return [
            c
            for c in self._checkpoints.values()
            if c.environment_type == env.environment_type
            or c.metadata.get("env_name") == env_name
        ]

    def list_all(self) -> list[CheckpointInfo]:
        """List all tracked checkpoints, sorted by timestamp descending."""
        return sorted(
            self._checkpoints.values(),
            key=lambda c: c.timestamp,
            reverse=True,
        )

    @inlineCallbacks
    def sync_from_environment(self, env_name: str) -> Deferred[list[CheckpointInfo]]:
        """
        Query the environment for its known checkpoints and merge them
        into the local registry. Useful for discovering checkpoints
        created outside this manager.
        """
        env = self._get_env(env_name)
        remote = yield env.list_checkpoints()
        added = 0
        for info in remote:
            if info.checkpoint_id not in self._checkpoints:
                info.metadata["env_name"] = env_name
                self._checkpoints[info.checkpoint_id] = info
                added += 1
        if added:
            self._save_registry()
            log.msg(
                f"CheckpointManager: synced {added} new checkpoint(s) "
                f"from {env_name!r}"
            )
        return remote

    def prune(self, max_age_seconds: float = 0, max_count: int = 0) -> int:
        """
        Remove old checkpoint records from the registry.
        Does NOT delete the actual snapshot files.

        max_age_seconds: Remove checkpoints older than this (0 = no age limit)
        max_count: Keep at most this many checkpoints per environment (0 = no limit)

        Returns the number of pruned entries.
        """
        pruned = 0
        now = time.time()

        if max_age_seconds > 0:
            expired = [
                cid
                for cid, c in self._checkpoints.items()
                if (now - c.timestamp) > max_age_seconds
            ]
            for cid in expired:
                del self._checkpoints[cid]
                pruned += 1

        if max_count > 0:
            by_type: dict[str, list[tuple[str, CheckpointInfo]]] = {}
            for cid, c in self._checkpoints.items():
                by_type.setdefault(c.environment_type, []).append((cid, c))
            for env_type, entries in by_type.items():
                entries.sort(key=lambda x: x[1].timestamp, reverse=True)
                for cid, _ in entries[max_count:]:
                    if cid in self._checkpoints:
                        del self._checkpoints[cid]
                        pruned += 1

        if pruned:
            self._save_registry()
        return pruned

    # -- Internal helpers --

    def _get_env(self, name: str) -> CheckpointedEnvironment:
        if name not in self._environments:
            raise KeyError(
                f"Environment {name!r} not registered. "
                f"Available: {list(self._environments.keys())}"
            )
        return self._environments[name]

    def _get_checkpoint(self, checkpoint_id: str) -> CheckpointInfo:
        if checkpoint_id not in self._checkpoints:
            raise KeyError(
                f"Checkpoint {checkpoint_id!r} not found in registry"
            )
        return self._checkpoints[checkpoint_id]

    def _load_registry(self) -> None:
        if not os.path.exists(self.registry_path):
            return
        try:
            with open(self.registry_path) as f:
                data = json.load(f)
            for entry in data.get("checkpoints", []):
                info = CheckpointInfo(
                    checkpoint_id=entry["checkpoint_id"],
                    environment_type=entry["environment_type"],
                    timestamp=entry.get("timestamp", 0),
                    label=entry.get("label", ""),
                    size_bytes=entry.get("size_bytes", 0),
                    incremental=entry.get("incremental", False),
                    parent_id=entry.get("parent_id", ""),
                    metadata=entry.get("metadata", {}),
                )
                self._checkpoints[info.checkpoint_id] = info
        except (json.JSONDecodeError, OSError) as e:
            log.err(f"CheckpointManager: failed to load registry: {e}")

    def _save_registry(self) -> None:
        data = {
            "checkpoints": [
                {
                    "checkpoint_id": c.checkpoint_id,
                    "environment_type": c.environment_type,
                    "timestamp": c.timestamp,
                    "label": c.label,
                    "size_bytes": c.size_bytes,
                    "incremental": c.incremental,
                    "parent_id": c.parent_id,
                    "metadata": c.metadata,
                }
                for c in self._checkpoints.values()
            ]
        }
        try:
            os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
            with open(self.registry_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            log.err(f"CheckpointManager: failed to save registry: {e}")
