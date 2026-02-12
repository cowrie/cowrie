# Checkpointed Image Environment Integration for Claude Code
#
# This module provides a unified interface for Claude Code to interact with
# checkpointed image environments: persistent runtime systems where the
# entire program state (objects, code, data, execution context) lives as
# a single mutable world that can be snapshotted and restored.
#
# Supported environments:
#   - DGD (Dworkin's Game Driver): LPC-based persistent application server
#   - LambdaMOO: MOO-based virtual world with periodic database checkpoints
#   - Smalltalk (Pharo/Squeak/GNU): Image-based object environment
#   - Lisp Machines (Open Genera, CADR, Lambda): World/band-based Lisp systems
#
# Architecture:
#   CheckpointedEnvironment (base.py) - abstract protocol for all environments
#   CheckpointManager (checkpoint.py) - snapshot lifecycle management
#   EnvironmentBridge (bridge.py)     - connects Claude Code tools to environments
#   adapters/                         - environment-specific implementations

from cowrie.checkpointed.base import (
    CheckpointedEnvironment,
    EnvironmentCapability,
    CheckpointInfo,
    ObjectInfo,
    EvalResult,
)
from cowrie.checkpointed.checkpoint import CheckpointManager
from cowrie.checkpointed.bridge import EnvironmentBridge

__all__ = [
    "CheckpointedEnvironment",
    "EnvironmentCapability",
    "CheckpointInfo",
    "ObjectInfo",
    "EvalResult",
    "CheckpointManager",
    "EnvironmentBridge",
]
