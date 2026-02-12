# Environment-specific adapters for checkpointed image systems.
#
# Each adapter implements CheckpointedEnvironment for a specific runtime:
#   dgd.py         - DGD (Dworkin's Game Driver) via telnet/binary ports
#   lambdamoo.py   - LambdaMOO/ToastStunt via telnet or HTTP
#   smalltalk.py   - Pharo/GNU Smalltalk via HTTP API, NeoConsole, or pipe
#   lispmachine.py - Lisp Machines (Open Genera, CADR) via telnet and NFS

from cowrie.checkpointed.adapters.dgd import DGDEnvironment
from cowrie.checkpointed.adapters.lambdamoo import LambdaMOOEnvironment
from cowrie.checkpointed.adapters.smalltalk import SmalltalkEnvironment
from cowrie.checkpointed.adapters.lispmachine import LispMachineEnvironment

__all__ = [
    "DGDEnvironment",
    "LambdaMOOEnvironment",
    "SmalltalkEnvironment",
    "LispMachineEnvironment",
]
