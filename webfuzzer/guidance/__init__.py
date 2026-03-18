"""Static analysis guidance for differential fuzzing.

Combines protocol-aware static analysis with fuzzer feedback loops
to guide mutation toward authentication bypass paths.

Architecture:
    ProtocolSpec  → defines required security checkpoints per protocol
    Analyzer      → extracts GuidanceProfile from library source code
    GuidanceEngine → bidirectional bridge between analysis and fuzzer
"""

from webfuzzer.guidance.profile import (
    CheckpointStatus,
    ErrorSwallow,
    GuidanceProfile,
    TaintPath,
)
from webfuzzer.guidance.spec import Checkpoint, ProtocolSpec
from webfuzzer.guidance.engine import GuidanceEngine

__all__ = [
    "Checkpoint",
    "CheckpointStatus",
    "ErrorSwallow",
    "GuidanceEngine",
    "GuidanceProfile",
    "ProtocolSpec",
    "TaintPath",
]
