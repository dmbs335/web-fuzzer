"""Language-specific static analyzers.

Each analyzer takes library source code + a ProtocolSpec,
and produces a GuidanceProfile.
"""

from webfuzzer.guidance.analyzers.base import BaseAnalyzer

__all__ = ["BaseAnalyzer"]
