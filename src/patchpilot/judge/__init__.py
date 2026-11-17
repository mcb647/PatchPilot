"""PatchPilot P1 Judge package (contract, context, orchestration, adapters).

The package is deliberately importable without any optional dependency: the
only network client uses :mod:`urllib` from the standard library.
"""

from __future__ import annotations

from .contract import (
    AdapterResult,
    JudgeAdapterError,
    JudgeContext,
    JudgeRequest,
    validate_verdict,
)
from .context import build_contexts, estimate_tokens
from .runner import JudgeRunResult, run_judge

__all__ = [
    "AdapterResult",
    "JudgeAdapterError",
    "JudgeContext",
    "JudgeRequest",
    "JudgeRunResult",
    "build_contexts",
    "estimate_tokens",
    "run_judge",
    "validate_verdict",
]
