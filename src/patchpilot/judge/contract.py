"""Judge wire contract: request/context dataclasses, adapter boundary and validation.

Nothing in this module talks to the network.  ``validate_verdict`` is the single
trust boundary between an adapter (or an LLM response) and the rest of
PatchPilot: every verdict that reaches storage has passed it, so evidence
locations are guaranteed to refer to source ranges that were actually sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import models

# Bounds from docs/CONTRACTS-P1.md section 5.1.
MAX_REASON_CHARS = 1000
MAX_CONDITIONS = 10
MAX_CONDITION_CHARS = 200
MAX_UNCERTAINTY_CHARS = 300


@dataclass
class JudgeContext:
    """The minimal, budgeted evidence bundle sent for one impact candidate."""

    candidate_id: str
    symbol_change_id: str
    seed_symbol_id: str
    candidate_symbol_id: str
    side: str
    evidence: list[models.JudgeEvidenceRef] = field(default_factory=list)
    omitted: list[str] = field(default_factory=list)
    text: str = ""
    digest: str = ""
    estimated_tokens: int = 0


@dataclass
class JudgeRequest:
    request_id: str
    schema_version: int = models.JUDGE_SCHEMA_VERSION
    prompt_version: str = models.JUDGE_PROMPT_VERSION
    candidate_id: str = ""
    symbol_change_id: str = ""
    context: JudgeContext | None = None
    deadline_seconds: int = 20


@dataclass
class AdapterResult:
    adapter: str
    model: str | None
    raw: dict
    request_id: str | None = None
    usage: dict = field(default_factory=dict)


class JudgeAdapterError(Exception):
    """Normalized adapter failure; ``category`` is a ``models.JUDGE_ERROR_*`` value."""

    def __init__(
        self,
        category: str,
        message: str,
        retryable: bool = False,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category or models.JUDGE_ERROR_UNAVAILABLE
        self.message = message
        self.retryable = retryable
        self.request_id = request_id


def _invalid(message: str) -> JudgeAdapterError:
    return JudgeAdapterError(models.JUDGE_ERROR_INVALID_OUTPUT, message)


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid(f"{name} must be an integer")
    return value


def _validate_evidence_ref(
    item: Any, sent: list[models.JudgeEvidenceRef]
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise _invalid("verdict evidence entries must be objects")
    path = item.get("path")
    side = item.get("side")
    if not isinstance(path, str) or not path:
        raise _invalid("verdict evidence is missing a path")
    if side not in models.SIDES:
        raise _invalid("verdict evidence has an invalid side")
    start_line = _require_int(item.get("start_line"), "evidence.start_line")
    end_line = _require_int(item.get("end_line"), "evidence.end_line")
    if start_line < 1 or end_line < start_line:
        raise _invalid("verdict evidence has an invalid line range")

    evidence_id = item.get("evidence_id")
    if evidence_id is not None and not isinstance(evidence_id, str):
        raise _invalid("verdict evidence_id must be a string")

    matched: models.JudgeEvidenceRef | None = None
    for sent_ref in sent:
        if evidence_id is not None and sent_ref.evidence_id != evidence_id:
            continue
        if sent_ref.path != path or sent_ref.side != side:
            continue
        if sent_ref.start_line <= start_line and end_line <= sent_ref.end_line:
            matched = sent_ref
            break
    if matched is None:
        # A model may not cite a location that was not part of the request.
        raise _invalid("verdict evidence does not match a range that was sent")

    return {
        "evidence_id": matched.evidence_id,
        "path": path,
        "side": side,
        "start_line": start_line,
        "end_line": end_line,
        "kind": matched.kind,
    }


def _validate_conditions(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise _invalid("conditions must be a list of strings")
    if len(raw) > MAX_CONDITIONS:
        raise _invalid(f"conditions must contain at most {MAX_CONDITIONS} entries")
    conditions: list[str] = []
    for condition in raw:
        if not isinstance(condition, str):
            raise _invalid("conditions must be a list of strings")
        if len(condition) > MAX_CONDITION_CHARS:
            raise _invalid(f"each condition must be at most {MAX_CONDITION_CHARS} characters")
        condition = condition.strip()
        if condition:
            conditions.append(condition)
    return conditions


def _validate_uncertainty(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise _invalid("uncertainty must be a string or null")
    uncertainty = raw.strip()
    if len(uncertainty) > MAX_UNCERTAINTY_CHARS:
        raise _invalid(f"uncertainty must be at most {MAX_UNCERTAINTY_CHARS} characters")
    return uncertainty or None


def validate_verdict(raw: dict, request: JudgeRequest) -> models.JudgeVerdict:
    """Validate one adapter payload and convert it into a :class:`models.JudgeVerdict`.

    The returned verdict has ``attempt_no=0``, ``adapter=""`` and ``model=None``;
    the runner fills those in from the attempt that produced it.  Any contract
    violation raises ``JudgeAdapterError("invalid_output")``.
    """

    if not isinstance(raw, dict):
        raise _invalid("adapter output must be a JSON object")

    verdict = raw.get("verdict")
    if verdict not in models.VERDICTS:
        raise _invalid("adapter output has an invalid verdict value")

    candidate_id = raw.get("candidate_id")
    if not isinstance(candidate_id, str) or candidate_id != request.candidate_id:
        raise _invalid("adapter output does not match the requested candidate")

    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise _invalid("adapter output is missing a reason")
    reason = reason.strip()
    if len(reason) > MAX_REASON_CHARS:
        raise _invalid(f"reason must be at most {MAX_REASON_CHARS} characters")

    context = request.context
    sent = list(context.evidence) if context is not None else []

    raw_evidence = raw.get("evidence", [])
    if raw_evidence is None:
        raw_evidence = []
    if not isinstance(raw_evidence, list):
        raise _invalid("evidence must be a list")
    evidence = [_validate_evidence_ref(item, sent) for item in raw_evidence]

    conditions = _validate_conditions(raw.get("conditions"))
    uncertainty = _validate_uncertainty(raw.get("uncertainty"))

    return models.JudgeVerdict(
        candidate_id=candidate_id,
        attempt_no=0,
        verdict=verdict,
        reason=reason,
        adapter="",
        model=None,
        evidence=evidence,
        conditions=conditions,
        uncertainty=uncertainty,
    )
