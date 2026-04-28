"""分析报告序列化。"""

from __future__ import annotations

from typing import Any

from semgrep_llm_vul.models import (
    CodeLocation,
    Evidence,
    FunctionSignature,
    SinkCandidate,
    SinkGenerationReport,
    SourceReference,
    VulnerabilityInput,
)


def sink_generation_report_to_dict(
    report: SinkGenerationReport,
    *,
    task: VulnerabilityInput,
) -> dict[str, Any]:
    """将 sink generation report 转为稳定 JSON 结构。"""

    return {
        "schema_version": 1,
        "kind": "sink_generation_report",
        "mode": task.mode.value,
        "target": {
            "repo_url": task.target.repo_url,
            "affected_version": task.target.affected_version,
            "fixed_version": task.target.fixed_version,
            "language": task.target.language,
        },
        "recommended": _candidate_to_dict(report.recommended),
        "candidates": [_candidate_to_dict(candidate) for candidate in report.candidates],
        "evidence": [_evidence_to_dict(evidence) for evidence in report.evidence],
        "unknowns": list(report.unknowns),
    }


def _candidate_to_dict(candidate: SinkCandidate | None) -> dict[str, Any] | None:
    if candidate is None:
        return None
    return {
        "signature": _signature_to_dict(candidate.signature),
        "reason": candidate.reason,
        "confidence": _confidence(candidate.confidence),
        "evidence": [_evidence_to_dict(evidence) for evidence in candidate.evidence],
    }


def _signature_to_dict(signature: FunctionSignature) -> dict[str, Any]:
    return {
        "raw": signature.raw,
        "name": signature.name,
        "receiver": signature.receiver,
        "parameters": list(signature.parameters),
        "returns": signature.returns,
        "location": _location_to_dict(signature.location),
        "language": signature.language,
    }


def _evidence_to_dict(evidence: Evidence) -> dict[str, Any]:
    return {
        "source": _source_reference_to_dict(evidence.source),
        "summary": evidence.summary,
        "reasoning": evidence.reasoning,
        "confidence": _confidence(evidence.confidence),
        "reproducible_steps": list(evidence.reproducible_steps),
        "open_questions": list(evidence.open_questions),
    }


def _source_reference_to_dict(source: SourceReference) -> dict[str, Any]:
    return {
        "kind": source.kind.value,
        "uri": source.uri,
        "commit": source.commit,
        "location": _location_to_dict(source.location),
        "metadata": source.metadata,
    }


def _location_to_dict(location: CodeLocation | None) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": location.path,
        "start_line": location.start_line,
        "start_col": location.start_col,
        "end_line": location.end_line,
        "end_col": location.end_col,
    }


def _confidence(value: float) -> float:
    return round(value, 4)
