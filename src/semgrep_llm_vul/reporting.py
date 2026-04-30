"""分析报告序列化。"""

from __future__ import annotations

from typing import Any

from semgrep_llm_vul.models import (
    BlockingFactor,
    CodeLocation,
    Evidence,
    FunctionSignature,
    ReachabilityAssessment,
    ReachabilityCallStep,
    ReachabilityEntrypoint,
    SemanticHint,
    SemanticHintReport,
    SinkCandidate,
    SinkGenerationReport,
    SourceControlAssessment,
    SourceReference,
    TaintPath,
    VulnerabilityInput,
)
from semgrep_llm_vul.reachability import ReachabilityReport
from semgrep_llm_vul.taint_path_generation import TaintPathGenerationReport


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


def taint_path_generation_report_to_dict(
    report: TaintPathGenerationReport,
    *,
    task: VulnerabilityInput,
) -> dict[str, Any]:
    """将 taint path generation report 转为稳定 JSON 结构。"""

    return {
        "schema_version": 1,
        "kind": "taint_path_generation_report",
        "mode": task.mode.value,
        "target": {
            "repo_url": task.target.repo_url,
            "affected_version": task.target.affected_version,
            "fixed_version": task.target.fixed_version,
            "language": task.target.language,
        },
        "paths": [_taint_path_to_dict(path) for path in report.paths],
        "evidence": [_evidence_to_dict(evidence) for evidence in report.evidence],
        "unknowns": list(report.unknowns),
    }


def reachability_report_to_dict(
    report: ReachabilityReport,
    *,
    task: VulnerabilityInput,
) -> dict[str, Any]:
    """将 reachability report 转为稳定 JSON 结构。"""

    return {
        "schema_version": 1,
        "kind": "reachability_report",
        "mode": task.mode.value,
        "target": {
            "repo_url": task.target.repo_url,
            "affected_version": task.target.affected_version,
            "fixed_version": task.target.fixed_version,
            "language": task.target.language,
        },
        "assessments": [
            _reachability_assessment_to_dict(assessment)
            for assessment in report.assessments
        ],
        "evidence": [_evidence_to_dict(evidence) for evidence in report.evidence],
        "unknowns": list(report.unknowns),
    }


def semantic_hint_report_to_dict(
    report: SemanticHintReport,
    *,
    task: VulnerabilityInput,
) -> dict[str, Any]:
    """将 semantic hint report 转为稳定 JSON 结构。"""

    return {
        "schema_version": 1,
        "kind": "semantic_hint_report",
        "mode": task.mode.value,
        "target": {
            "repo_url": task.target.repo_url,
            "affected_version": task.target.affected_version,
            "fixed_version": task.target.fixed_version,
            "language": task.target.language,
        },
        "hints": [_semantic_hint_to_dict(hint) for hint in report.hints],
        "evidence": [_evidence_to_dict(evidence) for evidence in report.evidence],
        "unknowns": list(report.unknowns),
    }


def _reachability_assessment_to_dict(
    assessment: ReachabilityAssessment,
) -> dict[str, Any]:
    return {
        "path": _taint_path_to_dict(assessment.path),
        "reachable": assessment.reachable,
        "entrypoint": _entrypoint_to_dict(assessment.entrypoint),
        "call_chain": [_call_step_to_dict(step) for step in assessment.call_chain],
        "source_control": _source_control_to_dict(assessment.source_control),
        "blocking_factors": [
            _blocking_factor_to_dict(factor)
            for factor in assessment.blocking_factors
        ],
        "evidence": [_evidence_to_dict(evidence) for evidence in assessment.evidence],
        "unknowns": list(assessment.unknowns),
    }


def _semantic_hint_to_dict(hint: SemanticHint) -> dict[str, Any]:
    return {
        "symbol": hint.symbol,
        "kind": hint.kind.value,
        "summary": hint.summary,
        "reasoning": hint.reasoning,
        "confidence": _confidence(hint.confidence),
        "location": _location_to_dict(hint.location),
        "evidence": [_evidence_to_dict(evidence) for evidence in hint.evidence],
        "applicable_versions": list(hint.applicable_versions),
        "applicable_contexts": list(hint.applicable_contexts),
        "preconditions": list(hint.preconditions),
        "failure_modes": list(hint.failure_modes),
        "unknowns": list(hint.unknowns),
    }


def _taint_path_to_dict(path: TaintPath) -> dict[str, Any]:
    return {
        "source": {
            "name": path.source.name,
            "location": _location_to_dict(path.source.location),
            "reason": path.source.reason,
            "confidence": _confidence(path.source.confidence),
            "evidence": [_evidence_to_dict(evidence) for evidence in path.source.evidence],
        },
        "sink": _candidate_to_dict(path.sink),
        "steps": [
            {
                "location": _location_to_dict(step.location),
                "role": step.role.value if step.role else None,
                "symbol": step.symbol,
                "description": step.description,
                "evidence": [_evidence_to_dict(evidence) for evidence in step.evidence],
            }
            for step in path.steps
        ],
        "reachable": path.reachable,
        "evidence": [_evidence_to_dict(evidence) for evidence in path.evidence],
    }


def _entrypoint_to_dict(
    entrypoint: ReachabilityEntrypoint | None,
) -> dict[str, Any] | None:
    if entrypoint is None:
        return None
    return {
        "kind": entrypoint.kind,
        "name": entrypoint.name,
        "location": _location_to_dict(entrypoint.location),
        "evidence": [_evidence_to_dict(evidence) for evidence in entrypoint.evidence],
    }


def _call_step_to_dict(step: ReachabilityCallStep) -> dict[str, Any]:
    return {
        "symbol": step.symbol,
        "location": _location_to_dict(step.location),
        "evidence": [_evidence_to_dict(evidence) for evidence in step.evidence],
    }


def _source_control_to_dict(
    source_control: SourceControlAssessment | None,
) -> dict[str, Any] | None:
    if source_control is None:
        return None
    return {
        "controlled": source_control.controlled,
        "reason": source_control.reason,
        "evidence": [_evidence_to_dict(evidence) for evidence in source_control.evidence],
    }


def _blocking_factor_to_dict(factor: BlockingFactor) -> dict[str, Any]:
    return {
        "kind": factor.kind,
        "summary": factor.summary,
        "location": _location_to_dict(factor.location),
        "evidence": [_evidence_to_dict(evidence) for evidence in factor.evidence],
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
