"""M2 最小可触达确认。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semgrep_llm_vul.models import (
    BlockingFactor,
    CodeLocation,
    Evidence,
    EvidenceKind,
    ReachabilityAssessment,
    ReachabilityCallStep,
    ReachabilityEntrypoint,
    SourceControlAssessment,
    SourceReference,
    TaintPath,
    VulnerabilityInput,
)
from semgrep_llm_vul.taint_path_generation import TaintPathGenerationReport


class ReachabilityEvidenceError(ValueError):
    """可触达证据输入无法读取或无法解析。"""


@dataclass(frozen=True)
class ReachabilityEvidenceRecord:
    """本地可触达证据记录。"""

    path_match: dict[str, Any]
    reachable: bool | None
    entrypoint: ReachabilityEntrypoint | None = None
    call_chain: tuple[ReachabilityCallStep, ...] = ()
    source_control: SourceControlAssessment | None = None
    blocking_factors: tuple[BlockingFactor, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.reachable is False and not self.blocking_factors:
            raise ReachabilityEvidenceError(
                "reachable=false 的证据记录必须提供 blocking_factors"
            )
        if self.reachable is True and self.entrypoint is None:
            raise ReachabilityEvidenceError("reachable=true 的证据记录必须提供 entrypoint")
        if self.reachable is True and not self.call_chain:
            raise ReachabilityEvidenceError("reachable=true 的证据记录必须提供 call_chain")


@dataclass(frozen=True)
class ReachabilityReport:
    """可触达确认报告。"""

    assessments: tuple[ReachabilityAssessment, ...]
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


def load_reachability_evidence(path: str | Path) -> tuple[ReachabilityEvidenceRecord, ...]:
    """读取本地 reachability JSON 证据。"""

    evidence_path = Path(path)
    try:
        text = evidence_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReachabilityEvidenceError(f"无法读取 reachability evidence：{path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReachabilityEvidenceError(f"reachability evidence 不是有效 JSON：{path}") from exc
    if not isinstance(data, dict):
        raise ReachabilityEvidenceError("reachability evidence 必须是 object")
    if data.get("schema_version") != 1:
        raise ReachabilityEvidenceError("reachability evidence schema_version 必须是 1")
    records = data.get("assessments")
    if not isinstance(records, list):
        raise ReachabilityEvidenceError("reachability evidence assessments 必须是 list")
    return tuple(_record_from_dict(item, evidence_path=evidence_path) for item in records)


def generate_reachability_report(
    task: VulnerabilityInput,
    *,
    taint_report: TaintPathGenerationReport,
    evidence_records: tuple[ReachabilityEvidenceRecord, ...] = (),
) -> ReachabilityReport:
    """从候选 taint path 和本地证据生成可触达确认报告。"""

    report_evidence = (_task_evidence(task),)
    unknowns: list[str] = []

    if not taint_report.paths:
        unknowns.append("缺少 candidate taint path，无法进行可触达确认。")
        return ReachabilityReport(
            assessments=(),
            evidence=report_evidence,
            unknowns=tuple(unknowns),
        )
    if not evidence_records:
        unknowns.append("缺少本地 reachability evidence，所有路径保持 reachable=null。")

    assessments = tuple(
        _assess_path(path, evidence_records=evidence_records)
        for path in taint_report.paths
    )
    return ReachabilityReport(
        assessments=assessments,
        evidence=report_evidence,
        unknowns=tuple(dict.fromkeys(unknowns)),
    )


def _record_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityEvidenceRecord:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("reachability assessment 必须是 object")
    path_match = item.get("path_match")
    if not isinstance(path_match, dict):
        raise ReachabilityEvidenceError("reachability assessment.path_match 必须是 object")
    reachable = item.get("reachable")
    if reachable not in {True, False, None}:
        raise ReachabilityEvidenceError("reachability assessment.reachable 必须是 true/false/null")
    entrypoint = _entrypoint_from_dict(item.get("entrypoint"), evidence_path=evidence_path)
    call_chain = tuple(
        _call_step_from_dict(step, evidence_path=evidence_path)
        for step in _optional_list(item, "call_chain")
    )
    source_control = _source_control_from_dict(
        item.get("source_control"),
        evidence_path=evidence_path,
    )
    blocking_factors = tuple(
        _blocking_factor_from_dict(factor, evidence_path=evidence_path)
        for factor in _optional_list(item, "blocking_factors")
    )
    evidence = tuple(
        _evidence_from_dict(evidence_item, evidence_path=evidence_path)
        for evidence_item in _optional_list(item, "evidence")
    )
    unknowns = tuple(_str_list(item, "unknowns"))
    return ReachabilityEvidenceRecord(
        path_match=path_match,
        reachable=reachable,
        entrypoint=entrypoint,
        call_chain=call_chain,
        source_control=source_control,
        blocking_factors=blocking_factors,
        evidence=evidence,
        unknowns=unknowns,
    )


def _assess_path(
    path: TaintPath,
    *,
    evidence_records: tuple[ReachabilityEvidenceRecord, ...],
) -> ReachabilityAssessment:
    record = next(
        (candidate for candidate in evidence_records if _matches_path(path, candidate.path_match)),
        None,
    )
    if record is None:
        return ReachabilityAssessment(
            path=_path_with_reachability(path, None),
            reachable=None,
            unknowns=("未找到匹配该 taint path 的本地 reachability evidence。",),
        )
    evidence = (
        *record.evidence,
        _assessment_evidence(record),
    )
    return ReachabilityAssessment(
        path=_path_with_reachability(path, record.reachable),
        reachable=record.reachable,
        entrypoint=record.entrypoint,
        call_chain=record.call_chain,
        source_control=record.source_control,
        blocking_factors=record.blocking_factors,
        evidence=evidence,
        unknowns=record.unknowns,
    )


def _path_with_reachability(path: TaintPath, reachable: bool | None) -> TaintPath:
    return TaintPath(
        source=path.source,
        sink=path.sink,
        steps=path.steps,
        reachable=reachable,
        evidence=path.evidence,
    )


def _matches_path(path: TaintPath, path_match: dict[str, Any]) -> bool:
    if "source_name" in path_match and path.source.name != path_match["source_name"]:
        return False
    if "sink_name" in path_match and path.sink.signature.name != path_match["sink_name"]:
        return False
    source = path_match.get("source")
    if isinstance(source, dict) and not _location_matches(path.source.location, source):
        return False
    sink = path_match.get("sink")
    if isinstance(sink, dict) and not _location_matches(path.sink.signature.location, sink):
        return False
    return True


def _location_matches(actual: CodeLocation | None, expected: dict[str, Any]) -> bool:
    if actual is None:
        return False
    if "path" in expected and actual.path != expected["path"]:
        return False
    if "start_line" in expected and actual.start_line != expected["start_line"]:
        return False
    return True


def _entrypoint_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityEntrypoint | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("entrypoint 必须是 object")
    kind = _required_str(item, "kind")
    name = _required_str(item, "name")
    location = _location_from_dict(item.get("location"))
    return ReachabilityEntrypoint(
        kind=kind,
        name=name,
        location=location,
        evidence=(_auto_evidence(f"入口证据：{name}", evidence_path, location),),
    )


def _call_step_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityCallStep:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("call_chain[] 必须是 object")
    symbol = _required_str(item, "symbol")
    location = _location_from_dict(item.get("location"))
    return ReachabilityCallStep(
        symbol=symbol,
        location=location,
        evidence=(_auto_evidence(f"调用链节点：{symbol}", evidence_path, location),),
    )


def _source_control_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> SourceControlAssessment | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("source_control 必须是 object")
    controlled = item.get("controlled")
    if controlled not in {True, False, None}:
        raise ReachabilityEvidenceError("source_control.controlled 必须是 true/false/null")
    reason = _required_str(item, "reason")
    return SourceControlAssessment(
        controlled=controlled,
        reason=reason,
        evidence=(_auto_evidence(f"source 可控性：{reason}", evidence_path, None),),
    )


def _blocking_factor_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> BlockingFactor:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("blocking_factors[] 必须是 object")
    kind = _required_str(item, "kind")
    summary = _required_str(item, "summary")
    location = _location_from_dict(item.get("location"))
    return BlockingFactor(
        kind=kind,
        summary=summary,
        location=location,
        evidence=(_auto_evidence(f"阻断因素：{summary}", evidence_path, location),),
    )


def _evidence_from_dict(item: Any, *, evidence_path: Path) -> Evidence:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("evidence[] 必须是 object")
    summary = _required_str(item, "summary")
    reasoning = _required_str(item, "reasoning")
    confidence = item.get("confidence", 0.6)
    if not isinstance(confidence, int | float):
        raise ReachabilityEvidenceError("evidence[].confidence 必须是 number")
    location = _location_from_dict(item.get("location"))
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(evidence_path),
            location=location,
        ),
        summary=summary,
        reasoning=reasoning,
        confidence=float(confidence),
        reproducible_steps=(f"inspect {evidence_path}",),
    )


def _assessment_evidence(record: ReachabilityEvidenceRecord) -> Evidence:
    state = "unknown" if record.reachable is None else str(record.reachable).lower()
    open_questions = record.unknowns
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            metadata={
                "reachable": record.reachable,
                "path_match": record.path_match,
            },
        ),
        summary=f"本地 reachability evidence 给出 reachable={state}。",
        reasoning=(
            "该结论来自本地结构化证据，只表示 M2 静态可触达确认，"
            "不表示 PoC 已触发或漏洞已验证。"
        ),
        confidence=0.7 if record.reachable is True else 0.6,
        open_questions=open_questions,
    )


def _task_evidence(task: VulnerabilityInput) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.VULNERABILITY_DESCRIPTION,
            uri=task.target.repo_url,
            metadata={
                "affected_version": task.target.affected_version,
                "fixed_version": task.target.fixed_version,
                "mode": task.mode.value,
            },
        ),
        summary="漏洞描述作为可触达确认任务的语义输入。",
        reasoning="可触达确认必须由入口、调用链、阻断因素和路径证据锚定。",
        confidence=0.3,
        open_questions=("需要确认该静态可触达判断是否足以支撑后续 PoC。",),
    )


def _auto_evidence(
    summary: str,
    evidence_path: Path,
    location: CodeLocation | None,
) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(evidence_path),
            location=location,
        ),
        summary=summary,
        reasoning="该证据来自本地 reachability evidence JSON。",
        confidence=0.6,
        reproducible_steps=(f"inspect {evidence_path}",),
    )


def _location_from_dict(item: Any) -> CodeLocation | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("location 必须是 object")
    path = _required_str(item, "path")
    return CodeLocation(
        path=path,
        start_line=_optional_int(item, "start_line"),
        start_col=_optional_int(item, "start_col"),
        end_line=_optional_int(item, "end_line"),
        end_col=_optional_int(item, "end_col"),
    )


def _optional_list(data: dict[str, Any], field: str) -> list[Any]:
    value = data.get(field, [])
    if not isinstance(value, list):
        raise ReachabilityEvidenceError(f"{field} 必须是 list")
    return value


def _str_list(data: dict[str, Any], field: str) -> list[str]:
    items = _optional_list(data, field)
    if not all(isinstance(item, str) for item in items):
        raise ReachabilityEvidenceError(f"{field} 必须是 string list")
    return items


def _required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise ReachabilityEvidenceError(f"{field} 必须是非空字符串")
    return value


def _optional_int(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, int):
        raise ReachabilityEvidenceError(f"{field} 必须是整数")
    return value
