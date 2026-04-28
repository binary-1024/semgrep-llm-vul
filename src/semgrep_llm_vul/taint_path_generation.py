"""M2 最小污点路径候选生成。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from semgrep_llm_vul.models import (
    Evidence,
    EvidenceKind,
    SinkCandidate,
    SinkGenerationReport,
    SourceReference,
    TaintPath,
    VulnerabilityInput,
)


@dataclass(frozen=True)
class TaintPathGenerationReport:
    """污点路径候选生成报告。"""

    paths: tuple[TaintPath, ...]
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


def generate_taint_path_report(
    task: VulnerabilityInput,
    *,
    sink_report: SinkGenerationReport,
    semgrep_taint_paths: tuple[TaintPath, ...] = (),
) -> TaintPathGenerationReport:
    """从 sink candidate 和 Semgrep taint paths 生成最小路径候选。"""

    report_evidence = (_task_evidence(task),)
    unknowns: list[str] = []

    if not sink_report.candidates:
        unknowns.append("缺少 sink candidate，无法从 sink 出发生成污点路径候选。")
    if not semgrep_taint_paths:
        unknowns.append("缺少 Semgrep taint path 候选。")
    if unknowns:
        return TaintPathGenerationReport(
            paths=(),
            evidence=report_evidence,
            unknowns=tuple(dict.fromkeys(unknowns)),
        )

    paths: list[TaintPath] = []
    unmatched = 0
    for taint_path in semgrep_taint_paths:
        sink = _matching_sink(taint_path, sink_report.candidates)
        if sink is None:
            unmatched += 1
            continue
        paths.append(_path_with_sink_candidate(taint_path, sink))

    if not paths:
        unknowns.append("Semgrep taint path 未能与当前 sink candidates 对齐。")
    elif unmatched:
        unknowns.append(f"{unmatched} 条 Semgrep taint path 未能与当前 sink candidates 对齐。")

    return TaintPathGenerationReport(
        paths=tuple(paths),
        evidence=report_evidence,
        unknowns=tuple(dict.fromkeys(unknowns)),
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
        summary="漏洞描述作为污点路径生成任务的语义输入。",
        reasoning="描述提供风险语义，但路径候选必须由 sink 和静态路径证据锚定。",
        confidence=0.3,
        open_questions=("需要后续可触达确认、sanitizer 判断和版本对照验证。",),
    )


def _matching_sink(
    taint_path: TaintPath,
    candidates: tuple[SinkCandidate, ...],
) -> SinkCandidate | None:
    taint_names = {
        _normalize_call_name(taint_path.sink.signature.raw),
        _normalize_call_name(taint_path.sink.signature.name),
    }
    return next(
        (
            candidate
            for candidate in candidates
            if _normalize_call_name(candidate.signature.name) in taint_names
            or _normalize_call_name(candidate.signature.raw) in taint_names
        ),
        None,
    )


def _path_with_sink_candidate(
    taint_path: TaintPath,
    sink: SinkCandidate,
) -> TaintPath:
    evidence = (
        *taint_path.evidence,
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.CODE_LOCATION,
                location=sink.signature.location,
                metadata={"sink_signature": sink.signature.raw},
            ),
            summary=f"污点路径 sink 与候选 sink 对齐：{sink.signature.raw}",
            reasoning=(
                "该路径由静态 taint trace 与 M1 sink candidate 对齐得到，"
                "仍是候选路径，不代表已确认可触达或可利用。"
            ),
            confidence=min(sink.confidence, 0.7),
            open_questions=(
                "需要确认入口可达性。",
                "需要确认 sanitizer 是否充分。",
                "需要后续 PoC/exp 验证。",
            ),
        ),
    )
    return TaintPath(
        source=taint_path.source,
        sink=sink,
        steps=taint_path.steps,
        reachable=None,
        evidence=evidence,
    )


def _normalize_call_name(value: str | None) -> str:
    if not value:
        return ""
    name = value.strip().split(".")[-1]
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", name)
    return match.group(1).lower() if match else name.lower()
