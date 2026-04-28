"""证据优先的 sink candidate 生成。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from semgrep_llm_vul.models import (
    AnalysisArtifact,
    CodeLocation,
    Evidence,
    EvidenceKind,
    FunctionSignature,
    InputMode,
    NormalizedFinding,
    SinkCandidate,
    SinkGenerationReport,
    SourceReference,
    VulnerabilityInput,
)

DANGEROUS_CALL_NAMES = (
    "redirect",
    "exec",
    "eval",
    "system",
    "popen",
    "subprocess",
    "deserialize",
    "loads",
)

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")
DIFF_HUNK_RE = re.compile(
    r"@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@"
)


class SinkGenerationError(ValueError):
    """sink 生成输入证据无法处理。"""


def generate_sink_report(
    task: VulnerabilityInput,
    *,
    semgrep_findings: tuple[NormalizedFinding, ...] = (),
    artifact_base: str | Path | None = None,
) -> SinkGenerationReport:
    """根据任务输入和本地证据生成 sink candidate 报告。"""

    drafts: dict[str, _CandidateDraft] = {}
    report_evidence: list[Evidence] = []
    unknowns: list[str] = []

    description_evidence = _description_evidence(task)
    report_evidence.append(description_evidence)

    if task.mode is InputMode.KNOWN_SINK:
        if task.sink_signature is None:
            raise SinkGenerationError("known_sink 模式缺少 sink_signature")
        evidence = [description_evidence, *_known_sink_evidence(task)]
        _add_draft(
            drafts,
            signature=task.sink_signature,
            reason="用户显式提供 sink signature，作为高优先级候选。",
            evidence=tuple(evidence),
            source="known_sink",
        )

    for finding in semgrep_findings:
        signature = _signature_from_finding(finding)
        if signature is None:
            unknowns.append(
                f"Semgrep finding {finding.rule_id} 缺少可识别调用表达式，无法生成 sink candidate。"
            )
            continue
        evidence = (
            *finding.evidence,
            _semgrep_candidate_evidence(finding, signature),
        )
        _add_draft(
            drafts,
            signature=signature,
            reason="Semgrep finding 命中危险调用，作为候选 sink 证据。",
            evidence=evidence,
            source="semgrep",
        )

    for artifact in task.artifacts:
        if artifact.kind not in {"diff", "patch"}:
            continue
        diff_text = _read_artifact_text(artifact, artifact_base=artifact_base)
        diff_candidates = _signatures_from_diff(diff_text, artifact=artifact)
        if not diff_candidates:
            unknowns.append(f"diff artifact {artifact.path or artifact.uri} 未发现可识别危险调用。")
            continue
        for signature, evidence in diff_candidates:
            _add_draft(
                drafts,
                signature=signature,
                reason="diff 线索显示危险调用或修复相关调用，作为候选 sink 证据。",
                evidence=(evidence,),
                source="diff",
            )

    if task.vulnerable_snippet:
        snippet_candidates = _signatures_from_snippet(task.vulnerable_snippet, task=task)
        if not snippet_candidates:
            unknowns.append("vulnerable_snippet 未发现可识别危险调用。")
        for signature, evidence in snippet_candidates:
            _add_draft(
                drafts,
                signature=signature,
                reason="漏洞代码片段中出现危险调用，作为候选 sink 证据。",
                evidence=(evidence,),
                source="snippet",
            )

    candidates = tuple(
        draft.to_candidate()
        for draft in sorted(
            drafts.values(),
            key=lambda item: (
                -item.score,
                item.signature.raw,
                item.signature.location.path if item.signature.location else "",
            ),
        )
    )
    if not candidates:
        unknowns.append("证据不足，无法推荐 sink candidate。")

    return SinkGenerationReport(
        candidates=candidates,
        recommended=candidates[0] if candidates else None,
        evidence=tuple(report_evidence),
        unknowns=tuple(dict.fromkeys(unknowns)),
    )


@dataclass
class _CandidateDraft:
    signature: FunctionSignature
    reason_parts: list[str]
    evidence: list[Evidence]
    sources: set[str]

    @property
    def score(self) -> float:
        score = 0.0
        if "known_sink" in self.sources:
            score += 0.9
        if "semgrep" in self.sources:
            score += 0.65
        if "diff" in self.sources:
            score += 0.6
        if "snippet" in self.sources:
            score += 0.45
        if len(self.sources) > 1:
            score += 0.1
        if self.signature.location is not None:
            score += 0.05
        return min(score, 0.95)

    def to_candidate(self) -> SinkCandidate:
        return SinkCandidate(
            signature=self.signature,
            reason="；".join(dict.fromkeys(self.reason_parts)),
            confidence=self.score,
            evidence=tuple(self.evidence),
        )


def _add_draft(
    drafts: dict[str, _CandidateDraft],
    *,
    signature: FunctionSignature,
    reason: str,
    evidence: tuple[Evidence, ...],
    source: str,
) -> None:
    key = _candidate_key(signature)
    draft = drafts.get(key)
    if draft is None:
        drafts[key] = _CandidateDraft(
            signature=signature,
            reason_parts=[reason],
            evidence=list(evidence),
            sources={source},
        )
        return

    draft.reason_parts.append(reason)
    draft.evidence.extend(evidence)
    draft.sources.add(source)
    if draft.signature.location is None and signature.location is not None:
        draft.signature = FunctionSignature(
            raw=draft.signature.raw,
            name=draft.signature.name,
            receiver=draft.signature.receiver,
            parameters=draft.signature.parameters,
            returns=draft.signature.returns,
            location=signature.location,
            language=draft.signature.language or signature.language,
        )


def _candidate_key(signature: FunctionSignature) -> str:
    return (signature.name or signature.raw).lower()


def _description_evidence(task: VulnerabilityInput) -> Evidence:
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
        summary="漏洞描述作为 sink 生成任务的语义输入。",
        reasoning="描述提供风险语义，但不能单独证明具体 sink。",
        confidence=0.35,
        open_questions=("需要代码、diff 或扫描结果作为 sink 证据锚点。",),
    )


def _known_sink_evidence(task: VulnerabilityInput) -> tuple[Evidence, ...]:
    assert task.sink_signature is not None
    evidence = [
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.HUMAN_INPUT,
                location=task.sink_signature.location,
                metadata={"signature": task.sink_signature.raw},
            ),
            summary=f"用户提供 sink signature：{task.sink_signature.raw}",
            reasoning=(
                "用户显式输入是 known_sink 场景的主要候选来源，"
                "但仍需要后续路径和验证阶段确认。"
            ),
            confidence=0.9,
        )
    ]
    if task.vulnerable_snippet:
        evidence.append(
            Evidence(
                source=SourceReference(kind=EvidenceKind.CODE_LOCATION),
                summary="用户提供漏洞代码片段。",
                reasoning="代码片段可辅助确认 sink 语义，但不单独证明可触达或可利用。",
                confidence=0.65,
                open_questions=("需要确认片段对应的真实文件、版本和调用上下文。",),
            )
        )
    return tuple(evidence)


def _signature_from_finding(finding: NormalizedFinding) -> FunctionSignature | None:
    name = _first_dangerous_call(finding.code or finding.message)
    if name is None:
        return None

    return FunctionSignature(
        raw=f"{name}(...)",
        name=name.split(".")[-1],
        location=finding.location,
        language=finding.language,
    )


def _semgrep_candidate_evidence(
    finding: NormalizedFinding,
    signature: FunctionSignature,
) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.SEMGREP_FINDING,
            location=finding.location,
            metadata={"rule_id": finding.rule_id, "severity": finding.severity},
        ),
        summary=f"Semgrep finding 指向候选 sink：{signature.raw}",
        reasoning="Semgrep finding 是静态候选证据，不能直接等同最终漏洞结论。",
        confidence=0.65,
        reproducible_steps=("重新运行对应 Semgrep 规则并检查 JSON finding。",),
    )


def _signatures_from_diff(
    diff_text: str,
    *,
    artifact: AnalysisArtifact,
) -> list[tuple[FunctionSignature, Evidence]]:
    candidates = []
    old_path: str | None = None
    new_path: str | None = None
    old_line: int | None = None
    new_line: int | None = None
    for line in diff_text.splitlines():
        if line.startswith("--- a/"):
            old_path = line.removeprefix("--- a/")
            continue
        if line.startswith("+++ b/"):
            new_path = line.removeprefix("+++ b/")
            continue
        hunk_match = DIFF_HUNK_RE.match(line)
        if hunk_match:
            old_line = int(hunk_match.group("old_start"))
            new_line = int(hunk_match.group("new_start"))
            continue
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            if old_line is not None and new_line is not None and line.startswith(" "):
                old_line += 1
                new_line += 1
            continue
        side = "added" if line.startswith("+") else "removed"
        line_number = new_line if side == "added" else old_line
        if side == "added" and new_line is not None:
            new_line += 1
        if side == "removed" and old_line is not None:
            old_line += 1
        name = _first_dangerous_call(line)
        if name is None:
            continue
        path = (
            (new_path if side == "added" else old_path)
            or artifact.path
            or artifact.uri
            or "<diff>"
        )
        location = CodeLocation(path=path, start_line=line_number)
        signature = FunctionSignature(
            raw=f"{name}(...)",
            name=name.split(".")[-1],
            location=location,
        )
        evidence = Evidence(
            source=SourceReference(
                kind=EvidenceKind.DIFF,
                uri=artifact.uri,
                location=location,
                metadata={
                    "artifact_path": artifact.path,
                    "diff_side": side,
                    "line": line[:200],
                },
            ),
            summary=f"diff 中出现候选危险调用：{name}",
            reasoning=(
                "修复 diff 中的危险调用或相关修改可作为 sink 推断线索，"
                "但需要后续代码和路径验证。"
            ),
            confidence=0.6,
            reproducible_steps=(f"inspect diff artifact {artifact.path or artifact.uri}",),
        )
        candidates.append((signature, evidence))
    return candidates


def _signatures_from_snippet(
    snippet: str,
    *,
    task: VulnerabilityInput,
) -> list[tuple[FunctionSignature, Evidence]]:
    candidates = []
    seen: set[str] = set()
    for name in _dangerous_calls(snippet):
        if name in seen:
            continue
        seen.add(name)
        location = task.sink_signature.location if task.sink_signature else None
        signature = FunctionSignature(
            raw=f"{name}(...)",
            name=name.split(".")[-1],
            location=location,
            language=task.target.language,
        )
        evidence = Evidence(
            source=SourceReference(kind=EvidenceKind.CODE_LOCATION, location=location),
            summary=f"代码片段中出现候选危险调用：{name}",
            reasoning="漏洞片段中的危险调用可作为 sink 候选线索，但仍需定位到项目真实版本。",
            confidence=0.45,
            open_questions=("需要确认片段文件位置和完整调用上下文。",),
        )
        candidates.append((signature, evidence))
    return candidates


def _read_artifact_text(
    artifact: AnalysisArtifact,
    *,
    artifact_base: str | Path | None,
) -> str:
    if artifact.path is None:
        raise SinkGenerationError("diff artifact 第一版必须提供本地 path")
    path = Path(artifact.path)
    if not path.is_absolute():
        path = (Path(artifact_base) if artifact_base is not None else Path.cwd()) / path
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SinkGenerationError(f"无法读取 diff artifact：{artifact.path}") from exc


def _first_dangerous_call(text: str | None) -> str | None:
    for name in _dangerous_calls(text):
        return name
    return None


def _dangerous_calls(text: str | None) -> tuple[str, ...]:
    if not text:
        return ()
    calls = []
    for match in CALL_RE.finditer(text):
        name = match.group(1)
        short_name = name.split(".")[-1].lower()
        if short_name in DANGEROUS_CALL_NAMES:
            calls.append(name)
    return tuple(calls)
