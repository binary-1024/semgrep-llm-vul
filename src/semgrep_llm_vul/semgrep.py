"""Semgrep JSON 结果归一化。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from semgrep_llm_vul.models import (
    CodeLocation,
    Evidence,
    EvidenceKind,
    FunctionSignature,
    NormalizedFinding,
    SinkCandidate,
    SourceCandidate,
    SourceReference,
    TaintPath,
    TaintRole,
    TaintStep,
)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
}


class SemgrepParseError(ValueError):
    """Semgrep JSON 无法解析或结构不符合预期。"""


def load_semgrep_findings(path: str | Path) -> list[NormalizedFinding]:
    """从文件读取 Semgrep JSON，并归一化为内部 finding。"""

    result_path = Path(path)
    try:
        raw = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SemgrepParseError(f"Semgrep JSON 解析失败：{result_path}") from exc

    return normalize_semgrep_results(raw, source_uri=str(result_path))


def load_semgrep_taint_paths(path: str | Path) -> list[TaintPath]:
    """从文件读取 Semgrep JSON，并派生可识别的 taint paths。"""

    result_path = Path(path)
    try:
        raw = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SemgrepParseError(f"Semgrep JSON 解析失败：{result_path}") from exc

    return normalize_semgrep_taint_paths(raw, source_uri=str(result_path))


def normalize_semgrep_results(
    semgrep_json: dict[str, Any],
    *,
    source_uri: str | None = None,
) -> list[NormalizedFinding]:
    """归一化 Semgrep JSON 中的 results 字段。"""

    results = semgrep_json.get("results")
    if not isinstance(results, list):
        raise SemgrepParseError("Semgrep JSON 必须包含 list 类型的 results 字段")

    return [_normalize_result(result, source_uri=source_uri) for result in results]


def normalize_semgrep_taint_paths(
    semgrep_json: dict[str, Any],
    *,
    source_uri: str | None = None,
) -> list[TaintPath]:
    """从 Semgrep JSON 中派生可识别的 taint paths。

    trace 缺失或结构不完整时不会强行生成路径；原始 finding 仍可通过
    `normalize_semgrep_results` 获取。
    """

    results = semgrep_json.get("results")
    if not isinstance(results, list):
        raise SemgrepParseError("Semgrep JSON 必须包含 list 类型的 results 字段")

    taint_paths = []
    for result in results:
        finding = _normalize_result(result, source_uri=source_uri)
        trace = _extract_dataflow_trace(result)
        taint_path = _taint_path_from_trace(finding, trace, source_uri=source_uri)
        if taint_path is not None:
            taint_paths.append(taint_path)

    return taint_paths


def _normalize_result(result: Any, *, source_uri: str | None) -> NormalizedFinding:
    if not isinstance(result, dict):
        raise SemgrepParseError("Semgrep result 必须是 object")

    path = _required_str(result, "path")
    rule_id = _required_str(result, "check_id")
    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        raise SemgrepParseError("Semgrep result.extra 必须是 object")

    message = _optional_str(extra.get("message")) or ""
    severity = _optional_str(extra.get("severity")) or "UNKNOWN"
    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {"raw_metadata": metadata}

    location = CodeLocation(
        path=path,
        start_line=_location_value(result.get("start"), "line"),
        start_col=_location_value(result.get("start"), "col"),
        end_line=_location_value(result.get("end"), "line"),
        end_col=_location_value(result.get("end"), "col"),
    )
    code = _optional_str(extra.get("lines"))
    language = _infer_language(path, metadata)
    evidence = Evidence(
        source=SourceReference(
            kind=EvidenceKind.SEMGREP_FINDING,
            uri=source_uri,
            location=location,
            metadata={"rule_id": rule_id, "severity": severity},
        ),
        summary=f"Semgrep 规则 {rule_id} 命中 {path}",
        reasoning=(
            "该 finding 来自 Semgrep 结构化扫描结果，"
            "作为后续 sink/source/path 判断的原始证据。"
        ),
        confidence=0.7,
        reproducible_steps=(f"semgrep scan --json > {source_uri}",) if source_uri else (),
    )

    return NormalizedFinding(
        tool="semgrep",
        rule_id=rule_id,
        message=message,
        severity=severity,
        location=location,
        language=language,
        code=code,
        metadata=metadata,
        evidence=(evidence,),
    )


def _required_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise SemgrepParseError(f"Semgrep result 缺少字符串字段：{key}")
    return value


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _location_value(location: Any, key: str) -> int | None:
    if not isinstance(location, dict):
        return None

    value = location.get(key)
    return value if isinstance(value, int) else None


def _infer_language(path: str, metadata: dict[str, Any]) -> str | None:
    language = metadata.get("language")
    if isinstance(language, str) and language:
        return language

    languages = metadata.get("languages")
    if isinstance(languages, list):
        for item in languages:
            if isinstance(item, str) and item:
                return item

    return LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower())


def _extract_dataflow_trace(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None

    extra = result.get("extra")
    if not isinstance(extra, dict):
        return None

    trace = extra.get("dataflow_trace")
    return trace if isinstance(trace, dict) else None


def _taint_path_from_trace(
    finding: NormalizedFinding,
    trace: dict[str, Any] | None,
    *,
    source_uri: str | None,
) -> TaintPath | None:
    if trace is None:
        return None

    source_step = _trace_step(trace.get("taint_source"), role=TaintRole.SOURCE, finding=finding)
    sink_step = _trace_step(trace.get("taint_sink"), role=TaintRole.SINK, finding=finding)
    if source_step is None or sink_step is None:
        return None

    intermediate_steps = tuple(
        step
        for item in _trace_list(trace.get("intermediate_vars"))
        if (step := _trace_step(item, role=TaintRole.INTERMEDIATE, finding=finding)) is not None
    )
    steps = (source_step, *intermediate_steps, sink_step)
    path_evidence = _taint_path_evidence(
        finding=finding,
        trace=trace,
        location=sink_step.location,
        source_uri=source_uri,
    )

    source = SourceCandidate(
        name=source_step.symbol or source_step.description or "semgrep-taint-source",
        location=source_step.location,
        reason="Semgrep taint-mode 报告该位置为 source。",
        confidence=0.7,
        evidence=source_step.evidence,
    )
    sink = SinkCandidate(
        signature=FunctionSignature(
            raw=sink_step.symbol or sink_step.description or finding.rule_id,
            name=sink_step.symbol,
            location=sink_step.location,
            language=finding.language,
        ),
        reason="Semgrep taint-mode 报告污点到达该 sink。",
        confidence=0.7,
        evidence=sink_step.evidence,
    )

    return TaintPath(
        source=source,
        sink=sink,
        steps=steps,
        reachable=None,
        evidence=(path_evidence,),
    )


def _trace_step(
    raw_step: Any,
    *,
    role: TaintRole,
    finding: NormalizedFinding,
) -> TaintStep | None:
    location_payload = _trace_location_payload(raw_step)
    if location_payload is None:
        return None

    location = _code_location_from_trace_payload(location_payload)
    if location is None:
        return None

    symbol = _trace_symbol(raw_step, location_payload)
    description = _trace_description(raw_step, location_payload)
    evidence = Evidence(
        source=SourceReference(
            kind=EvidenceKind.SEMGREP_FINDING,
            uri=finding.evidence[0].source.uri if finding.evidence else None,
            location=location,
            metadata={
                "rule_id": finding.rule_id,
                "role": role.value,
                "raw_trace_step": raw_step,
            },
        ),
        summary=f"Semgrep taint-mode 报告 {role.value} 节点：{location.path}",
        reasoning="该节点来自 Semgrep dataflow_trace，作为候选污点路径的一部分。",
        confidence=0.7,
        open_questions=(
            "该路径尚未完成可触达确认。",
            "该路径尚未完成 sanitizer 充分性确认。",
            "该路径尚未完成受影响版本与修复版本对照验证。",
        ),
    )

    return TaintStep(
        location=location,
        role=role,
        symbol=symbol,
        description=description,
        evidence=(evidence,),
    )


def _trace_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _trace_location_payload(raw_step: Any) -> dict[str, Any] | None:
    if isinstance(raw_step, dict):
        return raw_step

    if isinstance(raw_step, list):
        for item in raw_step:
            if isinstance(item, dict):
                return item
            nested = _trace_location_payload(item)
            if nested is not None:
                return nested

    return None


def _code_location_from_trace_payload(payload: dict[str, Any]) -> CodeLocation | None:
    location_payload = (
        payload.get("location") if isinstance(payload.get("location"), dict) else payload
    )

    path = location_payload.get("path") or location_payload.get("file")
    if not isinstance(path, str) or not path:
        return None

    start = (
        location_payload.get("start")
        if isinstance(location_payload.get("start"), dict)
        else location_payload
    )
    end = (
        location_payload.get("end")
        if isinstance(location_payload.get("end"), dict)
        else location_payload
    )

    return CodeLocation(
        path=path,
        start_line=_location_value(start, "line"),
        start_col=_location_value(start, "col"),
        end_line=_location_value(end, "line"),
        end_col=_location_value(end, "col"),
    )


def _trace_symbol(raw_step: Any, payload: dict[str, Any]) -> str | None:
    for key in ("name", "symbol", "metavar", "content"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value

    sibling_content = _trace_sibling_content(raw_step)
    if sibling_content is not None:
        return sibling_content

    return None


def _trace_description(raw_step: Any, payload: dict[str, Any]) -> str | None:
    for key in ("message", "description", "content", "lines"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value

    sibling_content = _trace_sibling_content(raw_step)
    if sibling_content is not None:
        return sibling_content

    return None


def _trace_sibling_content(raw_step: Any) -> str | None:
    if not isinstance(raw_step, list):
        return None

    for item in raw_step:
        if isinstance(item, str) and item not in {"CliLoc", "Source", "Sink", "Propagation"}:
            return item

        if isinstance(item, list):
            nested = _trace_sibling_content(item)
            if nested is not None:
                return nested

    return None


def _taint_path_evidence(
    *,
    finding: NormalizedFinding,
    trace: dict[str, Any],
    location: CodeLocation,
    source_uri: str | None,
) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.SEMGREP_FINDING,
            uri=source_uri,
            location=location,
            metadata={
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "raw_trace": trace,
            },
        ),
        summary=f"Semgrep taint-mode 报告候选污点路径：{finding.rule_id}",
        reasoning=(
            "该路径由 Semgrep dataflow_trace 派生，"
            "表示静态分析报告的候选路径，不代表已确认可触达或可利用。"
        ),
        confidence=0.7,
        reproducible_steps=(f"semgrep scan --json > {source_uri}",) if source_uri else (),
        open_questions=(
            "Semgrep 可能只报告一条代表 trace，而不是完整路径枚举。",
            "该路径尚未完成可触达确认。",
            "该路径尚未完成受影响版本与修复版本对照验证。",
        ),
    )
