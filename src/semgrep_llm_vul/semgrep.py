"""Semgrep JSON 结果归一化。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from semgrep_llm_vul.models import (
    CodeLocation,
    Evidence,
    EvidenceKind,
    NormalizedFinding,
    SourceReference,
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
