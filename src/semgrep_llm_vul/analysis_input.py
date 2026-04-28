"""分析任务输入文件解析。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from semgrep_llm_vul.models import (
    AnalysisArtifact,
    AnalysisTarget,
    CodeLocation,
    FunctionSignature,
    InputMode,
    VulnerabilityInput,
)

SUPPORTED_SCHEMA_VERSION = 1


class AnalysisInputError(ValueError):
    """分析任务输入文件格式错误。"""


def load_analysis_input(path: str | Path) -> VulnerabilityInput:
    """从 YAML 或 JSON 文件读取分析任务输入。"""

    input_path = Path(path)
    try:
        text = input_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AnalysisInputError(f"无法读取分析任务输入文件：{input_path}") from exc

    data = _load_mapping(text, suffix=input_path.suffix.lower(), path=input_path)
    return parse_analysis_input(data)


def parse_analysis_input(data: dict[str, Any]) -> VulnerabilityInput:
    """将 dict 形式的分析任务输入转换为内部模型。"""

    if not isinstance(data, dict):
        raise AnalysisInputError("分析任务输入必须是 object")

    schema_version = data.get("schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise AnalysisInputError("schema_version 必须是 1")

    mode = _parse_mode(_required_str(data, "mode"))
    target = _parse_target(_required_mapping(data, "target"))
    description = _required_str(data, "description")
    sink_signature = _parse_sink(data.get("sink"))
    vulnerable_snippet = _optional_str(data.get("vulnerable_snippet"))
    candidate_prs = tuple(_string_list(data.get("candidate_prs"), field="candidate_prs"))
    artifacts = tuple(_parse_artifacts(data.get("artifacts")))

    try:
        return VulnerabilityInput(
            target=target,
            description=description,
            mode=mode,
            sink_signature=sink_signature,
            vulnerable_snippet=vulnerable_snippet,
            candidate_prs=candidate_prs,
            artifacts=artifacts,
        )
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def _load_mapping(text: str, *, suffix: str, path: Path) -> dict[str, Any]:
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AnalysisInputError(f"JSON 解析失败：{path}") from exc
    elif suffix in {".yaml", ".yml"}:
        yaml = YAML(typ="safe")
        try:
            data = yaml.load(text)
        except YAMLError as exc:
            raise AnalysisInputError(f"YAML 解析失败：{path}") from exc
    else:
        raise AnalysisInputError("分析任务输入文件仅支持 .yaml、.yml 或 .json")

    if not isinstance(data, dict):
        raise AnalysisInputError("分析任务输入必须是 object")
    return data


def _parse_mode(value: str) -> InputMode:
    try:
        return InputMode(value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in InputMode)
        raise AnalysisInputError(f"mode 必须是：{allowed}") from exc


def _parse_target(data: dict[str, Any]) -> AnalysisTarget:
    return AnalysisTarget(
        repo_url=_required_str(data, "repo_url"),
        affected_version=_required_str(data, "affected_version"),
        fixed_version=_optional_str(data.get("fixed_version")),
        introduced_version=_optional_str(data.get("introduced_version")),
        pre_introduced_version=_optional_str(data.get("pre_introduced_version")),
        language=_optional_str(data.get("language")),
    )


def _parse_sink(value: Any) -> FunctionSignature | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AnalysisInputError("sink 必须是 object")

    return FunctionSignature(
        raw=_required_str(value, "signature"),
        name=_optional_str(value.get("name")),
        receiver=_optional_str(value.get("receiver")),
        parameters=tuple(_string_list(value.get("parameters"), field="sink.parameters")),
        returns=_optional_str(value.get("returns")),
        location=_parse_location(value.get("location")),
        language=_optional_str(value.get("language")),
    )


def _parse_location(value: Any) -> CodeLocation | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AnalysisInputError("location 必须是 object")

    path = _optional_str(value.get("path"))
    if path is None:
        raise AnalysisInputError("location.path 必须是字符串")

    return CodeLocation(
        path=path,
        start_line=_optional_int(value.get("start_line"), field="location.start_line"),
        start_col=_optional_int(value.get("start_col"), field="location.start_col"),
        end_line=_optional_int(value.get("end_line"), field="location.end_line"),
        end_col=_optional_int(value.get("end_col"), field="location.end_col"),
    )


def _parse_artifacts(value: Any) -> list[AnalysisArtifact]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AnalysisInputError("artifacts 必须是 list")

    artifacts = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise AnalysisInputError(f"artifacts[{index}] 必须是 object")
        sensitive = item.get("sensitive", False)
        if not isinstance(sensitive, bool):
            raise AnalysisInputError(f"artifacts[{index}].sensitive 必须是 bool")
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            raise AnalysisInputError(f"artifacts[{index}].metadata 必须是 object")

        artifacts.append(
            AnalysisArtifact(
                kind=_required_str(item, "kind"),
                uri=_optional_str(item.get("uri")),
                path=_optional_str(item.get("path")),
                sensitive=sensitive,
                metadata=metadata,
            )
        )
    return artifacts


def _required_mapping(data: dict[str, Any], field: str) -> dict[str, Any]:
    value = data.get(field)
    if not isinstance(value, dict):
        raise AnalysisInputError(f"{field} 必须是 object")
    return value


def _required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise AnalysisInputError(f"{field} 必须是非空字符串")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AnalysisInputError("可选字符串字段必须是 string 或 null")
    return value if value else None


def _optional_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise AnalysisInputError(f"{field} 必须是 int 或 null")
    return value


def _string_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AnalysisInputError(f"{field} 必须是 list")
    if not all(isinstance(item, str) and item for item in value):
        raise AnalysisInputError(f"{field} 必须只包含非空字符串")
    return value
