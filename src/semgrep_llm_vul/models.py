"""语言无关的漏洞分析数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InputMode(str, Enum):
    """漏洞分析输入模式。"""

    KNOWN_SINK = "known_sink"
    UNKNOWN_SINK = "unknown_sink"


class EvidenceKind(str, Enum):
    """证据类型。"""

    VULNERABILITY_DESCRIPTION = "vulnerability_description"
    CODE_LOCATION = "code_location"
    DIFF = "diff"
    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    SEMGREP_FINDING = "semgrep_finding"
    EXECUTION_LOG = "execution_log"
    HUMAN_INPUT = "human_input"


class ArtifactKind(str, Enum):
    """分析产物类型。"""

    POC = "poc"
    EXP = "exp"
    REPORT = "report"
    LOG = "log"
    RAW_SCAN = "raw_scan"


@dataclass(frozen=True)
class CodeLocation:
    """代码位置，行列号使用 1-based 语义。"""

    path: str
    start_line: int | None = None
    start_col: int | None = None
    end_line: int | None = None
    end_col: int | None = None


@dataclass(frozen=True)
class SourceReference:
    """证据来源引用。"""

    kind: EvidenceKind
    uri: str | None = None
    commit: str | None = None
    location: CodeLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """支持某个判断的证据链条目。"""

    source: SourceReference
    summary: str
    reasoning: str
    confidence: float
    reproducible_steps: tuple[str, ...] = ()
    open_questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence 必须位于 0.0 到 1.0 之间")


@dataclass(frozen=True)
class AnalysisTarget:
    """待分析目标项目。"""

    repo_url: str
    affected_version: str
    fixed_version: str | None = None
    introduced_version: str | None = None
    pre_introduced_version: str | None = None
    language: str | None = None


@dataclass(frozen=True)
class FunctionSignature:
    """语言无关的函数或方法签名描述。"""

    raw: str
    name: str | None = None
    receiver: str | None = None
    parameters: tuple[str, ...] = ()
    returns: str | None = None
    location: CodeLocation | None = None
    language: str | None = None


@dataclass(frozen=True)
class VulnerabilityInput:
    """漏洞分析任务输入。"""

    target: AnalysisTarget
    description: str
    mode: InputMode
    sink_signature: FunctionSignature | None = None
    vulnerable_snippet: str | None = None
    candidate_prs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode is InputMode.KNOWN_SINK and self.sink_signature is None:
            raise ValueError("known_sink 模式必须提供 sink_signature")


@dataclass(frozen=True)
class NormalizedFinding:
    """从 Semgrep 等扫描器归一化得到的 finding。"""

    tool: str
    rule_id: str
    message: str
    severity: str
    location: CodeLocation
    language: str | None = None
    code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class SinkCandidate:
    """候选 sink 函数。"""

    signature: FunctionSignature
    reason: str
    confidence: float
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence 必须位于 0.0 到 1.0 之间")


@dataclass(frozen=True)
class SourceCandidate:
    """候选 source。"""

    name: str
    location: CodeLocation
    reason: str
    confidence: float
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence 必须位于 0.0 到 1.0 之间")


@dataclass(frozen=True)
class TaintStep:
    """污点路径中的一个节点。"""

    location: CodeLocation
    symbol: str | None = None
    description: str | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class TaintPath:
    """语言无关的污点路径。"""

    source: SourceCandidate
    sink: SinkCandidate
    steps: tuple[TaintStep, ...]
    reachable: bool | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Artifact:
    """PoC、exp、报告或日志等分析产物。"""

    kind: ArtifactKind
    path: str | None = None
    content: str | None = None
    evidence: tuple[Evidence, ...] = ()
