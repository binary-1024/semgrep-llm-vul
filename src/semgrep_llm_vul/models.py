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
    REACHABILITY_EVIDENCE = "reachability_evidence"


class ArtifactKind(str, Enum):
    """分析产物类型。"""

    POC = "poc"
    EXP = "exp"
    REPORT = "report"
    LOG = "log"
    RAW_SCAN = "raw_scan"


class TaintRole(str, Enum):
    """污点路径节点角色。"""

    SOURCE = "source"
    INTERMEDIATE = "intermediate"
    SINK = "sink"


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
class AnalysisArtifact:
    """分析任务引用的外部材料。"""

    kind: str
    uri: str | None = None
    path: str | None = None
    sensitive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


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
    artifacts: tuple[AnalysisArtifact, ...] = ()

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
class SinkGenerationReport:
    """sink 生成阶段的结构化报告。"""

    candidates: tuple[SinkCandidate, ...]
    recommended: SinkCandidate | None = None
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


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
    role: TaintRole | None = None
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
class ReachabilityEntrypoint:
    """可触达确认中的入口证据。"""

    kind: str
    name: str
    location: CodeLocation | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ReachabilityCallStep:
    """入口到候选路径上下文的调用链节点。"""

    symbol: str
    location: CodeLocation | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class BlockingFactor:
    """阻断可触达确认的明确证据。"""

    kind: str
    summary: str
    location: CodeLocation | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class SourceControlAssessment:
    """source 是否可能由外部输入控制的判断。"""

    controlled: bool | None
    reason: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ReachabilityAssessment:
    """候选污点路径的可触达确认结果。"""

    path: TaintPath
    reachable: bool | None
    entrypoint: ReachabilityEntrypoint | None = None
    call_chain: tuple[ReachabilityCallStep, ...] = ()
    source_control: SourceControlAssessment | None = None
    blocking_factors: tuple[BlockingFactor, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.reachable is False and not self.blocking_factors:
            raise ValueError("reachable=false 必须提供明确 blocking_factors")


@dataclass(frozen=True)
class Artifact:
    """PoC、exp、报告或日志等分析产物。"""

    kind: ArtifactKind
    path: str | None = None
    content: str | None = None
    evidence: tuple[Evidence, ...] = ()
