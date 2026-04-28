"""本地内置 sink heuristic pack。"""

from __future__ import annotations

import re
from dataclasses import dataclass

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")


@dataclass(frozen=True)
class SinkHeuristic:
    """候选 sink 调用规则。"""

    name: str
    call_names: tuple[str, ...]
    category: str
    languages: tuple[str, ...] = ()
    confidence: float = 0.6
    description: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence 必须位于 0.0 到 1.0 之间")


@dataclass(frozen=True)
class SinkHeuristicMatch:
    """一次 sink heuristic 命中。"""

    call_name: str
    heuristic: SinkHeuristic


DEFAULT_SINK_HEURISTICS: tuple[SinkHeuristic, ...] = (
    SinkHeuristic(
        name="open_redirect",
        call_names=("redirect",),
        category="open_redirect",
        confidence=0.6,
        description="跳转目标可能受外部输入控制，需验证是否存在开放重定向。",
    ),
    SinkHeuristic(
        name="command_execution",
        call_names=("exec", "eval", "system", "popen", "subprocess"),
        category="command_execution",
        confidence=0.7,
        description="命令或代码执行 API 可能形成注入 sink，需验证输入控制与执行边界。",
    ),
    SinkHeuristic(
        name="deserialization",
        call_names=("deserialize", "loads", "pickle.load"),
        category="deserialization",
        confidence=0.65,
        description="反序列化入口可能处理外部可控数据，需验证格式、类型与执行副作用。",
    ),
)


def find_sink_heuristic_matches(
    text: str | None,
    *,
    language: str | None = None,
    heuristics: tuple[SinkHeuristic, ...] = DEFAULT_SINK_HEURISTICS,
) -> tuple[SinkHeuristicMatch, ...]:
    """从代码文本中寻找候选 sink heuristic 命中。"""

    if not text:
        return ()

    matches: list[SinkHeuristicMatch] = []
    for regex_match in CALL_RE.finditer(text):
        call_name = regex_match.group(1)
        short_name = call_name.split(".")[-1].lower()
        for heuristic in heuristics:
            if not _language_matches(language, heuristic):
                continue
            allowed_names = {item.lower() for item in heuristic.call_names}
            if call_name.lower() in allowed_names or short_name in allowed_names:
                matches.append(SinkHeuristicMatch(call_name=call_name, heuristic=heuristic))
                break
    return tuple(matches)


def _language_matches(language: str | None, heuristic: SinkHeuristic) -> bool:
    if not heuristic.languages or language is None:
        return True
    return language.lower() in {item.lower() for item in heuristic.languages}
