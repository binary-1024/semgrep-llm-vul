"""M3 最小结构化 PoC planning。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from semgrep_llm_vul.models import (
    Evidence,
    EvidenceKind,
    PocExecutionState,
    PocParameterLocation,
    PocPlan,
    PocRequestParameter,
    PocRequestShape,
    PocTriggerInput,
    PocVerdict,
    ReachabilityAssessment,
    SourceReference,
    VulnerabilityInput,
)
from semgrep_llm_vul.reachability import ReachabilityReport

_ENTRYPOINT_NAME_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>/.*)$")
_REQUEST_SOURCE_RE = re.compile(
    r"request\.(?P<field>args|form|values|json|cookies|headers|view_args)"
    r"(?:\[(?P<bracket_quote>['\"])(?P<bracket_key>.+?)(?P=bracket_quote)\]"
    r"|\.get\((?P<call_quote>['\"])(?P<call_key>.+?)(?P=call_quote)\))"
)


@dataclass(frozen=True)
class PocGenerationReport:
    """PoC planning 报告。"""

    plans: tuple[PocPlan, ...]
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


def generate_poc_report(
    task: VulnerabilityInput,
    *,
    reachability_report: ReachabilityReport,
) -> PocGenerationReport:
    """从 M2 reachability 结果生成最小结构化 PoC planning。"""

    report_evidence = (_task_evidence(task),)
    unknowns = list(reachability_report.unknowns)
    plans: list[PocPlan] = []

    if not reachability_report.assessments:
        unknowns.append("缺少 reachability assessment，无法进入 PoC planning。")
        return PocGenerationReport(
            plans=(),
            evidence=report_evidence,
            unknowns=tuple(dict.fromkeys(unknowns)),
        )

    for assessment in reachability_report.assessments:
        if assessment.reachable is not True:
            unknowns.append(_skip_reason(assessment))
            continue

        plan = _plan_from_assessment(assessment)
        if plan is None:
            unknowns.append(
                "存在 reachable=true 的路径，但当前最小 M3 planner 无法恢复足够的请求形态。"
            )
            continue
        plans.append(plan)

    if not plans:
        unknowns.append("没有可生成结构化 PoC plan 的 reachable=true 路径。")

    return PocGenerationReport(
        plans=tuple(plans),
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
        summary="漏洞描述作为 PoC planning 的语义输入。",
        reasoning="M3 只消费已经确认 reachable=true 的路径，再把它转成最小触发计划。",
        confidence=0.35,
        open_questions=("是否具备真实运行环境与隔离执行条件，由后续 M4 决定。",),
    )


def _skip_reason(assessment: ReachabilityAssessment) -> str:
    if assessment.reachable is False:
        return "reachable=false 的路径保留为阻断证据，不进入 PoC planning。"
    return "reachable=null 的路径证据不足，不进入 PoC planning。"


def _plan_from_assessment(assessment: ReachabilityAssessment) -> PocPlan | None:
    sink_name = assessment.path.sink.signature.name
    if sink_name != "redirect":
        return None
    if assessment.entrypoint is None:
        return None

    entrypoint = _parse_entrypoint(assessment.entrypoint.name)
    if entrypoint is None:
        return None
    method, route_path = entrypoint

    trigger_input = _resolve_trigger_input(assessment)
    if trigger_input is None:
        return None

    request = PocRequestShape(
        method=method,
        path=route_path,
        parameter_location=trigger_input.location,
        parameters=(
            PocRequestParameter(
                name=trigger_input.name,
                value=trigger_input.value,
            ),
        ),
    )

    unknowns: list[str] = []
    limitations = [
        "当前只生成结构化 planning report，未实际发送请求。",
        "未验证认证态、部署前缀、代理层和运行时状态。",
    ]
    if trigger_input.location is PocParameterLocation.QUERY_OR_FORM:
        unknowns.append("该输入来自 request.values，当前无法仅凭本地 AST 区分 query 或 form。")

    evidence = (
        *assessment.path.evidence,
        *assessment.entrypoint.evidence,
        *(assessment.source_control.evidence if assessment.source_control else ()),
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.REACHABILITY_EVIDENCE,
                uri=assessment.entrypoint.location.path
                if assessment.entrypoint.location is not None
                else None,
                location=assessment.entrypoint.location,
                metadata={
                    "stage": "M3",
                    "planner": "structured_poc_plan",
                    "sink_name": sink_name,
                },
            ),
            summary=(
                f"将 reachable=true 的 {sink_name} 路径收敛为 "
                f"{method} {route_path} 的最小 PoC 触发计划。"
            ),
            reasoning=(
                "当前 planner 只消费已确认 reachable=true 的路径，"
                "并恢复入口、参数位置、参数键名和最小样例值；"
                "它不表示请求已执行成功。"
            ),
            confidence=0.8,
            reproducible_steps=(
                f"inspect {assessment.entrypoint.location.path}"
                if assessment.entrypoint.location is not None
                else f"inspect entrypoint {assessment.entrypoint.name}",
            ),
            open_questions=("真实运行是否成功仍需后续 M4 或人工验证。",),
        ),
    )

    return PocPlan(
        verdict=PocVerdict.PLANNED,
        execution_state=PocExecutionState.NOT_RUN,
        vulnerability_type="open_redirect",
        path=assessment.path,
        entrypoint=assessment.entrypoint,
        trigger_input=trigger_input,
        request=request,
        expected_effect="响应返回 30x，并把 Location 指向攻击者控制的外部 URL。",
        call_chain=assessment.call_chain,
        preconditions=(
            "目标路由按当前 entrypoint 注册并可接收该输入参数。",
            "目标版本仍包含当前 reachable=true 对应的代码路径。",
        ),
        evidence=evidence,
        unknowns=tuple(unknowns),
        limitations=tuple(limitations),
    )


def _parse_entrypoint(entrypoint_name: str) -> tuple[str, str] | None:
    match = _ENTRYPOINT_NAME_RE.match(entrypoint_name.strip())
    if match is None:
        return None
    return match.group("method"), match.group("path")


def _resolve_trigger_input(assessment: ReachabilityAssessment) -> PocTriggerInput | None:
    metadata = _source_control_metadata(assessment)
    if metadata is not None:
        request_key = metadata.get("request_key")
        request_field = metadata.get("request_field")
        if isinstance(request_key, str) and request_key and isinstance(request_field, str):
            location = _parameter_location_for_field(request_field)
            return PocTriggerInput(
                location=location,
                name=request_key,
                value=_sample_payload_value(assessment),
                reasoning=(
                    "根据 source.location 对应的本地 AST 赋值语句，"
                    f"确认该输入来自 Flask request.{request_field}。"
                ),
            )

    match = _REQUEST_SOURCE_RE.search(assessment.path.source.name)
    if match is None:
        return None
    request_field = match.group("field")
    request_key = match.group("bracket_key") or match.group("call_key")
    if not request_key:
        return None
    return PocTriggerInput(
        location=_parameter_location_for_field(request_field),
        name=request_key,
        value=_sample_payload_value(assessment),
        reasoning=(
            "根据 taint path source.name 恢复最小输入；"
            f"当前 source 直接读取 request.{request_field}['{request_key}'] 或等价 get(...)。"
        ),
    )


def _source_control_metadata(
    assessment: ReachabilityAssessment,
) -> dict[str, object] | None:
    source_control = assessment.source_control
    if source_control is None:
        return None
    for evidence in source_control.evidence:
        metadata = evidence.source.metadata
        if metadata.get("evidence_type") == "source_assignment_ast":
            return metadata
    return None


def _parameter_location_for_field(request_field: str) -> PocParameterLocation:
    mapping = {
        "args": PocParameterLocation.QUERY,
        "form": PocParameterLocation.FORM,
        "values": PocParameterLocation.QUERY_OR_FORM,
        "json": PocParameterLocation.JSON,
        "headers": PocParameterLocation.HEADER,
        "cookies": PocParameterLocation.COOKIE,
        "view_args": PocParameterLocation.PATH,
    }
    return mapping.get(request_field, PocParameterLocation.UNKNOWN)


def _sample_payload_value(assessment: ReachabilityAssessment) -> str:
    sink_name = assessment.path.sink.signature.name
    if sink_name == "redirect":
        return "https://attacker.example/poc"
    return "controlled-input"
