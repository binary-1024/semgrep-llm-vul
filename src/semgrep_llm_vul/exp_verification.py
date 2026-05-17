"""M4 最小结构化 exp verification。"""

from __future__ import annotations

import http.client
import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from semgrep_llm_vul.managed_fixtures import managed_fixture_targets
from semgrep_llm_vul.models import (
    Evidence,
    EvidenceKind,
    ExpEffectState,
    ExpExecutionState,
    ExpObservation,
    ExpRequestArtifact,
    ExpVerification,
    ExpVerificationVerdict,
    ExpVersionRole,
    PocExecutionState,
    PocParameterLocation,
    PocPlan,
    PocRequestParameter,
    PocRequestShape,
    SourceReference,
    VulnerabilityInput,
)
from semgrep_llm_vul.poc_generation import PocGenerationReport

_TARGET_HOST_PLACEHOLDER = "http://TARGET_HOST"
_EXTERNAL_URL_PREFIXES = ("http://", "https://")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_BODY_EXCERPT_LIMIT = 200
_META_REFRESH_URL_RE = re.compile(
    r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'][^\"'>]*url\s*=\s*([^\"'>\s;]+)[^\"'>]*[\"']",
    re.IGNORECASE,
)


class ExecutionEvidenceError(ValueError):
    """M4 execution evidence 输入无法读取或无法解析。"""


class LocalExecutionError(ValueError):
    """M4 本地 live runner 输入不满足安全边界。"""


@dataclass(frozen=True)
class LocalExecutionTarget:
    """本地 live runner 的一个受限目标。"""

    version_role: ExpVersionRole
    base_url: str
    host: str
    port: int


@dataclass(frozen=True)
class ExecutionEvidenceRecord:
    """单个版本上的本地执行观察。"""

    plan_match: dict[str, Any]
    version_role: ExpVersionRole
    execution_state: ExpExecutionState
    request: PocRequestShape
    version: str | None = None
    exit_code: int | None = None
    status_code: int | None = None
    response_headers: tuple[tuple[str, str], ...] = ()
    response_body_text: str | None = None
    notes: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ExpVerificationReport:
    """M4 exp verification 报告。"""

    verifications: tuple[ExpVerification, ...]
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


def collect_local_execution_records(
    poc_report: PocGenerationReport,
    *,
    affected_base_url: str | None = None,
    fixed_base_url: str | None = None,
    timeout_seconds: float = 5.0,
) -> tuple[ExecutionEvidenceRecord, ...]:
    """对 loopback 上已运行的本地服务执行最小 live HTTP replay。"""

    if timeout_seconds <= 0:
        raise LocalExecutionError("timeout_seconds 必须为正数")

    targets = tuple(
        target
        for target in (
            _local_target(ExpVersionRole.AFFECTED, affected_base_url),
            _local_target(ExpVersionRole.FIXED, fixed_base_url),
        )
        if target is not None
    )
    records: list[ExecutionEvidenceRecord] = []
    for plan in poc_report.plans:
        if plan.execution_state is not PocExecutionState.NOT_RUN:
            continue
        for target in targets:
            records.append(
                _execute_local_request(
                    plan,
                    target=target,
                    timeout_seconds=timeout_seconds,
                )
            )
    return tuple(records)


def collect_managed_fixture_execution_records(
    poc_report: PocGenerationReport,
    *,
    fixture_name: str,
    timeout_seconds: float = 5.0,
) -> tuple[ExecutionEvidenceRecord, ...]:
    """通过仓库内置 managed fixture 获取最小 live execution records。"""

    with managed_fixture_targets(
        fixture_name,
        timeout_seconds=timeout_seconds,
    ) as targets:
        return collect_local_execution_records(
            poc_report,
            affected_base_url=targets.affected_base_url,
            fixed_base_url=targets.fixed_base_url,
            timeout_seconds=timeout_seconds,
        )


def load_execution_evidence(path: str | Path) -> tuple[ExecutionEvidenceRecord, ...]:
    """读取本地 execution evidence JSON。"""

    evidence_path = Path(path)
    try:
        text = evidence_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExecutionEvidenceError(f"无法读取 execution evidence：{path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExecutionEvidenceError(f"execution evidence 不是有效 JSON：{path}") from exc
    if not isinstance(data, dict):
        raise ExecutionEvidenceError("execution evidence 必须是 object")
    if data.get("schema_version") != 1:
        raise ExecutionEvidenceError("execution evidence schema_version 必须是 1")
    observations = data.get("observations")
    if not isinstance(observations, list):
        raise ExecutionEvidenceError("execution evidence observations 必须是 list")
    return tuple(
        _execution_record_from_dict(item, evidence_path=evidence_path)
        for item in observations
    )


def generate_exp_verification_report(
    task: VulnerabilityInput,
    *,
    poc_report: PocGenerationReport,
    execution_records: tuple[ExecutionEvidenceRecord, ...] = (),
) -> ExpVerificationReport:
    """从 M3 结构化 PoC planning 生成 M4 最小 exp verification 报告。"""

    report_evidence = (_task_evidence(task),)
    unknowns = list(poc_report.unknowns)
    verifications: list[ExpVerification] = []

    if not poc_report.plans:
        unknowns.append("缺少可进入 M4 的 PoC plan，无法进行 exp verification。")
        return ExpVerificationReport(
            verifications=(),
            evidence=report_evidence,
            unknowns=tuple(dict.fromkeys(unknowns)),
        )

    if not execution_records:
        unknowns.append("缺少本地 execution evidence，无法完成 M4 对照验证。")

    for plan in poc_report.plans:
        if plan.execution_state is not PocExecutionState.NOT_RUN:
            unknowns.append("当前 M4 只消费 execution_state=not_run 的 PoC plan。")
            continue
        verifications.append(
            _verification_from_plan(
                task,
                plan,
                execution_records=execution_records,
            )
        )

    if not verifications:
        unknowns.append("没有可生成 exp verification 的 PoC plan。")

    return ExpVerificationReport(
        verifications=tuple(verifications),
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
        summary="漏洞描述作为 M4 exp verification 的语义输入。",
        reasoning=(
            "M4 只消费已经形成结构化 request 形态的 PoC plan，"
            "再结合受影响版本 / 修复版本的执行观察给出最终验证结论。"
        ),
        confidence=0.4,
        open_questions=("是否具备真实可比的运行环境，由执行观察证据决定。",),
    )


def _verification_from_plan(
    task: VulnerabilityInput,
    plan: PocPlan,
    *,
    execution_records: tuple[ExecutionEvidenceRecord, ...],
) -> ExpVerification:
    exp_request = _build_exp_request(plan)
    matched_records = tuple(
        record for record in execution_records if _record_matches_plan(record, plan)
    )
    affected_record = _first_record_for_role(matched_records, ExpVersionRole.AFFECTED)
    fixed_record = _first_record_for_role(matched_records, ExpVersionRole.FIXED)

    unknowns: list[str] = []
    limitations = [
        "当前只支持 http_request_replay 这一类窄 runner。",
        (
            "当前 effect observation 只覆盖 Flask open redirect，"
            "包括 header redirect 与 meta refresh body signature。"
        ),
        (
            "当前支持 execution evidence JSON 或 loopback live HTTP replay；"
            "不自动启动真实服务，不连接真实公网目标。"
        ),
    ]

    affected = None
    if affected_record is None:
        unknowns.append("缺少 affected 版本 execution evidence。")
    else:
        affected = _observation_from_record(
            plan,
            affected_record,
            default_version=task.target.affected_version,
        )

    fixed = None
    if task.target.fixed_version is not None:
        if fixed_record is None:
            unknowns.append("缺少 fixed 版本 execution evidence。")
        else:
            fixed = _observation_from_record(
                plan,
                fixed_record,
                default_version=task.target.fixed_version,
            )

    verdict, comparison_summary, verdict_unknowns = _derive_verdict(
        affected=affected,
        fixed=fixed,
        has_fixed_version=task.target.fixed_version is not None,
    )
    unknowns.extend(verdict_unknowns)

    evidence = (
        *plan.evidence,
        *(affected.evidence if affected is not None else ()),
        *(fixed.evidence if fixed is not None else ()),
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.EXECUTION_LOG,
                metadata={
                    "stage": "M4",
                    "runner": exp_request.runner,
                    "verification_verdict": verdict.value,
                    "vulnerability_type": plan.vulnerability_type,
                },
            ),
            summary="将 M3 PoC plan 与版本对照执行观察收敛为 M4 exp verification 结论。",
            reasoning=(
                "M4 同时检查受影响版本和修复版本的执行观察，"
                "并把执行状态、效果状态和最终 verdict 明确分层。"
            ),
            confidence=0.82,
            reproducible_steps=(
                "load local execution evidence fixtures",
                "compare affected/fixed observations under the same request artifact",
            ),
            open_questions=tuple(verdict_unknowns),
        ),
    )

    return ExpVerification(
        verdict=verdict,
        vulnerability_type=plan.vulnerability_type,
        poc_plan=plan,
        exp_request=exp_request,
        affected=affected,
        fixed=fixed,
        comparison_summary=comparison_summary,
        evidence=evidence,
        unknowns=tuple(dict.fromkeys(unknowns)),
        limitations=tuple(limitations),
    )


def _build_exp_request(plan: PocPlan) -> ExpRequestArtifact:
    request = plan.request
    command = _curl_command_for_request(request)
    reasoning = (
        "当前 M4 以可重放 request artifact 表达最小 exp；"
        f"请将 `{_TARGET_HOST_PLACEHOLDER}` 替换为隔离环境中的 affected 或 fixed 服务地址。"
    )
    if request.parameter_location is PocParameterLocation.QUERY_OR_FORM:
        reasoning += (
            " 当前默认优先生成 query replay；"
            "若目标实现实际从 form 消费，需要人工切换请求位置。"
        )
    return ExpRequestArtifact(
        runner="http_request_replay",
        command=command,
        reasoning=reasoning,
    )


def _local_target(
    version_role: ExpVersionRole,
    base_url: str | None,
) -> LocalExecutionTarget | None:
    if base_url is None:
        return None
    try:
        parsed = urlsplit(base_url)
    except ValueError as exc:
        raise LocalExecutionError(f"{version_role.value} base URL 非法：{base_url}") from exc
    if parsed.scheme != "http":
        raise LocalExecutionError(
            f"{version_role.value} base URL 只允许 loopback http：{base_url}"
        )
    if parsed.username or parsed.password:
        raise LocalExecutionError(f"{version_role.value} base URL 不允许包含用户信息")
    if parsed.query or parsed.fragment:
        raise LocalExecutionError(f"{version_role.value} base URL 不允许包含 query 或 fragment")
    if parsed.path not in ("", "/"):
        raise LocalExecutionError(f"{version_role.value} base URL 不允许包含 path 前缀")
    host = parsed.hostname
    if host is None or host not in _LOOPBACK_HOSTS:
        raise LocalExecutionError(
            f"{version_role.value} base URL 只允许 localhost/127.0.0.1/::1：{base_url}"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise LocalExecutionError(f"{version_role.value} base URL 端口非法：{base_url}") from exc
    if port is None or port <= 0:
        raise LocalExecutionError(f"{version_role.value} base URL 必须显式包含端口：{base_url}")
    return LocalExecutionTarget(
        version_role=version_role,
        base_url=base_url,
        host=host,
        port=port,
    )


def _curl_command_for_request(request: PocRequestShape) -> str:
    url = f"{_TARGET_HOST_PLACEHOLDER}{request.path}"
    first_parameter = request.parameters[0] if request.parameters else None
    if first_parameter is None:
        return f"curl -i '{url}'"
    encoded_pair = f"{first_parameter.name}={first_parameter.value}"

    if request.parameter_location in {
        PocParameterLocation.QUERY,
        PocParameterLocation.QUERY_OR_FORM,
    }:
        return f"curl -i -G --data-urlencode '{encoded_pair}' '{url}'"
    if request.parameter_location is PocParameterLocation.FORM:
        return f"curl -i -X {request.method} --data-urlencode '{encoded_pair}' '{url}'"
    if request.parameter_location is PocParameterLocation.JSON:
        payload = json.dumps({first_parameter.name: first_parameter.value}, ensure_ascii=False)
        return (
            f"curl -i -X {request.method} -H 'Content-Type: application/json' "
            f"--data '{payload}' '{url}'"
        )
    if request.parameter_location is PocParameterLocation.HEADER:
        return (
            f"curl -i -X {request.method} "
            f"-H '{first_parameter.name}: {first_parameter.value}' '{url}'"
        )
    if request.parameter_location is PocParameterLocation.COOKIE:
        return (
            f"curl -i -X {request.method} "
            f"--cookie '{first_parameter.name}={first_parameter.value}' '{url}'"
        )
    if request.parameter_location is PocParameterLocation.PATH:
        return f"curl -i -X {request.method} '{url}'"
    return f"curl -i -X {request.method} '{url}'"


def _execute_local_request(
    plan: PocPlan,
    *,
    target: LocalExecutionTarget,
    timeout_seconds: float,
) -> ExecutionEvidenceRecord:
    request_path, request_body, headers, request_notes = _request_components(plan.request)
    try:
        connection = http.client.HTTPConnection(
            target.host,
            target.port,
            timeout=timeout_seconds,
        )
        connection.request(
            plan.request.method,
            request_path,
            body=request_body,
            headers=headers,
        )
        response = connection.getresponse()
        response_headers = tuple(response.getheaders())
        status_code = response.status
        response_body_text = _decode_response_body(response.read())
        notes = request_notes
        execution_state = ExpExecutionState.COMPLETED
        exit_code = 0
    except ConnectionRefusedError:
        response_headers = ()
        status_code = None
        response_body_text = None
        notes = (
            *request_notes,
            f"{target.version_role.value} 目标未监听：{target.base_url}",
        )
        execution_state = ExpExecutionState.ENVIRONMENT_MISSING
        exit_code = 1
    except socket.gaierror:
        response_headers = ()
        status_code = None
        response_body_text = None
        notes = (
            *request_notes,
            f"{target.version_role.value} 目标地址无法解析：{target.base_url}",
        )
        execution_state = ExpExecutionState.ENVIRONMENT_MISSING
        exit_code = 1
    except TimeoutError:
        response_headers = ()
        status_code = None
        response_body_text = None
        notes = (
            *request_notes,
            f"{target.version_role.value} 本地请求超时：{target.base_url}",
        )
        execution_state = ExpExecutionState.RUN_FAILED
        exit_code = 1
    except OSError as exc:
        response_headers = ()
        status_code = None
        response_body_text = None
        notes = (
            *request_notes,
            f"{target.version_role.value} 本地请求失败：{exc}",
        )
        execution_state = ExpExecutionState.RUN_FAILED
        exit_code = 1
    finally:
        if "connection" in locals():
            connection.close()

    plan_match = _plan_match_for_plan(plan)
    evidence = (
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.EXECUTION_LOG,
                uri=target.base_url,
                metadata={
                    "execution_source": "loopback_live_http",
                    "version_role": target.version_role.value,
                    "status_code": status_code,
                    "plan_match": plan_match,
                    "request_path": request_path,
                },
            ),
            summary=(
                f"loopback live runner 记录了 "
                f"{target.version_role.value} 版本的真实首跳 HTTP 观察。"
            ),
            reasoning=(
                "M4.1 将 execution observation 的来源从静态 JSON fixture 扩展到"
                " localhost/127.0.0.1/::1 上的真实 HTTP replay。"
            ),
            confidence=0.82,
            reproducible_steps=(
                f"send {plan.request.method} {request_path} to {target.base_url}",
            ),
            open_questions=tuple(notes),
        ),
    )
    return ExecutionEvidenceRecord(
        plan_match=plan_match,
        version_role=target.version_role,
        execution_state=execution_state,
        request=plan.request,
        exit_code=exit_code,
        status_code=status_code,
        response_headers=response_headers,
        response_body_text=response_body_text,
        notes=tuple(notes),
        evidence=evidence,
    )


def _plan_match_for_plan(plan: PocPlan) -> dict[str, str]:
    return {
        "vulnerability_type": plan.vulnerability_type,
        "sink_name": plan.path.sink.signature.name,
        "entrypoint_name": plan.entrypoint.name,
        "parameter_name": plan.trigger_input.name,
    }


def _request_components(
    request: PocRequestShape,
) -> tuple[str, bytes | None, dict[str, str], tuple[str, ...]]:
    path = request.path if request.path.startswith("/") else f"/{request.path}"
    parameters = [(item.name, item.value) for item in request.parameters]
    headers: dict[str, str] = {}
    body: bytes | None = None
    notes: list[str] = []

    if request.parameter_location in {
        PocParameterLocation.QUERY,
        PocParameterLocation.QUERY_OR_FORM,
    }:
        if parameters:
            path = f"{path}?{urlencode(parameters, doseq=True)}"
        if request.parameter_location is PocParameterLocation.QUERY_OR_FORM:
            notes.append("QUERY_OR_FORM 当前按 query replay 执行。")
        return path, body, headers, tuple(notes)

    if request.parameter_location is PocParameterLocation.FORM:
        body = urlencode(parameters, doseq=True).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return path, body, headers, tuple(notes)

    if request.parameter_location is PocParameterLocation.JSON:
        payload = {name: value for name, value in parameters}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        return path, body, headers, tuple(notes)

    if request.parameter_location is PocParameterLocation.HEADER:
        headers.update({name: value for name, value in parameters})
        return path, body, headers, tuple(notes)

    if request.parameter_location is PocParameterLocation.COOKIE:
        if parameters:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in parameters)
        return path, body, headers, tuple(notes)

    if request.parameter_location is PocParameterLocation.PATH:
        return path, body, headers, tuple(notes)

    return path, body, headers, tuple(notes)


def _record_matches_plan(record: ExecutionEvidenceRecord, plan: PocPlan) -> bool:
    match = record.plan_match
    if "vulnerability_type" in match and match["vulnerability_type"] != plan.vulnerability_type:
        return False
    if "sink_name" in match and match["sink_name"] != plan.path.sink.signature.name:
        return False
    if "entrypoint_name" in match and match["entrypoint_name"] != plan.entrypoint.name:
        return False
    if "parameter_name" in match and match["parameter_name"] != plan.trigger_input.name:
        return False
    return True


def _first_record_for_role(
    records: tuple[ExecutionEvidenceRecord, ...],
    role: ExpVersionRole,
) -> ExecutionEvidenceRecord | None:
    for record in records:
        if record.version_role is role:
            return record
    return None


def _observation_from_record(
    plan: PocPlan,
    record: ExecutionEvidenceRecord,
    *,
    default_version: str | None,
) -> ExpObservation:
    effect_state, observed_effect, unknowns = _effect_from_record(plan, record)
    return ExpObservation(
        version_role=record.version_role,
        version=record.version or default_version,
        execution_state=record.execution_state,
        effect_state=effect_state,
        request=record.request,
        exit_code=record.exit_code,
        status_code=record.status_code,
        response_headers=record.response_headers,
        response_body_excerpt=_body_excerpt(record.response_body_text),
        observed_effect=observed_effect,
        evidence=record.evidence,
        unknowns=tuple(dict.fromkeys((*record.notes, *unknowns))),
    )


def _effect_from_record(
    plan: PocPlan,
    record: ExecutionEvidenceRecord,
) -> tuple[ExpEffectState, str, tuple[str, ...]]:
    if record.execution_state is not ExpExecutionState.COMPLETED:
        return (
            ExpEffectState.EFFECT_UNKNOWN,
            "执行观察未完成，当前无法判断是否观察到预期效果。",
            ("需要补足可比的执行环境或运行日志。",),
        )
    if plan.vulnerability_type != "open_redirect":
        return (
            ExpEffectState.EFFECT_UNKNOWN,
            "当前 M4 只支持 open_redirect 的最小 effect observation。",
            ("需要为新的 vulnerability_type 单独引入观察规则。",),
        )
    return _open_redirect_effect_from_record(plan, record)


def _open_redirect_effect_from_record(
    plan: PocPlan,
    record: ExecutionEvidenceRecord,
) -> tuple[ExpEffectState, str, tuple[str, ...]]:
    headers = {name.lower(): value for name, value in record.response_headers}
    location = headers.get("location")
    status_code = record.status_code
    if _looks_external_url(location):
        if location == plan.trigger_input.value:
            return (
                ExpEffectState.EFFECT_OBSERVED,
                "响应返回 30x，Location 与攻击者控制的外部 URL 一致。",
                (),
            )
        return (
            ExpEffectState.EFFECT_OBSERVED,
            "响应返回 30x，Location 指向外部 URL，观察到 open redirect 风格效果。",
            ("实际 Location 与 M3 样例值不完全一致，需要人工确认是否为等价外跳。",),
        )
    meta_refresh_url = _extract_meta_refresh_url(record.response_body_text)
    if _looks_external_url(meta_refresh_url):
        if meta_refresh_url == plan.trigger_input.value:
            return (
                ExpEffectState.EFFECT_OBSERVED,
                "响应 body 中的 meta refresh 与攻击者控制的外部 URL 一致。",
                (),
            )
        return (
            ExpEffectState.EFFECT_OBSERVED,
            "响应 body 中的 meta refresh 指向外部 URL，观察到 open redirect 风格效果。",
            ("实际 body redirect 目标与 M3 样例值不完全一致，需要人工确认是否为等价外跳。",),
        )
    if status_code is not None and not 300 <= status_code < 400:
        return (
            ExpEffectState.EFFECT_NOT_OBSERVED,
            f"响应状态码为 {status_code}，且未观察到 Location 或 meta refresh 外跳效果。",
            (),
        )
    if not location:
        return (
            ExpEffectState.EFFECT_NOT_OBSERVED,
            "响应缺少 Location header，且 body 未观察到可用于 open redirect 的 meta refresh 效果。",
            (),
        )
    return (
        ExpEffectState.EFFECT_NOT_OBSERVED,
        "响应重定向到站内或非外部目标，且 body 未观察到外跳效果。",
        (),
    )


def _looks_external_url(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(_EXTERNAL_URL_PREFIXES)


def _extract_meta_refresh_url(body: str | None) -> str:
    if not body:
        return ""
    match = _META_REFRESH_URL_RE.search(body)
    if match is None:
        return ""
    return match.group(1).strip()


def _body_excerpt(body: str | None) -> str | None:
    if not body:
        return None
    compact = " ".join(body.split())
    if len(compact) <= _BODY_EXCERPT_LIMIT:
        return compact
    return f"{compact[:_BODY_EXCERPT_LIMIT - 3]}..."


def _derive_verdict(
    *,
    affected: ExpObservation | None,
    fixed: ExpObservation | None,
    has_fixed_version: bool,
) -> tuple[ExpVerificationVerdict, str, tuple[str, ...]]:
    unknowns: list[str] = []
    if affected is None:
        unknowns.append("缺少 affected 版本观察，无法形成对照结论。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "缺少 affected 版本观察，M4 结果保持 inconclusive。",
            tuple(unknowns),
        )

    if affected.execution_state is not ExpExecutionState.COMPLETED:
        unknowns.append("affected 版本执行未完成。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "affected 版本执行未完成，无法判断是否验证成功。",
            tuple(unknowns),
        )

    if affected.effect_state is ExpEffectState.EFFECT_UNKNOWN:
        unknowns.append("affected 版本效果观察仍不明确。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "affected 版本效果观察不明确，无法形成稳定 verdict。",
            tuple(unknowns),
        )

    if not has_fixed_version:
        unknowns.append("缺少 fixed_version，对照验证语义不完整。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "当前缺少 fixed 版本对照，M4 结果保持 inconclusive。",
            tuple(unknowns),
        )

    if fixed is None:
        unknowns.append("缺少 fixed 版本观察，无法完成版本对照。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "缺少 fixed 版本观察，M4 结果保持 inconclusive。",
            tuple(unknowns),
        )

    if fixed.execution_state is not ExpExecutionState.COMPLETED:
        unknowns.append("fixed 版本执行未完成。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "fixed 版本执行未完成，无法完成对照验证。",
            tuple(unknowns),
        )

    if fixed.effect_state is ExpEffectState.EFFECT_UNKNOWN:
        unknowns.append("fixed 版本效果观察仍不明确。")
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "fixed 版本效果观察不明确，M4 结果保持 inconclusive。",
            tuple(unknowns),
        )

    if (
        affected.effect_state is ExpEffectState.EFFECT_OBSERVED
        and fixed.effect_state is ExpEffectState.EFFECT_NOT_OBSERVED
    ):
        return (
            ExpVerificationVerdict.VERIFIED,
            "affected 版本观察到预期效果，fixed 版本未观察到效果，漏洞判断得到对照验证。",
            (),
        )

    if affected.effect_state is ExpEffectState.EFFECT_NOT_OBSERVED:
        return (
            ExpVerificationVerdict.NOT_VERIFIED,
            "affected 版本未观察到预期效果，当前漏洞判断未得到验证。",
            (),
        )

    if (
        affected.effect_state is ExpEffectState.EFFECT_OBSERVED
        and fixed.effect_state is ExpEffectState.EFFECT_OBSERVED
    ):
        unknowns.append(
            "affected 与 fixed 都观察到外跳效果，"
            "当前无法仅凭最小 harness 判断修复是否失效。"
        )
        return (
            ExpVerificationVerdict.INCONCLUSIVE,
            "affected 与 fixed 都观察到效果，当前先保持 inconclusive。",
            tuple(unknowns),
        )

    return (
        ExpVerificationVerdict.INCONCLUSIVE,
        "当前观察结果不足以收敛为 verified 或 not_verified。",
        tuple(unknowns),
    )


def _execution_record_from_dict(
    data: object,
    *,
    evidence_path: Path,
) -> ExecutionEvidenceRecord:
    if not isinstance(data, dict):
        raise ExecutionEvidenceError("execution observation 必须是 object")
    plan_match = data.get("plan_match")
    if not isinstance(plan_match, dict):
        raise ExecutionEvidenceError("execution observation.plan_match 必须是 object")
    version_role = _enum_from_value(
        ExpVersionRole,
        data.get("version_role"),
        field="execution observation.version_role",
    )
    execution_state = _enum_from_value(
        ExpExecutionState,
        data.get("execution_state"),
        field="execution observation.execution_state",
    )
    request = _request_from_dict(data.get("request"))
    version = _optional_str(data.get("version"))
    exit_code = _optional_int(data.get("exit_code"))

    response = data.get("response", {})
    if response is None:
        response = {}
    if not isinstance(response, dict):
        raise ExecutionEvidenceError("execution observation.response 必须是 object")
    status_code = _optional_int(response.get("status_code"))
    response_headers = _headers_from_mapping(response.get("headers"))
    response_body_text = _optional_str(response.get("body"))
    notes = _string_list(data.get("notes"), field="execution observation.notes")
    evidence = (
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.EXECUTION_LOG,
                uri=str(evidence_path),
                metadata={
                    "version_role": version_role.value,
                    "version": version,
                    "status_code": status_code,
                    "plan_match": plan_match,
                },
            ),
            summary=f"本地 execution evidence 记录了 {version_role.value} 版本的执行观察。",
            reasoning="M4 使用受影响版本 / 修复版本的本地执行观察来形成差分验证结论。",
            confidence=0.78,
            reproducible_steps=(f"inspect {evidence_path}",),
            open_questions=tuple(notes),
        ),
    )

    return ExecutionEvidenceRecord(
        plan_match=plan_match,
        version_role=version_role,
        execution_state=execution_state,
        request=request,
        version=version,
        exit_code=exit_code,
        status_code=status_code,
        response_headers=response_headers,
        response_body_text=response_body_text,
        notes=tuple(notes),
        evidence=evidence,
    )


def _request_from_dict(data: object) -> PocRequestShape:
    if not isinstance(data, dict):
        raise ExecutionEvidenceError("execution observation.request 必须是 object")
    method = data.get("method")
    path = data.get("path")
    if not isinstance(method, str) or not method:
        raise ExecutionEvidenceError("execution observation.request.method 必须是非空字符串")
    if not isinstance(path, str) or not path:
        raise ExecutionEvidenceError("execution observation.request.path 必须是非空字符串")
    parameter_location = _enum_from_value(
        PocParameterLocation,
        data.get("parameter_location"),
        field="execution observation.request.parameter_location",
    )
    parameters_data = data.get("parameters", [])
    if not isinstance(parameters_data, list):
        raise ExecutionEvidenceError("execution observation.request.parameters 必须是 list")
    parameters = []
    for item in parameters_data:
        if not isinstance(item, dict):
            raise ExecutionEvidenceError("execution observation.request.parameters[] 必须是 object")
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not name:
            raise ExecutionEvidenceError(
                "execution observation.request.parameters[].name 必须是非空字符串"
            )
        if not isinstance(value, str):
            raise ExecutionEvidenceError(
                "execution observation.request.parameters[].value 必须是字符串"
            )
        parameters.append(PocRequestParameter(name=name, value=value))
    return PocRequestShape(
        method=method,
        path=path,
        parameter_location=parameter_location,
        parameters=tuple(parameters),
    )


def _headers_from_mapping(data: object) -> tuple[tuple[str, str], ...]:
    if data is None:
        return ()
    if not isinstance(data, dict):
        raise ExecutionEvidenceError("execution observation.response.headers 必须是 object")
    headers = []
    for name, value in data.items():
        if not isinstance(name, str) or not name:
            raise ExecutionEvidenceError(
                "execution observation.response.headers key 必须是非空字符串"
            )
        if not isinstance(value, str):
            raise ExecutionEvidenceError(
                "execution observation.response.headers value 必须是字符串"
            )
        headers.append((name, value))
    return tuple(headers)


def _enum_from_value(enum_type, value: object, *, field: str):
    if not isinstance(value, str) or not value:
        raise ExecutionEvidenceError(f"{field} 必须是非空字符串")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ExecutionEvidenceError(f"{field} 不是受支持的枚举值：{value}") from exc


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise ExecutionEvidenceError("execution observation 中的整数字段必须是整数或 null")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExecutionEvidenceError("execution observation 中的字符串字段必须是字符串或 null")
    return value


def _decode_response_body(body: bytes) -> str | None:
    if not body:
        return None
    return body.decode("utf-8", errors="replace")


def _string_list(value: object, *, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ExecutionEvidenceError(f"{field} 必须是 list")
    result = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ExecutionEvidenceError(f"{field} 只能包含非空字符串")
        result.append(item)
    return tuple(result)
