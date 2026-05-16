from pathlib import Path

from semgrep_llm_vul import (
    AnalysisTarget,
    CodeLocation,
    Evidence,
    ExpEffectState,
    ExpExecutionState,
    ExpObservation,
    ExpRequestArtifact,
    ExpVerification,
    ExpVerificationVerdict,
    ExpVersionRole,
    FunctionSignature,
    InputMode,
    PocExecutionState,
    PocParameterLocation,
    PocPlan,
    PocRequestParameter,
    PocRequestShape,
    PocTriggerInput,
    PocVerdict,
    ReachabilityEntrypoint,
    SemanticHint,
    SemanticHintKind,
    SemanticHintReport,
    SinkCandidate,
    SourceCandidate,
    TaintPath,
    TaintStep,
    VulnerabilityInput,
)
from semgrep_llm_vul.exp_verification import ExpVerificationReport
from semgrep_llm_vul.models import EvidenceKind, SourceReference
from semgrep_llm_vul.poc_generation import PocGenerationReport
from semgrep_llm_vul.reporting import (
    exp_verification_report_to_dict,
    poc_generation_report_to_dict,
    semantic_hint_report_to_dict,
    sink_generation_report_to_dict,
    taint_path_generation_report_to_dict,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent


def test_sink_generation_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.KNOWN_SINK,
        sink_signature=FunctionSignature(raw="flask.redirect(location)", name="redirect"),
    )

    report = sink_generation_report_to_dict(generate_sink_report(task), task=task)

    assert report["schema_version"] == 1
    assert report["kind"] == "sink_generation_report"
    assert report["mode"] == "known_sink"
    assert report["target"]["repo_url"] == "https://github.com/example/flask-app"
    assert report["recommended"]["signature"]["name"] == "redirect"
    assert report["recommended"]["confidence"] == 0.9
    assert report["candidates"][0]["evidence"]
    assert isinstance(report["unknowns"], list)


def test_taint_path_generation_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )
    fixture = ROOT / "fixtures" / "semgrep" / "taint-result-with-trace.json"
    sink_report = generate_sink_report(task, semgrep_findings=tuple(load_semgrep_findings(fixture)))
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=tuple(load_semgrep_taint_paths(fixture)),
    )

    report = taint_path_generation_report_to_dict(taint_report, task=task)

    assert report["schema_version"] == 1
    assert report["kind"] == "taint_path_generation_report"
    assert report["mode"] == "unknown_sink"
    assert report["target"]["language"] == "python"
    assert report["paths"][0]["source"]["name"] == 'request.args["next"]'
    assert report["paths"][0]["sink"]["signature"]["name"] == "redirect"
    assert report["paths"][0]["steps"][0]["role"] == "source"
    assert report["paths"][0]["reachable"] is None
    assert report["paths"][0]["evidence"]
    assert isinstance(report["unknowns"], list)


def test_semantic_hint_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )
    location = CodeLocation(path="app/helpers.py", start_line=12, start_col=5)
    evidence = Evidence(
        source=SourceReference(kind=EvidenceKind.CODE_LOCATION, location=location),
        summary="Helper wraps redirect.",
        reasoning="The helper name and body both suggest redirect semantics.",
        confidence=0.7,
        reproducible_steps=("inspect app/helpers.py:12",),
    )
    report = semantic_hint_report_to_dict(
        SemanticHintReport(
            hints=(
                SemanticHint(
                    symbol="issue_redirect",
                    kind=SemanticHintKind.SINK,
                    summary="Likely redirect-style sink wrapper.",
                    reasoning="The helper forwards a user-influenced URL into redirect.",
                    confidence=0.74,
                    location=location,
                    evidence=(evidence,),
                    applicable_versions=("v1.0.0",),
                    applicable_contexts=("open_redirect", "flask_helper_wrapper"),
                    preconditions=("Need local AST or call-chain evidence.",),
                    failure_modes=("Could be a safe wrapper that validates destinations.",),
                    unknowns=("Validation logic has not been confirmed.",),
                ),
            ),
            evidence=(evidence,),
            unknowns=("LLM hints are candidates only, not final verdicts.",),
        ),
        task=task,
    )

    assert report["schema_version"] == 1
    assert report["kind"] == "semantic_hint_report"
    assert report["target"]["language"] == "python"
    assert report["hints"][0]["symbol"] == "issue_redirect"
    assert report["hints"][0]["kind"] == "sink"
    assert report["hints"][0]["location"]["path"] == "app/helpers.py"
    assert report["hints"][0]["applicable_versions"] == ["v1.0.0"]
    assert report["hints"][0]["applicable_contexts"] == [
        "open_redirect",
        "flask_helper_wrapper",
    ]
    assert report["hints"][0]["failure_modes"] == [
        "Could be a safe wrapper that validates destinations."
    ]
    assert report["unknowns"] == ["LLM hints are candidates only, not final verdicts."]


def test_poc_generation_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )
    location = CodeLocation(path="app/routes.py", start_line=12)
    evidence = Evidence(
        source=SourceReference(kind=EvidenceKind.CODE_LOCATION, location=location),
        summary="request.args reaches redirect.",
        reasoning="The same route reads next and returns redirect(next_url).",
        confidence=0.8,
    )
    plan = PocPlan(
        verdict=PocVerdict.PLANNED,
        execution_state=PocExecutionState.NOT_RUN,
        vulnerability_type="open_redirect",
        path=TaintPath(
            source=SourceCandidate(
                name='request.args["next"]',
                location=location,
                reason="User-controlled query parameter.",
                confidence=0.8,
                evidence=(evidence,),
            ),
            sink=SinkCandidate(
                signature=FunctionSignature(raw="redirect(location)", name="redirect"),
                reason="redirect can send users to attacker-controlled locations.",
                confidence=0.8,
                evidence=(evidence,),
            ),
            steps=(TaintStep(location=location, symbol="redirect", evidence=(evidence,)),),
            reachable=True,
            evidence=(evidence,),
        ),
        entrypoint=ReachabilityEntrypoint(
            kind="flask_route",
            name="GET /login",
            location=location,
            evidence=(evidence,),
        ),
        trigger_input=PocTriggerInput(
            location=PocParameterLocation.QUERY,
            name="next",
            value="https://attacker.example/poc",
            reasoning="source 直接来自 request.args。",
        ),
        request=PocRequestShape(
            method="GET",
            path="/login",
            parameter_location=PocParameterLocation.QUERY,
            parameters=(PocRequestParameter(name="next", value="https://attacker.example/poc"),),
        ),
        expected_effect="响应返回 30x，并把 Location 指向攻击者控制 URL。",
        evidence=(evidence,),
        unknowns=("未验证认证要求。",),
        limitations=("当前未实际发送请求。",),
    )

    report = poc_generation_report_to_dict(
        PocGenerationReport(
            plans=(plan,),
            evidence=(evidence,),
            unknowns=("M3 当前默认不执行请求。",),
        ),
        task=task,
    )

    assert report["schema_version"] == 1
    assert report["kind"] == "poc_generation_report"
    assert report["plans"][0]["verdict"] == "planned"
    assert report["plans"][0]["execution_state"] == "not_run"
    assert report["plans"][0]["trigger_input"]["location"] == "query"
    assert report["plans"][0]["request"]["method"] == "GET"
    assert report["plans"][0]["request"]["parameters"][0]["name"] == "next"
    assert report["unknowns"] == ["M3 当前默认不执行请求。"]


def test_exp_verification_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )
    location = CodeLocation(path="app/routes.py", start_line=12)
    evidence = Evidence(
        source=SourceReference(kind=EvidenceKind.CODE_LOCATION, location=location),
        summary="request.args reaches redirect.",
        reasoning="The same route reads next and returns redirect(next_url).",
        confidence=0.8,
    )
    plan = PocPlan(
        verdict=PocVerdict.PLANNED,
        execution_state=PocExecutionState.NOT_RUN,
        vulnerability_type="open_redirect",
        path=TaintPath(
            source=SourceCandidate(
                name='request.args["next"]',
                location=location,
                reason="User-controlled query parameter.",
                confidence=0.8,
                evidence=(evidence,),
            ),
            sink=SinkCandidate(
                signature=FunctionSignature(raw="redirect(location)", name="redirect"),
                reason="redirect can send users to attacker-controlled locations.",
                confidence=0.8,
                evidence=(evidence,),
            ),
            steps=(TaintStep(location=location, symbol="redirect", evidence=(evidence,)),),
            reachable=True,
            evidence=(evidence,),
        ),
        entrypoint=ReachabilityEntrypoint(
            kind="flask_route",
            name="GET /login",
            location=location,
            evidence=(evidence,),
        ),
        trigger_input=PocTriggerInput(
            location=PocParameterLocation.QUERY,
            name="next",
            value="https://attacker.example/poc",
            reasoning="source 直接来自 request.args。",
        ),
        request=PocRequestShape(
            method="GET",
            path="/login",
            parameter_location=PocParameterLocation.QUERY,
            parameters=(PocRequestParameter(name="next", value="https://attacker.example/poc"),),
        ),
        expected_effect="响应返回 30x，并把 Location 指向攻击者控制 URL。",
        evidence=(evidence,),
    )

    report = exp_verification_report_to_dict(
        ExpVerificationReport(
            verifications=(
                ExpVerification(
                    verdict=ExpVerificationVerdict.VERIFIED,
                    vulnerability_type="open_redirect",
                    poc_plan=plan,
                    exp_request=ExpRequestArtifact(
                        runner="http_request_replay",
                        command="curl -i -G --data-urlencode 'next=https://attacker.example/poc' 'http://TARGET_HOST/login'",
                        reasoning="使用 query replay。",
                    ),
                    affected=ExpObservation(
                        version_role=ExpVersionRole.AFFECTED,
                        version="v1.0.0",
                        execution_state=ExpExecutionState.COMPLETED,
                        effect_state=ExpEffectState.EFFECT_OBSERVED,
                        request=plan.request,
                        exit_code=0,
                        status_code=302,
                        response_headers=(("Location", "https://attacker.example/poc"),),
                        observed_effect="观察到外跳。",
                        evidence=(evidence,),
                    ),
                    fixed=ExpObservation(
                        version_role=ExpVersionRole.FIXED,
                        version="v1.0.1",
                        execution_state=ExpExecutionState.COMPLETED,
                        effect_state=ExpEffectState.EFFECT_NOT_OBSERVED,
                        request=plan.request,
                        exit_code=0,
                        status_code=302,
                        response_headers=(("Location", "/"),),
                        observed_effect="未观察到外跳。",
                        evidence=(evidence,),
                    ),
                    comparison_summary="affected 观察到外跳，fixed 未观察到外跳。",
                    evidence=(evidence,),
                    unknowns=("当前仍未自动启动真实服务。",),
                ),
            ),
            evidence=(evidence,),
            unknowns=("M4 当前只支持本地 execution evidence。",),
        ),
        task=task,
    )

    assert report["schema_version"] == 1
    assert report["kind"] == "exp_verification_report"
    assert report["verifications"][0]["verdict"] == "verified"
    assert report["verifications"][0]["exp_request"]["runner"] == "http_request_replay"
    assert report["verifications"][0]["affected"]["execution_state"] == "completed"
    assert report["verifications"][0]["affected"]["effect_state"] == "effect_observed"
    assert report["verifications"][0]["fixed"]["response_headers"]["Location"] == "/"
    assert report["unknowns"] == ["M4 当前只支持本地 execution evidence。"]
