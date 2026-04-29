import json
import subprocess
from pathlib import Path

from semgrep_llm_vul.benchmark import (
    BenchmarkCaseError,
    benchmark_cases_to_dict,
    benchmark_evaluations_to_dict,
    discover_benchmark_cases,
    evaluate_benchmark_case,
    load_benchmark_case,
)
from semgrep_llm_vul.cli import main

ROOT = Path(__file__).resolve().parent.parent


def test_load_benchmark_case_converts_inputs_to_vulnerability_task() -> None:
    case = load_benchmark_case(
        ROOT / "benchmarks" / "cases" / "curated-open-redirect-safe-wrapper"
    )

    assert case.case_id == "curated-open-redirect-safe-wrapper"
    assert case.target_stage == "M1"
    assert case.case_type == "curated_minimal"
    assert case.source["name"] == "project-curated"
    assert case.task.mode.value == "unknown_sink"
    assert case.task.artifacts[0].path == "fixtures/sink/open-redirect-fix.diff"
    assert case.expected["sink_candidates"][0]["name"] == "redirect"


def test_load_benchmark_case_rejects_invalid_case_type(tmp_path: Path) -> None:
    case_dir = _write_minimal_case(tmp_path, case_type="unknown_kind")

    try:
        load_benchmark_case(case_dir)
    except BenchmarkCaseError as exc:
        assert "type 必须是" in str(exc)
    else:
        raise AssertionError("invalid case type should fail")


def test_load_benchmark_case_requires_safety_block(tmp_path: Path) -> None:
    case_dir = _write_minimal_case(tmp_path, include_safety=False)

    try:
        load_benchmark_case(case_dir)
    except BenchmarkCaseError as exc:
        assert "safety 必须是 object" in str(exc)
    else:
        raise AssertionError("missing safety block should fail")


def test_load_benchmark_case_rejects_invalid_expected_schema(tmp_path: Path) -> None:
    case_dir = _write_minimal_case(tmp_path, expected_schema_version=2)

    try:
        load_benchmark_case(case_dir)
    except BenchmarkCaseError as exc:
        assert "expected.json schema_version 必须是 1" in str(exc)
    else:
        raise AssertionError("invalid expected schema should fail")


def test_load_benchmark_case_requires_notes_file(tmp_path: Path) -> None:
    case_dir = _write_minimal_case(tmp_path, include_notes=False)

    try:
        load_benchmark_case(case_dir)
    except BenchmarkCaseError as exc:
        assert "缺少 benchmark case notes" in str(exc)
    else:
        raise AssertionError("missing notes.md should fail")


def test_benchmark_sources_catalog_exists() -> None:
    sources = ROOT / "benchmarks" / "sources.md"

    text = sources.read_text(encoding="utf-8")

    assert "NIST SARD" in text
    assert "OWASP Benchmark" in text
    assert "Vul4J" in text
    assert "command injection distillation" in text
    assert "deserialization distillation" in text
    assert "第一批 case 筛选标准" in text


def test_benchmark_templates_exist_and_are_not_discovered_as_cases() -> None:
    templates = ROOT / "benchmarks" / "templates"

    assert (templates / "case.yaml").is_file()
    assert (templates / "expected.json").is_file()
    assert (templates / "notes.md").is_file()
    assert "replace-with-kebab-case-id" in (templates / "case.yaml").read_text(
        encoding="utf-8"
    )

    discovered_from_root = discover_benchmark_cases(ROOT / "benchmarks")

    assert len(discovered_from_root) == 22
    assert all(case.case_id != "replace-with-kebab-case-id" for case in discovered_from_root)


def test_evaluate_benchmark_case_passes_expected_sink_candidate() -> None:
    case = load_benchmark_case(
        ROOT / "benchmarks" / "cases" / "curated-open-redirect-safe-wrapper"
    )

    evaluation = evaluate_benchmark_case(case, artifact_base=ROOT)

    assert evaluation.outcome == "passed"
    assert evaluation.details == ()
    assert evaluation.report is not None
    assert evaluation.report.recommended is not None
    assert evaluation.report.recommended.signature.name == "redirect"


def test_evaluate_benchmark_case_passes_negative_case_without_candidates() -> None:
    case = load_benchmark_case(ROOT / "benchmarks" / "cases" / "curated-open-redirect-safe-diff")

    evaluation = evaluate_benchmark_case(case, artifact_base=ROOT)

    assert evaluation.outcome == "passed"
    assert evaluation.report is not None
    assert evaluation.report.candidates == ()


def test_evaluate_benchmark_case_fails_when_expected_candidate_missing(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "case.yaml").write_text(
        """
schema_version: 1
id: missing-candidate
type: curated_minimal
target_stage: M1
status: candidate
source:
  name: project-curated
  url: null
  license: project
target:
  repo_url: https://github.com/example/flask-app
  affected_version: v1.0.0
  language: python
inputs:
  description: No code evidence.
  mode: unknown_sink
safety:
  contains_poc: false
  contains_exp: false
  requires_isolation: false
""".lstrip(),
        encoding="utf-8",
    )
    (case_dir / "expected.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "stage": "M1",
                "expected_status": "candidate",
                "sink_candidates": [{"name": "redirect"}],
                "must_not_include": [],
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "notes.md").write_text("# missing-candidate\n", encoding="utf-8")
    case = load_benchmark_case(case_dir)

    evaluation = evaluate_benchmark_case(case, artifact_base=ROOT)

    assert evaluation.outcome == "failed"
    assert "missing expected sink candidate" in evaluation.details[0]


def test_benchmark_evaluations_to_dict_counts_outcomes() -> None:
    cases = discover_benchmark_cases(ROOT / "benchmarks" / "cases")
    evaluations = tuple(evaluate_benchmark_case(case, artifact_base=ROOT) for case in cases)

    report = benchmark_evaluations_to_dict(evaluations, cases=cases)

    assert report["kind"] == "benchmark_evaluation_report"
    assert report["summary"]["total"] == len(cases)
    assert report["summary"]["failed"] == 0
    assert report["summary"]["passed"] == 11
    assert report["summary"]["blocked"] == 1
    assert report["summary"]["unsupported"] == 10
    assert report["coverage"]["by_type"] == {
        "curated_minimal": 17,
        "real_vulnerability": 3,
        "synthetic_benchmark": 2,
    }
    assert report["coverage"]["by_stage"] == {"M1": 12, "M2": 9, "M3": 1}
    assert report["gaps"] == [
        {
            "case_id": "curated-open-redirect-reachability",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-blocked",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-cross-file-helper",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-from-import-helper",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-helper",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-import-alias-helper",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-multi-layer-helper",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-reachability-unknown",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "curated-open-redirect-taint-path",
            "code": "unsupported_stage",
            "stage": "M2",
            "source": "project-curated",
            "message": "当前 evaluator 不支持 M2。",
        },
        {
            "case_id": "cvefixes-dataset-intake-unsupported",
            "code": "unsupported_source_ingestion",
            "stage": "M1",
            "source": "CVEfixes",
            "message": "当前不支持直接导入完整 CVEfixes 数据库。",
        },
        {
            "case_id": "vul4j-real-java-intake-blocked",
            "code": "blocked_runtime",
            "stage": "M3",
            "source": "Vul4J",
            "message": "需要隔离环境、checkout 或运行边界后才能执行。",
        },
    ]
    first_case = report["cases"][0]
    assert first_case["type"] in {
        "curated_minimal",
        "synthetic_benchmark",
        "real_vulnerability",
    }
    assert "declared_status" in first_case
    assert "source" in first_case


def test_benchmark_cases_to_dict_outputs_inventory() -> None:
    cases = discover_benchmark_cases(ROOT / "benchmarks" / "cases")

    inventory = benchmark_cases_to_dict(cases)

    assert inventory["kind"] == "benchmark_case_inventory"
    assert inventory["summary"] == {
        "total": 22,
        "candidate": 20,
        "blocked": 1,
        "unsupported": 1,
    }
    assert inventory["coverage"]["by_stage"] == {"M1": 12, "M2": 9, "M3": 1}
    assert inventory["cases"][0]["safety"]["contains_poc"] is False


def test_benchmark_script_runs_harness() -> None:
    result = subprocess.run(
        [str(ROOT / "scripts" / "benchmark")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Benchmark/case harness check passed." in result.stdout


def _write_minimal_case(
    tmp_path: Path,
    *,
    case_type: str = "curated_minimal",
    include_safety: bool = True,
    include_notes: bool = True,
    expected_schema_version: int = 1,
) -> Path:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    safety = (
        """
safety:
  contains_poc: false
  contains_exp: false
  requires_isolation: false
"""
        if include_safety
        else ""
    )
    (case_dir / "case.yaml").write_text(
        f"""
schema_version: 1
id: schema-validation-case
type: {case_type}
target_stage: M1
status: candidate
source:
  name: project-curated
  url: null
  license: project
target:
  repo_url: https://github.com/example/flask-app
  affected_version: v1.0.0
  language: python
inputs:
  description: No code evidence.
  mode: unknown_sink
{safety}
""".lstrip(),
        encoding="utf-8",
    )
    (case_dir / "expected.json").write_text(
        json.dumps(
            {
                "schema_version": expected_schema_version,
                "stage": "M1",
                "expected_status": "candidate",
                "sink_candidates": [],
                "must_not_include": [],
            }
        ),
        encoding="utf-8",
    )
    if include_notes:
        (case_dir / "notes.md").write_text("# schema-validation-case\n", encoding="utf-8")
    return case_dir


def test_evaluate_benchmarks_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "evaluate-benchmarks",
            str(ROOT / "benchmarks" / "cases"),
            "--artifact-base",
            str(ROOT),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "benchmark_evaluation_report"
    assert report["summary"]["failed"] == 0
    assert report["summary"]["total"] == 22
    assert report["summary"]["passed"] == 11
    assert report["summary"]["blocked"] == 1
    assert report["summary"]["unsupported"] == 10
    assert {gap["code"] for gap in report["gaps"]} == {
        "blocked_runtime",
        "unsupported_stage",
        "unsupported_source_ingestion",
    }
