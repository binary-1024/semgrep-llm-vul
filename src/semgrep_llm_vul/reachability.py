"""M2 最小可触达确认。"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semgrep_llm_vul.models import (
    BlockingFactor,
    CodeLocation,
    Evidence,
    EvidenceKind,
    ReachabilityAssessment,
    ReachabilityCallStep,
    ReachabilityEntrypoint,
    SourceControlAssessment,
    SourceReference,
    TaintPath,
    VulnerabilityInput,
)
from semgrep_llm_vul.taint_path_generation import TaintPathGenerationReport

_RouteFunction = ast.FunctionDef | ast.AsyncFunctionDef
_MAX_FLASK_HELPER_HOPS = 2
_FLASK_REQUEST_FIELDS = {
    "args",
    "form",
    "values",
    "json",
    "cookies",
    "headers",
    "view_args",
}


class ReachabilityEvidenceError(ValueError):
    """可触达证据输入无法读取或无法解析。"""


@dataclass(frozen=True)
class ReachabilityEvidenceRecord:
    """本地可触达证据记录。"""

    path_match: dict[str, Any]
    reachable: bool | None
    entrypoint: ReachabilityEntrypoint | None = None
    call_chain: tuple[ReachabilityCallStep, ...] = ()
    source_control: SourceControlAssessment | None = None
    blocking_factors: tuple[BlockingFactor, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.reachable is False and not self.blocking_factors:
            raise ReachabilityEvidenceError(
                "reachable=false 的证据记录必须提供 blocking_factors"
            )
        if self.reachable is True and self.entrypoint is None:
            raise ReachabilityEvidenceError("reachable=true 的证据记录必须提供 entrypoint")
        if self.reachable is True and not self.call_chain:
            raise ReachabilityEvidenceError("reachable=true 的证据记录必须提供 call_chain")


@dataclass(frozen=True)
class ReachabilityReport:
    """可触达确认报告。"""

    assessments: tuple[ReachabilityAssessment, ...]
    evidence: tuple[Evidence, ...] = ()
    unknowns: tuple[str, ...] = ()


def load_reachability_evidence(path: str | Path) -> tuple[ReachabilityEvidenceRecord, ...]:
    """读取本地 reachability JSON 证据。"""

    evidence_path = Path(path)
    try:
        text = evidence_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReachabilityEvidenceError(f"无法读取 reachability evidence：{path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReachabilityEvidenceError(f"reachability evidence 不是有效 JSON：{path}") from exc
    if not isinstance(data, dict):
        raise ReachabilityEvidenceError("reachability evidence 必须是 object")
    if data.get("schema_version") != 1:
        raise ReachabilityEvidenceError("reachability evidence schema_version 必须是 1")
    records = data.get("assessments")
    if not isinstance(records, list):
        raise ReachabilityEvidenceError("reachability evidence assessments 必须是 list")
    return tuple(_record_from_dict(item, evidence_path=evidence_path) for item in records)


def discover_flask_route_evidence(
    source_root: str | Path,
    *,
    taint_paths: tuple[TaintPath, ...],
) -> tuple[ReachabilityEvidenceRecord, ...]:
    """从本地 Python 源码中提取最小 Flask route 可触达证据。"""

    root = Path(source_root)
    if not root.exists():
        raise ReachabilityEvidenceError(f"source root 不存在：{source_root}")
    if not root.is_dir():
        raise ReachabilityEvidenceError(f"source root 必须是目录：{source_root}")

    records: list[ReachabilityEvidenceRecord] = []
    module_index = _python_modules_by_path(root)
    for taint_path in taint_paths:
        sink_location = taint_path.sink.signature.location
        if sink_location is None:
            continue
        route, call_chain_functions = _route_for_sink_location(
            module_index,
            sink_path=sink_location.path,
            sink_line=sink_location.start_line,
        )
        if route is None:
            continue
        records.append(
            _record_from_flask_route(
                taint_path,
                route,
                call_chain_functions=call_chain_functions,
                module_index=module_index,
                source_root=root,
            )
        )
    return tuple(records)


def generate_reachability_report(
    task: VulnerabilityInput,
    *,
    taint_report: TaintPathGenerationReport,
    evidence_records: tuple[ReachabilityEvidenceRecord, ...] = (),
) -> ReachabilityReport:
    """从候选 taint path 和本地证据生成可触达确认报告。"""

    report_evidence = (_task_evidence(task),)
    unknowns: list[str] = []

    if not taint_report.paths:
        unknowns.append("缺少 candidate taint path，无法进行可触达确认。")
        return ReachabilityReport(
            assessments=(),
            evidence=report_evidence,
            unknowns=tuple(unknowns),
        )
    if not evidence_records:
        unknowns.append("缺少本地 reachability evidence，所有路径保持 reachable=null。")

    assessments = tuple(
        _assess_path(path, evidence_records=evidence_records)
        for path in taint_report.paths
    )
    return ReachabilityReport(
        assessments=assessments,
        evidence=report_evidence,
        unknowns=tuple(dict.fromkeys(unknowns)),
    )


@dataclass(frozen=True)
class _FlaskRoute:
    path: str
    route: str
    methods: tuple[str, ...]
    function: _PythonFunction
    source_path: Path


@dataclass(frozen=True)
class _PythonCall:
    name: str
    owner: str | None
    lineno: int | None


@dataclass(frozen=True)
class _PythonFunction:
    path: str
    name: str
    function: _RouteFunction
    calls: tuple[_PythonCall, ...]


@dataclass(frozen=True)
class _ImportedFunction:
    local_name: str
    target_path: str
    target_name: str


@dataclass(frozen=True)
class _ImportedModule:
    local_name: str
    target_path: str


@dataclass(frozen=True)
class _PythonModule:
    path: str
    source_path: Path
    tree: ast.Module
    routes: tuple[_FlaskRoute, ...]
    functions: tuple[_PythonFunction, ...]
    imported_functions: tuple[_ImportedFunction, ...]
    imported_modules: tuple[_ImportedModule, ...]


def _python_modules_by_path(root: Path) -> dict[str, _PythonModule]:
    modules: dict[str, _PythonModule] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        functions = tuple(
            _python_function_from_ast(node, relative=relative)
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        )
        imported_functions = _imported_functions_from_ast(tree, relative=relative)
        imported_modules = _imported_modules_from_ast(tree, relative=relative)
        routes: list[_FlaskRoute] = []
        for function in functions:
            route = _route_from_function(function, relative=relative, source_path=path)
            if route is None:
                continue
            routes.append(route)
        modules[relative] = _PythonModule(
            path=relative,
            source_path=path,
            tree=tree,
            routes=tuple(routes),
            functions=functions,
            imported_functions=imported_functions,
            imported_modules=imported_modules,
        )
    return modules


def _python_function_from_ast(function: _RouteFunction, *, relative: str) -> _PythonFunction:
    return _PythonFunction(
        path=relative,
        name=function.name,
        function=function,
        calls=tuple(
            _PythonCall(name=call_name, owner=call_owner, lineno=call_lineno)
            for call_name, call_owner, call_lineno in _direct_name_calls(function)
        ),
    )


def _imported_functions_from_ast(
    tree: ast.Module,
    *,
    relative: str,
) -> tuple[_ImportedFunction, ...]:
    imports: list[_ImportedFunction] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        target_path = _import_from_target_path(node, relative=relative)
        if target_path is None:
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            imports.append(
                _ImportedFunction(
                    local_name=alias.asname or alias.name,
                    target_path=target_path,
                    target_name=alias.name,
                )
            )
    return tuple(imports)


def _imported_modules_from_ast(
    tree: ast.Module,
    *,
    relative: str,
) -> tuple[_ImportedModule, ...]:
    imports: list[_ImportedModule] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(_imported_modules_from_import(node))
            continue
        if isinstance(node, ast.ImportFrom):
            imports.extend(_imported_modules_from_import_from(node, relative=relative))
    return tuple(imports)


def _module_name_to_path(module_name: str) -> str | None:
    parts = [part for part in module_name.split(".") if part]
    if not parts:
        return None
    return "/".join(parts) + ".py"


def _imported_modules_from_import(node: ast.Import) -> tuple[_ImportedModule, ...]:
    imports: list[_ImportedModule] = []
    for alias in node.names:
        target_path = _module_name_to_path(alias.name)
        if target_path is None:
            continue
        local_name = alias.asname or alias.name.rsplit(".", 1)[-1]
        imports.append(
            _ImportedModule(
                local_name=local_name,
                target_path=target_path,
            )
        )
    return tuple(imports)


def _imported_modules_from_import_from(
    node: ast.ImportFrom,
    *,
    relative: str,
) -> tuple[_ImportedModule, ...]:
    base_path = _import_from_target_path(node, relative=relative)
    if base_path is None:
        return ()
    package_path = base_path.removesuffix(".py")
    imports: list[_ImportedModule] = []
    for alias in node.names:
        if alias.name == "*":
            continue
        local_name = alias.asname or alias.name
        imports.append(
            _ImportedModule(
                local_name=local_name,
                target_path=f"{package_path}/{alias.name}.py",
            )
        )
    return tuple(imports)


def _import_from_target_path(node: ast.ImportFrom, *, relative: str) -> str | None:
    module_parts = [part for part in (node.module or "").split(".") if part]
    relative_parts = relative.removesuffix(".py").split("/")
    package_parts = relative_parts[:-1]

    if node.level:
        if node.level > len(package_parts) + 1:
            return None
        anchor_parts = package_parts[: len(package_parts) - (node.level - 1)]
        resolved_parts = [*anchor_parts, *module_parts]
    else:
        resolved_parts = module_parts

    if not resolved_parts:
        return None
    return "/".join(resolved_parts) + ".py"


def _route_from_function(
    function: _PythonFunction,
    *,
    relative: str,
    source_path: Path,
) -> _FlaskRoute | None:
    for decorator in function.function.decorator_list:
        route = _route_from_decorator(decorator)
        if route is None:
            continue
        route_path, methods = route
        return _FlaskRoute(
            path=relative,
            route=route_path,
            methods=methods,
            function=function,
            source_path=source_path,
        )
    return None


def _route_for_sink_location(
    module_index: dict[str, _PythonModule],
    *,
    sink_path: str,
    sink_line: int | None,
) -> tuple[_FlaskRoute | None, tuple[_PythonFunction, ...]]:
    module = module_index.get(sink_path)
    if module is None:
        return None, ()
    sink_function = next(
        (
            function
            for function in module.functions
            if _line_within(sink_line, function.function)
        ),
        None,
    )
    if sink_function is None:
        return None, ()
    for candidate_module in module_index.values():
        for route in candidate_module.routes:
            call_chain = _call_chain_to_function(
                candidate_module,
                route.function,
                sink_function,
                module_index=module_index,
                remaining_hops=_MAX_FLASK_HELPER_HOPS,
            )
            if call_chain is not None:
                return route, call_chain
    return None, ()


def _call_chain_to_function(
    module: _PythonModule,
    function: _PythonFunction,
    target: _PythonFunction,
    *,
    module_index: dict[str, _PythonModule],
    remaining_hops: int,
    visited: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[_PythonFunction, ...] | None:
    function_ref = (function.path, function.name)
    if function_ref in visited:
        return None
    if function.path == target.path and function.name == target.name:
        return (function,)
    if remaining_hops <= 0:
        return None

    next_visited = visited | {function_ref}
    for called_function in _direct_called_functions(
        module,
        function,
        module_index=module_index,
    ):
        called_module = module_index.get(called_function.path)
        if called_module is None:
            continue
        sub_chain = _call_chain_to_function(
            called_module,
            called_function,
            target,
            module_index=module_index,
            remaining_hops=remaining_hops - 1,
            visited=next_visited,
        )
        if sub_chain is not None:
            return (function, *sub_chain)
    return None


def _direct_called_functions(
    module: _PythonModule,
    function: _PythonFunction,
    *,
    module_index: dict[str, _PythonModule],
) -> tuple[_PythonFunction, ...]:
    called_functions: list[_PythonFunction] = []
    for call in function.calls:
        resolved = _resolve_called_function(
            module,
            call,
            module_index=module_index,
        )
        if resolved is None:
            continue
        called_functions.append(resolved)
    return tuple(called_functions)


def _resolve_called_function(
    module: _PythonModule,
    call: _PythonCall,
    *,
    module_index: dict[str, _PythonModule],
) -> _PythonFunction | None:
    if call.owner is None:
        local_function = next(
            (function for function in module.functions if function.name == call.name),
            None,
        )
        if local_function is not None:
            return local_function

        imported_function = next(
            (
                candidate
                for candidate in module.imported_functions
                if candidate.local_name == call.name
            ),
            None,
        )
        if imported_function is None:
            return None
        imported_module = module_index.get(imported_function.target_path)
        if imported_module is None:
            return None
        return next(
            (
                function
                for function in imported_module.functions
                if function.name == imported_function.target_name
            ),
            None,
        )

    imported_module_ref = next(
        (
            candidate
            for candidate in module.imported_modules
            if candidate.local_name == call.owner
        ),
        None,
    )
    if imported_module_ref is None:
        return None
    imported_module = module_index.get(imported_module_ref.target_path)
    if imported_module is None:
        return None
    return next(
        (
            function
            for function in imported_module.functions
            if function.name == call.name
        ),
        None,
    )


def _direct_name_calls(function: _RouteFunction) -> tuple[tuple[str, str | None, int | None], ...]:
    calls: list[tuple[str, str | None, int | None]] = []
    for statement in function.body:
        calls.extend(_name_calls_in_node(statement))
    return tuple(calls)


def _name_calls_in_node(node: ast.AST) -> list[tuple[str, str | None, int | None]]:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
        return []
    calls: list[tuple[str, str | None, int | None]] = []
    if isinstance(node, ast.Call):
        call = _call_target_from_ast(node)
        if call is not None:
            calls.append(call)
    for child in ast.iter_child_nodes(node):
        calls.extend(_name_calls_in_node(child))
    return calls


def _call_target_from_ast(node: ast.Call) -> tuple[str, str | None, int | None] | None:
    if isinstance(node.func, ast.Name):
        return node.func.id, None, getattr(node, "lineno", None)
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    ):
        return node.func.attr, node.func.value.id, getattr(node, "lineno", None)
    return None


def _route_from_decorator(decorator: ast.expr) -> tuple[str, tuple[str, ...]] | None:
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute) or func.attr != "route":
        return None
    if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
        return None
    route_path = decorator.args[0].value
    if not isinstance(route_path, str):
        return None
    methods = _methods_from_decorator(decorator)
    return route_path, methods


def _methods_from_decorator(decorator: ast.Call) -> tuple[str, ...]:
    for keyword in decorator.keywords:
        if keyword.arg != "methods":
            continue
        value = keyword.value
        if not isinstance(value, ast.List | ast.Tuple):
            continue
        methods = []
        for item in value.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                methods.append(item.value.upper())
        return tuple(methods) or ("GET",)
    return ("GET",)


def _record_from_flask_route(
    taint_path: TaintPath,
    route: _FlaskRoute,
    *,
    call_chain_functions: tuple[_PythonFunction, ...],
    module_index: dict[str, _PythonModule],
    source_root: Path,
) -> ReachabilityEvidenceRecord:
    decorator_line = route.function.function.decorator_list[0].lineno
    entrypoint_location = CodeLocation(path=route.path, start_line=decorator_line)
    route_function_name = route.function.name
    sink_location = taint_path.sink.signature.location
    method = route.methods[0] if route.methods else "GET"
    sink_symbol = _sink_step_symbol(taint_path)
    helper_names = [function.name for function in call_chain_functions[1:]]
    helper_paths = [function.path for function in call_chain_functions[1:]]
    helper_scope = (
        "same_file"
        if helper_paths and all(path == route.path for path in helper_paths)
        else "cross_file"
        if helper_paths
        else "handler"
    )
    helper_inspect_paths = tuple(
        dict.fromkeys(
            str(source_root / function.path)
            for function in call_chain_functions[1:]
            if function.path != route.path
        )
    )
    source_control = _source_control_assessment(
        taint_path,
        source_root=source_root,
        module_index=module_index,
    )
    evidence = (
        Evidence(
            source=SourceReference(
                kind=EvidenceKind.REACHABILITY_EVIDENCE,
                uri=str(route.source_path),
                location=entrypoint_location,
                metadata={
                    "framework": "flask",
                    "source_root": str(source_root),
                    "call_chain_functions": [function.name for function in call_chain_functions],
                    "call_chain_paths": [function.path for function in call_chain_functions],
                },
            ),
            summary=_flask_route_summary(
                method=method,
                route_path=route.route,
                route_function_name=route_function_name,
                helper_names=helper_names,
            ),
            reasoning=_flask_route_reasoning(helper_names, helper_scope=helper_scope),
            confidence=0.7,
            reproducible_steps=(
                f"inspect {route.source_path}",
                *tuple(f"inspect {path}" for path in helper_inspect_paths),
            ),
        ),
    )
    return ReachabilityEvidenceRecord(
        path_match={
            "source_name": taint_path.source.name,
            "sink_name": _normalize_call_name(taint_path.sink.signature.name),
            "sink": {
                "path": sink_location.path if sink_location else route.path,
                "start_line": sink_location.start_line if sink_location else None,
            },
        },
        reachable=True,
        entrypoint=ReachabilityEntrypoint(
            kind="flask_route",
            name=f"{method} {route.route}",
            location=entrypoint_location,
            evidence=evidence,
        ),
        call_chain=(
            *tuple(
                ReachabilityCallStep(
                    symbol=function.name,
                    location=CodeLocation(
                        path=function.path,
                        start_line=function.function.lineno,
                    ),
                    evidence=evidence,
                )
                for function in call_chain_functions
            ),
            ReachabilityCallStep(
                symbol=sink_symbol,
                location=sink_location,
                evidence=evidence,
            ),
        ),
        source_control=source_control,
        evidence=evidence,
        unknowns=("尚未运行 PoC 验证该 Flask route 的触发行为。",),
    )


def _flask_route_summary(
    *,
    method: str,
    route_path: str,
    route_function_name: str,
    helper_names: list[str],
) -> str:
    if not helper_names:
        return f"Flask route {method} {route_path} 作为入口调用 {route_function_name}。"
    helper_path = " -> ".join(helper_names)
    return (
        f"Flask route {method} {route_path} 作为入口调用 {route_function_name}，"
        f"并继续进入 {helper_path}。"
    )


def _flask_route_reasoning(helper_names: list[str], *, helper_scope: str) -> str:
    if not helper_names:
        return (
            "该入口由本地 Python AST 从 @*.route(...) 装饰器提取，"
            "sink 位于该 handler 函数体内。"
        )
    helper_path = " -> ".join(helper_names)
    if helper_scope == "same_file":
        helper_reason = f"route handler 在同文件内通过局部 helper chain 调用 {helper_path}，"
    else:
        helper_reason = f"route handler 通过 import 解析和局部 helper chain 调用 {helper_path}，"
    return (
        "该入口由本地 Python AST 从 @*.route(...) 装饰器提取，"
        + helper_reason
        + "且 sink 位于该局部调用链到达的函数体内。"
    )


def _line_within(line: int | None, function: _RouteFunction) -> bool:
    if line is None:
        return False
    end_line = function.end_lineno or function.lineno
    return function.lineno <= line <= end_line


def _sink_step_symbol(taint_path: TaintPath) -> str:
    sink_steps = [step for step in taint_path.steps if step.role and step.role.value == "sink"]
    if sink_steps and sink_steps[-1].symbol:
        return sink_steps[-1].symbol
    return taint_path.sink.signature.raw


def _source_control_assessment(
    taint_path: TaintPath,
    *,
    source_root: Path,
    module_index: dict[str, _PythonModule],
) -> SourceControlAssessment:
    if _source_name_looks_request_controlled(taint_path.source.name):
        source_evidence = _source_name_evidence(
            taint_path,
            _source_path_for_evidence(taint_path, source_root),
        )
        return SourceControlAssessment(
            controlled=True,
            reason="source 名称直接指向 Flask request 对象。",
            evidence=(source_evidence,),
        )

    source_location = taint_path.source.location
    if source_location is not None:
        module = module_index.get(source_location.path)
        if module is not None:
            ast_evidence = _source_ast_evidence(
                taint_path,
                module=module,
                source_root=source_root,
            )
            if ast_evidence is not None:
                return SourceControlAssessment(
                    controlled=True,
                    reason="source.location 对应的本地赋值语句直接读取 Flask request 对象。",
                    evidence=(ast_evidence,),
                )

    source_evidence = _source_name_evidence(
        taint_path,
        _source_path_for_evidence(taint_path, source_root),
    )
    return SourceControlAssessment(
        controlled=None,
        reason="当前本地证据不足以确认 source 是否直接受 Flask request 控制。",
        evidence=(source_evidence,),
    )


def _source_name_looks_request_controlled(source_name: str) -> bool:
    return "request." in source_name


def _source_path_for_evidence(taint_path: TaintPath, source_root: Path) -> Path:
    source_location = taint_path.source.location
    if source_location is None:
        return source_root
    return source_root / source_location.path


def _source_name_evidence(taint_path: TaintPath, source_path: Path) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(source_path),
            location=taint_path.source.location,
        ),
        summary=f"source {taint_path.source.name} 的可控性先按名称和位置做本地检查。",
        reasoning=(
            "当前先检查 source 名称是否直接指向 request，"
            "再按 source.location 读取本地赋值语句。"
        ),
        confidence=0.45,
        reproducible_steps=(f"inspect {source_path}",),
        open_questions=("需要后续确认具体参数是否可由攻击者控制。",),
    )


def _source_ast_evidence(
    taint_path: TaintPath,
    *,
    module: _PythonModule,
    source_root: Path,
) -> Evidence | None:
    source_location = taint_path.source.location
    if source_location is None:
        return None
    assignment = _assignment_for_source_location(
        module.tree,
        source_name=taint_path.source.name,
        line=source_location.start_line,
    )
    if assignment is None:
        return None
    value = _assignment_value(assignment)
    if value is None or not _is_request_controlled_expr(value):
        return None
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(module.source_path),
            location=source_location,
            metadata={
                "framework": "flask",
                "source_root": str(source_root),
                "evidence_type": "source_assignment_ast",
            },
        ),
        summary=(
            f"source {taint_path.source.name} 在 "
            f"{source_location.path}:{source_location.start_line} "
            "的赋值语句中直接读取 Flask request 对象。"
        ),
        reasoning=(
            "当前本地 AST 证据只检查 source.location 对应赋值语句，"
            "并确认其是否直接来自 request.args/form/values/json 等字段。"
        ),
        confidence=0.8,
        reproducible_steps=(f"inspect {module.source_path}",),
        open_questions=("尚未跨语句跟踪赋值传播或 wrapper 封装。",),
    )


def _assignment_for_source_location(
    tree: ast.Module,
    *,
    source_name: str,
    line: int | None,
) -> ast.Assign | ast.AnnAssign | ast.NamedExpr | None:
    if line is None:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign | ast.NamedExpr):
            continue
        if not _node_spans_line(node, line):
            continue
        if not _assignment_targets_name(node, source_name):
            continue
        return node
    return None


def _node_spans_line(node: ast.AST, line: int) -> bool:
    start_line = getattr(node, "lineno", None)
    if start_line is None:
        return False
    end_line = getattr(node, "end_lineno", start_line)
    return start_line <= line <= end_line


def _assignment_targets_name(
    node: ast.Assign | ast.AnnAssign | ast.NamedExpr,
    source_name: str,
) -> bool:
    if isinstance(node, ast.Assign):
        return any(_target_contains_name(target, source_name) for target in node.targets)
    if isinstance(node, ast.AnnAssign):
        return _target_contains_name(node.target, source_name)
    return _target_contains_name(node.target, source_name)


def _target_contains_name(target: ast.expr, source_name: str) -> bool:
    return isinstance(target, ast.Name) and target.id == source_name


def _assignment_value(node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> ast.expr | None:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    return node.value


def _is_request_controlled_expr(node: ast.AST) -> bool:
    if _is_request_field(node):
        return True
    if isinstance(node, ast.Subscript):
        return _is_request_field(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and _is_request_field(node.func.value):
            return True
        return _is_request_controlled_expr(node.func)
    if isinstance(node, ast.BoolOp):
        return any(_is_request_controlled_expr(value) for value in node.values)
    if isinstance(node, ast.IfExp):
        return any(
            _is_request_controlled_expr(value)
            for value in (node.test, node.body, node.orelse)
        )
    if isinstance(node, ast.Compare):
        return _is_request_controlled_expr(node.left) or any(
            _is_request_controlled_expr(comparator) for comparator in node.comparators
        )
    if isinstance(node, ast.UnaryOp):
        return _is_request_controlled_expr(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_request_controlled_expr(node.left) or _is_request_controlled_expr(
            node.right
        )
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_is_request_controlled_expr(value) for value in node.elts)
    if isinstance(node, ast.Dict):
        return any(
            _is_request_controlled_expr(value)
            for value in (*node.keys, *node.values)
            if value is not None
        )
    if isinstance(node, ast.NamedExpr):
        return _is_request_controlled_expr(node.value)
    if isinstance(node, ast.Attribute):
        return _is_request_controlled_expr(node.value)
    if isinstance(node, ast.Expr):
        return _is_request_controlled_expr(node.value)
    return False


def _is_request_field(node: ast.AST) -> bool:
    if not isinstance(node, ast.Attribute):
        return False
    if not isinstance(node.value, ast.Name):
        return False
    return node.value.id == "request" and node.attr in _FLASK_REQUEST_FIELDS


def _record_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityEvidenceRecord:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("reachability assessment 必须是 object")
    path_match = item.get("path_match")
    if not isinstance(path_match, dict):
        raise ReachabilityEvidenceError("reachability assessment.path_match 必须是 object")
    reachable = item.get("reachable")
    if reachable not in {True, False, None}:
        raise ReachabilityEvidenceError("reachability assessment.reachable 必须是 true/false/null")
    entrypoint = _entrypoint_from_dict(item.get("entrypoint"), evidence_path=evidence_path)
    call_chain = tuple(
        _call_step_from_dict(step, evidence_path=evidence_path)
        for step in _optional_list(item, "call_chain")
    )
    source_control = _source_control_from_dict(
        item.get("source_control"),
        evidence_path=evidence_path,
    )
    blocking_factors = tuple(
        _blocking_factor_from_dict(factor, evidence_path=evidence_path)
        for factor in _optional_list(item, "blocking_factors")
    )
    evidence = tuple(
        _evidence_from_dict(evidence_item, evidence_path=evidence_path)
        for evidence_item in _optional_list(item, "evidence")
    )
    unknowns = tuple(_str_list(item, "unknowns"))
    return ReachabilityEvidenceRecord(
        path_match=path_match,
        reachable=reachable,
        entrypoint=entrypoint,
        call_chain=call_chain,
        source_control=source_control,
        blocking_factors=blocking_factors,
        evidence=evidence,
        unknowns=unknowns,
    )


def _assess_path(
    path: TaintPath,
    *,
    evidence_records: tuple[ReachabilityEvidenceRecord, ...],
) -> ReachabilityAssessment:
    record = next(
        (candidate for candidate in evidence_records if _matches_path(path, candidate.path_match)),
        None,
    )
    if record is None:
        return ReachabilityAssessment(
            path=_path_with_reachability(path, None),
            reachable=None,
            unknowns=("未找到匹配该 taint path 的本地 reachability evidence。",),
        )
    evidence = (
        *record.evidence,
        _assessment_evidence(record),
    )
    return ReachabilityAssessment(
        path=_path_with_reachability(path, record.reachable),
        reachable=record.reachable,
        entrypoint=record.entrypoint,
        call_chain=record.call_chain,
        source_control=record.source_control,
        blocking_factors=record.blocking_factors,
        evidence=evidence,
        unknowns=record.unknowns,
    )


def _path_with_reachability(path: TaintPath, reachable: bool | None) -> TaintPath:
    return TaintPath(
        source=path.source,
        sink=path.sink,
        steps=path.steps,
        reachable=reachable,
        evidence=path.evidence,
    )


def _matches_path(path: TaintPath, path_match: dict[str, Any]) -> bool:
    if "source_name" in path_match and path.source.name != path_match["source_name"]:
        return False
    if "sink_name" in path_match and _normalize_call_name(
        path.sink.signature.name
    ) != _normalize_call_name(path_match["sink_name"]):
        return False
    source = path_match.get("source")
    if isinstance(source, dict) and not _location_matches(path.source.location, source):
        return False
    sink = path_match.get("sink")
    if isinstance(sink, dict) and not _location_matches(path.sink.signature.location, sink):
        return False
    return True


def _location_matches(actual: CodeLocation | None, expected: dict[str, Any]) -> bool:
    if actual is None:
        return False
    if "path" in expected and actual.path != expected["path"]:
        return False
    if "start_line" in expected and actual.start_line != expected["start_line"]:
        return False
    return True


def _entrypoint_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityEntrypoint | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("entrypoint 必须是 object")
    kind = _required_str(item, "kind")
    name = _required_str(item, "name")
    location = _location_from_dict(item.get("location"))
    return ReachabilityEntrypoint(
        kind=kind,
        name=name,
        location=location,
        evidence=(_auto_evidence(f"入口证据：{name}", evidence_path, location),),
    )


def _call_step_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> ReachabilityCallStep:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("call_chain[] 必须是 object")
    symbol = _required_str(item, "symbol")
    location = _location_from_dict(item.get("location"))
    return ReachabilityCallStep(
        symbol=symbol,
        location=location,
        evidence=(_auto_evidence(f"调用链节点：{symbol}", evidence_path, location),),
    )


def _source_control_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> SourceControlAssessment | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("source_control 必须是 object")
    controlled = item.get("controlled")
    if controlled not in {True, False, None}:
        raise ReachabilityEvidenceError("source_control.controlled 必须是 true/false/null")
    reason = _required_str(item, "reason")
    return SourceControlAssessment(
        controlled=controlled,
        reason=reason,
        evidence=(_auto_evidence(f"source 可控性：{reason}", evidence_path, None),),
    )


def _blocking_factor_from_dict(
    item: Any,
    *,
    evidence_path: Path,
) -> BlockingFactor:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("blocking_factors[] 必须是 object")
    kind = _required_str(item, "kind")
    summary = _required_str(item, "summary")
    location = _location_from_dict(item.get("location"))
    return BlockingFactor(
        kind=kind,
        summary=summary,
        location=location,
        evidence=(_auto_evidence(f"阻断因素：{summary}", evidence_path, location),),
    )


def _evidence_from_dict(item: Any, *, evidence_path: Path) -> Evidence:
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("evidence[] 必须是 object")
    summary = _required_str(item, "summary")
    reasoning = _required_str(item, "reasoning")
    confidence = item.get("confidence", 0.6)
    if not isinstance(confidence, int | float):
        raise ReachabilityEvidenceError("evidence[].confidence 必须是 number")
    location = _location_from_dict(item.get("location"))
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(evidence_path),
            location=location,
        ),
        summary=summary,
        reasoning=reasoning,
        confidence=float(confidence),
        reproducible_steps=(f"inspect {evidence_path}",),
    )


def _assessment_evidence(record: ReachabilityEvidenceRecord) -> Evidence:
    state = "unknown" if record.reachable is None else str(record.reachable).lower()
    open_questions = record.unknowns
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            metadata={
                "reachable": record.reachable,
                "path_match": record.path_match,
            },
        ),
        summary=f"本地 reachability evidence 给出 reachable={state}。",
        reasoning=(
            "该结论来自本地结构化证据，只表示 M2 静态可触达确认，"
            "不表示 PoC 已触发或漏洞已验证。"
        ),
        confidence=0.7 if record.reachable is True else 0.6,
        open_questions=open_questions,
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
        summary="漏洞描述作为可触达确认任务的语义输入。",
        reasoning="可触达确认必须由入口、调用链、阻断因素和路径证据锚定。",
        confidence=0.3,
        open_questions=("需要确认该静态可触达判断是否足以支撑后续 PoC。",),
    )


def _auto_evidence(
    summary: str,
    evidence_path: Path,
    location: CodeLocation | None,
) -> Evidence:
    return Evidence(
        source=SourceReference(
            kind=EvidenceKind.REACHABILITY_EVIDENCE,
            uri=str(evidence_path),
            location=location,
        ),
        summary=summary,
        reasoning="该证据来自本地 reachability evidence JSON。",
        confidence=0.6,
        reproducible_steps=(f"inspect {evidence_path}",),
    )


def _location_from_dict(item: Any) -> CodeLocation | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ReachabilityEvidenceError("location 必须是 object")
    path = _required_str(item, "path")
    return CodeLocation(
        path=path,
        start_line=_optional_int(item, "start_line"),
        start_col=_optional_int(item, "start_col"),
        end_line=_optional_int(item, "end_line"),
        end_col=_optional_int(item, "end_col"),
    )


def _optional_list(data: dict[str, Any], field: str) -> list[Any]:
    value = data.get(field, [])
    if not isinstance(value, list):
        raise ReachabilityEvidenceError(f"{field} 必须是 list")
    return value


def _str_list(data: dict[str, Any], field: str) -> list[str]:
    items = _optional_list(data, field)
    if not all(isinstance(item, str) for item in items):
        raise ReachabilityEvidenceError(f"{field} 必须是 string list")
    return items


def _required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise ReachabilityEvidenceError(f"{field} 必须是非空字符串")
    return value


def _optional_int(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, int):
        raise ReachabilityEvidenceError(f"{field} 必须是整数")
    return value


def _normalize_call_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return value.strip().split(".")[-1].split("(", maxsplit=1)[0].lower()
