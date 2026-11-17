"""Deterministic Python AST index for one snapshot side.

The index is built in two passes over every Python file whose text was captured
in the snapshot (``SnapshotSide.contents``):

1. modules, symbols, lexical scopes and name bindings are collected;
2. calls and imports are resolved against the complete symbol table.

Only standard library modules are used; no repository code is imported or
executed.  The public contract lives in ``docs/CONTRACTS.md`` section 3.

Resolution scope (P0 + P1)
--------------------------

Resolved call forms (all other forms are recorded as *unresolved* edges so the
coverage statistics stay honest -- the index never guesses a target):

* a unique top-level function of the same module, called by bare name, when no
  binding shadows the name on the call-site scope chain;
* ``from pkg.mod import fn as alias`` followed by ``alias()`` (also relative
  imports that resolve inside a regular package);
* ``import pkg.mod as mod`` followed by ``mod.fn()`` (exactly one attribute).

P1 adds a bounded method/constructor dispatch layer.  Every resolved edge below
carries the assumption in ``reason`` so consumers can tell the rules apart:

* ``self.method()`` / ``cls.method()`` in a method body, when the owning class
  defines the method exactly once (``reason="self_method_unique"``);
* ``C.method()``, ``mod.C.method()`` or ``cls.method()`` when ``C`` uniquely
  resolves to a class (module-level definition, ``from`` import or
  ``import ... as mod`` attribute) and the class defines the method exactly once
  (``reason="explicit_class"``);
* ``obj.method()`` where ``obj`` is bound by one unconditional simple
  assignment ``obj = C(...)`` in the same function body and never rebound
  (``reason="constructor_binding"``);
* ``C()`` class instantiation, resolving to the class symbol itself
  (``reason="class_instantiation"``) so class definition changes can be traced
  to their instantiation sites.

The P1 additions are still strictly bounded: attribute chains longer than one
receiver segment, ``super()``, dynamic imports, factory/return values,
lambdas, callbacks, ``self.attr`` receiver mutations and ambiguous or rebound
names stay ``unresolved``.

Global reads (P1)
-----------------

Module-scope ``Assign``/``AnnAssign``/``AugAssign`` statements with ``Name``
targets are recorded as :class:`ModuleAssignment` spans.  A ``Name`` load inside
a function/method body that resolves through the scope chain to such a
module-level binding (and is not shadowed by any local/parameter/class binding)
produces a ``CallEdge`` with ``edge_kind=EDGE_GLOBAL_READ`` whose ``callee_id``
is the module pseudo symbol and ``target`` is the variable name.  Module top
level reads never produce a global-read edge.  ``Index.global_names_at`` exposes
the assignment spans for ``changes.map_symbol_changes``.

Everything else -- parameters/local assignments/loop targets shadowing a name,
conditional imports, duplicate definitions, nested local functions, local
imports, ``super()``, attribute chains longer than one segment, ambiguous
classes/methods, factory return values, lambdas and other computed callees,
dynamic imports, re-exports and external modules -- produces a ``CallEdge``
with ``resolution="unresolved"``, ``callee_id=None`` and a ``reason`` such as
``shadowed``, ``local_binding``, ``conditional_import``, ``nested_local``,
``ambiguous_definition``, ``dynamic_method``, ``attribute``,
``class_instantiation``, ``reassigned``, ``unsupported_expression``,
``dynamic_import``, ``external_module`` or ``unresolved_module``.

The module is intentionally read-only and deterministic: the same snapshot side
and configuration always produce the same symbols, edges, diagnostics and
digests.  :meth:`Index.to_cache_dict` / :meth:`Index.from_cache_dict` persist and
restore the complete index without keeping any AST node alive.
"""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import models
from .config import Config
from .models import (
    EDGE_CALL,
    EDGE_GLOBAL_READ,
    EDGE_IMPORT,
    SYMBOL_ASYNC_FUNCTION,
    SYMBOL_CLASS,
    SYMBOL_FUNCTION,
    SYMBOL_METHOD,
    SYMBOL_MODULE,
    SYMBOL_NESTED_FUNCTION,
    CallEdge,
    Diagnostic,
    SnapshotSide,
    Symbol,
    diag,
    module_symbol_id,
    sha256_text,
    source_lines,
    symbol_id as make_symbol_id,
)

__all__ = ["Index", "ModuleAssignment", "ModuleInfo", "build_index"]

RESOLVED = "resolved"
UNRESOLVED = "unresolved"

#: Version of the ``to_cache_dict`` payload.  Callers key their cache entries
#: with the analyzer/schema versions; a payload with a different format version
#: is rejected with ``ValueError`` instead of being misread.
CACHE_FORMAT_VERSION = 2

_STATS_KEYS = (
    "symbols",
    "resolved_calls",
    "unresolved_calls",
    "imports_resolved",
    "imports_unresolved",
    "python_files_indexed",
    "python_bytes_indexed",
    "global_reads",
)

_EDGE_KINDS = frozenset({EDGE_CALL, EDGE_IMPORT, EDGE_GLOBAL_READ})
_RESOLUTIONS = frozenset({RESOLVED, UNRESOLVED})

_TEST_FILE_RE = re.compile(r"^(?:test_.*\.py|.*_test\.py)$")
_CALLABLE_KINDS = frozenset({SYMBOL_FUNCTION, SYMBOL_ASYNC_FUNCTION})
_TOP_SYMBOL_KINDS = frozenset(
    {SYMBOL_FUNCTION, SYMBOL_ASYNC_FUNCTION, SYMBOL_CLASS}
)
#: import binding outcome failures that still identify a module-ish base.
_MODULE_REASONS = frozenset(
    {
        "conditional_import",
        "ambiguous_definition",
        "local_binding",
        "external_module",
        "unresolved_module",
        "not_importable",
        "duplicate_module",
    }
)

_TRY_TYPES: tuple[type[ast.AST], ...] = (ast.Try,)
if hasattr(ast, "TryStar"):  # pragma: no branch - Python >= 3.11
    _TRY_TYPES = (ast.Try, ast.TryStar)


# --------------------------------------------------------------------------
# public data model
# --------------------------------------------------------------------------


@dataclass
class ModuleInfo:
    """Module identity resolved from a repository-relative Python path."""

    name: str
    path: str
    symbol_id: str
    importable: bool = True
    package_root: str | None = None


@dataclass
class ModuleAssignment:
    """One module-scope assignment binding (P1 global-read tracking).

    ``line``/``end_line`` are the 1-based inclusive span of the assignment
    statement, so callers can map changed source lines back to the module-level
    variable names they touched.
    """

    name: str
    line: int
    end_line: int


# --------------------------------------------------------------------------
# internal data model
# --------------------------------------------------------------------------


@dataclass
class _ImportSpec:
    """One imported binding plus the module dependency it represents."""

    kind: str  # "import" | "from"
    level: int
    module: str | None
    imported: str | None
    bound_name: str
    node: ast.AST
    line: int
    col: int
    conditional: bool
    is_module_level: bool
    target_text: str = ""
    bound_module: str | None = None
    resolved_module: str | None = None
    resolved_info: ModuleInfo | None = None
    bound_info: ModuleInfo | None = None
    target_kind: str | None = None  # "function" | "class" | "module" | "star"
    symbol_id: str | None = None
    failure: str | None = None


@dataclass
class _Binding:
    name: str
    kind: str  # def | class | param | assign | for | with | except | import
    line: int
    conditional: bool = False
    symbol_id: str | None = None
    symbol_kind: str | None = None
    import_spec: _ImportSpec | None = None
    # P1: the assigned expression for a single simple ``name = expression``
    # binding; used by the bounded constructor-binding rule.
    value: ast.AST | None = None


class _Scope:
    """One lexical scope: module, class, function, lambda or comprehension."""

    __slots__ = (
        "kind",
        "parent",
        "owner_symbol",
        "bindings",
        "global_names",
        "nonlocal_names",
        "star_import",
    )

    def __init__(
        self,
        kind: str,
        parent: "_Scope | None",
        owner_symbol: Symbol | None,
    ) -> None:
        self.kind = kind
        self.parent = parent
        self.owner_symbol = owner_symbol
        self.bindings: dict[str, list[_Binding]] = {}
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self.star_import = False


@dataclass
class _NameResult:
    """Outcome of resolving one bare name at a call site."""

    kind: str  # function | class | module | unresolved
    reason: str | None = None
    symbol: Symbol | None = None
    module_name: str | None = None
    module_info: ModuleInfo | None = None
    failure: str | None = None


@dataclass
class _FileState:
    path: str
    text: str
    module_info: ModuleInfo
    module_symbol: Symbol
    tree: ast.Module | None = None
    module_scope: _Scope | None = None
    symbols: list[Symbol] = field(default_factory=list)
    calls: list[tuple[ast.Call, _Scope]] = field(default_factory=list)
    name_loads: list[tuple[ast.Name, _Scope]] = field(default_factory=list)
    import_specs: list[_ImportSpec] = field(default_factory=list)
    module_import_specs: list[_ImportSpec] = field(default_factory=list)
    module_assignments: list[ModuleAssignment] = field(default_factory=list)
    attribute_mutations: set[tuple[str, str]] = field(default_factory=set)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _render_expression(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive, parsed trees always render
        return ""


def _render_from_target(level: int, module: str | None) -> str:
    if level:
        return "." * level + (module or "")
    return module or ""


def _normalize_source_root(root: str) -> str:
    value = (root or "").replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    value = value.strip("/")
    if value == ".":
        return ""
    return value


def _attribute_depth(node: ast.AST) -> int:
    depth = 0
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        depth += 1
        current = current.value
    return depth


def _iter_arguments(args: ast.arguments) -> list[ast.arg]:
    collected: list[ast.arg] = []
    collected.extend(args.posonlyargs)
    collected.extend(args.args)
    if args.vararg is not None:
        collected.append(args.vararg)
    collected.extend(args.kwonlyargs)
    if args.kwarg is not None:
        collected.append(args.kwarg)
    return collected


def _scan_declarations(
    node: ast.AST,
    global_names: set[str],
    nonlocal_names: set[str],
) -> None:
    if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ):
        return
    if isinstance(node, ast.Global):
        global_names.update(node.names)
        return
    if isinstance(node, ast.Nonlocal):
        nonlocal_names.update(node.names)
        return
    for child in ast.iter_child_nodes(node):
        _scan_declarations(child, global_names, nonlocal_names)


def _collect_declarations(stmts: list[ast.stmt], scope: _Scope) -> None:
    for stmt in stmts:
        _scan_declarations(stmt, scope.global_names, scope.nonlocal_names)


def _path_is_present(side: SnapshotSide, path: str) -> bool:
    if path in side.contents:
        return True
    entry = side.entries.get(path)
    return entry is not None and entry.status == "present"


def _missing_package_inits(
    side: SnapshotSide, root: str, rel_path: str
) -> list[str]:
    parent = posixpath.dirname(rel_path)
    if not parent:
        return []
    prefix = root + "/" if root else ""
    parts = parent.split("/")
    missing: list[str] = []
    for index in range(1, len(parts) + 1):
        init_path = prefix + "/".join(parts[:index]) + "/__init__.py"
        if not _path_is_present(side, init_path):
            missing.append(init_path)
    return missing


# --------------------------------------------------------------------------
# module name resolution
# --------------------------------------------------------------------------


def _resolve_module_info(
    side: SnapshotSide,
    config: Config,
    path: str,
) -> tuple[ModuleInfo, list[Diagnostic]]:
    """Resolve the module name (and importability) of one indexed path."""

    diagnostics: list[Diagnostic] = []
    roots: list[tuple[int, str, str]] = []
    for raw_root in config.files.source_roots:
        normalized = _normalize_source_root(raw_root)
        if normalized and path.startswith(normalized + "/"):
            roots.append((len(normalized), normalized, path[len(normalized) + 1 :]))
        elif not normalized:
            roots.append((0, normalized, path))
    roots.sort(key=lambda item: (-item[0], item[1]))

    fallback = path[:-3].replace("/", ".") if path.endswith(".py") else path.replace("/", ".")
    if not roots:
        diagnostics.append(
            diag(
                "not_importable",
                f"{path!r} is outside every configured source root; using fallback module name {fallback!r}",
                severity="info",
                path=path,
                details={"reason": "outside_source_roots", "module": fallback},
            )
        )
        return (
            ModuleInfo(name=fallback, path=path, symbol_id="", importable=False),
            diagnostics,
        )

    _, root, rel_path = roots[0]
    rel_no_ext = rel_path[:-3] if rel_path.endswith(".py") else rel_path
    parts = [part for part in rel_no_ext.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    name = ".".join(parts)
    package_root = root or "."

    if not name:
        diagnostics.append(
            diag(
                "not_importable",
                f"{path!r} does not yield a usable module name; using fallback {fallback!r}",
                severity="info",
                path=path,
                details={"reason": "empty_module_name", "module": fallback},
            )
        )
        return (
            ModuleInfo(
                name=fallback,
                path=path,
                symbol_id="",
                importable=False,
                package_root=package_root,
            ),
            diagnostics,
        )

    missing = _missing_package_inits(side, root, rel_path)
    if missing:
        diagnostics.append(
            diag(
                "namespace_package",
                f"{path!r} is not importable: missing package initializer(s) {', '.join(missing)}",
                severity="info",
                path=path,
                details={"module": name, "missing": missing},
            )
        )
        return (
            ModuleInfo(
                name=name,
                path=path,
                symbol_id="",
                importable=False,
                package_root=package_root,
            ),
            diagnostics,
        )

    return (
        ModuleInfo(name=name, path=path, symbol_id="", package_root=package_root),
        diagnostics,
    )


# --------------------------------------------------------------------------
# first pass: symbols, scopes, bindings
# --------------------------------------------------------------------------


class _Scanner:
    """First-pass walker for one module AST."""

    def __init__(self, index: "Index", state: _FileState, tree: ast.Module) -> None:
        self.index = index
        self.state = state
        self.tree = tree
        self.module_scope = state.module_scope or _Scope(
            "module", None, state.module_symbol
        )

    # -- entry point ------------------------------------------------------
    def run(self) -> None:
        for stmt in self.tree.body:
            self._walk(stmt, self.module_scope, False)

    # -- bindings ---------------------------------------------------------
    def _bind(self, scope: _Scope, binding: _Binding) -> None:
        target = scope
        if scope.kind in ("function", "lambda"):
            if binding.name in scope.global_names:
                target = self.module_scope
            elif binding.name in scope.nonlocal_names:
                parent = scope.parent
                while parent is not None and parent.kind not in ("function", "lambda"):
                    parent = parent.parent
                target = parent or self.module_scope
        target.bindings.setdefault(binding.name, []).append(binding)

    def _bind_target(
        self,
        target: ast.AST,
        scope: _Scope,
        conditional: bool,
        kind: str,
        *,
        value: ast.AST | None = None,
    ) -> None:
        if isinstance(target, ast.Name):
            self._bind(
                scope,
                _Binding(
                    name=target.id,
                    kind=kind,
                    line=getattr(target, "lineno", 0),
                    conditional=conditional,
                    value=value,
                ),
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, scope, conditional, kind)
            return
        if isinstance(target, ast.Starred):
            self._bind_target(target.value, scope, conditional, kind)
            return
        # Attribute / Subscript targets do not create local names but may
        # contain calls or other expressions that must be scanned.  Attribute
        # writes also act as potential monkey patches, which P0 never resolves.
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            self.state.attribute_mutations.add((target.value.id, target.attr))
        self._walk(target, scope, conditional)

    def _module_target_names(self, target: ast.AST, collected: list[str]) -> None:
        """Collect the ``Name`` targets of one module-scope assignment."""

        if isinstance(target, ast.Name):
            collected.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._module_target_names(element, collected)
        elif isinstance(target, ast.Starred):
            self._module_target_names(target.value, collected)

    def _record_module_assignments(self, node: ast.stmt) -> None:
        """Record the module-level variable spans bound by one statement."""

        names: list[str] = []
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._module_target_names(target, names)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            self._module_target_names(node.target, names)
        line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", None) or line
        for name in names:
            self.state.module_assignments.append(
                ModuleAssignment(name=name, line=line, end_line=end_line)
            )

    # -- definition symbols ----------------------------------------------
    def _define_symbol(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        scope: _Scope,
        *,
        is_async: bool,
        is_class: bool,
    ) -> Symbol:
        owner = scope.owner_symbol
        name = node.name
        if is_class:
            kind = SYMBOL_CLASS
        elif scope.kind == "module":
            kind = SYMBOL_ASYNC_FUNCTION if is_async else SYMBOL_FUNCTION
        elif scope.kind == "class":
            kind = SYMBOL_METHOD
        else:
            kind = SYMBOL_NESTED_FUNCTION

        prefix = owner.qualified_name if owner is not None else ""
        qualified_name = f"{prefix}.{name}" if prefix else name
        def_line = node.lineno
        decorators = getattr(node, "decorator_list", []) or []
        start_line = def_line
        decorator_start: int | None = None
        if decorators:
            decorator_start = min(decorator.lineno for decorator in decorators)
            start_line = min(start_line, decorator_start)
        end_line = node.end_lineno or def_line
        symbol_id = make_symbol_id(self.index.side, self.state.path, qualified_name, def_line)
        is_test = (
            not is_class
            and scope.kind == "module"
            and _TEST_FILE_RE.match(posixpath.basename(self.state.path)) is not None
            and name.startswith("test_")
        )
        symbol = Symbol(
            symbol_id=symbol_id,
            side=self.index.side,
            path=self.state.path,
            module=self.state.module_info.name,
            qualified_name=qualified_name,
            kind=kind,
            parent_id=owner.symbol_id if owner is not None else None,
            start_line=start_line,
            end_line=end_line,
            def_line=def_line,
            decorator_start=decorator_start,
            is_test=is_test,
        )
        self.index.symbols[symbol_id] = symbol
        self.index._symbol_nodes[symbol_id] = node
        self.state.symbols.append(symbol)
        self._bind(
            scope,
            _Binding(
                name=name,
                kind="class" if is_class else "def",
                line=def_line,
                symbol_id=symbol_id,
                symbol_kind=kind,
            ),
        )
        return symbol

    def _walk_outer_arguments(
        self, args: ast.arguments, scope: _Scope, conditional: bool
    ) -> None:
        for arg in _iter_arguments(args):
            if arg.annotation is not None:
                self._walk(arg.annotation, scope, conditional)
        for default in args.defaults:
            self._walk(default, scope, conditional)
        for default in args.kw_defaults:
            if default is not None:
                self._walk(default, scope, conditional)

    def _handle_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: _Scope,
        conditional: bool,
    ) -> None:
        symbol = self._define_symbol(
            node,
            scope,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_class=False,
        )
        for decorator in node.decorator_list:
            self._walk(decorator, scope, conditional)
        self._walk_outer_arguments(node.args, scope, conditional)
        if node.returns is not None:
            self._walk(node.returns, scope, conditional)
        for type_param in getattr(node, "type_params", []) or []:
            self._walk(type_param, scope, conditional)

        inner = _Scope("function", scope, symbol)
        for arg in _iter_arguments(node.args):
            inner.bindings.setdefault(arg.arg, []).append(
                _Binding(
                    name=arg.arg,
                    kind="param",
                    line=getattr(arg, "lineno", node.lineno),
                )
            )
        _collect_declarations(node.body, inner)
        for stmt in node.body:
            self._walk(stmt, inner, False)

    def _handle_class(
        self,
        node: ast.ClassDef,
        scope: _Scope,
        conditional: bool,
    ) -> None:
        symbol = self._define_symbol(node, scope, is_async=False, is_class=True)
        for decorator in node.decorator_list:
            self._walk(decorator, scope, conditional)
        for base in node.bases:
            self._walk(base, scope, conditional)
        for keyword in node.keywords:
            self._walk(keyword.value, scope, conditional)
        for type_param in getattr(node, "type_params", []) or []:
            self._walk(type_param, scope, conditional)

        inner = _Scope("class", scope, symbol)
        for stmt in node.body:
            self._walk(stmt, inner, False)

    def _handle_lambda(self, node: ast.Lambda, scope: _Scope) -> None:
        self._walk_outer_arguments(node.args, scope, False)
        inner = _Scope("lambda", scope, scope.owner_symbol)
        for arg in _iter_arguments(node.args):
            inner.bindings.setdefault(arg.arg, []).append(
                _Binding(
                    name=arg.arg,
                    kind="param",
                    line=getattr(arg, "lineno", 0),
                )
            )
        self._walk(node.body, inner, False)

    def _handle_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        scope: _Scope,
    ) -> None:
        inner = _Scope("comprehension", scope, scope.owner_symbol)
        for index, generator in enumerate(node.generators):
            # Python evaluates the first iterable in the enclosing scope.
            self._walk(generator.iter, scope if index == 0 else inner, False)
            self._bind_target(generator.target, inner, False, "for")
            for condition in generator.ifs:
                self._walk(condition, inner, False)
        if isinstance(node, ast.DictComp):
            self._walk(node.key, inner, False)
            self._walk(node.value, inner, False)
        else:
            self._walk(node.elt, inner, False)

    # -- imports ----------------------------------------------------------
    def _register_spec(self, spec: _ImportSpec, scope: _Scope) -> None:
        self.state.import_specs.append(spec)
        if spec.is_module_level:
            self.state.module_import_specs.append(spec)
        if spec.imported == "*":
            scope.star_import = True
            return
        self._bind(
            scope,
            _Binding(
                name=spec.bound_name,
                kind="import",
                line=spec.line,
                conditional=spec.conditional,
                import_spec=spec,
            ),
        )

    def _handle_import(
        self,
        node: ast.Import | ast.ImportFrom,
        scope: _Scope,
        conditional: bool,
    ) -> None:
        is_module_level = scope.kind == "module"
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                spec = _ImportSpec(
                    kind="import",
                    level=0,
                    module=alias.name,
                    imported=None,
                    bound_name=bound,
                    node=node,
                    line=node.lineno,
                    col=node.col_offset,
                    conditional=conditional,
                    is_module_level=is_module_level,
                    target_text=alias.name,
                    bound_module=alias.name if alias.asname else alias.name.split(".")[0],
                )
                self._register_spec(spec, scope)
            return

        level = node.level
        module = node.module
        for alias in node.names:
            imported = alias.name
            bound = alias.asname or imported
            spec = _ImportSpec(
                kind="from",
                level=level,
                module=module,
                imported=imported,
                bound_name=bound,
                node=node,
                line=node.lineno,
                col=node.col_offset,
                conditional=conditional,
                is_module_level=is_module_level,
                target_text=_render_from_target(level, module),
            )
            self._register_spec(spec, scope)

    # -- patterns ---------------------------------------------------------
    def _bind_pattern(self, pattern: ast.AST, scope: _Scope, conditional: bool) -> None:
        if isinstance(pattern, ast.MatchAs):
            if pattern.name:
                self._bind(
                    scope,
                    _Binding(
                        name=pattern.name,
                        kind="except",
                        line=getattr(pattern, "lineno", 0),
                        conditional=conditional,
                    ),
                )
            if pattern.pattern is not None:
                self._bind_pattern(pattern.pattern, scope, conditional)
            return
        if isinstance(pattern, ast.MatchStar):
            if pattern.name:
                self._bind(
                    scope,
                    _Binding(
                        name=pattern.name,
                        kind="except",
                        line=getattr(pattern, "lineno", 0),
                        conditional=conditional,
                    ),
                )
            return
        if isinstance(pattern, ast.MatchMapping):
            for key in pattern.keys:
                self._walk(key, scope, conditional)
            for sub_pattern in pattern.patterns:
                self._bind_pattern(sub_pattern, scope, conditional)
            if pattern.rest:
                self._bind(
                    scope,
                    _Binding(
                        name=pattern.rest,
                        kind="except",
                        line=getattr(pattern, "lineno", 0),
                        conditional=conditional,
                    ),
                )
            return
        if isinstance(pattern, ast.MatchClass):
            self._walk(pattern.cls, scope, conditional)
            for sub_pattern in pattern.patterns:
                self._bind_pattern(sub_pattern, scope, conditional)
            for sub_pattern in pattern.kwd_patterns:
                self._bind_pattern(sub_pattern, scope, conditional)
            return
        if isinstance(pattern, ast.MatchSequence):
            for sub_pattern in pattern.patterns:
                self._bind_pattern(sub_pattern, scope, conditional)
            return
        if isinstance(pattern, ast.MatchOr):
            for sub_pattern in pattern.patterns:
                self._bind_pattern(sub_pattern, scope, conditional)

    # -- generic walker ---------------------------------------------------
    def _walk(self, node: ast.AST | None, scope: _Scope, conditional: bool) -> None:
        if node is None:
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._handle_function(node, scope, conditional)
            return
        if isinstance(node, ast.ClassDef):
            self._handle_class(node, scope, conditional)
            return
        if isinstance(node, ast.Lambda):
            self._handle_lambda(node, scope)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            self._handle_comprehension(node, scope)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._handle_import(node, scope, conditional)
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            # Declarations were pre-collected for the enclosing function scope.
            return
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                self.state.name_loads.append((node, scope))
            return
        if isinstance(node, ast.Assign):
            self._walk(node.value, scope, conditional)
            simple_value = (
                node.value
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                else None
            )
            for target in node.targets:
                self._bind_target(
                    target, scope, conditional, "assign", value=simple_value
                )
            if scope.kind == "module":
                self._record_module_assignments(node)
            return
        if isinstance(node, ast.AnnAssign):
            self._walk(node.annotation, scope, conditional)
            if node.value is not None:
                self._walk(node.value, scope, conditional)
            simple_value = node.value if isinstance(node.target, ast.Name) else None
            self._bind_target(
                node.target, scope, conditional, "assign", value=simple_value
            )
            if scope.kind == "module":
                self._record_module_assignments(node)
            return
        if isinstance(node, ast.AugAssign):
            self._walk(node.target, scope, conditional)
            self._walk(node.value, scope, conditional)
            if isinstance(node.target, ast.Name):
                self._bind(
                    scope,
                    _Binding(
                        name=node.target.id,
                        kind="assign",
                        line=node.target.lineno,
                        conditional=conditional,
                    ),
                )
            if scope.kind == "module":
                self._record_module_assignments(node)
            return
        if isinstance(node, ast.NamedExpr):
            self._walk(node.value, scope, conditional)
            if isinstance(node.target, ast.Name):
                # Walrus targets inside comprehensions bind in the enclosing
                # scope, including across nested comprehensions (PEP 572).
                binding_scope = scope
                while binding_scope.kind == "comprehension":
                    assert binding_scope.parent is not None
                    binding_scope = binding_scope.parent
                self._bind(
                    binding_scope,
                    _Binding(
                        name=node.target.id,
                        kind="assign",
                        line=node.target.lineno,
                        conditional=conditional or binding_scope is not scope,
                    ),
                )
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._walk(node.iter, scope, conditional)
            self._bind_target(node.target, scope, conditional, "for")
            for stmt in node.body:
                self._walk(stmt, scope, True)
            for stmt in node.orelse:
                self._walk(stmt, scope, True)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._walk(item.context_expr, scope, conditional)
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, scope, conditional, "with")
            for stmt in node.body:
                self._walk(stmt, scope, conditional)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.type is not None:
                self._walk(node.type, scope, conditional)
            if node.name:
                self._bind(
                    scope,
                    _Binding(
                        name=node.name,
                        kind="except",
                        line=node.lineno,
                        conditional=True,
                    ),
                )
            for stmt in node.body:
                self._walk(stmt, scope, True)
            return
        if _TRY_TYPES and isinstance(node, _TRY_TYPES):
            for stmt in node.body:
                self._walk(stmt, scope, True)
            for handler in node.handlers:
                self._walk(handler, scope, True)
            for stmt in node.orelse:
                self._walk(stmt, scope, True)
            for stmt in node.finalbody:
                self._walk(stmt, scope, True)
            return
        if isinstance(node, (ast.If, ast.While)):
            self._walk(node.test, scope, conditional)
            for stmt in node.body:
                self._walk(stmt, scope, True)
            for stmt in node.orelse:
                self._walk(stmt, scope, True)
            return
        if isinstance(node, ast.Match):
            self._walk(node.subject, scope, conditional)
            for case in node.cases:
                self._bind_pattern(case.pattern, scope, True)
                if case.guard is not None:
                    self._walk(case.guard, scope, True)
                for stmt in case.body:
                    self._walk(stmt, scope, True)
            return
        if isinstance(node, ast.Call):
            self.state.calls.append((node, scope))
            self._walk(node.func, scope, conditional)
            for argument in node.args:
                self._walk(argument, scope, conditional)
            for keyword in node.keywords:
                self._walk(keyword.value, scope, conditional)
            return
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope, conditional)


# --------------------------------------------------------------------------
# public index
# --------------------------------------------------------------------------


class Index:
    """Immutable-in-spirit result of :func:`build_index` for one snapshot side."""

    def __init__(self, side: str) -> None:
        self.side = side
        self.symbols: dict[str, Symbol] = {}
        self.modules: dict[str, ModuleInfo] = {}
        self.path_modules: dict[str, ModuleInfo] = {}
        self.edges: list[CallEdge] = []
        self.diagnostics: list[Diagnostic] = []
        self.parse_errors: dict[str, str] = {}
        self.stats: dict[str, int] = {
            "symbols": 0,
            "resolved_calls": 0,
            "unresolved_calls": 0,
            "imports_resolved": 0,
            "imports_unresolved": 0,
            "python_files_indexed": 0,
            "python_bytes_indexed": 0,
            "global_reads": 0,
        }
        # P1: module-scope variable assignment spans, per path (deterministically
        # ordered by line and name).
        self.module_assignments: dict[str, list[ModuleAssignment]] = {}
        # transient build state (not part of the persisted contract)
        self._symbol_nodes: dict[str, ast.AST] = {}
        self._symbol_fallbacks: dict[str, str] = {}
        self._digest_cache: dict[str, str] = {}
        self._edge_map: dict[str, CallEdge] = {}
        self._depths: dict[str, int] = {}
        self._by_path: dict[str, list[Symbol]] = {}
        self._top_symbols: dict[str, dict[str, Symbol]] = {}
        self._top_duplicates: dict[str, set[str]] = {}
        self._class_methods: dict[str, dict[str, list[Symbol]]] = {}
        self._duplicate_names: set[str] = set()

    # -- public contract --------------------------------------------------
    def symbol_at(self, path: str, line: int) -> Symbol | None:
        """Innermost definition whose span contains ``line`` (1-based).

        The module pseudo symbol spans the whole file, so any in-range line has
        at least the module as fallback; out-of-range lines return ``None``.
        """

        candidates = [
            symbol
            for symbol in self._by_path.get(path, ())
            if symbol.start_line <= line <= symbol.end_line
        ]
        if not candidates:
            return None

        def sort_key(symbol: Symbol) -> tuple[int, int, int, str]:
            return (
                -self._depths.get(symbol.symbol_id, 0),
                -(symbol.end_line - symbol.start_line),
                -symbol.start_line,
                symbol.symbol_id,
            )

        return min(candidates, key=sort_key)

    def symbols_for_path(self, path: str) -> list[Symbol]:
        """Symbols of one file, in source order (module symbol first)."""

        return list(self._by_path.get(path, ()))

    def structure_digest(self, symbol_id: str) -> str:
        """SHA-256 of the normalized AST dumped for one symbol.

        Module symbols digest the whole file AST; a file that could not be
        parsed falls back to the digest of its text.
        """

        cached = self._digest_cache.get(symbol_id)
        if cached is not None:
            return cached
        node = self._symbol_nodes.get(symbol_id)
        if node is not None:
            digest = sha256_text(ast.dump(node, include_attributes=False))
        else:
            digest = self._symbol_fallbacks.get(symbol_id, "")
        self._digest_cache[symbol_id] = digest
        return digest

    def module_symbol(self, path: str) -> Symbol | None:
        """Module pseudo symbol of an indexed path, if any."""

        return self.symbols.get(module_symbol_id(self.side, path))

    def global_names_at(self, path: str, lines: list[int]) -> list[str]:
        """Module-level variable names whose assignment span touches ``lines``.

        ``lines`` are 1-based source lines; a name matches when any of its
        module-scope assignment statements (including multi-line ones) overlaps
        one of them.  Names are sorted and de-duplicated, so the result feeds
        ``SymbolChange.details["global_names"]`` deterministically.
        """

        assignments = self.module_assignments.get(path)
        if not assignments:
            return []
        targets = sorted({line for line in lines if isinstance(line, int)})
        if not targets:
            return []
        names = {
            assignment.name
            for assignment in assignments
            if any(
                assignment.line <= line <= assignment.end_line for line in targets
            )
        }
        return sorted(names)

    # -- cache serialization (P1) -----------------------------------------
    def to_cache_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly snapshot of this index.

        The payload is self-contained: structure digests are materialized so a
        restored index answers ``structure_digest``/``symbol_at``/
        ``symbols_for_path``/``module_symbol`` exactly like the original without
        needing any AST node.
        """

        digests = {
            symbol_id: self.structure_digest(symbol_id) for symbol_id in self.symbols
        }
        return {
            "cache_format": CACHE_FORMAT_VERSION,
            "analyzer_version": models.ANALYZER_VERSION,
            "side": self.side,
            "symbols": [asdict(symbol) for symbol in self.symbols.values()],
            "modules": {
                name: asdict(info) for name, info in self.modules.items()
            },
            "path_modules": {
                path: asdict(info) for path, info in self.path_modules.items()
            },
            "edges": [
                {**asdict(edge), "target": models.persistent_edge_target(edge)}
                for edge in self.edges
            ],
            "diagnostics": [
                diagnostic.to_dict() for diagnostic in self.diagnostics
            ],
            "parse_errors": dict(self.parse_errors),
            "stats": dict(self.stats),
            "module_assignments": {
                path: [asdict(assignment) for assignment in assignments]
                for path, assignments in self.module_assignments.items()
            },
            "structure_digests": digests,
        }

    @classmethod
    def from_cache_dict(
        cls, side: str, data: dict[str, Any], config: Config
    ) -> "Index":
        """Rebuild an index from :meth:`to_cache_dict` output.

        Payloads that do not match the current cache format, declare another
        side or contain malformed/unknown structures raise ``ValueError`` (the
        caller treats that as a cache miss and rebuilds).  ``config`` mirrors
        :func:`build_index`; cache key/version validation stays the caller's
        responsibility.
        """

        if side not in models.SIDES:
            raise _cache_error(f"unsupported side {side!r}")
        payload = _cache_mapping(data, "payload")
        if payload.get("cache_format") != CACHE_FORMAT_VERSION:
            raise _cache_error(
                f"unsupported cache_format {payload.get('cache_format')!r}"
            )
        if payload.get("side") != side:
            raise _cache_error(
                f"payload side {payload.get('side')!r} does not match {side!r}"
            )

        index = cls(side)

        symbols = [
            _symbol_from_cache(item) for item in _cache_list(payload.get("symbols"), "symbols")
        ]
        for symbol in symbols:
            if symbol.side != side:
                raise _cache_error(
                    f"symbol {symbol.symbol_id!r} belongs to side {symbol.side!r}"
                )
        index.symbols = {symbol.symbol_id: symbol for symbol in symbols}
        if len(index.symbols) != len(symbols):
            raise _cache_error("duplicate symbol ids in payload")

        modules = _cache_mapping(payload.get("modules"), "modules")
        index.modules = {
            _cache_str(name, "modules key"): _module_info_from_cache(value, "modules")
            for name, value in modules.items()
        }
        path_modules = _cache_mapping(payload.get("path_modules"), "path_modules")
        index.path_modules = {
            _cache_str(path, "path_modules key"): _module_info_from_cache(
                value, "path_modules"
            )
            for path, value in path_modules.items()
        }

        index.edges = [
            _edge_from_cache(item) for item in _cache_list(payload.get("edges"), "edges")
        ]
        for edge in index.edges:
            if edge.side != side:
                raise _cache_error(
                    f"edge {edge.edge_id!r} belongs to side {edge.side!r}"
                )

        index.diagnostics = [
            _diagnostic_from_cache(item)
            for item in _cache_list(payload.get("diagnostics"), "diagnostics")
        ]

        parse_errors = _cache_mapping(payload.get("parse_errors"), "parse_errors")
        index.parse_errors = {
            _cache_str(path, "parse_errors key"): _cache_str(
                summary, "parse_errors value", allow_empty=True
            )
            for path, summary in parse_errors.items()
        }

        stats = _cache_mapping(payload.get("stats"), "stats")
        normalized: dict[str, int] = {}
        for key, value in stats.items():
            name = _cache_str(key, "stats key")
            normalized[name] = _cache_int(value, f"stats[{name!r}]")
        missing = [key for key in _STATS_KEYS if key not in normalized]
        if missing:
            raise _cache_error(f"stats missing keys {', '.join(missing)}")
        index.stats = normalized

        assignments = _cache_mapping(
            payload.get("module_assignments"), "module_assignments"
        )
        index.module_assignments = {
            _cache_str(path, "module_assignments key"): [
                _module_assignment_from_cache(item)
                for item in _cache_list(items, f"module_assignments[{path!r}]")
            ]
            for path, items in assignments.items()
        }

        digests = _cache_mapping(
            payload.get("structure_digests"), "structure_digests"
        )
        digest_cache: dict[str, str] = {}
        for symbol_id, digest in digests.items():
            name = _cache_str(symbol_id, "structure_digests key")
            digest_cache[name] = _cache_str(
                digest, f"structure_digests[{name!r}]"
            )
        if set(digest_cache) != set(index.symbols):
            raise _cache_error("structure digests do not cover the symbol table")
        index._digest_cache = digest_cache

        index._compute_depths()
        index._build_symbol_tables()
        return index

    # -- build helpers ----------------------------------------------------
    def _record_edge(
        self,
        *,
        caller_id: str,
        path: str,
        line: int,
        col: int,
        edge_kind: str,
        target: str,
        resolution: str,
        callee_id: str | None = None,
        reason: str | None = None,
        callee_module: str | None = None,
    ) -> None:
        edge = CallEdge(
            edge_id=models.edge_id(self.side, caller_id, target, line, col, edge_kind),
            side=self.side,
            caller_id=caller_id,
            callee_id=callee_id,
            path=path,
            line=line,
            col=col,
            edge_kind=edge_kind,
            resolution=resolution,
            reason=reason,
            target=target,
            callee_module=callee_module,
        )
        self._edge_map[edge.edge_id] = edge

    def _register_modules(self, states: list[_FileState]) -> None:
        by_name: dict[str, list[ModuleInfo]] = {}
        for state in states:
            by_name.setdefault(state.module_info.name, []).append(state.module_info)
        self.path_modules = {
            state.path: state.module_info
            for state in sorted(states, key=lambda item: item.path)
        }
        for name in sorted(by_name):
            infos = by_name[name]
            if len(infos) > 1:
                self._duplicate_names.add(name)
                for info in infos:
                    info.importable = False
                self.diagnostics.append(
                    diag(
                        "duplicate_module",
                        f"module name {name!r} is provided by {len(infos)} files; "
                        "imports of it stay unresolved",
                        severity="warning",
                        details={
                            "module": name,
                            "paths": sorted(info.path for info in infos),
                        },
                    )
                )
                continue
            self.modules[name] = infos[0]

    def _build_symbol_tables(self) -> None:
        """Derive path/depth/top-symbol/class-method tables from ``symbols``.

        All of them are pure functions of the symbol table, which is what lets a
        cache-restored index behave exactly like a freshly built one.
        """

        self._build_path_index()
        self._rebuild_top_symbols()
        self._build_class_methods()

    def _build_path_index(self) -> None:
        self._by_path = {}
        for symbol in self.symbols.values():
            self._by_path.setdefault(symbol.path, []).append(symbol)
        for path in self._by_path:
            self._by_path[path].sort(
                key=lambda symbol: (
                    symbol.start_line,
                    symbol.def_line,
                    symbol.qualified_name,
                    symbol.symbol_id,
                )
            )

    def _rebuild_top_symbols(self) -> None:
        self._top_symbols = {}
        self._top_duplicates = {}
        for path, symbols in self._by_path.items():
            module_id = next(
                (
                    symbol.symbol_id
                    for symbol in symbols
                    if symbol.kind == SYMBOL_MODULE
                ),
                None,
            )
            grouped: dict[str, list[Symbol]] = {}
            for symbol in symbols:
                if symbol.parent_id != module_id:
                    continue
                if symbol.kind not in _TOP_SYMBOL_KINDS:
                    continue
                grouped.setdefault(symbol.qualified_name, []).append(symbol)
            table: dict[str, Symbol] = {}
            duplicates: set[str] = set()
            for qualified_name, matches in grouped.items():
                if len(matches) == 1:
                    table[qualified_name] = matches[0]
                else:
                    duplicates.add(qualified_name)
            self._top_symbols[path] = table
            self._top_duplicates[path] = duplicates

    def _build_class_methods(self) -> None:
        methods: dict[str, dict[str, list[Symbol]]] = {}
        for symbol in self.symbols.values():
            if symbol.kind != SYMBOL_METHOD or not symbol.parent_id:
                continue
            parent = self.symbols.get(symbol.parent_id)
            if parent is None or parent.kind != SYMBOL_CLASS:
                continue
            name = symbol.qualified_name.rsplit(".", 1)[-1]
            if not name:
                continue
            methods.setdefault(parent.symbol_id, {}).setdefault(name, []).append(
                symbol
            )
        self._class_methods = methods

    def _collect_module_assignments(self, states: list[_FileState]) -> None:
        self.module_assignments = {
            state.path: sorted(
                state.module_assignments,
                key=lambda assignment: (
                    assignment.line,
                    assignment.end_line,
                    assignment.name,
                ),
            )
            for state in states
        }

    def _module_failure(self, name: str, *, relative: bool) -> str:
        info = self.modules.get(name)
        if info is not None:
            return "not_importable"
        if name in self._duplicate_names:
            return "duplicate_module"
        if relative:
            return "unresolved_module"
        parts = name.split(".")
        for index in range(1, len(parts)):
            if ".".join(parts[:index]) in self.modules:
                return "unresolved_module"
        return "external_module"

    def _resolve_module(
        self, name: str, *, relative: bool
    ) -> tuple[ModuleInfo | None, str | None]:
        if not name:
            return None, "unresolved_module"
        info = self.modules.get(name)
        if info is not None:
            return (info, None) if info.importable else (None, "not_importable")
        return None, self._module_failure(name, relative=relative)

    def _relative_target(
        self, state: _FileState, level: int, module: str | None
    ) -> str | None:
        current = state.module_info.name
        is_package = posixpath.basename(state.path) == "__init__.py"
        package_parts = current.split(".") if is_package else current.split(".")[:-1]
        if level - 1 >= len(package_parts):
            return None
        base = package_parts[: len(package_parts) - (level - 1)]
        if not base:
            return None
        if module:
            return ".".join(base + module.split("."))
        return ".".join(base)

    def _resolve_import_spec(self, state: _FileState, spec: _ImportSpec) -> None:
        if spec.kind == "import":
            full = spec.module or ""
            info, failure = self._resolve_module(full, relative=False)
            if info is not None:
                spec.resolved_module = full
                spec.resolved_info = info
            else:
                spec.failure = failure
            bound = spec.bound_module or full
            bound_info, bound_failure = self._resolve_module(bound, relative=False)
            if bound_info is not None:
                spec.target_kind = "module"
                spec.bound_module = bound
                spec.bound_info = bound_info
            else:
                spec.target_kind = None
                spec.failure = spec.failure or bound_failure
        else:
            if spec.level:
                target = self._relative_target(state, spec.level, spec.module)
                if target is None:
                    info, failure = None, "unresolved_module"
                else:
                    info, failure = self._resolve_module(target, relative=True)
            else:
                target = spec.module or ""
                info, failure = self._resolve_module(target, relative=False)
            if info is not None:
                spec.resolved_module = info.name
                spec.resolved_info = info
            else:
                spec.failure = failure

            imported = spec.imported or ""
            if imported == "*":
                spec.target_kind = "star" if info is not None else None
            elif info is not None:
                submodule_name = f"{info.name}.{imported}"
                sub_info = self.modules.get(submodule_name)
                if sub_info is not None and sub_info.importable:
                    spec.target_kind = "module"
                    spec.bound_module = submodule_name
                    spec.bound_info = sub_info
                elif imported in self._top_duplicates.get(info.path, set()):
                    spec.target_kind = None
                    spec.failure = "ambiguous_definition"
                else:
                    symbol = self._top_symbols.get(info.path, {}).get(imported)
                    if symbol is not None and symbol.kind in _CALLABLE_KINDS:
                        spec.target_kind = "function"
                        spec.symbol_id = symbol.symbol_id
                    elif symbol is not None and symbol.kind == SYMBOL_CLASS:
                        spec.target_kind = "class"
                        spec.symbol_id = symbol.symbol_id
                    else:
                        spec.target_kind = None
                        spec.failure = "unresolved_import"

        if spec.is_module_level:
            self._emit_import_edge(state, spec)

    def _emit_import_edge(self, state: _FileState, spec: _ImportSpec) -> None:
        resolved = (
            spec.resolved_info is not None
            and spec.resolved_info.importable
            and spec.resolved_module is not None
        )
        if spec.conditional:
            self._record_edge(
                caller_id=state.module_symbol.symbol_id,
                path=state.path,
                line=spec.line,
                col=spec.col,
                edge_kind=EDGE_IMPORT,
                target=spec.target_text,
                resolution=UNRESOLVED,
                reason="conditional_import",
            )
            return
        if resolved:
            info = spec.resolved_info
            assert info is not None  # narrowed above
            self._record_edge(
                caller_id=state.module_symbol.symbol_id,
                path=state.path,
                line=spec.line,
                col=spec.col,
                edge_kind=EDGE_IMPORT,
                target=spec.target_text,
                resolution=RESOLVED,
                callee_id=info.symbol_id,
                callee_module=info.name,
            )
            return
        self._record_edge(
            caller_id=state.module_symbol.symbol_id,
            path=state.path,
            line=spec.line,
            col=spec.col,
            edge_kind=EDGE_IMPORT,
            target=spec.target_text,
            resolution=UNRESOLVED,
            reason=spec.failure or "unresolved_module",
        )

    # -- name lookup ------------------------------------------------------
    def _import_name_result(self, spec: _ImportSpec) -> _NameResult:
        if spec.target_kind == "function":
            symbol = self.symbols.get(spec.symbol_id or "")
            if symbol is not None:
                return _NameResult(kind="function", symbol=symbol)
            return _NameResult(kind="unresolved", reason="unresolved_import")
        if spec.target_kind == "class":
            symbol = self.symbols.get(spec.symbol_id or "")
            if symbol is not None:
                return _NameResult(kind="class", symbol=symbol)
            return _NameResult(kind="unresolved", reason="unresolved_import")
        if spec.target_kind == "module":
            return _NameResult(
                kind="module",
                module_name=spec.bound_module,
                module_info=spec.bound_info,
                failure=spec.failure if spec.bound_info is None else None,
            )
        return _NameResult(
            kind="unresolved", reason=spec.failure or "unresolved_import"
        )

    def _resolve_scope_bindings(
        self, scope: _Scope, binds: list[_Binding]
    ) -> _NameResult:
        if scope.kind != "module":
            kinds = {binding.kind for binding in binds}
            if "def" in kinds:
                return _NameResult(kind="unresolved", reason="nested_local")
            if "class" in kinds:
                return _NameResult(kind="unresolved", reason="class_instantiation")
            if "import" in kinds:
                return _NameResult(kind="unresolved", reason="local_binding")
            return _NameResult(kind="unresolved", reason="shadowed")

        imports = [
            binding
            for binding in binds
            if binding.kind == "import" and binding.import_spec is not None
        ]
        definitions = [binding for binding in binds if binding.kind == "def"]
        classes = [binding for binding in binds if binding.kind == "class"]
        others = [
            binding
            for binding in binds
            if binding.kind not in ("import", "def", "class")
        ]

        if imports:
            if any(
                binding.import_spec is not None and binding.import_spec.conditional
                for binding in imports
            ):
                return _NameResult(kind="unresolved", reason="conditional_import")
            if definitions or classes or others:
                return _NameResult(kind="unresolved", reason="ambiguous_definition")
            outcomes: dict[tuple[str, str], _NameResult] = {}
            for binding in imports:
                assert binding.import_spec is not None
                result = self._import_name_result(binding.import_spec)
                if result.kind == "function" and result.symbol is not None:
                    key = ("function", result.symbol.symbol_id)
                elif result.kind == "class" and result.symbol is not None:
                    key = ("class", result.symbol.symbol_id)
                elif result.kind == "module":
                    key = (
                        "module",
                        result.module_name or f"!{result.failure or 'unresolved'}",
                    )
                else:
                    key = ("failed", result.reason or "unresolved_import")
                outcomes[key] = result
            if len(outcomes) == 1:
                return next(iter(outcomes.values()))
            has_resolved = any(
                key[0] in ("function", "class", "module") for key in outcomes
            )
            if has_resolved:
                return _NameResult(kind="unresolved", reason="ambiguous_definition")
            return next(iter(outcomes.values()))

        function_ids: list[str] = []
        class_ids: list[str] = []
        for binding in definitions:
            symbol = self.symbols.get(binding.symbol_id or "")
            if symbol is None:
                continue
            if symbol.kind in _CALLABLE_KINDS:
                function_ids.append(symbol.symbol_id)
            elif symbol.kind == SYMBOL_CLASS:
                class_ids.append(symbol.symbol_id)
        for binding in classes:
            symbol = self.symbols.get(binding.symbol_id or "")
            if symbol is not None:
                class_ids.append(symbol.symbol_id)

        unique_functions = list(dict.fromkeys(function_ids))
        unique_classes = list(dict.fromkeys(class_ids))
        if unique_functions and unique_classes:
            return _NameResult(kind="unresolved", reason="ambiguous_definition")
        if len(unique_functions) > 1 or len(unique_classes) > 1:
            return _NameResult(kind="unresolved", reason="ambiguous_definition")
        if unique_functions:
            if others:
                return _NameResult(kind="unresolved", reason="reassigned")
            symbol = self.symbols[unique_functions[0]]
            return _NameResult(kind="function", symbol=symbol)
        if unique_classes:
            if others:
                return _NameResult(kind="unresolved", reason="reassigned")
            return _NameResult(kind="class", symbol=self.symbols[unique_classes[0]])
        if others:
            return _NameResult(kind="unresolved", reason="non_function_binding")
        return _NameResult(kind="unresolved", reason="external_call")

    def _scope_has_star_import(self, scope: _Scope) -> bool:
        current: _Scope | None = scope
        while current is not None:
            if current.kind == "class" and current is not scope:
                current = current.parent
                continue
            if current.star_import:
                return True
            current = current.parent
        return False

    def _resolve_name(self, name: str, scope: _Scope) -> _NameResult:
        current: _Scope | None = scope
        while current is not None:
            if current.kind == "class" and current is not scope:
                current = current.parent
                continue
            binds = current.bindings.get(name)
            if binds:
                return self._resolve_scope_bindings(current, binds)
            current = current.parent
        if self._scope_has_star_import(scope):
            return _NameResult(kind="unresolved", reason="star_import")
        return _NameResult(kind="unresolved", reason="external_call")

    # -- P1 bounded method/constructor dispatch ---------------------------
    def _class_method(
        self, class_symbol: Symbol, method_name: str
    ) -> tuple[Symbol | None, str | None]:
        """Return the unique method ``method_name`` of ``class_symbol``.

        Inherited and dynamically supplied attributes are never guessed: a
        method that is not defined directly on the class resolves to
        ``dynamic_method``.  Multiple same-name definitions are ambiguous.
        """

        candidates = self._class_methods.get(class_symbol.symbol_id, {}).get(
            method_name, []
        )
        if not candidates:
            return None, "dynamic_method"
        unique = list({symbol.symbol_id: symbol for symbol in candidates}.values())
        if len(unique) > 1:
            return None, "ambiguous_definition"
        return unique[0], None

    def _class_attribute_mutated(
        self,
        state: _FileState,
        class_symbol: Symbol,
        receiver_name: str | None,
        attribute: str,
    ) -> bool:
        """True when the file rebinds ``receiver.attribute`` or ``Class.attribute``.

        A rebound attribute may no longer be the defined method, so the index
        keeps the call unresolved instead of guessing the original symbol.
        """

        if receiver_name is not None:
            if (receiver_name, attribute) in state.attribute_mutations:
                return True
        simple = class_symbol.qualified_name.rsplit(".", 1)[-1]
        return (simple, attribute) in state.attribute_mutations

    def _method_receiver(self, name: str, scope: _Scope) -> Symbol | None:
        """Class owning the receiver when ``name`` is ``self``/``cls``.

        Only a directly enclosing method body qualifies (comprehensions are
        transparent); the name must be bound exclusively by that method's
        receiver parameter, so rebinding or shadowing disables the rule.
        """

        if name not in ("self", "cls"):
            return None
        current: _Scope | None = scope
        while current is not None and current.kind == "comprehension":
            current = current.parent
        if current is None or current.kind != "function":
            return None
        owner = current.owner_symbol
        if owner is None or owner.kind != SYMBOL_METHOD or not owner.parent_id:
            return None
        binds = current.bindings.get(name, [])
        if len(binds) != 1 or binds[0].kind != "param":
            return None
        return self.symbols.get(owner.parent_id)

    def _class_from_expression(
        self, state: _FileState, node: ast.AST, scope: _Scope
    ) -> Symbol | None:
        """Resolve ``C`` / ``mod.C`` to a unique class symbol, if possible."""

        if isinstance(node, ast.Name):
            result = self._resolve_name(node.id, scope)
            if result.kind == "class" and result.symbol is not None:
                return result.symbol
            return None
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base = node.value
            result = self._resolve_name(base.id, scope)
            if result.kind != "module" or result.module_info is None:
                return None
            info = result.module_info
            if (base.id, node.attr) in state.attribute_mutations:
                return None
            if node.attr in self._top_duplicates.get(info.path, set()):
                return None
            symbol = self._top_symbols.get(info.path, {}).get(node.attr)
            if symbol is not None and symbol.kind == SYMBOL_CLASS:
                return symbol
        return None

    def _constructor_class(
        self, state: _FileState, name: str, scope: _Scope, line: int
    ) -> Symbol | None:
        """Class bound by one simple unconditional ``name = C(...)`` assignment.

        The binding must be the name's only binding in its own function scope,
        unconditional, located before the call and initialised from a uniquely
        resolvable class expression.  Anything else stays unresolved.
        """

        current: _Scope | None = scope
        while current is not None and current.kind == "comprehension":
            current = current.parent
        if current is None or current.kind != "function":
            return None
        binds = current.bindings.get(name, [])
        if len(binds) != 1:
            return None
        binding = binds[0]
        if binding.kind != "assign" or binding.conditional or binding.value is None:
            return None
        if binding.line > line:
            return None
        value = binding.value
        if not isinstance(value, ast.Call):
            return None
        return self._class_from_expression(state, value.func, current)

    # -- P1 global reads --------------------------------------------------
    def _function_caller(self, scope: _Scope) -> Symbol | None:
        """Nearest function/method symbol containing ``scope`` (None at top level)."""

        current: _Scope | None = scope
        while current is not None:
            if current.kind in ("function", "lambda"):
                return current.owner_symbol
            if current.kind == "module":
                return None
            current = current.parent
        return None

    def _source_is_module_read(
        self, state: _FileState, name: str, scope: _Scope
    ) -> bool:
        """True when ``name`` resolves to a module-scope assignment from here."""

        current: _Scope | None = scope
        while current is not None:
            if current.kind == "class" and current is not scope:
                current = current.parent
                continue
            binds = current.bindings.get(name)
            if binds:
                if current.kind != "module":
                    return False
                if any(binding.kind != "assign" for binding in binds):
                    return False
                return any(
                    assignment.name == name
                    for assignment in state.module_assignments
                )
            current = current.parent
        return False

    def _resolve_global_read(
        self, state: _FileState, node: ast.Name, scope: _Scope
    ) -> None:
        caller = self._function_caller(scope)
        if caller is None:
            return
        if not self._source_is_module_read(state, node.id, scope):
            return
        self._record_edge(
            caller_id=caller.symbol_id,
            path=state.path,
            line=node.lineno,
            col=node.col_offset,
            edge_kind=EDGE_GLOBAL_READ,
            target=node.id,
            resolution=RESOLVED,
            callee_id=state.module_symbol.symbol_id,
            reason="global_read",
            callee_module=state.module_info.name,
        )

    # -- call resolution --------------------------------------------------
    def _resolve_call(self, state: _FileState, call: ast.Call, scope: _Scope) -> None:
        caller = scope.owner_symbol or state.module_symbol
        function_node = call.func
        target = _render_expression(function_node)
        line = call.lineno
        col = call.col_offset
        def unresolved(reason: str) -> None:
            self._record_edge(
                caller_id=caller.symbol_id,
                path=state.path,
                line=line,
                col=col,
                edge_kind=EDGE_CALL,
                target=target,
                resolution=UNRESOLVED,
                reason=reason,
            )

        def resolved(symbol: Symbol, reason: str | None = None) -> None:
            self._record_edge(
                caller_id=caller.symbol_id,
                path=state.path,
                line=line,
                col=col,
                edge_kind=EDGE_CALL,
                target=target,
                resolution=RESOLVED,
                callee_id=symbol.symbol_id,
                reason=reason,
                callee_module=symbol.module,
            )

        if isinstance(function_node, ast.Name):
            if function_node.id == "__import__":
                unresolved("dynamic_import")
                return
            result = self._resolve_name(function_node.id, scope)
            if result.kind == "function" and result.symbol is not None:
                resolved(result.symbol)
            elif result.kind == "class" and result.symbol is not None:
                # P1: class instantiation points at the class symbol so class
                # definition changes can be traced to their construction sites.
                resolved(result.symbol, "class_instantiation")
            elif result.kind == "class":
                unresolved("class_instantiation")
            elif result.kind == "module":
                if result.module_info is not None:
                    unresolved("unsupported_expression")
                else:
                    unresolved(result.failure or "external_module")
            else:
                unresolved(result.reason or "external_call")
            return

        if isinstance(function_node, ast.Attribute):
            if function_node.attr == "import_module":
                unresolved("dynamic_import")
                return
            depth = _attribute_depth(function_node)
            if depth > 2:
                unresolved("attribute")
                return
            if depth == 2:
                # ``mod.C.method()``: the receiver expression must uniquely
                # resolve to a class; anything else keeps the P0 behaviour.
                class_symbol = self._class_from_expression(
                    state, function_node.value, scope
                )
                if class_symbol is None:
                    unresolved("attribute")
                    return
                if self._class_attribute_mutated(
                    state,
                    class_symbol,
                    function_node.value.attr,
                    function_node.attr,
                ):
                    unresolved("reassigned")
                    return
                method, failure = self._class_method(
                    class_symbol, function_node.attr
                )
                if method is None:
                    unresolved(failure or "dynamic_method")
                else:
                    resolved(method, "explicit_class")
                return
            base = function_node.value
            if not isinstance(base, ast.Name):
                # ``super().method()`` and other computed receivers.
                unresolved("dynamic_method")
                return
            attribute = function_node.attr
            receiver = self._method_receiver(base.id, scope)
            if receiver is not None:
                if self._class_attribute_mutated(
                    state, receiver, base.id, attribute
                ):
                    unresolved("reassigned")
                    return
                method, failure = self._class_method(receiver, attribute)
                if method is None:
                    unresolved(failure or "dynamic_method")
                else:
                    resolved(method, "self_method_unique")
                return
            result = self._resolve_name(base.id, scope)
            if result.kind == "class" and result.symbol is not None:
                if self._class_attribute_mutated(
                    state, result.symbol, base.id, attribute
                ):
                    unresolved("reassigned")
                    return
                method, failure = self._class_method(result.symbol, attribute)
                if method is None:
                    unresolved(failure or "dynamic_method")
                else:
                    resolved(method, "explicit_class")
                return
            if result.kind == "unresolved":
                class_symbol = self._constructor_class(
                    state, base.id, scope, line
                )
                if class_symbol is not None:
                    if self._class_attribute_mutated(
                        state, class_symbol, base.id, attribute
                    ):
                        unresolved("reassigned")
                        return
                    method, failure = self._class_method(class_symbol, attribute)
                    if method is None:
                        unresolved(failure or "dynamic_method")
                    else:
                        resolved(method, "constructor_binding")
                    return
            if result.kind == "module":
                info = result.module_info
                if info is None:
                    unresolved(result.failure or "external_module")
                    return
                if (base.id, attribute) in state.attribute_mutations:
                    # The attribute was rebound in this file (monkey patch or
                    # plain attribute assignment); never guess the target.
                    unresolved("reassigned")
                    return
                if attribute in self._top_duplicates.get(info.path, set()):
                    unresolved("ambiguous_definition")
                    return
                symbol = self._top_symbols.get(info.path, {}).get(attribute)
                if symbol is None:
                    unresolved("unresolved_attribute")
                elif symbol.kind in _CALLABLE_KINDS:
                    resolved(symbol)
                elif symbol.kind == SYMBOL_CLASS:
                    # ``mod.C()`` class instantiation.
                    resolved(symbol, "class_instantiation")
                else:
                    unresolved("class_instantiation")
                return
            if result.kind == "unresolved" and result.reason in _MODULE_REASONS:
                unresolved(result.reason or "unresolved_module")
                return
            unresolved("dynamic_method")
            return

        # Computed callee (factory return value, subscript, call of a call, ...).
        # Render the whole call so this edge cannot collide with the edge of the
        # inner call expression, which shares the same start position.
        target = _render_expression(call)
        unresolved("unsupported_expression")

    # -- finalisation -----------------------------------------------------
    def _compute_depths(self) -> None:
        self._depths = {}
        for symbol_id, symbol in self.symbols.items():
            depth = 0
            current = symbol
            seen: set[str] = set()
            while current.parent_id and current.parent_id in self.symbols:
                if current.parent_id in seen:
                    break
                seen.add(current.parent_id)
                depth += 1
                current = self.symbols[current.parent_id]
            self._depths[symbol_id] = depth

    def _finalize(
        self,
        selected_paths: list[str],
        total_bytes: int,
        config: Config,
    ) -> None:
        edges = sorted(
            self._edge_map.values(),
            key=lambda edge: (
                edge.path,
                edge.line,
                edge.col,
                edge.edge_kind,
                edge.target or "",
                edge.edge_id,
            ),
        )
        limit = config.analysis.max_edges
        if len(edges) > limit:
            self.diagnostics.append(
                diag(
                    "edge_limit",
                    "call/import/global-read edge budget exceeded; keeping "
                    f"the first {limit} edges",
                    severity="warning",
                    details={"limit": limit, "total": len(edges)},
                )
            )
            edges = edges[:limit]
        self.edges = edges

        self.diagnostics.sort(
            key=lambda item: (
                item.path or "",
                item.line or 0,
                item.code,
                item.message,
            )
        )

        self._compute_depths()
        self._build_symbol_tables()

        resolved_calls = 0
        unresolved_calls = 0
        imports_resolved = 0
        imports_unresolved = 0
        global_reads = 0
        for edge in edges:
            if edge.edge_kind == EDGE_CALL:
                if edge.resolution == RESOLVED:
                    resolved_calls += 1
                else:
                    unresolved_calls += 1
            elif edge.edge_kind == EDGE_IMPORT:
                if edge.resolution == RESOLVED:
                    imports_resolved += 1
                else:
                    imports_unresolved += 1
            elif edge.edge_kind == EDGE_GLOBAL_READ:
                global_reads += 1
        self.stats = {
            "symbols": len(self.symbols),
            "resolved_calls": resolved_calls,
            "unresolved_calls": unresolved_calls,
            "imports_resolved": imports_resolved,
            "imports_unresolved": imports_unresolved,
            "python_files_indexed": len(selected_paths),
            "python_bytes_indexed": total_bytes,
            "global_reads": global_reads,
        }


# --------------------------------------------------------------------------
# cache (de)serialization helpers
# --------------------------------------------------------------------------


def _cache_error(message: str) -> ValueError:
    return ValueError(f"invalid AST index cache: {message}")


def _cache_mapping(value: Any, field: str) -> dict:
    if not isinstance(value, dict):
        raise _cache_error(f"{field} must be an object")
    return value


def _cache_list(value: Any, field: str) -> list:
    if not isinstance(value, list):
        raise _cache_error(f"{field} must be a list")
    return value


def _cache_str(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _cache_error(f"{field} must be a non-empty string")
    return value


def _cache_optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _cache_str(value, field, allow_empty=True)


def _cache_int(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise _cache_error(f"{field} must be an integer >= {minimum}")
    return value


def _cache_optional_int(value: Any, field: str, *, minimum: int = 1) -> int | None:
    if value is None:
        return None
    return _cache_int(value, field, minimum=minimum)


def _symbol_from_cache(raw: Any) -> Symbol:
    data = _cache_mapping(raw, "symbol")
    return Symbol(
        symbol_id=_cache_str(data.get("symbol_id"), "symbol.symbol_id"),
        side=_cache_str(data.get("side"), "symbol.side"),
        path=_cache_str(data.get("path"), "symbol.path"),
        module=_cache_str(data.get("module"), "symbol.module", allow_empty=True),
        qualified_name=_cache_str(
            data.get("qualified_name"),
            "symbol.qualified_name",
            allow_empty=True,
        ),
        kind=_cache_str(data.get("kind"), "symbol.kind"),
        parent_id=_cache_optional_str(data.get("parent_id"), "symbol.parent_id"),
        start_line=_cache_int(data.get("start_line"), "symbol.start_line", minimum=1),
        end_line=_cache_int(data.get("end_line"), "symbol.end_line", minimum=1),
        def_line=_cache_int(data.get("def_line"), "symbol.def_line", minimum=1),
        decorator_start=_cache_optional_int(
            data.get("decorator_start"), "symbol.decorator_start"
        ),
        is_test=bool(data.get("is_test", False)),
    )


def _module_info_from_cache(raw: Any, field: str) -> ModuleInfo:
    data = _cache_mapping(raw, field)
    importable = data.get("importable", True)
    if not isinstance(importable, bool):
        raise _cache_error(f"{field}.importable must be a boolean")
    return ModuleInfo(
        name=_cache_str(data.get("name"), f"{field}.name"),
        path=_cache_str(data.get("path"), f"{field}.path"),
        symbol_id=_cache_str(
            data.get("symbol_id"), f"{field}.symbol_id", allow_empty=True
        ),
        importable=importable,
        package_root=_cache_optional_str(
            data.get("package_root"), f"{field}.package_root"
        ),
    )


def _edge_from_cache(raw: Any) -> CallEdge:
    data = _cache_mapping(raw, "edge")
    edge_kind = _cache_str(data.get("edge_kind"), "edge.edge_kind")
    if edge_kind not in _EDGE_KINDS:
        raise _cache_error(f"edge.edge_kind {edge_kind!r} is not supported")
    resolution = _cache_str(data.get("resolution"), "edge.resolution")
    if resolution not in _RESOLUTIONS:
        raise _cache_error(f"edge.resolution {resolution!r} is not supported")
    return CallEdge(
        edge_id=_cache_str(data.get("edge_id"), "edge.edge_id"),
        side=_cache_str(data.get("side"), "edge.side"),
        caller_id=_cache_str(data.get("caller_id"), "edge.caller_id"),
        callee_id=_cache_optional_str(data.get("callee_id"), "edge.callee_id"),
        path=_cache_str(data.get("path"), "edge.path"),
        line=_cache_int(data.get("line"), "edge.line", minimum=1),
        col=_cache_int(data.get("col"), "edge.col"),
        edge_kind=edge_kind,
        resolution=resolution,
        reason=_cache_optional_str(data.get("reason"), "edge.reason"),
        target=_cache_optional_str(data.get("target"), "edge.target"),
        callee_module=_cache_optional_str(
            data.get("callee_module"), "edge.callee_module"
        ),
    )


def _diagnostic_from_cache(raw: Any) -> Diagnostic:
    data = _cache_mapping(raw, "diagnostic")
    severity = data.get("severity", "warning")
    if severity not in ("info", "warning", "error"):
        raise _cache_error(f"diagnostic.severity {severity!r} is not supported")
    details = data.get("details", {})
    if details is None:
        details = {}
    details = _cache_mapping(details, "diagnostic.details")
    return Diagnostic(
        code=_cache_str(data.get("code"), "diagnostic.code"),
        message=_cache_str(
            data.get("message"), "diagnostic.message", allow_empty=True
        ),
        severity=severity,
        path=_cache_optional_str(data.get("path"), "diagnostic.path"),
        line=_cache_optional_int(data.get("line"), "diagnostic.line"),
        details=dict(details),
    )


def _module_assignment_from_cache(raw: Any) -> ModuleAssignment:
    data = _cache_mapping(raw, "module assignment")
    line = _cache_int(data.get("line"), "module_assignment.line", minimum=1)
    end_line = _cache_int(
        data.get("end_line"), "module_assignment.end_line", minimum=1
    )
    if end_line < line:
        raise _cache_error("module_assignment.end_line precedes line")
    return ModuleAssignment(
        name=_cache_str(data.get("name"), "module_assignment.name"),
        line=line,
        end_line=end_line,
    )


# --------------------------------------------------------------------------
# per-file scanning
# --------------------------------------------------------------------------


def _scan_file(
    index: Index,
    side: SnapshotSide,
    config: Config,
    path: str,
    text: str,
) -> _FileState:
    module_info, name_diagnostics = _resolve_module_info(side, config, path)
    module_info.symbol_id = module_symbol_id(side.side, path)
    index.diagnostics.extend(name_diagnostics)

    line_count = max(1, len(source_lines(text)))
    module_symbol = Symbol(
        symbol_id=module_info.symbol_id,
        side=side.side,
        path=path,
        module=module_info.name,
        qualified_name="",
        kind=SYMBOL_MODULE,
        parent_id=None,
        start_line=1,
        end_line=line_count,
        def_line=1,
        decorator_start=None,
        is_test=False,
    )
    index.symbols[module_symbol.symbol_id] = module_symbol
    state = _FileState(
        path=path,
        text=text,
        module_info=module_info,
        module_symbol=module_symbol,
    )
    state.symbols.append(module_symbol)

    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError) as exc:
        summary = _syntax_error_summary(exc)
        index.parse_errors[path] = summary
        index.diagnostics.append(
            diag(
                "syntax_error",
                f"cannot parse {path!r}: {summary}",
                severity="error",
                path=path,
                line=getattr(exc, "lineno", None),
            )
        )
        index._symbol_fallbacks[module_symbol.symbol_id] = sha256_text(text)
        return state
    except RecursionError as exc:  # pragma: no cover - pathological nesting
        summary = f"RecursionError: {exc}"
        index.parse_errors[path] = summary
        index.diagnostics.append(
            diag(
                "ast_recursion",
                f"cannot index {path!r}: {summary}",
                severity="error",
                path=path,
            )
        )
        index._symbol_fallbacks[module_symbol.symbol_id] = sha256_text(text)
        return state

    state.tree = tree
    index._symbol_nodes[module_symbol.symbol_id] = tree
    state.module_scope = _Scope("module", None, module_symbol)
    try:
        _Scanner(index, state, tree).run()
    except RecursionError as exc:  # pragma: no cover - pathological nesting
        summary = f"RecursionError: {exc}"
        index.parse_errors[path] = summary
        index.diagnostics.append(
            diag(
                "ast_recursion",
                f"cannot index {path!r}: {summary}",
                severity="error",
                path=path,
            )
        )
        # Drop anything partially collected from this file so the index never
        # exposes half a symbol table.
        for symbol in state.symbols:
            index.symbols.pop(symbol.symbol_id, None)
            index._symbol_nodes.pop(symbol.symbol_id, None)
        state.symbols = [module_symbol]
        state.calls.clear()
        state.import_specs.clear()
        state.module_import_specs.clear()
        index.symbols[module_symbol.symbol_id] = module_symbol
        index._symbol_fallbacks[module_symbol.symbol_id] = sha256_text(text)
    return state


def _syntax_error_summary(exc: BaseException) -> str:
    if isinstance(exc, SyntaxError):
        message = exc.msg or "invalid syntax"
        if exc.lineno:
            return f"SyntaxError: {message} (line {exc.lineno})"
        return f"SyntaxError: {message}"
    return f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------


def build_index(side: SnapshotSide, config: Config) -> Index:
    """Build the deterministic AST index for one snapshot side."""

    index = Index(side.side)
    paths = sorted(side.contents)
    file_limit = config.analysis.max_python_files_per_side
    if len(paths) > file_limit:
        index.diagnostics.append(
            diag(
                "python_limit",
                f"Python file budget exceeded; indexing the first {file_limit} paths",
                severity="warning",
                details={
                    "side": side.side,
                    "limit": file_limit,
                    "total": len(paths),
                },
            )
        )
        paths = paths[:file_limit]

    total_bytes = 0
    states: list[_FileState] = []
    for path in paths:
        text = side.contents[path]
        total_bytes += len(text.encode("utf-8", "replace"))
        states.append(_scan_file(index, side, config, path, text))

    index._register_modules(states)
    index._build_symbol_tables()
    index._collect_module_assignments(states)

    for state in states:
        for spec in state.import_specs:
            index._resolve_import_spec(state, spec)
    for state in states:
        if state.tree is None:
            continue
        for call, scope in state.calls:
            index._resolve_call(state, call, scope)
    for state in states:
        if state.tree is None:
            continue
        for load, scope in state.name_loads:
            index._resolve_global_read(state, load, scope)

    index._finalize(paths, total_bytes, config)
    return index
