"""Lightweight intra-file data flow scaffolding."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .ast_utils import (
    MAX_FILES,
    SUPPORTED_EXTENSIONS,
    identifier_name,
    iter_source_files,
    node_text,
    parser_for_extension,
    walk,
)
from .gadget_detection import GadgetFinding
from .payload_guidance import build_payload_variants
from .payload_library import fingerprint_for_alias, payload_library
from .sink_detection import SinkFinding
from .source_detection import SourceFinding


SEVERITY_BY_GADGET_PREFIX = {
    "gadget.rce": "critical",
    "gadget.template": "high",
    "gadget.fs": "high",
    "gadget.http": "high",
    "gadget.https": "high",
    "gadget.tls": "high",
    "gadget.runtime": "high",
    "gadget.ui": "high",
    "gadget.dom": "high",
    "gadget.client": "high",
    "gadget.deno": "high",
    "gadget.timer": "medium",
}
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_LEVELS)}
SOURCE_KIND_PRIORITY = [
    ("http.", 5),
    ("browser.", 4),
    ("websocket.", 3),
    ("cli.", 2),
    ("config.", 1),
]
DEFAULT_PAYLOAD = '{"__proto__":{"polluted":"yes"}}'
PAYLOAD_TEMPLATES = {
    "sink.object.assign": '{"__proto__":{"polluted":"owned"}}',
    "sink.package.merge": '{"__proto__":{"polluted":"owned"}}',
    "sink.package.deepmerge": '{"__proto__":{"polluted":"owned"}}',
    "sink.package.extend": '{"__proto__":{"polluted":"owned"}}',
    "sink.package.defaults": '{"__proto__":{"polluted":"owned"}}',
    "sink.lodash.set": 'path=__proto__.polluted&value=owned',
    "sink.lodash.defaultsDeep": '{"deepDefaults":{"__proto__":{"polluted":"owned"}}}',
    "sink.parser.qs": 'payload=__proto__.polluted&value=owned',
    "sink.parser.querystring": 'payload=__proto__.polluted&value=owned',
    "sink.parser.ini": "[__proto__]\npolluted=yes",
    "sink.parser.toml": '__proto__ = { polluted = "yes" }',
    "sink.dynamic.property.assignment": '{"dynamicKey":"__proto__","dynamicValue":{"polluted":"owned"}}',
    "sink.json.parse.reviver": '{"payload":"{\\"__proto__\\":{\\"polluted\\":\\"yes\\"}}"}',
    "sink.path.dotProp": '{"path":"__proto__.polluted","value":"owned"}',
    "sink.path.setValue": '{"path":"__proto__.polluted","value":"owned"}',
}
PAYLOAD_HINTS = {
    "sink.parser.qs": "Send payload as query string parameters (e.g., `?payload=...`).",
    "sink.parser.querystring": "Send payload as query string parameters.",
    "sink.parser.ini": "Upload or parse an INI payload containing prototype keys.",
    "sink.parser.toml": "Upload or parse a TOML payload containing prototype keys.",
    "sink.path.dotProp": "Send JSON body with attacker-controlled `path` and `value` fields.",
    "sink.path.setValue": "Send JSON body with attacker-controlled `path` and `value` fields.",
    "sink.dynamic.property.assignment": "Send JSON body controlling both the key and the value fields.",
}
FRIENDLY_SINK_NAMES = {
    "sink.object.assign": "Object.assign merge",
    "sink.object.spread": "object spread merge",
    "sink.dynamic.property.assignment": "dynamic property assignment",
    "sink.dynamic.defineProperty": "Object.defineProperty usage",
    "sink.dynamic.reflectSet": "Reflect.set usage",
    "sink.prototype.setPrototypeOf": "Object.setPrototypeOf call",
    "sink.constructor.prototype": "constructor prototype write",
    "sink.loop.assign": "unsafe merge loop",
    "sink.lodash.merge": "lodash.merge",
    "sink.lodash.defaults": "lodash.defaults",
    "sink.lodash.defaultsDeep": "lodash.defaultsDeep",
    "sink.lodash.extend": "lodash.extend",
    "sink.lodash.set": "lodash.set",
    "sink.jquery.extend": "jQuery.extend",
    "sink.package.merge": "merge package",
    "sink.package.deepmerge": "deepmerge package",
    "sink.package.extend": "extend package",
    "sink.package.defaults": "defaults package",
    "sink.path.dotProp": "dot-prop setter",
    "sink.path.setValue": "set-value helper",
    "sink.json.parse.reviver": "JSON.parse reviver",
    "sink.parser.qs": "qs.parse",
    "sink.parser.querystring": "querystring.parse",
    "sink.parser.ini": "INI parser",
    "sink.parser.toml": "TOML parser",
    "sink.clone.structuredClone": "structuredClone",
}
SINK_ACTIONS = {
    "sink.object.assign": "merge attacker JSON into existing objects",
    "sink.object.spread": "spread attacker-controlled objects into targets",
    "sink.dynamic.property.assignment": "write attacker-controlled keys to runtime objects",
    "sink.lodash.set": "set nested paths (including `__proto__`) on application objects",
    "sink.lodash.defaultsDeep": "deeply merge attacker defaults into config",
    "sink.lodash.defaults": "merge attacker defaults into config",
    "sink.package.merge": "merge arbitrary objects without prototype filtering",
    "sink.package.deepmerge": "deep merge attacker supplied structures",
    "sink.parser.qs": "parse query strings into objects, honoring prototype keys",
    "sink.parser.querystring": "parse query strings into objects, honoring prototype keys",
    "sink.parser.ini": "parse INI configuration into objects",
    "sink.parser.toml": "parse TOML configuration into objects",
    "sink.json.parse.reviver": "revive JSON entries into arbitrary keys",
    "sink.loop.assign": "copy every enumerable key without hasOwnProperty checks",
    "sink.constructor.prototype": "write attacker data directly to constructor prototypes",
}
GADGET_EFFECTS = {
    "gadget.rce.child_process": "execute arbitrary OS commands",
    "gadget.rce.vm": "evaluate attacker-controlled JavaScript in `vm`",
    "gadget.rce.function": "run attacker code through `Function` or similar APIs",
    "gadget.template": "render attacker-controlled templates (XSS/RCE)",
    "gadget.fs": "read or write sensitive files",
    "gadget.http": "abuse HTTP client defaults for SSRF",
    "gadget.https": "abuse HTTPS requests for SSRF",
    "gadget.tls": "redirect TLS connections for SSRF or cert bypass",
    "gadget.runtime": "spawn worker threads or runtimes with attacker options",
    "gadget.ui": "inject attacker-controlled UI flows (React/Vue)",
    "gadget.dom": "bypass DOM sanitizers and execute scripts",
    "gadget.client.dom": "bypass DOM sanitizers and execute attacker HTML",
    "gadget.client.analytics": "hijack analytics/tag managers to load attacker scripts",
    "gadget.client.media": "inject attacker HTML into embedded widgets",
    "gadget.client": "abuse client-side third-party libraries",
    "gadget.deno.run": "execute arbitrary OS commands via Deno.run",
    "gadget.deno.command": "execute arbitrary OS commands via Deno.Command",
    "gadget.deno.temp": "create attacker-controlled temp paths (path traversal)",
    "gadget.deno.fs": "write or modify arbitrary files via Deno file APIs",
    "gadget.deno": "abuse privileged Deno runtime APIs",
}

@dataclass(frozen=True, slots=True)
class FlowChain:
    """Represents a simple source → sink (+ gadget) relationship."""

    source: SourceFinding
    sink: SinkFinding
    gadget: GadgetFinding | None = None
    severity: str = "medium"
    metadata: Dict[str, bool] = field(default_factory=dict)
    route: Optional[Tuple[str, str]] = None
    exploit_steps: List[str] = field(default_factory=list)
    description: str = ""
    validation: str = ""
    exploit_example: str = ""
    payload_variants: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "gadget": self.gadget.to_dict() if self.gadget else None,
            "severity": self.severity,
            "metadata": dict(self.metadata),
            "route": {"method": self.route[0], "path": self.route[1]} if self.route else None,
            "exploitSteps": list(self.exploit_steps),
            "description": self.description,
            "validation": self.validation,
            "exploitExample": self.exploit_example,
            "payloadVariants": list(self.payload_variants),
        }


@dataclass(frozen=True, slots=True)
class ModuleBinding:
    """Represents how a local identifier maps to an imported module."""

    module_path: Path
    export: Optional[str] = None  # None indicates default export
    namespace: bool = False


@dataclass(frozen=True, slots=True)
class CallEdge:
    """A call from one file into an imported module export."""

    caller: Path
    callee: Path
    export: Optional[str]
    arg_names: List[str | None]


class FileFlowGraph:
    """Tracks simple variable aliases inside a file."""

    def __init__(self) -> None:
        self.aliases: dict[str, set[str]] = {}

    def add_alias(self, target: str, source: str) -> None:
        group = self.aliases.setdefault(target, set())
        group.add(source)

    def related(self, target: str) -> set[str]:
        visited = set()
        stack = [target]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for alias, sources in self.aliases.items():
                if alias == current:
                    stack.extend(sources)
                elif current in sources:
                    stack.append(alias)
        return visited


@dataclass(slots=True)
class FileAnalysis:
    """Holds reusable per-file analysis artifacts."""

    path: Path
    graph: FileFlowGraph
    validated_variables: Set[str]
    requires_auth: bool
    routes: List[Dict[str, object]]
    named_exports: Dict[str, List[str]]
    default_export: Optional[List[str]]
    imports: Dict[str, ModuleBinding]
    call_edges: List[CallEdge]


def _call_arg_identifier(node, source: bytes) -> str | None:
    args = node.child_by_field_name("arguments")
    if not args or not args.named_children:
        return None
    return identifier_name(args.named_children[0], source)


def _record_alias(graph: FileFlowGraph, target: str | None, source: str | None) -> None:
    if not target or not source:
        return
    graph.add_alias(target, source)
    if "." in source:
        parent = source.rsplit(".", 1)[0]
        if parent and parent != source:
            graph.add_alias(target, parent)
    if "." in target:
        target_parent = target.rsplit(".", 1)[0]
        if target_parent and target_parent != target:
            graph.add_alias(target_parent, source)


def _handle_object_pattern(graph, pattern, base_name: str | None, source_bytes: bytes) -> None:
    if not base_name or pattern is None:
        return

    def _record(local: str | None, prop: str | None) -> None:
        if not local:
            return
        prop_source = f"{base_name}.{prop}" if prop else base_name
        _record_alias(graph, local, prop_source)
        _record_alias(graph, local, base_name)

    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            name = identifier_name(child, source_bytes)
            _record(name, name)
        elif child.type == "object_assignment_pattern":
            left = child.child_by_field_name("left")
            name = identifier_name(left, source_bytes)
            _record(name, identifier_name(left, source_bytes))
            value = child.child_by_field_name("right")
            if value and value.type == "object_pattern":
                sub_base = f"{base_name}.{identifier_name(left, source_bytes)}"
                _handle_object_pattern(graph, value, sub_base, source_bytes)
        elif child.type == "pair_pattern":
            key_node = child.child_by_field_name("key")
            prop_name = identifier_name(key_node, source_bytes)
            value_node = child.child_by_field_name("value")
            if value_node is None:
                continue
            if value_node.type == "identifier":
                local = identifier_name(value_node, source_bytes)
                _record(local, prop_name or local)
            elif value_node.type == "assignment_pattern":
                left = value_node.child_by_field_name("left")
                local = identifier_name(left, source_bytes)
                _record(local, prop_name or local)
            elif value_node.type == "object_pattern":
                new_base = f"{base_name}.{prop_name}" if prop_name else base_name
                _handle_object_pattern(graph, value_node, new_base, source_bytes)
            else:
                local = identifier_name(value_node, source_bytes)
                _record(local, prop_name or local)
        elif child.type == "assignment_pattern":
            left = child.child_by_field_name("left")
            name = identifier_name(left, source_bytes)
            _record(name, identifier_name(left, source_bytes))


def _arrow_function_return_expr(node, source_bytes: bytes) -> Optional[Dict[str, object]]:
    if node is None or node.type != "arrow_function":
        return None
    body = node.child_by_field_name("body")
    if body is None or body.type == "statement_block":
        return None
    expression = identifier_name(body, source_bytes)
    if not expression:
        return None
    return {"expression": expression, "params": _extract_params(node, source_bytes)}


def _collect_implicit_returns(tree, source_bytes: bytes) -> Dict[str, Dict[str, object]]:
    implicit: Dict[str, Dict[str, object]] = {}
    for node in walk(tree.root_node):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        name = identifier_name(name_node, source_bytes)
        if not name:
            continue
        details = _arrow_function_return_expr(value_node, source_bytes)
        if details and details.get("expression"):
            implicit[name] = details
    return implicit


def _resolve_call_alias(node, source_bytes: bytes, implicit_returns: Dict[str, Dict[str, object]]) -> Optional[str]:
    func = node.child_by_field_name("function")
    if func is None or func.type != "identifier":
        return None
    func_name = identifier_name(func, source_bytes)
    if not func_name:
        return None
    details = implicit_returns.get(func_name)
    if not details:
        return None
    expression = details.get("expression")
    if not expression:
        return None
    params = details.get("params") or []
    args = _argument_identifiers(node.child_by_field_name("arguments"), source_bytes)
    alias = expression
    for idx, param in enumerate(params):
        if not param:
            continue
        arg = args[idx] if idx < len(args) else None
        if not arg:
            continue
        if alias == param:
            alias = arg
        elif alias.startswith(param + "."):
            suffix = alias[len(param) + 1 :]
            alias = f"{arg}.{suffix}"
    return alias


def _enclosing_class_name(node, source_bytes: bytes) -> Optional[str]:
    current = node
    while current is not None:
        if current.type == "class_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return node_text(name_node, source_bytes)
        current = current.parent
    return None


def _field_target_name(node, source_bytes: bytes) -> Optional[str]:
    prop_node = None
    for child in node.children:
        if child.type in {"property_identifier", "private_property_identifier"}:
            prop_node = child
            break
    if prop_node is None:
        return None
    prop_name = node_text(prop_node, source_bytes)
    if not prop_name:
        return None
    is_static = any(child.type == "static" for child in node.children)
    if is_static:
        class_name = _enclosing_class_name(node, source_bytes)
        if not class_name:
            return None
        return f"{class_name}.{prop_name}"
    return f"this.{prop_name}"


def _field_value_node(node):
    for child in node.named_children:
        if child.type not in {"property_identifier", "private_property_identifier"}:
            return child
    return None


def _build_aliases(tree, source_bytes: bytes) -> FileFlowGraph:
    graph = FileFlowGraph()
    implicit_returns = _collect_implicit_returns(tree, source_bytes)
    for node in walk(tree.root_node):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None:
                continue
            if name_node.type == "object_pattern":
                base_name = identifier_name(value_node, source_bytes)
                _handle_object_pattern(graph, name_node, base_name, source_bytes)
                continue
            name = identifier_name(name_node, source_bytes)
            value = identifier_name(value_node, source_bytes)
            if name and value:
                _record_alias(graph, name, value)
            elif name and value_node and value_node.type == "call_expression":
                call_alias = _resolve_call_alias(value_node, source_bytes, implicit_returns)
                if call_alias:
                    _record_alias(graph, name, call_alias)
                else:
                    arg_name = _call_arg_identifier(value_node, source_bytes)
                    if arg_name:
                        _record_alias(graph, name, arg_name)
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            if left_node is None:
                continue
            if left_node.type == "object_pattern":
                base_name = identifier_name(right_node, source_bytes)
                _handle_object_pattern(graph, left_node, base_name, source_bytes)
                continue
            left = identifier_name(left_node, source_bytes)
            right = identifier_name(right_node, source_bytes)
            if left and right:
                _record_alias(graph, left, right)
            elif left and right_node and right_node.type == "call_expression":
                call_alias = _resolve_call_alias(right_node, source_bytes, implicit_returns)
                if call_alias:
                    _record_alias(graph, left, call_alias)
                else:
                    arg_name = _call_arg_identifier(right_node, source_bytes)
                    if arg_name:
                        _record_alias(graph, left, arg_name)
        elif node.type == "field_definition":
            target = _field_target_name(node, source_bytes)
            value_node = _field_value_node(node)
            value = identifier_name(value_node, source_bytes)
            if target and value:
                _record_alias(graph, target, value)
    return graph


def _parameter_names(node, source_bytes: bytes) -> List[str]:
    if node is None:
        return []
    if node.type == "identifier":
        name = identifier_name(node, source_bytes)
        return [name] if name else []
    names: List[str] = []
    for child in node.named_children:
        name = identifier_name(child, source_bytes)
        if name:
            names.append(name)
    return names


def _extract_params(node, source_bytes: bytes) -> List[str]:
    if node is None:
        return []
    params_node = node.child_by_field_name("parameters")
    if params_node is None and node.type == "arrow_function":
        single_param = node.child_by_field_name("parameter")
        if single_param is not None:
            return _parameter_names(single_param, source_bytes)
    return _parameter_names(params_node, source_bytes)


def _collect_function_definitions(tree, source_bytes: bytes) -> Dict[str, List[str]]:
    functions: Dict[str, List[str]] = {}
    for node in walk(tree.root_node):
        if node.type == "function_declaration":
            name = identifier_name(node.child_by_field_name("name"), source_bytes)
            if name:
                functions[name] = _extract_params(node, source_bytes)
        elif node.type == "variable_declarator":
            name = identifier_name(node.child_by_field_name("name"), source_bytes)
            value = node.child_by_field_name("value")
            if not name or value is None:
                continue
            if value.type in {"function", "function_expression", "arrow_function"}:
                functions[name] = _extract_params(value, source_bytes)
    return functions


def _string_literal_value(node, source_bytes: bytes) -> Optional[str]:
    if node is None:
        return None
    if node.type in {"string", "template_string"}:
        text = node_text(node, source_bytes).strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
            return text[1:-1]
        return text
    if node.type == "string_fragment":
        return node_text(node, source_bytes)
    return None


def _resolve_module_path(current_file: Path, literal: Optional[str]) -> Optional[Path]:
    if not literal:
        return None
    literal = literal.strip()
    if not literal:
        return None
    if literal.startswith("."):
        base = (current_file.parent / literal).resolve()
    elif literal.startswith("/"):
        base = Path(literal).resolve()
    else:
        return None
    candidates: List[Path] = []
    if base.is_file():
        candidates.append(base)
    if base.suffix:
        candidates.append(base)
    else:
        for ext in SUPPORTED_EXTENSIONS:
            candidates.append(base.with_suffix(ext))
    if base.is_dir():
        for ext in SUPPORTED_EXTENSIONS:
            candidates.append((base / f"index{ext}"))
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def _collect_imports(path: Path, tree, source_bytes: bytes) -> Dict[str, ModuleBinding]:
    bindings: Dict[str, ModuleBinding] = {}
    for node in walk(tree.root_node):
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            literal = _string_literal_value(source_node, source_bytes)
            target = _resolve_module_path(path, literal)
            if not target:
                continue
            clause = None
            for child in node.children:
                if child.type == "import_clause":
                    clause = child
                    break
            if clause is None:
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    name = identifier_name(child, source_bytes)
                    if name:
                        bindings[name] = ModuleBinding(target, export=None, namespace=False)
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        if spec.type != "import_specifier":
                            continue
                        export_name = identifier_name(spec.child_by_field_name("name"), source_bytes)
                        local_name = identifier_name(spec.child_by_field_name("alias"), source_bytes) or export_name
                        if local_name and export_name:
                            bindings[local_name] = ModuleBinding(target, export=export_name, namespace=False)
                elif child.type == "namespace_import":
                    identifier_node = child.child_by_field_name("name")
                    if identifier_node is None:
                        identifier_node = child.child_by_field_name("alias")
                    if identifier_node is None:
                        identifier_node = next((c for c in child.children if c.type == "identifier"), None)
                    name = identifier_name(identifier_node, source_bytes)
                    if name:
                        bindings[name] = ModuleBinding(target, export=None, namespace=True)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is None or value.type != "call_expression":
                continue
            func = value.child_by_field_name("function")
            if func is None or identifier_name(func, source_bytes) != "require":
                continue
            args = value.child_by_field_name("arguments")
            literal = None
            if args and args.named_children:
                literal = _string_literal_value(args.named_children[0], source_bytes)
            target = _resolve_module_path(path, literal)
            if not target:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            if name_node.type == "identifier":
                name = identifier_name(name_node, source_bytes)
                if name:
                    bindings[name] = ModuleBinding(target, export=None, namespace=True)
            elif name_node.type == "object_pattern":
                for prop in name_node.named_children:
                    if prop.type == "pair_pattern":
                        export_name = identifier_name(prop.child_by_field_name("key"), source_bytes)
                        local_name = identifier_name(prop.child_by_field_name("value"), source_bytes)
                    else:
                        export_name = identifier_name(prop, source_bytes)
                        local_name = export_name
                    if local_name and export_name:
                        bindings[local_name] = ModuleBinding(target, export=export_name, namespace=False)
    return bindings


def _argument_identifiers(node, source_bytes: bytes) -> List[Optional[str]]:
    if node is None:
        return []
    names: List[Optional[str]] = []
    for child in node.named_children:
        names.append(identifier_name(child, source_bytes))
    return names


def _collect_call_edges(path: Path, tree, source_bytes: bytes, imports: Dict[str, ModuleBinding]) -> List[CallEdge]:
    edges: List[CallEdge] = []
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        args = _argument_identifiers(node.child_by_field_name("arguments"), source_bytes)
        if func is None:
            continue
        if func.type == "identifier":
            name = identifier_name(func, source_bytes)
            binding = imports.get(name or "")
            if not binding:
                continue
            edges.append(CallEdge(path, binding.module_path, binding.export, args))
        elif func.type == "member_expression":
            base = identifier_name(func.child_by_field_name("object"), source_bytes)
            prop = identifier_name(func.child_by_field_name("property"), source_bytes)
            binding = imports.get(base or "")
            if not binding or not prop:
                continue
            edges.append(CallEdge(path, binding.module_path, prop, args))
    return edges


def _params_from_value(value, source_bytes: bytes, functions: Dict[str, List[str]]) -> List[str]:
    if value is None:
        return []
    if value.type in {"function", "function_expression", "arrow_function"}:
        return _extract_params(value, source_bytes)
    return functions.get(identifier_name(value, source_bytes) or "", [])


def _collect_exports(tree, source_bytes: bytes, functions: Dict[str, List[str]]) -> Tuple[Dict[str, List[str]], Optional[List[str]]]:
    named: Dict[str, List[str]] = {}
    default_export: Optional[List[str]] = None

    def record_named(name: Optional[str], params: List[str]) -> None:
        if name and params:
            named[name] = params

    for node in walk(tree.root_node):
        if node.type == "export_statement":
            is_default = any(child.type == "default" for child in node.children)
            payload = [child for child in node.named_children if child.type not in {"export", "default"}]
            for target in payload:
                if target.type == "function_declaration":
                    name = identifier_name(target.child_by_field_name("name"), source_bytes)
                    params = _extract_params(target, source_bytes)
                    if is_default and params:
                        default_export = params
                    else:
                        record_named(name, params)
                elif target.type == "lexical_declaration":
                    for declarator in target.named_children:
                        if declarator.type != "variable_declarator":
                            continue
                        var_name = identifier_name(declarator.child_by_field_name("name"), source_bytes)
                        params = _params_from_value(declarator.child_by_field_name("value"), source_bytes, functions)
                        if is_default and params:
                            default_export = params
                        else:
                            record_named(var_name, params)
                elif target.type == "identifier":
                    params = functions.get(identifier_name(target, source_bytes) or "", [])
                    if is_default and params:
                        default_export = params
                    else:
                        record_named(identifier_name(target, source_bytes), params)
                elif target.type in {"function_expression", "arrow_function"}:
                    params = _extract_params(target, source_bytes)
                    if is_default and params:
                        default_export = params
                elif target.type == "export_clause":
                    for spec in target.named_children:
                        if spec.type != "export_specifier":
                            continue
                        export_name = identifier_name(spec.child_by_field_name("alias"), source_bytes) or identifier_name(
                            spec.child_by_field_name("name"), source_bytes
                        )
                        reference = identifier_name(spec.child_by_field_name("name"), source_bytes)
                        params = functions.get(reference or "", [])
                        record_named(export_name, params)
        elif node.type == "assignment_expression":
            left = identifier_name(node.child_by_field_name("left"), source_bytes)
            value = node.child_by_field_name("right")
            if left == "module.exports":
                if value and value.type == "object":
                    for prop in value.named_children:
                        if prop.type == "pair":
                            export_name = identifier_name(prop.child_by_field_name("key"), source_bytes)
                            params = _params_from_value(prop.child_by_field_name("value"), source_bytes, functions)
                            record_named(export_name, params)
                        elif prop.type == "shorthand_property_identifier":
                            name = identifier_name(prop, source_bytes) or node_text(prop, source_bytes).strip()
                            record_named(name, functions.get(name or "", []))
                        elif prop.type == "method_definition":
                            export_name = identifier_name(prop.child_by_field_name("name"), source_bytes)
                            params = _parameter_names(prop.child_by_field_name("parameters"), source_bytes)
                            record_named(export_name, params)
                else:
                    params = _params_from_value(value, source_bytes, functions)
                    if params:
                        default_export = params
            elif left and left.startswith("module.exports."):
                export_name = left.split(".", 2)[2] if "." in left else None
                params = _params_from_value(value, source_bytes, functions)
                record_named(export_name, params)
            elif left and left.startswith("exports."):
                export_name = left.split(".", 1)[1]
                params = _params_from_value(value, source_bytes, functions)
                record_named(export_name, params)
    return named, default_export


def _is_truthy_literal(node, source_bytes: bytes) -> bool:
    if node is None:
        return False
    node_type = node.type
    if node_type == "true":
        return True
    if node_type in {"false", "null"}:
        return False
    if node_type == "number":
        try:
            return float(node_text(node, source_bytes)) != 0
        except ValueError:
            return False
    if node_type == "string":
        value = node_text(node, source_bytes).strip("\"'`").lower()
        return value in {"true", "1", "yes"}
    return False


def _object_has_strip_unknown(option_node, source_bytes: bytes) -> bool:
    if option_node is None or option_node.type != "object":
        return False
    for prop in option_node.named_children:
        if prop.type != "pair":
            continue
        key = identifier_name(prop.child_by_field_name("key"), source_bytes)
        value = prop.child_by_field_name("value")
        if key == "stripUnknown" and _is_truthy_literal(value, source_bytes):
            return True
        if key == "unknown" and value is not None and value.type == "string":
            literal = node_text(value, source_bytes).strip("\"'`").lower()
            if literal == "strip":
                return True
    return False


def _validation_strips_unknown(node, source_bytes: bytes) -> bool:
    args = node.child_by_field_name("arguments")
    if not args or len(args.named_children) < 2:
        return False
    for arg in args.named_children[1:]:
        if _object_has_strip_unknown(arg, source_bytes):
            return True
    return False


def _detect_schema_validations(tree, source_bytes: bytes) -> Set[str]:
    validated: Set[str] = set()
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        func_name = None
        if func.type == "member_expression":
            func_name = identifier_name(func.child_by_field_name("property"), source_bytes)
        else:
            func_name = identifier_name(func, source_bytes)
        if func_name not in {"validate", "validateSync", "safeParse"}:
            continue
        strips_unknown = _validation_strips_unknown(node, source_bytes)
        if not strips_unknown:
            continue
        arg_name = _call_arg_identifier(node, source_bytes)
        if arg_name:
            validated.add(arg_name)
        parent = node.parent
        target = None
        if parent and parent.type == "variable_declarator":
            target = identifier_name(parent.child_by_field_name("name"), source_bytes)
        elif parent and parent.type == "assignment_expression":
            target = identifier_name(parent.child_by_field_name("left"), source_bytes)
        if target:
            validated.add(target)
    return validated


def _detect_requires_auth(source_text: str) -> bool:
    keywords = ("requireAuth", "ensureAuth", "authMiddleware")
    return any(keyword in source_text for keyword in keywords)


def _detect_routes(tree, source_bytes: bytes) -> List[Dict[str, object]]:
    routes: List[Dict[str, object]] = []
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            continue
        obj = identifier_name(func.child_by_field_name("object"), source_bytes)
        method = identifier_name(func.child_by_field_name("property"), source_bytes)
        if obj not in {"app", "router"} or method not in {"get", "post", "put", "delete", "patch"}:
            continue
        args = node.child_by_field_name("arguments")
        if not args or len(args.named_children) < 2:
            continue
        path_literal = args.named_children[0]
        handler = args.named_children[-1]
        route_path = node_text(path_literal, source_bytes).strip().strip("\"'`")
        body_text = node_text(handler, source_bytes)
        routes.append(
            {
                "method": method.upper() if method else "GET",
                "path": route_path or "unknown",
                "start_line": handler.start_point[0] + 1,
                "end_line": handler.end_point[0] + 1,
                "requires_auth": "requireAuth" in body_text or "ensureAuth" in body_text,
                "has_validation": "stripUnknown" in body_text or "unknown:" in body_text,
            }
        )
    return routes


def _source_identifier(snippet: str) -> Optional[str]:
    snippet = snippet.strip()
    if not snippet:
        return None
    return snippet.split(" ")[0]


def _propagate_alias(graph: FileFlowGraph, tokens: Dict[str, Set[int]], alias: str) -> None:
    sources = tokens.get(alias)
    if not sources:
        return
    for related in graph.related(alias):
        tokens.setdefault(related, set()).update(sources)


def _add_sources(graph: FileFlowGraph, tokens: Dict[str, Set[int]], alias: str, source_ids: Set[int]) -> bool:
    if not alias or not source_ids:
        return False
    entry = tokens.setdefault(alias, set())
    before = len(entry)
    entry.update(source_ids)
    if len(entry) > before:
        _propagate_alias(graph, tokens, alias)
        return True
    return False


def _aliases_for_source(tokens: Dict[str, Set[int]], source_id: int) -> Set[str]:
    return {alias for alias, owners in tokens.items() if source_id in owners and alias}


def _find_route_for_line(routes: List[Dict[str, object]], line: int) -> Optional[Dict[str, object]]:
    for route in routes:
        if route["start_line"] <= line <= route["end_line"]:
            return route
    return None


def _route_tuple(route: Optional[Dict[str, object]]) -> Optional[Tuple[str, str]]:
    if not route:
        return None
    method = str(route.get("method") or "").strip().upper()
    path = str(route.get("path") or "").strip()
    if not method and not path:
        return None
    return (method, path)


def _params_for_export(info: FileAnalysis, export_name: Optional[str]) -> List[str]:
    if export_name:
        return info.named_exports.get(export_name, [])
    return info.default_export or []


def _severity_for_gadget(gadget: GadgetFinding | None) -> str:
    if gadget is None:
        return "medium"
    for prefix, severity in SEVERITY_BY_GADGET_PREFIX.items():
        if gadget.kind.startswith(prefix):
            return severity
    return "medium"


def _downgrade_severity(base: str, steps: int) -> str:
    try:
        idx = SEVERITY_LEVELS.index(base)
    except ValueError:
        idx = 1
    new_idx = max(0, idx - steps)
    return SEVERITY_LEVELS[new_idx]


def _source_kind_priority(kind: str | None) -> int:
    kind = kind or ""
    for prefix, score in SOURCE_KIND_PRIORITY:
        if kind.startswith(prefix):
            return score
    return 0


def _chain_priority(chain: FlowChain) -> tuple[int, int, int]:
    severity_score = SEVERITY_RANK.get(chain.severity, 1)
    route_score = 1 if chain.route else 0
    source_score = _source_kind_priority(chain.source.kind)
    return (severity_score, route_score, source_score)


def _friendly_sink_name(kind: str | None) -> str:
    if not kind:
        return "prototype pollution sink"
    return FRIENDLY_SINK_NAMES.get(kind, kind)


def _sink_action(kind: str | None) -> str:
    if not kind:
        return "mutate object prototypes"
    return SINK_ACTIONS.get(kind, "mutate object prototypes with attacker data")


def _payload_example(kind: str | None) -> str:
    if not kind:
        return DEFAULT_PAYLOAD
    return PAYLOAD_TEMPLATES.get(kind, DEFAULT_PAYLOAD)


def _payload_hint(kind: str | None) -> str:
    if not kind:
        return "Send payload below as JSON body."
    return PAYLOAD_HINTS.get(kind, "Send payload below as JSON body.")


def _gadget_effect_text(gadget: GadgetFinding | None) -> str:
    if gadget is None:
        return "Poisoned prototypes impact subsequent object creations."
    for prefix, effect in GADGET_EFFECTS.items():
        if gadget.kind.startswith(prefix):
            return effect
    return "Escalate impact using polluted prototype properties."


def build_flow_chains(
    project_root: Path,
    sources: List[SourceFinding],
    sinks: List[SinkFinding],
    gadgets: List[GadgetFinding],
    max_files: int = MAX_FILES,
) -> List[FlowChain]:
    """Match sources to sinks across files using a lightweight project graph."""

    root = project_root.expanduser().resolve()
    findings: Dict[tuple, FlowChain] = {}
    finding_order: List[tuple] = []

    sinks_by_file: Dict[Path, List[SinkFinding]] = {}
    for sink in sinks:
        sinks_by_file.setdefault(sink.path, []).append(sink)
    gadgets_by_file: Dict[Path, List[GadgetFinding]] = {}
    for gadget in gadgets:
        gadgets_by_file.setdefault(gadget.path, []).append(gadget)

    all_files = iter_source_files(root)
    analyses: Dict[Path, FileAnalysis] = {}
    for path in all_files:
        parser = parser_for_extension(path.suffix.lower())
        if not parser:
            continue
        try:
            source_bytes = path.read_bytes()
        except OSError:
            continue
        tree = parser.parse(source_bytes)
        functions = _collect_function_definitions(tree, source_bytes)
        imports = _collect_imports(path, tree, source_bytes)
        named_exports, default_export = _collect_exports(tree, source_bytes, functions)
        analyses[path] = FileAnalysis(
            path=path,
            graph=_build_aliases(tree, source_bytes),
            validated_variables=_detect_schema_validations(tree, source_bytes),
            requires_auth=_detect_requires_auth(source_bytes.decode("utf-8", errors="ignore")),
            routes=_detect_routes(tree, source_bytes),
            named_exports=named_exports,
            default_export=default_export,
            imports=imports,
            call_edges=_collect_call_edges(path, tree, source_bytes, imports),
        )

    call_edges_by_path: Dict[Path, List[CallEdge]] = defaultdict(list)
    for info in analyses.values():
        for edge in info.call_edges:
            if edge.callee in analyses:
                call_edges_by_path[edge.caller].append(edge)

    tokens: Dict[Path, Dict[str, Set[int]]] = defaultdict(dict)
    queue: deque[Path] = deque()
    queued: Set[Path] = set()

    def enqueue(path: Path) -> None:
        if path in analyses and path not in queued:
            queue.append(path)
            queued.add(path)

    for idx, source in enumerate(sources):
        info = analyses.get(source.path)
        alias = _source_identifier(source.snippet)
        if not info or not alias:
            continue
        if _add_sources(info.graph, tokens[source.path], alias, {idx}):
            enqueue(source.path)

    while queue:
        path = queue.popleft()
        queued.discard(path)
        info = analyses.get(path)
        if not info:
            continue
        current_tokens = tokens[path]
        for edge in call_edges_by_path.get(path, []):
            callee_info = analyses.get(edge.callee)
            if not callee_info:
                continue
            params = _params_for_export(callee_info, edge.export)
            if not params:
                continue
            for position, arg_name in enumerate(edge.arg_names):
                if arg_name is None or position >= len(params):
                    continue
                source_ids = current_tokens.get(arg_name)
                if not source_ids:
                    continue
                param_name = params[position]
                if not param_name:
                    continue
                added = _add_sources(callee_info.graph, tokens[edge.callee], param_name, set(source_ids))
                if added:
                    enqueue(edge.callee)

    source_route_map: Dict[int, Optional[Dict[str, object]]] = {}
    for idx, source in enumerate(sources):
        info = analyses.get(source.path)
        route = _find_route_for_line(info.routes, source.line) if info else None
        source_route_map[idx] = route

    for path, sink_list in sinks_by_file.items():
        analysis = analyses.get(path)
        if not analysis:
            continue
        file_tokens = tokens.get(path, {})
        if not file_tokens:
            continue

        gadget = None
        if path in gadgets_by_file:
            gadget = max(gadgets_by_file[path], key=lambda item: SEVERITY_RANK.get(_severity_for_gadget(item), 1))
        base_severity = _severity_for_gadget(gadget)

        for sink in sink_list:
            snippet = sink.snippet
            matching_sources: Set[int] = set()
            for alias, source_ids in file_tokens.items():
                if alias and alias in snippet:
                    matching_sources.update(source_ids)
            if not matching_sources:
                continue
            for source_id in sorted(matching_sources):
                source = sources[source_id]
                source_tokens = tokens.get(source.path, {})
                sink_aliases = _aliases_for_source(file_tokens, source_id)
                source_aliases = _aliases_for_source(source_tokens, source_id)

                route_info = _find_route_for_line(analysis.routes, sink.line)
                route_tuple = _route_tuple(route_info)
                route_requires_auth = route_info.get("requires_auth") if route_info else None
                has_validation = bool(route_info.get("has_validation")) if route_info else False

                source_route = source_route_map.get(source_id)
                source_route_tuple = _route_tuple(source_route)

                if route_tuple and source_route_tuple and route_tuple != source_route_tuple:
                    continue

                if not route_tuple and source_route:
                    route_tuple = source_route_tuple
                if route_requires_auth is None:
                    if source_route and source_route.get("requires_auth") is not None:
                        route_requires_auth = source_route.get("requires_auth")
                    else:
                        source_info = analyses.get(source.path)
                        route_requires_auth = source_info.requires_auth if source_info else False

                if not has_validation and sink_aliases & analysis.validated_variables:
                    has_validation = True
                if not has_validation and source_route and source_route.get("has_validation"):
                    has_validation = True
                if not has_validation:
                    source_info = analyses.get(source.path)
                    if source_info and source_aliases & source_info.validated_variables:
                        has_validation = True

                metadata = {
                    "requiresAuth": bool(route_requires_auth),
                    "hasSchemaValidation": has_validation,
                }
                metadata["clientGadget"] = False
                downgrade_steps = int(metadata["requiresAuth"]) + int(metadata["hasSchemaValidation"])
                severity = _downgrade_severity(base_severity, downgrade_steps)

                route_text = f"{route_tuple[0]} {route_tuple[1]}" if route_tuple else "an exported function"
                sink_location = f"{sink.path}:{sink.line}"
                friendly_sink = _friendly_sink_name(sink.kind)
                sink_action = _sink_action(sink.kind)
                payload_example = _payload_example(sink.kind)
                payload_hint = _payload_hint(sink.kind)
                gadget_effect = _gadget_effect_text(gadget)
                fingerprint = None
                if gadget:
                    fingerprint = fingerprint_for_alias(gadget.kind)
                    impact = fingerprint.get("impact") if fingerprint else None
                    metadata["gadgetImpact"] = impact or gadget_effect
                    requirement = fingerprint.get("requirement") if fingerprint else None
                    if requirement:
                        metadata["gadgetRequirement"] = requirement
                    if fingerprint and fingerprint.get("name"):
                        metadata["gadgetFingerprint"] = fingerprint["name"]
                    if gadget.kind.startswith(("gadget.client", "gadget.dom", "gadget.ui")):
                        metadata["clientGadget"] = True
                    elif fingerprint and fingerprint.get("category", "").lower() == "client":
                        metadata["clientGadget"] = True

                steps = [
                    f"{route_text} accepts attacker-controlled input",
                    f"{friendly_sink} at {sink_location} executes and {sink_action}",
                ]
                if gadget:
                    steps.append(f"Polluted data reaches {gadget.kind}, enabling attackers to {gadget_effect}")
                else:
                    steps.append("Polluted prototypes remain globally accessible for subsequent operations")

                description = (
                    f"Attacker input from {route_text} reaches {friendly_sink} at {sink_location}, "
                    f"allowing an adversary to {sink_action}."
                )
                if gadget:
                    description += f" The polluted state then enables them to {gadget_effect}."
                else:
                    description += " The polluted prototype impacts any future object creations and library calls."

                validation_parts = []
                if metadata["requiresAuth"]:
                    validation_parts.append("Requires authenticated request (x-auth header).")
                else:
                    validation_parts.append("Reachable anonymously.")
                if metadata["hasSchemaValidation"]:
                    validation_parts.append("Input passes schema.validate but prototype keys are not stripped.")
                else:
                    validation_parts.append("No schema stripping detected; prototype keys will be accepted.")
                validation_parts.append(payload_hint)
                validation_parts.append("Replay the payload below to observe prototype pollution.")
                validation = " ".join(validation_parts)
                payload_variants = build_payload_variants(
                    source.kind,
                    route_tuple,
                    metadata,
                    gadget.kind if gadget else None,
                    fallback_payload=payload_example,
                )
                exploit_example = payload_variants[0]["payload"] if payload_variants else payload_example

                chain = FlowChain(
                    source=source,
                    sink=sink,
                    gadget=gadget,
                    severity=severity,
                    metadata=metadata,
                    route=route_tuple,
                    exploit_steps=steps,
                    description=description,
                    validation=validation,
                    exploit_example=exploit_example,
                    payload_variants=payload_variants,
                )
                key = (
                    route_tuple,
                    sink.path,
                    sink.line,
                    sink.kind,
                    gadget.kind if gadget else None,
                )
                if key not in findings:
                    findings[key] = chain
                    finding_order.append(key)
                else:
                    existing = findings[key]
                    if _chain_priority(chain) > _chain_priority(existing):
                        findings[key] = chain

    ordered = [findings[key] for key in finding_order]
    return ordered[:100]
