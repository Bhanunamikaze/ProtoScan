"""Project-level graph utilities for ProtoScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

from .ast_utils import JS_PARSER, node_text, parser_for_extension, walk


@dataclass(slots=True)
class ProjectGraph:
    exports: Dict[Path, Set[str]] = field(default_factory=dict)
    imports: Dict[Path, List[Tuple[str, Path]]] = field(default_factory=dict)


def _resolve_import(base: Path, specifier: str) -> Path | None:
    if specifier.startswith("."):
        candidate = (base.parent / specifier).resolve()
        if candidate.is_file():
            return candidate
        for ext in (".js", ".ts", ".mjs", ".cjs"):
            if candidate.with_suffix(ext).is_file():
                return candidate.with_suffix(ext)
        if candidate.is_dir():
            for ext in ("index.js", "index.ts"):
                target = candidate / ext
                if target.is_file():
                    return target
    return None


def _collect_exports(path: Path, source: bytes) -> Set[str]:
    parser = parser_for_extension(path.suffix.lower()) or JS_PARSER
    tree = parser.parse(source)
    exports: Set[str] = set()
    for node in walk(tree.root_node):
        if node.type == "export_statement":
            child = node.child_by_field_name("declaration")
            if child and child.type in {"function_declaration", "lexical_declaration"}:
                name = node_text(child.child_by_field_name("name"), source)
                if name:
                    exports.add(name)
        elif node.type == "expression_statement":
            text = node_text(node, source)
            if text.startswith("module.exports"):
                exports.add("__all__")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and left.type == "member_expression":
                object_text = node_text(left.child_by_field_name("object"), source)
                if object_text in {"module.exports", "exports"}:
                    prop = node_text(left.child_by_field_name("property"), source)
                    if prop:
                        exports.add(prop)
    return exports


def _collect_imports(path: Path, source: bytes) -> List[Tuple[str, Path]]:
    parser = parser_for_extension(path.suffix.lower()) or JS_PARSER
    tree = parser.parse(source)
    imports: List[Tuple[str, Path]] = []
    for node in walk(tree.root_node):
        if node.type == "import_statement":
            spec = node_text(node.child_by_field_name("source"), source).strip('"\'')
            resolved = _resolve_import(path, spec)
            if resolved:
                imports.append((spec, resolved))
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for child in node.children:
                if child.type == "variable_declarator":
                    init = child.child_by_field_name("value")
                    if init and node_text(init, source).startswith("require("):
                        arg = node_text(init.child_by_field_name("arguments"), source)
                        spec = arg.strip("()\"'")
                        resolved = _resolve_import(path, spec)
                        if resolved:
                            imports.append((spec, resolved))
    return imports


def build_project_graph(project_root: Path) -> ProjectGraph:
    root = project_root.expanduser().resolve()
    graph = ProjectGraph()
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in {".js", ".ts", ".mjs", ".cjs"}:
            continue
        source = file_path.read_bytes()
        exports = _collect_exports(file_path, source)
        if exports:
            graph.exports[file_path] = exports
        imports = _collect_imports(file_path, source)
        if imports:
            graph.imports[file_path] = imports
    return graph
