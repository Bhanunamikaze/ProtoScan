"""Command-line entry points for the scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .config import load_config
from .dataflow import build_flow_chains
from .dependency_analysis import analyze_dependencies
from .gadget_detection import find_gadgets
from .payload_library import payload_library
from .reporters import render_human, render_html, render_json, render_sarif, render_csv
from .runtime_detection import detect_runtime
from .sink_detection import find_sinks
from .source_detection import find_sources


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protoscan",
        description="Prototype pollution scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a project")
    scan_parser.add_argument(
        "--project",
        default=".",
        help="Project root to scan (defaults to cwd)",
    )
    scan_parser.add_argument(
        "--config",
        help="Path to configuration file (.protoscanrc.json by default)",
    )
    scan_parser.add_argument(
        "--severity",
        help="Override minimum severity (low|medium|high|critical)",
    )
    scan_parser.add_argument(
        "--runtime-hint",
        action="append",
        default=None,
        help="Provide additional runtime hints (repeatable)",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable cache for this run",
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "sarif", "human", "html", "csv"],
        action="append",
        help="Report format(s) to emit (default: json)",
    )
    scan_parser.add_argument(
        "--output",
        action="append",
        nargs=2,
        metavar=("FORMAT", "PATH"),
        help="Write report to file (e.g., --output sarif report.sarif)",
    )
    scan_parser.add_argument(
        "--bundle",
        help="Zip file path bundling JSON/SARIF/HTML/CSV reports",
    )
    return parser


def _config_overrides(ns: argparse.Namespace) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    if ns.severity:
        overrides["severity"] = ns.severity
    if ns.runtime_hint:
        overrides["runtime_hints"] = ns.runtime_hint
    if ns.no_cache:
        overrides["cache_enabled"] = False
    return overrides


def _handle_scan(ns: argparse.Namespace) -> int:
    project_root = Path(ns.project)
    config = load_config(
        project_root=project_root,
        config_path=Path(ns.config) if ns.config else None,
        overrides=_config_overrides(ns) or None,
    )
    metadata = detect_runtime(project_root)
    dependency_report = analyze_dependencies(project_root)
    source_findings = find_sources(project_root)
    sink_findings = find_sinks(project_root)
    gadget_findings = find_gadgets(project_root)
    flow_chains = build_flow_chains(project_root, source_findings, sink_findings, gadget_findings)
    report = {
        "projectRoot": str(config.project_root),
        "config": config.to_dict(),
        "runtimeDetection": metadata.to_dict(),
        "dependencyReport": dependency_report.to_dict(),
        "sourceFindings": [finding.to_dict() for finding in source_findings],
        "sinkFindings": [finding.to_dict() for finding in sink_findings],
        "gadgetFindings": [finding.to_dict() for finding in gadget_findings],
        "flowChains": [chain.to_dict() for chain in flow_chains],
        "payloadLibrary": payload_library(),
    }
    formats = ns.format or ["json"]
    output_targets: List[Tuple[str, Path]] = []
    for spec in ns.output or []:
        fmt, path_str = spec
        output_targets.append((fmt, Path(path_str)))
    _print_report(report, formats, output_targets, Path(ns.bundle) if ns.bundle else None)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    if args.command == "scan":
        return _handle_scan(args)
    parser.error(f"Unknown command: {args.command}")
    return 1


def _print_report(
    data: Dict[str, object],
    formats: List[str],
    output_targets: List[Tuple[str, Path]],
    bundle_path: Path | None,
) -> None:
    formatters = {
        "json": render_json,
        "sarif": render_sarif,
        "human": render_human,
        "html": render_html,
        "csv": render_csv,
    }
    outputs: Dict[str, str] = {}
    for fmt in formats:
        renderer = formatters.get(fmt)
        if not renderer:
            continue
        outputs[fmt] = renderer(data)
    for idx, (fmt, content) in enumerate(outputs.items(), start=1):
        if len(outputs) > 1:
            print(f"--- {fmt} report {idx}/{len(outputs)} ---")
        print(content)
    for fmt, path in output_targets:
        renderer = formatters.get(fmt)
        if not renderer:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        content = outputs.get(fmt) or renderer(data)
        outputs.setdefault(fmt, content)
        path.write_text(content)

    if bundle_path:
        from zipfile import ZipFile

        bundle_formats = ["json", "sarif", "html", "csv"]
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(bundle_path, "w") as archive:
            for fmt in bundle_formats:
                renderer = formatters.get(fmt)
                if not renderer:
                    continue
                content = outputs.get(fmt) or renderer(data)
                outputs.setdefault(fmt, content)
                extension = "txt" if fmt == "human" else fmt
                archive.writestr(f"report.{extension}", content)


def _collect_route_paths(report: Dict[str, object]) -> List[str]:
    routes: List[str] = []
    for chain in report.get("flowChains", []):
        route = chain.get("route") or {}
        path = str(route.get("path") or "").strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        if path not in routes:
            routes.append(path)
    return routes


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
