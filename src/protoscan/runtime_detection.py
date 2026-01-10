"""Runtime and framework detection heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Dict, Iterable, Mapping

NODE_FILE_SIGNATURES = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".nvmrc",
    "nodemon.json",
    "ecosystem.config.js",
)
DENO_FILE_SIGNATURES = ("deno.json", "deno.jsonc", "import_map.json")
BUN_FILE_SIGNATURES = ("bun.lockb", "bunfig.toml")
TYPESCRIPT_FILES = ("tsconfig.json",)
BROWSER_HTML_FILES = ("public/index.html",)

FRAMEWORK_DEPENDENCIES: Mapping[str, str] = {
    "express": "Express.js",
    "fastify": "Fastify",
    "koa": "Koa",
    "hapi": "Hapi",
    "@nestjs/core": "NestJS",
    "next": "Next.js",
    "nuxt": "Nuxt.js",
    "apollo-server": "Apollo GraphQL",
}

BUILD_TOOL_FILES: Mapping[str, str] = {
    "webpack.config.js": "Webpack",
    "vite.config.js": "Vite",
    "rollup.config.js": "Rollup",
    "parcel.config.js": "Parcel",
    "esbuild.config.js": "esbuild",
}

BUILD_TOOL_DEPENDENCIES: Mapping[str, str] = {
    "webpack": "Webpack",
    "vite": "Vite",
    "rollup": "Rollup",
    "parcel-bundler": "Parcel",
    "esbuild": "esbuild",
}

BROWSER_DEPENDENCIES = {
    "react",
    "react-dom",
    "vue",
    "nuxt",
    "next",
    "svelte",
    "@sveltejs/kit",
    "angular",
    "preact",
}
SUBPROJECT_SIGNATURES = tuple(
    sorted(
        {
            *NODE_FILE_SIGNATURES,
            *DENO_FILE_SIGNATURES,
            *BUN_FILE_SIGNATURES,
            *TYPESCRIPT_FILES,
            "package.json",
            "public/index.html",
        }
    )
)
IGNORED_DIR_NAMES = {"node_modules", ".git", ".hg", ".svn", ".venv", ".tox"}
MAX_SUBPROJECTS = 16


@dataclass(slots=True)
class ProjectRuntime:
    """Runtime/build metadata for a specific directory."""

    path: str
    runtimes: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    build_tools: set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, list[str]]:
        return {
            "path": self.path,
            "runtimes": sorted(self.runtimes),
            "frameworks": sorted(self.frameworks),
            "build_tools": sorted(self.build_tools),
        }

    def has_data(self) -> bool:
        return bool(self.runtimes or self.frameworks or self.build_tools)


@dataclass(slots=True)
class RuntimeMetadata:
    """Detected runtimes, frameworks, and build tools."""

    runtimes: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    build_tools: set[str] = field(default_factory=set)
    projects: list[ProjectRuntime] = field(default_factory=list)

    def add_project(self, project: ProjectRuntime) -> None:
        if not project.has_data():
            return
        self.projects.append(project)
        self.runtimes.update(project.runtimes)
        self.frameworks.update(project.frameworks)
        self.build_tools.update(project.build_tools)

    def to_dict(self) -> Dict[str, list[str]]:
        return {
            "runtimes": sorted(self.runtimes),
            "frameworks": sorted(self.frameworks),
            "build_tools": sorted(self.build_tools),
            "projects": [project.to_dict() for project in self.projects],
        }


def _read_package_json(root: Path) -> Dict[str, Dict[str, str]]:
    package_file = root / "package.json"
    if not package_file.exists():
        return {}
    try:
        data = json.loads(package_file.read_text())
    except json.JSONDecodeError:
        return {}
    return {
        "dependencies": data.get("dependencies", {}) or {},
        "devDependencies": data.get("devDependencies", {}) or {},
        "peerDependencies": data.get("peerDependencies", {}) or {},
    }


def _has_any_file(root: Path, candidates: Iterable[str]) -> bool:
    return any((root / candidate).exists() for candidate in candidates)


def _search_for_extensions(root: Path, extensions: tuple[str, ...], limit: int = 25) -> bool:
    if not root.exists():
        return False
    seen = 0
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in extensions:
            return True
        seen += 1
        if seen >= limit:
            break
    return False


def _apply_framework_hints(dependencies: Mapping[str, str], meta) -> None:
    for pkg, framework in FRAMEWORK_DEPENDENCIES.items():
        if pkg in dependencies:
            meta.frameworks.add(framework)


def _apply_build_tool_hints(dependencies: Mapping[str, str], meta, root: Path) -> None:
    for file_name, tool in BUILD_TOOL_FILES.items():
        if (root / file_name).exists():
            meta.build_tools.add(tool)
    for pkg, tool in BUILD_TOOL_DEPENDENCIES.items():
        if pkg in dependencies:
            meta.build_tools.add(tool)


def _is_browser_project(root: Path, dependencies: Mapping[str, str]) -> bool:
    if any(dep in dependencies for dep in BROWSER_DEPENDENCIES):
        return True
    if _has_any_file(root, BROWSER_HTML_FILES):
        return True
    src_dir = root / "src"
    return _search_for_extensions(src_dir, (".jsx", ".tsx"))


def _relative_label(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
        return "." if not rel.parts else rel.as_posix()
    except ValueError:
        return str(path)


def _should_skip_subproject(path: Path) -> bool:
    return any(part in IGNORED_DIR_NAMES for part in path.parts)


def _resolve_project_root(candidate: Path, signature: str) -> Path:
    depth = signature.count("/") + signature.count("\\") + 1
    project = candidate
    for _ in range(depth):
        project = project.parent
    return project


def _collect_subproject_roots(root: Path) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    for signature in SUBPROJECT_SIGNATURES:
        for candidate in root.rglob(signature):
            if len(roots) >= MAX_SUBPROJECTS:
                return roots
            project_root = _resolve_project_root(candidate, signature).resolve()
            if project_root == root:
                continue
            if project_root in seen:
                continue
            if _should_skip_subproject(project_root):
                continue
            if not project_root.exists():
                continue
            seen.add(project_root)
            roots.append(project_root)
    return roots


def _scan_project_runtime(root: Path, label: str) -> ProjectRuntime:
    project = ProjectRuntime(path=label)
    package_deps = _read_package_json(root)
    aggregated_deps = {
        **package_deps.get("dependencies", {}),
        **package_deps.get("devDependencies", {}),
        **package_deps.get("peerDependencies", {}),
    }

    if package_deps:
        project.runtimes.add("node")

    if _has_any_file(root, NODE_FILE_SIGNATURES):
        project.runtimes.add("node")
    if _has_any_file(root, DENO_FILE_SIGNATURES):
        project.runtimes.add("deno")
    if _has_any_file(root, BUN_FILE_SIGNATURES):
        project.runtimes.add("bun")
    if _has_any_file(root, TYPESCRIPT_FILES) or _search_for_extensions(root, (".ts", ".tsx")):
        project.runtimes.add("typescript")
    if _is_browser_project(root, aggregated_deps):
        project.runtimes.add("browser")

    _apply_framework_hints(aggregated_deps, project)
    _apply_build_tool_hints(aggregated_deps, project, root)
    return project


def detect_runtime(project_root: Path) -> RuntimeMetadata:
    """Detect runtimes/frameworks/build tools for a project."""

    root = project_root.expanduser().resolve()
    meta = RuntimeMetadata()
    main_project = _scan_project_runtime(root, ".")
    meta.add_project(main_project)

    for subroot in _collect_subproject_roots(root):
        label = _relative_label(subroot, root)
        sub_project = _scan_project_runtime(subroot, label)
        meta.add_project(sub_project)

    return meta
