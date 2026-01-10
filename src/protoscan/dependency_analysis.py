"""Dependency manifest parsing and vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
import json
import os
from pathlib import Path
from typing import Dict, Iterable, Mapping

from packaging.version import InvalidVersion, Version


_ADVISORY_CACHE: tuple[dict[str, object], ...] | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilityFinding:
    """Represents a vulnerable dependency instance."""

    name: str
    installed_version: str
    spec: str
    severity: str
    cves: tuple[str, ...]
    reference: str
    via: str  # direct | transitive
    project: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "installedVersion": self.installed_version,
            "spec": self.spec,
            "severity": self.severity,
            "cves": list(self.cves),
            "reference": self.reference,
            "via": self.via,
            "project": self.project,
        }


@dataclass(slots=True)
class DependencyReport:
    """Aggregated dependency data for a project."""

    direct_dependencies: Dict[str, str] = field(default_factory=dict)
    transitive_dependencies: Dict[str, str] = field(default_factory=dict)
    findings: list[VulnerabilityFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "directDependencies": dict(self.direct_dependencies),
            "transitiveDependencies": dict(self.transitive_dependencies),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _read_json_any(path: Path):
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _cache_dir() -> Path:
    override = os.environ.get("PROTOSCAN_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cache" / "protoscan"


def _advisory_cache_path() -> Path:
    override = os.environ.get("PROTOSCAN_VULN_CACHE")
    if override:
        return Path(override).expanduser()
    return _cache_dir() / "advisories.json"


def _load_advisories_from_path(path: Path | None) -> list[dict[str, object]]:
    if not path:
        return []
    data = _read_json_any(path)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _load_packaged_advisories() -> list[dict[str, object]]:
    text = ""
    data_file = Path(__file__).resolve().parent / "data" / "vuln-db.json"
    if data_file.exists():
        try:
            text = data_file.read_text()
        except OSError:
            text = ""
    if not text:
        try:
            data_path = resources.files("protoscan").joinpath("data", "vuln-db.json")
            text = data_path.read_text()
        except (FileNotFoundError, ModuleNotFoundError, AttributeError, OSError):
            return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _write_cache(data: Iterable[dict[str, object]]) -> None:
    path = _advisory_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(list(data), indent=2))
    except OSError:
        return


def _load_advisories() -> tuple[dict[str, object], ...]:
    global _ADVISORY_CACHE
    if _ADVISORY_CACHE is not None:
        return _ADVISORY_CACHE
    env_path = os.environ.get("PROTOSCAN_VULN_DB")
    data = _load_advisories_from_path(Path(env_path).expanduser()) if env_path else []
    if not data:
        data = _load_advisories_from_path(_advisory_cache_path())
    if not data:
        data = _load_packaged_advisories()
        if data:
            _write_cache(data)
    _ADVISORY_CACHE = tuple(data)
    return _ADVISORY_CACHE


def _clear_advisory_cache() -> None:
    """Reset advisory cache (primarily for tests)."""

    global _ADVISORY_CACHE
    _ADVISORY_CACHE = None


def _read_package_json(root: Path) -> Mapping[str, Mapping[str, str]]:
    package_file = root / "package.json"
    if not package_file.exists():
        return {}
    data = _read_json(package_file)
    return {
        "dependencies": data.get("dependencies", {}) or {},
        "devDependencies": data.get("devDependencies", {}) or {},
        "peerDependencies": data.get("peerDependencies", {}) or {},
    }


def _flatten_package_lock_deps(node: Mapping[str, object], acc: Dict[str, str]) -> None:
    deps = node.get("dependencies")
    if not isinstance(deps, dict):
        return
    for name, entry in deps.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str):
            acc.setdefault(name, version)
        _flatten_package_lock_deps(entry, acc)


def _read_package_lock(root: Path) -> Dict[str, str]:
    lock_file = root / "package-lock.json"
    if not lock_file.exists():
        return {}
    data = _read_json(lock_file)
    collected: Dict[str, str] = {}
    _flatten_package_lock_deps(data, collected)
    return collected


def _normalize_version(value: str) -> str | None:
    cleaned = value.strip()
    for prefix in ("^", "~", ">=", "<=", ">", "<", "="):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip()
    if " " in cleaned:
        cleaned = cleaned.split()[0]
    if not cleaned:
        return None
    try:
        Version(cleaned)
        return cleaned
    except InvalidVersion:
        return None


def _parse_spec(spec: str) -> tuple[str, Version] | None:
    spec = spec.strip()
    if spec.startswith("<="):
        operator = "<="
        version_part = spec[2:]
    elif spec.startswith("<"):
        operator = "<"
        version_part = spec[1:]
    elif spec.startswith("=="):
        operator = "=="
        version_part = spec[2:]
    else:
        return None
    version_part = version_part.strip()
    if not version_part:
        return None
    try:
        return operator, Version(version_part)
    except InvalidVersion:
        return None


def _is_vulnerable(version: str, spec: str) -> bool:
    normalized = _normalize_version(version)
    if normalized is None:
        return False
    parsed = _parse_spec(spec)
    if not parsed:
        return False
    operator, target_version = parsed
    try:
        installed_version = Version(normalized)
    except InvalidVersion:
        return False

    if operator == "<":
        return installed_version < target_version
    if operator == "<=":
        return installed_version <= target_version
    if operator == "==":
        return installed_version == target_version
    return False


def _detect_in_set(
    dependencies: Mapping[str, str],
    via: str,
    project_label: str,
) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for definition in _load_advisories():
        name = definition.get("name")
        spec = definition.get("spec")
        if not isinstance(name, str) or not isinstance(spec, str):
            continue
        if name not in dependencies:
            continue
        version = dependencies[name]
        if not isinstance(version, str):
            continue
        if _is_vulnerable(version, spec):  # type: ignore[arg-type]
            findings.append(
                VulnerabilityFinding(
                    name=name,
                    installed_version=version,
                    spec=spec,
                    severity=str(definition.get("severity", "medium")),
                    cves=tuple(definition.get("cves", [])) if isinstance(definition.get("cves"), list) else (),
                    reference=str(definition.get("reference", "")),
                    via=via,
                    project=project_label,
                )
            )
    return findings


def _analyze_manifest(manifest_root: Path) -> DependencyReport:
    package_json = _read_package_json(manifest_root)
    direct_dependencies: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = package_json.get(section, {}) or {}
        for name, version in deps.items():
            if isinstance(version, str):
                normalized = _normalize_version(version) or version
                direct_dependencies[name] = normalized

    lock_dependencies = _read_package_lock(manifest_root)
    transitive_dependencies = {
        name: version
        for name, version in lock_dependencies.items()
        if name not in direct_dependencies
    }

    return DependencyReport(
        direct_dependencies=direct_dependencies,
        transitive_dependencies=transitive_dependencies,
        findings=[],
    )


def _iter_manifests(root: Path) -> list[Path]:
    manifests = []
    main = root / "package.json"
    if main.exists():
        manifests.append(main)
    for path in root.rglob("package.json"):
        if main.exists() and path == main:
            continue
        manifests.append(path)
    return manifests


def analyze_dependencies(project_root: Path) -> DependencyReport:
    """Analyze the project's dependencies for known prototype pollution CVEs."""

    root = project_root.expanduser().resolve()
    manifests = _iter_manifests(root)
    if not manifests:
        return DependencyReport()

    aggregate_direct: Dict[str, str] = {}
    aggregate_transitive: Dict[str, str] = {}
    findings: list[VulnerabilityFinding] = []

    direct_set = False
    for manifest in manifests:
        manifest_root = manifest.parent
        report = _analyze_manifest(manifest_root)
        label = (
            "."
            if manifest_root == root
            else str(manifest_root.relative_to(root))
        )
        findings.extend(
            _detect_in_set(report.direct_dependencies, "direct", label)
        )
        findings.extend(
            _detect_in_set(report.transitive_dependencies, "transitive", label)
        )
        if not direct_set:
            aggregate_direct = report.direct_dependencies
            aggregate_transitive = report.transitive_dependencies
            direct_set = True

    return DependencyReport(
        direct_dependencies=aggregate_direct,
        transitive_dependencies=aggregate_transitive,
        findings=findings,
    )
