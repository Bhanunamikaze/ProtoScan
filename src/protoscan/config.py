"""Configuration loading helpers for the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, Iterable


DEFAULT_CONFIG: Dict[str, Any] = {
    "severity": "medium",
    "ignore": [],
    "runtime_hints": [],
    "cache_enabled": True,
}


@dataclass(slots=True)
class ScannerConfig:
    """Represents the flattened scanner configuration."""

    project_root: Path
    severity: str = "medium"
    ignore: list[str] = field(default_factory=list)
    runtime_hints: list[str] = field(default_factory=list)
    cache_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_root": str(self.project_root),
            "severity": self.severity,
            "ignore": list(self.ignore),
            "runtime_hints": list(self.runtime_hints),
            "cache_enabled": self.cache_enabled,
        }


def _merge(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = {**base}
    for key, value in updates.items():
        if (
            isinstance(value, dict)
            and isinstance(merged.get(key), dict)
        ):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_json_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:  # pragma: no cover - bubbled up
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def _config_sources(project_root: Path, user_config: Path | None) -> Iterable[Path]:
    default_file = project_root / ".protoscanrc.json"
    if default_file.exists():
        yield default_file
    if user_config is not None:
        user_file = user_config
        if not user_file.is_absolute():
            user_file = project_root / user_file
        if user_file.exists():
            yield user_file


def load_config(
    project_root: Path,
    config_path: Path | None = None,
    overrides: Dict[str, Any] | None = None,
) -> ScannerConfig:
    """Load configuration from defaults, files, and CLI overrides."""

    root = project_root.expanduser().resolve()
    config_data: Dict[str, Any] = {**DEFAULT_CONFIG}
    for path in _config_sources(root, config_path):
        config_data = _merge(config_data, _read_json_file(path))
    if overrides:
        config_data = _merge(config_data, overrides)
    return ScannerConfig(
        project_root=root,
        severity=str(config_data.get("severity", DEFAULT_CONFIG["severity"])),
        ignore=list(config_data.get("ignore", [])),
        runtime_hints=list(config_data.get("runtime_hints", [])),
        cache_enabled=bool(config_data.get("cache_enabled", True)),
    )
