"""
config.py — ExportPrefs → dataclass + YAML loading.

Allows exporting/importing ExportPrefs from a YAML config file.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

import yaml

from mib2vrl.export.export_settings import ExportPrefs


def load_config(path: Path | str) -> ExportPrefs:
    """Load ExportPrefs from a YAML file."""
    with open(path, encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}
    return ExportPrefs(
        scope=data.get("scope", "TRAPS"),
        subtrees_only=data.get("subtrees_only", False),
        export_dir=data.get("export_dir", "./out"),
        include_path=data.get("include_path", "$OMNIHOME/probes/solaris2/include"),
        rules_one_agent=data.get("rules_one_agent", True),
        rules_class=data.get("rules_class", True),
        rules_varbind_details=data.get("rules_varbind_details", True),
        rules_better_alert_key=data.get("rules_better_alert_key", False),
        rules_varbind_oids=data.get("rules_varbind_oids", False),
        version=data.get("version", "0.1.0"),
        eol_format=data.get("eol_format", "\n"),
        output_format=data.get("output_format", "vrl"),
    )


def save_config(prefs: ExportPrefs, path: Path | str) -> None:
    """Save ExportPrefs to a YAML file."""
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(asdict(prefs), f, default_flow_style=False)


def default_config() -> ExportPrefs:
    """Return default ExportPrefs."""
    return ExportPrefs()
