"""
export_settings.py — Template context builder for VRL export.

ExportSettings builds the Jinja2 data model dict that is passed to
all templates.  ExportPrefs is a plain dataclass replacing the Eclipse
preference-based export configuration

Template variables (mirrors ExportSettings.initSettings()):
  TRAP_LIST         — list of Trap dataclasses
  MIB_OBJECT_LIST   — list of MibObjectDict
  EXPORT_HELPER     — ExportHelper instance
  SCOPE             — "ALL" | "TRAPS" | "OBJECTS"
  SUBTREES_ONLY     — bool
  SCOPE_ALL / SCOPE_TRAPS / SCOPE_OBJECTS — string constants
  DEFAULT_INCLUDE_PATH — include path for generated rules
  RULES_ONE_AGENT   — bool
  RULES_CLASS       — bool
  RULES_VARBIND_DETAILS — bool
  RULES_BETTER_ALERT_KEY — bool
  RULES_VARBIND_OIDS — bool
  VERSION           — tool version string
  FILE_SEPARATOR    — os.sep
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mib2vrl.models.trap import Trap


# ---------------------------------------------------------------------------
# Scope constants (ExportFormat.Scope enum)
# ---------------------------------------------------------------------------
SCOPE_ALL = "ALL"
SCOPE_TRAPS = "TRAPS"
SCOPE_OBJECTS = "OBJECTS"


@dataclass
class ExportPrefs:
    """
    Export preferences dataclass

    All Eclipse preferences are replaced by direct fields with defaults
    matching the preference defaults in the original application.
    """

    scope: str = SCOPE_TRAPS
    """Export scope: ALL, TRAPS, or OBJECTS."""

    subtrees_only: bool = False
    """If True, only export selected sub-trees."""

    export_dir: str = "./out"
    """Output directory path."""

    include_path: str = "$OMNIHOME/probes/solaris2/include"
    """DEFAULT_INCLUDE_PATH for generated .rules files."""

    rules_one_agent: bool = True
    """Put all rules in a single agent block."""

    rules_class: bool = True
    """Add @Class field to rules."""

    rules_varbind_details: bool = True
    """Emit detailed varbind assignments."""

    rules_better_alert_key: bool = False
    """Use varbind name instead of index for @AlertKey."""

    rules_varbind_oids: bool = False
    """Include varbind OIDs in comments."""

    version: str = "0.1.0"
    """Tool version string injected into output."""

    eol_format: str = "\n"
    """End-of-line format for output files."""

    output_format: str = "vrl"
    """Output format: vrl | netcool | both."""


class ExportSettings:
    """
    ExportSettings.py.

    Builds the Jinja2 context dict from ExportPrefs + trap/object lists +
    export helper.  Mirror of initSettings() + setOptionTags() +
    setPropertyTags() + mibListTag().
    """

    def __init__(self, prefs: ExportPrefs) -> None:
        self._prefs = prefs
        self._data: dict[str, Any] = {}

    def init_settings(
        self,
        traps: list[Trap],
        mib_objects: list[Any],
        export_helper: Any,
    ) -> dict[str, Any]:
        """
        ExportSettings.initSettings() — builds and returns the full template context.

        Parameters
        ----------
        traps        : list[Trap]    — resolved trap objects
        mib_objects  : list          — all MIB object dicts
        export_helper: ExportHelper  — helper callable from templates
        """
        self._data = {}
        self._set_option_tags()
        self._set_property_tags()
        self._set_mib_list_tags(traps, mib_objects)
        self._data["EXPORT_HELPER"] = export_helper
        return self._data

    # ------------------------------------------------------------------
    # ExportSettings.setOptionTags()
    # ------------------------------------------------------------------
    def _set_option_tags(self) -> None:
        self._data["SCOPE"] = self._prefs.scope
        self._data["SUBTREES_ONLY"] = self._prefs.subtrees_only
        self._data["SCOPE_ALL"] = SCOPE_ALL
        self._data["SCOPE_TRAPS"] = SCOPE_TRAPS
        self._data["SCOPE_OBJECTS"] = SCOPE_OBJECTS

    # ------------------------------------------------------------------
    # ExportSettings.setPropertyTags()
    # ------------------------------------------------------------------
    def _set_property_tags(self) -> None:
        self._data["DEFAULT_INCLUDE_PATH"] = self._prefs.include_path
        self._data["RULES_ONE_AGENT"] = self._prefs.rules_one_agent
        self._data["RULES_CLASS"] = self._prefs.rules_class
        self._data["RULES_VARBIND_DETAILS"] = self._prefs.rules_varbind_details
        self._data["RULES_BETTER_ALERT_KEY"] = self._prefs.rules_better_alert_key
        self._data["RULES_VARBIND_OIDS"] = self._prefs.rules_varbind_oids
        self._data["VERSION"] = self._prefs.version
        self._data["FILE_SEPARATOR"] = os.sep

    # ------------------------------------------------------------------
    # ExportSettings.mibListTag()
    # ------------------------------------------------------------------
    def _set_mib_list_tags(
        self, traps: list[Trap], mib_objects: list[Any]
    ) -> None:
        self._data["TRAP_LIST"] = traps
        self._data["MIB_OBJECT_LIST"] = mib_objects

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    @property
    def prefs(self) -> ExportPrefs:
        return self._prefs
