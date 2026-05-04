"""
export_helper.py — ExportHelperTM.py.

Export helper utilities for VRL template rendering.
The Java class used FreeMarker TemplateModel wrappers; here we use
plain Python dicts and lists that Jinja2 can access natively.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


class HashTM:
    """ExportHelperTM.HashTM — mutable dict wrapper for templates."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value

    def get(self, key: str) -> Any:
        return self._data.get(key)

    def keys(self) -> list[str]:
        return list(self._data.keys())

    def size(self) -> int:
        return len(self._data)

    def contains_key(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        return f"HashTM({self._data!r})"


class ListTM:
    """ExportHelperTM.ListTM — mutable list wrapper for templates."""

    def __init__(self) -> None:
        self._data: list[Any] = []

    def add(self, value: Any) -> None:
        self._data.append(value)

    def get(self, index: int) -> Any:
        return self._data[index]

    def size(self) -> int:
        return len(self._data)

    def contains(self, obj: Any) -> bool:
        return obj in self._data

    def list(self) -> list[Any]:
        return self._data

    def clear(self) -> None:
        self._data.clear()

    def __repr__(self) -> str:
        return f"ListTM({self._data!r})"


class ExportHelper:
    """
    ExportHelperTM.py.

    All public methods preserved with their original names (camelCase)
    aliased to snake_case equivalents used by Python templates.
    """

    def __init__(
        self,
        oid_registry: dict[str, str] | None = None,
        export_dir: str = "./out",
        version: str = "0.1.0",
    ) -> None:
        self._oid_registry = oid_registry or {}
        self._export_dir = export_dir
        self._version = version
        self._cancelled = False
        self._progress_tasks: list[tuple[str, int]] = []

    # ------------------------------------------------------------------
    # Progress / cancellation (ExportHelperTM.startTask / worked / cancel)
    # ------------------------------------------------------------------

    def startTask(self, task_name: str, max_units: int) -> None:
        """ExportHelperTM.startTask()."""
        self._progress_tasks.append((task_name, max_units))
        logger.debug("Task start: %s (%d)", task_name, max_units)

    def worked(self, units: int) -> None:
        """ExportHelperTM.worked()."""
        pass  # no-op for headless export

    def exportCanceled(self) -> bool:
        """ExportHelperTM.exportCanceled()."""
        return self._cancelled

    def cancel(self) -> None:
        """ExportHelperTM.cancel()."""
        self._cancelled = True

    # ------------------------------------------------------------------
    # Logging (ExportHelperTM.logMessage / logVerboseMessage / logWarningMessage)
    # ------------------------------------------------------------------

    def logMessage(self, message: str, *bindings: Any) -> None:
        """ExportHelperTM.logMessage() — logs at DEBUG level."""
        if bindings:
            logger.debug(message, *bindings)
        else:
            logger.debug(message)

    def logVerboseMessage(self, message: str, *bindings: Any) -> None:
        """ExportHelperTM.logVerboseMessage() — logs at DEBUG level."""
        self.logMessage(message, *bindings)

    def logWarningMessage(self, message: str, *bindings: Any) -> None:
        """ExportHelperTM.logWarningMessage() — logs at WARNING level."""
        if bindings:
            logger.warning(message, *bindings)
        else:
            logger.warning(message)

    # ------------------------------------------------------------------
    # OID / module helpers
    # ------------------------------------------------------------------

    def getModuleNames(self, oid: str) -> list[str]:
        """
        ExportHelperTM.getModuleNames() — returns module names that define an OID.

        Returns empty list if OID not found.
        """
        # TODO: implement once module registry is wired in
        return []

    def getMostPopularName(self, oid: str) -> str:
        """
        ExportHelperTM.getMostPopularName() — returns most common name for OID.

        Falls back to the OID string itself.
        """
        return self._oid_registry.get(oid, oid)

    # ------------------------------------------------------------------
    # Date
    # ------------------------------------------------------------------

    def getDate(self) -> datetime:
        """ExportHelperTM.getDate() — returns current datetime."""
        return datetime.now()

    # ------------------------------------------------------------------
    # Filename utilities
    # ------------------------------------------------------------------

    def getFilenameLength(self, filename: str) -> int:
        """
        ExportHelperTM.getFilenameLength().

        Returns length of the full output path for the given filename.
        """
        import os
        return len(os.path.join(self._export_dir, filename))

    # ------------------------------------------------------------------
    # Syntax helpers
    # ------------------------------------------------------------------

    def getSyntaxText(self, syntax: Any) -> str:
        """
        ExportHelperTM.getSyntaxText().

        In the original, ISyntax had getValue() and getType() methods.
        Here we accept a string or dict.
        """
        if syntax is None:
            return ""
        if isinstance(syntax, str):
            return syntax
        if isinstance(syntax, dict):
            value = syntax.get("value") or ""
            if not value:
                return syntax.get("type") or ""
            return value
        return str(syntax)

    def resolveSyntax(self, syntax: Any, root_syntax: bool = True) -> Any:
        """
        ExportHelperTM.resolveSyntax().

        In the original this walked TC chains.  Here we return the
        syntax as-is since full TC resolution is done at parse time.
        TODO: wire in TC lookup when full TC chain resolution is needed.
        """
        return syntax

    def getVarbindObjectSyntax(self, varbind: Any) -> Any:
        """ExportHelperTM.getVarbindObjectSyntax()."""
        if hasattr(varbind, "syntax"):
            return varbind.syntax
        if isinstance(varbind, dict):
            return varbind.get("syntax", "")
        return ""

    def getTCMaxValue(self, syntax: Any) -> int:
        """
        ExportHelperTM.getTCMaxValue().

        Returns max value for TC range constraints.
        TODO: implement full TC range lookup.
        """
        return 2147483647  # safe default

    # ------------------------------------------------------------------
    # Template data structure factories
    # ------------------------------------------------------------------

    def sanitize_description(self, desc: str, max_len: int = 200) -> str:
        """Collapse whitespace in MIB DESCRIPTION fields and truncate."""
        import re
        cleaned = re.sub(r'\s+', ' ', desc.strip())
        if len(cleaned) > max_len:
            return cleaned[:max_len - 3] + "..."
        return cleaned

    def makeHash(self) -> HashTM:
        """ExportHelperTM.makeHash() — creates a new HashTM."""
        return HashTM()

    def makeList(self) -> ListTM:
        """ExportHelperTM.makeList() — creates a new ListTM."""
        return ListTM()

    # ------------------------------------------------------------------
    # OID tree (stub — original used Eclipse TreeViewer)
    # ------------------------------------------------------------------

    def getOIDRootTreeNode(self) -> dict[str, Any]:
        """ExportHelperTM.getOIDRootTreeNode() — stub."""
        return {"name": "root", "children": []}

    def getOIDTreeImage(self, object_type: str) -> str:
        """
        ExportHelperTM.getOIDTreeImage().

        Returns icon name for given object type (for HTML template use).
        """
        type_map = {
            "OBJECT-TYPE": "object-type.gif",
            "NOTIFICATION-TYPE": "notification.gif",
            "TRAP-TYPE": "trap.gif",
            "OBJECT IDENTIFIER": "oid.gif",
            "TEXTUAL-CONVENTION": "tc.gif",
            "MODULE-IDENTITY": "module.gif",
        }
        return type_map.get(object_type, "")
