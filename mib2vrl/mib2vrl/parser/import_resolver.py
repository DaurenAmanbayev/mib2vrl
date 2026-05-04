"""
import_resolver.py — ImportResolver.py.

Resolves imported MIB module dependencies by searching through a list
of search-path directories.  Mirrors the recursive import logic from
Resolves MIB module imports from filesystem search paths.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from mib2vrl.parser import regexdef as rx
from mib2vrl.parser.mib_parser import MibModule, parse_mib

logger = logging.getLogger(__name__)


class ImportResolver:
    """
    Resolves MIB imports by scanning search-path directories.

    Usage:
        resolver = ImportResolver([Path("./mibs"), Path("/usr/share/snmp/mibs")])
        modules = resolver.resolve(["IF-MIB", "SNMPv2-MIB"])
    """

    def __init__(self, search_paths: list[Path]) -> None:
        self._search_paths = [Path(p) for p in search_paths]
        self._loaded: dict[str, MibModule] = {}
        """name → MibModule for already-loaded modules."""
        self._failed: set[str] = set()
        """Module names that could not be found/parsed."""
        self._file_cache: dict[Path, dict[str, str]] = {}
        """path → {mib_name: mib_body} split cache."""

    def resolve(self, module_names: list[str]) -> dict[str, MibModule]:
        """
        Resolve a list of module names, recursively importing dependencies.

        Returns dict of {module_name: MibModule} for all successfully loaded modules.
        """
        queue = list(module_names)
        while queue:
            name = queue.pop(0)
            if name in self._loaded or name in self._failed:
                continue
            module = self._load_module(name)
            if module is not None:
                self._loaded[name] = module
                # Queue transitive imports
                for obj_name, from_module in module.imports:
                    if from_module not in self._loaded and from_module not in self._failed:
                        queue.append(from_module)
            else:
                self._failed.add(name)
                logger.warning("ImportResolver: could not resolve module %r", name)
        return dict(self._loaded)

    def _load_module(self, name: str) -> Optional[MibModule]:
        """ImportResolver.processImport() — find and parse a module by name."""
        for search_path in self._search_paths:
            if not search_path.is_dir():
                continue
            for file_path in search_path.rglob("*"):
                if not file_path.is_file():
                    continue
                mibs = self._get_file_mibs(file_path)
                if name in mibs:
                    body = mibs[name]
                    try:
                        module = parse_mib(
                            body,
                            mib_name=name,
                            source_file=str(file_path),
                        )
                        logger.info("ImportResolver: loaded %s from %s", name, file_path)
                        return module
                    except Exception as e:
                        logger.warning(
                            "ImportResolver: parse error for %s in %s: %s",
                            name, file_path, e
                        )
                        return None
        return None

    def _get_file_mibs(self, file_path: Path) -> dict[str, str]:
        """
        Returns the {name: body} mapping for a file, using a cache.
        Mirrors ImportResolver.SearchPathFile + RegexDef.SplitMibs().
        """
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # latin-1 fallback — matches Java 'readBinaryChar' warning
                content = file_path.read_text(encoding="latin-1")
                logger.info(
                    "ImportResolver: used latin-1 fallback for %s", file_path
                )
        except OSError as e:
            logger.warning("ImportResolver: cannot read %s: %s", file_path, e)
            self._file_cache[file_path] = {}
            return {}

        try:
            mibs = rx.split_mibs(content)
        except Exception as e:
            logger.warning("ImportResolver: split_mibs failed for %s: %s", file_path, e)
            mibs = {}

        self._file_cache[file_path] = mibs
        return mibs
