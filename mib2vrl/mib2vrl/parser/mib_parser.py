"""
mib_parser.py — MIB file parsing pipeline.

Entry point for parsing a single MIB module text block.
Mirrors the MibParser.parseMIB() pipeline:

  1. ReplaceStrings
  2. RemoveComments
  3. ExtractMacros
  4. ExtractImports
  5. ExtractExports
  6. ExtractV1Tcs
  7. ExtractV2Tcs
  8. ExtractTrapTypes  → parse each via mib_object_parser.parse_trap_type
  9. ExtractObjects    → route to appropriate parser

Returns a MibModule dataclass with all parsed objects.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from mib2vrl.parser import regexdef as rx
from mib2vrl.parser.mib_object_parser import (
    MibObjectDict,
    TYPE_NOTIFICATION_TYPE,
    TYPE_OBJECT_IDENTIFIER,
    TYPE_OBJECT_IDENTITY,
    TYPE_OBJECT_TYPE,
    TYPE_TRAP_TYPE,
    parse_module_identity,
    parse_notification_type,
    parse_object_identifier,
    parse_object_identity,
    parse_object_type,
    parse_textual_convention,
    parse_trap_type,
)
from mib2vrl.parser.oid_resolver import OidResolver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MibModule — result container (replaces MibModuleDocument / DOM)
# ---------------------------------------------------------------------------

@dataclass
class MibModule:
    """Parsed MIB module — equivalent to MibModuleDocument."""

    name: str = ""
    source_file: str = ""

    imports: list[tuple[str, str]] = field(default_factory=list)
    """List of (object_name, from_module) import pairs."""

    exports: list[str] = field(default_factory=list)

    textual_conventions: list[MibObjectDict] = field(default_factory=list)
    trap_types: list[MibObjectDict] = field(default_factory=list)
    """SNMPv1 TRAP-TYPE definitions."""
    notification_types: list[MibObjectDict] = field(default_factory=list)
    """SNMPv2 NOTIFICATION-TYPE definitions."""
    object_identifiers: list[MibObjectDict] = field(default_factory=list)
    object_types: list[MibObjectDict] = field(default_factory=list)
    module_identities: list[MibObjectDict] = field(default_factory=list)
    other_objects: list[MibObjectDict] = field(default_factory=list)

    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def all_traps(self) -> list[MibObjectDict]:
        """Combined SNMPv1 + SNMPv2 trap definitions."""
        return self.trap_types + self.notification_types


def _determine_object_type(text: str) -> str:
    """
    Mirrors RegexDef.GetObjectType() — identifies an object text block's type.
    Returns one of the TYPE_* constants.
    """
    if rx.obj_NOTIFICATIONTYPE.search(text) and rx.obj_NOTIFICATIONTYPE_MIN in text:
        return TYPE_NOTIFICATION_TYPE
    if rx.obj_OBJECTTYPE.search(text) and rx.obj_OBJECTTYPE_MIN in text:
        return TYPE_OBJECT_TYPE
    if rx.obj_OBJECTIDENTIFIER.search(text) and rx.obj_OBJECTIDENTIFIER_MIN in text:
        return TYPE_OBJECT_IDENTIFIER
    if rx.obj_OBJECTIDENTITY.search(text) and rx.obj_OBJECTIDENTITY_MIN in text:
        return TYPE_OBJECT_IDENTITY
    if rx.obj_MODULEIDENTITY.search(text) and rx.obj_MODULEIDENTITY_MIN in text:
        return "MODULE-IDENTITY"
    return "UNKNOWN"


def parse_mib(
    text: str,
    mib_name: str = "",
    source_file: str = "",
    strict: bool = False,
) -> MibModule:
    """
    MibParser.parseMIB() — full parsing pipeline for a single MIB module text.

    text       — the raw MIB body (already extracted from multi-MIB file)
    mib_name   — the module name
    source_file — file this came from
    strict     — if True, raise on parse errors; if False, warn and continue
    """
    module = MibModule(name=mib_name, source_file=source_file)
    _dbg = logger.isEnabledFor(logging.DEBUG)

    def _t(label: str, t0: float) -> float:
        t1 = time.perf_counter()
        if _dbg:
            logger.debug("[%s] %s: %.3fs", mib_name, label, t1 - t0)
        return t1

    t0 = time.perf_counter()

    # Step 1: protect strings
    work = rx.replace_strings(text)
    t0 = _t("replace_strings", t0)

    # Step 2: remove comments
    work = rx.remove_comments(work)
    t0 = _t("remove_comments", t0)

    # Step 3: extract/remove macros
    try:
        work = rx.extract_macros(work)
    except Exception as e:
        msg = f"Failed to extract macros: {e}"
        module.warnings.append(msg)
        logger.warning(msg)
    t0 = _t("extract_macros", t0)

    # Step 4: extract imports
    try:
        work, imports = rx.extract_imports(work)
        module.imports = imports
    except Exception as e:
        msg = f"Failed to extract imports: {e}"
        module.warnings.append(msg)
        logger.warning(msg)
    t0 = _t("extract_imports", t0)

    # Step 5: extract exports
    try:
        work, exports = rx.extract_exports(work)
        module.exports = exports
    except Exception as e:
        msg = f"Failed to extract exports: {e}"
        module.warnings.append(msg)
        logger.warning(msg)
    t0 = _t("extract_exports", t0)

    # Step 6: extract v1 TCs
    try:
        work, tc_blocks = rx.extract_v1_tcs(work)
        for block in tc_blocks:
            restored = rx.restore_strings(block)
            try:
                tc = parse_textual_convention(restored, strict)
                module.textual_conventions.append(tc)
            except Exception as e:
                module.warnings.append(f"TC v1 parse error: {e}")
    except Exception as e:
        module.warnings.append(f"V1 TC extraction error: {e}")
        logger.warning("V1 TC extraction error: %s", e)
    t0 = _t("extract_v1_tcs", t0)

    # Step 7: extract v2 TCs
    try:
        work, tc_blocks = rx.extract_v2_tcs(work)
        for block in tc_blocks:
            restored = rx.restore_strings(block)
            try:
                tc = parse_textual_convention(restored, strict)
                module.textual_conventions.append(tc)
            except Exception as e:
                module.warnings.append(f"TC v2 parse error: {e}")
    except Exception as e:
        module.warnings.append(f"V2 TC extraction error: {e}")
        logger.warning("V2 TC extraction error: %s", e)
    t0 = _t("extract_v2_tcs", t0)

    # Step 8: extract TRAP-TYPE (SNMPv1)
    try:
        work, trap_blocks = rx.extract_trap_types(work)
        for block in trap_blocks:
            restored = rx.restore_strings(block)
            try:
                trap = parse_trap_type(restored, strict)
                trap["MibModule"] = mib_name
                module.trap_types.append(trap)
            except Exception as e:
                module.warnings.append(f"TRAP-TYPE parse error: {e}")
    except Exception as e:
        module.warnings.append(f"TRAP-TYPE extraction error: {e}")
        logger.warning("TRAP-TYPE extraction error: %s", e)
    t0 = _t("extract_trap_types", t0)

    # Step 9: extract generic MIB objects (NOTIFICATION-TYPE, OBJECT-TYPE, etc.)
    try:
        work, obj_blocks = rx.extract_objects(work)
        for block in obj_blocks:
            restored = rx.restore_strings(block)
            obj_type = _determine_object_type(restored)
            try:
                if obj_type == TYPE_NOTIFICATION_TYPE:
                    obj = parse_notification_type(restored, strict)
                    obj["MibModule"] = mib_name
                    module.notification_types.append(obj)
                elif obj_type == TYPE_OBJECT_TYPE:
                    obj = parse_object_type(restored, strict)
                    obj["MibModule"] = mib_name
                    module.object_types.append(obj)
                elif obj_type == TYPE_OBJECT_IDENTIFIER:
                    obj = parse_object_identifier(restored, strict)
                    obj["MibModule"] = mib_name
                    module.object_identifiers.append(obj)
                elif obj_type == TYPE_OBJECT_IDENTITY:
                    obj = parse_object_identity(restored, strict)
                    obj["MibModule"] = mib_name
                    module.other_objects.append(obj)
                elif obj_type == "MODULE-IDENTITY":
                    obj = parse_module_identity(restored, strict)
                    obj["MibModule"] = mib_name
                    module.module_identities.append(obj)
                else:
                    module.other_objects.append({"type": obj_type, "raw": restored[:200]})
            except Exception as e:
                module.warnings.append(f"Object parse error ({obj_type}): {e}")
    except Exception as e:
        module.warnings.append(f"Object extraction error: {e}")
        logger.warning("Object extraction error: %s", e)
    _t("extract_objects", t0)

    rx._reset_stores()
    return module


def parse_file(
    content: str,
    source_file: str = "",
    strict: bool = False,
    encoding: str = "utf-8",
) -> list[MibModule]:
    """
    Parse a raw MIB file (possibly containing multiple modules).

    Uses RegexDef.SplitMibs() to split, then parses each module.
    Falls back to latin-1 if UTF-8 fails (matching Java behaviour for
    'binary char' warnings from Utils.CatFile).
    """
    try:
        mibs = rx.split_mibs(content)
    except Exception as e:
        logger.error("split_mibs failed: %s", e)
        return []

    modules: list[MibModule] = []
    for name, body in mibs.items():
        logger.info("Parsing MIB module: %s", name)
        module = parse_mib(body, mib_name=name, source_file=source_file, strict=strict)
        modules.append(module)
    return modules
