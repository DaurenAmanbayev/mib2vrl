"""
mib_object_parser.py — Parser for individual MIB object blocks.

Parses individual MIB object text blocks into Python dicts.
Only trap-relevant methods are fully implemented (parseTrapType,
parseNotificationType).  Other object types are stubbed with basic
field extraction sufficient for OID resolution.


"""

from __future__ import annotations

import logging
from typing import Any, Optional

from mib2vrl.parser import regexdef as rx
from mib2vrl.parser.oid_parser import parse as parse_oid

logger = logging.getLogger(__name__)

# MIB object type identifiers
MIB_OBJECT_ELEMENT = "MibObject"
DESCRIPTION_ELEMENT = "DESCRIPTION"
REFERENCE_ELEMENT = "REFERENCE"
MACRO_ELEMENT = "MACRO"
TEXTUAL_CONVENTION_ELEMENT = "TEXTUAL-CONVENTION"
DISPLAY_HINT_ELEMENT = "DISPLAY-HINT"
STATUS_ELEMENT = "STATUS"
MODULE_ELEMENT = "MODULE"
MANDATORY_GROUPS_ELEMENT = "MANDATORY-GROUPS"
GROUP_ELEMENT = "GROUP"
OBJECT_ELEMENT = "OBJECT"
MIN_ACCESS_ELEMENT = "MIN-ACCESS"
LAST_UPDATED_ELEMENT = "LAST-UPDATED"
ORGANIZATION_ELEMENT = "ORGANIZATION"
CONTACT_INFO_ELEMENT = "CONTACT-INFO"
NOTIFICATIONS_ELEMENT = "NOTIFICATIONS"
NOTIFICATION_ELEMENT = "NOTIFICATION"
OBJECTS_ELEMENT = "OBJECTS"
VARIABLES_ELEMENT = "VARIABLES"
VARIABLE_ELEMENT = "VARIABLE"
ACCESS_ELEMENT = "ACCESS"
MAX_ACCESS_ELEMENT = "MAX-ACCESS"
UNITS_ELEMENT = "UNITS"
INDEX_ELEMENT = "INDEX"
AUGMENTS_ELEMENT = "AUGMENTS"
DEFVAL_ELEMENT = "DEFVAL"
ENTERPRISE_ELEMENT = "ENTERPRISE"
OID_ATTRIBUTE = "OID"
NAME_ATTRIBUTE = "name"
TYPE_ATTRIBUTE = "type"
VERSION_ATTRIBUTE = "version"
TRAP_NUMBER_ATTRIBUTE = "trapNumber"
MIB_MODULE_ATTRIBUTE = "MibModule"

# Object type strings
TYPE_MODULE_COMPLIANCE = "MODULE-COMPLIANCE"
TYPE_MODULE_IDENTITY = "MODULE-IDENTITY"
TYPE_NOTIFICATION_GROUP = "NOTIFICATION-GROUP"
TYPE_NOTIFICATION_TYPE = "NOTIFICATION-TYPE"
TYPE_OBJECT_CLASS = "OBJECT-CLASS"
TYPE_OBJECT_GROUP = "OBJECT-GROUP"
TYPE_OBJECT_IDENTIFIER = "OBJECT IDENTIFIER"
TYPE_OBJECT_IDENTITY = "OBJECT-IDENTITY"
TYPE_OBJECT_TYPE = "OBJECT-TYPE"
TYPE_TRAP_TYPE = "TRAP-TYPE"


# ---------------------------------------------------------------------------
# Result dict structure (replaces DOM node)
# Keys mirror XML attribute/element names from original
# ---------------------------------------------------------------------------
MibObjectDict = dict[str, Any]

_synthetic_nodes: list[dict[str, str]] = []


def _new_node_cb(parent: str, name: str, number: str) -> None:
    """Callback for OIDParser synthetic node creation (replaces DOM mutation)."""
    _synthetic_nodes.append({"parent": parent, "name": name, "number": number})


def _try_parse_oid(ancestors: Optional[str], strict: bool) -> str:
    """Wrapper around parse_oid with error handling."""
    if not ancestors:
        return ""
    try:
        result = parse_oid(ancestors.strip(), _new_node_cb)
        return result
    except ValueError as e:
        logger.warning("OID parse failed for %r: %s", ancestors, e)
        if strict:
            raise
        return ""


def parse_trap_type(text: str, strict: bool = False) -> MibObjectDict:
    """
    MibObjectParser.parseTrapType() — parses SNMPv1 TRAP-TYPE definition.

    Returns dict with keys: type, name, trapNumber, OID, ENTERPRISE,
    DESCRIPTION, REFERENCE, VARIABLES (list of variable names).
    """
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_TRAP_TYPE, NAME_ATTRIBUTE: "", TRAP_NUMBER_ATTRIBUTE: "0"}

    # obj_TRAPTYPE: /^(\S+)\s+TRAP-TYPE\s+(.*?)\s*::=\s*([0-9]+)/s
    m = rx.obj_TRAPTYPE.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        result[TRAP_NUMBER_ATTRIBUTE] = m.group(3).strip()
        parts = m.group(2)
    else:
        logger.warning("parseTrapType: no TRAP-TYPE match in %r", text[:120])
        parts = text

    # ENTERPRISE clause
    e_m = rx.part_ENTERPRISE.search(parts) if parts else None
    if e_m:
        enterprise_raw = e_m.group(1)
        result[ENTERPRISE_ELEMENT] = enterprise_raw.strip()
        result[OID_ATTRIBUTE] = _try_parse_oid(enterprise_raw, strict)
    else:
        msg = "parseTrapType: missing ENTERPRISE clause"
        logger.warning("%s in %r", msg, text[:120])
        if strict:
            raise ValueError(msg)

    # DESCRIPTION
    d_m = rx.part_DESCRIPTION.search(text)
    result[DESCRIPTION_ELEMENT] = d_m.group(1) if d_m else ""

    # REFERENCE
    r_m = rx.part_REFERENCE.search(text)
    result[REFERENCE_ELEMENT] = r_m.group(1) if r_m else ""

    # VARIABLES clause
    result[VARIABLES_ELEMENT] = []
    v_m = rx.part_VARIABLES.search(parts) if parts else None
    if v_m:
        varbind_list = v_m.group(1)
        result[VARIABLES_ELEMENT] = [v.strip() for v in varbind_list.split(",") if v.strip()]
    else:
        logger.debug("parseTrapType: no VARIABLES clause")

    return result


def parse_notification_type(text: str, strict: bool = False) -> MibObjectDict:
    """
    MibObjectParser.parseNotificationType() — parses SNMPv2 NOTIFICATION-TYPE.

    Returns dict with keys: type, name, OID, STATUS, DESCRIPTION, REFERENCE,
    OBJECTS (list of object names).
    """
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_NOTIFICATION_TYPE, NAME_ATTRIBUTE: ""}

    # obj_NOTIFICATIONTYPE: /^(\S+)\s+NOTIFICATION-TYPE(.*?)::=\s*{\s*([^{]+)\s*}/s
    m = rx.obj_NOTIFICATIONTYPE.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        parts = m.group(2)
        ancestors = m.group(3)
    else:
        logger.warning("parseNotificationType: no NOTIFICATION-TYPE match in %r", text[:120])
        parts = ""
        ancestors = ""

    # STATUS
    s_m = rx.part_STATUS.search(parts) if parts else None
    if s_m:
        result[STATUS_ELEMENT] = s_m.group(1).strip()
    else:
        logger.warning("parseNotificationType: missing STATUS in %r", text[:120])
        if strict:
            raise ValueError("Missing STATUS in NOTIFICATION-TYPE")
        result[STATUS_ELEMENT] = ""

    # DESCRIPTION
    d_m = rx.part_DESCRIPTION.search(text)
    result[DESCRIPTION_ELEMENT] = d_m.group(1) if d_m else ""

    # REFERENCE
    r_m = rx.part_REFERENCE.search(text)
    result[REFERENCE_ELEMENT] = r_m.group(1) if r_m else ""

    # OBJECTS clause
    result[OBJECTS_ELEMENT] = []
    o_m = rx.part_OBJECTS.search(parts) if parts else None
    if o_m:
        obj_list = o_m.group(1)
        result[OBJECTS_ELEMENT] = [o.strip() for o in obj_list.split(",") if o.strip()]

    # OID
    result[OID_ATTRIBUTE] = _try_parse_oid(ancestors, strict)

    return result


def parse_object_identifier(text: str, strict: bool = False) -> MibObjectDict:
    """MibObjectParser.parseObjectIdentifier() — OBJECT IDENTIFIER definition."""
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_OBJECT_IDENTIFIER, NAME_ATTRIBUTE: ""}
    m = rx.obj_OBJECTIDENTIFIER.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        result[OID_ATTRIBUTE] = _try_parse_oid(m.group(2), strict)
    return result


def parse_object_type(text: str, strict: bool = False) -> MibObjectDict:
    """MibObjectParser.parseObjectType() — OBJECT-TYPE definition (stub)."""
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_OBJECT_TYPE, NAME_ATTRIBUTE: ""}
    m = rx.obj_OBJECTTYPE.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        result[OID_ATTRIBUTE] = _try_parse_oid(m.group(3), strict)
        parts = m.group(2)
        s_m = rx.part_SYNTAX.search(parts) if parts else None
        result["SYNTAX"] = s_m.group(1).strip() if s_m else ""
        d_m = rx.part_DESCRIPTION.search(text)
        result[DESCRIPTION_ELEMENT] = d_m.group(1) if d_m else ""
        ma_m = rx.part_MAXACCESS.search(parts) if parts else None
        result[MAX_ACCESS_ELEMENT] = ma_m.group(1).strip() if ma_m else ""
        st_m = rx.part_STATUS.search(parts) if parts else None
        result[STATUS_ELEMENT] = st_m.group(1).strip() if st_m else ""
    return result


def parse_module_identity(text: str, strict: bool = False) -> MibObjectDict:
    """MibObjectParser.parseModuleIdentity() — MODULE-IDENTITY (stub)."""
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_MODULE_IDENTITY, NAME_ATTRIBUTE: ""}
    m = rx.obj_MODULEIDENTITY.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        result[OID_ATTRIBUTE] = _try_parse_oid(m.group(3), strict)
    return result


def parse_object_identity(text: str, strict: bool = False) -> MibObjectDict:
    """MibObjectParser.parseObjectIdentity() — OBJECT-IDENTITY (stub)."""
    result: MibObjectDict = {TYPE_ATTRIBUTE: TYPE_OBJECT_IDENTITY, NAME_ATTRIBUTE: ""}
    m = rx.obj_OBJECTIDENTITY.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(1).strip()
        result[OID_ATTRIBUTE] = _try_parse_oid(m.group(3), strict)
    return result


def parse_textual_convention(text: str, strict: bool = False) -> MibObjectDict:
    """MibObjectParser.parseTextualConvention() — TC definition (stub)."""
    result: MibObjectDict = {TYPE_ATTRIBUTE: TEXTUAL_CONVENTION_ELEMENT, NAME_ATTRIBUTE: ""}
    # Try v2 first
    m = rx.obj_V2TC.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(2).strip()
        result["SYNTAX"] = m.group(3).strip() if m.group(3) else ""
        result[VERSION_ATTRIBUTE] = "2"
        return result
    # Try v1
    m = rx.obj_V1TC.search(text)
    if m:
        result[NAME_ATTRIBUTE] = m.group(2).strip()
        result["SYNTAX"] = m.group(3).strip() if m.group(3) else ""
        result[VERSION_ATTRIBUTE] = "1"
    return result


def get_synthetic_nodes() -> list[dict[str, str]]:
    """Returns and clears the list of synthetic OID nodes created during parsing."""
    nodes = list(_synthetic_nodes)
    _synthetic_nodes.clear()
    return nodes
