"""
oid_parser.py — OIDParser.py.

Parses raw OID strings from MIB files into canonical form suitable
for the resolver.  Returns either:
  - A dot-notation numeric string: "1.3.6.1.2.1.2.2.1.1"
  - A "parentName leaf" string: "interfaces 1"
  - A bare name: "ifIndex"

When a V1-to-V2 conversion is needed (three-token form with non-zero
middle number), a synthetic node is registered via the `new_node_cb`
callback instead of mutating a DOM document.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Optional

from mib2vrl.parser import regexdef as rx

logger = logging.getLogger(__name__)

_unknown_counter: int = 0


def _get_unknown_object_name() -> str:
    """OIDParser.GetUnknownObjectName() — generates synthetic object names."""
    global _unknown_counter
    _unknown_counter += 1
    return "UnknownObject" + "A" * _unknown_counter


def _extract_parent_name(parent_name: str) -> str:
    """OIDParser.ExtractParentName() — strips (n) suffix from name(n)."""
    m = rx.oid_FULLYQUALIFIED_NODE.match(parent_name.strip())
    if m:
        return m.group(1)
    return parent_name


def _get_elements_from_rest(rest: str) -> list[str]:
    """OIDParser.GetElementsFromRestOfMixedOid()."""
    elements = rest.replace("\n", " ").replace("\r", " ").split(" ")
    return [e for e in elements if e.strip()]


def _parse_mixed(
    text: str,
    new_node_cb: Optional[Callable[[str, str, str], None]] = None,
) -> Optional[str]:
    """OIDParser.ParseMixed() — handles mixed name(n)/number OID formats."""
    m = rx.oid_MIXED.match(text)
    if m:
        parent_name = _extract_parent_name(m.group(1))
        rest = m.group(2)
        return _parse_mixed_parts(text, parent_name, rest, new_node_cb)

    m = rx.oid_MIXED_LONG.match(text)
    if m:
        parent_name = _extract_parent_name(m.group(1))
        rest = (m.group(2) + " " + m.group(3)).strip()
        return _parse_mixed_parts(text, parent_name, rest, new_node_cb)

    return None


def _parse_mixed_parts(
    oid: str,
    parent_name: str,
    rest: str,
    new_node_cb: Optional[Callable[[str, str, str], None]],
) -> Optional[str]:
    """OIDParser.ParseMixed(doc, oid, parentName, rest)."""
    elements = _get_elements_from_rest(rest)
    if not elements:
        raise ValueError(f"Unknown OID format: {oid!r}")

    result: Optional[str] = None
    current_parent = parent_name

    for i, elem in enumerate(elements):
        if i == len(elements) - 1:
            # Last element must be a leaf number
            leaf_m = rx.oid_LEAF.match(elem.strip())
            if leaf_m:
                result = f"{current_parent} {leaf_m.group(1)}"
                break
            raise ValueError(f"Unknown OID format: {oid!r}")

        # Intermediate elements: either name(n) or just n
        fqn_m = rx.oid_FULLYQUALIFIED_NODE.match(elem.strip())
        if fqn_m:
            name = fqn_m.group(1)
            number = fqn_m.group(2)
        else:
            leaf_m = rx.oid_LEAF.match(elem.strip())
            if not leaf_m:
                raise ValueError(f"Unknown OID format: {oid!r}")
            number = leaf_m.group(1)
            name = _get_unknown_object_name()

        if new_node_cb:
            new_node_cb(current_parent, name, number)
        current_parent = name

    return result


def parse(
    text: str,
    new_node_cb: Optional[Callable[[str, str, str], None]] = None,
) -> str:
    """
    OIDParser.Parse() — converts raw OID text to canonical form.

    new_node_cb(parent_name, new_name, number):
        Called when a synthetic intermediate OID node must be created
        (V1-to-V2 conversion or mixed-format intermediate nodes).
        Replaces DOM mutation in original Java.

    Returns canonical string — either dot-notation or "parent leaf".
    Raises ValueError for unrecognizable formats.
    """
    t = text.strip()
    logger.debug("OIDParser.parse: %r", t)

    # 1. Leaf: pure digit(s)
    m = rx.oid_LEAF.match(t)
    if m:
        return m.group(1)

    # 2. Null: "0 0"
    if rx.oid_NULL.match(t):
        return "0.0"

    # 3. V1-to-V2: "name num1 num2"
    m = rx.oid_V1TOV2.match(t)
    if m:
        parent_name = m.group(1)
        middle = m.group(2).strip()
        leaf = m.group(3).strip()
        if middle == "0":
            # Generic trap parent: "name 0 leaf" → "name leaf"
            return f"{parent_name} {leaf}"
        # Enterprise-specific: create synthetic node with deterministic name
        new_name = f"{parent_name}.{middle}"
        logger.warning("OIDParser: V1→V2 OID %r; registering synthetic node %s", t, new_name)
        if new_node_cb:
            new_node_cb(parent_name, new_name, middle)
        return f"{new_name} {leaf}"

    # 4. Space-separated digits: "1 3 6 1 2 1" → "1.3.6.1.2.1"
    m = rx.oid_SPACESEPARATED.match(t)
    if m:
        return re.sub(r" +", ".", m.group(1).strip())

    # 5. Dot-separated digits
    m = rx.oid_DOTSEPARATED.match(t)
    if m:
        return m.group(1)

    # 6. Mixed format
    result = _parse_mixed(t, new_node_cb)
    if result is not None:
        return result

    # 7. Fully-qualified: "iso(1) org(3) dod(6) ..."
    if rx.oid_FULLYQUALIFIED.match(t):
        parts = t.split()
        oid_parts: list[str] = []
        for part in parts:
            fqn_m = rx.oid_FULLYQUALIFIED_NODE.match(part.strip())
            if fqn_m:
                oid_parts.append(fqn_m.group(2))
        if oid_parts:
            return ".".join(oid_parts)

    # 8. Normal: "parentName leafNumber"
    m = rx.oid_NORMAL.match(t)
    if m:
        return f"{m.group(1)} {m.group(2)}"

    # 9. Enterprise: single bare name
    m = rx.oid_ENTERPRISE.match(t)
    if m:
        return m.group(1)

    raise ValueError(f"OIDParser: unknown OID format: {text!r}")
