"""
oid_resolver.py — OID resolution via graphlib.TopologicalSorter.

Replaces AbstractMibObjectResolver.resolveFromHash() which used a
while-passCount loop (bounded by gReferencedObjects.size()).

The Java loop would break after passCount > size, silently leaving
unresolved OIDs.  We replace it with a proper topological sort:
  - Cycle → graphlib.CycleError with clear path message.
  - Unknown parent → warning, OID left as relative reference.

Seed registry from AbstractMibObjectResolver.initAncestorsList():
  ccitt        = 0
  iso          = 1
  joint-iso-ccitt = 2  (also: joint-iso-itu-t)
  mib-2        = 1.3.6.1.2.1
  enterprises  = 1.3.6.1.4.1
"""

from __future__ import annotations

import graphlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seed OID registry  (RootMibObject equivalents from AbstractMibObjectResolver)
# ---------------------------------------------------------------------------
SEED_OIDS: dict[str, str] = {
    "ccitt": "0",
    "iso": "1",
    "joint-iso-ccitt": "2",
    "joint-iso-itu-t": "2",
    # Commonly needed well-known nodes
    "org": "1.3",
    "dod": "1.3.6",
    "internet": "1.3.6.1",
    "mgmt": "1.3.6.1.2",
    "mib-2": "1.3.6.1.2.1",
    "transmission": "1.3.6.1.2.1.10",
    "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5",
    "snmpV2": "1.3.6.1.6",
    "snmpDomains": "1.3.6.1.6.1",
    "snmpProxys": "1.3.6.1.6.2",
    "snmpModules": "1.3.6.1.6.3",
}


@dataclass
class OidNode:
    """
    Represents one resolvable OID node (mirrors IReferencedObject).

    parent_ref is the name that must be resolved first.
    If parent_ref is empty string, the node is a root.
    """

    name: str
    """Fully-qualified name: 'moduleName.objectName' or seed name."""

    object_name: str
    """Just the object name portion."""

    parent_ref: str
    """Name of the parent node (may be bare name or module.name)."""

    relative_oid: str
    """
    The leaf or sub-OID fragment relative to parent (e.g. "2" or "1.2").
    """

    resolved_oid: str = ""
    """Filled in during resolution."""

    is_resolved: bool = False


class OidResolver:
    """
    Resolves relative OID references to absolute dot-notation OIDs.

    Usage:
        resolver = OidResolver()
        resolver.add_node("IF-MIB.interfaces", "interfaces", "mib-2", "2")
        resolver.add_node("IF-MIB.ifNumber", "ifNumber", "interfaces", "1")
        registry = resolver.resolve()
        # registry["IF-MIB.ifNumber"] == "1.3.6.1.2.1.2.1"
    """

    def __init__(self) -> None:
        self._nodes: dict[str, OidNode] = {}
        # Pre-seed with well-known OIDs
        for name, oid in SEED_OIDS.items():
            node = OidNode(
                name=name,
                object_name=name,
                parent_ref="",
                relative_oid=oid,
                resolved_oid=oid,
                is_resolved=True,
            )
            self._nodes[name] = node

    def add_node(
        self,
        name: str,
        object_name: str,
        parent_ref: str,
        relative_oid: str,
    ) -> None:
        """
        Register an OID node for resolution.

        name         — unique key (e.g. "IF-MIB.ifIndex" or just "ifIndex")
        object_name  — the bare object name used for fallback lookup
        parent_ref   — the parent name reference from the MIB
        relative_oid — leaf number(s) relative to parent
        """
        if name in self._nodes and self._nodes[name].is_resolved:
            return  # seed or already added
        self._nodes[name] = OidNode(
            name=name,
            object_name=object_name,
            parent_ref=parent_ref,
            relative_oid=relative_oid,
        )

    def _find_parent(self, parent_ref: str, module: str) -> Optional[str]:
        """
        Look up a parent reference, trying module-qualified name first,
        then bare name.  Mirrors AbstractMibObjectResolver.lookupReferencedBy().
        """
        # Try fully-qualified: "module.name"
        fq = f"{module}.{parent_ref}" if module else parent_ref
        if fq in self._nodes:
            return fq
        # Try bare name
        if parent_ref in self._nodes:
            return parent_ref
        # Try just object_name scan
        for node in self._nodes.values():
            if node.object_name == parent_ref:
                return node.name
        return None

    def resolve(self) -> dict[str, str]:
        """
        Resolve all registered nodes to absolute OIDs.

        Returns mapping of name → absolute OID string.
        Raises graphlib.CycleError if a dependency cycle is detected.
        """
        # Build dependency graph for unresolved nodes only
        graph: dict[str, set[str]] = {}
        for name, node in self._nodes.items():
            if node.is_resolved:
                graph[name] = set()
                continue
            # Find the canonical parent key
            parent_key = self._find_parent(node.parent_ref, "")
            if parent_key is None:
                # Unknown parent — treat as root with warning
                logger.warning(
                    "OID resolver: cannot find parent '%s' for '%s'; "
                    "treating as unresolvable root",
                    node.parent_ref,
                    name,
                )
                graph[name] = set()
            else:
                graph[name] = {parent_key}
                # Store back the resolved parent key
                node.parent_ref = parent_key

        try:
            ts = graphlib.TopologicalSorter(graph)
            order = list(ts.static_order())
        except graphlib.CycleError as exc:
            cycle_path = " → ".join(str(n) for n in exc.args[1])
            raise graphlib.CycleError(
                f"OID dependency cycle detected: {cycle_path}"
            ) from exc

        for name in order:
            node = self._nodes[name]
            if node.is_resolved:
                continue
            parent_key = node.parent_ref
            parent_node = self._nodes.get(parent_key)
            if parent_node and parent_node.resolved_oid:
                node.resolved_oid = (
                    parent_node.resolved_oid + "." + node.relative_oid
                )
            else:
                # Parent unresolvable — use relative fragment as-is
                node.resolved_oid = node.relative_oid
                logger.warning(
                    "OID resolver: parent '%s' has no resolved OID for '%s'",
                    parent_key,
                    name,
                )
            node.is_resolved = True

        return {n: node.resolved_oid for n, node in self._nodes.items()}
