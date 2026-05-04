"""
varbind.py — Varbind dataclass.

Represents a varbind variable binding in an SNMP trap.

The Java Varbind resolved multiple possible IMibObjects per varbind name
(because a name could be defined in multiple imported MIB modules).
`candidates` holds all resolved options; `get_best_for_module()` replicates
Module-aware varbind object selection logic.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VarbindCandidate:
    """
    A single resolved MIB object candidate for a varbind name.

    Per-module object entry for varbind resolution.
    """

    module: str
    """MIB module that defines this object."""

    oid: str = ""
    """Resolved dot-notation OID."""

    syntax: str = ""
    """SMI syntax type string."""

    description: str = ""
    """DESCRIPTION text from the object definition."""

    parent_oid: Optional[str] = None
    parent_name: Optional[str] = None
    parent_index: Optional[str] = None


@dataclass
class Varbind:
    """
    Represents a single varbind (VARIABLE) entry within a TRAP-TYPE or
    OBJECTS list of a NOTIFICATION-TYPE.

    Varbind with associated MIB object resolution
    """

    name: str
    """Varbind name as it appears in the VARIABLES clause (e.g. 'ifIndex')."""

    oid: str = ""
    """Resolved dot-notation OID string (e.g. '1.3.6.1.2.1.2.2.1.1')."""

    syntax: str = ""
    """SMI syntax type string (e.g. 'INTEGER', 'OCTET STRING', 'OID')."""

    description: str = ""
    """DESCRIPTION text from the MIB object definition."""

    index: int = 0
    """
    Zero-based position in the varbind list for this trap.
    Used in VRL field mapping: .varbinds[{index}]
    """

    module: str = ""
    """MIB module that defines this varbind object (best match)."""

    parent_oid: Optional[str] = None
    """OID of the parent table row object (for table scalars)."""

    parent_name: Optional[str] = None
    """Name of the parent object."""

    parent_index: Optional[str] = None
    """INDEX clause of the parent table object."""

    candidates: list[VarbindCandidate] = field(default_factory=list)
    """
    All resolved MIB object candidates for this varbind name, one per
    defining module.  Populated when multiple modules define the same name
    (e.g. ifIndex defined in IF-MIB but imported into vendor MIBs).
    """

    def get_best_for_module(self, trap_module: str) -> "Varbind":
        """
        Selects best matching MIB object for this varbind.

        Select the best candidate for the given trap module:
        1. Exact module match.
        2. First candidate (fallback).
        3. Self unchanged (no candidates registered).

        Returns a *new* Varbind with fields updated from the chosen candidate,
        leaving the original unmodified.
        """
        if not self.candidates:
            return self

        # Prefer a candidate whose module matches the trap's module
        chosen: Optional[VarbindCandidate] = None
        for c in self.candidates:
            if c.module == trap_module:
                chosen = c
                break
        if chosen is None:
            chosen = self.candidates[0]

        return Varbind(
            name=self.name,
            oid=chosen.oid,
            syntax=chosen.syntax,
            description=chosen.description,
            index=self.index,
            module=chosen.module,
            parent_oid=chosen.parent_oid,
            parent_name=chosen.parent_name,
            parent_index=chosen.parent_index,
            candidates=self.candidates,
        )
