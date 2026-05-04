"""
trap.py — Trap dataclass.

Models a single SNMP trap/notification with resolved varbinds and OID.

Severity mapping: if severity == "d" (GUI default) → emit "3" (WARNING).
Otherwise the stored severity string is used as-is.

SNMP versions:
  1 → SNMPv1 TRAP-TYPE (enterprise-specific or generic)
  2 → SNMPv2 NOTIFICATION-TYPE
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mib2vrl.models.varbind import Varbind


# Sentinel values for trap severity
DEFAULT_TRAP: int = -1
ENTERPRISE_WIDE_TRAP: int = -2

# SNMPv1 generic trap OID map (RFC 1215 / RFC 3418)
# Generic trap numbers 0–5 map to snmpTraps subtree 1.3.6.1.6.3.1.1.5.{n+1}
GENERIC_TRAP_OIDS: dict[int, str] = {
    0: "1.3.6.1.6.3.1.1.5.1",  # coldStart
    1: "1.3.6.1.6.3.1.1.5.2",  # warmStart
    2: "1.3.6.1.6.3.1.1.5.3",  # linkDown
    3: "1.3.6.1.6.3.1.1.5.4",  # linkUp
    4: "1.3.6.1.6.3.1.1.5.5",  # authenticationFailure
    5: "1.3.6.1.6.3.1.1.5.6",  # egpNeighborLoss
}


@dataclass
class Trap:
    """
    Represents a single SNMP trap/notification extracted from a MIB.

    Dataclass representing a parsed SNMP trap.
    """

    # -----------------------------------------------------------------------
    # Core identity
    # -----------------------------------------------------------------------
    name: str
    """Object name as defined in the MIB (e.g. 'linkDown')."""

    trap_number: int = 0
    """
    Trap-specific number from TRAP-TYPE ::= N.
    0 for NOTIFICATION-TYPE (SNMPv2).
    -1 (DEFAULT_TRAP) for generic traps.
    -2 (ENTERPRISE_WIDE_TRAP) for enterprise-wide.
    """

    oid: str = ""
    """Resolved full dot-notation OID string."""

    snmp_version: int = 2
    """1 for SNMPv1 TRAP-TYPE, 2 for SNMPv2 NOTIFICATION-TYPE."""

    # -----------------------------------------------------------------------
    # Enterprise / source
    # -----------------------------------------------------------------------
    enterprise: str = ""
    """Enterprise name from the ENTERPRISE clause (SNMPv1) or OID parent."""

    trap_enterprise_oid: str = ""
    """Resolved OID of the ENTERPRISE clause."""

    vendor_enterprise_name: str = ""
    """Top-level vendor enterprise name (e.g. 'cisco')."""

    vendor_enterprise_oid: Optional[str] = None
    """
    Set for specific (enterprise) traps; None for generic.
    Mirrors Trap.isSpecificTrap() == (gVendorEnterpriseOID != None).
    """

    trap_parent_name: str = ""
    """Parent node name in the OID tree."""

    module: str = ""
    """MIB module name this trap belongs to."""

    module_version: str = ""
    """MIB module version string."""

    source_file: str = ""
    """Path of the source MIB file."""

    # -----------------------------------------------------------------------
    # Object fields
    # -----------------------------------------------------------------------
    description: str = ""
    status: str = "current"
    reference: str = ""
    alert_group: str = ""

    # -----------------------------------------------------------------------
    # Netcool rule-specific fields (user-configurable via GUI in original app)
    # -----------------------------------------------------------------------
    severity: str = "d"
    """
    Severity string. "d" means default (maps to 3=WARNING in rules).
    Values: "d", "1", "2", "3", "4", "5" matching Netcool severity levels.
    """

    type_field: str = "1"
    """Alert type field value (string int)."""

    expire_time: str = "0"
    """Expire time value string."""

    expire_time_unit: str = "s"
    """Expire time unit ('s'=seconds, 'm'=minutes, etc.)."""

    code_block: str = ""
    """Custom Netcool rules code block."""

    # -----------------------------------------------------------------------
    # Varbinds
    # -----------------------------------------------------------------------
    varbinds: list[Varbind] = field(default_factory=list)
    """Ordered list of resolved varbind objects."""

    # -----------------------------------------------------------------------
    # Computed properties
    # -----------------------------------------------------------------------
    def get_rules_severity(self) -> str:
        """
        Maps severity codes to string values.

        Returns "3" (WARNING) when severity is "d" (the GUI default),
        otherwise returns the stored severity string.
        """
        if self.severity == "d":
            return "3"
        return self.severity

    @property
    def is_specific_trap(self) -> bool:
        """isSpecificTrap() — True if vendor_enterprise_oid is set."""
        return self.vendor_enterprise_oid is not None

    @property
    def expire_time_seconds(self) -> int:
        """getExpireTimeSeconds() — expire time as integer seconds."""
        try:
            return int(self.expire_time)
        except (ValueError, TypeError):
            return 0

    def get_varbind_names(self) -> list[str]:
        """getVarbindNames() — list of varbind name strings."""
        return [v.name for v in self.varbinds]

    def get_snmpv1_oid(self) -> str:
        """
        Compute the effective OID for SNMPv1 trap matching.

        - Generic traps (trap_number 0–5, no vendor_enterprise_oid):
          map to snmpTraps sub-tree: 1.3.6.1.6.3.1.1.5.{trap_number+1}
        - Specific / enterprise traps (vendor_enterprise_oid set):
          formula:  vendor_enterprise_oid + ".0." + str(trap_number)

        Used by vrl_remap.j2 to emit correct OID-based match conditions for
        SNMPv1 traps instead of the less-precise enterprise+specific_trap pair.
        Returns empty string if not applicable (e.g. SNMPv2 trap).
        """
        if self.snmp_version != 1:
            return ""
        if self.vendor_enterprise_oid is not None:
            # Specific enterprise trap
            return f"{self.vendor_enterprise_oid}.0.{self.trap_number}"
        # Generic trap (0–5)
        return GENERIC_TRAP_OIDS.get(self.trap_number, "")
