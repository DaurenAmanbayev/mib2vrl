"""
field_mapper.py — Bidirectional mapping between Netcool @Field names
and VRL .field_name paths.

All fields listed in the rules2vrl spec plus the complete ObjectServer
field set (Identifier, Node, Summary, Severity, etc.).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Netcool @Field → VRL .field mapping
# ---------------------------------------------------------------------------

NETCOOL_TO_VRL: dict[str, str] = {
    "@Agent":           ".agent",
    "@AlertGroup":      ".alert_group",
    "@AlertKey":        ".alert_key",
    "@Summary":         ".summary",
    "@Severity":        ".severity",
    "@Node":            ".node",
    "@NodeAlias":       ".node_alias",
    "@Manager":         ".manager",
    "@Class":           "._class",          # 'class' is reserved in some contexts
    "@Identifier":      ".identifier",
    "@Type":            ".type",
    "@Location":        ".location",
    "@Customer":        ".customer",
    "@Service":         ".service",
    "@FirstOccurrence": ".first_occurrence",
    "@LastOccurrence":  ".last_occurrence",
    "@Grade":           ".grade",
    "@ProcessReq":      ".process_req",
    "@Acknowledged":    ".acknowledged",
    "@Suppressed":      ".suppressed",
    # Probe-specific fields
    "@SpecificTrap":    ".snmp_specific_trap",
    "@Enterprise":      ".enterprise",
    "@AgentAddr":       ".agent_addr",
    "@GenericTrap":     ".generic_trap",
    "@TrapNum":         ".trap_num",
    "@Community":       ".community",
    "@Protocol":        ".protocol",
    "@OsTime":          ".os_time",
    "@OwnerUID":        ".owner_uid",
    "@OwnerGID":        ".owner_gid",
    "@ExtendedAttr":    ".extended_attr",
    "@SuppressEscl":    ".suppress_escl",
    "@ClearOnAcknowledge": ".clear_on_acknowledge",
    "@InternalLast":    ".internal_last",
    "@BSM_Identity":    ".bsm_identity",
    "@TaskList":        ".task_list",
    "@TicketKey":       ".ticket_key",
    "@NmosObjInst":     ".nmos_obj_inst",
    "@NmosSerial":      ".nmos_serial",
    "@NmosCausedBy":    ".nmos_caused_by",
    "@NmosDomainName":  ".nmos_domain_name",
    "@RemoteName":      ".remote_name",
    "@RemoteNodeAlias": ".remote_node_alias",
    "@RemoteManager":   ".remote_manager",
    "@Tally":           ".tally",
    "@X733EventType":   ".x733_event_type",
    "@X733ProbableCause": ".x733_probable_cause",
    "@X733SpecificProb": ".x733_specific_prob",
    "@X733CorrNotifs":  ".x733_corr_notifs",
    "@URL":             ".url",
    "@LocalNodeAlias":  ".local_node_alias",
    "@LocalPriObj":     ".local_pri_obj",
    "@LocalSecObj":     ".local_sec_obj",
    "@LocalRootObj":    ".local_root_obj",
    "@AdvCorrCauses":   ".adv_corr_causes",
    "@AdvCorrSymptoms": ".adv_corr_symptoms",
    "@ServerName":      ".server_name",
    "@ServerSerial":    ".server_serial",
}

# Reverse mapping for reference
VRL_TO_NETCOOL: dict[str, str] = {v: k for k, v in NETCOOL_TO_VRL.items()}

# Pattern for $N → .varbinds[N-1]
_VARBIND_RE = re.compile(r'^\$([0-9]+)$')


def field_to_vrl(netcool_field: str) -> str:
    """
    Map a Netcool @FieldName string to its VRL .field_name equivalent.

    Falls back to snake_case conversion for unknown fields, prefixed with
    a leading dot.  Unknown fields are logged at DEBUG level.
    """
    if netcool_field in NETCOOL_TO_VRL:
        return NETCOOL_TO_VRL[netcool_field]

    # Fallback: @UnknownField → .unknown_field  (camelCase → snake_case)
    name = netcool_field.lstrip("@")
    snake = _camel_to_snake(name)
    return f".{snake}"


def varbind_to_vrl(index: int) -> str:
    """
    Map a 0-based varbind index to its VRL .varbinds[N] reference.

    index should already be 0-based (converted from $N → N-1 at parse time).
    """
    return f".varbinds[{index}]"


def named_varbind_to_vrl(name: str) -> str:
    """
    Map a named varbind variable $name to a VRL local variable _name.

    VRL local variables use underscore prefix by convention.
    Hyphens are replaced with underscores for valid VRL identifiers.
    """
    return f"_{name.replace('-', '_')}"


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase or mixedCase to snake_case."""
    # Insert underscore before sequences of uppercase letters
    s1 = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()
