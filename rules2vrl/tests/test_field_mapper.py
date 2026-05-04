"""
test_field_mapper.py — Tests for the Netcool @Field → VRL .field mapper.

Every entry in NETCOOL_TO_VRL is exercised.
"""

import pytest

from rules2vrl.codegen.field_mapper import (
    NETCOOL_TO_VRL,
    VRL_TO_NETCOOL,
    field_to_vrl,
    varbind_to_vrl,
    named_varbind_to_vrl,
    _camel_to_snake,
)


# ---------------------------------------------------------------------------
# field_to_vrl — known mappings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("netcool,expected", [
    ("@Agent",            ".agent"),
    ("@AlertGroup",       ".alert_group"),
    ("@AlertKey",         ".alert_key"),
    ("@Summary",          ".summary"),
    ("@Severity",         ".severity"),
    ("@Node",             ".node"),
    ("@NodeAlias",        ".node_alias"),
    ("@Manager",          ".manager"),
    ("@Class",            "._class"),
    ("@Identifier",       ".identifier"),
    ("@Type",             ".type"),
    ("@Location",         ".location"),
    ("@Customer",         ".customer"),
    ("@Service",          ".service"),
    ("@FirstOccurrence",  ".first_occurrence"),
    ("@LastOccurrence",   ".last_occurrence"),
    ("@Grade",            ".grade"),
    ("@ProcessReq",       ".process_req"),
    ("@Acknowledged",     ".acknowledged"),
    ("@Suppressed",       ".suppressed"),
    ("@SpecificTrap",     ".snmp_specific_trap"),
    ("@Enterprise",       ".enterprise"),
    ("@AgentAddr",        ".agent_addr"),
])
def test_known_field_mapping(netcool: str, expected: str):
    assert field_to_vrl(netcool) == expected


# ---------------------------------------------------------------------------
# field_to_vrl — fallback for unknown fields
# ---------------------------------------------------------------------------

def test_unknown_field_fallback():
    result = field_to_vrl("@UnknownField")
    assert result.startswith(".")
    # Should be snake_case
    assert result == ".unknown_field"


def test_unknown_field_camel_case_conversion():
    result = field_to_vrl("@MyCustomField")
    assert result == ".my_custom_field"


# ---------------------------------------------------------------------------
# varbind_to_vrl
# ---------------------------------------------------------------------------

def test_varbind_index_0():
    assert varbind_to_vrl(0) == ".varbinds[0]"

def test_varbind_index_1():
    assert varbind_to_vrl(1) == ".varbinds[1]"

def test_varbind_index_9():
    assert varbind_to_vrl(9) == ".varbinds[9]"


# ---------------------------------------------------------------------------
# named_varbind_to_vrl
# ---------------------------------------------------------------------------

def test_named_varbind_simple():
    assert named_varbind_to_vrl("ifIndex") == "_ifIndex"

def test_named_varbind_complex():
    assert named_varbind_to_vrl("ciscoEnvMonVoltageState") == "_ciscoEnvMonVoltageState"


# ---------------------------------------------------------------------------
# Bidirectional mapping consistency
# ---------------------------------------------------------------------------

def test_all_netcool_fields_map_to_vrl():
    """Every entry in NETCOOL_TO_VRL should produce a .xxx string."""
    for netcool, vrl in NETCOOL_TO_VRL.items():
        assert vrl.startswith("."), f"{netcool} maps to {vrl!r} without leading dot"


def test_reverse_mapping_complete():
    """VRL_TO_NETCOOL should cover all values of NETCOOL_TO_VRL."""
    for vrl_field in NETCOOL_TO_VRL.values():
        assert vrl_field in VRL_TO_NETCOOL, f"{vrl_field} missing from VRL_TO_NETCOOL"


def test_no_duplicate_vrl_values():
    """Each @Field must map to a unique VRL path."""
    vrl_values = list(NETCOOL_TO_VRL.values())
    assert len(vrl_values) == len(set(vrl_values)), "Duplicate VRL mappings detected"


# ---------------------------------------------------------------------------
# _camel_to_snake helper
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("camel,snake", [
    ("AlertGroup",    "alert_group"),
    ("AlertKey",      "alert_key"),
    ("NodeAlias",     "node_alias"),
    ("FirstOccurrence", "first_occurrence"),
    ("BSMIdentity",   "bsm_identity"),
    ("Agent",         "agent"),
    ("Class",         "class"),
])
def test_camel_to_snake(camel: str, snake: str):
    assert _camel_to_snake(camel) == snake
