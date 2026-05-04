"""
test_parser.py — Integration tests for MibObjectParser and MibParser.
"""

import pytest
from mib2vrl.parser.mib_object_parser import (
    parse_trap_type,
    parse_notification_type,
    parse_object_identifier,
    parse_object_type,
    TYPE_TRAP_TYPE,
    TYPE_NOTIFICATION_TYPE,
)
from mib2vrl.parser.mib_parser import parse_mib, parse_file


LINKDOWN_TRAP_V1 = """\
linkDown TRAP-TYPE
    ENTERPRISE snmp
    VARIABLES { ifIndex, ifAdminStatus, ifOperStatus }
    DESCRIPTION
        "A linkDown trap signifies that the sending protocol
         entity recognizes a failure in one of the communication
         links represented in the agent's configuration."
    ::= 3
"""

LINKDOWN_NOTIF_V2 = """\
linkDown NOTIFICATION-TYPE
    OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }
    STATUS  current
    DESCRIPTION
        "A linkDown notification signifies that the SNMP entity,
         acting in an agent role, has detected that the ifOperStatus
         object for one of its communication links left the up state."
    ::= { snmpTraps 3 }
"""

IF_MIB_SNIPPET = """\
IF-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Counter32, Gauge32, TimeTicks,
        Integer32, PhysAddress, TruthValue, RowStatus,
        NOTIFICATION-TYPE                        FROM SNMPv2-SMI
    DisplayString, PhysAddress, TruthValue       FROM SNMPv2-TC
    MODULE-COMPLIANCE, OBJECT-GROUP,
        NOTIFICATION-GROUP                       FROM SNMPv2-CONF
    snmpTraps                                    FROM SNMPv2-MIB;

ifMIB MODULE-IDENTITY
    LAST-UPDATED "200006140000Z"
    ORGANIZATION "IETF Interfaces MIB Working Group"
    DESCRIPTION  "The MIB module to describe generic objects for network interfaces."
    ::= { mib-2 31 }

linkDown NOTIFICATION-TYPE
    OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }
    STATUS  current
    DESCRIPTION "A linkDown trap."
    ::= { snmpTraps 3 }

linkUp NOTIFICATION-TYPE
    OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }
    STATUS  current
    DESCRIPTION "A linkUp trap."
    ::= { snmpTraps 4 }

END
"""


class TestParseTrapType:
    def test_name_extracted(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert r["name"] == "linkDown"

    def test_trap_number(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert r["trapNumber"] == "3"

    def test_enterprise(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert r["ENTERPRISE"] == "snmp"

    def test_variables(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert "ifIndex" in r["VARIABLES"]
        assert "ifAdminStatus" in r["VARIABLES"]
        assert "ifOperStatus" in r["VARIABLES"]

    def test_description(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert "linkDown" in r["DESCRIPTION"] or "failure" in r["DESCRIPTION"]

    def test_type_field(self):
        r = parse_trap_type(LINKDOWN_TRAP_V1)
        assert r["type"] == TYPE_TRAP_TYPE

    def test_missing_enterprise_non_strict(self):
        text = "bad TRAP-TYPE ::= 99\n"
        r = parse_trap_type(text, strict=False)
        assert r["name"] == "bad"

    def test_missing_enterprise_strict_raises(self):
        text = "bad TRAP-TYPE ::= 99\n"
        with pytest.raises(ValueError):
            parse_trap_type(text, strict=True)


class TestParseNotificationType:
    def test_name_extracted(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        assert r["name"] == "linkDown"

    def test_objects(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        assert "ifIndex" in r["OBJECTS"]
        assert "ifAdminStatus" in r["OBJECTS"]

    def test_status(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        assert r["STATUS"] == "current"

    def test_description(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        assert len(r["DESCRIPTION"]) > 0

    def test_type_field(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        assert r["type"] == TYPE_NOTIFICATION_TYPE

    def test_oid_extracted(self):
        r = parse_notification_type(LINKDOWN_NOTIF_V2)
        # OID comes from parse_oid("snmpTraps 3") → "snmpTraps 3" (name ref)
        assert r["OID"] != ""


class TestParseObjectIdentifier:
    def test_basic(self):
        text = "mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }"
        r = parse_object_identifier(text)
        assert r["name"] == "mib-2"
        assert r["OID"] != ""


class TestParseMib:
    def test_parse_if_mib_snippet(self):
        module = parse_mib(IF_MIB_SNIPPET, mib_name="IF-MIB")
        assert module.name == "IF-MIB"

    def test_notification_types_found(self):
        module = parse_mib(IF_MIB_SNIPPET, mib_name="IF-MIB")
        names = [n["name"] for n in module.notification_types]
        assert "linkDown" in names
        assert "linkUp" in names

    def test_imports_found(self):
        module = parse_mib(IF_MIB_SNIPPET, mib_name="IF-MIB")
        # Should have imports from SNMPv2-SMI and SNMPv2-TC at minimum
        mib_names = {mib for _, mib in module.imports}
        assert len(mib_names) > 0

    def test_module_identity_found(self):
        module = parse_mib(IF_MIB_SNIPPET, mib_name="IF-MIB")
        assert len(module.module_identities) >= 1

    def test_no_fatal_errors(self):
        module = parse_mib(IF_MIB_SNIPPET, mib_name="IF-MIB")
        assert len(module.errors) == 0


class TestParseFile:
    def test_split_multiple_mibs(self):
        text = """\
MIB-ONE DEFINITIONS ::= BEGIN
testA OBJECT IDENTIFIER ::= { enterprises 1 }
END

MIB-TWO DEFINITIONS ::= BEGIN
testB OBJECT IDENTIFIER ::= { enterprises 2 }
END
"""
        modules = parse_file(text, source_file="test.mib")
        names = [m.name for m in modules]
        assert "MIB-ONE" in names
        assert "MIB-TWO" in names

    def test_single_mib_file(self):
        modules = parse_file(IF_MIB_SNIPPET, source_file="IF-MIB.txt")
        assert len(modules) == 1
        assert modules[0].name == "IF-MIB"
