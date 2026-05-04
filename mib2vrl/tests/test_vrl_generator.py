"""
test_vrl_generator.py — Tests for VRL and vector.yaml template generation.
"""

import re
from pathlib import Path

import pytest

from mib2vrl.export.export_helper import ExportHelper, HashTM, ListTM
from mib2vrl.export.export_processor import ExportProcessor
from mib2vrl.export.export_settings import ExportPrefs, ExportSettings
from mib2vrl.models.trap import Trap, GENERIC_TRAP_OIDS
from mib2vrl.models.varbind import Varbind, VarbindCandidate


TEMPLATE_DIR = Path(__file__).parent.parent / "mib2vrl" / "export" / "templates"


def make_test_traps() -> list[Trap]:
    return [
        Trap(
            name="linkDown",
            trap_number=3,
            oid="1.3.6.1.6.3.1.1.5.3",
            snmp_version=2,
            enterprise="snmp",
            description="A link went down.",
            module="IF-MIB",
            severity="d",
            varbinds=[
                Varbind(name="ifIndex", oid="1.3.6.1.2.1.2.2.1.1", syntax="INTEGER", index=0),
                Varbind(name="ifAdminStatus", oid="1.3.6.1.2.1.2.2.1.7", syntax="INTEGER", index=1),
                Varbind(name="ifOperStatus", oid="1.3.6.1.2.1.2.2.1.8", syntax="INTEGER", index=2),
            ],
        ),
        Trap(
            name="enterpriseTrap",
            trap_number=1,
            oid="1.3.6.1.4.1.99999.0.1",
            snmp_version=1,
            enterprise="myVendor",
            vendor_enterprise_oid="1.3.6.1.4.1.99999",
            description="Vendor-specific trap.",
            module="VENDOR-MIB",
            severity="2",
            varbinds=[
                Varbind(name="vendorStatus", oid="1.3.6.1.4.1.99999.2.1", syntax="INTEGER", index=0),
            ],
        ),
    ]


def make_context(traps: list[Trap]) -> dict:
    prefs = ExportPrefs(rules_varbind_oids=True, rules_varbind_details=True)
    helper = ExportHelper(export_dir="./out", version="0.1.0-test")
    settings = ExportSettings(prefs)
    return settings.init_settings(traps, [], helper)


class TestVrlRemapTemplate:
    def test_renders_without_error(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        assert "vrl_remap" in results

    def test_contains_linkdown_oid(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        assert "1.3.6.1.6.3.1.1.5.3" in content

    def test_snmpv1_specific_trap_uses_computed_oid(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        # SNMPv1 specific trap with vendor_enterprise_oid set:
        # OID = vendor_enterprise_oid + ".0." + trap_number = "1.3.6.1.4.1.99999.0.1"
        assert "snmp_trap_oid" in content
        assert "1.3.6.1.4.1.99999.0.1" in content

    def test_varbind_assignments(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        assert ".ifIndex = .varbinds[0]" in content
        assert ".ifAdminStatus = .varbinds[1]" in content

    def test_severity_default_maps_to_3(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        # linkDown has severity="d" → should render 3
        assert ".severity    = 3" in content

    def test_explicit_severity_preserved(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        # enterpriseTrap has severity="2"
        assert ".severity    = 2" in content


class TestVectorYamlTemplate:
    def test_renders_without_error(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        assert "vector.yaml" in results

    def test_is_valid_yaml(self, tmp_path):
        import yaml
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        # Should parse as valid YAML
        parsed = yaml.safe_load(content)
        assert parsed is not None

    def test_contains_sources_section(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert "sources:" in content
        assert "snmp_udp" in content

    def test_contains_transforms_section(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert "transforms:" in content

    def test_contains_sinks_section(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert "sinks:" in content


class TestNetcoolRulesTemplate:
    def test_renders_without_error(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["netcool.rules.j2"], context)
        assert "netcool.rules" in results

    def test_contains_trap_names(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["netcool.rules.j2"], context)
        content = results.get("netcool.rules", "")
        assert "linkDown" in content
        assert "enterpriseTrap" in content

    def test_snmpv1_uses_specific_trap(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["netcool.rules.j2"], context)
        content = results.get("netcool.rules", "")
        assert "@SpecificTrap == 1" in content

    def test_severity_assignment(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["netcool.rules.j2"], context)
        content = results.get("netcool.rules", "")
        assert "@Severity    = 3" in content  # linkDown default → 3


class TestEnrichmentCsvTemplate:
    def test_renders_csv(self, tmp_path):
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["enrichment_severity.csv.j2"], context)
        content = results.get("enrichment_severity.csv", "")
        assert "severity_code" in content
        assert "Critical" in content
        assert "Warning" in content


class TestExportHelper:
    def test_get_rules_severity_default(self):
        trap = Trap(name="t", severity="d")
        assert trap.get_rules_severity() == "3"

    def test_get_rules_severity_explicit(self):
        trap = Trap(name="t", severity="1")
        assert trap.get_rules_severity() == "1"

    def test_make_hash(self):
        h = ExportHelper()
        ht = h.makeHash()
        ht.put("key", "value")
        assert ht.get("key") == "value"
        assert ht.contains_key("key")
        assert not ht.contains_key("other")
        assert ht.size() == 1

    def test_make_list(self):
        h = ExportHelper()
        lt = h.makeList()
        lt.add("item1")
        lt.add("item2")
        assert lt.size() == 2
        assert lt.get(0) == "item1"
        assert lt.contains("item2")
        lt.clear()
        assert lt.size() == 0

    def test_get_syntax_text_string(self):
        h = ExportHelper()
        assert h.getSyntaxText("INTEGER") == "INTEGER"

    def test_get_syntax_text_none(self):
        h = ExportHelper()
        assert h.getSyntaxText(None) == ""

    def test_get_date_returns_datetime(self):
        from datetime import datetime
        h = ExportHelper()
        d = h.getDate()
        assert isinstance(d, datetime)

    def test_export_not_cancelled(self):
        h = ExportHelper()
        assert not h.exportCanceled()
        h.cancel()
        assert h.exportCanceled()


# ---------------------------------------------------------------------------
# GAP 2 — Trap.get_snmpv1_oid() tests
# ---------------------------------------------------------------------------

class TestGetSnmpv1Oid:
    def test_generic_trap_0_cold_start(self):
        t = Trap(name="coldStart", trap_number=0, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.1"

    def test_generic_trap_1_warm_start(self):
        t = Trap(name="warmStart", trap_number=1, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.2"

    def test_generic_trap_2_link_down(self):
        t = Trap(name="linkDown", trap_number=2, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.3"

    def test_generic_trap_3_link_up(self):
        t = Trap(name="linkUp", trap_number=3, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.4"

    def test_generic_trap_4_auth_failure(self):
        t = Trap(name="authFailure", trap_number=4, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.5"

    def test_generic_trap_5_egp_loss(self):
        t = Trap(name="egpLoss", trap_number=5, snmp_version=1)
        assert t.get_snmpv1_oid() == "1.3.6.1.6.3.1.1.5.6"

    def test_specific_trap_formula(self):
        t = Trap(
            name="vendorAlarm",
            trap_number=7,
            snmp_version=1,
            vendor_enterprise_oid="1.3.6.1.4.1.9876",
        )
        assert t.get_snmpv1_oid() == "1.3.6.1.4.1.9876.0.7"

    def test_snmpv2_returns_empty(self):
        t = Trap(name="linkDown", trap_number=0, snmp_version=2, oid="1.3.6.1.6.3.1.1.5.3")
        assert t.get_snmpv1_oid() == ""

    def test_generic_trap_oids_dict_complete(self):
        assert len(GENERIC_TRAP_OIDS) == 6
        assert all(k in GENERIC_TRAP_OIDS for k in range(6))

    def test_vrl_generic_snmpv1_uses_oid(self, tmp_path):
        """SNMPv1 generic trap (trap_number 0-5, no vendor OID) uses OID path."""
        trap = Trap(
            name="linkDown",
            trap_number=2,
            oid="1.3.6.1.6.3.1.1.5.3",
            snmp_version=1,
            enterprise="snmp",
            module="IF-MIB",
            severity="d",
        )
        prefs = ExportPrefs()
        helper = ExportHelper(export_dir="./out", version="0.1.0-test")
        settings = ExportSettings(prefs)
        context = settings.init_settings([trap], [], helper)
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        assert "1.3.6.1.6.3.1.1.5.3" in content
        assert "snmp_trap_oid" in content
        assert "snmp_specific_trap" not in content


# ---------------------------------------------------------------------------
# GAP 3 — Varbind.get_best_for_module() tests
# ---------------------------------------------------------------------------

class TestVarbindGetBestForModule:
    def _make_varbind_with_candidates(self) -> Varbind:
        return Varbind(
            name="ifIndex",
            oid="1.3.6.1.2.1.2.2.1.1",  # default (IF-MIB)
            syntax="INTEGER",
            index=0,
            module="IF-MIB",
            candidates=[
                VarbindCandidate(
                    module="IF-MIB",
                    oid="1.3.6.1.2.1.2.2.1.1",
                    syntax="INTEGER",
                    description="IF-MIB ifIndex",
                ),
                VarbindCandidate(
                    module="CISCO-IF-MIB",
                    oid="1.3.6.1.4.1.9.2.2.1.1",
                    syntax="INTEGER",
                    description="Cisco ifIndex",
                ),
            ],
        )

    def test_no_candidates_returns_self(self):
        vb = Varbind(name="myVar", oid="1.2.3", index=0)
        result = vb.get_best_for_module("ANY-MIB")
        assert result is vb

    def test_exact_module_match(self):
        vb = self._make_varbind_with_candidates()
        result = vb.get_best_for_module("CISCO-IF-MIB")
        assert result.module == "CISCO-IF-MIB"
        assert result.oid == "1.3.6.1.4.1.9.2.2.1.1"
        assert result.description == "Cisco ifIndex"

    def test_fallback_to_first_candidate(self):
        vb = self._make_varbind_with_candidates()
        result = vb.get_best_for_module("UNKNOWN-MIB")
        assert result.module == "IF-MIB"
        assert result.oid == "1.3.6.1.2.1.2.2.1.1"

    def test_index_preserved_on_best_match(self):
        vb = self._make_varbind_with_candidates()
        vb.index = 3
        result = vb.get_best_for_module("IF-MIB")
        assert result.index == 3

    def test_candidates_preserved_on_result(self):
        vb = self._make_varbind_with_candidates()
        result = vb.get_best_for_module("IF-MIB")
        assert len(result.candidates) == 2

    def test_original_varbind_unchanged(self):
        vb = self._make_varbind_with_candidates()
        original_module = vb.module
        _ = vb.get_best_for_module("CISCO-IF-MIB")
        assert vb.module == original_module  # original not mutated

    def test_name_preserved(self):
        vb = self._make_varbind_with_candidates()
        result = vb.get_best_for_module("CISCO-IF-MIB")
        assert result.name == "ifIndex"


# ---------------------------------------------------------------------------
# Issue 1 — VRL event return statement
# ---------------------------------------------------------------------------

class TestVrlReturnStatement:
    def test_vrl_ends_with_return_dot(self, tmp_path):
        """Generated VRL must end with '.' to return the event (prevents silent data loss)."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        non_empty = [line for line in content.splitlines() if line.strip()]
        assert non_empty, "VRL output should not be empty"
        assert non_empty[-1].strip() == ".", (
            "VRL transform must end with '.' to return the event — "
            "omitting this causes Vector to silently drop all events"
        )

    def test_vector_yaml_mib_remap_ends_with_return_dot(self, tmp_path):
        """Inline VRL in vector.yaml snmp_mib_remap must end with '.' (returns event)."""
        import yaml
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        parsed = yaml.safe_load(content)
        source = parsed["transforms"]["snmp_mib_remap"]["source"]
        non_empty = [line for line in source.splitlines() if line.strip()]
        assert non_empty, "snmp_mib_remap source should not be empty"
        assert non_empty[-1].strip() == ".", (
            "snmp_mib_remap VRL source must end with '.' to return the event"
        )

    def test_vector_yaml_snmp_parse_has_oid_normalization(self, tmp_path):
        """snmp_parse transform must include the OID normalization map."""
        import yaml
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        parsed = yaml.safe_load(content)
        source = parsed["transforms"]["snmp_parse"]["source"]
        assert "oid_map" in source
        assert "snmpTraps 3" in source  # linkDown generic OID text alias
        assert "1.3.6.1.6.3.1.1.5.3" in source  # linkDown numeric OID

    def test_vector_yaml_snmpv1_specific_uses_oid_match(self, tmp_path):
        """SNMPv1 specific traps in vector.yaml must use OID comparison, not enterprise+specific."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        # enterpriseTrap: vendor_enterprise_oid="1.3.6.1.4.1.99999", trap_number=1
        assert "1.3.6.1.4.1.99999.0.1" in content

    def test_sanitize_description_collapses_whitespace(self):
        """sanitize_description must collapse multiple spaces/newlines to single space."""
        from mib2vrl.export.export_helper import ExportHelper
        h = ExportHelper()
        desc = "A link   went\n\ndown due  to  environmental              issues."
        result = h.sanitize_description(desc)
        assert result == "A link went down due to environmental issues."
        assert "  " not in result
        assert "\n" not in result

    def test_sanitize_description_truncates(self):
        """sanitize_description must truncate long descriptions and append '...'."""
        from mib2vrl.export.export_helper import ExportHelper
        h = ExportHelper()
        long_desc = "word " * 50  # 250 chars
        result = h.sanitize_description(long_desc, max_len=20)
        assert len(result) <= 20
        assert result.endswith("...")

    def test_vrl_description_comment_uses_sanitize(self, tmp_path):
        """Description comments in generated VRL must use sanitize_description output."""
        trap = make_test_traps()[0]  # linkDown with description "A link went down."
        context = make_context([trap])
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vrl_remap.j2"], context)
        content = results.get("vrl_remap", "")
        assert "A link went down." in content
        assert "truncate" not in content  # Jinja2 filter should not appear literally

    def test_oid_map_uses_null_safe_lookup(self, tmp_path):
        """OID lookup uses get!() + null check: get() ?? x fails because ?? is error-only, not null-coalescing."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert "_mapped = get!(oid_map" in content, "must assign get!() result to temp var for null check"
        assert "if _mapped != null" in content, "must use explicit null check instead of ??"
        assert "get(oid_map, [.snmp_trap_oid]) ?? .snmp_trap_oid" not in content

    def test_enrichment_path_is_absolute(self, tmp_path):
        """Enrichment CSV path must be the hardcoded Docker mount path."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert 'path: "/etc/vector/enrichment_severity.csv"' in content
        assert "/app/out" not in content

    def test_enrichment_filename_has_csv_extension(self, tmp_path):
        """Enrichment template must produce a file named enrichment_severity.csv."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["enrichment_severity.csv.j2"], context)
        assert "enrichment_severity.csv" in results, (
            "Output key must be 'enrichment_severity.csv' — Vector enrichment_tables "
            "requires the .csv extension to detect format"
        )
        assert (tmp_path / "enrichment_severity.csv").exists()

    def test_enrichment_path_hardcoded_for_docker(self, tmp_path):
        """Enrichment path must be the Docker mount point, not the build-time export_dir."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        content = results.get("vector.yaml", "")
        assert 'path: "/etc/vector/enrichment_severity.csv"' in content
        assert "/app/out" not in content

    def test_vector_yaml_filename_has_extension(self, tmp_path):
        """vector.yaml.j2 must produce a file named vector.yaml (with .yaml extension)."""
        context = make_context(make_test_traps())
        proc = ExportProcessor(TEMPLATE_DIR, tmp_path)
        results = proc.render(["vector.yaml.j2"], context)
        assert "vector.yaml" in results, (
            "Output key must be 'vector.yaml' — Vector auto-detects YAML format from "
            "the .yaml extension, allowing --config flag without --config-yaml"
        )
        assert (tmp_path / "vector.yaml").exists()

    def test_docker_compose_uses_config_yaml_flag(self):
        """docker-compose.yml must reference vector.yaml (extension) or --config-yaml flag."""
        from pathlib import Path
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        assert "--config-yaml" in content or "vector.yaml" in content, (
            "Vector must be told the config is YAML — either via --config-yaml flag "
            "or via .yaml extension so Vector auto-detects the format"
        )
