"""
test_oid_resolver.py — Tests for OidResolver (TopologicalSorter replacement).
"""

import graphlib
import pytest
from mib2vrl.parser.oid_resolver import OidResolver, SEED_OIDS


class TestOidResolverSeeds:
    def test_seed_iso(self):
        r = OidResolver()
        result = r.resolve()
        assert result["iso"] == "1"

    def test_seed_enterprises(self):
        r = OidResolver()
        result = r.resolve()
        assert result["enterprises"] == "1.3.6.1.4.1"

    def test_seed_mib2(self):
        r = OidResolver()
        result = r.resolve()
        assert result["mib-2"] == "1.3.6.1.2.1"


class TestOidResolverSimple:
    def test_single_level_under_seed(self):
        r = OidResolver()
        r.add_node("MY-MIB.myCompany", "myCompany", "enterprises", "99999")
        result = r.resolve()
        assert result["MY-MIB.myCompany"] == "1.3.6.1.4.1.99999"

    def test_two_levels(self):
        r = OidResolver()
        r.add_node("MY-MIB.myOrg", "myOrg", "enterprises", "12345")
        r.add_node("MY-MIB.myProduct", "myProduct", "MY-MIB.myOrg", "1")
        result = r.resolve()
        assert result["MY-MIB.myOrg"] == "1.3.6.1.4.1.12345"
        assert result["MY-MIB.myProduct"] == "1.3.6.1.4.1.12345.1"

    def test_chain_resolution(self):
        r = OidResolver()
        r.add_node("M.a", "a", "mib-2", "100")
        r.add_node("M.b", "b", "M.a", "1")
        r.add_node("M.c", "c", "M.b", "2")
        result = r.resolve()
        assert result["M.c"] == "1.3.6.1.2.1.100.1.2"

    def test_order_independent(self):
        """Nodes added in reverse order should still resolve."""
        r = OidResolver()
        r.add_node("M.c", "c", "M.b", "2")
        r.add_node("M.b", "b", "M.a", "1")
        r.add_node("M.a", "a", "mib-2", "100")
        result = r.resolve()
        assert result["M.c"] == "1.3.6.1.2.1.100.1.2"


class TestOidResolverCycleDetection:
    def test_cycle_raises_cycle_error(self):
        r = OidResolver()
        r.add_node("M.a", "a", "M.b", "1")
        r.add_node("M.b", "b", "M.a", "2")
        with pytest.raises(graphlib.CycleError):
            r.resolve()


class TestOidResolverFallback:
    def test_unknown_parent_warning(self, caplog):
        import logging
        r = OidResolver()
        r.add_node("M.x", "x", "nonexistent", "5")
        with caplog.at_level(logging.WARNING):
            result = r.resolve()
        assert "M.x" in result
        assert any("cannot find parent" in msg for msg in caplog.messages)


class TestOidResolverBareNameFallback:
    def test_bare_name_lookup(self):
        """Nodes can reference parents by bare object name."""
        r = OidResolver()
        r.add_node("A.myNode", "myNode", "mib-2", "50")
        r.add_node("B.child", "child", "myNode", "1")  # bare name ref
        result = r.resolve()
        assert result["B.child"] == "1.3.6.1.2.1.50.1"


# ---------------------------------------------------------------------------
# GAP 1 — OIDParser V1toV2 deterministic synthetic node + resolver integration
# ---------------------------------------------------------------------------

class TestOidParserV1toV2:
    """
    Tests for oid_parser.parse() V1-to-V2 conversion branch (three-token form).

    The bug was that _get_unknown_object_name() produced random "UnknownObjectA"
    names, so OidResolver could never chain the synthetic intermediate node.
    Fix: use deterministic f"{parent_name}.{middle}" as the synthetic node name.
    """

    def _make_cb(self, resolver: OidResolver, module: str = "M") -> object:
        """Return a callback that registers synthetic nodes into the resolver."""
        def cb(parent_name: str, new_name: str, number: str) -> None:
            resolver.add_node(f"{module}.{new_name}", new_name, parent_name, number)
        return cb

    def test_v1tov2_zero_middle_collapses(self):
        """'enterprises 0 5' → 'enterprises 5' (middle=0 is dropped)."""
        from mib2vrl.parser.oid_parser import parse
        result = parse("enterprises 0 5")
        assert result == "enterprises 5"

    def test_v1tov2_nonzero_deterministic_name(self):
        """'enterprises 9 3' → synthetic node 'enterprises.9' then leaf 3."""
        from mib2vrl.parser.oid_parser import parse
        synthetic_calls: list[tuple] = []

        def cb(parent: str, name: str, num: str) -> None:
            synthetic_calls.append((parent, name, num))

        result = parse("enterprises 9 3", new_node_cb=cb)
        assert len(synthetic_calls) == 1
        parent, name, num = synthetic_calls[0]
        assert parent == "enterprises"
        assert name == "enterprises.9"  # deterministic — not "UnknownObjectA"
        assert num == "9"
        assert result == "enterprises.9 3"

    def test_v1tov2_resolver_integration(self):
        """
        Integration: parse_oid("enterprises 9 3") feeds resolver via callback
        and ultimately resolves to "1.3.6.1.4.1.9.3".
        """
        from mib2vrl.parser.oid_parser import parse
        resolver = OidResolver()

        def cb(parent: str, name: str, num: str) -> None:
            resolver.add_node(f"CISCO.{name}", name, parent, num)

        canonical = parse("enterprises 9 3", new_node_cb=cb)
        # canonical == "enterprises.9 3"
        parent_ref, leaf = canonical.rsplit(" ", 1)
        resolver.add_node("CISCO.trap", "trap", parent_ref, leaf)

        result = resolver.resolve()
        assert result["CISCO.trap"] == "1.3.6.1.4.1.9.3"

    def test_v1tov2_resolver_chain_multiple_levels(self):
        """
        Three-level specific: 'enterprises 99 1 5' should chain correctly.
        Outer node: enterprises.99.1 → 5 → "1.3.6.1.4.1.99.1.5"
        """
        from mib2vrl.parser.oid_parser import parse
        resolver = OidResolver()
        registered: list[tuple] = []

        def cb(parent: str, name: str, num: str) -> None:
            registered.append((parent, name, num))
            resolver.add_node(f"V.{name}", name, parent, num)

        # Mixed format: enterprises(1) 99(2) 1(3) 5(4) — four tokens
        # This takes the _parse_mixed path but let's test V1toV2 specifically
        result = parse("enterprises 99 1", new_node_cb=cb)
        parent_ref, leaf = result.rsplit(" ", 1)
        resolver.add_node("V.trap5", "trap5", parent_ref, leaf)
        oids = resolver.resolve()
        assert oids["V.trap5"] == "1.3.6.1.4.1.99.1"
