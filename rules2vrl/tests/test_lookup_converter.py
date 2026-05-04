"""
test_lookup_converter.py — Tests for .lookup/.severity table conversion.
"""

import csv
import io
from pathlib import Path

import pytest

from rules2vrl.ast.nodes import TableDefinition
from rules2vrl.codegen.lookup_converter import (
    table_to_csv,
    write_enrichment_csv,
    lookup_vrl_snippet,
    enrichment_table_yaml_entry,
    extract_tables,
    convert_lookup_file,
)
from rules2vrl.ast.parser import parse_rules

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# table_to_csv
# ---------------------------------------------------------------------------

def test_table_to_csv_header():
    table = TableDefinition(name="test", entries=[("1", "up"), ("2", "down")])
    csv_text = table_to_csv(table)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert rows[0] == ["key", "value"]


def test_table_to_csv_rows():
    entries = [("linkDown", "4"), ("linkUp", "1"), ("coldStart", "2")]
    table = TableDefinition(name="sev_map", entries=entries)
    csv_text = table_to_csv(table)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert rows[1] == ["linkDown", "4"]
    assert rows[2] == ["linkUp", "1"]
    assert rows[3] == ["coldStart", "2"]


def test_table_to_csv_empty():
    table = TableDefinition(name="empty", entries=[])
    csv_text = table_to_csv(table)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert rows == [["key", "value"]]


# ---------------------------------------------------------------------------
# write_enrichment_csv
# ---------------------------------------------------------------------------

def test_write_enrichment_csv(tmp_path):
    table = TableDefinition(name="if_status", entries=[("1", "up"), ("2", "down")])
    csv_path = write_enrichment_csv(table, tmp_path)
    assert csv_path.exists()
    assert csv_path.name == "enrichment_if_status.csv"
    text = csv_path.read_text()
    assert "key,value" in text
    assert "1,up" in text


# ---------------------------------------------------------------------------
# lookup_vrl_snippet
# ---------------------------------------------------------------------------

def test_lookup_vrl_snippet_basic():
    snippet = lookup_vrl_snippet("sev_table", ".traptype", ".severity")
    assert 'get_enrichment_table_record("sev_table"' in snippet
    assert '"key": .traptype' in snippet
    assert "if _err == null" in snippet
    assert ".severity = _result.value" in snippet


def test_lookup_vrl_snippet_indent():
    snippet = lookup_vrl_snippet("t", ".f", ".v", indent="    ")
    assert snippet.startswith("    ")


# ---------------------------------------------------------------------------
# enrichment_table_yaml_entry
# ---------------------------------------------------------------------------

def test_yaml_entry_contains_name():
    entry = enrichment_table_yaml_entry("my_table", "/etc/vector/enrichment_my_table.csv")
    assert "my_table:" in entry
    assert "/etc/vector/enrichment_my_table.csv" in entry
    assert "type: file" in entry


# ---------------------------------------------------------------------------
# extract_tables
# ---------------------------------------------------------------------------

def test_extract_tables_from_program():
    text = """
    table t1 = { "a" : "1", }
    table t2 = { "b" : "2", }
    """
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 2
    names = {t.name for t in tables}
    assert names == {"t1", "t2"}


def test_extract_tables_inside_if():
    text = """
    if(match(@Manager, "SNMP")) {
        table nested = { "x" : "y", }
    }
    """
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 1
    assert tables[0].name == "nested"


# ---------------------------------------------------------------------------
# convert_lookup_file
# ---------------------------------------------------------------------------

def test_convert_lookup_file(tmp_path):
    results = convert_lookup_file(FIXTURES / "sample.lookup", tmp_path)
    assert len(results) >= 2
    for table, csv_path in results:
        assert isinstance(table, TableDefinition)
        assert csv_path.exists()
        assert csv_path.suffix == ".csv"


def test_convert_lookup_file_csv_content(tmp_path):
    results = convert_lookup_file(FIXTURES / "sample.lookup", tmp_path)
    # Find if_oper_status table
    status_table = next(
        (t for t, _ in results if t.name == "if_oper_status"), None
    )
    assert status_table is not None
    assert any(e[0] == "1" and e[1] == "up" for e in status_table.entries)


# ---------------------------------------------------------------------------
# Tuple format (Cisco .sev.snmptrap.lookup style)
# ---------------------------------------------------------------------------

def test_tuple_format_table():
    """Table with per-entry braces: {"key", value}, {"key2", value2}"""
    text = """
    table sev = {
        {"linkDown", 4},
        {"linkUp", 1},
        {"coldStart", 2},
    }
    """
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 1
    t = tables[0]
    assert t.name == "sev"
    assert ("linkDown", "4") in t.entries
    assert ("linkUp", "1") in t.entries
    assert ("coldStart", "2") in t.entries


def test_flat_tuple_format_table():
    """Table with flat tuple entries: \"key\", value (no per-entry braces)"""
    text = """
    table sev = {
        "linkDown", 4,
        "linkUp", 1,
    }
    """
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 1
    t = tables[0]
    assert ("linkDown", "4") in t.entries
    assert ("linkUp", "1") in t.entries


def test_lookup_with_leading_comments():
    """Table definition preceded by ### comment lines."""
    text = """
    ### Cisco SNMP severity lookup
    ### Generated automatically
    table sev = {
        {"linkDown", 4},
        {"linkUp", 1},
    }
    """
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 1
    assert tables[0].name == "sev"
    assert ("linkDown", "4") in tables[0].entries


def test_lookup_comment_between_assign_and_brace():
    """Comment between '=' and '{' in table definition must be skipped."""
    text = (
        "table sev =\n"
        "### generated\n"
        "{\n"
        '    {"linkDown", 4},\n'
        "}\n"
    )
    prog = parse_rules(text)
    tables = extract_tables(prog)
    assert len(tables) == 1
    assert ("linkDown", "4") in tables[0].entries
