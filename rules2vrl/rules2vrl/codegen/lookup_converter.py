"""
lookup_converter.py — Convert Netcool .lookup and .severity tables to
VRL enrichment CSVs and vector.yaml enrichment_tables entries.

.lookup file format (two variants found in the wild):
  table NAME = {
      {"key1", value1},       # tuple format
      {"key2", value2},
  }
  default = "unknown"

  table NAME = {              # dict format
      "key1" : value1,
      "key2" : value2,
  }

Output:
  enrichment_NAME.csv   — two-column CSV (key, value)
  VRL snippet           — get_enrichment_table_record("NAME", {"key": .field})
  vector.yaml fragment  — enrichment_tables: section
"""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

from rules2vrl.ast.nodes import TableDefinition, Program
from rules2vrl.ast.parser import parse_rules_file, parse_rules

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------

def table_to_csv(table: TableDefinition) -> str:
    """
    Render a TableDefinition as a two-column CSV string (key, value).

    The CSV is suitable for use as a Vector.dev enrichment table file.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["key", "value"])
    for key, value in table.entries:
        writer.writerow([key, value])
    return buf.getvalue()


def write_enrichment_csv(table: TableDefinition, output_dir: Path) -> Path:
    """
    Write enrichment_NAME.csv to output_dir and return the written path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / f"enrichment_{table.name}.csv"
    csv_path.write_text(table_to_csv(table), encoding="utf-8")
    logger.info("Wrote enrichment CSV: %s (%d entries)", csv_path, len(table.entries))
    return csv_path


# ---------------------------------------------------------------------------
# VRL snippet generation
# ---------------------------------------------------------------------------

def lookup_vrl_snippet(
    table_name: str,
    key_field_vrl: str,
    result_field_vrl: str,
    indent: str = "",
) -> str:
    """
    Generate the VRL lines for a lookup table access.

    Example output:
        _result, _err = get_enrichment_table_record("sev_table", {"key": .traptype})
        if _err == null { .severity = _result.value }
    """
    lines = [
        f'{indent}_result, _err = get_enrichment_table_record("{table_name}", {{"key": {key_field_vrl}}})',
        f"{indent}if _err == null {{ {result_field_vrl} = _result.value }}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# vector.yaml enrichment_tables entry
# ---------------------------------------------------------------------------

def enrichment_table_yaml_entry(table_name: str, csv_path: str) -> str:
    """
    Return a YAML fragment for a single enrichment table entry in vector.yaml.

    Example:
      my_table:
        type: file
        file:
          path: "/etc/vector/enrichment_my_table.csv"
          encoding:
            type: csv
        schema:
          key: "bytes"
          value: "bytes"
    """
    return (
        f"  {table_name}:\n"
        f"    type: file\n"
        f"    file:\n"
        f'      path: "{csv_path}"\n'
        f"      encoding:\n"
        f"        type: csv\n"
        f"    schema:\n"
        f'      key: "bytes"\n'
        f'      value: "bytes"\n'
    )


# ---------------------------------------------------------------------------
# Extract all TableDefinitions from a parsed Program
# ---------------------------------------------------------------------------

def extract_tables(program: Program) -> list[TableDefinition]:
    """Walk a Program AST and collect all TableDefinition nodes."""
    from rules2vrl.ast.nodes import TableDefinition as TD
    tables: list[TableDefinition] = []
    _walk_for_tables(program.body, tables)
    return tables


def _walk_for_tables(nodes: list, out: list[TableDefinition]) -> None:
    from rules2vrl.ast.nodes import TableDefinition as TD, IfBlock
    for node in nodes:
        if isinstance(node, TD):
            out.append(node)
        elif isinstance(node, IfBlock):
            _walk_for_tables(node.body, out)
            if node.else_body:
                _walk_for_tables(node.else_body, out)


# ---------------------------------------------------------------------------
# Convert a complete .lookup or .severity file
# ---------------------------------------------------------------------------

def convert_lookup_file(
    path: str | Path,
    output_dir: Path,
) -> list[tuple[TableDefinition, Path]]:
    """
    Parse a .lookup or .severity file and write enrichment CSVs.

    Returns a list of (TableDefinition, csv_path) pairs.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = p.read_text(encoding="latin-1")
        logger.info("latin-1 fallback: %s", p)

    program = parse_rules(text, source=str(p))
    tables = extract_tables(program)

    if not tables:
        logger.warning("No table definitions found in %s", p)
        return []

    results: list[tuple[TableDefinition, Path]] = []
    for table in tables:
        csv_path = write_enrichment_csv(table, output_dir)
        results.append((table, csv_path))

    return results
