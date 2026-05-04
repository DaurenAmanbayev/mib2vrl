"""
cli.py — rules2vrl CLI.

Provides the rules-convert command that is registered as a subcommand
on the mib2vrl Typer app.

Standalone usage (for development / testing):
    python -m rules2vrl.cli --rules ./rules/ --output ./out/

Integrated usage (via mib2vrl):
    mib2vrl rules-convert --rules ./rules/ --output ./out/
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="rules2vrl",
    help="Convert Netcool probe rules to Vector.dev VRL transforms.",
    add_completion=False,
)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)s %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


@app.command(name="convert")
def rules_convert(
    rules: Path = typer.Option(
        ..., "--rules", "-r",
        help="Directory containing .rules, .lookup, .severity files",
        exists=True, file_okay=False,
    ),
    output: Path = typer.Option(
        Path("./out"), "--output", "-o",
        help="Output directory",
    ),
    fmt: str = typer.Option(
        "both", "--format", "-f",
        help="Output format: vrl | vector | both",
    ),
    include_path: Optional[Path] = typer.Option(
        None, "--include-path",
        help="Additional search path for include file resolution",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """
    Convert Netcool probe rules (.rules, .lookup, .severity) to VRL transforms.

    Generates:
      - VRL remap source file(s)
      - Enrichment CSV files from .lookup/.severity tables
      - vector.yaml pipeline configuration (with --format vector or both)
    """
    _setup_logging(verbose)
    logger = logging.getLogger("rules2vrl.convert")

    from rules2vrl.ast.parser import parse_rules_file, parse_rules
    from rules2vrl.codegen.vrl_codegen import VrlCodegen
    from rules2vrl.codegen.lookup_converter import (
        convert_lookup_file, extract_tables,
        enrichment_table_yaml_entry,
    )
    from jinja2 import Environment, FileSystemLoader

    template_dir = Path(__file__).parent / "templates"
    jinja_env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        keep_trailing_newline=True,
    )

    output.mkdir(parents=True, exist_ok=True)
    enrichment_dir = output / "enrichment_csv"

    # ----------------------------------------------------------------
    # 1. Collect files
    # ----------------------------------------------------------------
    rules_files = sorted(rules.rglob("*.rules"))
    lookup_files = sorted(rules.rglob("*.lookup")) + sorted(rules.rglob("*.severity"))

    if not rules_files and not lookup_files:
        typer.echo(f"No .rules / .lookup / .severity files found in {rules}", err=True)
        raise typer.Exit(1)

    logger.info(
        "Found %d .rules files, %d .lookup/.severity files",
        len(rules_files), len(lookup_files),
    )

    # ----------------------------------------------------------------
    # 2. Convert lookup / severity tables → enrichment CSVs
    # ----------------------------------------------------------------
    enrichment_tables: list[tuple[str, str]] = []  # (name, csv_path)

    for lf in lookup_files:
        try:
            results = convert_lookup_file(lf, enrichment_dir)
            for table, csv_path in results:
                enrichment_tables.append((table.name, str(csv_path)))
        except Exception as exc:
            logger.error("Failed to convert lookup file %s: %s", lf, exc)

    # ----------------------------------------------------------------
    # 3. Parse + generate VRL for each .rules file
    # ----------------------------------------------------------------
    codegen = VrlCodegen()
    generated_files: list[str] = []
    date_str = datetime.now().isoformat(timespec="seconds")

    for rf in rules_files:
        try:
            program = parse_rules_file(rf)
        except Exception as exc:
            logger.error("Failed to parse %s: %s", rf, exc)
            continue

        vrl_source = codegen.generate(program)
        stem = rf.stem

        if fmt in ("vrl", "both"):
            # Render VRL with header template
            tmpl = jinja_env.get_template("vrl_rules.j2")
            rendered = tmpl.render(
                version="0.1.0",
                source_file=str(rf),
                date=date_str,
                vrl_source=vrl_source,
            )
            out_path = output / f"{stem}.vrl"
            out_path.write_text(rendered, encoding="utf-8")
            generated_files.append(str(out_path))
            logger.info("Wrote VRL: %s", out_path)

        if fmt in ("vector", "both"):
            # Render vector.yaml
            vrl_lines = vrl_source.rstrip("\n").split("\n")
            tmpl = jinja_env.get_template("vector_rules.j2")
            rendered = tmpl.render(
                version="0.1.0",
                source_file=str(rf),
                date=date_str,
                vrl_lines=vrl_lines,
                enrichment_tables=enrichment_tables,
            )
            yaml_path = output / f"vector_{stem}.yaml"
            yaml_path.write_text(rendered, encoding="utf-8")
            generated_files.append(str(yaml_path))
            logger.info("Wrote vector.yaml: %s", yaml_path)

    # ----------------------------------------------------------------
    # 4. Report
    # ----------------------------------------------------------------
    total = len(generated_files) + len(enrichment_tables)
    typer.echo(
        f"Generated {total} output file(s) in {output}/"
        f" ({len(enrichment_tables)} enrichment CSV(s))"
    )
    for f in generated_files:
        typer.echo(f"  {f}")
    for _, csv_p in enrichment_tables:
        typer.echo(f"  {csv_p}")


if __name__ == "__main__":
    app()
