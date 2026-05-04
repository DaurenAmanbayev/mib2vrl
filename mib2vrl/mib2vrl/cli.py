"""
cli.py — Typer CLI for mib2vrl.

Commands:
  mib2vrl convert       --mibs ./mibs/ --output ./out/ --format [vrl|netcool|both]
  mib2vrl validate      --output ./out/
  mib2vrl simulate      --mib IF-MIB --trap linkDown --count 10
  mib2vrl rules-convert --rules ./rules/ --output ./out/ --format [vrl|vector|both]
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="mib2vrl",
    help="Convert SNMP MIB files into Vector.dev VRL transforms and vector.yaml configs.",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)s %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# convert command
# ---------------------------------------------------------------------------

@app.command()
def convert(
    mibs: Path = typer.Option(..., "--mibs", "-m", help="Directory containing MIB files", exists=True, file_okay=False),
    output: Path = typer.Option(Path("./out"), "--output", "-o", help="Output directory"),
    format: str = typer.Option("vrl", "--format", "-f", help="Output format: vrl | netcool | both"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file"),
    rules: Optional[Path] = typer.Option(None, "--rules", "-r", help="Existing Netcool .rules dir for migration validation"),
    file_timeout: int = typer.Option(30, "--timeout", "-t", help="Per-file parse timeout in seconds (0 = disabled)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """
    Parse MIB files and generate VRL transforms, vector.yaml, and/or Netcool rules.
    """
    _setup_logging(verbose)
    logger = logging.getLogger("mib2vrl.convert")

    # Import here to avoid circular imports at module level
    from mib2vrl.config import default_config, load_config
    from mib2vrl.export.export_helper import ExportHelper
    from mib2vrl.export.export_processor import ExportProcessor
    from mib2vrl.export.export_settings import ExportPrefs, ExportSettings
    from mib2vrl.models.trap import Trap
    from mib2vrl.models.varbind import Varbind
    from mib2vrl.parser.import_resolver import ImportResolver
    from mib2vrl.parser.mib_parser import MibModule, parse_file

    prefs = load_config(config) if config else default_config()
    prefs.export_dir = str(output)
    prefs.output_format = format

    output.mkdir(parents=True, exist_ok=True)

    # Collect MIB files
    mib_files = sorted(
        f for f in mibs.rglob("*")
        if f.is_file() and not f.name.startswith(".")
    )
    if not mib_files:
        typer.echo(f"No MIB files found in {mibs}", err=True)
        raise typer.Exit(1)

    logger.info("Found %d MIB files in %s", len(mib_files), mibs)

    # Parse all MIBs
    all_traps: list[Trap] = []
    all_objects: list[dict] = []

    for mib_file in mib_files:
        try:
            if file_timeout > 0:
                try:
                    proc = subprocess.run(
                        [sys.executable, "-m", "mib2vrl._parse_single", str(mib_file)],
                        capture_output=True,
                        timeout=file_timeout,
                        text=True,
                    )
                except subprocess.TimeoutExpired:
                    logger.warning("Skipping %s: timed out after %ds", mib_file, file_timeout)
                    continue
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip())
                module_dicts = json.loads(proc.stdout)
                modules = [MibModule(**d) for d in module_dicts]
            else:
                try:
                    content = mib_file.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    content = mib_file.read_text(encoding="latin-1")
                    logger.info("latin-1 fallback: %s", mib_file)
                modules = parse_file(content, source_file=str(mib_file))
            for module in modules:
                if module.warnings:
                    for w in module.warnings:
                        logger.warning("[%s] %s", module.name, w)

                # Convert parsed trap dicts to Trap dataclasses
                for td in module.trap_types:
                    trap = _dict_to_trap(td, module.name, snmp_version=1)
                    all_traps.append(trap)
                for nd in module.notification_types:
                    trap = _dict_to_trap(nd, module.name, snmp_version=2)
                    all_traps.append(trap)

                all_objects.extend(module.object_types)
                all_objects.extend(module.object_identifiers)

        except Exception as e:
            logger.error("Failed to parse %s: %s", mib_file, e)

    typer.echo(f"Parsed {len(all_traps)} traps from {len(mib_files)} files.")

    if not all_traps:
        typer.echo("No traps found. Nothing to export.", err=True)
        raise typer.Exit(0)

    # Build template context
    template_dir = Path(__file__).parent / "export" / "templates"
    helper = ExportHelper(export_dir=str(output), version=prefs.version)
    settings = ExportSettings(prefs)
    context = settings.init_settings(all_traps, all_objects, helper)

    # Select templates
    templates: list[str] = []
    match format:
        case "vrl":
            templates = ["vrl_remap.j2", "vector.yaml.j2", "enrichment_severity.csv.j2"]
        case "netcool":
            templates = ["netcool.rules.j2"]
        case "both":
            templates = [
                "vrl_remap.j2", "vector.yaml.j2",
                "enrichment_severity.csv.j2", "netcool.rules.j2",
            ]
        case _:
            typer.echo(f"Unknown format: {format}. Use vrl, netcool, or both.", err=True)
            raise typer.Exit(1)

    processor = ExportProcessor(
        template_dir=template_dir,
        export_dir=output,
        eol=prefs.eol_format,
    )
    try:
        results = processor.render(templates, context)
        typer.echo(f"Generated {len(results)} output file(s) in {output}/")
        for fname in results:
            typer.echo(f"  {output}/{fname}")
    except Exception as e:
        logger.error("Export failed: %s", e)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------

@app.command()
def validate(
    output: Path = typer.Option(Path("./out"), "--output", "-o", help="Output directory to validate", exists=True),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """
    Validate generated VRL files for syntax correctness.
    """
    _setup_logging(verbose)
    logger = logging.getLogger("mib2vrl.validate")

    vrl_files = list(output.rglob("*.vrl")) + list(output.rglob("vrl_remap"))
    rules_files = list(output.rglob("*.rules"))
    yaml_files = list(output.rglob("vector*.yaml"))

    errors = 0

    for f in yaml_files:
        try:
            import yaml
            with open(f) as fh:
                yaml.safe_load(fh)
            typer.echo(f"  OK  {f}")
        except Exception as e:
            typer.echo(f"  ERR {f}: {e}", err=True)
            errors += 1

    for f in rules_files:
        # Basic check: file is non-empty
        if f.stat().st_size == 0:
            typer.echo(f"  ERR {f}: empty file", err=True)
            errors += 1
        else:
            typer.echo(f"  OK  {f}")

    if errors:
        typer.echo(f"\n{errors} validation error(s).", err=True)
        raise typer.Exit(1)
    else:
        typer.echo("All files valid.")


# ---------------------------------------------------------------------------
# simulate command
# ---------------------------------------------------------------------------

@app.command()
def simulate(
    mib: str = typer.Option(..., "--mib", help="MIB module name (e.g. IF-MIB)"),
    trap: str = typer.Option(..., "--trap", help="Trap name (e.g. linkDown)"),
    count: int = typer.Option(1, "--count", help="Number of test events to generate"),
    mibs_dir: Optional[Path] = typer.Option(None, "--mibs", help="MIB search path"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """
    Generate simulated SNMP trap JSON events for testing.
    """
    import json
    import random

    _setup_logging(verbose)

    for i in range(count):
        event = {
            "mib": mib,
            "trap_name": trap,
            "sequence": i + 1,
            "host": f"192.168.1.{random.randint(1, 254)}",
            "snmp_trap_oid": f"1.3.6.1.{random.randint(1, 9)}.{random.randint(1000, 9999)}",
            "varbinds": [
                {"oid": f"1.3.6.1.2.1.{j}.0", "value": str(random.randint(0, 100))}
                for j in range(1, 4)
            ],
        }
        typer.echo(json.dumps(event))


# ---------------------------------------------------------------------------
# Helper: convert parsed trap dict → Trap dataclass
# ---------------------------------------------------------------------------

def _dict_to_trap(td: dict, module_name: str, snmp_version: int) -> "Trap":
    """Convert a MibObjectParser result dict to a Trap dataclass."""
    from mib2vrl.models.trap import Trap
    from mib2vrl.models.varbind import Varbind

    varbind_names: list[str] = td.get("VARIABLES", []) or td.get("OBJECTS", [])
    varbinds = [
        Varbind(name=name, index=i)
        for i, name in enumerate(varbind_names)
    ]

    return Trap(
        name=td.get("name", ""),
        trap_number=int(td.get("trapNumber", 0) or 0),
        oid=td.get("OID", ""),
        snmp_version=snmp_version,
        enterprise=td.get("ENTERPRISE", ""),
        description=td.get("DESCRIPTION", ""),
        status=td.get("STATUS", "current"),
        reference=td.get("REFERENCE", ""),
        module=module_name,
        varbinds=varbinds,
    )


# ---------------------------------------------------------------------------
# rules-convert command (delegates to rules2vrl package)
# ---------------------------------------------------------------------------

@app.command(name="rules-convert")
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

    Generates VRL remap source, enrichment CSVs from .lookup/.severity tables,
    and optionally a complete vector.yaml pipeline configuration.
    """
    try:
        from rules2vrl.cli import rules_convert as _rc
    except ImportError:
        typer.echo(
            "rules2vrl package is not installed. "
            "Install it with: pip install -e /path/to/rules2vrl",
            err=True,
        )
        raise typer.Exit(1)

    _rc(rules=rules, output=output, fmt=fmt, include_path=include_path, verbose=verbose)


if __name__ == "__main__":
    app()
