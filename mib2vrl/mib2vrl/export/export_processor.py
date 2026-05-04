"""
export_processor.py — ExportProcessor.py.

Replaces FreeMarker template engine with Jinja2.
The original multi-file output protocol using <template_output file="...">
XML tags is preserved: if a template renders such tags, they are split
into separate files.

ExportProcessor.doExport() → ExportProcessor.render()
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

logger = logging.getLogger(__name__)

# Java ExportProcessor constants for the multi-file output protocol
START_PATTERN = re.compile(
    r'<template_output\s+file="(.*?)"(?:\s+append="(true|false)")?>\s*[\n\r]*',
    re.IGNORECASE
)
END_PATTERN = re.compile(r'</template_output>', re.IGNORECASE)


class ExportProcessor:
    """
    ExportProcessor.py.

    Executes Jinja2 templates against the context built by ExportSettings
    and writes outputs to the export directory.
    """

    def __init__(
        self,
        template_dir: Path | str,
        export_dir: Path | str,
        eol: str = "\n",
    ) -> None:
        self._template_dir = Path(template_dir)
        self._export_dir = Path(export_dir)
        self._eol = eol
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            undefined=StrictUndefined,
            trim_blocks=False,
            lstrip_blocks=False,
            keep_trailing_newline=True,
        )

    def render(
        self,
        template_names: list[str],
        context: dict[str, Any],
    ) -> dict[str, str]:
        """
        ExportProcessor.doExport() — renders templates and returns
        {output_filename: content} mapping.

        Also writes files to export_dir.
        """
        self._export_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, str] = {}

        for tpl_name in template_names:
            logger.info("Processing template: %s", tpl_name)
            try:
                template = self._env.get_template(tpl_name)
                rendered = template.render(**context)
            except Exception as e:
                logger.error("Template %s failed: %s", tpl_name, e)
                raise

            # Determine primary output filename (strip .j2 suffix)
            output_name = tpl_name
            if output_name.endswith(".j2"):
                output_name = output_name[:-3]

            # Process multi-file output protocol
            file_outputs = self._process_template_output(rendered, output_name)
            results.update(file_outputs)

            # Write all output files
            for fname, content in file_outputs.items():
                if content.strip():
                    out_path = self._safe_output_path(self._export_dir, fname)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(self._replace_eol(content), encoding="utf-8")
                    logger.info("Wrote: %s", out_path)

        return results

    def _process_template_output(
        self,
        rendered: str,
        default_output: str,
    ) -> dict[str, str]:
        """
        ExportProcessor.processTemplateOutput() — handles multi-file protocol.

        Splits output on <template_output file="...">...</template_output>
        markers into separate files.  Content outside markers goes to
        default_output.
        """
        outputs: dict[str, str] = {default_output: ""}
        stack: list[str] = [default_output]
        buffers: dict[str, list[str]] = {default_output: []}

        pos = 0
        for start_m in re.finditer(
            r'<template_output\s+file="(.*?)"(?:\s+append="(true|false)")?>\s*[\n\r]*'
            r'|</template_output>',
            rendered,
            re.IGNORECASE
        ):
            # Append text before this marker to current file
            buffers[stack[-1]].append(rendered[pos:start_m.start()])
            pos = start_m.end()

            matched = start_m.group(0)
            if matched.startswith("<template_output"):
                fname = start_m.group(1)
                append = start_m.group(2) != "false" if start_m.group(2) else True
                if fname not in buffers or not append:
                    buffers[fname] = []
                stack.append(fname)
            else:  # </template_output>
                if len(stack) > 1:
                    stack.pop()

        # Remaining text
        buffers[stack[-1]].append(rendered[pos:])

        return {fname: "".join(parts) for fname, parts in buffers.items()}

    def _safe_output_path(self, export_dir: Path, fname: str) -> Path:
        """Validate output filename to prevent path traversal attacks."""
        if not fname or fname.startswith('/') or '..' in fname.split('/'):
            raise ValueError(f"Invalid output filename: {fname!r}")
        out_path = (export_dir / fname).resolve()
        export_dir_resolved = export_dir.resolve()
        if not str(out_path).startswith(str(export_dir_resolved)):
            raise ValueError(
                f"Output path {out_path} escapes export directory {export_dir_resolved}"
            )
        return out_path

    def _replace_eol(self, text: str) -> str:
        """ExportProcessor.replaceEOL()."""
        if self._eol == "\n":
            return text.replace("\r\n", "\n").replace("\r", "\n")
        elif self._eol == "\r\n":
            # Ensure no existing \r\n becomes \r\r\n
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            return normalized.replace("\n", "\r\n")
        return text
