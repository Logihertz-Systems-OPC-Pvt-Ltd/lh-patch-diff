# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        src.lh_patch_diff.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-patch-diff."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from lh_patch_diff.advisory_matcher import scan_target_path
from lh_patch_diff.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_style,
)
from lh_patch_diff.models import RULES_REGISTRY, FindingSeverity

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-patch",
    help=(
        "Zero-daemon lockfile vulnerability analyzer and semantic version patch diff engine. "
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    add_completion=True,
    rich_markup_mode=None,
)

console = Console()


class OutputFormat(StrEnum):
    """Supported output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


@app.command(name="scan")
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Target lockfile, manifest, or project directory to scan",
            exists=True,
            readable=True,
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report output format (table, json, sarif)",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional destination file path for scan output",
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            "-m",
            help="Minimum finding severity threshold to include (low, medium, high, critical)",
        ),
    ] = "low",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Minimum severity threshold that triggers non-zero exit code",
        ),
    ] = "high",
    advisories: Annotated[
        Path | None,
        typer.Option(
            "--advisories",
            "-a",
            help="Optional path to custom offline advisory feed (.json or .yaml)",
            exists=True,
            readable=True,
        ),
    ] = None,
) -> None:
    """Scan locked dependencies for known vulnerabilities and compute patch upgrade diffs."""
    min_sev = FindingSeverity.from_string(min_severity)
    fail_sev = FindingSeverity.from_string(fail_on)

    report = scan_target_path(target, custom_advisories=advisories)

    # Filter findings by min_severity
    filtered_findings = [f for f in report.findings if f.severity.meets_threshold(min_sev)]
    report.findings = filtered_findings
    report.findings_count = len(filtered_findings)
    report.summary = {
        "critical": sum(1 for f in filtered_findings if f.severity == FindingSeverity.CRITICAL),
        "high": sum(1 for f in filtered_findings if f.severity == FindingSeverity.HIGH),
        "medium": sum(1 for f in filtered_findings if f.severity == FindingSeverity.MEDIUM),
        "low": sum(1 for f in filtered_findings if f.severity == FindingSeverity.LOW),
    }

    # Render according to requested format
    rendered_output = ""
    if format == OutputFormat.JSON:
        rendered_output = export_json(report)
        if not output:
            typer.echo(rendered_output)
    elif format == OutputFormat.SARIF:
        rendered_output = export_sarif(report)
        if not output:
            typer.echo(rendered_output)
    else:
        render_table_report(report, console=console)

    if output and rendered_output:
        output.write_text(rendered_output, encoding="utf-8")
        console.print(f"[bold green]Report exported successfully to {output}[/]")
    elif output and format == OutputFormat.TABLE:
        # Export table as text to output file
        file_console = Console(file=output.open("w", encoding="utf-8"), width=160)
        render_table_report(report, console=file_console)
        console.print(f"[bold green]Table report exported successfully to {output}[/]")

    # Check failure threshold
    has_failing = any(f.severity.meets_threshold(fail_sev) for f in report.findings)
    if has_failing:
        console.print(
            f"[bold red]Scan failed: Found findings meeting or exceeding threshold "
            f"'{fail_sev.value}'.[/]"
        )
        sys.exit(1)


@app.command(name="rules")
def list_rules() -> None:
    """List all supported LH-PATCH vulnerability detection and patch diff rules."""
    table = Table(
        title="LH-PATCH Vulnerability & SemVer Diff Rules",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=16)
    table.add_column("Title", width=36)
    table.add_column("Description", width=48)

    for rule_id, rule_def in RULES_REGISTRY.items():
        sev_style = severity_to_style(rule_def.severity)
        table.add_row(
            rule_id,
            f"[{sev_style}]{rule_def.severity.value}[/]",
            rule_def.category,
            rule_def.title,
            rule_def.description,
        )

    console.print(table)


def main() -> None:
    """Entry point for CLI invocations."""
    app()


if __name__ == "__main__":
    main()
