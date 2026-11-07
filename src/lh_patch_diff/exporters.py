# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        src.lh_patch_diff.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Report exporters for lh-patch-diff: Rich Table, JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_patch_diff.models import (
    RULES_REGISTRY,
    FindingSeverity,
    PatchDiffReport,
)


def severity_to_style(severity: FindingSeverity) -> str:
    """Return Rich markup style for severity rating."""
    mapping = {
        FindingSeverity.CRITICAL: "bold red",
        FindingSeverity.HIGH: "red",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
    }
    return mapping.get(severity, "white")


def severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF 2.1.0 level."""
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
    }
    return mapping.get(severity, "note")


def render_table_report(report: PatchDiffReport, console: Console | None = None) -> None:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render an enterprise Rich table report of patch diff findings."""
    con = console or Console()

    if not report.findings:
        con.print(
            Panel(
                f"[bold green]No dependency patch diffs or vulnerabilities detected "
                f"across {report.packages_analyzed} packages scanned in '{report.target}'.[/]",
                title="[bold green]Scan Clean[/]",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"lh-patch-diff Vulnerability & Upgrade Report ({report.findings_count} Findings)",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Package", width=16)
    table.add_column("Current", width=10)
    table.add_column("Target", width=12)
    table.add_column("Risk", width=10, justify="center")
    table.add_column("Advisory ID", width=22)
    table.add_column("Details", width=36)

    for f in report.findings:
        sev_style = severity_to_style(f.severity)
        target_v = f.fixed_version or "UNPATCHED"
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/]",
            f.package_name,
            f.current_version,
            target_v,
            f.upgrade_risk.value,
            f.advisory_id,
            f.title,
        )

    con.print(table)

    summary_text = (
        f"[bold red]Critical:[/] {report.summary.get('critical', 0)} | "
        f"[red]High:[/] {report.summary.get('high', 0)} | "
        f"[yellow]Medium:[/] {report.summary.get('medium', 0)} | "
        f"[blue]Low:[/] {report.summary.get('low', 0)} | "
        f"[bold]Total Packages:[/] {report.packages_analyzed}"
    )
    con.print(Panel(summary_text, title="[bold]Severity Summary[/]", border_style="cyan"))


def export_json(report: PatchDiffReport, indent: int = 2) -> str:
    """Export report as structured JSON document."""
    data: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scanner": "lh-patch-diff",
        "target": report.target,
        "advisory_db_timestamp": report.advisory_db_timestamp,
        "manifest_files": report.manifest_files,
        "lockfiles_scanned": report.lockfiles_scanned,
        "packages_analyzed": report.packages_analyzed,
        "findings_count": report.findings_count,
        "summary": report.summary,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(data, indent=indent)


def export_sarif(report: PatchDiffReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export report as OASIS SARIF v2.1.0 document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    for rule_id, rule_def in RULES_REGISTRY.items():
        rules_dict[rule_id] = {
            "id": rule_id,
            "name": rule_def.title.replace(" ", ""),
            "shortDescription": {"text": rule_def.title},
            "fullDescription": {"text": rule_def.description},
            "defaultConfiguration": {"level": severity_to_sarif_level(rule_def.severity)},
            "help": {"text": f"Remediation: {rule_def.remediation}"},
        }

    results: list[dict[str, Any]] = []
    for f in report.findings:
        res = {
            "ruleId": f.rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {
                "text": (
                    f"Package '{f.package_name}' ({f.current_version}) matches {f.advisory_id}: "
                    f"{f.title}. Target: {f.fixed_version or 'N/A'} (Risk: {f.upgrade_risk.value})"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target_file},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "advisoryId": f.advisory_id,
                "cvss": f.cvss,
                "upgradeRisk": f.upgrade_risk.value,
                "diffPreview": f.diff_preview,
            },
        }
        results.append(res)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-patch-diff",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-patch-diff",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=indent)
