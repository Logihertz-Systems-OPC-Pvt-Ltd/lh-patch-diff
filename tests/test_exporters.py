# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Rich table, JSON, and SARIF report exporters."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from lh_patch_diff.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_sarif_level,
    severity_to_style,
)
from lh_patch_diff.models import (
    Ecosystem,
    FindingSeverity,
    PatchDiffReport,
    PatchFinding,
    UpgradeRisk,
)


def _sample_report(has_findings: bool = True) -> PatchDiffReport:
    findings: list[PatchFinding] = []
    if has_findings:
        findings.append(
            PatchFinding(
                rule_id="LH-PATCH-001",
                severity=FindingSeverity.CRITICAL,
                package_name="pyyaml",
                ecosystem=Ecosystem.PYPI,
                current_version="5.3.1",
                fixed_version="5.4",
                target_file="requirements.txt",
                upgrade_risk=UpgradeRisk.MINOR,
                advisory_id="GHSA-8q59-q68m-5vel",
                cvss=9.8,
                title="PyYAML arbitrary code execution",
                description="Deserialization vulnerability in PyYAML load",
                remediation="Upgrade to 5.4",
                diff_preview=(
                    "--- a/requirements.txt\n+++ b/requirements.txt\n-pyyaml==5.3.1\n+pyyaml==5.4"
                ),
            )
        )
    return PatchDiffReport(
        target="requirements.txt",
        manifest_files=["requirements.txt"],
        lockfiles_scanned=["requirements.txt"],
        packages_analyzed=1,
        findings_count=len(findings),
        findings=findings,
        advisory_db_timestamp="2026-10-01T00:00:00Z",
    )


def test_render_table_report_with_findings() -> None:
    """Test Rich table rendering with findings."""
    buf = StringIO()
    con = Console(file=buf, width=160)
    report = _sample_report(has_findings=True)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "LH-PATCH-001" in output
    assert "pyyaml" in output
    assert "CRITICAL" in output


def test_render_table_report_clean() -> None:
    """Test Rich table rendering for clean scan."""
    buf = StringIO()
    con = Console(file=buf, width=160)
    report = _sample_report(has_findings=False)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "Scan Clean" in output


def test_export_json_schema() -> None:
    """Test JSON export schema structure."""
    report = _sample_report(has_findings=True)
    raw_json = export_json(report)
    data = json.loads(raw_json)

    assert data["schema_version"] == "1.0.0"
    assert data["scanner"] == "lh-patch-diff"
    assert data["packages_analyzed"] == 1
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule_id"] == "LH-PATCH-001"
    assert f["package_name"] == "pyyaml"
    assert f["upgrade_risk"] == "MINOR"


def test_export_sarif_schema() -> None:
    """Test OASIS SARIF v2.1.0 export."""
    report = _sample_report(has_findings=True)
    raw_sarif = export_sarif(report)
    data = json.loads(raw_sarif)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-patch-diff"
    assert len(driver["rules"]) == 10

    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "LH-PATCH-001"
    assert results[0]["level"] == "error"


def test_severity_helpers() -> None:
    """Test severity to styling and SARIF level mappings."""
    assert severity_to_style(FindingSeverity.CRITICAL) == "bold red"
    assert severity_to_style(FindingSeverity.LOW) == "blue"
    assert severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert severity_to_sarif_level(FindingSeverity.LOW) == "note"
