# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Integration tests for lh-patch-diff command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_patch_diff.cli import app

runner = CliRunner()
ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_rules_command() -> None:
    """Test listing all LH-PATCH detection rules."""
    result = runner.invoke(app, ["rules"], env=ENV)
    assert result.exit_code == 0
    assert "LH-PATCH-001" in result.output
    assert "LH-PATCH-010" in result.output
    assert "Critical CVE/GHSA" in result.output


def test_cli_scan_clean_project(clean_project: Path) -> None:
    """Test scan command on clean dependencies passes with exit code 0."""
    result = runner.invoke(app, ["scan", str(clean_project)], env=ENV)
    assert result.exit_code == 0
    assert "Scan Clean" in result.output or "No dependency patch diffs" in result.output


def test_cli_scan_vulnerable_fails_threshold(vulnerable_requirements: Path) -> None:
    """Test scan command on vulnerable dependencies triggers non-zero exit code."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_requirements), "--fail-on", "high"],
        env=ENV,
    )
    assert result.exit_code == 1
    assert "Scan failed" in result.output
    assert "LH-PATCH-001" in result.output


def test_cli_scan_fail_on_threshold_not_reached(tmp_path: Path) -> None:
    """Test scan passes when vulnerabilities do not meet fail-on severity."""
    req = tmp_path / "requirements.txt"
    req.write_text("docutils==0.16\n", encoding="utf-8")  # LOW severity

    result = runner.invoke(
        app,
        ["scan", str(req), "--fail-on", "high"],
        env=ENV,
    )
    assert result.exit_code == 0


def test_cli_scan_format_json(vulnerable_requirements: Path) -> None:
    """Test scan output with JSON format."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_requirements), "--format", "json", "--fail-on", "critical"],
        env=ENV,
    )
    # Output may fail with code 1 because CRITICAL exists, but stdout must be valid JSON
    assert "schema_version" in result.output
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    assert data["scanner"] == "lh-patch-diff"
    assert data["findings_count"] > 0


def test_cli_scan_format_sarif(vulnerable_requirements: Path) -> None:
    """Test scan output with SARIF format."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_requirements), "--format", "sarif", "--fail-on", "critical"],
        env=ENV,
    )
    assert "https://json.schemastore.org/sarif-2.1.0.json" in result.output
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    assert data["version"] == "2.1.0"


def test_cli_scan_output_file(vulnerable_requirements: Path, tmp_path: Path) -> None:
    """Test writing scan output to destination file."""
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(vulnerable_requirements),
            "--format",
            "json",
            "--output",
            str(out_file),
            "--fail-on",
            "critical",
        ],
        env=ENV,
    )
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["scanner"] == "lh-patch-diff"
    assert "Report exported successfully" in result.output


def test_cli_scan_min_severity_filter(vulnerable_requirements: Path) -> None:
    """Test filtering scan findings by minimum severity."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(vulnerable_requirements),
            "--min-severity",
            "critical",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ],
        env=ENV,
    )
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    for f in data["findings"]:
        assert f["severity"] == "CRITICAL"


def test_cli_scan_with_custom_advisories(custom_advisory_feed: Path, tmp_path: Path) -> None:
    """Test scan with custom offline advisory feed."""
    req = tmp_path / "requirements.txt"
    req.write_text("custom-lib==1.0.0\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(req),
            "--advisories",
            str(custom_advisory_feed),
            "--fail-on",
            "critical",
        ],
        env=ENV,
    )
    assert "CUSTOM-CVE-2026-9999" in result.output


def test_cli_scan_nonexistent_path() -> None:
    """Test scanning a nonexistent file path fails."""
    result = runner.invoke(app, ["scan", "/nonexistent/path/12345"], env=ENV)
    assert result.exit_code != 0
