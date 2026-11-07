# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        tests.test_advisory_matcher
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for SemVer parsing and offline advisory matching engine."""

from __future__ import annotations

from pathlib import Path

from lh_patch_diff.advisory_matcher import (
    load_advisory_database,
    match_packages_against_advisories,
    scan_target_path,
)
from lh_patch_diff.models import (
    RULES_REGISTRY,
    Ecosystem,
    LockedPackage,
    SemVer,
    UpgradeRisk,
)


def test_semver_parsing_and_comparisons() -> None:
    """Test SemVer 2.0.0 parsing, ordering, and comparison operators."""
    v1 = SemVer.parse("1.2.3")
    v2 = SemVer.parse("v1.2.4")
    v3 = SemVer.parse("2.0.0-rc1")

    assert v1.major == 1 and v1.minor == 2 and v1.patch == 3
    assert v2.major == 1 and v2.minor == 2 and v2.patch == 4
    assert v3.major == 2 and v3.minor == 0 and v3.patch == 0

    assert v1 < v2
    assert v2 <= v2
    assert v3 > v1
    assert v1 != v3
    assert v1 == SemVer.parse("1.2.3")


def test_semver_range_satisfaction() -> None:
    """Test SemVer range satisfaction expressions."""
    v = SemVer.parse("1.2.5")
    assert v.satisfies_range("<1.3.0")
    assert v.satisfies_range(">=1.0.0, <2.0.0")
    assert not v.satisfies_range("<1.2.0")
    assert v.satisfies_range("==1.2.5")
    assert not v.satisfies_range("==1.2.6")


def test_semver_risk_calculation() -> None:
    """Test determining upgrade risk between versions."""
    base = SemVer.parse("1.2.3")
    assert base.calculate_risk(None) == UpgradeRisk.UNPATCHED
    assert base.calculate_risk(SemVer.parse("1.2.4")) == UpgradeRisk.PATCH
    assert base.calculate_risk(SemVer.parse("1.3.0")) == UpgradeRisk.MINOR
    assert base.calculate_risk(SemVer.parse("2.0.0")) == UpgradeRisk.MAJOR
    assert base.calculate_risk(SemVer.parse("1.2.3")) == UpgradeRisk.NONE


def test_rules_registry_has_ten_rules() -> None:
    """Verify rules LH-PATCH-001 through LH-PATCH-010 are registered."""
    for i in range(1, 11):
        rule_id = f"LH-PATCH-{i:03d}"
        assert rule_id in RULES_REGISTRY
        assert RULES_REGISTRY[rule_id].title
        assert RULES_REGISTRY[rule_id].remediation


def test_match_vulnerable_requirements(vulnerable_requirements: Path) -> None:
    """Validate rules matched on vulnerable requirements.txt."""
    report = scan_target_path(vulnerable_requirements)
    rule_ids = {f.rule_id for f in report.findings}

    assert "LH-PATCH-001" in rule_ids  # pyyaml
    assert "LH-PATCH-002" in rule_ids  # urllib3
    assert "LH-PATCH-003" in rule_ids  # zeroday-lib
    assert "LH-PATCH-005" in rule_ids  # requests
    assert "LH-PATCH-006" in rule_ids  # legacy-orm (major break)
    assert "LH-PATCH-010" in rule_ids  # docutils (low)


def test_match_npm_vulnerabilities(vulnerable_npm_lock: Path) -> None:
    """Validate npm lockfile matching (LH-PATCH-001, LH-PATCH-008, LH-PATCH-009)."""
    report = scan_target_path(vulnerable_npm_lock)
    rule_ids = {f.rule_id for f in report.findings}

    assert "LH-PATCH-001" in rule_ids  # lodash
    assert "LH-PATCH-008" in rule_ids  # malicious-pkg
    assert "LH-PATCH-009" in rule_ids  # deep-extend (transitive)


def test_match_cyclonedx_kev(cyclonedx_sbom: Path) -> None:
    """Validate CycloneDX SBOM CISA KEV matching (LH-PATCH-004)."""
    report = scan_target_path(cyclonedx_sbom)
    rule_ids = {f.rule_id for f in report.findings}
    assert "LH-PATCH-004" in rule_ids


def test_match_manifest_drift(drift_project: Path) -> None:
    """Validate manifest-to-lockfile drift rule (LH-PATCH-007)."""
    report = scan_target_path(drift_project)
    rule_ids = {f.rule_id for f in report.findings}
    assert "LH-PATCH-007" in rule_ids


def test_clean_project_scan(clean_project: Path) -> None:
    """Validate clean project produces zero vulnerability findings."""
    report = scan_target_path(clean_project)
    vuln_findings = [f for f in report.findings if f.rule_id != "LH-PATCH-010"]
    assert len(vuln_findings) == 0


def test_custom_advisory_feed_loading(custom_advisory_feed: Path) -> None:
    """Validate loading custom offline advisory feed."""
    db = load_advisory_database(custom_advisory_feed)
    assert any(a.advisory_id == "CUSTOM-CVE-2026-9999" for a in db.advisories)

    pkgs = [
        LockedPackage(
            name="custom-lib",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            file_path="custom.txt",
        )
    ]
    findings = match_packages_against_advisories(pkgs, db)
    assert any(f.advisory_id == "CUSTOM-CVE-2026-9999" for f in findings)
