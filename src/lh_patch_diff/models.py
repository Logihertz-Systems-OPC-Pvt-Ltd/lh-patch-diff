# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        src.lh_patch_diff.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-patch-diff."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for patch diff and vulnerability findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class Ecosystem(StrEnum):
    """Supported dependency ecosystems."""

    PYPI = "PyPI"
    NPM = "npm"
    CARGO = "Cargo"
    GO = "Go"
    GENERIC = "Generic"


class UpgradeRisk(StrEnum):
    """Semantic version upgrade risk classification."""

    NONE = "NONE"
    PATCH = "PATCH"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    UNPATCHED = "UNPATCHED"


@dataclass(order=True)
class SemVer:
    """Semantic version model supporting SemVer 2.0.0 parsing and comparison."""

    major: int = 0
    minor: int = 0
    patch: int = 0
    prerelease: str = field(default="", compare=False)
    raw: str = field(default="", compare=False)

    @classmethod
    def parse(cls, version_str: str) -> SemVer:
        """Parse arbitrary version strings into structured SemVer."""
        if not version_str or not version_str.strip():
            return cls(raw=version_str or "")

        cleaned = version_str.strip().lstrip("v").lstrip("=")
        # Extract major, minor, patch, prerelease
        match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-+](.+))?$", cleaned)
        if match:
            maj = int(match.group(1))
            min_v = int(match.group(2)) if match.group(2) else 0
            pat = int(match.group(3)) if match.group(3) else 0
            pre = match.group(4) or ""
            return cls(major=maj, minor=min_v, patch=pat, prerelease=pre, raw=version_str)

        return cls(raw=version_str)

    def satisfies_range(self, range_expr: str) -> bool:
        """Check if this SemVer satisfies an advisory range expression.

        Supports comma-separated or space-separated clauses like:
        '<1.2.3', '>=1.0.0, <2.0.0', '<=2.1.0', '==1.0.5'.
        """
        if not range_expr or not range_expr.strip():
            return False

        clauses = [c.strip() for c in range_expr.replace(";", ",").split(",") if c.strip()]
        for clause in clauses:
            m = re.match(r"^([<>!=]=?|=)?\s*([0-9a-zA-Z\.\-]+)$", clause)
            if not m:
                continue
            op = m.group(1) or "=="
            op = "==" if op == "=" else op
            target = SemVer.parse(m.group(2))

            if op == "<" and not (self < target):
                return False
            if op == "<=" and not (self <= target):
                return False
            if op == ">" and not (self > target):
                return False
            if op == ">=" and not (self >= target):
                return False
            if op == "==" and not (
                self.major == target.major
                and self.minor == target.minor
                and self.patch == target.patch
            ):
                return False
            if op == "!=" and (
                self.major == target.major
                and self.minor == target.minor
                and self.patch == target.patch
            ):
                return False

        return True

    def calculate_risk(self, target: SemVer | None) -> UpgradeRisk:
        """Determine semantic upgrade risk jumping from self to target version."""
        if target is None or not target.raw:
            return UpgradeRisk.UNPATCHED
        if target.major > self.major:
            return UpgradeRisk.MAJOR
        if target.minor > self.minor:
            return UpgradeRisk.MINOR
        if target.patch > self.patch:
            return UpgradeRisk.PATCH
        return UpgradeRisk.NONE


@dataclass
class LockedPackage:
    """Resolved package dependency pinned in a manifest or lockfile."""

    name: str
    version: str
    ecosystem: Ecosystem
    file_path: str
    is_direct: bool = True
    required_by: str | None = None
    parsed_version: SemVer = field(init=False)

    def __post_init__(self) -> None:
        self.parsed_version = SemVer.parse(self.version)


@dataclass
class VulnerabilityAdvisory:
    """Offline vulnerability advisory record."""

    advisory_id: str
    ecosystem: Ecosystem
    package_name: str
    affected_range: str
    fixed_version: str | None = None
    cvss_score: float = 0.0
    severity: FindingSeverity = FindingSeverity.MEDIUM
    title: str = ""
    description: str = ""
    is_kev: bool = False
    is_malicious: bool = False
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class AdvisoryDatabase:
    """Offline database bundle containing vulnerability advisories."""

    timestamp: str = "2026-10-01T00:00:00Z"
    source: str = "embedded-osv-nvd"
    advisories: list[VulnerabilityAdvisory] = field(default_factory=list)


@dataclass
class PatchFinding:
    """A detected vulnerability or patch diff finding."""

    rule_id: str
    severity: FindingSeverity
    package_name: str
    ecosystem: Ecosystem
    current_version: str
    fixed_version: str | None
    target_file: str
    upgrade_risk: UpgradeRisk
    advisory_id: str
    cvss: float
    title: str
    description: str
    remediation: str
    diff_preview: str

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into dictionary for reporting."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem.value,
            "current_version": self.current_version,
            "fixed_version": self.fixed_version,
            "target_file": self.target_file,
            "upgrade_risk": self.upgrade_risk.value,
            "advisory_id": self.advisory_id,
            "cvss": self.cvss,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "diff_preview": self.diff_preview,
        }


@dataclass
class PatchDiffReport:
    """Aggregated scan findings and summary across target dependencies."""

    target: str
    manifest_files: list[str]
    lockfiles_scanned: list[str]
    packages_analyzed: int
    findings_count: int
    findings: list[PatchFinding]
    advisory_db_timestamp: str
    summary: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.summary:
            self.summary = {
                "critical": sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == FindingSeverity.LOW),
            }


@dataclass
class PatchRuleDefinition:
    """Rule catalog definition."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, PatchRuleDefinition] = {
    "LH-PATCH-001": PatchRuleDefinition(
        rule_id="LH-PATCH-001",
        title="Critical CVE/GHSA Vulnerability Match",
        severity=FindingSeverity.CRITICAL,
        category="Vulnerability",
        description=(
            "Locked package version matches a critical-severity advisory (CVSS >= 9.0 or "
            "CRITICAL) allowing remote code execution, authentication bypass, or deserialization."
        ),
        remediation="Upgrade package immediately to resolved upstream fixed release.",
    ),
    "LH-PATCH-002": PatchRuleDefinition(
        rule_id="LH-PATCH-002",
        title="High-Severity Vulnerability Match",
        severity=FindingSeverity.HIGH,
        category="Vulnerability",
        description=(
            "Locked package version matches a high-severity advisory (7.0 <= CVSS < 9.0) "
            "with an available upstream patched release."
        ),
        remediation="Apply minor or patch version upgrade to fixed release.",
    ),
    "LH-PATCH-003": PatchRuleDefinition(
        rule_id="LH-PATCH-003",
        title="Unpatched / Zero-Fix Vulnerability",
        severity=FindingSeverity.CRITICAL,
        category="Unpatched Flaw",
        description=(
            "Locked package matches an active vulnerability advisory where no upstream fixed "
            "version is available yet."
        ),
        remediation="Isolate component, implement runtime workarounds, or replace dependency.",
    ),
    "LH-PATCH-004": PatchRuleDefinition(
        rule_id="LH-PATCH-004",
        title="Known Exploited Vulnerability (KEV) Match",
        severity=FindingSeverity.CRITICAL,
        category="Threat Intel",
        description=(
            "Locked package matches a CVE cataloged in CISA KEV or actively exploited in the wild."
        ),
        remediation="Prioritize emergency patch application ahead of standard deployment cycles.",
    ),
    "LH-PATCH-005": PatchRuleDefinition(
        rule_id="LH-PATCH-005",
        title="Medium-Severity Vulnerability Match",
        severity=FindingSeverity.MEDIUM,
        category="Vulnerability",
        description=(
            "Locked package matches a medium-severity advisory (4.0 <= CVSS < 7.0) with "
            "a non-breaking patch upgrade available."
        ),
        remediation="Schedule dependency update in next standard release milestone.",
    ),
    "LH-PATCH-006": PatchRuleDefinition(
        rule_id="LH-PATCH-006",
        title="Breaking Major SemVer Upgrade Required",
        severity=FindingSeverity.HIGH,
        category="Upgrade Risk",
        description=(
            "Remediating a matched vulnerability requires jumping across a major SemVer boundary "
            "(e.g., 1.x to 2.x), introducing breaking API changes."
        ),
        remediation="Review upstream changelog and migration guide before upgrading major version.",
    ),
    "LH-PATCH-007": PatchRuleDefinition(
        rule_id="LH-PATCH-007",
        title="Manifest-to-Lockfile Version Drift",
        severity=FindingSeverity.MEDIUM,
        category="Supply Chain",
        description=(
            "Locked package version in lockfile is older than or conflicts with the version "
            "constraint declared in manifest files."
        ),
        remediation="Re-lock project dependency tree to synchronize manifests and lockfile state.",
    ),
    "LH-PATCH-008": PatchRuleDefinition(
        rule_id="LH-PATCH-008",
        title="Malicious, Yanked, or Compromised Package Release",
        severity=FindingSeverity.CRITICAL,
        category="Supply Chain",
        description=(
            "Locked package matches a known malicious release (MAL-*), backdoored package, "
            "or yanked supply chain compromise entry."
        ),
        remediation="Remove dependency immediately and inspect environment for compromised keys.",
    ),
    "LH-PATCH-009": PatchRuleDefinition(
        rule_id="LH-PATCH-009",
        title="Transitive Vulnerability Pinning Bottleneck",
        severity=FindingSeverity.HIGH,
        category="Supply Chain",
        description=(
            "A vulnerable transitive dependency cannot be upgraded because an outdated direct "
            "parent dependency restricts its version range."
        ),
        remediation="Upgrade direct parent dependency constraint or apply dependency overrides.",
    ),
    "LH-PATCH-010": PatchRuleDefinition(
        rule_id="LH-PATCH-010",
        title="Low-Severity Advisory or Stale Offline Feed",
        severity=FindingSeverity.LOW,
        category="Vulnerability",
        description=(
            "Locked package has a low-severity advisory (CVSS < 4.0) or local advisory database "
            "timestamp is older than 90 days."
        ),
        remediation="Update advisory feed bundle or apply optional patch as schedule permits.",
    ),
}
