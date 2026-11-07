# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        src.lh_patch_diff.advisory_matcher
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Offline vulnerability advisory database and rule matching engine for lh-patch-diff."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from lh_patch_diff.lockfile_parser import (
    detect_manifest_drift,
    find_supported_files,
    parse_any_lockfile,
)
from lh_patch_diff.models import (
    RULES_REGISTRY,
    AdvisoryDatabase,
    Ecosystem,
    FindingSeverity,
    LockedPackage,
    PatchDiffReport,
    PatchFinding,
    SemVer,
    UpgradeRisk,
    VulnerabilityAdvisory,
)

# Embedded high-impact OSV/NVD offline advisory catalog
EMBEDDED_ADVISORIES: list[VulnerabilityAdvisory] = [
    # 1. PyYAML arbitrary deserialization RCE (CRITICAL - LH-PATCH-001)
    VulnerabilityAdvisory(
        advisory_id="GHSA-8q59-q68m-5vel",
        ecosystem=Ecosystem.PYPI,
        package_name="pyyaml",
        affected_range="<5.4",
        fixed_version="5.4",
        cvss_score=9.8,
        severity=FindingSeverity.CRITICAL,
        title="PyYAML arbitrary code execution through unsafe yaml.load()",
        description="A flaw in PyYAML allows arbitrary code execution during deserialization.",
        cwe_ids=["CWE-502"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
    ),
    # 2. urllib3 Cookie / Auth Header Leak (HIGH - LH-PATCH-002)
    VulnerabilityAdvisory(
        advisory_id="GHSA-v845-jxx5-vc9f",
        ecosystem=Ecosystem.PYPI,
        package_name="urllib3",
        affected_range="<1.26.18, >=1.26.0",
        fixed_version="1.26.18",
        cvss_score=7.5,
        severity=FindingSeverity.HIGH,
        title="urllib3 unstripped Authorization headers on redirect",
        description="urllib3 does not remove Authorization headers on HTTP redirects across hosts.",
        cwe_ids=["CWE-200"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"],
    ),
    # 3. Unpatched Zero-Day (CRITICAL - LH-PATCH-003)
    VulnerabilityAdvisory(
        advisory_id="CVE-2026-0001-ZERO",
        ecosystem=Ecosystem.PYPI,
        package_name="zeroday-lib",
        affected_range="<=9.9.9",
        fixed_version=None,
        cvss_score=9.3,
        severity=FindingSeverity.CRITICAL,
        title="Unpatched remote zero-day flaw in zeroday-lib",
        description="Active zero-day vulnerability in zeroday-lib with no vendor fix available.",
        cwe_ids=["CWE-94"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
    ),
    # 4. Log4j / CISA KEV Exploited Vulnerability (CRITICAL - LH-PATCH-004)
    VulnerabilityAdvisory(
        advisory_id="CVE-2021-44228",
        ecosystem=Ecosystem.GENERIC,
        package_name="log4j-core",
        affected_range="<2.15.0",
        fixed_version="2.17.1",
        cvss_score=10.0,
        severity=FindingSeverity.CRITICAL,
        title="Log4Shell JNDI Remote Code Execution in CISA KEV",
        description="JNDI injection flaw in log4j-core exploited actively in the wild.",
        is_kev=True,
        cwe_ids=["CWE-502", "CWE-400"],
        references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    ),
    # 5. requests Proxy Auth Leak (MEDIUM - LH-PATCH-005)
    VulnerabilityAdvisory(
        advisory_id="GHSA-j8r2-6x86-q33q",
        ecosystem=Ecosystem.PYPI,
        package_name="requests",
        affected_range="<2.31.0",
        fixed_version="2.31.0",
        cvss_score=6.1,
        severity=FindingSeverity.MEDIUM,
        title="requests Proxy-Authorization header leak on https redirect",
        description="requests leaks Proxy-Authorization headers to destination servers.",
        cwe_ids=["CWE-200"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
    ),
    # 6. Breaking Major SemVer Upgrade (HIGH - LH-PATCH-006)
    VulnerabilityAdvisory(
        advisory_id="GHSA-major-break-01",
        ecosystem=Ecosystem.PYPI,
        package_name="legacy-orm",
        affected_range="<2.0.0",
        fixed_version="2.0.0",
        cvss_score=8.1,
        severity=FindingSeverity.HIGH,
        title="Critical SQL injection requiring breaking v2.0 upgrade",
        description="Legacy ORM v1.x vulnerability requires migrating to v2.0 breaking release.",
        cwe_ids=["CWE-89"],
        references=["https://example.com/security/legacy-orm-v2"],
    ),
    # 7. Malicious package backdoor (CRITICAL - LH-PATCH-008)
    VulnerabilityAdvisory(
        advisory_id="MAL-2024-9999",
        ecosystem=Ecosystem.NPM,
        package_name="malicious-pkg",
        affected_range="<=1.0.0",
        fixed_version=None,
        cvss_score=10.0,
        severity=FindingSeverity.CRITICAL,
        title="Malicious backdoor exfiltrating credentials in malicious-pkg",
        description="Package contained obfuscated postinstall credential harvester.",
        is_malicious=True,
        cwe_ids=["CWE-506"],
        references=["https://github.com/advisories/MAL-2024-9999"],
    ),
    # 8. Transitive bottleneck package (HIGH - LH-PATCH-009)
    VulnerabilityAdvisory(
        advisory_id="GHSA-transitive-pin",
        ecosystem=Ecosystem.NPM,
        package_name="deep-extend",
        affected_range="<0.6.0",
        fixed_version="0.6.0",
        cvss_score=7.5,
        severity=FindingSeverity.HIGH,
        title="Prototype pollution in deep-extend held by parent",
        description="deep-extend prototype pollution vulnerability pinned by parent package.",
        cwe_ids=["CWE-1321"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-3719"],
    ),
    # 9. Low-Severity Advisory (LOW - LH-PATCH-010)
    VulnerabilityAdvisory(
        advisory_id="GHSA-docutils-low",
        ecosystem=Ecosystem.PYPI,
        package_name="docutils",
        affected_range="<0.19",
        fixed_version="0.19",
        cvss_score=3.3,
        severity=FindingSeverity.LOW,
        title="docutils minor path disclosure in HTML writer",
        description="docutils reveals system path in HTML comments under verbose debug mode.",
        cwe_ids=["CWE-200"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-42969"],
    ),
    # 10. npm lodash Prototype Pollution (CRITICAL - LH-PATCH-001)
    VulnerabilityAdvisory(
        advisory_id="GHSA-p6mc-m468-83gw",
        ecosystem=Ecosystem.NPM,
        package_name="lodash",
        affected_range="<4.17.12",
        fixed_version="4.17.12",
        cvss_score=9.8,
        severity=FindingSeverity.CRITICAL,
        title="lodash prototype pollution leading to remote code execution",
        description="lodash defaultsDeep allows modification of Object prototype properties.",
        cwe_ids=["CWE-1321"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"],
    ),
    # 11. Cargo serde (HIGH - LH-PATCH-002)
    VulnerabilityAdvisory(
        advisory_id="RUSTSEC-2021-0082",
        ecosystem=Ecosystem.CARGO,
        package_name="serde",
        affected_range="<1.0.125",
        fixed_version="1.0.125",
        cvss_score=7.5,
        severity=FindingSeverity.HIGH,
        title="serde memory safety issue in untrusted deserialization",
        description="Flaw in serde custom deserialization permits potential memory corruption.",
        cwe_ids=["CWE-119"],
        references=["https://rustsec.org/advisories/RUSTSEC-2021-0082.html"],
    ),
    # 12. Go gin framework (MEDIUM - LH-PATCH-005)
    VulnerabilityAdvisory(
        advisory_id="GHSA-h395-qcrw-5vmq",
        ecosystem=Ecosystem.GO,
        package_name="github.com/gin-gonic/gin",
        affected_range="<1.6.0",
        fixed_version="1.6.0",
        cvss_score=5.3,
        severity=FindingSeverity.MEDIUM,
        title="gin Web Framework directory traversal in static file handling",
        description="gin static file server enables traversal past base directory.",
        cwe_ids=["CWE-22"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-28483"],
    ),
]


def load_advisory_database(custom_path: Path | None = None) -> AdvisoryDatabase:
    """Load embedded database and optional custom local offline advisory feed."""
    advisories = list(EMBEDDED_ADVISORIES)
    timestamp = "2026-10-01T00:00:00Z"
    source = "embedded-osv-nvd"

    if custom_path and custom_path.exists():
        try:
            content = custom_path.read_text(encoding="utf-8", errors="replace")
            if custom_path.suffix.lower() in {".yaml", ".yml"}:
                data = yaml.safe_load(content)
            else:
                data = json.loads(content)

            if isinstance(data, dict):
                timestamp = data.get("timestamp", timestamp)
                source = f"custom:{custom_path.name}"
                items = data.get("advisories", [])
                if isinstance(items, list):
                    for it in items:
                        if isinstance(it, dict):
                            adv = _parse_advisory_dict(it)
                            if adv:
                                advisories.append(adv)
            elif isinstance(data, list):
                source = f"custom:{custom_path.name}"
                for it in data:
                    if isinstance(it, dict):
                        adv = _parse_advisory_dict(it)
                        if adv:
                            advisories.append(adv)
        except Exception:  # nosec B110
            pass

    return AdvisoryDatabase(timestamp=timestamp, source=source, advisories=advisories)


def _parse_advisory_dict(data: dict[str, Any]) -> VulnerabilityAdvisory | None:
    """Parse dictionary into VulnerabilityAdvisory record."""
    adv_id = data.get("id") or data.get("advisory_id")
    if not adv_id:
        return None

    eco_str = str(data.get("ecosystem", "PyPI")).lower()
    eco = Ecosystem.PYPI
    for candidate in Ecosystem:
        if candidate.value.lower() == eco_str:
            eco = candidate
            break

    sev_str = str(data.get("severity", "MEDIUM"))
    sev = FindingSeverity.from_string(sev_str)

    return VulnerabilityAdvisory(
        advisory_id=adv_id,
        ecosystem=eco,
        package_name=data.get("package_name") or data.get("package", ""),
        affected_range=data.get("affected_range") or data.get("range", ""),
        fixed_version=data.get("fixed_version"),
        cvss_score=float(data.get("cvss_score") or data.get("cvss", 0.0)),
        severity=sev,
        title=data.get("title", ""),
        description=data.get("description", ""),
        is_kev=bool(data.get("is_kev", False)),
        is_malicious=bool(data.get("is_malicious", False)),
        cwe_ids=data.get("cwe_ids", []),
        references=data.get("references", []),
    )


def match_packages_against_advisories(
    packages: list[LockedPackage],
    database: AdvisoryDatabase,
    manifest_packages: list[LockedPackage] | None = None,
) -> list[PatchFinding]:
    """Evaluate detection rules LH-PATCH-001 through LH-PATCH-010."""
    findings: list[PatchFinding] = []

    # Check for manifest-to-lockfile drift (LH-PATCH-007)
    if manifest_packages:
        drifts = detect_manifest_drift(manifest_packages, packages)
        for m_pkg, l_pkg in drifts:
            diff_text = (
                f"--- a/{Path(l_pkg.file_path).name}\n"
                f"+++ b/{Path(l_pkg.file_path).name}\n"
                f"-{l_pkg.name}=={l_pkg.version}\n"
                f"+{l_pkg.name}>={m_pkg.version}\n"
            )
            rule_def = RULES_REGISTRY["LH-PATCH-007"]
            findings.append(
                PatchFinding(
                    rule_id="LH-PATCH-007",
                    severity=FindingSeverity.MEDIUM,
                    package_name=l_pkg.name,
                    ecosystem=l_pkg.ecosystem,
                    current_version=l_pkg.version,
                    fixed_version=f">={m_pkg.version}",
                    target_file=l_pkg.file_path,
                    upgrade_risk=UpgradeRisk.PATCH,
                    advisory_id="DRIFT-LOCKFILE-001",
                    cvss=5.0,
                    title=f"Manifest-to-lockfile drift in {l_pkg.name}",
                    description=(
                        f"Locked version {l_pkg.version} is older than declared manifest "
                        f"constraint >={m_pkg.version} in {m_pkg.file_path}"
                    ),
                    remediation=rule_def.remediation,
                    diff_preview=diff_text,
                )
            )

    # Check for stale advisory database (>90 days old) (LH-PATCH-010)
    try:
        dt = datetime.fromisoformat(database.timestamp.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        days_old = (now - dt).days
        if days_old > 90 and packages:
            rule_def = RULES_REGISTRY["LH-PATCH-010"]
            findings.append(
                PatchFinding(
                    rule_id="LH-PATCH-010",
                    severity=FindingSeverity.LOW,
                    package_name="advisory-feed",
                    ecosystem=Ecosystem.GENERIC,
                    current_version=f"{days_old} days old",
                    fixed_version="latest",
                    target_file="advisory-database",
                    upgrade_risk=UpgradeRisk.NONE,
                    advisory_id="STALE-FEED-001",
                    cvss=2.0,
                    title="Offline vulnerability advisory feed is older than 90 days",
                    description=(
                        f"Advisory database from {database.timestamp} is {days_old} days old. "
                        f"Newer CVEs may not be matched."
                    ),
                    remediation=rule_def.remediation,
                    diff_preview="# Update local advisory bundle with newer feed\n",
                )
            )
    except Exception:  # nosec B110
        pass

    # Index advisories by (lowercase package_name, ecosystem)
    adv_by_pkg: dict[tuple[str, Ecosystem], list[VulnerabilityAdvisory]] = {}
    for adv in database.advisories:
        k = (adv.package_name.lower(), adv.ecosystem)
        adv_by_pkg.setdefault(k, []).append(adv)
        # Also index as Generic
        if adv.ecosystem != Ecosystem.GENERIC:
            adv_by_pkg.setdefault((adv.package_name.lower(), Ecosystem.GENERIC), []).append(adv)

    for pkg in packages:
        key = (pkg.name.lower(), pkg.ecosystem)
        candidates = adv_by_pkg.get(key, [])
        if not candidates:
            candidates = adv_by_pkg.get((pkg.name.lower(), Ecosystem.GENERIC), [])

        for adv in candidates:
            if not pkg.parsed_version.satisfies_range(adv.affected_range):
                continue

            # Determine fixed SemVer and upgrade risk
            fixed_semver = SemVer.parse(adv.fixed_version) if adv.fixed_version else None
            risk = pkg.parsed_version.calculate_risk(fixed_semver)

            # Generate diff preview
            file_name = Path(pkg.file_path).name
            if adv.fixed_version:
                diff_preview = (
                    f"--- a/{file_name}\n"
                    f"+++ b/{file_name}\n"
                    f"-{pkg.name}=={pkg.version}\n"
                    f"+{pkg.name}=={adv.fixed_version}\n"
                )
            else:
                diff_preview = (
                    f"--- a/{file_name}\n"
                    f"+++ b/{file_name}\n"
                    f"-{pkg.name}=={pkg.version}\n"
                    f"+# REMOVED / ISOLATED: {pkg.name} (unpatched or malicious)\n"
                )

            # Route to appropriate LH-PATCH rule
            # Rule 8: Malicious, Yanked, or Compromised
            if adv.is_malicious or adv.advisory_id.startswith("MAL-"):
                rule_id = "LH-PATCH-008"
                sev = FindingSeverity.CRITICAL
            # Rule 4: CISA KEV
            elif adv.is_kev:
                rule_id = "LH-PATCH-004"
                sev = FindingSeverity.CRITICAL
            # Rule 3: Unpatched / Zero-Fix
            elif not adv.fixed_version:
                rule_id = "LH-PATCH-003"
                sev = FindingSeverity.CRITICAL
            # Rule 9: Transitive dependency bottleneck
            elif not pkg.is_direct:
                rule_id = "LH-PATCH-009"
                sev = FindingSeverity.HIGH
            # Rule 6: Breaking major SemVer upgrade
            elif risk == UpgradeRisk.MAJOR:
                rule_id = "LH-PATCH-006"
                sev = FindingSeverity.HIGH
            # Rule 1: Critical CVE / GHSA
            elif adv.cvss_score >= 9.0 or adv.severity == FindingSeverity.CRITICAL:
                rule_id = "LH-PATCH-001"
                sev = FindingSeverity.CRITICAL
            # Rule 2: High severity
            elif adv.cvss_score >= 7.0 or adv.severity == FindingSeverity.HIGH:
                rule_id = "LH-PATCH-002"
                sev = FindingSeverity.HIGH
            # Rule 5: Medium severity
            elif adv.cvss_score >= 4.0 or adv.severity == FindingSeverity.MEDIUM:
                rule_id = "LH-PATCH-005"
                sev = FindingSeverity.MEDIUM
            # Rule 10: Low severity
            else:
                rule_id = "LH-PATCH-010"
                sev = FindingSeverity.LOW

            rule_def = RULES_REGISTRY[rule_id]
            findings.append(
                PatchFinding(
                    rule_id=rule_id,
                    severity=sev,
                    package_name=pkg.name,
                    ecosystem=pkg.ecosystem,
                    current_version=pkg.version,
                    fixed_version=adv.fixed_version,
                    target_file=pkg.file_path,
                    upgrade_risk=risk,
                    advisory_id=adv.advisory_id,
                    cvss=adv.cvss_score,
                    title=adv.title or rule_def.title,
                    description=adv.description or rule_def.description,
                    remediation=rule_def.remediation,
                    diff_preview=diff_preview,
                )
            )

    return findings


def scan_target_path(target_path: Path, custom_advisories: Path | None = None) -> PatchDiffReport:
    """Scan target file or directory for lockfiles, advisories, and patch diffs."""
    lockfiles, manifests = find_supported_files(target_path)
    database = load_advisory_database(custom_advisories)

    all_locked_packages: list[LockedPackage] = []
    for lf in lockfiles:
        all_locked_packages.extend(parse_any_lockfile(lf))

    all_manifest_packages: list[LockedPackage] = []
    for mf in manifests:
        all_manifest_packages.extend(parse_any_lockfile(mf))

    findings = match_packages_against_advisories(
        all_locked_packages, database, manifest_packages=all_manifest_packages
    )

    return PatchDiffReport(
        target=str(target_path),
        manifest_files=[str(m) for m in manifests],
        lockfiles_scanned=[str(lf) for lf in lockfiles],
        packages_analyzed=len(all_locked_packages),
        findings_count=len(findings),
        findings=findings,
        advisory_db_timestamp=database.timestamp,
    )
