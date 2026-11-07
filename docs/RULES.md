# Security Rules Reference: lh-patch-diff

An enterprise lockfile vulnerability & patch diff analyzer developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-patch-diff`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-PATCH-001` | `CRITICAL` | Vulnerability | Critical CVE/GHSA Vulnerability Match |
| `LH-PATCH-002` | `HIGH` | Vulnerability | High-Severity Vulnerability Match |
| `LH-PATCH-003` | `CRITICAL` | Vulnerability | Unpatched / Zero-Fix Vulnerability |
| `LH-PATCH-004` | `CRITICAL` | Exploitation | Known Exploited Vulnerability (KEV) Match |
| `LH-PATCH-005` | `MEDIUM` | Vulnerability | Medium-Severity Vulnerability Match |
| `LH-PATCH-006` | `HIGH` | Upgrade Risk | Breaking Major SemVer Upgrade Required |
| `LH-PATCH-007` | `MEDIUM` | Dependency Drift | Manifest-to-Lockfile Version Drift |
| `LH-PATCH-008` | `CRITICAL` | Supply Chain | Malicious or Yanked Package Release |
| `LH-PATCH-009` | `HIGH` | Supply Chain | Transitive Vulnerability Pinning Bottleneck |
| `LH-PATCH-010` | `LOW` | Governance | Low-Severity Advisory or Stale Offline Feed |

---

## Granular Rule Specifications

### `LH-PATCH-001`: Critical CVE/GHSA Vulnerability Match

- **Severity**: `CRITICAL`
- **Category**: `Vulnerability`
- **Description**: Locked package version falls within affected SemVer range of a critical advisory (CVSS >= 9.0).
- **Remediation**: Upgrade package to recommended fixed version declared in security advisory.

---

### `LH-PATCH-002`: High-Severity Vulnerability Match

- **Severity**: `HIGH`
- **Category**: `Vulnerability`
- **Description**: Locked package version matches a high-severity OSV/NVD advisory (7.0 <= CVSS < 9.0).
- **Remediation**: Apply minor or patch version upgrade to safe upstream release.

---

### `LH-PATCH-003`: Unpatched / Zero-Fix Vulnerability

- **Severity**: `CRITICAL`
- **Category**: `Vulnerability`
- **Description**: Locked package matches active vulnerability advisory where no upstream fix exists.
- **Remediation**: Apply runtime mitigation, isolate affected component, or migrate to alternative library.

---

### `LH-PATCH-004`: Known Exploited Vulnerability (KEV) Match

- **Severity**: `CRITICAL`
- **Category**: `Exploitation`
- **Description**: Locked package matches CVE flagged in CISA KEV active exploitation catalog.
- **Remediation**: Prioritize immediate emergency remediation within 24-48 hours.

---

### `LH-PATCH-005`: Medium-Severity Vulnerability Match

- **Severity**: `MEDIUM`
- **Category**: `Vulnerability`
- **Description**: Locked package matches medium-severity advisory (4.0 <= CVSS < 7.0).
- **Remediation**: Upgrade package in next scheduled maintenance cycle.

---

### `LH-PATCH-006`: Breaking Major SemVer Upgrade Required

- **Severity**: `HIGH`
- **Category**: `Upgrade Risk`
- **Description**: Remediating matched vulnerability requires crossing major SemVer boundary (e.g. 1.x to 2.x).
- **Remediation**: Review library changelog and migration guide before applying major version upgrade.

---

### `LH-PATCH-007`: Manifest-to-Lockfile Version Drift

- **Severity**: `MEDIUM`
- **Category**: `Dependency Drift`
- **Description**: Locked version conflicts with constraint declared in pyproject.toml or package.json.
- **Remediation**: Run package manager lock update command (e.g., uv lock) to synchronize manifests.

---

### `LH-PATCH-008`: Malicious or Yanked Package Release

- **Severity**: `CRITICAL`
- **Category**: `Supply Chain`
- **Description**: Locked package matches known malicious advisory (MAL-*) or yanked release.
- **Remediation**: Purge package from lockfiles immediately and audit systems for indicators of compromise.

---

### `LH-PATCH-009`: Transitive Vulnerability Pinning Bottleneck

- **Severity**: `HIGH`
- **Category**: `Supply Chain`
- **Description**: Vulnerable transitive dependency held back by outdated direct parent dependency constraint.
- **Remediation**: Upgrade direct parent dependency to release that permits patched transitive version.

---

### `LH-PATCH-010`: Low-Severity Advisory or Stale Offline Feed

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Package matches low-severity advisory (CVSS < 4.0) or advisory bundle is > 90 days old.
- **Remediation**: Update offline advisory database bundle with latest OSV/NVD feed snapshots.

---
