# lh-patch-diff

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-patch-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-patch-diff/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise offline vulnerability & semver patch auditor developed by **Logihertz Systems (OPC) Private Limited**.

Correlates software package inventories and lockfiles against offline OSV/NVD vulnerability advisory feeds, computing minimum safe SemVer upgrade versions, CVSS v3.1 severity gates, and breaking-change risk scores.

---

## Key Features

- **Multi-Ecosystem Lockfile Parsing**: Ingests Python, JavaScript/Node.js, Rust, Go, and CycloneDX dependency lockfiles without external binaries.
- **Offline Advisory Matching**: Evaluates package versions against embedded OSV/NVD CVE advisories and local advisory bundles offline.
- **Semantic Version Patch Diffing**: Calculates SemVer diffs (major, minor, patch) and flags breaking API upgrade risks.
- **Known Exploited Vulnerabilities (KEV)**: Flags active CVEs cataloged in CISA KEV or supply-chain compromise databases.
- **Transitive Bottleneck Identification**: Pinpoints outdated parent dependencies holding back transitive security patches.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-PATCH-001` | `CRITICAL` | Critical CVE/GHSA Vulnerability Match — locked package version matches CVSS >= 9.0 advisory |
| `LH-PATCH-002` | `HIGH` | High-Severity Vulnerability Match — locked package matches a high-severity advisory (7.0 <= CVSS < 9.0) |
| `LH-PATCH-003` | `CRITICAL` | Unpatched / Zero-Fix Vulnerability — matched vulnerability has no upstream fixed release available |
| `LH-PATCH-004` | `CRITICAL` | Known Exploited Vulnerability (KEV) Match — package matches an active CISA KEV catalog entry |
| `LH-PATCH-005` | `MEDIUM` | Medium-Severity Vulnerability Match — locked package matches medium advisory with patch available |
| `LH-PATCH-006` | `HIGH` | Breaking Major SemVer Upgrade Required — remediating vulnerability requires crossing major version boundary |
| `LH-PATCH-007` | `MEDIUM` | Manifest-to-Lockfile Version Drift — version in lockfile conflicts with declared manifest range |
| `LH-PATCH-008` | `CRITICAL` | Malicious or Yanked Package Release — package matches known MAL-* advisory or supply-chain compromise |
| `LH-PATCH-009` | `HIGH` | Transitive Vulnerability Pinning Bottleneck — vulnerable transitive dependency held back by direct parent |
| `LH-PATCH-010` | `LOW` | Low-Severity Advisory or Stale Offline Feed — low severity advisory (CVSS < 4.0) or feed age > 90 days |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-patch-diff.git
cd lh-patch-diff

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-patch` (also accessible via `lh-patch`, `lh-patch-diff`).

```bash
# Scan a lockfile for vulnerabilities and patch diffs
lh-patch scan uv.lock

# Scan requirements.txt with custom offline advisory database
lh-patch scan requirements.txt --advisories ./osv-feed.json

# Export findings to OASIS SARIF v2.1.0
lh-patch scan package-lock.json --format sarif --output patch-results.sarif

# List all detection rules
lh-patch rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
