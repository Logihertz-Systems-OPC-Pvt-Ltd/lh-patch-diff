# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Test fixtures and mock dependency artifacts for lh-patch-diff test suite."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def clean_project(tmp_path: Path) -> Path:
    """Create a project with secure, modern, and up-to-date dependencies."""
    proj = tmp_path / "clean_proj"
    proj.mkdir()

    req = proj / "requirements.txt"
    req.write_text(
        "pyyaml==6.0.1\nurllib3==2.2.1\nrequests==2.31.0\ndocutils==0.20.1\n",
        encoding="utf-8",
    )

    cargo = proj / "Cargo.lock"
    cargo.write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.197"\n',
        encoding="utf-8",
    )

    return proj


@pytest.fixture
def vulnerable_requirements(tmp_path: Path) -> Path:
    """Create requirements.txt triggering rules LH-PATCH-001, 002, 003, 005, 006, 010."""
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# Vulnerable dependencies\n"
        "pyyaml==5.3.1\n"  # CRITICAL (LH-PATCH-001)
        "urllib3==1.26.4\n"  # HIGH (LH-PATCH-002)
        "zeroday-lib==1.0.0\n"  # CRITICAL Unpatched (LH-PATCH-003)
        "requests==2.28.1\n"  # MEDIUM (LH-PATCH-005)
        "legacy-orm==1.2.0\n"  # HIGH Major breaking (LH-PATCH-006)
        "docutils==0.16\n",  # LOW (LH-PATCH-010)
        encoding="utf-8",
    )
    return req


@pytest.fixture
def vulnerable_npm_lock(tmp_path: Path) -> Path:
    """Create package-lock.json triggering LH-PATCH-001, LH-PATCH-008, LH-PATCH-009."""
    proj = tmp_path / "npm_app"
    proj.mkdir()

    npm_lock = proj / "package-lock.json"
    npm_lock.write_text(
        """{
  "name": "demo-npm",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo-npm",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.11"
    },
    "node_modules/malicious-pkg": {
      "version": "1.0.0"
    },
    "node_modules/parent-pkg": {
      "version": "1.0.0"
    },
    "node_modules/parent-pkg/node_modules/deep-extend": {
      "version": "0.5.1"
    }
  }
}
""",
        encoding="utf-8",
    )
    return npm_lock


@pytest.fixture
def vulnerable_cargo_lock(tmp_path: Path) -> Path:
    """Create Cargo.lock triggering LH-PATCH-002."""
    cargo = tmp_path / "Cargo.lock"
    cargo.write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.100"\n',
        encoding="utf-8",
    )
    return cargo


@pytest.fixture
def vulnerable_go_mod(tmp_path: Path) -> Path:
    """Create go.mod triggering LH-PATCH-005."""
    go_file = tmp_path / "go.mod"
    go_file.write_text(
        "module example.com/goapp\n\n"
        "go 1.21\n\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.5.0\n"
        ")\n",
        encoding="utf-8",
    )
    return go_file


@pytest.fixture
def cyclonedx_sbom(tmp_path: Path) -> Path:
    """Create CycloneDX SBOM triggering LH-PATCH-004 (CISA KEV)."""
    sbom = tmp_path / "cyclonedx.json"
    sbom.write_text(
        """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ]
}
""",
        encoding="utf-8",
    )
    return sbom


@pytest.fixture
def drift_project(tmp_path: Path) -> Path:
    """Create project exhibiting manifest-to-lockfile drift (LH-PATCH-007)."""
    proj = tmp_path / "drift_proj"
    proj.mkdir()

    # Manifest requires urllib3>=2.0.0
    pyp = proj / "pyproject.toml"
    pyp.write_text(
        '[project]\nname = "drift"\nversion = "0.1.0"\ndependencies = ["urllib3>=2.0.0"]\n',
        encoding="utf-8",
    )

    # Lockfile has locked older urllib3==1.26.4
    uv_lock = proj / "uv.lock"
    uv_lock.write_text(
        'version = 1\n\n[[package]]\nname = "urllib3"\nversion = "1.26.4"\n',
        encoding="utf-8",
    )

    return proj


@pytest.fixture
def custom_advisory_feed(tmp_path: Path) -> Path:
    """Create custom offline advisory JSON feed."""
    feed = tmp_path / "custom_advisories.json"
    feed.write_text(
        """{
  "timestamp": "2026-11-01T00:00:00Z",
  "advisories": [
    {
      "id": "CUSTOM-CVE-2026-9999",
      "ecosystem": "PyPI",
      "package_name": "custom-lib",
      "affected_range": "<2.5.0",
      "fixed_version": "2.5.0",
      "cvss": 8.5,
      "severity": "HIGH",
      "title": "Custom library SQL injection",
      "description": "Custom advisory for test validation"
    }
  ]
}
""",
        encoding="utf-8",
    )
    return feed
