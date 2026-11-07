# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        tests.test_lockfile_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for multi-ecosystem lockfile and manifest parser."""

from __future__ import annotations

from pathlib import Path

from lh_patch_diff.lockfile_parser import (
    detect_manifest_drift,
    find_supported_files,
    parse_any_lockfile,
    parse_cargo_lock,
    parse_cyclonedx_sbom,
    parse_go_mod,
    parse_package_lock_json,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_uv_or_poetry_lock,
)
from lh_patch_diff.models import Ecosystem, LockedPackage


def test_parse_requirements_txt(vulnerable_requirements: Path) -> None:
    """Test parsing pinned pip requirements."""
    pkgs = parse_requirements_txt(vulnerable_requirements)
    names = {p.name for p in pkgs}
    assert "pyyaml" in names
    assert "urllib3" in names
    assert "requests" in names

    pyyaml_pkg = next(p for p in pkgs if p.name == "pyyaml")
    assert pyyaml_pkg.version == "5.3.1"
    assert pyyaml_pkg.ecosystem == Ecosystem.PYPI


def test_parse_package_lock_json(vulnerable_npm_lock: Path) -> None:
    """Test parsing npm v2/v3 lockfile."""
    pkgs = parse_package_lock_json(vulnerable_npm_lock)
    names = {p.name for p in pkgs}
    assert "lodash" in names
    assert "malicious-pkg" in names
    assert "deep-extend" in names

    lodash_pkg = next(p for p in pkgs if p.name == "lodash")
    assert lodash_pkg.version == "4.17.11"
    assert lodash_pkg.ecosystem == Ecosystem.NPM


def test_parse_cargo_lock(vulnerable_cargo_lock: Path) -> None:
    """Test parsing Rust Cargo.lock."""
    pkgs = parse_cargo_lock(vulnerable_cargo_lock)
    assert len(pkgs) == 1
    assert pkgs[0].name == "serde"
    assert pkgs[0].version == "1.0.100"
    assert pkgs[0].ecosystem == Ecosystem.CARGO


def test_parse_go_mod(vulnerable_go_mod: Path) -> None:
    """Test parsing Go go.mod."""
    pkgs = parse_go_mod(vulnerable_go_mod)
    assert len(pkgs) == 1
    assert pkgs[0].name == "github.com/gin-gonic/gin"
    assert pkgs[0].version == "1.5.0"
    assert pkgs[0].ecosystem == Ecosystem.GO


def test_parse_cyclonedx_sbom(cyclonedx_sbom: Path) -> None:
    """Test parsing CycloneDX SBOM JSON."""
    pkgs = parse_cyclonedx_sbom(cyclonedx_sbom)
    assert len(pkgs) == 1
    assert pkgs[0].name == "log4j-core"
    assert pkgs[0].version == "2.14.1"


def test_parse_pyproject_toml(tmp_path: Path) -> None:
    """Test parsing pyproject.toml PEP 621 dependencies."""
    pyp = tmp_path / "pyproject.toml"
    pyp.write_text(
        '[project]\nname = "my-tool"\nversion = "0.1.0"\n'
        'dependencies = ["httpx==0.24.1", "pydantic>=2.0.0"]\n',
        encoding="utf-8",
    )
    pkgs = parse_pyproject_toml(pyp)
    names = {p.name for p in pkgs}
    assert "httpx" in names
    assert "pydantic" in names


def test_parse_uv_or_poetry_lock(tmp_path: Path) -> None:
    """Test parsing uv.lock or poetry.lock."""
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n\n[[package]]\nname = "click"\nversion = "8.1.7"\n',
        encoding="utf-8",
    )
    pkgs = parse_uv_or_poetry_lock(lock)
    assert len(pkgs) == 1
    assert pkgs[0].name == "click"
    assert pkgs[0].version == "8.1.7"


def test_find_supported_files(clean_project: Path) -> None:
    """Test discovering lockfiles and manifests in repository."""
    lockfiles, manifests = find_supported_files(clean_project)
    lock_names = {p.name for p in lockfiles}
    manifest_names = {p.name for p in manifests}
    assert "Cargo.lock" in lock_names
    assert "requirements.txt" in manifest_names


def test_parse_any_lockfile_fallback(tmp_path: Path) -> None:
    """Test parse_any_lockfile fallback behavior."""
    unknown = tmp_path / "pinned.txt"
    unknown.write_text("urllib3==1.26.18\n", encoding="utf-8")
    pkgs = parse_any_lockfile(unknown)
    assert len(pkgs) == 1
    assert pkgs[0].name == "urllib3"


def test_detect_manifest_drift() -> None:
    """Test detecting manifest-to-lockfile drift when lockfile is older."""
    manifest_pkgs = [
        LockedPackage(
            name="urllib3",
            version="2.0.0",
            ecosystem=Ecosystem.PYPI,
            file_path="pyproject.toml",
        )
    ]
    lock_pkgs = [
        LockedPackage(
            name="urllib3",
            version="1.26.4",
            ecosystem=Ecosystem.PYPI,
            file_path="uv.lock",
        )
    ]

    drifts = detect_manifest_drift(manifest_pkgs, lock_pkgs)
    assert len(drifts) == 1
    m, l_pkg = drifts[0]
    assert m.version == "2.0.0"
    assert l_pkg.version == "1.26.4"
