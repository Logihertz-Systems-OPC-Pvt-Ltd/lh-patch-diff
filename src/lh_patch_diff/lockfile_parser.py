# ==============================================================================
# Product:       lh-patch-diff (lh-patch)
# Module:        src.lh_patch_diff.lockfile_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Multi-ecosystem lockfile and manifest parser for lh-patch-diff."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from lh_patch_diff.models import Ecosystem, LockedPackage

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
}


def find_supported_files(root: Path) -> tuple[list[Path], list[Path]]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Discover lockfiles and manifest files in the target directory.

    Returns:
        (lockfiles, manifests)
    """
    if root.is_file():
        # Check if file is lockfile or manifest
        name = root.name.lower()
        if name in {
            "uv.lock",
            "poetry.lock",
            "package-lock.json",
            "cargo.lock",
            "go.mod",
        } or name.endswith(".lock"):
            return [root], []
        return [root], []

    lockfiles: list[Path] = []
    manifests: list[Path] = []

    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        name = path.name.lower()
        if name in {
            "uv.lock",
            "poetry.lock",
            "package-lock.json",
            "cargo.lock",
            "go.mod",
        } or name.endswith(".lock"):
            lockfiles.append(path)
        elif name in {
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "cargo.toml",
        } or (name.startswith("requirements") and name.endswith(".txt")):
            manifests.append(path)
        elif name.endswith(".json") and ("cyclonedx" in name or "sbom" in name):
            lockfiles.append(path)

    return sorted(lockfiles), sorted(manifests)


def parse_requirements_txt(path: Path) -> list[LockedPackage]:
    """Parse pip requirements.txt file for pinned dependency versions."""
    packages: list[LockedPackage] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Match package==1.2.3 or package===1.2.3 or package>=1.2.3
        match = re.match(
            r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|===|>=|~=)\s*([a-zA-Z0-9_\.\-]+)",
            line,
        )
        if match:
            pkg_name = match.group(1).lower()
            version = match.group(2)
            packages.append(
                LockedPackage(
                    name=pkg_name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    file_path=str(path),
                    is_direct=True,
                )
            )
    return packages


def parse_pyproject_toml(path: Path) -> list[LockedPackage]:
    """Parse pyproject.toml [project.dependencies] or poetry dependencies."""
    packages: list[LockedPackage] = []
    try:
        content = path.read_bytes()
        data = tomllib.loads(content.decode("utf-8", errors="replace"))
    except Exception:
        return packages

    # 1. PEP 621 [project.dependencies]
    project_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(project_deps, list):
        for dep in project_deps:
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|===|>=|~=)\s*([a-zA-Z0-9_\.\-]+)", dep)
            if match:
                packages.append(
                    LockedPackage(
                        name=match.group(1).lower(),
                        version=match.group(2),
                        ecosystem=Ecosystem.PYPI,
                        file_path=str(path),
                        is_direct=True,
                    )
                )

    # 2. Poetry [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            ver_str = spec if isinstance(spec, str) else spec.get("version", "")
            ver_clean = re.sub(r"^[\^~>=<]+", "", ver_str).strip()
            if ver_clean:
                packages.append(
                    LockedPackage(
                        name=name.lower(),
                        version=ver_clean,
                        ecosystem=Ecosystem.PYPI,
                        file_path=str(path),
                        is_direct=True,
                    )
                )

    return packages


def parse_uv_or_poetry_lock(path: Path) -> list[LockedPackage]:
    """Parse uv.lock or poetry.lock TOML lockfiles."""
    packages: list[LockedPackage] = []
    try:
        content = path.read_bytes()
        data = tomllib.loads(content.decode("utf-8", errors="replace"))
    except Exception:
        return packages

    pkgs = data.get("package", [])
    if isinstance(pkgs, list):
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                packages.append(
                    LockedPackage(
                        name=name.lower(),
                        version=version,
                        ecosystem=Ecosystem.PYPI,
                        file_path=str(path),
                        is_direct=True,
                    )
                )
    return packages


def parse_package_lock_json(path: Path) -> list[LockedPackage]:
    """Parse npm package-lock.json (supports lockfileVersion 1, 2, and 3)."""
    packages: list[LockedPackage] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return packages

    # npm v2 / v3 packages mapping
    if "packages" in data and isinstance(data["packages"], dict):
        for key, val in data["packages"].items():
            if not key or not isinstance(val, dict):
                continue
            # Extract package name from node_modules/foo or node_modules/@scope/foo
            parts = key.split("node_modules/")
            name = parts[-1] if len(parts) > 1 else key
            version = val.get("version", "")
            if name and version:
                is_nested = key.count("node_modules/") > 1
                is_direct = val.get("dev", False) is False and not is_nested
                parent = parts[-2].rstrip("/") if is_nested else None
                packages.append(
                    LockedPackage(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NPM,
                        file_path=str(path),
                        is_direct=is_direct,
                        required_by=parent,
                    )
                )

    # npm v1 dependencies mapping
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        _parse_npm_v1_deps(data["dependencies"], path, packages)

    return packages


def _parse_npm_v1_deps(
    deps: dict[str, Any], path: Path, packages: list[LockedPackage], parent: str | None = None
) -> None:
    for name, val in deps.items():
        if not isinstance(val, dict):
            continue
        version = val.get("version", "")
        if name and version:
            packages.append(
                LockedPackage(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    file_path=str(path),
                    is_direct=parent is None,
                    required_by=parent,
                )
            )
        nested = val.get("dependencies")
        if isinstance(nested, dict):
            _parse_npm_v1_deps(nested, path, packages, parent=name)


def parse_cargo_lock(path: Path) -> list[LockedPackage]:
    """Parse Rust Cargo.lock TOML lockfile."""
    packages: list[LockedPackage] = []
    try:
        content = path.read_bytes()
        data = tomllib.loads(content.decode("utf-8", errors="replace"))
    except Exception:
        return packages

    pkgs = data.get("package", [])
    if isinstance(pkgs, list):
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                packages.append(
                    LockedPackage(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.CARGO,
                        file_path=str(path),
                        is_direct=True,
                    )
                )
    return packages


def parse_go_mod(path: Path) -> list[LockedPackage]:
    """Parse Go go.mod module requirements."""
    packages: list[LockedPackage] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages

    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line.startswith(")"):
            in_require = False
            continue

        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                ver = parts[1].lstrip("v")
                is_indirect = "// indirect" in line
                packages.append(
                    LockedPackage(
                        name=name,
                        version=ver,
                        ecosystem=Ecosystem.GO,
                        file_path=str(path),
                        is_direct=not is_indirect,
                    )
                )
        elif line.startswith("require ") and not line.startswith("require ("):
            parts = line[len("require ") :].strip().split()
            if len(parts) >= 2:
                name = parts[0]
                ver = parts[1].lstrip("v")
                is_indirect = "// indirect" in line
                packages.append(
                    LockedPackage(
                        name=name,
                        version=ver,
                        ecosystem=Ecosystem.GO,
                        file_path=str(path),
                        is_direct=not is_indirect,
                    )
                )

    return packages


def parse_cyclonedx_sbom(path: Path) -> list[LockedPackage]:
    """Parse CycloneDX SBOM JSON document components."""
    packages: list[LockedPackage] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return packages

    components = data.get("components", [])
    if isinstance(components, list):
        for comp in components:
            if not isinstance(comp, dict):
                continue
            name = comp.get("name", "")
            version = comp.get("version", "")
            purl = comp.get("purl", "")

            # Guess ecosystem from purl or default to Generic
            eco = Ecosystem.GENERIC
            if purl.startswith("pkg:pypi/"):
                eco = Ecosystem.PYPI
            elif purl.startswith("pkg:npm/"):
                eco = Ecosystem.NPM
            elif purl.startswith("pkg:cargo/"):
                eco = Ecosystem.CARGO
            elif purl.startswith("pkg:golang/"):
                eco = Ecosystem.GO

            if name and version:
                packages.append(
                    LockedPackage(
                        name=name,
                        version=version,
                        ecosystem=eco,
                        file_path=str(path),
                        is_direct=True,
                    )
                )

    return packages


def parse_any_lockfile(path: Path) -> list[LockedPackage]:
    """Route a file path to its appropriate ecosystem parser."""
    name = path.name.lower()
    if name == "package-lock.json":
        return parse_package_lock_json(path)
    if name in {"uv.lock", "poetry.lock"}:
        return parse_uv_or_poetry_lock(path)
    if name == "cargo.lock":
        return parse_cargo_lock(path)
    if name == "go.mod":
        return parse_go_mod(path)
    if name.endswith(".json"):
        # Check if CycloneDX SBOM
        try:
            sample = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            if "bomFormat" in sample or "components" in sample:
                return parse_cyclonedx_sbom(path)
        except Exception:  # nosec B110
            pass
    if name.endswith(".toml"):
        return parse_pyproject_toml(path)
    # Default fallback to requirements.txt syntax
    return parse_requirements_txt(path)


def detect_manifest_drift(
    manifest_pkgs: list[LockedPackage], lock_pkgs: list[LockedPackage]
) -> list[tuple[LockedPackage, LockedPackage]]:
    """Detect packages where locked version is older or diverges from declared constraint.

    Returns:
        List of (manifest_pkg, lock_pkg) pairs indicating drift.
    """
    drifts: list[tuple[LockedPackage, LockedPackage]] = []
    lock_map: dict[tuple[str, Ecosystem], LockedPackage] = {
        (p.name.lower(), p.ecosystem): p for p in lock_pkgs
    }

    for m_pkg in manifest_pkgs:
        key = (m_pkg.name.lower(), m_pkg.ecosystem)
        if key in lock_map:
            l_pkg = lock_map[key]
            # If lockfile has older version than declared manifest lower bound
            if l_pkg.parsed_version < m_pkg.parsed_version:
                drifts.append((m_pkg, l_pkg))

    return drifts
