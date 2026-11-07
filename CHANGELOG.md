# Changelog

All notable changes to `lh-patch-diff` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-07

### Added
- **Initial Release**: Production-ready clean-room release of `lh-patch-diff` developed by **Logihertz Systems (OPC) Private Limited**.
- **Core Parser Capabilities**: Ingestion and offline static evaluation of Lockfiles (`requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `package-lock.json`, `Cargo.lock`, `go.mod`, CycloneDX `.json`).
- **Security Rule Registry**: Complete 10-rule detection catalog spanning `LH-PATCH-001` through `LH-PATCH-010`.
- **Reporting Engine**: Multi-format exporters including colorized Rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0 for GitHub Code Scanning integration.
- **Command-Line Interface**: Executable entrypoints (`lh-patch`, `lh-patch-diff`) supporting `--format`, `--output`, `--min-severity`, and `--fail-on` flags.
- **Zero-Daemon Architecture**: Pure Python 3.11+ clean-room implementation with zero background daemons, zero external database requirements, and zero outbound network telemetry.
