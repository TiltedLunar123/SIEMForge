# Changelog

All notable changes to SIEMForge are documented here.

## [3.0.0] - 2026-04-05

### Added
- **Log scanner** (`--scan`): match log files against Sigma rules with JSON, syslog, and CSV support
- Sample log files under `samples/` demonstrating detection capabilities
- `python -m siemforge` entry point
- `NO_COLOR` environment variable support
- `--scan-format` flag for explicit format hinting
- `--json` output mode for scan results
- Test coverage reporting in CI
- Ruff linting in CI pipeline
- `requirements.txt` and `requirements-dev.txt`

### Changed
- Refactored monolithic `siemforge.py` into a proper Python package (`siemforge/`)
- Updated CI to target `master` branch (was incorrectly targeting `main`)
- Fixed build backend in `pyproject.toml` (was using deprecated path)
- Manifest export timestamps now use UTC with timezone info
- Bumped minimum Python version to 3.10

### Fixed
- CI workflow never triggered due to branch name mismatch
- Rule IDs replaced with proper uuid4 values
- Rule dates staggered to reflect iterative development

## [2.1.0] - 2025-06-15

### Added
- Sigma-to-SIEM query converter with Splunk SPL, Elasticsearch Lucene, and Kibana KQL backends
- `--convert`, `--convert-output`, `--convert-rule` CLI flags
- Converter test suite

## [2.0.0] - 2025-06-01

### Added
- Sigma rule validation with `--validate`
- MITRE ATT&CK coverage display with `--mitre`
- Full export with manifest via `--export-all`
- Dry-run mode
- JSON statistics output
- 78 pytest tests

## [1.0.0] - 2025-03-08

### Added
- Initial release with 10 Sigma detection rules
- Sysmon configuration optimized for detection rules
- Wazuh custom rules with MITRE ATT&CK mapping
- CLI for rule listing, export, and statistics
