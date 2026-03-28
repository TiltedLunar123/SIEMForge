"""Tests for export and stats functionality."""

import json
import pytest
from pathlib import Path

from siemforge import (
    load_sigma_rules, export_sigma_rules, export_all,
    _collect_techniques, _count_levels, MITRE_MAP,
)


class TestCollectTechniques:
    """Tests for MITRE technique extraction from parsed rules."""

    def test_extracts_techniques_from_loaded_rules(self):
        rules = load_sigma_rules()
        techniques, tactics = _collect_techniques(rules)
        assert len(techniques) > 0
        assert len(tactics) > 0

    def test_technique_ids_are_uppercase(self):
        rules = load_sigma_rules()
        techniques, _ = _collect_techniques(rules)
        for tid in techniques:
            assert tid == tid.upper(), f"Technique {tid} is not uppercase"

    def test_all_techniques_in_mitre_map(self):
        rules = load_sigma_rules()
        techniques, _ = _collect_techniques(rules)
        for tid in techniques:
            assert tid in MITRE_MAP, f"Technique {tid} not in MITRE_MAP"

    def test_empty_rules_returns_empty_sets(self):
        techniques, tactics = _collect_techniques({})
        assert techniques == set()
        assert tactics == set()

    def test_rule_without_tags_handled(self):
        rules = {"test.yml": {"title": "No tags"}}
        techniques, tactics = _collect_techniques(rules)
        assert techniques == set()


class TestCountLevels:
    """Tests for severity level counting."""

    def test_counts_from_loaded_rules(self):
        rules = load_sigma_rules()
        levels = _count_levels(rules)
        total = sum(levels.values())
        assert total == len(rules)

    def test_all_levels_valid(self):
        rules = load_sigma_rules()
        levels = _count_levels(rules)
        valid = {"informational", "low", "medium", "high", "critical"}
        for lvl in levels:
            assert lvl in valid, f"Unexpected level: {lvl}"

    def test_empty_rules(self):
        levels = _count_levels({})
        assert levels == {}


class TestExportSigmaRules:
    """Tests for Sigma rule export."""

    def test_dry_run_creates_no_files(self, tmp_path):
        rules = load_sigma_rules()
        out_dir = tmp_path / "export"
        export_sigma_rules(rules, output_dir=str(out_dir), dry_run=True)
        assert not out_dir.exists()

    def test_export_creates_files(self, tmp_path):
        rules = load_sigma_rules()
        out_dir = tmp_path / "sigma_export"
        export_sigma_rules(rules, output_dir=str(out_dir), dry_run=False)
        assert out_dir.exists()
        exported_files = list(out_dir.glob("*.yml"))
        assert len(exported_files) == len(rules)


class TestExportAll:
    """Tests for full export."""

    def test_dry_run_creates_no_files(self, tmp_path):
        rules = load_sigma_rules()
        out_dir = tmp_path / "full_export"
        export_all(rules, output_dir=str(out_dir), dry_run=True)
        assert not out_dir.exists()

    def test_full_export_creates_structure(self, tmp_path):
        rules = load_sigma_rules()
        out_dir = tmp_path / "full_export"
        export_all(rules, output_dir=str(out_dir), dry_run=False)

        assert (out_dir / "sigma_rules").is_dir()
        assert (out_dir / "sysmon").is_dir()
        assert (out_dir / "wazuh").is_dir()
        assert (out_dir / "manifest.json").is_file()
        assert (out_dir / "sysmon" / "sysmon_config.xml").is_file()
        assert (out_dir / "wazuh" / "local_rules.xml").is_file()
        assert (out_dir / "wazuh" / "agent_ossec_snippet.xml").is_file()

        # Validate manifest
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["tool"] == "SIEMForge"
        assert manifest["sigma_count"] == len(rules)
        assert len(manifest["mitre_techniques"]) > 0
