"""Tests for export and stats functionality."""

import json

from siemforge import (
    MITRE_MAP,
    _collect_techniques,
    _count_levels,
    export_all,
    export_sigma_rules,
    load_sigma_rules,
)
from siemforge.stats import count_levels, show_rule_summary, show_stats, show_stats_json


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


class TestStatsOutput:
    """Tests for stats display functions."""

    def test_show_stats_runs(self, capsys):
        rules = load_sigma_rules()
        show_stats(rules)
        output = capsys.readouterr().out
        assert "Sigma Detection Rules" in output

    def test_show_stats_json_valid(self, capsys):
        rules = load_sigma_rules()
        show_stats_json(rules)
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "version" in data
        assert "sigma_rules" in data
        assert "severity_breakdown" in data
        assert data["sigma_rules"] == len(rules)

    def test_show_rule_summary_runs(self, capsys):
        rules = load_sigma_rules()
        show_rule_summary(rules)
        output = capsys.readouterr().out
        assert "Total Rules" in output

    def test_count_levels_mixed(self):
        rules = {
            "a.yml": {"level": "high"},
            "b.yml": {"level": "high"},
            "c.yml": {"level": "low"},
        }
        levels = count_levels(rules)
        assert levels["high"] == 2
        assert levels["low"] == 1

    def test_count_levels_missing_level(self):
        rules = {"a.yml": {"title": "no level field"}}
        levels = count_levels(rules)
        assert levels.get("unknown") == 1
