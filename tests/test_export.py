"""Tests for export and stats functionality."""

import json
from pathlib import Path

from siemforge import (
    MITRE_MAP,
    _collect_techniques,
    _count_levels,
    export_all,
    export_sigma_rules,
    load_sigma_rules,
)
from siemforge.export import export_sysmon_config, export_wazuh_rules
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


class TestExportSysmonConfig:
    """Tests for the standalone Sysmon config export."""

    def test_dry_run_creates_no_files(self, tmp_path):
        out_dir = tmp_path / "sysmon"
        result = export_sysmon_config(output_dir=str(out_dir), dry_run=True)
        assert not out_dir.exists()
        assert result == out_dir / "sysmon_config.xml"

    def test_export_writes_config(self, tmp_path):
        out_dir = tmp_path / "sysmon"
        result = export_sysmon_config(output_dir=str(out_dir), dry_run=False)
        written = out_dir / "sysmon_config.xml"
        assert written.is_file()
        assert result == written
        assert written.read_text(encoding="utf-8").strip()

    def test_install_commands_printed(self, tmp_path, capsys):
        out_dir = tmp_path / "sysmon"
        export_sysmon_config(output_dir=str(out_dir), dry_run=False)
        output = capsys.readouterr().out
        assert "sysmon64.exe" in output


class TestExportWazuhRules:
    """Tests for the standalone Wazuh rules export."""

    def test_dry_run_creates_no_files(self, tmp_path):
        out_dir = tmp_path / "wazuh"
        result = export_wazuh_rules(output_dir=str(out_dir), dry_run=True)
        assert not out_dir.exists()
        assert result == out_dir

    def test_export_writes_both_files(self, tmp_path):
        out_dir = tmp_path / "wazuh"
        result = export_wazuh_rules(output_dir=str(out_dir), dry_run=False)
        local_rules = out_dir / "local_rules.xml"
        agent_snippet = out_dir / "agent_ossec_snippet.xml"
        assert result == out_dir
        assert local_rules.is_file()
        assert agent_snippet.is_file()
        assert local_rules.read_text(encoding="utf-8").strip()
        assert agent_snippet.read_text(encoding="utf-8").strip()


def _raise_oserror(*args, **kwargs):
    raise OSError("simulated disk failure")


class TestExportErrorHandling:
    """The exporters should report I/O failures and return cleanly, not crash."""

    def test_sigma_export_reports_mkdir_failure(self, tmp_path, monkeypatch, capsys):
        rules = load_sigma_rules()
        monkeypatch.setattr(Path, "mkdir", _raise_oserror)
        result = export_sigma_rules(rules, output_dir=str(tmp_path / "out"), dry_run=False)
        assert result is None
        assert "Cannot create directory" in capsys.readouterr().out

    def test_sigma_export_reports_write_failure(self, tmp_path, monkeypatch, capsys):
        rules = load_sigma_rules()
        monkeypatch.setattr(Path, "write_text", _raise_oserror)
        out = tmp_path / "out"
        result = export_sigma_rules(rules, output_dir=str(out), dry_run=False)
        # The directory is created, so a path comes back, but each write is
        # reported as a failure rather than raising.
        assert result == out
        assert "Failed to write" in capsys.readouterr().out

    def test_sysmon_export_reports_mkdir_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "mkdir", _raise_oserror)
        result = export_sysmon_config(output_dir=str(tmp_path / "out"), dry_run=False)
        assert result is None
        assert "Cannot create directory" in capsys.readouterr().out

    def test_sysmon_export_reports_write_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "write_text", _raise_oserror)
        result = export_sysmon_config(output_dir=str(tmp_path / "out"), dry_run=False)
        assert result is None
        assert "Failed to write" in capsys.readouterr().out

    def test_wazuh_export_reports_mkdir_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "mkdir", _raise_oserror)
        result = export_wazuh_rules(output_dir=str(tmp_path / "out"), dry_run=False)
        assert result is None
        assert "Cannot create directory" in capsys.readouterr().out

    def test_wazuh_export_reports_write_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "write_text", _raise_oserror)
        out = tmp_path / "out"
        result = export_wazuh_rules(output_dir=str(out), dry_run=False)
        # Both files fail to write but the directory path still comes back.
        assert result == out
        assert capsys.readouterr().out.count("Failed to write") == 2

    def test_export_all_reports_base_mkdir_failure(self, tmp_path, monkeypatch, capsys):
        rules = load_sigma_rules()
        monkeypatch.setattr(Path, "mkdir", _raise_oserror)
        export_all(rules, output_dir=str(tmp_path / "out"), dry_run=False)
        assert "Cannot create export directory" in capsys.readouterr().out

    def test_export_all_reports_write_failures(self, tmp_path, monkeypatch, capsys):
        # Directories are created for real; only the writes fail, so every
        # section (sigma, sysmon, wazuh, manifest) logs its own failure.
        rules = load_sigma_rules()
        monkeypatch.setattr(Path, "write_text", _raise_oserror)
        export_all(rules, output_dir=str(tmp_path / "out"), dry_run=False)
        out = capsys.readouterr().out
        assert "Failed to write" in out
        assert "manifest.json" in out


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
