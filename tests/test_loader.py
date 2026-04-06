"""Tests for rule loading functionality."""


import pytest

from siemforge import SIGMA_RULES_DIR, load_config_file, load_sigma_rules


class TestLoadSigmaRules:
    """Tests for loading Sigma YAML rules from disk."""

    def test_loads_all_rules_from_default_dir(self):
        rules = load_sigma_rules()
        rule_files = list(SIGMA_RULES_DIR.glob("*.yml"))
        assert len(rules) == len(rule_files), (
            f"Expected {len(rule_files)} Sigma rules, got {len(rules)}"
        )

    def test_all_rules_are_dicts(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            assert isinstance(rule, dict), f"{filename} did not parse to a dict"

    def test_rule_filenames_end_with_yml(self):
        rules = load_sigma_rules()
        for filename in rules:
            assert filename.endswith(".yml"), f"{filename} does not end with .yml"

    def test_returns_empty_for_nonexistent_dir(self, tmp_path):
        rules = load_sigma_rules(tmp_path / "nonexistent")
        assert rules == {}

    def test_skips_invalid_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text(": : : not valid yaml [[[", encoding="utf-8")
        good_file = tmp_path / "good.yml"
        good_file.write_text("title: Test Rule\nid: abc-123\n", encoding="utf-8")

        rules = load_sigma_rules(tmp_path)
        assert "good.yml" in rules
        assert "bad.yml" not in rules

    def test_every_rule_has_title(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            assert "title" in rule, f"{filename} is missing 'title'"

    def test_every_rule_has_detection(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            assert "detection" in rule, f"{filename} is missing 'detection'"

    def test_every_rule_has_id(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            assert "id" in rule, f"{filename} is missing 'id'"

    def test_rules_sorted_by_filename(self):
        rules = load_sigma_rules()
        filenames = list(rules.keys())
        assert filenames == sorted(filenames)


class TestLoadConfigFile:
    """Tests for loading XML config files."""

    def test_loads_sysmon_config(self):
        content = load_config_file("sysmon_config.xml")
        assert "<Sysmon" in content
        assert "EventFiltering" in content

    def test_loads_wazuh_rules(self):
        content = load_config_file("wazuh_local_rules.xml")
        assert '<group name="siemforge,">' in content
        assert '<rule id="100100"' in content

    def test_loads_wazuh_agent_snippet(self):
        content = load_config_file("wazuh_agent_snippet.xml")
        assert "Sysmon" in content
        assert "<localfile>" in content

    def test_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config_file("nonexistent.xml")
