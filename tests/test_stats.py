"""Tests for siemforge.stats."""
from __future__ import annotations

import json

from siemforge.stats import count_levels


class TestCountLevels:

    def test_empty_rules_dict(self):
        assert count_levels({}) == {}

    def test_counts_by_level(self):
        rules = {
            "a.yml": {"level": "high"},
            "b.yml": {"level": "high"},
            "c.yml": {"level": "medium"},
            "d.yml": {"level": "low"},
        }
        result = count_levels(rules)
        assert result == {"high": 2, "medium": 1, "low": 1}

    def test_missing_level_buckets_as_unknown(self):
        rules = {"orphan.yml": {"title": "no-level rule"}}
        result = count_levels(rules)
        assert result == {"unknown": 1}

    def test_mixed_known_and_unknown(self):
        rules = {
            "a.yml": {"level": "critical"},
            "b.yml": {},
            "c.yml": {"level": "critical"},
        }
        result = count_levels(rules)
        assert result["critical"] == 2
        assert result["unknown"] == 1


class TestShowStatsJson:

    def test_json_output_shape(self, capsys):
        from siemforge.stats import show_stats_json

        rules = {
            "rule_a.yml": {"level": "high", "tags": ["attack.t1059"]},
            "rule_b.yml": {"level": "low", "tags": []},
        }
        show_stats_json(rules)
        captured = capsys.readouterr().out
        payload = json.loads(captured)
        assert payload["sigma_rules"] == 2
        assert "version" in payload
        assert payload["severity_breakdown"]["high"] == 1
        assert payload["severity_breakdown"]["low"] == 1
        assert "mitre_techniques" in payload
        assert "rule_files" in payload
        assert sorted(payload["rule_files"]) == ["rule_a.yml", "rule_b.yml"]
