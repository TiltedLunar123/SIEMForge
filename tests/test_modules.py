"""Tests for mitre, stats, and display helper modules."""
from __future__ import annotations

import importlib
import json

from siemforge import display, mitre, stats
from siemforge._version import VERSION

# ── mitre.py ───────────────────────────────────


class TestCollectTechniques:

    def test_maps_known_technique_to_tactic(self):
        rules = {"r": {"tags": ["attack.t1059.001"]}}
        techniques, tactics = mitre.collect_techniques(rules)
        assert techniques == {"T1059.001"}
        assert tactics == {"Execution"}

    def test_unknown_technique_has_no_tactic(self):
        rules = {"r": {"tags": ["attack.t9999.999"]}}
        techniques, tactics = mitre.collect_techniques(rules)
        assert techniques == {"T9999.999"}
        assert tactics == set()

    def test_plain_tactic_tag_is_titled(self):
        rules = {"r": {"tags": ["attack.credential_access"]}}
        techniques, tactics = mitre.collect_techniques(rules)
        assert techniques == set()
        assert tactics == {"Credential Access"}

    def test_rule_without_tags_is_skipped(self):
        techniques, tactics = mitre.collect_techniques({"r": {}})
        assert techniques == set()
        assert tactics == set()

    def test_deduplicates_across_rules(self):
        rules = {
            "a": {"tags": ["attack.t1059.001"]},
            "b": {"tags": ["attack.t1059.001"]},
        }
        techniques, _ = mitre.collect_techniques(rules)
        assert techniques == {"T1059.001"}

    def test_multi_tactic_technique_counts_every_tactic(self):
        # T1053.005 (Scheduled Task) is filed under three tactics in ATT&CK.
        rules = {"r": {"tags": ["attack.t1053.005"]}}
        techniques, tactics = mitre.collect_techniques(rules)
        assert techniques == {"T1053.005"}
        assert tactics == {"Execution", "Persistence", "Privilege Escalation"}

    def test_show_mitre_coverage_runs(self, capsys):
        rules = {
            "a": {"tags": ["attack.t1059.001"]},
            "b": {"tags": ["attack.t9999.999"]},
        }
        mitre.show_mitre_coverage(rules)
        out = capsys.readouterr().out
        assert "T1059.001" in out
        assert "Unknown" in out
        assert "Total Techniques Covered" in out


class TestTacticsFor:

    def test_single_tactic_returns_one(self):
        assert mitre.tactics_for("T1059.001") == ["Execution"]

    def test_multi_tactic_returns_full_list_primary_first(self):
        result = mitre.tactics_for("T1547.001")
        assert result[0] == "Persistence"
        assert set(result) == {"Persistence", "Privilege Escalation"}

    def test_unknown_id_returns_empty(self):
        assert mitre.tactics_for("T9999.999") == []


class TestMitreMapConsistency:
    """Guard the shape of every MITRE_MAP entry."""

    def test_every_entry_has_name_and_tactic(self):
        for tid, entry in mitre.MITRE_MAP.items():
            assert isinstance(entry.get("name"), str), tid
            assert isinstance(entry.get("tactic"), str), tid

    def test_primary_tactic_leads_the_list(self):
        for tid, entry in mitre.MITRE_MAP.items():
            tactics = entry.get("tactics")
            if tactics is None:
                continue
            assert isinstance(tactics, list) and len(tactics) >= 2, tid
            assert tactics[0] == entry["tactic"], tid
            assert len(tactics) == len(set(tactics)), tid


class TestBundledRulesAreMapped:
    """Guard: no shipped rule may reference a technique missing from MITRE_MAP."""

    def test_every_bundled_technique_is_in_the_map(self):
        from siemforge.loader import load_sigma_rules

        rules = load_sigma_rules()
        techniques, _ = mitre.collect_techniques(rules)
        missing = sorted(t for t in techniques if t not in mitre.MITRE_MAP)
        assert not missing, (
            f"Bundled rules reference techniques not in MITRE_MAP: {missing}. "
            "Add them to siemforge/mitre.py so coverage doesn't show 'Unknown'."
        )


# ── stats.py ───────────────────────────────────


class TestCountLevels:

    def test_counts_each_level(self):
        rules = {
            "a": {"level": "high"},
            "b": {"level": "high"},
            "c": {"level": "low"},
        }
        assert stats.count_levels(rules) == {"high": 2, "low": 1}

    def test_missing_level_is_unknown(self):
        assert stats.count_levels({"a": {}}) == {"unknown": 1}


class TestShowStatsJson:

    def test_emits_valid_json_payload(self, capsys):
        rules = {
            "lsass.yml": {"level": "critical", "tags": ["attack.t1003.001"]},
            "ps.yml": {"level": "high", "tags": ["attack.t1059.001"]},
        }
        stats.show_stats_json(rules)
        payload = json.loads(capsys.readouterr().out)
        assert payload["version"] == VERSION
        assert payload["sigma_rules"] == 2
        assert payload["mitre_technique_count"] == 2
        assert payload["severity_breakdown"] == {"critical": 1, "high": 1}
        assert sorted(payload["rule_files"]) == ["lsass.yml", "ps.yml"]

    def test_show_stats_runs(self, capsys):
        rules = {"a.yml": {"level": "high", "tags": ["attack.t1059.001"]}}
        stats.show_stats(rules)
        out = capsys.readouterr().out
        assert "PROJECT STATISTICS" in out
        assert "Severity Breakdown" in out


# ── display.py ─────────────────────────────────


class TestDisplay:

    def test_status_helpers_emit_message(self, capsys):
        display.ok("alpha")
        display.info("bravo")
        display.warn("charlie")
        display.err("delta")
        display.bullet("echo")
        out = capsys.readouterr().out
        for msg in ("alpha", "bravo", "charlie", "delta", "echo"):
            assert msg in out

    def test_header_prints_title(self, capsys):
        display.header("MY SECTION")
        assert "MY SECTION" in capsys.readouterr().out

    def test_supports_unicode_returns_bool(self):
        assert isinstance(display._supports_unicode(), bool)

    def test_no_color_blanks_codes(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        reloaded = importlib.reload(display)
        try:
            assert reloaded.C.RED == ""
            assert reloaded.C.RESET == ""
        finally:
            monkeypatch.delenv("NO_COLOR", raising=False)
            importlib.reload(display)

    def test_colors_present_without_no_color(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        reloaded = importlib.reload(display)
        assert reloaded.C.RED.startswith("\033[")
