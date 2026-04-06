"""Tests for Sigma condition parser and converter backends."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from converters.base import (
    BaseConverter,
    ConditionAnd,
    ConditionNot,
    ConditionOr,
    ConditionRef,
    parse_condition,
)
from converters.elastic import ElasticConverter
from converters.kibana import KibanaConverter
from converters.splunk import SplunkConverter

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"


# ── Parser Tests ───────────────────────────────


class TestParseCondition:

    def test_simple_identifier(self):
        result = parse_condition("selection")
        assert result == ConditionRef("selection")

    def test_or_two_identifiers(self):
        result = parse_condition("selection_a or selection_b")
        assert result == ConditionOr([
            ConditionRef("selection_a"),
            ConditionRef("selection_b"),
        ])

    def test_or_three_identifiers(self):
        result = parse_condition("selection_pipe or selection_service or selection_process")
        assert result == ConditionOr([
            ConditionRef("selection_pipe"),
            ConditionRef("selection_service"),
            ConditionRef("selection_process"),
        ])

    def test_and_not(self):
        result = parse_condition("selection and not filter_system")
        assert result == ConditionAnd([
            ConditionRef("selection"),
            ConditionNot(ConditionRef("filter_system")),
        ])

    def test_and_multiple_nots(self):
        result = parse_condition(
            "selection and not filter_legitimate and not filter_same_process"
        )
        assert result == ConditionAnd([
            ConditionRef("selection"),
            ConditionNot(ConditionRef("filter_legitimate")),
            ConditionNot(ConditionRef("filter_same_process")),
        ])

    def test_parenthesized_or_then_and_not(self):
        result = parse_condition(
            "(selection_schtasks or selection_powershell) and not filter_system"
        )
        assert result == ConditionAnd([
            ConditionOr([
                ConditionRef("selection_schtasks"),
                ConditionRef("selection_powershell"),
            ]),
            ConditionNot(ConditionRef("filter_system")),
        ])

    def test_parenthesized_triple_or_then_and_not(self):
        result = parse_condition(
            "(selection_sc or selection_powershell or selection_event) "
            "and not filter_legitimate"
        )
        assert result == ConditionAnd([
            ConditionOr([
                ConditionRef("selection_sc"),
                ConditionRef("selection_powershell"),
                ConditionRef("selection_event"),
            ]),
            ConditionNot(ConditionRef("filter_legitimate")),
        ])

    def test_complex_nested_condition(self):
        result = parse_condition(
            "selection_process and "
            "(selection_encoded or selection_download or selection_bypass)"
        )
        assert result == ConditionAnd([
            ConditionRef("selection_process"),
            ConditionOr([
                ConditionRef("selection_encoded"),
                ConditionRef("selection_download"),
                ConditionRef("selection_bypass"),
            ]),
        ])

    def test_operator_precedence_and_binds_tighter(self):
        result = parse_condition("a or b and c")
        assert result == ConditionOr([
            ConditionRef("a"),
            ConditionAnd([
                ConditionRef("b"),
                ConditionRef("c"),
            ]),
        ])

    def test_multiline_condition_stripped(self):
        result = parse_condition(
            "selection_powershell_disable or selection_registry or\n"
            "selection_service_stop or selection_tamper\n"
        )
        assert result == ConditionOr([
            ConditionRef("selection_powershell_disable"),
            ConditionRef("selection_registry"),
            ConditionRef("selection_service_stop"),
            ConditionRef("selection_tamper"),
        ])

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="[Ee]mpty"):
            parse_condition("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="[Ee]mpty"):
            parse_condition("   \n  ")


# ── Field Parsing Tests ────────────────────────


class TestBaseConverterFieldParsing:

    def test_plain_field(self):
        field, mods = BaseConverter.parse_field_name("Image")
        assert field == "Image"
        assert mods == []

    def test_endswith_modifier(self):
        field, mods = BaseConverter.parse_field_name("Image|endswith")
        assert field == "Image"
        assert mods == ["endswith"]

    def test_contains_modifier(self):
        field, mods = BaseConverter.parse_field_name("CommandLine|contains")
        assert field == "CommandLine"
        assert mods == ["contains"]

    def test_startswith_modifier(self):
        field, mods = BaseConverter.parse_field_name("Path|startswith")
        assert field == "Path"
        assert mods == ["startswith"]


# ── Splunk Tests ───────────────────────────────


class TestSplunkConverter:

    def setup_method(self):
        self.conv = SplunkConverter()

    def test_exact_field_match(self):
        result = self.conv.convert_field_match("EventType", [], ["failure"])
        assert result == 'EventType="failure"'

    def test_multi_value_field(self):
        result = self.conv.convert_field_match(
            "Image", ["endswith"], ["\\\\powershell.exe", "\\\\pwsh.exe"]
        )
        assert 'Image="*\\\\powershell.exe"' in result
        assert 'Image="*\\\\pwsh.exe"' in result
        assert " OR " in result

    def test_contains_modifier(self):
        result = self.conv.convert_field_match(
            "CommandLine", ["contains"], ["-enc"]
        )
        assert result == 'CommandLine="*-enc*"'

    def test_keyword_field(self):
        result = self.conv.convert_field_match(
            "_keyword", [], ["Failed password", "authentication failure"]
        )
        assert '"Failed password"' in result
        assert '"authentication failure"' in result

    def test_full_rule_ssh_bruteforce(self):
        rule_path = RULES_DIR / "ssh_bruteforce_burst.yml"
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        result = self.conv.convert_rule(rule)
        assert "EventType" in result or "Failed password" in result
        assert len(result) > 10

    def test_full_rule_powershell(self):
        rule_path = RULES_DIR / "powershell_suspicious_execution.yml"
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        result = self.conv.convert_rule(rule)
        assert "powershell.exe" in result
        assert "EncodedCommand" in result or "-enc" in result

    def test_all_rules_convert(self):
        for rule_path in sorted(RULES_DIR.glob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            result = self.conv.convert_rule(rule)
            assert len(result) > 10, f"Empty output for {rule_path.name}"


# ── Elasticsearch Tests ────────────────────────


class TestElasticConverter:

    def setup_method(self):
        self.conv = ElasticConverter()

    def test_exact_field_match(self):
        result = self.conv.convert_field_match("EventType", [], ["failure"])
        assert result == 'EventType:"failure"'

    def test_contains_modifier(self):
        result = self.conv.convert_field_match(
            "CommandLine", ["contains"], ["-enc"]
        )
        assert result == 'CommandLine:"*-enc*"'

    def test_multi_value_or(self):
        result = self.conv.convert_field_match(
            "Image", ["endswith"], ["\\\\powershell.exe", "\\\\pwsh.exe"]
        )
        assert "OR" in result

    def test_keyword_field(self):
        result = self.conv.convert_field_match(
            "_keyword", [], ["Failed password"]
        )
        assert '"Failed password"' in result

    def test_all_rules_convert(self):
        for rule_path in sorted(RULES_DIR.glob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            result = self.conv.convert_rule(rule)
            assert len(result) > 10, f"Empty output for {rule_path.name}"


# ── Kibana Tests ───────────────────────────────


class TestKibanaConverter:

    def setup_method(self):
        self.conv = KibanaConverter()

    def test_exact_field_match(self):
        result = self.conv.convert_field_match("EventType", [], ["failure"])
        assert result == 'EventType: "failure"'

    def test_contains_modifier(self):
        result = self.conv.convert_field_match(
            "CommandLine", ["contains"], ["-enc"]
        )
        assert result == 'CommandLine: "*-enc*"'

    def test_multi_value_or(self):
        result = self.conv.convert_field_match(
            "Image", ["endswith"], ["\\\\powershell.exe", "\\\\pwsh.exe"]
        )
        assert " or " in result

    def test_negation(self):
        result = self.conv.negate('User: "SYSTEM"')
        assert result == 'not (User: "SYSTEM")'

    def test_all_rules_convert(self):
        for rule_path in sorted(RULES_DIR.glob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            result = self.conv.convert_rule(rule)
            assert len(result) > 10, f"Empty output for {rule_path.name}"


# ── CLI Integration Tests ──────────────────────


class TestCLIConvert:

    def test_convert_splunk_runs(self):
        result = subprocess.run(
            [sys.executable, "siemforge.py", "--convert", "splunk"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        assert result.returncode == 0

    def test_convert_elastic_runs(self):
        result = subprocess.run(
            [sys.executable, "siemforge.py", "--convert", "elastic"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        assert result.returncode == 0

    def test_convert_kibana_runs(self):
        result = subprocess.run(
            [sys.executable, "siemforge.py", "--convert", "kibana"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        assert result.returncode == 0

    def test_convert_invalid_backend_fails(self):
        result = subprocess.run(
            [sys.executable, "siemforge.py", "--convert", "invalid"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        assert result.returncode != 0

    def test_convert_output_creates_files(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "siemforge.py", "--convert", "splunk",
             "--convert-output", str(tmp_path)],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        assert result.returncode == 0
        spl_files = list(tmp_path.glob("*.spl"))
        expected = len(list(RULES_DIR.glob("*.yml")))
        assert len(spl_files) == expected
