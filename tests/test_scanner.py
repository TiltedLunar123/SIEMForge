"""Tests for the log scanner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from siemforge.scanner import (
    parse_log_file, match_rule, scan_logs, _flatten, _match_value,
)
from siemforge.loader import load_sigma_rules

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestParseLogFile:

    def test_parse_json_array(self):
        events = parse_log_file(SAMPLES_DIR / "powershell_attack.json")
        assert len(events) == 4
        assert events[0]["EventID"] == 1

    def test_parse_syslog(self):
        events = parse_log_file(SAMPLES_DIR / "ssh_bruteforce.log", fmt="syslog")
        assert len(events) >= 7
        assert "sshd" in events[0].get("program", "")

    def test_parse_json_explicit_format(self):
        events = parse_log_file(SAMPLES_DIR / "credential_dump.json", fmt="json")
        assert len(events) == 3


class TestFlatten:

    def test_flat_dict(self):
        result = _flatten({"a": "1", "b": "2"})
        assert result == {"a": "1", "b": "2"}

    def test_nested_dict(self):
        result = _flatten({"outer": {"inner": "val"}})
        assert "outer.inner" in result


class TestMatchValue:

    def test_exact_match(self):
        assert _match_value("hello", "hello", [])

    def test_contains(self):
        assert _match_value("hello world", "world", ["contains"])

    def test_endswith(self):
        assert _match_value(
            "C:\\Windows\\powershell.exe", "powershell.exe", ["endswith"]
        )

    def test_startswith(self):
        assert _match_value(
            "C:\\Windows\\System32", "C:\\Windows", ["startswith"]
        )

    def test_case_insensitive(self):
        assert _match_value("PowerShell.EXE", "powershell.exe", [])


class TestMatchRule:

    def setup_method(self):
        self.rules = load_sigma_rules()

    def test_powershell_encoded_triggers(self):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
            "User": "CORP\\test",
        }
        ps_rule = self.rules["powershell_suspicious_execution.yml"]
        assert match_rule(event, ps_rule)

    def test_notepad_does_not_trigger_powershell(self):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe file.txt",
            "User": "CORP\\test",
        }
        ps_rule = self.rules["powershell_suspicious_execution.yml"]
        assert not match_rule(event, ps_rule)

    def test_lsass_access_triggers(self):
        event = {
            "EventID": 10,
            "SourceImage": "C:\\Tools\\mimikatz.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
        }
        rule = self.rules["lsass_credential_dump.yml"]
        assert match_rule(event, rule)

    def test_lsass_from_svchost_filtered(self):
        event = {
            "EventID": 10,
            "SourceImage": "C:\\Windows\\System32\\svchost.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
        }
        rule = self.rules["lsass_credential_dump.yml"]
        assert not match_rule(event, rule)

    def test_defender_tampering_triggers(self):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
        }
        rule = self.rules["defender_tampering.yml"]
        assert match_rule(event, rule)

    def test_registry_persistence_triggers(self):
        event = {
            "EventID": 13,
            "Image": "C:\\Users\\attacker\\malware.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\backdoor.exe",
        }
        rule = self.rules["registry_run_key_persistence.yml"]
        assert match_rule(event, rule)


class TestScanLogs:

    def test_scan_powershell_sample(self, capsys):
        rules = load_sigma_rules()
        count = scan_logs(str(SAMPLES_DIR / "powershell_attack.json"), rules)
        assert count >= 2

    def test_scan_credential_dump(self, capsys):
        rules = load_sigma_rules()
        count = scan_logs(str(SAMPLES_DIR / "credential_dump.json"), rules)
        assert count >= 1

    def test_scan_nonexistent_file(self, capsys):
        rules = load_sigma_rules()
        count = scan_logs("/tmp/nonexistent_file_12345.json", rules)
        assert count == 0

    def test_scan_json_output(self, capsys):
        rules = load_sigma_rules()
        count = scan_logs(str(SAMPLES_DIR / "powershell_attack.json"), rules, output_json=True)
        output = capsys.readouterr().out
        # Extract the JSON array from output (skip banner/header lines)
        json_start = output.find("[")
        assert json_start >= 0, "No JSON array found in output"
        data = json.loads(output[json_start:])
        assert isinstance(data, list)
        assert len(data) >= 2
        assert count >= 2
