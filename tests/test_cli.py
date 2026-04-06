"""CLI integration tests for SIEMForge."""
from __future__ import annotations

import json
import os
import subprocess
import sys

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")
ENV = {**os.environ, "PYTHONUTF8": "1"}


def _run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "siemforge", *args],
        capture_output=True, timeout=30, env=ENV,
        encoding="utf-8", errors="replace",
        **kwargs,
    )


class TestCLIBasic:
    """Verify every top-level flag runs without error."""

    def test_version(self):
        result = _run("--version")
        assert result.returncode == 0
        assert "SIEMForge" in result.stdout

    def test_help(self):
        result = _run("--help")
        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()

    def test_validate(self):
        result = _run("--validate")
        assert result.returncode == 0

    def test_mitre(self):
        result = _run("--mitre")
        assert result.returncode == 0

    def test_stats(self):
        result = _run("--stats")
        assert result.returncode == 0

    def test_stats_json(self):
        result = _run("--stats", "--json")
        assert result.returncode == 0
        # JSON is embedded in banner output; find the opening brace
        out = result.stdout
        start = out.find("{")
        assert start >= 0, "No JSON object in output"
        data = json.loads(out[start:out.rfind("}") + 1])
        assert "sigma_rules" in data
        assert "severity_breakdown" in data

    def test_list(self):
        result = _run("--list")
        assert result.returncode == 0

    def test_tests(self):
        result = _run("--tests")
        assert result.returncode == 0

    def test_default_no_args(self):
        result = _run()
        assert result.returncode == 0


class TestCLIConvert:
    """Test all three converter backends via the CLI."""

    def test_convert_elastic(self):
        result = _run("--convert", "elastic")
        assert result.returncode == 0

    def test_convert_kibana(self):
        result = _run("--convert", "kibana")
        assert result.returncode == 0

    def test_convert_splunk(self):
        result = _run("--convert", "splunk")
        assert result.returncode == 0

    def test_convert_invalid_backend(self):
        result = _run("--convert", "invalid")
        assert result.returncode != 0


class TestCLIScan:
    """Test log scanning via CLI."""

    def test_scan_json_sample(self):
        path = os.path.join(SAMPLES_DIR, "powershell_attack.json")
        result = _run("--scan", path)
        assert result.returncode == 0

    def test_scan_syslog_sample(self):
        path = os.path.join(SAMPLES_DIR, "ssh_bruteforce.log")
        result = _run("--scan", path)
        assert result.returncode == 0

    def test_scan_missing_file(self):
        result = _run("--scan", "nonexistent_file.json")
        assert result.returncode == 0  # prints error but does not crash

    def test_scan_json_output(self):
        path = os.path.join(SAMPLES_DIR, "powershell_attack.json")
        result = _run("--scan", path, "--json")
        assert result.returncode == 0
        # JSON array is embedded in banner output; extract it
        out = result.stdout
        # Find the actual JSON array by looking for "[\n  {"
        start = out.find("[\n")
        if start < 0:
            start = out.find("[{")
        if start < 0:
            start = out.find("[")
        assert start >= 0, "No JSON array in output"
        end = out.rfind("]")
        assert end >= start, "No closing bracket"
        data = json.loads(out[start:end + 1])
        assert isinstance(data, list)


class TestCLIExport:
    """Test export flags."""

    def test_export_all_dry_run(self, tmp_path):
        result = _run("--export-all", "--dry-run", "--output-dir", str(tmp_path))
        assert result.returncode == 0
        # dry-run should not create rule files
        assert not list(tmp_path.glob("**/*.yml"))

    def test_sigma_export(self, tmp_path):
        result = _run("--sigma", "--output-dir", str(tmp_path))
        assert result.returncode == 0
        assert list(tmp_path.glob("*.yml"))

    def test_convert_output_dir(self, tmp_path):
        result = _run("--convert", "splunk", "--convert-output", str(tmp_path))
        assert result.returncode == 0
        assert list(tmp_path.glob("*.spl"))
