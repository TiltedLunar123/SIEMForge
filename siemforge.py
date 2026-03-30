#!/usr/bin/env python3
"""
SIEMForge | SIEM Detection Content Toolkit
Sigma Rules & Wazuh/Sysmon Detection Engineering

Author: Jude Hilgendorf
GitHub: github.com/TiltedLunar123

Manages, exports, validates, and tests Sigma detection rules,
Sysmon configuration, and Wazuh custom rules — loaded from
external YAML/XML files.
"""
from __future__ import annotations

import os
import sys
import json
import argparse
import datetime
import re
from pathlib import Path
from typing import Optional

import yaml

VERSION = "2.1.0"

# ──────────────────────────────────────────────
# PATHS — resolve relative to this script
# ──────────────────────────────────────────────

_SCRIPT_DIR = Path(__file__).resolve().parent
SIGMA_RULES_DIR = _SCRIPT_DIR / "rules" / "sigma"
CONFIGS_DIR = _SCRIPT_DIR / "configs"


# ──────────────────────────────────────────────
# ANSI COLORS
# ──────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


BANNER = rf"""
{C.CYAN}{C.BOLD}
  ____  ___ _____ __  __ _____
 / ___|/ _ \_   _|  \/  |  ___|__  _ __ __ _  ___
 \___ \ | | || | | |\/| | |_ / _ \| '__/ _` |/ _ \
  ___) | |_| || | | |  | |  _| (_) | | | (_| |  __/
 |____/ \___/ |_| |_|  |_|_|  \___/|_|  \__, |\___|
                                         |___/
{C.RESET}
{C.DIM}  SIEM Detection Content Toolkit
  Sigma Rules | Sysmon Config | Wazuh Integration
  Author : Jude Hilgendorf
  GitHub : github.com/TiltedLunar123{C.RESET}
"""

def _supports_unicode() -> bool:
    """Check if the terminal can handle Unicode box-drawing characters."""
    try:
        encoding = sys.stdout.encoding or ""
        if encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32"):
            return True
        "\u2550".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False

_UNICODE = _supports_unicode()
_DIV_CHAR = "\u2550" if _UNICODE else "="
_LINE_CHAR = "\u2500" if _UNICODE else "-"
DIV = f"{C.BLUE}{_DIV_CHAR * 70}{C.RESET}"


def header(title: str):
    print(f"\n{DIV}")
    print(f"  {C.BOLD}{C.CYAN}[ {title} ]{C.RESET}")
    print(DIV)


_OK  = "[\u2713]" if _UNICODE else "[+]"
_ERR = "[\u2717]" if _UNICODE else "[X]"
_BUL = "\u2022"   if _UNICODE else "*"


def ok(msg: str):
    print(f"  {C.GREEN}{_OK}{C.RESET} {msg}")


def info(msg: str):
    print(f"  {C.BLUE}[i]{C.RESET} {msg}")


def warn(msg: str):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str):
    print(f"  {C.RED}{_ERR}{C.RESET} {msg}")


def bullet(msg: str):
    print(f"    {C.DIM}{_BUL}{C.RESET} {msg}")


# ──────────────────────────────────────────────
# RULE LOADING
# ──────────────────────────────────────────────

def load_sigma_rules(rules_dir: Path | None = None) -> dict[str, dict]:
    """Load all Sigma YAML rules from disk and return {filename: parsed_dict}."""
    rules_dir = rules_dir or SIGMA_RULES_DIR
    rules: dict[str, dict] = {}
    if not rules_dir.is_dir():
        return rules
    for filepath in sorted(rules_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                rules[filepath.name] = data
        except (yaml.YAMLError, OSError) as exc:
            err(f"Failed to load {filepath.name}: {exc}")
    return rules


def load_config_file(filename: str, configs_dir: Path | None = None) -> str:
    """Load a config file (XML) from the configs directory."""
    configs_dir = configs_dir or CONFIGS_DIR
    filepath = configs_dir / filename
    return filepath.read_text(encoding="utf-8")


# ──────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ──────────────────────────────────────────────

MITRE_MAP = {
    "T1110.001": {"name": "Brute Force: Password Guessing",     "tactic": "Credential Access"},
    "T1059.001": {"name": "PowerShell",                         "tactic": "Execution"},
    "T1027.010": {"name": "Command Obfuscation",                "tactic": "Defense Evasion"},
    "T1136.001": {"name": "Create Account: Local Account",      "tactic": "Persistence"},
    "T1098":     {"name": "Account Manipulation",               "tactic": "Persistence"},
    "T1055.003": {"name": "Process Injection: Thread Injection", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS",       "tactic": "Credential Access"},
    "T1562.001": {"name": "Impair Defenses: Disable Tools",     "tactic": "Defense Evasion"},
    "T1021.002": {"name": "SMB/Windows Admin Shares",           "tactic": "Lateral Movement"},
    "T1547.001": {"name": "Boot/Logon Autostart: Registry",     "tactic": "Persistence"},
    "T1070.001": {"name": "Indicator Removal: Clear Logs",      "tactic": "Defense Evasion"},
    "T1105":     {"name": "Ingress Tool Transfer",              "tactic": "Command and Control"},
    "T1569.002": {"name": "Service Execution",                  "tactic": "Execution"},
    "T1570":     {"name": "Lateral Tool Transfer",              "tactic": "Lateral Movement"},
    "T1053.005": {"name": "Scheduled Task",                     "tactic": "Persistence"},
    "T1543.003": {"name": "Create/Modify System Service",       "tactic": "Persistence"},
}


# ──────────────────────────────────────────────
# VALIDATION (proper YAML parsing)
# ──────────────────────────────────────────────

REQUIRED_SIGMA_FIELDS = [
    "title", "id", "status", "description", "author",
    "date", "logsource", "detection", "level",
]

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)


def validate_sigma_rule(filename: str, rule: dict) -> tuple[list[str], list[str]]:
    """Validate a single parsed Sigma rule. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    # Check required fields
    for field in REQUIRED_SIGMA_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    # Validate UUID
    rule_id = rule.get("id", "")
    if rule_id and not UUID_PATTERN.match(str(rule_id)):
        errors.append(f"ID is not valid UUID format: {rule_id}")

    # Validate level
    level = rule.get("level", "")
    if level and level not in VALID_LEVELS:
        errors.append(f"Invalid level: {level}")

    # Validate logsource structure
    logsource = rule.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append("logsource must be a mapping")

    # Validate detection structure
    detection = rule.get("detection")
    if detection is not None:
        if not isinstance(detection, dict):
            errors.append("detection must be a mapping")
        elif "condition" not in detection:
            errors.append("detection is missing 'condition' field")

    # Check for MITRE tags
    tags = rule.get("tags", [])
    if not any(str(t).startswith("attack.t") for t in (tags or [])):
        warnings.append("No MITRE ATT&CK technique tag found")

    # Check falsepositives
    if "falsepositives" not in rule:
        warnings.append("No falsepositives section (recommended)")

    return errors, warnings


def validate_rules(rules: dict[str, dict] | None = None):
    """Validate all Sigma rules for required fields and structure."""
    header("VALIDATING SIGMA RULES")

    if rules is None:
        rules = load_sigma_rules()

    total   = len(rules)
    passed  = 0
    failed  = 0
    warnings_count = 0

    for filename, rule in rules.items():
        errors, warns = validate_sigma_rule(filename, rule)

        if errors:
            err(f"{filename}")
            for issue in errors:
                bullet(f"{C.RED}{issue}{C.RESET}")
            failed += 1
        else:
            ok(f"{filename}")
            passed += 1

        for w in warns:
            bullet(f"{C.YELLOW}{w}{C.RESET}")
            warnings_count += 1

    print(f"\n  {C.BOLD}Results:{C.RESET} {C.GREEN}{passed} passed{C.RESET}  "
          f"{C.RED}{failed} failed{C.RESET}  "
          f"{C.YELLOW}{warnings_count} warnings{C.RESET}  "
          f"/ {total} total")

    return passed, failed, warnings_count


# ──────────────────────────────────────────────
# CORE FUNCTIONS
# ──────────────────────────────────────────────

def _collect_techniques(rules: dict[str, dict]) -> tuple[set[str], set[str]]:
    """Extract MITRE technique IDs and tactic names from loaded rules."""
    techniques: set[str] = set()
    tactics: set[str] = set()
    for rule in rules.values():
        for tag in rule.get("tags", []):
            tag_str = str(tag)
            if tag_str.startswith("attack.t"):
                tid = tag_str.replace("attack.", "").upper()
                techniques.add(tid)
                if tid in MITRE_MAP:
                    tactics.add(MITRE_MAP[tid]["tactic"])
            elif tag_str.startswith("attack."):
                tactic = tag_str.replace("attack.", "").replace("_", " ").title()
                tactics.add(tactic)
    return techniques, tactics


def _count_levels(rules: dict[str, dict]) -> dict[str, int]:
    """Count severity levels across rules."""
    levels: dict[str, int] = {}
    for rule in rules.values():
        lvl = rule.get("level", "unknown")
        levels[lvl] = levels.get(lvl, 0) + 1
    return levels


def export_sigma_rules(rules: dict[str, dict], output_dir: str = "sigma_rules",
                       dry_run: bool = False):
    """Export all Sigma rules to individual YAML files."""
    header("EXPORTING SIGMA RULES")

    if dry_run:
        for filename in rules:
            info(f"Would write {output_dir}/{filename}")
        info(f"Dry run: {len(rules)} Sigma rules would be exported to ./{output_dir}/")
        return Path(output_dir)

    path = Path(output_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create directory {output_dir}: {e}")
        return None

    for filename, rule in rules.items():
        filepath = path / filename
        try:
            filepath.write_text(yaml.dump(rule, default_flow_style=False, sort_keys=False,
                                          allow_unicode=True), encoding="utf-8")
            ok(f"Wrote {filepath}")
        except OSError as e:
            err(f"Failed to write {filepath}: {e}")

    info(f"Exported {len(rules)} Sigma rules to ./{output_dir}/")
    return path


def export_sysmon_config(output_dir: str = "sysmon", dry_run: bool = False):
    """Export the Sysmon configuration XML."""
    header("EXPORTING SYSMON CONFIGURATION")

    if dry_run:
        info(f"Would write {output_dir}/sysmon_config.xml")
        return Path(output_dir) / "sysmon_config.xml"

    path = Path(output_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create directory {output_dir}: {e}")
        return None

    content = load_config_file("sysmon_config.xml")
    filepath = path / "sysmon_config.xml"
    try:
        filepath.write_text(content, encoding="utf-8")
        ok(f"Wrote {filepath}")
    except OSError as e:
        err(f"Failed to write {filepath}: {e}")
        return None

    info("Install command:")
    bullet("sysmon64.exe -accepteula -i sysmon_config.xml")
    info("Update command:")
    bullet("sysmon64.exe -c sysmon_config.xml")
    return filepath


def export_wazuh_rules(output_dir: str = "wazuh", dry_run: bool = False):
    """Export Wazuh custom rules and agent config snippet."""
    header("EXPORTING WAZUH RULES & CONFIG")

    if dry_run:
        info(f"Would write {output_dir}/local_rules.xml")
        info(f"Would write {output_dir}/agent_ossec_snippet.xml")
        return Path(output_dir)

    path = Path(output_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create directory {output_dir}: {e}")
        return None

    files = [
        ("local_rules.xml", "wazuh_local_rules.xml"),
        ("agent_ossec_snippet.xml", "wazuh_agent_snippet.xml"),
    ]
    for out_name, src_name in files:
        fpath = path / out_name
        try:
            content = load_config_file(src_name)
            fpath.write_text(content, encoding="utf-8")
            ok(f"Wrote {fpath}")
        except OSError as e:
            err(f"Failed to write {fpath}: {e}")

    info("Deploy rules to: /var/ossec/etc/rules/local_rules.xml")
    info("Restart manager: systemctl restart wazuh-manager")
    return path


def export_all(rules: dict[str, dict], output_dir: str = "siemforge_export",
               dry_run: bool = False):
    """Export everything — Sigma rules, Sysmon config, Wazuh rules."""
    header("FULL EXPORT \u2014 ALL DETECTION CONTENT")

    base = Path(output_dir)

    if dry_run:
        info(f"Dry run \u2014 previewing export to ./{base}/")
        for filename in rules:
            info(f"  Would write sigma_rules/{filename}")
        info("  Would write sysmon/sysmon_config.xml")
        info("  Would write wazuh/local_rules.xml")
        info("  Would write wazuh/agent_ossec_snippet.xml")
        info("  Would write manifest.json")
        info(f"Total: {len(rules)} Sigma rules, 1 Sysmon config, 2 Wazuh files")
        return

    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create export directory {base}: {e}")
        return

    # Sigma
    sigma_dir = base / "sigma_rules"
    sigma_dir.mkdir(exist_ok=True)
    for filename, rule in rules.items():
        try:
            (sigma_dir / filename).write_text(
                yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            ok(f"sigma_rules/{filename}")
        except OSError as e:
            err(f"Failed to write sigma_rules/{filename}: {e}")

    # Sysmon
    sysmon_dir = base / "sysmon"
    sysmon_dir.mkdir(exist_ok=True)
    try:
        content = load_config_file("sysmon_config.xml")
        (sysmon_dir / "sysmon_config.xml").write_text(content, encoding="utf-8")
        ok("sysmon/sysmon_config.xml")
    except OSError as e:
        err(f"Failed to write sysmon/sysmon_config.xml: {e}")

    # Wazuh
    wazuh_dir = base / "wazuh"
    wazuh_dir.mkdir(exist_ok=True)
    wazuh_files = [
        ("local_rules.xml", "wazuh_local_rules.xml"),
        ("agent_ossec_snippet.xml", "wazuh_agent_snippet.xml"),
    ]
    for out_name, src_name in wazuh_files:
        try:
            content = load_config_file(src_name)
            (wazuh_dir / out_name).write_text(content, encoding="utf-8")
            ok(f"wazuh/{out_name}")
        except OSError as e:
            err(f"Failed to write wazuh/{out_name}: {e}")

    # Manifest
    techniques, _ = _collect_techniques(rules)
    manifest = {
        "tool": "SIEMForge",
        "version": VERSION,
        "author": "Jude Hilgendorf",
        "exported": datetime.datetime.now().isoformat(),
        "sigma_rules": list(rules.keys()),
        "sigma_count": len(rules),
        "sysmon_config": "sysmon/sysmon_config.xml",
        "wazuh_rules": "wazuh/local_rules.xml",
        "wazuh_agent": "wazuh/agent_ossec_snippet.xml",
        "mitre_techniques": sorted(techniques),
    }
    manifest_path = base / "manifest.json"
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        ok("manifest.json")
    except OSError as e:
        err(f"Failed to write manifest.json: {e}")

    print(f"\n  {C.BOLD}Export complete \u2192 ./{base}/{C.RESET}")

    # Print tree
    print(f"\n  {C.DIM}Directory structure:{C.RESET}")
    print(f"  {base}/")
    print(f"  \u251c\u2500\u2500 manifest.json")
    print(f"  \u251c\u2500\u2500 sigma_rules/")
    for f in sorted(rules.keys()):
        print(f"  \u2502   \u251c\u2500\u2500 {f}")
    print(f"  \u251c\u2500\u2500 sysmon/")
    print(f"  \u2502   \u2514\u2500\u2500 sysmon_config.xml")
    print(f"  \u2514\u2500\u2500 wazuh/")
    print(f"      \u251c\u2500\u2500 local_rules.xml")
    print(f"      \u2514\u2500\u2500 agent_ossec_snippet.xml")


def show_mitre_coverage(rules: dict[str, dict]):
    """Display MITRE ATT&CK coverage matrix."""
    header("MITRE ATT&CK COVERAGE")

    covered, _ = _collect_techniques(rules)

    # Group by tactic
    tactics: dict[str, list[tuple[str, str]]] = {}
    for tid in sorted(covered):
        if tid in MITRE_MAP:
            tactic = MITRE_MAP[tid]["tactic"]
            name   = MITRE_MAP[tid]["name"]
        else:
            tactic = "Unknown"
            name   = tid
        tactics.setdefault(tactic, []).append((tid, name))

    for tactic in sorted(tactics.keys()):
        print(f"\n  {C.BOLD}{C.MAGENTA}{tactic}{C.RESET}")
        print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")
        for tid, name in tactics[tactic]:
            print(f"    {C.CYAN}{tid:<12}{C.RESET} {name}")

    print(f"\n  {C.BOLD}Total Techniques Covered:{C.RESET} {C.GREEN}{len(covered)}{C.RESET}")
    print(f"  {C.BOLD}Total Detection Rules:{C.RESET}    {C.GREEN}{len(rules)}{C.RESET}")


def show_rule_summary(rules: dict[str, dict]):
    """Display summary table of all detection rules."""
    header("DETECTION RULE INVENTORY")

    print(f"\n  {'#':<4} {'Filename':<42} {'Level':<12} {'Tactic'}")
    print(f"  {_LINE_CHAR*4} {_LINE_CHAR*42} {_LINE_CHAR*12} {_LINE_CHAR*25}")

    for i, (filename, rule) in enumerate(rules.items(), 1):
        level = rule.get("level", "?")

        # Extract first tactic tag
        tactic = ""
        for tag in rule.get("tags", []):
            tag_str = str(tag)
            if tag_str.startswith("attack.") and not tag_str.startswith("attack.t"):
                tactic = tag_str.replace("attack.", "").replace("_", " ").title()
                break

        level_colors = {
            "critical": C.RED, "high": C.YELLOW,
            "medium": C.CYAN, "low": C.GREEN,
            "informational": C.DIM,
        }
        lc = level_colors.get(level, C.WHITE)

        print(f"  {i:<4} {filename:<42} {lc}{level:<12}{C.RESET} {tactic}")

    print(f"\n  {C.BOLD}Total Rules:{C.RESET} {len(rules)}")


def generate_test_commands():
    """Generate safe test commands to trigger each detection rule."""
    header("TEST COMMANDS (Safe Trigger Simulation)")

    warn("These commands simulate attack patterns for testing.")
    warn("Run ONLY in isolated lab environments.\n")

    tests = [
        {
            "rule": "SSH Brute-Force Burst",
            "description": "Simulate failed SSH logins (Linux)",
            "commands": [
                "# Generate 10 rapid failed SSH attempts",
                "for i in $(seq 1 10); do",
                "  ssh -o ConnectTimeout=1 fakeuser@localhost 2>/dev/null",
                "done",
            ],
        },
        {
            "rule": "Suspicious PowerShell Execution",
            "description": "Trigger encoded command detection (Windows)",
            "commands": [
                '# Encoded "whoami" \u2014 harmless but triggers detection',
                'powershell -EncodedCommand dwBoAG8AYQBtAGkA',
                "",
                "# Download cradle pattern (will fail but triggers rule)",
                'powershell -NoProfile -ExecutionPolicy Bypass -Command '
                '"(New-Object Net.WebClient).DownloadString(\'http://127.0.0.1/test\')"',
            ],
        },
        {
            "rule": "Local Admin Creation",
            "description": "Create and remove test user (Windows, run as admin)",
            "commands": [
                "# Create test user",
                "net user SIEMForgeTest P@ssw0rd123! /add",
                "net localgroup Administrators SIEMForgeTest /add",
                "",
                "# Cleanup immediately",
                "net user SIEMForgeTest /delete",
            ],
        },
        {
            "rule": "LSASS Access (Credential Dump Simulation)",
            "description": "Use ProcDump to trigger Sysmon Event 10 (Windows)",
            "commands": [
                "# Requires Sysinternals ProcDump \u2014 triggers LSASS access alert",
                "procdump64.exe -accepteula -ma lsass.exe lsass_dump.dmp",
                "",
                "# Cleanup",
                "del lsass_dump.dmp",
            ],
        },
        {
            "rule": "Defender Tampering",
            "description": "Attempt to disable real-time protection (Windows, admin)",
            "commands": [
                "# This will trigger the detection rule",
                "# (Tamper protection may block the actual change)",
                "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
                "",
                "# Re-enable immediately",
                "powershell Set-MpPreference -DisableRealtimeMonitoring $false",
            ],
        },
        {
            "rule": "Registry Run Key Persistence",
            "description": "Add and remove test registry persistence (Windows)",
            "commands": [
                '# Add test Run key',
                'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v SIEMForgeTest /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f',
                "",
                "# Cleanup",
                'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v SIEMForgeTest /f',
            ],
        },
    ]

    for t in tests:
        print(f"\n  {C.BOLD}{C.MAGENTA}\u25b8 {t['rule']}{C.RESET}")
        print(f"  {C.DIM}{t['description']}{C.RESET}")
        print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")
        for cmd in t["commands"]:
            if cmd == "":
                print()
            elif cmd.startswith("#"):
                print(f"    {C.DIM}{cmd}{C.RESET}")
            else:
                print(f"    {C.GREEN}${C.RESET} {cmd}")


def show_stats(rules: dict[str, dict]):
    """Show project statistics."""
    header("PROJECT STATISTICS")

    techniques, tactics = _collect_techniques(rules)
    levels = _count_levels(rules)
    wazuh_content = load_config_file("wazuh_local_rules.xml")
    wazuh_count = wazuh_content.count('<rule id="')

    label_w = 30
    print()
    print(f"  {C.WHITE}{'Sigma Detection Rules':<{label_w}}{C.RESET}: {C.GREEN}{len(rules)}{C.RESET}")
    print(f"  {C.WHITE}{'Wazuh Custom Rules':<{label_w}}{C.RESET}: {C.GREEN}{wazuh_count}{C.RESET}")
    print(f"  {C.WHITE}{'Sysmon Event Types Covered':<{label_w}}{C.RESET}: {C.GREEN}9{C.RESET}")
    print(f"  {C.WHITE}{'MITRE Techniques':<{label_w}}{C.RESET}: {C.GREEN}{len(techniques)}{C.RESET}")
    print(f"  {C.WHITE}{'MITRE Tactics':<{label_w}}{C.RESET}: {C.GREEN}{len(tactics)}{C.RESET}")
    print()

    print(f"  {C.BOLD}Severity Breakdown:{C.RESET}")
    level_order = ["critical", "high", "medium", "low", "informational"]
    level_colors = {
        "critical": C.RED, "high": C.YELLOW,
        "medium": C.CYAN, "low": C.GREEN,
        "informational": C.DIM,
    }
    for lvl in level_order:
        count = levels.get(lvl, 0)
        if count:
            lc = level_colors.get(lvl, C.WHITE)
            bar = ("\u2588" if _UNICODE else "#") * count
            print(f"    {lc}{lvl:<16}{C.RESET} {bar} {count}")


def show_stats_json(rules: dict[str, dict]):
    """Output project statistics as JSON for automation and CI pipelines."""
    techniques, tactics = _collect_techniques(rules)
    levels = _count_levels(rules)
    wazuh_content = load_config_file("wazuh_local_rules.xml")
    wazuh_count = wazuh_content.count('<rule id="')

    stats = {
        "version": VERSION,
        "sigma_rules": len(rules),
        "wazuh_rules": wazuh_count,
        "sysmon_event_types": 9,
        "mitre_techniques": sorted(techniques),
        "mitre_technique_count": len(techniques),
        "mitre_tactics": sorted(tactics),
        "mitre_tactic_count": len(tactics),
        "severity_breakdown": levels,
        "rule_files": list(rules.keys()),
    }
    print(json.dumps(stats, indent=2))


# ──────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siemforge",
        description="SIEMForge \u2014 SIEM Detection Content Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python siemforge.py --export-all          Export everything\n"
            "  python siemforge.py --sigma               Export Sigma rules only\n"
            "  python siemforge.py --validate             Validate all rules\n"
            "  python siemforge.py --mitre               Show MITRE coverage\n"
            "  python siemforge.py --tests               Show test commands\n"
            "  python siemforge.py --stats               Show project stats\n"
            "  python siemforge.py --list                List all rules\n"
            "  python siemforge.py --convert splunk      Convert to Splunk SPL\n"
        ),
    )

    parser.add_argument("--version", "-V", action="version",
                        version=f"SIEMForge v{VERSION}")
    parser.add_argument("--export-all", action="store_true",
                        help="Export all detection content (Sigma + Sysmon + Wazuh)")
    parser.add_argument("--sigma", action="store_true",
                        help="Export Sigma rules to ./sigma_rules/")
    parser.add_argument("--sysmon", action="store_true",
                        help="Export Sysmon configuration to ./sysmon/")
    parser.add_argument("--wazuh", action="store_true",
                        help="Export Wazuh rules and agent config to ./wazuh/")
    parser.add_argument("--validate", action="store_true",
                        help="Validate all Sigma rules for required fields")
    parser.add_argument("--mitre", action="store_true",
                        help="Display MITRE ATT&CK coverage matrix")
    parser.add_argument("--tests", action="store_true",
                        help="Show safe test commands to trigger detections")
    parser.add_argument("--stats", action="store_true",
                        help="Show project statistics")
    parser.add_argument("--list", action="store_true",
                        help="List all detection rules with metadata")
    parser.add_argument("--output-dir", "-o", type=str, default=None,
                        help="Custom output directory for exports")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be exported without writing files")
    parser.add_argument("--json", action="store_true",
                        help="Output statistics in JSON format (machine-readable)")
    parser.add_argument("--convert", type=str, default=None,
                        choices=["splunk", "elastic", "kibana"],
                        help="Convert Sigma rules to SIEM query language")
    parser.add_argument("--convert-output", type=str, default=None,
                        help="Write converted queries to directory (one file per rule)")
    parser.add_argument("--convert-rule", type=str, default=None,
                        help="Convert a single rule by filename")

    return parser


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

CONVERT_EXTENSIONS = {"splunk": ".spl", "elastic": ".lucene", "kibana": ".kql"}


def convert_rules(rules, backend_name, output_dir=None, single_rule=None, dry_run=False):
    """Convert Sigma rules to SIEM queries using the specified backend."""
    from converters import BACKENDS

    backend_cls = BACKENDS[backend_name]
    converter = backend_cls()
    ext = CONVERT_EXTENSIONS[backend_name]

    if single_rule:
        if single_rule not in rules:
            err(f"Rule not found: {single_rule}")
            info("Available rules: " + ", ".join(sorted(rules.keys())))
            return
        rules = {single_rule: rules[single_rule]}

    header("CONVERTING SIGMA RULES \u2192 " + backend_name.upper())

    if output_dir:
        out_path = Path(output_dir)
        if dry_run:
            for filename in rules:
                stem = filename.rsplit(".", 1)[0]
                info(f"Would write {out_path / (stem + ext)}")
            return

        try:
            out_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            err(f"Cannot create directory {output_dir}: {e}")
            return

        for filename, rule in rules.items():
            stem = filename.rsplit(".", 1)[0]
            query = converter.convert_rule(rule)
            filepath = out_path / (stem + ext)
            try:
                filepath.write_text(query + "\n", encoding="utf-8")
                ok(f"Wrote {filepath}")
            except OSError as e:
                err(f"Failed to write {filepath}: {e}")

        info(f"Exported {len(rules)} queries to ./{out_path}/")
    else:
        for filename, rule in rules.items():
            title = rule.get("title", filename)
            level = rule.get("level", "?")

            technique = ""
            for tag in rule.get("tags", []):
                tag_str = str(tag)
                if tag_str.startswith("attack.t"):
                    technique = tag_str.replace("attack.", "").upper()
                    break

            print(f"\n  {C.BOLD}{C.MAGENTA}\u25b8 {title}{C.RESET} ({filename})")
            meta = f"Level: {level}"
            if technique:
                meta += f" | Technique: {technique}"
            print(f"    {C.DIM}{meta}{C.RESET}")
            print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")

            if dry_run:
                info("(dry run \u2014 query not generated)")
            else:
                query = converter.convert_rule(rule)
                for line in query.split("\n"):
                    print(f"    {C.GREEN}{line}{C.RESET}")

    print(f"\n  {C.BOLD}Backend:{C.RESET} {backend_name}")
    print(f"  {C.BOLD}Rules converted:{C.RESET} {len(rules)}")


def main():
    # Enable ANSI on Windows
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            pass

    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    # Load rules once
    rules = load_sigma_rules()

    ran_something = False
    dry_run = args.dry_run

    if args.export_all:
        export_all(rules, output_dir=args.output_dir or "siemforge_export", dry_run=dry_run)
        ran_something = True

    if args.sigma:
        export_sigma_rules(rules, output_dir=args.output_dir or "sigma_rules", dry_run=dry_run)
        ran_something = True

    if args.sysmon:
        export_sysmon_config(output_dir=args.output_dir or "sysmon", dry_run=dry_run)
        ran_something = True

    if args.wazuh:
        export_wazuh_rules(output_dir=args.output_dir or "wazuh", dry_run=dry_run)
        ran_something = True

    if args.validate:
        validate_rules(rules)
        ran_something = True

    if args.mitre:
        show_mitre_coverage(rules)
        ran_something = True

    if args.tests:
        generate_test_commands()
        ran_something = True

    if args.stats:
        if args.json:
            show_stats_json(rules)
        else:
            show_stats(rules)
        ran_something = True

    if args.list:
        show_rule_summary(rules)
        ran_something = True

    if args.convert:
        convert_rules(
            rules,
            backend_name=args.convert,
            output_dir=args.convert_output,
            single_rule=args.convert_rule,
            dry_run=dry_run,
        )
        ran_something = True

    if not ran_something:
        show_stats(rules)
        show_rule_summary(rules)
        print(f"\n  {C.DIM}Run with --help for all options or --export-all to export everything.{C.RESET}")

    print(f"\n{DIV}")
    print(f"  {C.CYAN}SIEMForge \u2014 Detection engineering made portable.{C.RESET}")
    print(f"{DIV}\n")


if __name__ == "__main__":
    main()
