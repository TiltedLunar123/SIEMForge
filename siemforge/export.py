"""Export Sigma rules, Sysmon config, and Wazuh rules."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import yaml

from siemforge._version import VERSION
from siemforge.display import C, ok, err, info, header
from siemforge.loader import load_config_file
from siemforge.mitre import collect_techniques


def export_sigma_rules(rules: dict[str, dict], output_dir: str = "sigma_rules",
                       dry_run: bool = False) -> Path | None:
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
            filepath.write_text(
                yaml.dump(rule, default_flow_style=False, sort_keys=False,
                          allow_unicode=True),
                encoding="utf-8",
            )
            ok(f"Wrote {filepath}")
        except OSError as e:
            err(f"Failed to write {filepath}: {e}")

    info(f"Exported {len(rules)} Sigma rules to ./{output_dir}/")
    return path


def export_sysmon_config(output_dir: str = "sysmon",
                         dry_run: bool = False) -> Path | None:
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

    from siemforge.display import bullet
    info("Install command:")
    bullet("sysmon64.exe -accepteula -i sysmon_config.xml")
    info("Update command:")
    bullet("sysmon64.exe -c sysmon_config.xml")
    return filepath


def export_wazuh_rules(output_dir: str = "wazuh",
                       dry_run: bool = False) -> Path | None:
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
               dry_run: bool = False) -> None:
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
                yaml.dump(rule, default_flow_style=False, sort_keys=False,
                          allow_unicode=True),
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
    techniques, _ = collect_techniques(rules)
    manifest = {
        "tool": "SIEMForge",
        "version": VERSION,
        "author": "Jude Hilgendorf",
        "exported": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
