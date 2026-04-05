"""Project statistics display."""
from __future__ import annotations

import json

from siemforge._version import VERSION
from siemforge.display import C, _UNICODE, header
from siemforge.loader import load_config_file
from siemforge.mitre import collect_techniques


def count_levels(rules: dict[str, dict]) -> dict[str, int]:
    """Count severity levels across rules."""
    levels: dict[str, int] = {}
    for rule in rules.values():
        lvl = rule.get("level", "unknown")
        levels[lvl] = levels.get(lvl, 0) + 1
    return levels


def show_stats(rules: dict[str, dict]) -> None:
    """Show project statistics."""
    header("PROJECT STATISTICS")

    techniques, tactics = collect_techniques(rules)
    levels = count_levels(rules)
    wazuh_content = load_config_file("wazuh_local_rules.xml")
    wazuh_count = wazuh_content.count('<rule id="')

    label_w = 30
    print()
    print(f"  {C.WHITE}{'Sigma Detection Rules':<{label_w}}{C.RESET}: "
          f"{C.GREEN}{len(rules)}{C.RESET}")
    print(f"  {C.WHITE}{'Wazuh Custom Rules':<{label_w}}{C.RESET}: "
          f"{C.GREEN}{wazuh_count}{C.RESET}")
    print(f"  {C.WHITE}{'MITRE Techniques':<{label_w}}{C.RESET}: "
          f"{C.GREEN}{len(techniques)}{C.RESET}")
    print(f"  {C.WHITE}{'MITRE Tactics':<{label_w}}{C.RESET}: "
          f"{C.GREEN}{len(tactics)}{C.RESET}")
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


def show_stats_json(rules: dict[str, dict]) -> None:
    """Output project statistics as JSON for automation and CI pipelines."""
    techniques, tactics = collect_techniques(rules)
    levels = count_levels(rules)
    wazuh_content = load_config_file("wazuh_local_rules.xml")
    wazuh_count = wazuh_content.count('<rule id="')

    stats = {
        "version": VERSION,
        "sigma_rules": len(rules),
        "wazuh_rules": wazuh_count,
        "mitre_techniques": sorted(techniques),
        "mitre_technique_count": len(techniques),
        "mitre_tactics": sorted(tactics),
        "mitre_tactic_count": len(tactics),
        "severity_breakdown": levels,
        "rule_files": list(rules.keys()),
    }
    print(json.dumps(stats, indent=2))


def show_rule_summary(rules: dict[str, dict]) -> None:
    """Display summary table of all detection rules."""
    from siemforge.display import _LINE_CHAR
    header("DETECTION RULE INVENTORY")

    print(f"\n  {'#':<4} {'Filename':<42} {'Level':<12} {'Tactic'}")
    print(f"  {_LINE_CHAR*4} {_LINE_CHAR*42} {_LINE_CHAR*12} {_LINE_CHAR*25}")

    for i, (filename, rule) in enumerate(rules.items(), 1):
        level = rule.get("level", "?")

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
