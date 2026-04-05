"""MITRE ATT&CK mapping and coverage display."""
from __future__ import annotations

from siemforge.display import C, _LINE_CHAR, header

MITRE_MAP: dict[str, dict[str, str]] = {
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1027.010": {"name": "Command Obfuscation", "tactic": "Defense Evasion"},
    "T1136.001": {"name": "Create Account: Local Account", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1055.003": {"name": "Process Injection: Thread Injection", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS", "tactic": "Credential Access"},
    "T1562.001": {"name": "Impair Defenses: Disable Tools", "tactic": "Defense Evasion"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1547.001": {"name": "Boot/Logon Autostart: Registry", "tactic": "Persistence"},
    "T1070.001": {"name": "Indicator Removal: Clear Logs", "tactic": "Defense Evasion"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1569.002": {"name": "Service Execution", "tactic": "Execution"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1543.003": {"name": "Create/Modify System Service", "tactic": "Persistence"},
}


def collect_techniques(rules: dict[str, dict]) -> tuple[set[str], set[str]]:
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


def show_mitre_coverage(rules: dict[str, dict]) -> None:
    """Display MITRE ATT&CK coverage matrix."""
    header("MITRE ATT&CK COVERAGE")

    covered, _ = collect_techniques(rules)

    tactics: dict[str, list[tuple[str, str]]] = {}
    for tid in sorted(covered):
        if tid in MITRE_MAP:
            tactic = MITRE_MAP[tid]["tactic"]
            name = MITRE_MAP[tid]["name"]
        else:
            tactic = "Unknown"
            name = tid
        tactics.setdefault(tactic, []).append((tid, name))

    for tactic in sorted(tactics.keys()):
        print(f"\n  {C.BOLD}{C.MAGENTA}{tactic}{C.RESET}")
        print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")
        for tid, name in tactics[tactic]:
            print(f"    {C.CYAN}{tid:<12}{C.RESET} {name}")

    print(f"\n  {C.BOLD}Total Techniques Covered:{C.RESET} {C.GREEN}{len(covered)}{C.RESET}")
    print(f"  {C.BOLD}Total Detection Rules:{C.RESET}    {C.GREEN}{len(rules)}{C.RESET}")
