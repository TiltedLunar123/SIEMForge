"""MITRE ATT&CK mapping and coverage display.

MITRE_MAP is the lookup used to turn an attack.tXXXX tag into a human name
and tactic. Every technique referenced by a bundled Sigma rule has to live
here, otherwise it renders as "Unknown" in the coverage view. A test in
tests/test_modules.py enforces that for the shipped rule set, so a new rule
that adds a technique will fail CI until the technique is added below.

Each entry stores a primary tactic in ``tactic``. A technique that ATT&CK
files under more than one tactic also carries a ``tactics`` list with every
tactic it belongs to, primary first. Read tactics through :func:`tactics_for`
so callers do not have to know which entries have the extra key. Names and
tactics follow the ATT&CK matrix at https://attack.mitre.org.
"""
from __future__ import annotations

from siemforge.display import _LINE_CHAR, C, header

# Value type is loose on purpose: every entry has a str "name" and a str
# "tactic", and multi-tactic entries add a list[str] "tactics".
MITRE_MAP: dict[str, dict[str, object]] = {
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1027.010": {"name": "Command Obfuscation", "tactic": "Defense Evasion"},
    "T1136.001": {"name": "Create Account: Local Account", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1055.003": {"name": "Process Injection: Thread Execution Hijacking",
                  "tactic": "Defense Evasion",
                  "tactics": ["Defense Evasion", "Privilege Escalation"]},
    "T1003.001": {"name": "OS Credential Dumping: LSASS", "tactic": "Credential Access"},
    "T1562.001": {"name": "Impair Defenses: Disable Tools", "tactic": "Defense Evasion"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1547.001": {"name": "Boot/Logon Autostart: Registry",
                  "tactic": "Persistence",
                  "tactics": ["Persistence", "Privilege Escalation"]},
    "T1070.001": {"name": "Indicator Removal: Clear Logs", "tactic": "Defense Evasion"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1569.002": {"name": "Service Execution", "tactic": "Execution"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1053.005": {"name": "Scheduled Task",
                  "tactic": "Execution",
                  "tactics": ["Execution", "Persistence", "Privilege Escalation"]},
    "T1543.003": {"name": "Create/Modify System Service",
                  "tactic": "Persistence",
                  "tactics": ["Persistence", "Privilege Escalation"]},
    # Commonly referenced techniques, pre-mapped so future rules don't show
    # up as "Unknown". Multi-tactic ones carry the full list per the note above.
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.003": {"name": "OS Credential Dumping: NTDS", "tactic": "Credential Access"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols",
                  "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts",
              "tactic": "Defense Evasion",
              "tactics": ["Defense Evasion", "Persistence",
                          "Privilege Escalation", "Initial Access"]},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1505.003": {"name": "Server Software Component: Web Shell", "tactic": "Persistence"},
    "T1546.003": {"name": "Event Triggered Execution: WMI Subscription",
                  "tactic": "Privilege Escalation",
                  "tactics": ["Privilege Escalation", "Persistence"]},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1574.002": {"name": "Hijack Execution Flow: DLL Side-Loading",
                  "tactic": "Persistence",
                  "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"]},
}


def tactics_for(tid: str) -> list[str]:
    """Return every ATT&CK tactic a technique belongs to, primary first.

    Most techniques have one tactic; some are filed under several. Returns an
    empty list for an id that is not in the map.
    """
    entry = MITRE_MAP.get(tid)
    if entry is None:
        return []
    extra = entry.get("tactics")
    if isinstance(extra, list):
        return list(extra)
    return [str(entry["tactic"])]


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
                tactics.update(tactics_for(tid))
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
            name = str(MITRE_MAP[tid]["name"])
            tids_tactics = tactics_for(tid)
        else:
            name = tid
            tids_tactics = ["Unknown"]
        for tactic in tids_tactics:
            tactics.setdefault(tactic, []).append((tid, name))

    for tactic in sorted(tactics.keys()):
        print(f"\n  {C.BOLD}{C.MAGENTA}{tactic}{C.RESET}")
        print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")
        for tid, name in tactics[tactic]:
            print(f"    {C.CYAN}{tid:<12}{C.RESET} {name}")

    print(f"\n  {C.BOLD}Total Techniques Covered:{C.RESET} {C.GREEN}{len(covered)}{C.RESET}")
    print(f"  {C.BOLD}Total Detection Rules:{C.RESET}    {C.GREEN}{len(rules)}{C.RESET}")
