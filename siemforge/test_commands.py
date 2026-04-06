"""Safe test commands to trigger detection rules."""
from __future__ import annotations

from siemforge.display import _LINE_CHAR, C, header, warn


def generate_test_commands() -> None:
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
