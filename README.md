# 🛡️ SIEMForge — SIEM Detection Content Toolkit

> **Author:** Jude Hilgendorf
> **GitHub:** [github.com/TiltedLunar123](https://github.com/TiltedLunar123)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange?logo=data:image/svg+xml;base64,)
![Wazuh](https://img.shields.io/badge/Wazuh-Custom%20Rules-3C91E6)
![Sysmon](https://img.shields.io/badge/Sysmon-Config-red)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

A single-file Python toolkit containing **Sigma detection rules**, a tuned **Sysmon configuration**, and **Wazuh custom rules** — all mapped to MITRE ATT&CK. Export, validate, and test detection content from one portable script.

---

## 🎯 Detection Coverage

| # | Rule | Technique | Tactic | Severity |
|---|------|-----------|--------|----------|
| 1 | SSH Brute-Force Burst | T1110.001 | Credential Access | High |
| 2 | Suspicious PowerShell Execution | T1059.001 | Execution | High |
| 3 | Local Admin Account Creation | T1136.001 / T1098 | Persistence | Critical |
| 4 | Process Injection (CreateRemoteThread) | T1055.003 | Defense Evasion | High |
| 5 | LSASS Credential Dumping | T1003.001 | Credential Access | Critical |
| 6 | Windows Defender Tampering | T1562.001 | Defense Evasion | Critical |
| 7 | PsExec Lateral Movement | T1021.002 | Lateral Movement | High |
| 8 | Registry Run Key Persistence | T1547.001 | Persistence | Medium |

---

## 🧩 What's Included

```
siemforge.py (single file contains everything)
│
├── 8 Sigma Detection Rules (YAML)
├── Sysmon Configuration (XML, schema 4.90)
├── 11 Wazuh Custom Rules (XML, IDs 100100–100170)
├── Wazuh Agent Config Snippet
├── MITRE ATT&CK Mapping
├── Rule Validator
├── Test Command Generator
└── Full Export Engine
```

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/TiltedLunar123/SIEMForge.git
cd SIEMForge

# See stats and rule inventory
python siemforge.py

# Export everything
python siemforge.py --export-all

# Validate all rules
python siemforge.py --validate

# Show MITRE ATT&CK coverage
python siemforge.py --mitre

# Generate test commands
python siemforge.py --tests
```

**Zero dependencies** — Python 3.8+ standard library only.

---

## 📋 CLI Options

| Flag | Description |
|------|-------------|
| `--export-all` | Export all content (Sigma + Sysmon + Wazuh) to `./siemforge_export/` |
| `--sigma` | Export Sigma rules only |
| `--sysmon` | Export Sysmon config only |
| `--wazuh` | Export Wazuh rules + agent config |
| `--validate` | Validate all Sigma rules for required fields |
| `--mitre` | Display MITRE ATT&CK technique coverage |
| `--tests` | Show safe commands to trigger each detection |
| `--stats` | Project statistics |
| `--list` | List all rules with metadata |

---

## 📁 Export Structure

Running `--export-all` creates:

```
siemforge_export/
├── manifest.json
├── sigma_rules/
│   ├── ssh_bruteforce_burst.yml
│   ├── powershell_suspicious_execution.yml
│   ├── local_admin_creation.yml
│   ├── process_injection_sysmon.yml
│   ├── lsass_credential_dump.yml
│   ├── defender_tampering.yml
│   ├── psexec_lateral_movement.yml
│   └── registry_run_key_persistence.yml
├── sysmon/
│   └── sysmon_config.xml
└── wazuh/
    ├── local_rules.xml
    └── agent_ossec_snippet.xml
```

---

## 🔧 Deployment Guide

### Sysmon (Windows Endpoint)

```powershell
# Download Sysmon from Microsoft Sysinternals
# Install with the exported config
sysmon64.exe -accepteula -i siemforge_export/sysmon/sysmon_config.xml

# Update existing Sysmon config
sysmon64.exe -c siemforge_export/sysmon/sysmon_config.xml
```

### Wazuh Manager

```bash
# Copy custom rules
sudo cp siemforge_export/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml

# Validate config
sudo /var/ossec/bin/wazuh-analysisd -t

# Restart manager
sudo systemctl restart wazuh-manager
```

### Wazuh Agent (Windows)

Add the contents of `agent_ossec_snippet.xml` to:

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Then restart the Wazuh agent service.

---

## 🗺️ MITRE ATT&CK Coverage

```
  Credential Access
  ──────────────────────────────────────────────────
    T1003.001    OS Credential Dumping: LSASS
    T1110.001    Brute Force: Password Guessing

  Defense Evasion
  ──────────────────────────────────────────────────
    T1027.010    Command Obfuscation
    T1055.003    Process Injection: Thread Injection
    T1070.001    Indicator Removal: Clear Logs
    T1562.001    Impair Defenses: Disable Tools

  Execution
  ──────────────────────────────────────────────────
    T1059.001    PowerShell
    T1569.002    Service Execution

  Lateral Movement
  ──────────────────────────────────────────────────
    T1021.002    SMB/Windows Admin Shares
    T1570        Lateral Tool Transfer

  Persistence
  ──────────────────────────────────────────────────
    T1098        Account Manipulation
    T1136.001    Create Account: Local Account
    T1547.001    Boot/Logon Autostart: Registry
```

---

## 📸 Example Output

```
══════════════════════════════════════════════════════════════════════
  [ PROJECT STATISTICS ]
══════════════════════════════════════════════════════════════════════

  Sigma Detection Rules          : 8
  Wazuh Custom Rules             : 11
  Sysmon Event Types Covered     : 9
  MITRE Techniques               : 13
  MITRE Tactics                  : 5

  Severity Breakdown:
    critical         ███ 3
    high             ████ 4
    medium           █ 1

══════════════════════════════════════════════════════════════════════
  [ VALIDATING SIGMA RULES ]
══════════════════════════════════════════════════════════════════════

  [✓] ssh_bruteforce_burst.yml
  [✓] powershell_suspicious_execution.yml
  [✓] local_admin_creation.yml
  [✓] process_injection_sysmon.yml
  [✓] lsass_credential_dump.yml
  [✓] defender_tampering.yml
  [✓] psexec_lateral_movement.yml
  [✓] registry_run_key_persistence.yml

  Results: 8 passed  0 failed  0 warnings  / 8 total
```

---

## 🏠 Home Lab Setup

This project was built and tested in a home lab:

```
┌──────────────────────────────────────────────────┐
│                  Home Lab Network                │
│                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐   │
│  │ Wazuh    │    │ Windows  │    │ Kali     │   │
│  │ Manager  │◄───│ 10/11    │    │ Linux    │   │
│  │ (Ubuntu) │    │ + Sysmon │    │ (Attack) │   │
│  └──────────┘    │ + Agent  │    └──────────┘   │
│       ▲          └──────────┘         │          │
│       │               ▲              │          │
│       └───────────────┴──────────────┘          │
│                    Alerts                        │
└──────────────────────────────────────────────────┘
```

---

## ⚠️ Disclaimer

This project is for **authorized security testing and educational purposes only**. Detection rules and test commands should only be used in environments you own or have explicit permission to test. The author is not responsible for misuse.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center"><b>Detection engineering, made portable.</b> 🛡️</p>
