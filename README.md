# SIEMForge — SIEM Detection Content Toolkit

> **Author:** Jude Hilgendorf
> **GitHub:** [github.com/TiltedLunar123](https://github.com/TiltedLunar123)

[![CI](https://github.com/TiltedLunar123/SIEMForge/actions/workflows/ci.yml/badge.svg)](https://github.com/TiltedLunar123/SIEMForge/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange)
![Wazuh](https://img.shields.io/badge/Wazuh-Custom%20Rules-3C91E6)
![Sysmon](https://img.shields.io/badge/Sysmon-Config-red)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

A portable Python toolkit for managing **Sigma detection rules**, a tuned **Sysmon configuration**, and **Wazuh custom rules** — all mapped to MITRE ATT&CK. Export, validate, convert to SIEM queries, and test detection content from one CLI.

**New in v2.1:** Built-in Sigma-to-SIEM query converter — translate rules to Splunk SPL, Elasticsearch Lucene, or Kibana KQL with zero extra dependencies.

---

## Detection Coverage

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
| 9 | Scheduled Task Persistence | T1053.005 | Persistence | Medium |
| 10 | Suspicious Service Installation | T1543.003 | Persistence | Medium |

---

## Project Structure

```
SIEMForge/
├── siemforge.py              # CLI entry point
├── converters/               # Sigma -> SIEM query backends
│   ├── base.py               # Condition parser + base converter
│   ├── splunk.py             # Splunk SPL
│   ├── elastic.py            # Elasticsearch Lucene
│   └── kibana.py             # Kibana KQL
├── rules/sigma/              # 10 Sigma detection rules (YAML)
├── configs/                  # Sysmon XML + Wazuh rules & agent config
├── tests/                    # 78 pytest tests
└── pyproject.toml            # Packaging & tool config
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/TiltedLunar123/SIEMForge.git
cd SIEMForge
pip install pyyaml

# See stats and rule inventory
python siemforge.py

# Convert rules to Splunk SPL
python siemforge.py --convert splunk

# Export everything
python siemforge.py --export-all

# Validate all rules
python siemforge.py --validate

# Show MITRE ATT&CK coverage
python siemforge.py --mitre
```

**Runtime dependency:** PyYAML only. Python 3.8+.

---

## Sigma Conversion

Convert Sigma rules to native SIEM query syntax — no external tools required.

```bash
# Print all rules as Splunk SPL to terminal
python siemforge.py --convert splunk

# Export as Elasticsearch Lucene queries to files
python siemforge.py --convert elastic --convert-output ./queries/

# Convert a single rule to Kibana KQL
python siemforge.py --convert kibana --convert-rule lsass_credential_dump.yml
```

### Example Output (Splunk)

```
══════════════════════════════════════════════════════════════════════
  [ CONVERTING SIGMA RULES -> SPLUNK SPL ]
══════════════════════════════════════════════════════════════════════

  > LSASS Credential Dumping (lsass_credential_dump.yml)
    Level: critical | Technique: T1003.001
  ──────────────────────────────────────────────────
    (TargetImage="*\lsass.exe" GrantedAccess="0x1010"
     OR GrantedAccess="0x1410") NOT (SourceImage="*\MsMpEng.exe" ...)
```

Supported backends:

| Backend | Output format | File extension |
|---------|--------------|----------------|
| `splunk` | Splunk SPL | `.spl` |
| `elastic` | Elasticsearch Lucene | `.lucene` |
| `kibana` | Kibana Query Language | `.kql` |

---

## CLI Options

| Flag | Description |
|------|-------------|
| `--convert <backend>` | Convert rules to SIEM queries (`splunk`, `elastic`, `kibana`) |
| `--convert-output <dir>` | Write converted queries to files (one per rule) |
| `--convert-rule <file>` | Convert a single rule by filename |
| `--export-all` | Export all content (Sigma + Sysmon + Wazuh) to `./siemforge_export/` |
| `--sigma` | Export Sigma rules only |
| `--sysmon` | Export Sysmon config only |
| `--wazuh` | Export Wazuh rules + agent config |
| `--validate` | Validate all Sigma rules for required fields |
| `--mitre` | Display MITRE ATT&CK technique coverage |
| `--tests` | Show safe commands to trigger each detection |
| `--stats` | Project statistics |
| `--stats --json` | Machine-readable JSON statistics |
| `--list` | List all rules with metadata |
| `--output-dir <dir>` | Custom output directory for exports |
| `--dry-run` | Preview what would be exported without writing files |
| `-V` / `--version` | Show version |

---

## Export Structure

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
│   ├── registry_run_key_persistence.yml
│   ├── scheduled_task_persistence.yml
│   └── suspicious_service_install.yml
├── sysmon/
│   └── sysmon_config.xml
└── wazuh/
    ├── local_rules.xml
    └── agent_ossec_snippet.xml
```

---

## Deployment Guide

### Sysmon (Windows Endpoint)

```powershell
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

## MITRE ATT&CK Coverage

```
  Credential Access
  ──────────────────────────────────────────────────
    T1003.001    OS Credential Dumping: LSASS
    T1110.001    Brute Force: Password Guessing

  Defense Evasion
  ──────────────────────────────────────────────────
    T1027.010    Command Obfuscation
    T1055.003    Process Injection: Thread Injection
    T1562.001    Impair Defenses: Disable Tools

  Execution
  ──────────────────────────────────────────────────
    T1053.005    Scheduled Task
    T1059.001    PowerShell
    T1543.003    Create/Modify System Service
    T1569.002    Service Execution

  Lateral Movement
  ──────────────────────────────────────────────────
    T1021.002    SMB/Windows Admin Shares

  Persistence
  ──────────────────────────────────────────────────
    T1098        Account Manipulation
    T1136.001    Create Account: Local Account
    T1547.001    Boot/Logon Autostart: Registry
```

---

## Home Lab Setup

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

## Disclaimer

This project is for **authorized security testing and educational purposes only**. Detection rules and test commands should only be used in environments you own or have explicit permission to test. The author is not responsible for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center"><b>Detection engineering, made portable.</b></p>
