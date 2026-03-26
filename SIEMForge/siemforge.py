#!/usr/bin/env python3
"""
SIEMForge | SIEM Detection Content Toolkit
Sigma Rules & Wazuh/Sysmon Detection Engineering

Author: Jude Hilgendorf
GitHub: github.com/TiltedLunar123

Manages, exports, validates, and tests Sigma detection rules,
Sysmon configuration, and Wazuh custom rules from a single file.
"""

import os
import sys
import json
import argparse
import datetime
import re
from pathlib import Path
from textwrap import dedent

VERSION = "1.1.0"


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
        "═".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False

_UNICODE = _supports_unicode()
DIV = f"{C.BLUE}{'═' * 70}{C.RESET}" if _UNICODE else f"{C.BLUE}{'=' * 70}{C.RESET}"


def header(title: str):
    print(f"\n{DIV}")
    print(f"  {C.BOLD}{C.CYAN}[ {title} ]{C.RESET}")
    print(DIV)


_OK  = "[✓]" if _UNICODE else "[+]"
_ERR = "[✗]" if _UNICODE else "[X]"
_BUL = "•"   if _UNICODE else "*"


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
# SIGMA DETECTION RULES
# ──────────────────────────────────────────────

SIGMA_RULES = {

    # ── RULE 1: SSH Brute-Force Burst ──
    "ssh_bruteforce_burst.yml": dedent("""\
        title: SSH Brute-Force Burst Detection
        id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
        status: experimental
        description: >
            Detects rapid SSH authentication failures indicating a brute-force
            attack. Triggers when multiple failed SSH login attempts occur from
            the same source within a short time window.
        references:
            - https://attack.mitre.org/techniques/T1110/001/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.credential_access
            - attack.t1110.001
            - attack.brute_force
        logsource:
            category: authentication
            product: linux
            service: sshd
        detection:
            selection_failed:
                EventType: failure
                ServiceName: sshd
            selection_keywords:
                - 'Failed password'
                - 'authentication failure'
                - 'Invalid user'
            condition: selection_failed or selection_keywords
        fields:
            - SourceIP
            - TargetUserName
            - EventType
        falsepositives:
            - Misconfigured automated scripts with wrong credentials
            - Users who forgot their password and retry rapidly
            - Vulnerability scanners performing auth checks
        level: high
        custom:
            threshold_count: 10
            threshold_window: 60s
            notes: >
                Tune threshold based on environment. In a home lab, 5 failures
                in 30 seconds is suspicious. Production may need higher thresholds.
    """),

    # ── RULE 2: Suspicious PowerShell Execution ──
    "powershell_suspicious_execution.yml": dedent("""\
        title: Suspicious PowerShell Command Execution
        id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
        status: experimental
        description: >
            Detects PowerShell execution with suspicious parameters commonly
            used by attackers — encoded commands, download cradles, execution
            policy bypasses, and AMSI bypass attempts.
        references:
            - https://attack.mitre.org/techniques/T1059/001/
            - https://attack.mitre.org/techniques/T1027/010/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.execution
            - attack.t1059.001
            - attack.defense_evasion
            - attack.t1027.010
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_process:
                Image|endswith:
                    - '\\powershell.exe'
                    - '\\pwsh.exe'
            selection_encoded:
                CommandLine|contains:
                    - '-enc'
                    - '-EncodedCommand'
                    - '-e '
                    - 'FromBase64String'
            selection_download:
                CommandLine|contains:
                    - 'Net.WebClient'
                    - 'DownloadString'
                    - 'DownloadFile'
                    - 'Invoke-WebRequest'
                    - 'IWR '
                    - 'wget '
                    - 'curl '
                    - 'Start-BitsTransfer'
                    - 'Invoke-RestMethod'
            selection_bypass:
                CommandLine|contains:
                    - '-ExecutionPolicy Bypass'
                    - '-ep bypass'
                    - '-exec bypass'
                    - 'Set-ExecutionPolicy Unrestricted'
            selection_amsi:
                CommandLine|contains:
                    - 'AmsiUtils'
                    - 'amsiInitFailed'
                    - 'Disable-Amsi'
                    - 'AmsiScanBuffer'
            selection_hidden:
                CommandLine|contains:
                    - '-WindowStyle Hidden'
                    - '-w hidden'
                    - '-NoProfile'
                    - '-nop '
                    - '-sta '
            condition: >
                selection_process and
                (selection_encoded or selection_download or
                 selection_bypass or selection_amsi or selection_hidden)
        fields:
            - User
            - CommandLine
            - ParentImage
            - ParentCommandLine
        falsepositives:
            - Legitimate admin scripts using encoded commands
            - Software deployment tools (SCCM, Intune)
            - Chocolatey or winget package manager operations
        level: high
    """),

    # ── RULE 3: Unauthorized Local Admin Creation ──
    "local_admin_creation.yml": dedent("""\
        title: Unauthorized Local Administrator Account Creation
        id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
        status: experimental
        description: >
            Detects creation of a new local user account followed by addition
            to the local Administrators group. This is a common persistence
            technique used by attackers after initial compromise.
        references:
            - https://attack.mitre.org/techniques/T1136/001/
            - https://attack.mitre.org/techniques/T1098/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.persistence
            - attack.t1136.001
            - attack.privilege_escalation
            - attack.t1098
        logsource:
            product: windows
            service: security
        detection:
            selection_user_created:
                EventID: 4720
            selection_admin_added:
                EventID: 4732
                TargetGroupName|contains:
                    - 'Administrators'
                    - 'Administradores'
                    - 'Administrateurs'
            selection_net_commands:
                EventID: 1
                CommandLine|contains:
                    - 'net user /add'
                    - 'net localgroup administrators'
                    - 'New-LocalUser'
                    - 'Add-LocalGroupMember'
            condition: selection_user_created or selection_admin_added or selection_net_commands
        fields:
            - SubjectUserName
            - TargetUserName
            - TargetGroupName
            - CommandLine
        falsepositives:
            - Legitimate IT provisioning of new admin accounts
            - Automated deployment scripts during initial setup
            - Domain join operations
        level: critical
    """),

    # ── RULE 4: Sysmon - Suspicious Process Injection ──
    "process_injection_sysmon.yml": dedent("""\
        title: Process Injection via CreateRemoteThread (Sysmon)
        id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
        status: experimental
        description: >
            Detects potential process injection using CreateRemoteThread.
            Sysmon Event ID 8 fires when a process creates a thread in
            another process, a hallmark of injection techniques.
        references:
            - https://attack.mitre.org/techniques/T1055/003/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.defense_evasion
            - attack.privilege_escalation
            - attack.t1055.003
        logsource:
            product: windows
            service: sysmon
        detection:
            selection:
                EventID: 8
            filter_legitimate:
                SourceImage|endswith:
                    - '\\csrss.exe'
                    - '\\lsass.exe'
                    - '\\services.exe'
                    - '\\svchost.exe'
                    - '\\wininit.exe'
                    - '\\MsMpEng.exe'
                    - '\\MpCmdRun.exe'
            filter_same_process:
                SourceImage: TargetImage
            condition: selection and not filter_legitimate and not filter_same_process
        fields:
            - SourceImage
            - TargetImage
            - SourceUser
            - StartFunction
            - StartModule
        falsepositives:
            - Antivirus and EDR products
            - Debugging tools (Visual Studio, WinDbg)
            - Some legitimate software using thread injection for hooking
        level: high
    """),

    # ── RULE 5: Credential Dumping via LSASS Access ──
    "lsass_credential_dump.yml": dedent("""\
        title: LSASS Memory Access - Credential Dumping Attempt
        id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
        status: experimental
        description: >
            Detects processes accessing LSASS memory which may indicate
            credential dumping (e.g., Mimikatz, ProcDump, comsvcs.dll).
            Uses Sysmon Event ID 10 (ProcessAccess).
        references:
            - https://attack.mitre.org/techniques/T1003/001/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.credential_access
            - attack.t1003.001
        logsource:
            product: windows
            service: sysmon
        detection:
            selection:
                EventID: 10
                TargetImage|endswith: '\\lsass.exe'
                GrantedAccess|contains:
                    - '0x1010'
                    - '0x1038'
                    - '0x1F0FFF'
                    - '0x1F1FFF'
                    - '0x143A'
            filter_system:
                SourceImage|endswith:
                    - '\\MsMpEng.exe'
                    - '\\csrss.exe'
                    - '\\wininit.exe'
                    - '\\wmiprvse.exe'
                    - '\\svchost.exe'
                    - '\\msiexec.exe'
            condition: selection and not filter_system
        fields:
            - SourceImage
            - TargetImage
            - GrantedAccess
            - SourceUser
            - CallTrace
        falsepositives:
            - Antivirus real-time scanning
            - Windows Error Reporting
            - Legitimate admin tools with process inspection
        level: critical
    """),

    # ── RULE 6: Windows Defender Tampering ──
    "defender_tampering.yml": dedent("""\
        title: Windows Defender Disabled or Tampered
        id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102
        status: experimental
        description: >
            Detects attempts to disable Windows Defender real-time protection,
            tamper protection, or core AV components via PowerShell, registry,
            or service manipulation.
        references:
            - https://attack.mitre.org/techniques/T1562/001/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.defense_evasion
            - attack.t1562.001
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_powershell_disable:
                CommandLine|contains:
                    - 'Set-MpPreference -DisableRealtimeMonitoring $true'
                    - 'Set-MpPreference -DisableBehaviorMonitoring $true'
                    - 'Set-MpPreference -DisableIOAVProtection $true'
                    - 'Set-MpPreference -DisableScriptScanning $true'
                    - 'Set-MpPreference -DisableBlockAtFirstSeen $true'
            selection_registry:
                CommandLine|contains:
                    - 'DisableAntiSpyware'
                    - 'DisableRealtimeMonitoring'
                    - 'DisableBehaviorMonitoring'
            selection_service_stop:
                CommandLine|contains:
                    - 'sc stop WinDefend'
                    - 'sc delete WinDefend'
                    - 'sc config WinDefend start= disabled'
                    - 'net stop WinDefend'
            selection_tamper:
                CommandLine|contains:
                    - 'TamperProtection'
                    - 'DisableAntiVirus'
            condition: >
                selection_powershell_disable or selection_registry or
                selection_service_stop or selection_tamper
        fields:
            - User
            - CommandLine
            - ParentImage
            - ParentCommandLine
        falsepositives:
            - Legitimate IT administration during troubleshooting
            - GPO deployments switching to third-party AV
        level: critical
    """),

    # ── RULE 7: Lateral Movement via PsExec ──
    "psexec_lateral_movement.yml": dedent("""\
        title: PsExec Lateral Movement Detection
        id: a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213
        status: experimental
        description: >
            Detects execution of PsExec or PsExec-like tools used for
            lateral movement. Monitors for the PsExec service installation,
            named pipe creation, and characteristic process patterns.
        references:
            - https://attack.mitre.org/techniques/T1021/002/
            - https://attack.mitre.org/techniques/T1570/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.lateral_movement
            - attack.t1021.002
            - attack.execution
            - attack.t1569.002
        logsource:
            product: windows
            service: sysmon
        detection:
            selection_pipe:
                EventID: 17
                PipeName|contains:
                    - '\\PSEXESVC'
                    - '\\psexec'
                    - '\\csexec'
                    - '\\paexec'
            selection_service:
                EventID: 7045
                ServiceName|contains:
                    - 'PSEXESVC'
                    - 'csexecsvc'
                    - 'paexec'
            selection_process:
                EventID: 1
                Image|endswith:
                    - '\\PsExec.exe'
                    - '\\PsExec64.exe'
                    - '\\csexec.exe'
                    - '\\paexec.exe'
            condition: selection_pipe or selection_service or selection_process
        fields:
            - SourceImage
            - User
            - PipeName
            - CommandLine
            - TargetHostname
        falsepositives:
            - Legitimate admin use of PsExec for remote management
            - SCCM or similar tools using PsExec for deployment
        level: high
    """),

    # ── RULE 8: Persistence via Registry Run Keys ──
    "registry_run_key_persistence.yml": dedent("""\
        title: Persistence via Registry Run Key Modification
        id: b8c9d0e1-f2a3-4b4c-5d6e-7f8091021324
        status: experimental
        description: >
            Detects modification of Windows Registry Run and RunOnce keys
            used to establish persistence. Monitors Sysmon Event ID 13
            (RegistryEvent - Value Set) for writes to common autostart
            registry locations.
        references:
            - https://attack.mitre.org/techniques/T1547/001/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.persistence
            - attack.t1547.001
        logsource:
            product: windows
            service: sysmon
        detection:
            selection:
                EventID: 13
                TargetObject|contains:
                    - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\'
                    - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'
                    - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices\\'
                    - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\'
                    - '\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            filter_legitimate:
                Image|endswith:
                    - '\\msiexec.exe'
                    - '\\MpCmdRun.exe'
                    - '\\OneDriveSetup.exe'
                    - '\\Teams.exe'
            condition: selection and not filter_legitimate
        fields:
            - Image
            - TargetObject
            - Details
            - User
        falsepositives:
            - Software installations adding legitimate startup entries
            - Windows feature updates
            - User-installed applications
        level: medium
    """),

    # ── RULE 9: Scheduled Task Persistence ──
    "scheduled_task_persistence.yml": dedent("""\
        title: Persistence via Scheduled Task Creation
        id: c9d0e1f2-a3b4-4c5d-6e7f-809102132435
        status: experimental
        description: >
            Detects creation of scheduled tasks via schtasks.exe or PowerShell,
            commonly abused by attackers to establish persistence or execute
            payloads at specific times or on user logon.
        references:
            - https://attack.mitre.org/techniques/T1053/005/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.persistence
            - attack.execution
            - attack.t1053.005
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_schtasks:
                Image|endswith: '\\schtasks.exe'
                CommandLine|contains:
                    - '/create'
                    - '/Create'
            selection_powershell:
                CommandLine|contains:
                    - 'New-ScheduledTask'
                    - 'Register-ScheduledTask'
                    - 'ScheduledTasks'
            filter_system:
                User|contains:
                    - 'SYSTEM'
                    - 'LOCAL SERVICE'
            condition: (selection_schtasks or selection_powershell) and not filter_system
        fields:
            - User
            - CommandLine
            - ParentImage
            - ParentCommandLine
        falsepositives:
            - Legitimate software installation creating scheduled tasks
            - IT automation and deployment tools
            - Windows Update creating maintenance tasks
        level: medium
    """),

    # ── RULE 10: Suspicious Service Installation ──
    "suspicious_service_install.yml": dedent("""\
        title: Suspicious Windows Service Installation
        id: d0e1f2a3-b4c5-4d6e-7f80-910213243546
        status: experimental
        description: >
            Detects installation of new Windows services via sc.exe or PowerShell,
            which is a common technique for persistence and privilege escalation.
            Filters out known legitimate service installers.
        references:
            - https://attack.mitre.org/techniques/T1543/003/
            - https://github.com/TiltedLunar123/SIEMForge
        author: Jude Hilgendorf
        date: 2025/06/15
        modified: 2025/06/15
        tags:
            - attack.persistence
            - attack.privilege_escalation
            - attack.t1543.003
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_sc:
                Image|endswith: '\\sc.exe'
                CommandLine|contains:
                    - 'create'
                    - 'config'
            selection_powershell:
                CommandLine|contains:
                    - 'New-Service'
                    - 'Set-Service'
            selection_event:
                EventID: 7045
            filter_legitimate:
                ParentImage|endswith:
                    - '\\msiexec.exe'
                    - '\\setup.exe'
                    - '\\MsMpEng.exe'
                    - '\\TiWorker.exe'
            condition: (selection_sc or selection_powershell or selection_event) and not filter_legitimate
        fields:
            - User
            - CommandLine
            - ParentImage
            - ServiceName
            - ImagePath
        falsepositives:
            - Legitimate software installation
            - System administrators deploying services
            - Windows updates and feature installations
        level: medium
    """),
}


# ──────────────────────────────────────────────
# SYSMON CONFIGURATION
# ──────────────────────────────────────────────

SYSMON_CONFIG = dedent("""\
<!--
    SIEMForge Sysmon Configuration
    Author: Jude Hilgendorf
    GitHub: github.com/TiltedLunar123

    Optimized for detection rules in this project.
    Captures process creation, network connections, file creation,
    registry modifications, process injection, and LSASS access.

    Install: sysmon64.exe -accepteula -i sysmon_config.xml
    Update:  sysmon64.exe -c sysmon_config.xml
-->
<Sysmon schemaversion="4.90">

    <HashAlgorithms>SHA256,MD5,IMPHASH</HashAlgorithms>
    <CheckRevocation>true</CheckRevocation>

    <EventFiltering>

        <!-- ═══ Event ID 1: Process Creation ═══ -->
        <RuleGroup name="ProcessCreate" groupRelation="or">
            <ProcessCreate onmatch="include">
                <!-- PowerShell -->
                <Image condition="end with">\\powershell.exe</Image>
                <Image condition="end with">\\pwsh.exe</Image>
                <!-- Command Processors -->
                <Image condition="end with">\\cmd.exe</Image>
                <Image condition="end with">\\wscript.exe</Image>
                <Image condition="end with">\\cscript.exe</Image>
                <Image condition="end with">\\mshta.exe</Image>
                <Image condition="end with">\\regsvr32.exe</Image>
                <Image condition="end with">\\rundll32.exe</Image>
                <!-- Lateral Movement -->
                <Image condition="end with">\\PsExec.exe</Image>
                <Image condition="end with">\\PsExec64.exe</Image>
                <!-- User Management -->
                <Image condition="end with">\\net.exe</Image>
                <Image condition="end with">\\net1.exe</Image>
                <!-- Credential Tools -->
                <Image condition="end with">\\mimikatz.exe</Image>
                <Image condition="end with">\\procdump.exe</Image>
                <Image condition="end with">\\procdump64.exe</Image>
                <!-- Suspicious CommandLine Patterns -->
                <CommandLine condition="contains">-EncodedCommand</CommandLine>
                <CommandLine condition="contains">FromBase64String</CommandLine>
                <CommandLine condition="contains">DownloadString</CommandLine>
                <CommandLine condition="contains">Net.WebClient</CommandLine>
                <CommandLine condition="contains">Invoke-Expression</CommandLine>
                <CommandLine condition="contains">IEX</CommandLine>
                <CommandLine condition="contains">-ExecutionPolicy Bypass</CommandLine>
                <CommandLine condition="contains">net user /add</CommandLine>
                <CommandLine condition="contains">net localgroup administrators</CommandLine>
                <CommandLine condition="contains">DisableRealtimeMonitoring</CommandLine>
                <CommandLine condition="contains">sc stop WinDefend</CommandLine>
            </ProcessCreate>
        </RuleGroup>

        <!-- ═══ Event ID 3: Network Connection ═══ -->
        <RuleGroup name="NetworkConnect" groupRelation="or">
            <NetworkConnect onmatch="include">
                <Image condition="end with">\\powershell.exe</Image>
                <Image condition="end with">\\pwsh.exe</Image>
                <Image condition="end with">\\cmd.exe</Image>
                <Image condition="end with">\\rundll32.exe</Image>
                <Image condition="end with">\\regsvr32.exe</Image>
                <Image condition="end with">\\mshta.exe</Image>
                <Image condition="end with">\\certutil.exe</Image>
                <Image condition="end with">\\bitsadmin.exe</Image>
                <DestinationPort condition="is">22</DestinationPort>
                <DestinationPort condition="is">4444</DestinationPort>
                <DestinationPort condition="is">5555</DestinationPort>
                <DestinationPort condition="is">8080</DestinationPort>
                <DestinationPort condition="is">8443</DestinationPort>
            </NetworkConnect>
        </RuleGroup>

        <!-- ═══ Event ID 7: Image Loaded (DLL) ═══ -->
        <RuleGroup name="ImageLoad" groupRelation="or">
            <ImageLoad onmatch="include">
                <ImageLoaded condition="end with">\\clrjit.dll</ImageLoaded>
                <ImageLoaded condition="end with">\\amsi.dll</ImageLoaded>
                <ImageLoaded condition="end with">\\comsvcs.dll</ImageLoaded>
            </ImageLoad>
        </RuleGroup>

        <!-- ═══ Event ID 8: CreateRemoteThread ═══ -->
        <RuleGroup name="CreateRemoteThread" groupRelation="or">
            <CreateRemoteThread onmatch="exclude">
                <SourceImage condition="end with">\\csrss.exe</SourceImage>
                <SourceImage condition="end with">\\lsass.exe</SourceImage>
                <SourceImage condition="end with">\\MsMpEng.exe</SourceImage>
                <SourceImage condition="end with">\\svchost.exe</SourceImage>
            </CreateRemoteThread>
        </RuleGroup>

        <!-- ═══ Event ID 10: Process Access (LSASS) ═══ -->
        <RuleGroup name="ProcessAccess" groupRelation="or">
            <ProcessAccess onmatch="include">
                <TargetImage condition="end with">\\lsass.exe</TargetImage>
            </ProcessAccess>
        </RuleGroup>

        <!-- ═══ Event ID 11: File Creation ═══ -->
        <RuleGroup name="FileCreate" groupRelation="or">
            <FileCreate onmatch="include">
                <TargetFilename condition="end with">.exe</TargetFilename>
                <TargetFilename condition="end with">.dll</TargetFilename>
                <TargetFilename condition="end with">.bat</TargetFilename>
                <TargetFilename condition="end with">.ps1</TargetFilename>
                <TargetFilename condition="end with">.vbs</TargetFilename>
                <TargetFilename condition="end with">.hta</TargetFilename>
                <TargetFilename condition="contains">\\Startup\\</TargetFilename>
                <TargetFilename condition="contains">\\Start Menu\\</TargetFilename>
                <TargetFilename condition="contains">\\Temp\\</TargetFilename>
            </FileCreate>
        </RuleGroup>

        <!-- ═══ Event ID 13: Registry Value Set ═══ -->
        <RuleGroup name="RegistryEvent" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>
                <TargetObject condition="contains">\\CurrentVersion\\RunOnce</TargetObject>
                <TargetObject condition="contains">\\CurrentVersion\\Policies\\Explorer\\Run</TargetObject>
                <TargetObject condition="contains">DisableAntiSpyware</TargetObject>
                <TargetObject condition="contains">DisableRealtimeMonitoring</TargetObject>
                <TargetObject condition="contains">EnableLUA</TargetObject>
            </RegistryEvent>
        </RuleGroup>

        <!-- ═══ Event ID 17/18: Pipe Created/Connected ═══ -->
        <RuleGroup name="PipeEvent" groupRelation="or">
            <PipeEvent onmatch="include">
                <PipeName condition="contains">\\PSEXESVC</PipeName>
                <PipeName condition="contains">\\psexec</PipeName>
                <PipeName condition="contains">\\paexec</PipeName>
                <PipeName condition="contains">\\csexec</PipeName>
            </PipeEvent>
        </RuleGroup>

        <!-- ═══ Event ID 22: DNS Query ═══ -->
        <RuleGroup name="DnsQuery" groupRelation="or">
            <DnsQuery onmatch="include">
                <Image condition="end with">\\powershell.exe</Image>
                <Image condition="end with">\\rundll32.exe</Image>
                <Image condition="end with">\\regsvr32.exe</Image>
                <QueryName condition="end with">.onion</QueryName>
                <QueryName condition="end with">.top</QueryName>
                <QueryName condition="end with">.tk</QueryName>
            </DnsQuery>
        </RuleGroup>

    </EventFiltering>
</Sysmon>
""")


# ──────────────────────────────────────────────
# WAZUH CUSTOM RULES
# ──────────────────────────────────────────────

WAZUH_RULES = dedent("""\
<!--
    SIEMForge Wazuh Custom Detection Rules
    Author: Jude Hilgendorf
    GitHub: github.com/TiltedLunar123

    Place in: /var/ossec/etc/rules/local_rules.xml
    Then restart Wazuh: systemctl restart wazuh-manager

    Rule ID Range: 100100 - 100199 (custom local range)
-->

<group name="siemforge,">

    <!-- ═══════════════════════════════════════════ -->
    <!-- SSH BRUTE FORCE BURST                       -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100100" level="10" frequency="8" timeframe="60">
        <if_matched_sid>5716</if_matched_sid>
        <same_source_ip />
        <description>SIEMForge: SSH brute-force burst detected — $(srcip) failed 8+ logins in 60 seconds</description>
        <mitre>
            <id>T1110.001</id>
        </mitre>
        <group>authentication_failures,brute_force,</group>
    </rule>

    <rule id="100101" level="12" frequency="20" timeframe="120">
        <if_matched_sid>5716</if_matched_sid>
        <same_source_ip />
        <description>SIEMForge: Aggressive SSH brute-force — $(srcip) failed 20+ logins in 2 minutes</description>
        <mitre>
            <id>T1110.001</id>
        </mitre>
        <group>authentication_failures,brute_force,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- SUSPICIOUS POWERSHELL EXECUTION             -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100110" level="12">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(encodedcommand|frombase64string|-enc\s)</field>
        <description>SIEMForge: PowerShell executed with encoded command — possible obfuscation</description>
        <mitre>
            <id>T1059.001</id>
            <id>T1027.010</id>
        </mitre>
        <group>powershell,suspicious_execution,</group>
    </rule>

    <rule id="100111" level="12">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer)</field>
        <description>SIEMForge: PowerShell download cradle detected — possible payload staging</description>
        <mitre>
            <id>T1059.001</id>
            <id>T1105</id>
        </mitre>
        <group>powershell,download_cradle,</group>
    </rule>

    <rule id="100112" level="10">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(executionpolicy\s+bypass|set-executionpolicy\s+unrestricted)</field>
        <description>SIEMForge: PowerShell execution policy bypass detected</description>
        <mitre>
            <id>T1059.001</id>
        </mitre>
        <group>powershell,policy_bypass,</group>
    </rule>

    <rule id="100113" level="14">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(amsiutils|amsiinitfailed|amsiScanbuffer|disable-amsi)</field>
        <description>SIEMForge: AMSI bypass attempt detected in PowerShell</description>
        <mitre>
            <id>T1562.001</id>
        </mitre>
        <group>powershell,amsi_bypass,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- LOCAL ADMIN ACCOUNT CREATION                -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100120" level="12">
        <if_sid>60106</if_sid>
        <field name="win.system.eventID">4720</field>
        <description>SIEMForge: New local user account created — $(win.eventdata.targetUserName)</description>
        <mitre>
            <id>T1136.001</id>
        </mitre>
        <group>account_creation,persistence,</group>
    </rule>

    <rule id="100121" level="14">
        <if_sid>60106</if_sid>
        <field name="win.system.eventID">4732</field>
        <field name="win.eventdata.targetGroupName" type="pcre2">(?i)admin</field>
        <description>SIEMForge: User added to Administrators group — $(win.eventdata.targetUserName) → $(win.eventdata.targetGroupName)</description>
        <mitre>
            <id>T1098</id>
            <id>T1136.001</id>
        </mitre>
        <group>privilege_escalation,admin_added,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- CREDENTIAL DUMPING (LSASS ACCESS)           -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100130" level="14">
        <if_sid>61603</if_sid>
        <field name="win.system.eventID">10</field>
        <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
        <description>SIEMForge: Process accessed LSASS memory — possible credential dumping by $(win.eventdata.sourceImage)</description>
        <mitre>
            <id>T1003.001</id>
        </mitre>
        <group>credential_access,lsass_access,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- WINDOWS DEFENDER TAMPERING                  -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100140" level="14">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection|sc\s+stop\s+windefend|sc\s+delete\s+windefend)</field>
        <description>SIEMForge: Windows Defender tampering detected — AV defense evasion</description>
        <mitre>
            <id>T1562.001</id>
        </mitre>
        <group>defense_evasion,av_tampering,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- LATERAL MOVEMENT (PSEXEC)                   -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100150" level="12">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.pipeName" type="pcre2">(?i)(psexesvc|psexec|paexec|csexec)</field>
        <description>SIEMForge: PsExec named pipe detected — lateral movement indicator</description>
        <mitre>
            <id>T1021.002</id>
            <id>T1570</id>
        </mitre>
        <group>lateral_movement,psexec,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- REGISTRY PERSISTENCE                        -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100160" level="10">
        <if_sid>61603</if_sid>
        <field name="win.system.eventID">13</field>
        <field name="win.eventdata.targetObject" type="pcre2">(?i)\\CurrentVersion\\(Run|RunOnce)\\</field>
        <description>SIEMForge: Registry Run key modified — possible persistence by $(win.eventdata.image)</description>
        <mitre>
            <id>T1547.001</id>
        </mitre>
        <group>persistence,registry_run_key,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!-- AUDIT LOG CLEARED                           -->
    <!-- ═══════════════════════════════════════════ -->

    <rule id="100170" level="14">
        <if_sid>60106</if_sid>
        <field name="win.system.eventID">1102</field>
        <description>SIEMForge: Windows Security audit log was cleared — anti-forensics indicator</description>
        <mitre>
            <id>T1070.001</id>
        </mitre>
        <group>defense_evasion,log_cleared,</group>
    </rule>

</group>
""")


# ──────────────────────────────────────────────
# WAZUH AGENT OSSEC.CONF SNIPPET
# ──────────────────────────────────────────────

WAZUH_AGENT_CONF = dedent("""\
<!--
    SIEMForge — Wazuh Agent Configuration Snippet
    Add this to the Wazuh agent's ossec.conf to forward Sysmon logs.
    Location: C:\\Program Files (x86)\\ossec-agent\\ossec.conf (Windows)
-->

<!-- Forward Sysmon operational log -->
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>

<!-- Forward Security event log -->
<localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
</localfile>

<!-- Forward PowerShell script block logging -->
<localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>

<!-- Forward Windows Defender logs -->
<localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
""")


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
# CORE FUNCTIONS
# ──────────────────────────────────────────────

def export_sigma_rules(output_dir: str = "sigma_rules", dry_run: bool = False):
    """Export all embedded Sigma rules to individual YAML files."""
    header("EXPORTING SIGMA RULES")

    if dry_run:
        for filename in SIGMA_RULES:
            info(f"Would write {output_dir}/{filename}")
        info(f"Dry run: {len(SIGMA_RULES)} Sigma rules would be exported to ./{output_dir}/")
        return Path(output_dir)

    path = Path(output_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create directory {output_dir}: {e}")
        return None

    for filename, content in SIGMA_RULES.items():
        filepath = path / filename
        try:
            filepath.write_text(content, encoding="utf-8")
            ok(f"Wrote {filepath}")
        except OSError as e:
            err(f"Failed to write {filepath}: {e}")

    info(f"Exported {len(SIGMA_RULES)} Sigma rules to ./{output_dir}/")
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

    filepath = path / "sysmon_config.xml"
    try:
        filepath.write_text(SYSMON_CONFIG, encoding="utf-8")
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

    for fname, content in [("local_rules.xml", WAZUH_RULES), ("agent_ossec_snippet.xml", WAZUH_AGENT_CONF)]:
        fpath = path / fname
        try:
            fpath.write_text(content, encoding="utf-8")
            ok(f"Wrote {fpath}")
        except OSError as e:
            err(f"Failed to write {fpath}: {e}")

    info("Deploy rules to: /var/ossec/etc/rules/local_rules.xml")
    info("Restart manager: systemctl restart wazuh-manager")
    return path


def validate_rules():
    """Validate all Sigma rules for required fields and structure."""
    header("VALIDATING SIGMA RULES")

    required_fields = [
        "title", "id", "status", "description", "author",
        "date", "logsource", "detection", "level",
    ]

    total   = len(SIGMA_RULES)
    passed  = 0
    failed  = 0
    warnings_count = 0

    for filename, content in SIGMA_RULES.items():
        issues = []
        warns_list = []

        # Check required fields exist
        for field in required_fields:
            # Simple YAML key check (line starts with "key:")
            if not any(line.strip().startswith(f"{field}:") for line in content.splitlines()):
                issues.append(f"Missing required field: {field}")

        # Check for MITRE tags
        if "attack.t" not in content.lower():
            warns_list.append("No MITRE ATT&CK technique tag found")

        # Check UUID format for id (must be valid UUIDv4 hex pattern)
        lines = content.splitlines()
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
        )
        for line in lines:
            if line.strip().startswith("id:"):
                rule_id = line.split(":", 1)[1].strip()
                if not uuid_pattern.match(rule_id):
                    issues.append(f"ID is not valid UUID format: {rule_id}")
                break

        # Check level value
        for line in lines:
            if line.strip().startswith("level:"):
                level_val = line.split(":", 1)[1].strip()
                valid_levels = ["informational", "low", "medium", "high", "critical"]
                if level_val not in valid_levels:
                    issues.append(f"Invalid level: {level_val}")
                break

        # Check falsepositives section
        if "falsepositives:" not in content:
            warns_list.append("No falsepositives section (recommended)")

        # Report results
        if issues:
            err(f"{filename}")
            for issue in issues:
                bullet(f"{C.RED}{issue}{C.RESET}")
            failed += 1
        else:
            ok(f"{filename}")
            passed += 1

        for w in warns_list:
            bullet(f"{C.YELLOW}{w}{C.RESET}")
            warnings_count += 1

    print(f"\n  {C.BOLD}Results:{C.RESET} {C.GREEN}{passed} passed{C.RESET}  "
          f"{C.RED}{failed} failed{C.RESET}  "
          f"{C.YELLOW}{warnings_count} warnings{C.RESET}  "
          f"/ {total} total")


def show_mitre_coverage():
    """Display MITRE ATT&CK coverage matrix."""
    header("MITRE ATT&CK COVERAGE")

    # Collect all technique IDs from rules
    covered: set = set()
    for content in SIGMA_RULES.values():
        for line in content.splitlines():
            line_s = line.strip()
            if line_s.startswith("- attack.t"):
                tid = line_s.replace("- attack.", "").upper()
                covered.add(tid)

    # Group by tactic
    tactics: dict = {}
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
        print(f"  {C.BLUE}{'─' * 50}{C.RESET}")
        for tid, name in tactics[tactic]:
            print(f"    {C.CYAN}{tid:<12}{C.RESET} {name}")

    print(f"\n  {C.BOLD}Total Techniques Covered:{C.RESET} {C.GREEN}{len(covered)}{C.RESET}")
    print(f"  {C.BOLD}Total Detection Rules:{C.RESET}    {C.GREEN}{len(SIGMA_RULES)}{C.RESET}")


def show_rule_summary():
    """Display summary table of all detection rules."""
    header("DETECTION RULE INVENTORY")

    print(f"\n  {'#':<4} {'Filename':<42} {'Level':<12} {'Tactic'}")
    print(f"  {'─'*4} {'─'*42} {'─'*12} {'─'*25}")

    for i, (filename, content) in enumerate(SIGMA_RULES.items(), 1):
        # Extract level
        level = "?"
        for line in content.splitlines():
            if line.strip().startswith("level:"):
                level = line.split(":", 1)[1].strip()
                break

        # Extract first tactic tag
        tactic = ""
        for line in content.splitlines():
            line_s = line.strip()
            if line_s.startswith("- attack.") and not line_s.startswith("- attack.t"):
                tactic = line_s.replace("- attack.", "").replace("_", " ").title()
                break

        # Color by level
        level_colors = {
            "critical": C.RED, "high": C.YELLOW,
            "medium": C.CYAN, "low": C.GREEN,
            "informational": C.DIM,
        }
        lc = level_colors.get(level, C.WHITE)

        print(f"  {i:<4} {filename:<42} {lc}{level:<12}{C.RESET} {tactic}")

    print(f"\n  {C.BOLD}Total Rules:{C.RESET} {len(SIGMA_RULES)}")


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
                '# Encoded "whoami" — harmless but triggers detection',
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
                "# Requires Sysinternals ProcDump — triggers LSASS access alert",
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
        print(f"\n  {C.BOLD}{C.MAGENTA}▸ {t['rule']}{C.RESET}")
        print(f"  {C.DIM}{t['description']}{C.RESET}")
        print(f"  {C.BLUE}{'─' * 50}{C.RESET}")
        for cmd in t["commands"]:
            if cmd == "":
                print()
            elif cmd.startswith("#"):
                print(f"    {C.DIM}{cmd}{C.RESET}")
            else:
                print(f"    {C.GREEN}${C.RESET} {cmd}")


def export_all(output_dir: str = "siemforge_export", dry_run: bool = False):
    """Export everything — Sigma rules, Sysmon config, Wazuh rules."""
    header("FULL EXPORT — ALL DETECTION CONTENT")

    base = Path(output_dir)

    if dry_run:
        info(f"Dry run — previewing export to ./{base}/")
        for filename in SIGMA_RULES:
            info(f"  Would write sigma_rules/{filename}")
        info("  Would write sysmon/sysmon_config.xml")
        info("  Would write wazuh/local_rules.xml")
        info("  Would write wazuh/agent_ossec_snippet.xml")
        info("  Would write manifest.json")
        info(f"Total: {len(SIGMA_RULES)} Sigma rules, 1 Sysmon config, 2 Wazuh files")
        return

    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"Cannot create export directory {base}: {e}")
        return

    # Sigma
    sigma_dir = base / "sigma_rules"
    sigma_dir.mkdir(exist_ok=True)
    for filename, content in SIGMA_RULES.items():
        try:
            (sigma_dir / filename).write_text(content, encoding="utf-8")
            ok(f"sigma_rules/{filename}")
        except OSError as e:
            err(f"Failed to write sigma_rules/{filename}: {e}")

    # Sysmon
    sysmon_dir = base / "sysmon"
    sysmon_dir.mkdir(exist_ok=True)
    try:
        (sysmon_dir / "sysmon_config.xml").write_text(SYSMON_CONFIG, encoding="utf-8")
        ok("sysmon/sysmon_config.xml")
    except OSError as e:
        err(f"Failed to write sysmon/sysmon_config.xml: {e}")

    # Wazuh
    wazuh_dir = base / "wazuh"
    wazuh_dir.mkdir(exist_ok=True)
    for fname, content in [("local_rules.xml", WAZUH_RULES), ("agent_ossec_snippet.xml", WAZUH_AGENT_CONF)]:
        try:
            (wazuh_dir / fname).write_text(content, encoding="utf-8")
            ok(f"wazuh/{fname}")
        except OSError as e:
            err(f"Failed to write wazuh/{fname}: {e}")

    # Manifest
    manifest = {
        "tool": "SIEMForge",
        "version": VERSION,
        "author": "Jude Hilgendorf",
        "exported": datetime.datetime.now().isoformat(),
        "sigma_rules": list(SIGMA_RULES.keys()),
        "sigma_count": len(SIGMA_RULES),
        "sysmon_config": "sysmon/sysmon_config.xml",
        "wazuh_rules": "wazuh/local_rules.xml",
        "wazuh_agent": "wazuh/agent_ossec_snippet.xml",
        "mitre_techniques": sorted(
            {line.strip().replace("- attack.", "").upper()
             for c in SIGMA_RULES.values()
             for line in c.splitlines()
             if line.strip().startswith("- attack.t")}
        ),
    }
    manifest_path = base / "manifest.json"
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        ok("manifest.json")
    except OSError as e:
        err(f"Failed to write manifest.json: {e}")

    print(f"\n  {C.BOLD}Export complete → ./{base}/{C.RESET}")

    # Print tree
    print(f"\n  {C.DIM}Directory structure:{C.RESET}")
    print(f"  {base}/")
    print(f"  ├── manifest.json")
    print(f"  ├── sigma_rules/")
    for f in sorted(SIGMA_RULES.keys()):
        print(f"  │   ├── {f}")
    print(f"  ├── sysmon/")
    print(f"  │   └── sysmon_config.xml")
    print(f"  └── wazuh/")
    print(f"      ├── local_rules.xml")
    print(f"      └── agent_ossec_snippet.xml")


def show_stats():
    """Show project statistics."""
    header("PROJECT STATISTICS")

    # Count techniques
    techniques: set = set()
    tactics: set = set()
    for content in SIGMA_RULES.values():
        for line in content.splitlines():
            line_s = line.strip()
            if line_s.startswith("- attack.t"):
                tid = line_s.replace("- attack.", "").upper()
                techniques.add(tid)
                if tid in MITRE_MAP:
                    tactics.add(MITRE_MAP[tid]["tactic"])
            elif line_s.startswith("- attack.") and not line_s.startswith("- attack.t"):
                tactic = line_s.replace("- attack.", "").replace("_", " ").title()
                tactics.add(tactic)

    # Count severity levels
    levels: dict = {}
    for content in SIGMA_RULES.values():
        for line in content.splitlines():
            if line.strip().startswith("level:"):
                lvl = line.split(":", 1)[1].strip()
                levels[lvl] = levels.get(lvl, 0) + 1

    # Count Wazuh rules
    wazuh_count = WAZUH_RULES.count('<rule id="')

    label_w = 30
    print()
    print(f"  {C.WHITE}{'Sigma Detection Rules':<{label_w}}{C.RESET}: {C.GREEN}{len(SIGMA_RULES)}{C.RESET}")
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
            bar = "█" * count
            print(f"    {lc}{lvl:<16}{C.RESET} {bar} {count}")


def show_stats_json():
    """Output project statistics as JSON for automation and CI pipelines."""
    techniques: set = set()
    tactics: set = set()
    for content in SIGMA_RULES.values():
        for line in content.splitlines():
            line_s = line.strip()
            if line_s.startswith("- attack.t"):
                tid = line_s.replace("- attack.", "").upper()
                techniques.add(tid)
                if tid in MITRE_MAP:
                    tactics.add(MITRE_MAP[tid]["tactic"])
            elif line_s.startswith("- attack.") and not line_s.startswith("- attack.t"):
                tactic = line_s.replace("- attack.", "").replace("_", " ").title()
                tactics.add(tactic)

    levels: dict = {}
    for content in SIGMA_RULES.values():
        for line in content.splitlines():
            if line.strip().startswith("level:"):
                lvl = line.split(":", 1)[1].strip()
                levels[lvl] = levels.get(lvl, 0) + 1

    wazuh_count = WAZUH_RULES.count('<rule id="')

    stats = {
        "version": VERSION,
        "sigma_rules": len(SIGMA_RULES),
        "wazuh_rules": wazuh_count,
        "sysmon_event_types": 9,
        "mitre_techniques": sorted(techniques),
        "mitre_technique_count": len(techniques),
        "mitre_tactics": sorted(tactics),
        "mitre_tactic_count": len(tactics),
        "severity_breakdown": levels,
        "rule_files": list(SIGMA_RULES.keys()),
    }
    print(json.dumps(stats, indent=2))


# ──────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siemforge",
        description="SIEMForge — SIEM Detection Content Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
            examples:
              python siemforge.py --export-all          Export everything
              python siemforge.py --sigma               Export Sigma rules only
              python siemforge.py --validate             Validate all rules
              python siemforge.py --mitre               Show MITRE coverage
              python siemforge.py --tests               Show test commands
              python siemforge.py --stats               Show project stats
              python siemforge.py --list                List all rules
        """),
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
                        help="Custom output directory for exports (default: per-type or siemforge_export)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be exported without writing files")
    parser.add_argument("--json", action="store_true",
                        help="Output statistics in JSON format (machine-readable)")

    return parser


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

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

    # If no arguments, show help + stats
    ran_something = False

    dry_run = args.dry_run

    if args.export_all:
        export_all(output_dir=args.output_dir or "siemforge_export", dry_run=dry_run)
        ran_something = True

    if args.sigma:
        export_sigma_rules(output_dir=args.output_dir or "sigma_rules", dry_run=dry_run)
        ran_something = True

    if args.sysmon:
        export_sysmon_config(output_dir=args.output_dir or "sysmon", dry_run=dry_run)
        ran_something = True

    if args.wazuh:
        export_wazuh_rules(output_dir=args.output_dir or "wazuh", dry_run=dry_run)
        ran_something = True

    if args.validate:
        validate_rules()
        ran_something = True

    if args.mitre:
        show_mitre_coverage()
        ran_something = True

    if args.tests:
        generate_test_commands()
        ran_something = True

    if args.stats:
        if args.json:
            show_stats_json()
        else:
            show_stats()
        ran_something = True

    if args.list:
        show_rule_summary()
        ran_something = True

    if not ran_something:
        show_stats()
        show_rule_summary()
        print(f"\n  {C.DIM}Run with --help for all options or --export-all to export everything.{C.RESET}")

    print(f"\n{DIV}")
    print(f"  {C.CYAN}SIEMForge — Detection engineering made portable.{C.RESET}")
    print(f"{DIV}\n")


if __name__ == "__main__":
    main()