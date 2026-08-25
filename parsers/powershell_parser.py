# parsers/powershell_parser.py
"""
PowerShell PSReadLine Command History Parser with Threat Intelligence Heuristics.
Extracts:
- Every executed PowerShell CLI command with line numbers.
- Timestamps from file metadata / context.
- Threat heuristics: Flags suspicious commands (Reverse shells, Download cradles,
  Encoded commands, Mimikatz, AMSI bypasses, Shadow copy deletion, Registry tampering).
"""

import os
import re
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

# Suspicious patterns to flag in investigative timeline
SUSPICIOUS_CLI_PATTERNS = [
    (re.compile(r"invoke-expression|iex\s", re.I), "High", "Dynamic Code Execution (IEX)"),
    (re.compile(r"downloadstring|downloadfile|webrequest|net\.webclient", re.I), "High", "Web Download Cradle"),
    (re.compile(r"encodedcommand|-enc\s|-e\s", re.I), "High", "Base64 Encoded Command Execution"),
    (re.compile(r"bypass|-exec\sbypass|-executionpolicy\sbypass", re.I), "Medium", "Execution Policy Bypass"),
    (re.compile(r"mimikatz|sekurlsa|kerberos|wdigest|lsass", re.I), "Critical", "Credential Harvesting / Mimikatz"),
    (re.compile(r"vssadmin\s+delete\s+shadows|wbadmin\s+delete", re.I), "Critical", "Shadow Copy Deletion (Ransomware Tactic)"),
    (re.compile(r"certutil(\.exe)?\s+(-urlcache|-decode|-f)", re.I), "High", "Certutil Ingress / Lolbin Usage"),
    (re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.I), "High", "Bitsadmin Background Transfer"),
    (re.compile(r"schtasks(\.exe)?\s+/create", re.I), "Medium", "Scheduled Task Persistence"),
    (re.compile(r"reg(\.exe)?\s+add\s+.*run", re.I), "High", "Registry Autorun Persistence"),
    (re.compile(r"net\s+(user|localgroup|group)\s+.*\/add", re.I), "High", "Account Creation / Privilege Escalation"),
    (re.compile(r"whoami(\.exe)?|net\s+user|ipconfig|quser", re.I), "Low", "Discovery / Reconnaissance Command"),
    (re.compile(r"amsiutils|system\.management\.automation\.amsi", re.I), "Critical", "AMSI Anti-Malware Bypass"),
    (re.compile(r"rundll32(\.exe)?|regsvr32(\.exe)?", re.I), "Medium", "Lolbin Execution (Rundll32/Regsvr32)")
]

def _check_suspicious_patterns(command: str) -> tuple[Optional[str], Optional[str]]:
    """Evaluates CLI string against threat heuristic signatures."""
    for pattern, severity, tag in SUSPICIOUS_CLI_PATTERNS:
        if pattern.search(command):
            return severity, tag
    return None, None

def parse_powershell_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses a single ConsoleHost_history.txt file.
    """
    records = []
    if not os.path.isfile(file_path):
        return records

    try:
        # File timestamp as base time
        mtime = os.path.getmtime(file_path)
        base_dt = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
        file_ts = normalize_timestamp(base_dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        file_ts = None

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            cmd = line.strip()
            if not cmd:
                continue

            severity, threat_tag = _check_suspicious_patterns(cmd)
            anomaly_info = f"[{severity}] {threat_tag}" if threat_tag else ""

            extra_dict = {
                "source": "psreadline_history",
                "line_no": idx,
                "command": cmd[:500],
                "threat_tag": threat_tag,
                "severity": severity
            }
            extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

            records.append({
                "artifact_type": "powershell_cmd",
                "name": cmd[:60] + ("..." if len(cmd) > 60 else ""),
                "path": file_path,
                "timestamp": file_ts,
                "last_access": None,
                "extra": extra_str,
                "details": str({
                    "command": cmd,
                    "line": idx,
                    "anomaly": anomaly_info,
                    "file": file_path
                })
            })
    except Exception:
        pass

    return records

def parse_all_live_powershell() -> List[Dict[str, Any]]:
    r"""
    Discovers and parses ConsoleHost_history.txt across the current user profile
    and all user directories under C:\Users.
    """
    records = []
    app_data = os.environ.get("APPDATA", "")
    current_history = os.path.join(app_data, r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")

    visited_paths = set()
    if os.path.isfile(current_history):
        visited_paths.add(current_history.lower())
        records.extend(parse_powershell_file(current_history))

    users_root = os.path.join(os.environ.get("SystemDrive", "C:"), r"\Users")
    if os.path.isdir(users_root):
        try:
            for user_dir in os.listdir(users_root):
                candidate = os.path.join(users_root, user_dir, r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
                if os.path.isfile(candidate) and candidate.lower() not in visited_paths:
                    visited_paths.add(candidate.lower())
                    records.extend(parse_powershell_file(candidate))
        except Exception:
            pass

    return records
