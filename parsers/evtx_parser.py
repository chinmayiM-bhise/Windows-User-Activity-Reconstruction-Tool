# parsers/evtx_parser.py
"""
Windows Event Log (EVTX) Forensic Parser.
Extracts high-priority DFIR security events:
- 4624: Successful Logon (Type 2: Interactive, 3: Network, 10: RDP Remote)
- 4625: Failed Logon (Brute Force / Password Guessing)
- 4688: Process Creation (Executed command lines)
- 7045: New Service Installed (Persistence)
- 1102 / 104: Audit Log Cleared (Anti-Forensics / Tampering Alert)
- 4104: PowerShell Script Block Execution
- 1116 / 1117: Windows Defender Malware Detections
- 21 / 25: Remote Desktop (RDP) Sessions
"""

import os
import re
import json
import datetime
import subprocess
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

# Critical Security Event Descriptions
EVENT_DEFINITIONS = {
    4624: ("Logon", "Successful User Logon"),
    4625: ("Logon_Failed", "Failed Logon Attempt (Potential Brute-Force)"),
    4634: ("Logoff", "User Logoff"),
    4672: ("Privilege_Assigned", "Special Privileges Assigned to New Logon"),
    4688: ("Process_Create", "New Process Created (CLI Execution)"),
    4689: ("Process_Exit", "Process Exited"),
    7045: ("Service_Install", "New System Service Installed"),
    1102: ("Log_Cleared", "CRITICAL: Security Audit Log Cleared (Tampering)"),
    104: ("Log_Cleared", "CRITICAL: System Log Cleared (Tampering)"),
    4104: ("PowerShell_Block", "PowerShell Script Block Execution"),
    1116: ("Defender_Threat", "Windows Defender Detected Malware"),
    1117: ("Defender_Action", "Windows Defender Took Action on Threat"),
    21: ("RDP_Connected", "Terminal Services: Session Logon Succeeded"),
    25: ("RDP_Reconnected", "Terminal Services: Session Reconnection"),
}

def parse_evtx_via_wevtutil(channel_or_path: str, max_events: int = 100) -> List[Dict[str, Any]]:
    """
    Parses Windows Event Logs using built-in Windows 'wevtutil.exe' utility (pure Windows stdlib).
    Works on live system without third-party C/Rust binaries.
    """
    records = []
    try:
        # Determine query string
        if os.path.isfile(channel_or_path):
            query_arg = f'/e:Events /l:false /uni:true /c:{max_events} /rd:true "{channel_or_path}"'
            cmd = f'wevtutil qe "{channel_or_path}" /lf:true /c:{max_events} /rd:true /f:text'
        else:
            channel = channel_or_path
            cmd = f'wevtutil qe "{channel}" /c:{max_events} /rd:true /f:text'

        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = res.stdout
        if not output:
            return records

        # Split output into event blocks (separated by "Event[" or empty lines)
        blocks = re.split(r"Event\[\d+\]:", output)
        for block in blocks:
            if not block.strip():
                continue

            event_id_m = re.search(r"Event ID:\s+(\d+)", block, re.I)
            time_m = re.search(r"Date:\s+([\d\-\:T\.\+ Z]+|\d{4}-\d{2}-\d{2}[ \d\:\.]+)", block, re.I)
            level_m = re.search(r"Level:\s+([^\r\n]+)", block, re.I)
            comp_m = re.search(r"Computer:\s+([^\r\n]+)", block, re.I)
            desc_m = re.search(r"Description:\s+([\s\S]+)", block, re.I)

            if not event_id_m:
                continue

            eid = int(event_id_m.group(1))
            raw_time = time_m.group(1).strip() if time_m else ""
            ts = normalize_timestamp(raw_time) if raw_time else None
            computer = comp_m.group(1).strip() if comp_m else ""
            desc = desc_m.group(1).strip() if desc_m else ""

            tag, friendly_title = EVENT_DEFINITIONS.get(eid, (f"Event_{eid}", f"Event ID {eid}"))

            # Check if this is a tampering event
            anomaly = ""
            if eid in (1102, 104):
                anomaly = "CRITICAL: Security Audit Log Cleared (Anti-Forensics Indicator)"
            elif eid == 4625:
                anomaly = "WARNING: Failed Logon Attempt"

            extra_dict = {
                "source": "wevtutil_log",
                "event_id": eid,
                "event_type": tag,
                "computer": computer,
                "channel": os.path.basename(channel_or_path),
                "anomaly": anomaly
            }
            extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

            records.append({
                "artifact_type": f"event_{tag.lower()}",
                "name": f"Event {eid}: {friendly_title[:50]}",
                "path": channel_or_path,
                "timestamp": ts,
                "last_access": None,
                "extra": extra_str,
                "details": str({
                    "event_id": eid,
                    "title": friendly_title,
                    "computer": computer,
                    "description": desc[:600],
                    "raw_time": raw_time
                })
            })

    except Exception:
        pass

    return records

def parse_live_event_logs() -> List[Dict[str, Any]]:
    """
    Parses live high-priority Windows Security and System event channels.
    """
    records = []
    channels = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]
    for ch in channels:
        records.extend(parse_evtx_via_wevtutil(ch, max_events=50))
    return records

def parse_evtx_file(evtx_path: str) -> List[Dict[str, Any]]:
    """
    Parses a target .evtx file.
    """
    if not os.path.isfile(evtx_path):
        return []
    return parse_evtx_via_wevtutil(evtx_path, max_events=100)
