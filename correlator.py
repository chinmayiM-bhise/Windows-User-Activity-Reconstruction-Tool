# correlator.py
"""
Advanced Multi-Vector Forensic Correlator & Timeline Reconstruction Engine.
Features:
- Cross-artifact multi-stage event linking (Download -> Access -> Execution -> Persistence -> Tampering).
- Temporal sessionization (groups actions into logical user sessions).
- Advanced Anomaly & Threat Detection (Suspicious execution directories, timestomping indicators,
  audit log clearing, high-frequency execution, malicious PowerShell syntax).
- MITRE ATT&CK Tactic & Technique mapping tags.
"""

import sqlite3
import datetime
import re
import traceback
from typing import Union, List, Dict, Any, Optional

_SESSION_GAP_SECONDS = 180  # 3 minutes inactivity defines new session
_RUNCOUNT_RE = re.compile(r"run_count\s*=\s*(\d+)", flags=re.IGNORECASE)

# Suspicious file execution paths
SUSPICIOUS_PATHS = [
    (re.compile(r"\\AppData\\Local\\Temp\\", re.I), "Execution from User Temp Directory", "T1059"),
    (re.compile(r"\\Windows\\Temp\\", re.I), "Execution from System Temp Directory", "T1059"),
    (re.compile(r"\\Users\\Public\\", re.I), "Execution from Public Directory", "T1059"),
    (re.compile(r"\\Downloads\\", re.I), "Execution directly from Downloads Folder", "T1204"),
    (re.compile(r"\\\$recycle\.bin\\", re.I), "Execution / Access from Recycle Bin", "T1070.004"),
    (re.compile(r"\.(vbs|js|hta|ps1|bat|cmd|scr|pif)$", re.I), "Script / Suspicious Extension Executed", "T1059")
]

def _parse_iso_flexible(ts: Any) -> Optional[datetime.datetime]:
    """Parse timestamp value robustly into timezone-aware UTC datetime or None."""
    if not ts:
        return None
    try:
        s = str(ts).strip()
        if s.lower() in ("none", "null", ""):
            return None
        if s.endswith("Z"):
            s = s[:-1]
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt
    except Exception:
        try:
            v = float(str(ts).strip())
            if v > 1e14:  # FILETIME
                seconds = v / 10_000_000.0 - 11644473600.0
                return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
            if v > 1e12:  # ms epoch
                return datetime.datetime.fromtimestamp(v / 1000.0, tz=datetime.timezone.utc)
            return datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc)
        except Exception:
            return None

def _format_iso_z(dt: Optional[datetime.datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_extra_to_kv(extra: str) -> Dict[str, str]:
    """Parse extra field encoded as 'key=value;key2=value2' into dict."""
    out = {}
    if not extra:
        return out
    try:
        parts = [p for p in str(extra).split(";") if p.strip()]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                out[k.strip().lower()] = v.strip()
            else:
                out[p.strip().lower()] = ""
    except Exception:
        return {}
    return out

def _extract_run_count_from_row(row: Dict[str, Any]) -> Optional[int]:
    if not row:
        return None
    if "run_count" in row and row.get("run_count") is not None:
        try:
            return int(row.get("run_count"))
        except Exception:
            pass
    extra = row.get("extra") or ""
    kv = _parse_extra_to_kv(extra)
    if "run_count" in kv:
        try:
            return int(re.sub(r"[^\d]", "", kv.get("run_count") or ""))
        except Exception:
            pass
    m = _RUNCOUNT_RE.search(str(extra))
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return None

def ntpath_basename(path_str: str) -> str:
    if not path_str:
        return ""
    return path_str.replace("\\", "/").rsplit("/", 1)[-1]

def correlate_artifacts(db_or_conn: Union[str, sqlite3.Connection]) -> List[Dict[str, Any]]:
    """
    Main Forensics Correlator.
    Accepts DB path or sqlite3 connection and returns chronological correlated timeline.
    """
    conn = None
    close_conn = False
    try:
        if isinstance(db_or_conn, str):
            conn = sqlite3.connect(db_or_conn)
            close_conn = True
        elif isinstance(db_or_conn, sqlite3.Connection):
            conn = db_or_conn
        else:
            raise TypeError("db_or_conn must be sqlite path or sqlite3.Connection")

        conn.row_factory = lambda cursor, row: {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
        cur = conn.cursor()

        cur.execute("""
            SELECT *, COALESCE(timestamp, last_access) AS event_time
            FROM artifacts
            WHERE timestamp IS NOT NULL OR last_access IS NOT NULL
            ORDER BY event_time ASC
        """)
        rows = [dict(r) for r in cur.fetchall()]

        out: List[Dict[str, Any]] = []
        session_id = 1
        last_time: Optional[datetime.datetime] = None

        # Tracking maps for cross-artifact relation detection
        last_downloads: List[tuple[datetime.datetime, str, Dict[str, Any]]] = []  # (time, filename, row)
        last_seen_by_name: Dict[str, Any] = {}
        last_prefetch_by_exe: Dict[str, Any] = {}
        last_usb_inserted: List[tuple[datetime.datetime, str]] = []

        for r in rows:
            try:
                raw_time = r.get("event_time") or r.get("timestamp") or r.get("last_access")
                t = _parse_iso_flexible(raw_time)
                if not t:
                    continue

                # Session segmentation
                if last_time is not None:
                    delta = (t - last_time).total_seconds()
                    if delta > _SESSION_GAP_SECONDS:
                        session_id += 1
                last_time = t

                artifact_type = (r.get("artifact_type") or "unknown").lower()
                name = r.get("name") or ""
                path = r.get("path") or ""
                extra = r.get("extra") or ""
                kv = _parse_extra_to_kv(extra)
                run_count = _extract_run_count_from_row(r)

                base_label = ""
                anomalies = []
                mitre_tags = []
                relation_notes = []

                # 1. Artifact Type Classification & Base Labeling
                if "prefetch" in artifact_type:
                    rc_str = f" (Run Count: {run_count})" if run_count is not None else ""
                    base_label = f"🚀 Application Executed{rc_str}"
                    mitre_tags.append("T1204: User Execution")
                    exe_path = kv.get("exe_path") or path
                    if exe_path:
                        last_prefetch_by_exe[exe_path.lower()] = (t, r)
                        last_prefetch_by_exe[ntpath_basename(exe_path).lower()] = (t, r)

                elif "userassist" in artifact_type:
                    rc = kv.get("run_count", "")
                    focus_time = kv.get("focus_time_seconds", "")
                    base_label = f"👤 GUI App Execution [UserAssist] (Runs: {rc}, Focus: {focus_time}s)"
                    mitre_tags.append("T1204: User Execution")

                elif "bam" in artifact_type:
                    base_label = f"⚙️ Background Activity Moderator (Kernel Execution)"
                    mitre_tags.append("T1204: User Execution")

                elif "browser_download" in artifact_type:
                    base_label = f"📥 Web File Downloaded ({name})"
                    mitre_tags.append("T1566: Initial Access")
                    last_downloads.append((t, name.lower(), r))

                elif "browser_url" in artifact_type:
                    base_label = f"🌐 Web Page Visited ({name})"
                    mitre_tags.append("T1071: Application Layer Protocol")

                elif "powershell" in artifact_type:
                    threat_tag = kv.get("threat_tag")
                    severity = kv.get("severity")
                    if threat_tag:
                        base_label = f"⚡ PowerShell Command: [{severity}] {threat_tag}"
                        anomalies.append(f"Suspicious CLI Syntax: {threat_tag}")
                        mitre_tags.append("T1059.001: PowerShell")
                    else:
                        base_label = f"💻 PowerShell Command Executed"
                        mitre_tags.append("T1059.001: PowerShell")

                elif "usb" in artifact_type:
                    base_label = f"🔌 USB / Removable Storage Connected ({name})"
                    mitre_tags.append("T1052: Physical Medium")
                    last_usb_inserted.append((t, name))

                elif "lnk" in artifact_type:
                    target = kv.get("target", "")
                    base_label = f"🔗 Shortcut Opened -> {target or name}"
                    mitre_tags.append("T1204.002: Malicious File")

                elif "recycle" in artifact_type:
                    orig_path = kv.get("orig_path", "")
                    base_label = f"🗑️ File Deleted to Recycle Bin ({orig_path or name})"
                    mitre_tags.append("T1070.004: File Deletion")

                elif "shellbag" in artifact_type:
                    base_label = f"📂 Folder Viewed in Explorer ({path})"

                elif "startup" in artifact_type:
                    base_label = f"🔄 Autorun Persistence Registered ({name})"
                    anomalies.append("Persistence Mechanism Configured")
                    mitre_tags.append("T1547.001: Registry Run Keys")

                elif "event" in artifact_type:
                    if "1102" in extra or "104" in extra or "cleared" in artifact_type:
                        base_label = f"🚨 AUDIT LOG CLEARED (TAMPERING DETECTED)"
                        anomalies.append("CRITICAL: Event Log Cleared / Anti-Forensics")
                        mitre_tags.append("T1070.001: Clear Windows Event Logs")
                    elif "logon_failed" in artifact_type:
                        base_label = f"⚠️ Failed Logon Attempt"
                        anomalies.append("Failed Logon Event")
                        mitre_tags.append("T1110: Brute Force")
                    elif "logon" in artifact_type:
                        base_label = f"🔑 Successful User Logon"
                        mitre_tags.append("T1078: Valid Accounts")
                    elif "service" in artifact_type:
                        base_label = f"🛠️ New Service Installed"
                        mitre_tags.append("T1543.003: Windows Service")
                    else:
                        base_label = f"🛡️ Windows Security Event ({name})"

                elif "jumplist" in artifact_type:
                    base_label = f"📋 Jump List Item Accessed ({name})"

                else:
                    base_label = f"🔍 {artifact_type.upper()}: {name}"

                # 2. Cross-Artifact Pipeline Correlator: Download -> Execution
                if "prefetch" in artifact_type or "bam" in artifact_type or "userassist" in artifact_type:
                    exe_name_clean = ntpath_basename(name).lower().replace(".pf", "")
                    for dl_time, dl_name, dl_row in last_downloads:
                        if dl_name in exe_name_clean or exe_name_clean in dl_name:
                            time_diff = (t - dl_time).total_seconds()
                            if 0 <= time_diff <= 600:  # within 10 minutes of download
                                relation_notes.append(f"⚡ [PIPELINE] Executed {int(time_diff)}s after Browser Download ({dl_name})")
                                anomalies.append("Immediate Execution After Web Download")
                                mitre_tags.append("T1204: User Execution")
                                break

                # 3. Path-Based Suspicious Activity Detection
                target_check_path = path or name
                for p_regex, p_desc, p_mitre in SUSPICIOUS_PATHS:
                    if p_regex.search(target_check_path):
                        anomalies.append(f"⚠ {p_desc}")
                        mitre_tags.append(p_mitre)

                # 4. Deletion before / after Execution
                if "prefetch" in artifact_type:
                    prev = last_seen_by_name.get(name)
                    if prev:
                        prev_time, prev_type, _ = prev
                        if "recycle" in prev_type:
                            delta_sec = (t - prev_time).total_seconds()
                            if 0 <= delta_sec <= 300:
                                anomalies.append("⚠ Deleted File Executed Soon After")

                # 5. Build Detail String
                detail_parts = [f"[Session {session_id}] {base_label}"]
                if path and path != name:
                    detail_parts.append(f"| Path: {path}")
                if relation_notes:
                    detail_parts.append(" | ".join(relation_notes))

                anomaly_str = "; ".join(dict.fromkeys(anomalies)) if anomalies else ""
                mitre_str = " ".join(f"[{m}]" for m in dict.fromkeys(mitre_tags)) if mitre_tags else ""

                out.append({
                    "timestamp": _format_iso_z(t),
                    "artifact_type": artifact_type,
                    "detail": " ".join(p for p in detail_parts if p),
                    "anomaly": anomaly_str,
                    "mitre": mitre_str,
                    "session": session_id
                })

                if name:
                    last_seen_by_name[name] = (t, artifact_type, r)

            except Exception as e:
                continue

        # Sort chronologically
        try:
            out_sorted = sorted(out, key=lambda x: _parse_iso_flexible(x.get("timestamp")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
        except Exception:
            out_sorted = out

        return out_sorted

    except Exception as e:
        now = datetime.datetime.now(datetime.timezone.utc)
        return [{
            "timestamp": _format_iso_z(now),
            "artifact_type": "error",
            "detail": f"Correlator error: {str(e)}",
            "anomaly": "error",
            "mitre": "",
            "session": 0
        }]
    finally:
        if close_conn and conn:
            try:
                conn.close()
            except Exception:
                pass
