# parsers/startup_parser.py
r"""
Startup & Persistence Autoruns Forensics Parser.
Extracts:
- Windows Run / RunOnce Registry keys (HKLM, HKCU, Wow6432Node)
- Startup folder shortcuts and executables
- Identifies persistence mechanisms used by malware.
"""

import os
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

STARTUP_REG_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run_Wow6432"),
]

def parse_live_startup() -> List[Dict[str, Any]]:
    """
    Parses live Registry startup keys and Startup directories.
    """
    records = []

    # 1. Registry Run / RunOnce
    if HAS_WINREG:
        for root_hkey, sub_path, label in STARTUP_REG_LOCATIONS:
            if root_hkey is None:
                continue
            try:
                with winreg.OpenKey(root_hkey, sub_path) as key:
                    key_info = winreg.QueryInfoKey(key)
                    val_count = key_info[1]
                    raw_time = key_info[2]

                    # Registry last modified time
                    ts = None
                    try:
                        if raw_time > 10**12:
                            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=raw_time / 10.0)
                        else:
                            dt = datetime.datetime.fromtimestamp(raw_time, tz=datetime.timezone.utc)
                        ts = normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
                    except Exception:
                        pass

                    for i in range(val_count):
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, i)
                            cmd_str = str(val_data)

                            extra_dict = {
                                "source": "registry:startup",
                                "key": label,
                                "entry_name": val_name,
                                "command": cmd_str[:300]
                            }
                            extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                            records.append({
                                "artifact_type": "startup_persistence",
                                "name": val_name[:80],
                                "path": cmd_str,
                                "timestamp": ts,
                                "last_access": None,
                                "extra": extra_str,
                                "details": str({
                                    "name": val_name,
                                    "command": cmd_str,
                                    "registry_location": f"{label}\\{sub_path}"
                                })
                            })
                        except Exception:
                            continue
            except (FileNotFoundError, OSError):
                continue
            except Exception:
                continue

    # 2. Startup Folders
    startup_folders = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]

    for s_dir in startup_folders:
        if os.path.isdir(s_dir):
            try:
                for f in os.listdir(s_dir):
                    f_path = os.path.join(s_dir, f)
                    if os.path.isfile(f_path) and f.lower() != "desktop.ini":
                        try:
                            mtime = os.path.getmtime(f_path)
                            dt = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
                            ts = normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
                        except Exception:
                            ts = None

                        extra_dict = {
                            "source": "filesystem:startup_folder",
                            "folder": s_dir,
                            "filename": f
                        }
                        extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                        records.append({
                            "artifact_type": "startup_persistence",
                            "name": f[:80],
                            "path": f_path,
                            "timestamp": ts,
                            "last_access": None,
                            "extra": extra_str,
                            "details": str({"filename": f, "folder": s_dir, "path": f_path})
                        })
            except Exception:
                pass

    return records
